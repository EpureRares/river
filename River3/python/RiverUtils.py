from typing import List, Dict
import heapq
import numpy as np
from triton import TritonContext
import logging
import argparse
import os
import json
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE

# Put the last bytes as fake sentinel inputs to promote some usages detection outside buffer
SENTINEL_SIZE = 4

def parseArgs():
    # Construct the argument parser
    ap = argparse.ArgumentParser()

    # Add the arguments to the parser
    ap.add_argument("-bp", "--binaryPath", required=False,
                    help="the test binary location")
    ap.add_argument("-entryfuncName", "--entryfuncName", required=False, default="RIVERTestOneInput",
                    help="the name of the entry function you want to start the test from. By default the function name is 'RIVERTestOneInput'!", type=str)
    ap.add_argument("-arch", "--architecture", required=False,
                    help="architecture of the executable: ARM32, ARM64, X86, X64 are supported")
    ap.add_argument("-max", "--maxLen", required=False,
                    help="maximum size of input length", type=int)
    ap.add_argument("-targetAddress", "--targetAddress", required=False, default=None,
                    help="the target address that your program is trying to reach", type=str)
    ap.add_argument("-logLevel", "--logLevel", required=False, default='CRITICAL',
                    help="set the log level threshold, see the Python logging module documentation for the list of levels. Set it to DEBUG to see everything!", type=str)
    ap.add_argument("-secondsBetweenStats", "--secondsBetweenStats", required=False, default='10',
                    help="the interval (in seconds) between showing new stats", type=int)
    ap.add_argument("-outputType", "--outputType", required=False, default='textual',
                    help="the output interface type, can be visual or textual", type=str)
    ap.add_argument("-isTraining", "--isTraining", required=False, default=0,
                    help="set it to 1 if using an untrained model or to 0 if using a saved model", type=int)
    ap.add_argument("-pathToModel", "--pathToModel", required=False, default=None,
                    help="path to the model to use", type=str)
    ap.add_argument("-stateful", "--stateful", required=False, default=False,
                    help="Either if stateful or stateless (default)", type=str)
    ap.add_argument("-outputEndpoint", "--outputEndpoint", required=False, default=None,
                     help="the HTTP endpoint where test execution data will be sent")
    #ap.add_argument("-defaultObsParams", "--defaultObsParams", required=False, default=False,
    #                help="Default Observation parameters - should be a binary string mapping in order the values from default self.observation_space", type=str)

    args = ap.parse_args()
    
    curr_path = os.getcwd()
    proj_root_idx = curr_path.find("/River3/")
    arguments_path = curr_path[0 : proj_root_idx] + "/River3/Unittests/arguments.json"

    with open(arguments_path, 'r') as f:
        ap.set_defaults(**json.load(f))
    args = ap.parse_args()

    loggingLevel = logging._nameToLevel[args.logLevel]
    logging.basicConfig(level=loggingLevel)  # filename='example.log', # Set DEBUG or INFO if you want to see more

    SECONDS_BETWEEN_STATS = args.secondsBetweenStats

    args.targetAddress = None if args.targetAddress is None else int(args.targetAddress, 16)

    #assert len(args.defaultObsParams) != 4 # There are 4 default obs types
    args.obs_map = 0 #int(args.defaultObsParams[0])
    args.obs_path = 0 #int(args.defaultObsParams[1])
    args.obs_path_stats = 1 # int(args.defaultObsParams[2])
    args.obs_embedding = 0 #int(args.defaultObsParams[3])

    # Set the architecture
    if args.architecture == "ARM32":
        args.architecture = ARCH.ARM32
    elif args.architecture == "ARM64":
        args.achitecture = ARCH.X86_64
    elif args.architecture == "x86":
        args.architecture = ARCH.X86
    elif args.architecture == "x64":
        args.architecture = ARCH.X86_64
    else:
        assert False, "This architecture is not implemented"
        raise NotImplementedError

    Input.MAX_LEN = args.maxLen

    return args

class ActionFunctors:
    # Change a byte at a given index with a new value
    @staticmethod
    def ChangeByte(params): # inputInstance is Input type
        inputInstance = params['inputInstance']
        currentInputLen = len(inputInstance.buffer)
        if currentInputLen == 0:
            return False

        indexToChange = params['index'] if 'index' in params else None # Index where to do the change
        valueToChange = params['value'] if 'value' in params else None# value to change with, can be none and a random will be added there


        if valueToChange is None:
            valueToChange = np.random.choice(256)
        if indexToChange is None:
            indexToChange = np.random.choice(len(inputInstance.buffer))

        inputInstance.buffer[indexToChange] = valueToChange
        return True

    # Erase one or more bytes from a given position
    @staticmethod
    def EraseBytes(params):
        inputInstance = params['inputInstance']
        currentInputLen = len(inputInstance.buffer)
        if currentInputLen == 0:
            return False

        indexToStartChange = params['index'] if 'index' in params else None  # Index where to do the change
        maxLenToDelete = params['maxLen'] if 'maxLen' in params else None
        inputInstance = params['inputInstance']

        if maxLenToDelete is None: # Randomize a percent from the buffer len
            randomPercent = np.random.randint(low=2, high=10)
            randomNumItems = float(randomPercent) / len(inputInstance.buffer)
            maxLenToDelete = int(max(randomNumItems, 2))
        if indexToStartChange is None:
            indexToStartChange = np.random.choice(len(inputInstance.buffer))

        assert isinstance(inputInstance.buffer, Dict) == False, "Dict kind of buffer not supported for now!"
        inputInstance.buffer[indexToStartChange : (indexToStartChange+maxLenToDelete)] = []
        return True

    # Insert one or more bytes at a given position
    @staticmethod
    def InsertRandomBytes(params):
        index = params['index'] if 'index' in params else None  # Index where to do the change
        bytesCountToAdd = params['count'] if 'count' in params else None # how many bytes to add
        inputInstance = params['inputInstance']
        assert isinstance(inputInstance.buffer, Dict) == False, "Dict kind of buffer not supported for now!"

        currentInputLen = len(inputInstance.buffer)

        if bytesCountToAdd is None: # Randomize a percent from the buffer len
            randomPercent = float(np.random.rand() * 1.0) # A maximum of 1 percent to add
            randomNumItems = float(randomPercent / 100.0) * len(inputInstance.buffer)
            bytesCountToAdd = int(max(randomNumItems, np.random.randint(low=1, high=10)))
        if index is None:
            index = np.random.choice(currentInputLen) if currentInputLen > 0 else None

        oldBuffer = inputInstance.buffer
        bytesToAdd = list(np.random.choice(256, bytesCountToAdd))
        bytesToAdd = [x.item() for x in bytesToAdd]
        #print(f"Adding {len(bytesToAdd)} bytes")

        if index is not None:
            inputInstance.buffer = oldBuffer[:index] + bytesToAdd + oldBuffer[index:]
        else:
            inputInstance.buffer = bytesToAdd

        inputInstance.checkTrimSize()
        return True

    # See below to check the significance of params
    @staticmethod
    def AddDictionaryWord(params):
        index = params['index'] if 'index' in params else None  # Index where to do the change
        override = params['isOverride'] if 'isOverride' in params else False # if it should override or just add
        inputInstance = params['inputInstance']
        assert isinstance(inputInstance.buffer, Dict) == False, "Dict kind of buffer not supported for now!"

        wordToAdd = params['fixedWord'] if 'fixedWord' in params else None # If NONE, a random word from dictionary will be added,
        assert wordToAdd is None or isinstance(wordToAdd, list), "this should be a list of bytes !"

        currentInputLen = len(inputInstance.buffer)
        if index is None:
            index = np.random.choice(currentInputLen) if currentInputLen > 0 else 0

        if wordToAdd is None:
            if len(inputInstance.tokensDictionary) == 0:
                return False

            wordToAdd = np.random.choice(inputInstance.tokensDictionary)
        wordToAdd_len = len(wordToAdd)
        assert wordToAdd_len > 0

        if override is False:
            oldBuffer = inputInstance.buffer
            inputInstance.buffer = oldBuffer[:index] + list(wordToAdd) + oldBuffer[index:]
        else:
            inputInstance.buffer[index : (index+wordToAdd_len)] = wordToAdd

        inputInstance.checkTrimSize()

        return True


#  Data structures  to hold inputs
# Currently we keep the input as a dictionary mapping from byte indices to values.
# The motivation for this now is that many times the input are large but only small parts from them are changing...
# usePlainBuffer = true if the input is not sparse, to represent the input indices as an array rather than a full vector
class Input:
    def __init__(self, buffer : Dict[int, any] = None, bound = None , priority = None, usePlainBuffer=False):
        self.buffer = buffer
        self.bound = bound
        self.priority = priority
        self.usePlainBuffer = False

    def __lt__(self, other):
        return self.priority > other.priority

    def __str__(self):
        maxKeysToShow = 10
        keysToShow = sorted(self.buffer)[:maxKeysToShow]
        valuesStrToShow = ' '.join(str(self.buffer[k]) for k in keysToShow)
        strRes = (f"({valuesStrToShow}..bound: {self.bound}, priority: {self.priority})")
        return strRes

    # Apply the changes to the buffer, as given in the dictionary mapping from byte index to the new value
    def applyChanges(self, changes : Dict[int, any]):
        if not self.usePlainBuffer:
            self.buffer.update(changes)
        else:
            for byteIndex,value in changes.items():
                self.buffer[byteIndex] = value

    # This is used to apply one of the registered actions.
    # Don't forget that client user have full control and append statically the default set of actions
    # actionContext is defined as a set of parameters needed for the functor of the specific action
    # Returns True if the action could be applied, false otherwise
    def applyAction(self, actionIndex : int, actionContext : any):
        functorForAction = Input.actionFunctors.get(actionIndex)
        assert functorForAction, f"The requested action {actionIndex} is not availble in the actions set !"
        res =  functorForAction(actionContext)
        self.sanityCheck()
        return res

    # Static functors to apply action over the existing input
    # TODO: implement all others from https://arxiv.org/pdf/1807.07490.pdf
    # This is extensible by client using the below functions:
    actionFunctors = {0: ActionFunctors.ChangeByte,
                      1: ActionFunctors.EraseBytes,
                      2: ActionFunctors.InsertRandomBytes,
                      3: ActionFunctors.AddDictionaryWord}

    tokensDictionary = []

    NO_ACTION_INDEX = -1
    MAX_LEN = None # Will be set by user parameters

    def sanityCheck(self):
        #print(len(self.buffer))
        #return
        # Check 1: is input size in the desired range ?
        assert len(self.buffer) <= Input.MAX_LEN, f"Input obtained is bigger than the maximum length !! Max size set in params was {Input.MAX_LEN} while buffer has currently size {len(self.buffer)}"

    # Trim if too big
    def checkTrimSize(self):
        if len(self.buffer) > Input.MAX_LEN:
            self.buffer = self.buffer[:Input.MAX_LEN]

    @staticmethod
    def getNumActionFunctors():
        return max(Input.actionFunctors.keys())

    # Register new action functor other than the default ones
    # Returns back the index of the registered action so you know what to ask for when you want to use applyAction
    # actionContext is actually the variables that you pass to your functor
    @staticmethod
    def registerNewActionFunctor(newActionFunctor):
        newIndex = Input.getNumActionFunctors() + 1
        Input.actionFunctors[newIndex] = newActionFunctor

    # Sets the tokens dictionary for the current problem.
    @staticmethod
    def setTokensDictionary(tokensDictionary):
        Input.tokensDictionary = tokensDictionary

# This is used for the contextual bandits problem
class InputRLGenerational(Input):
    def __init__(self):
        Input.__init__(self)
        self.buffer_parent = None # The input of the parent that generated the below PC
        self.priority = -1 # The estimated priority for the state
        self.stateEmbedding = None
        self.PC = None # The parent path constraint that generated the parent input
        self.BBPathInParentPC = None # The same as above but simplified, basically the path of basic blocks obtained by running buffer_parent
        self.constraint = None # The constraint needed (SMT) to give to solve to change the PC using action and produce the new input for this structure
        self.action = -1 # The action to take (which of the self.PC branches should we modify)

# A priority queue data structure for holding inputs by their priority
class InputsWorklist:
    def __init__(self):
        self.internalHeap = []

    def extractInput(self):
        if self.internalHeap:
            next_item = heapq.heappop(self.internalHeap)
            return next_item
        else:
            return None

    def addInput(self, inp: Input):
        heapq.heappush(self.internalHeap, inp)

    def __str__(self):
        str = f"[{' ; '.join(inpStr.__str__() for inpStr in self.internalHeap)}]"
        return str

    def __len__(self):
        return len(self.internalHeap)

# An example how to use the inputs worklist
def example_InputsWorkList():
    worklist = InputsWorklist()
    worklist.addInput(Input("aa", 0, 10))
    worklist.addInput(Input("bb", 1, 20))
    worklist.addInput(Input('cc', 2, 30))
    print(worklist)

# Process the list of inputs to convert to bytes if the input was in a string format
def processSeedDict(seedsDict : List[any]):
    for idx, oldVal in enumerate(seedsDict):
        if isinstance(oldVal, str):
            seedsDict[idx] = str.encode(oldVal)

    #print(seedsDict)


def riverExp():
    pass
    # import gym
    # from gym import spaces

    # obs = {'inputBuffer' : spaces.Box(0, 255, shape=(4096, )),
    #        'inputLen' : spaces.Discrete(4096)}



    # x = obs['inputLen'].sample()
    # print(obs['inputLen'].n)

if __name__ == "__main__":
    riverExp()
