# This is the implementation based on the SAGE paper
from __future__ import print_function
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
import os
import sys
curr_path = os.getcwd()
proj_root_idx = curr_path.find("/River3/")
py_modules_path = curr_path[0 : proj_root_idx] + "/River3/python"
sys.path.append(py_modules_path)
import argparse
import RiverUtils as RiverUtils
from RiverTracer import RiverTracer
from typing import List, Dict, Set
from signal import signal, SIGPIPE, SIG_DFL
# signal(SIGPIPE, SIG_DFL)
import copy
import time
from RiverOutputStats import RiverStatsTextual
import logging
import requests
import gdb

# TODO Bogdan, replace this with the graphical interface
# The online reconstructed graph that shows possible connections between basic blocks.
# We don't keep inputs or symbolic conditions because we don;t need them so far..just the graph
BlocksGraph : Dict[int, Set[int]] = {} # From basic block to the list of basic blocks and possible links

RECONSTRUCT_BB_GRAPH = False # Enable this if you need the block graph above

def onEdgeDetected(fromAddr, toAddr):
    if fromAddr not in BlocksGraph:
        BlocksGraph[fromAddr] = set()
    BlocksGraph[fromAddr].add(toAddr)

# This function returns a set of new inputs based on the last trace.
def Expand(symbolicTracer : RiverTracer, inputToTry):
    logging.critical(f"Seed injected:, {inputToTry}")

    symbolicTracer.runInput(inputToTry, symbolized=True, countBBlocks=False)

    # Set of new inputs
    inputs : List[RiverUtils.Input] = []

    # Get path constraints from the last execution
    PathConstraints = symbolicTracer.getLastRunPathConstraints()

    # Get the astContext
    astCtxt = symbolicTracer.getAstContext()

    # This represents the current path constraint, dummy initialization
    currentPathConstraint = astCtxt.equal(astCtxt.bvtrue(), astCtxt.bvtrue())

    # Go through the path constraints from bound of the input (to prevent backtracking as described in the paper)
    PCLen = len(PathConstraints)
    for pcIndex in range(inputToTry.bound, PCLen):
        pc = PathConstraints[pcIndex]

        # Get all branches
        branches = pc.getBranchConstraints()

        if RECONSTRUCT_BB_GRAPH:
            # Put all detected edges in the graph
            for branch in branches:
                onEdgeDetected(branch['srcAddr'], branch['dstAddr'])

        # If there is a condition on this path (not a direct jump), try to reverse it
        if pc.isMultipleBranches():
            takenAddress = pc.getTakenAddress()
            for branch in branches:
                # Get the constraint of the branch which has been not taken
                if branch['dstAddr'] != takenAddress:
                    #print(branch['constraint'])
                    #expr = astCtxt.unroll(branch['constraint'])
                    #expr = ctx.simplify(expr)

                    # Check if we can change current executed path with the branch changed
                    desiredConstrain = astCtxt.land([currentPathConstraint, branch['constraint']])
                    changes = symbolicTracer.solveInputChangesForPath(desiredConstrain)

                    # Then, if a possible change was detected => create a new input entry and add it to the output list
                    if changes:
                        newInput = copy.deepcopy(inputToTry)
                        newInput.applyChanges(changes)
                        newInput.bound = pcIndex + 1
                        inputs.append(newInput)

        # Update the previous constraints with taken(true) branch to keep the same path initially taken
        currentPathConstraint = astCtxt.land([currentPathConstraint, pc.getTakenPredicate()])

    # Clear the path constraints to be clean at the next execution.
    symbolicTracer.resetLastRunPathConstraints()

    return inputs

# This function starts with a given seed dictionary and does concolic execution starting from it.
def SearchInputs(symbolicTracer, simpleTracer, initialSeedDict, binaryPath, outputEndpoint):
    # Init the worklist with the initial seed dict
    worklist  = RiverUtils.InputsWorklist()
    forceFinish = False

    # Put all the the inputs in the seed dictionary to the worklist
    for initialSeed in initialSeedDict:
        inp = RiverUtils.Input()
        inp.buffer = {k: v for k, v in enumerate(initialSeed)}
        inp.bound = 0
        inp.priority = 0
        worklist.addInput(inp)

    startTime = currTime = time.time()
    while worklist:
        # Take the first seed
        inputSeed : RiverUtils.Input = worklist.extractInput()
        newInputs = Expand(symbolicTracer, inputSeed)

        for newInp in newInputs:
            # Execute the input to detect real issues with it
            issue = ExecuteInputToDetectIssues(binaryPath, newInp)
            if issue != None:
                print(f"{binaryPath} has issues: {issue} on input {newInp}")
                if outputEndpoint is not None:
                    # Send the issue data to provided output endpoint
                    SendIssueDataToEndpoint(binaryPath, issue, newInp, outputEndpoint)
                pass

            # Assign this input a priority, and check if the hacked target address was found or not
            targetFound, newInp.priority = ScoreInput(newInp, simpleTracer)

            if targetFound:
                logging.critical(f"The solution to get to the target address is input {newInp}")
                # TODO: Bogdan put this in output somewhere , folder, visualization etc.
                forceFinish = True # No reason to continue...
                break

            # Then put it in the worklist
            worklist.addInput(newInp)

        currTime = outputStats.UpdateOutputStats(startTime, currTime, collectorTracers=[simpleTracer])

        if forceFinish:
            break

    currTime = outputStats.UpdateOutputStats(startTime, currTime, collectorTracers=[simpleTracer], forceOutput=True)

def SendIssueDataToEndpoint(binaryPath, issue, causal_input, endpoint):
    payload = {
        "binaryPath": binaryPath,
        "issue": issue,
        "inputBytes": list(map(lambda k: causal_input.buffer[k], sorted(causal_input.buffer)))
    }
    try:
        print(f"Sending payload to '{endpoint}': {payload}")
        r = requests.post(endpoint, json=payload)
        print(r.json())
    except Exception as e:
        print(f"Error encountered while trying to send issue data to endpoint '{endpoint}': {e}")

def ExecuteInputToDetectIssues(binary_path, input : RiverUtils.Input):
    from bugs_detection.test_inputs import sig_str, test_input
    return sig_str.get(test_input(binary_path, bytes([v for v in input.buffer.values()])))

def ScoreInput(newInp : RiverUtils.Input, simpleTracer : RiverTracer):
    logging.critical(f"--Scoring input {newInp}")
    targetFound, numNewBlocks, allBBsInThisRun = simpleTracer.runInput(newInp, symbolized=False, countBBlocks=True)
    return targetFound, numNewBlocks # as default, return the bound...

if __name__ == '__main__':

    args = RiverUtils.parseArgs()
    gdb.execute("start")
    # Create two tracers : one symbolic used for detecting path constraints etc, and another one less heavy used only for tracing and scoring purpose
    symbolicTracer  = RiverTracer(symbolized=True,  architecture=args.architecture, maxInputSize=args.maxLen, targetAddressToReach=args.targetAddress)
    simpleTracer    = RiverTracer(symbolized=False, architecture=args.architecture, maxInputSize=args.maxLen, targetAddressToReach=args.targetAddress)

    # Load the binary info into the given list of tracers. We do this strage API to load only once the binary...
    RiverTracer.loadBinary([symbolicTracer, simpleTracer], args.binaryPath, args.entryfuncName)
    if args.outputType == "textual":
        outputStats = RiverStatsTextual()

    # TODO Bogdan: Implement the corpus strategies as defined in https://llvm.org/docs/LibFuzzer.html#corpus, or Random if not given
    initialSeedDict = ["good"] # ["a<9d"]
    RiverUtils.processSeedDict(initialSeedDict) # Transform the initial seed dict to bytes instead of chars if needed

    SearchInputs(symbolicTracer=symbolicTracer, simpleTracer=simpleTracer, initialSeedDict=initialSeedDict,
                binaryPath=args.binaryPath, outputEndpoint=args.outputEndpoint)

    if RECONSTRUCT_BB_GRAPH:
        print(f"Reconstructed graph is: {BlocksGraph}")
    sys.exit(0)
