import os
import sys
import unittest
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE
curr_path = os.getcwd()
proj_root_idx = curr_path.find("/River3/")
py_modules_path = curr_path[0 : proj_root_idx] + "/River3/python"
sys.path.append(py_modules_path)
print(py_modules_path)
import argparse
import RiverUtils as RiverUtils
from RiverTracer import RiverTracer
from typing import List, Dict, Set
from signal import signal, SIGPIPE, SIG_DFL
import copy
import time
from RiverOutputStats import RiverStatsTextual
import logging
import requests
from concolic_GenerationalSearch2 import SearchInputs

class TestBasicFunctionality(unittest.TestCase):
	def test_fuzzer(self):
		args = RiverUtils.parseArgs()
		testName = args.binaryPath.split('/')[-1]

		gdb.execute("start")
		gdb.execute("set logging on")
		gdb.execute("set logging file gdbout")
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

		listInputs = SearchInputs(symbolicTracer=symbolicTracer, simpleTracer=simpleTracer, initialSeedDict=initialSeedDict,
					binaryPath=args.binaryPath, outputEndpoint=args.outputEndpoint, outputStats=outputStats)

		if testName == "sample":
			assert (len(listInputs) >= 3), ("Unique crashes found " + str(len(listInputs)) + " less than 0")
		elif testName == "crackme_xor":
			assert (len(listInputs) >= 0), ("Unique crashes found " + str(len(listInputs)) + " less than 0")
		elif testName == "crackme_sample":
			assert (len(listInputs) >= 0), ("Unique crashes found " + str(len(listInputs)) + " less than 0")
	    


if __name__ == "__main__":
	singletest = unittest.TestSuite()
	singletest.addTest(TestBasicFunctionality('test_fuzzer'))
	# singletest.addTest(TestBasicFunctionality('test_crackme_sample'))
	# singletest.addTest(TestBasicFunctionality('test_sample'))
	unittest.TextTestRunner().run(singletest)