import RiverUtils
from RiverUtils import Input
from typing import List, Dict, Set
from triton import TritonContext, ARCH, Instruction, MemoryAccess, CPUSIZE, MODE, OPCODE
import logging
import pdb
import os
import re
import sys
import array
import string
import pdb
import gdb 
import numpy
import time

from bitstring import BitArray

# Some constants
# Where the input buffer will reside in the emulated program
INPUT_BUFFER_ADDRESS = 0x10000000

class Executor:
	def __init__(self, cmd):
		self.__cmd = cmd

	def __call__(self):
		gdb.execute(self.__cmd)

class GdbPage:
	def __init__(self, startAddr, endAddr, size, offset):
		self.__startAddr = startAddr
		self.__endAddr = endAddr
		self.__size = size
		self.__offset = offset

	def getStartAddr(self):
		return self.__startAddr

	def getEndAddr(self):
		return self.__endAddr

	def getSize(self):
		return self.__size

	def getOffset(self):
		return self.__offset

	@staticmethod
	def createPage(page):
		if len(page) == 4:
			return GdbPage(int(page[0].replace('\'',''), 0), \
						   int(page[1].replace('\'',''), 0), \
						   int(page[2].replace('\'',''), 0), \
						   int(page[3].replace('\'',''), 0)), "none"
			
		elif len(page) == 5:
			return GdbPage(int(page[0].replace('\'',''), 0), \
						   int(page[1].replace('\'',''), 0), \
						   int(page[2].replace('\'',''), 0), \
						   int(page[3].replace('\'',''), 0)), str(page[4])

	@staticmethod
	def createMemoryDict():
		global NAME_EXEC
		global DATA_SEGMENT_ADDR

		memory = {}
		info_mappings = gdb.execute("info proc mappings", False, True)
		info_mappings = info_mappings.split('\n')

		# se pastreaza tot fara header si ultimul element care este None
		info_mappings = [x.split() for x in info_mappings[4:-1]]

		for elem in info_mappings:
			page, name = GdbPage.createPage(elem)
			if name not in memory:
				memory[name] = []

			if ((name == NAME_EXEC and (DATA_SEGMENT_ADDR >= page.getStartAddr() or DATA_SEGMENT_ADDR < page.getEndAddr())) or name == "[stack]" or name == "[heap]") or DATA_SEGMENT_ADDR == 0:
				memory[name].append(page)

		return memory

	def __repr__(self):
		return "start address: {}\n end address: {}\n size: {}\n offset: {}\n" \
			.format(hex(self.__startAddr), \
			hex(self.__endAddr), hex(self.__size), hex(self.__offset)) 

class RiverTracer:
	# Creates the tracer either with symbolic execution enabled or not
	# And with the given architecture
	# if a targetToReach is used, then the emulation stops when the tracer gets to that address
	def __init__(self, architecture, symbolized, maxInputSize, targetAddressToReach = None):
		global INPUT_BUFFER_ADDRESS
		self.context = TritonContext(architecture)
		self.symbolized = symbolized
		self.resetSymbolicMemoryAtEachRun = False # KEEP IT FALSE OR TELL CPADURARU WHY YOU DO OTHERWISE
		self.maxInputSize = maxInputSize
		self.findCrash = False

		INPUT_BUFFER_ADDRESS = self.castGDBValue(int((gdb.execute("p &inputBuf", False, True)).split(") ")[1].split(" <")[0], 0))

		if symbolized is False:
			self.context.enableSymbolicEngine(False)
		assert self.context.isSymbolicEngineEnabled() == symbolized

		# Define some symbolic optimizations - play around with these since maybe there are variations between the used program under test
		self.context.setMode(MODE.ALIGNED_MEMORY, True)
		if symbolized:
			self.context.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
			# self.context.setMode(MODE.PC_TRACKING_SYMBOLIC, False)
			# symbolicContext.setMode(MODE.AST_OPTIMIZATIONS, True)
			# symbolicContext.setMode(MODE.CONSTANT_FOLDING, True)

		# The set of basic blocks found so far by this tracer.
		self.allBlocksFound: Set[int] = set()
		self.TARGET_TO_REACH = targetAddressToReach
		self.entryFuncAddr = None # Entry function address
		self.codeSection_begin = None # Where the code section begins and ends
		self.codeSection_end = None

		# Create the cache of symbolic variables if they are to be keep fixed.
		inputMaxLenPlusSentinelSize = self.maxInputSize + RiverUtils.SENTINEL_SIZE
		self.symbolicVariablesCache = [None] * inputMaxLenPlusSentinelSize
		if self.resetSymbolicMemoryAtEachRun == False:
			for byteIndex in range(inputMaxLenPlusSentinelSize):
				byteAddr = INPUT_BUFFER_ADDRESS + byteIndex
				symbolicVar = self.context.symbolizeMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))
				self.context.symbolizeMemory(MemoryAccess(byteAddr + 1, CPUSIZE.BYTE))
				self.symbolicVariablesCache[byteIndex] = symbolicVar

		#self.debugShowAllSymbolicVariables()
		assert self.resetSymbolicMemoryAtEachRun == True or len(self.symbolicVariablesCache) == inputMaxLenPlusSentinelSize


	def resetPersistentState(self):
		self.allBlocksFound = set()

	# Gets the context of this tracer
	def getContext(self):
		return self.context

	def getAstContext(self):
		return self.context.getAstContext()

	@staticmethod
	def castGDBValue(value):
		if int(value) < 0:
			value = int(value) + (1 << 64)
		return int(value)


	# Given a context where to emulate the binary already setup in memory with its input, and the PC address to emulate from, plus a few parameters...
	# Returns a tuple (true if the optional target address was reached, num new basic blocks found - if countBBlocks is True)
	# AND the path of basic block addresses found in this run
	def __emulate(self, pc: int, countBBlocks: bool, inputToTry: RiverUtils.Input, symbolized: bool):
		global BASE_EXEC
		global END_EXEC
		global NAME_EXEC
		global MAPPINGS
		global ADDRESS_HANDLES
		global INPUT_BUFFER_ADDRESS

		targetAddressFound = False
		currentBBlockAddr = pc  # The basic block address that we started to analyze currently
		numNewBasicBlocks = 0  # The number of new basic blocks found by this function (only if countBBlocks was activated)
		newBasicBlocksFound = set()
		basicBlocksPathFoundThisRun = []
		self.findCrash = False

		def updateMemory(memory, name_exec, inputToTry):
			global INPUT_BUFFER_ADDRESS
			update_memory = []

			for key in memory:
				if key == name_exec or key == "[stack]" or key == "[heap]":# or key == "none":
					update_memory.extend(memory[key])

			for page in update_memory:
				startAddr = page.getStartAddr()
				size = int(page.getSize() / 8)
				examine_command = "x/" + str(size) + "ug " + str(hex(startAddr))
				addresses = gdb.execute(examine_command, False, True)
				addresses = [elem for elem in re.split("[\n\t]", addresses)[:-1]]
				addresses = [int(elem).to_bytes(8, byteorder='little') for elem in addresses if ":" not in elem]
				
				for s in addresses:
					if s != self.context.getConcreteMemoryAreaValue(startAddr, 8):
						for byte_value in s:
							if byte_value != self.context.getConcreteMemoryValue(MemoryAccess(startAddr, CPUSIZE.BYTE)):
								self.context.setConcreteMemoryValue(startAddr, byte_value)
							startAddr += 1
						assert (s == self.context.getConcreteMemoryAreaValue(startAddr - 8, 8)), "Memory restoration failed"
					else:
						startAddr += 8


		def restoreRegister(tritonRegister, registerName):
			if self.context.getConcreteRegisterValue(tritonRegister) != self.castGDBValue(gdb.parse_and_eval(registerName)):
				self.context.setConcreteRegisterValue(tritonRegister, self.castGDBValue((gdb.parse_and_eval(registerName))))

		def restoreContext():
			restoreRegister(self.context.registers.rax, '$rax')
			restoreRegister(self.context.registers.rbx, '$rbx')
			restoreRegister(self.context.registers.rcx, '$rcx')
			restoreRegister(self.context.registers.rdx, '$rdx')
			restoreRegister(self.context.registers.rsi, '$rsi')
			restoreRegister(self.context.registers.rdi, '$rdi')
			restoreRegister(self.context.registers.rsp, '$rsp')
			restoreRegister(self.context.registers.rbp, '$rbp')
			restoreRegister(self.context.registers.r8, '$r8')
			restoreRegister(self.context.registers.r9, '$r9')
			restoreRegister(self.context.registers.r10, '$r10')
			restoreRegister(self.context.registers.r11, '$r11')
			restoreRegister(self.context.registers.r12, '$r12')
			restoreRegister(self.context.registers.r13, '$r13')
			restoreRegister(self.context.registers.r14, '$r14')
			restoreRegister(self.context.registers.r15, '$r15')
			restoreRegister(self.context.registers.rip, '$rip')
			restoreRegister(self.context.registers.eflags, '$eflags')

		def getHandlersAddresses():
			handleCalls = ["memmove"]
			addresses = []
			for call in handleCalls:
				gdb_command = "print *" + call
				addr = gdb.execute(gdb_command, False, True)
				addresses.append(int((addr.split("} ")[1]).split(" <")[0].replace('\'',''), 0))
			return addresses

		def handleMemmove():
			if symbolized:
				size = self.context.getRegisterAst(self.context.registers.rdx).evaluate()
				startAddress = self.context.getRegisterAst(self.context.registers.rdi).evaluate()
				srcAddress = self.context.getRegisterAst(self.context.registers.rsi).evaluate()
				# gdb.execute("stepi")
				gdb.execute("finish")
				updateMemory(GdbPage.createMemoryDict(), NAME_EXEC, inputToTry)
				restoreContext()
				for offset in range(size):
					addr = startAddress + offset
					if self.context.isMemorySymbolized(srcAddress + offset):
						self.context.assignSymbolicExpressionToMemory(self.context.getSymbolicMemory().get(srcAddress + offset), MemoryAccess(addr, CPUSIZE.BYTE))
			else:
				gdb.execute("finish")
				updateMemory(GdbPage.createMemoryDict(), NAME_EXEC, inputToTry)
				restoreContext()

		def event_handler(event):
			# if gdb.selected_inferior().is_running
			try:
				if isinstance(event, gdb.SignalEvent):
					gdb.execute("set scheduler-locking on") # to avoid parallel signals in other threads
					if event.stop_signal == "SIGABRT" or event.stop_signal == "SIGSEGV":
						self.findCrash = True
					gdb.execute("set scheduler-locking off") # otherwise just this thread is continued, leading to a deadlock   
			except:
				pass

		def onBasicBlockFound(addr):
			nonlocal numNewBasicBlocks
			nonlocal newBasicBlocksFound
			nonlocal basicBlocksPathFoundThisRun

			basicBlocksPathFoundThisRun.append(addr)
			# Is this a new basic block ?
			if addr not in self.allBlocksFound:
				numNewBasicBlocks += 1
				newBasicBlocksFound.add(addr)
				self.allBlocksFound.add(addr)

		onBasicBlockFound(currentBBlockAddr)

		logging.info('[+] Starting emulation.')

		value = "{"
		for (index, content) in inputToTry.buffer.items():
			value += str(content) + ","
		value += "0}"

		if gdb.selected_inferior().pid == 0:
			gdb.execute("start")

		command = "set {}{}{} {}={}".format("{uint8_t[",(len(inputToTry.buffer) + 1), "]}", "inputBuf", value)
		gdb.execute(command)
		handlerAddresses = getHandlersAddresses()

		gdb.events.stop.connect(event_handler)

		gdb_pc = (self.castGDBValue(gdb.parse_and_eval('$rip')))
		
		restoreContext()
		while pc < gdb_pc:
			opcode = self.context.getConcreteMemoryAreaValue(pc, 16)

			# Create the ctx instruction
			instruction = Instruction()
			instruction.setOpcode(opcode)
			instruction.setAddress(pc)

			#Process
			self.context.processing(instruction)
			logging.info(instruction)

			# Next
			prevpc = pc
			pc = self.context.getRegisterAst(self.context.registers.rip).evaluate()

		while pc:
			# Fetch opcode
			opcode = self.context.getConcreteMemoryAreaValue(pc, 16)

			# Create the ctx instruction
			instruction = Instruction()
			instruction.setOpcode(opcode)
			instruction.setAddress(pc)

			# Process
			self.context.processing(instruction)
			logging.info(instruction)

			if instruction.isControlFlow():
				currentBBlockAddr = pc
				onBasicBlockFound(currentBBlockAddr)

			# Next
			prevpc = pc
			pc = self.context.getRegisterAst(self.context.registers.rip).evaluate()

			gdb_pc = self.castGDBValue(gdb.parse_and_eval('$rip'))
			
			if (not (gdb_pc >= END_EXEC or gdb_pc <= BASE_EXEC)):
				gdb.execute("stepi")
				if gdb.selected_inferior().pid == 0:
					break
				gdb_pc = self.castGDBValue(gdb.parse_and_eval('$rip'))

			if (gdb_pc >= END_EXEC or gdb_pc <= BASE_EXEC) and gdb_pc not in handlerAddresses:
				pc = gdb_pc

				while ((pc >= END_EXEC or pc <= BASE_EXEC) and gdb.selected_inferior().pid != 0):
					gdb.execute("finish")
				
					if gdb.selected_inferior().pid == 0:
						break
					pc = (self.castGDBValue(gdb.parse_and_eval('$rip')))

				if gdb.selected_inferior().pid == 0:
					break
				updateMemory(GdbPage.createMemoryDict(), NAME_EXEC, inputToTry)
				restoreContext()
			elif gdb_pc in handlerAddresses:
				# print("intra", file=sys.stderr)
				# print(hex(gdb_pc), file=sys.stderr)
				handleMemmove()



			pc = (self.castGDBValue(gdb.parse_and_eval('$rip')))
			
			if self.TARGET_TO_REACH is not None and pc == self.TARGET_TO_REACH:
				targetAddressFound = True


		logging.info('[+] Emulation done.')
		if countBBlocks:
			logging.info(f'===== New basic blocks found: {[hex(intBlock) for intBlock in newBasicBlocksFound]}')

		if basicBlocksPathFoundThisRun[-1] == 0: # ret instruction
			basicBlocksPathFoundThisRun = basicBlocksPathFoundThisRun[:-1]

		# print(self.context.getAstRepresentationMode(), file=sys.stderr)
		return targetAddressFound, numNewBasicBlocks, basicBlocksPathFoundThisRun

	def debugShowAllSymbolicVariables(self):
		allSymbolicVariables = self.context.getSymbolicVariables()
		print(f"All symbolic variables: {allSymbolicVariables}")

		for k, v in sorted(self.context.getSymbolicVariables().items()):
			print(k, v)
			varValue = self.context.getConcreteVariableValue(v)
			print(f"Var id {k} name and size: {v} = {varValue}")

	# This function initializes the context memory for further emulation
	def __initContext(self, inputToTry: RiverUtils.Input, symbolized: bool):
		assert (self.context.isSymbolicEngineEnabled() == symbolized or symbolized == False), "Making sure that context has exactly the matching requirements for the call, nothing more, nothing less"

		inputToTry.sanityCheck()

		# Clean symbolic state
		if symbolized and self.resetSymbolicMemoryAtEachRun:
			self.context.concretizeAllRegister()
			self.context.concretizeAllMemory()

		# Byte level
		def symbolizeAndConcretizeByteIndex(byteIndex, value, symbolized):
			global INPUT_BUFFER_ADDRESS
			byteAddr = INPUT_BUFFER_ADDRESS + byteIndex
			if symbolized:
				# If not needed to reset symbolic state, just take the variable from the cache store and set its current value
				if self.resetSymbolicMemoryAtEachRun: # Not used anymore
					self.context.setConcreteMemoryValue(byteAddr, value)
					self.context.symbolizeMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))
				else:
					try:
						self.context.setConcreteVariableValue(self.symbolicVariablesCache[byteIndex], value)
						self.context.taintMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))
						assert self.context.getConcreteMemoryValue(MemoryAccess(byteAddr, CPUSIZE.BYTE)) == value
					except:
						pass

		# Continuous area level
		def symbolizeAndConcretizeArea(addr, values):
			global INPUT_BUFFER_ADDRESS
			if symbolized:
				if self.resetSymbolicMemoryAtEachRun: # Not used anymore
					self.context.setConcreteMemoryAreaValue(addr, values)
					for byteIndex, value in enumerate(values):
						byteAddr = INPUT_BUFFER_ADDRESS + byteIndex
						self.context.symbolizeMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))
				else:
					# If not needed to reset symbolic state, just take the variable from the cache store and set its current value
					# This will update both the symbolic state and concrete memory
					for byteIndex, value in enumerate(values):
						byteAddr = INPUT_BUFFER_ADDRESS + byteIndex
						self.context.setConcreteVariableValue(self.symbolicVariablesCache[byteIndex], value)
						#assert self.context.getConcreteMemoryValue(MemoryAccess(byteAddr, CPUSIZE.BYTE)) == value


		# Symbolize the input bytes in the input seed.
		# Put all the inputs in the buffer in the emulated program memory
		if inputToTry.usePlainBuffer == True:
			assert isinstance(inputToTry.buffer, list), "The input expected to be a series of bytes in a list "
			inputLen = len(inputToTry.buffer)
			symbolizeAndConcretizeArea(INPUT_BUFFER_ADDRESS, inputToTry.buffer)
			#for byteIndex, value in enumerate(inputToTry.buffer):
			#	symbolizeAndConcretizeByteIndex(byteIndex, value, symbolized)
		else:
			inputLen = max(inputToTry.buffer.keys()) + 1
			# self.context.symbolizeRegister(self.context.registers.rsi)
			for byteIndex, value in inputToTry.buffer.items():
				symbolizeAndConcretizeByteIndex(byteIndex, value, symbolized)

		if symbolized:
			for sentinelByteIndex in range(inputLen, inputLen + RiverUtils.SENTINEL_SIZE):
				symbolizeAndConcretizeByteIndex(sentinelByteIndex, 0, symbolized)

		# The commented version is the generic one if using a plain buffer and no dict
		"""
		for index in range(30):
			ctx.symbolizeMemory(MemoryAccess(0x10000000+index, CPUSIZE.BYTE))
		"""

		# Point RDI on our buffer. The address of our buffer is arbitrary. We just need
		# to point the RDI register on it as first argument of our targeted function.
		self.context.setConcreteRegisterValue(self.context.registers.rdi, INPUT_BUFFER_ADDRESS)
		self.context.setConcreteRegisterValue(self.context.registers.rsi, inputLen)

		# Setup fake stack on an abitrary address.
		self.context.setConcreteRegisterValue(self.context.registers.rsp, 0x7fffffff)
		self.context.setConcreteRegisterValue(self.context.registers.rbp, 0x7fffffff)
		return

	def runInput(self, inputToTry : RiverUtils.Input, symbolized : bool, countBBlocks : bool):
		# Init context memory
		self.__initContext(inputToTry, symbolized=symbolized)

		# Emulate the binary with the setup memory
		return self.__emulate(self.entryFuncAddr, countBBlocks=countBBlocks, inputToTry=inputToTry, symbolized=symbolized)

	def getLastRunPathConstraints(self):
		return self.context.getPathConstraints()

	def resetLastRunPathConstraints(self):
		self.context.clearPathConstraints()

	# Ask for a model to change the input conditions such that a base bath + a branch change condition constraints are met
	# Then put all the changed bytes (map from index to value) in a dictionary
	def solveInputChangesForPath(self, constraint):
		assert self.symbolized == True, "you try to solve inputs using a non-symbolic tracer context !"

		model = self.context.getModel(constraint)
		changes = dict()  # A dictionary  from byte index (relative to input buffer beginning) to the value it has in he model
		for k, v in list(model.items()):
			# Get the symbolic variable assigned to the model
			symVar = self.context.getSymbolicVariable(k)
			# Save the new input as seed.
			byteAddrAccessed = symVar.getOrigin()
			byteAddrAccessed_relativeToInputBuffer = byteAddrAccessed - INPUT_BUFFER_ADDRESS
			changes.update({byteAddrAccessed_relativeToInputBuffer: v.getValue()})

		return changes

	# Load the binary segments into the given set of contexts given as a list
	@staticmethod
	def loadBinary(tracersInstances, binaryPath, entryfuncName):
		global BASE_EXEC
		global END_EXEC
		global SIZE
		global IS_NORMAL
		global MAPPINGS
		global NAME_EXEC
		global DATA_SEGMENT_ADDR

		outEntryFuncAddr = None
		# gdb.execute("set args /home/ubuntu/Desktop/licenta/river/River3/TestPrograms/libxml2-v2.9.2/input-files/emptyArray")

		MAPPINGS = GdbPage.createMemoryDict()

		info_exec = gdb.execute("info proc exe", False, True)
		NAME_EXEC = (info_exec.split("exe = ")[1]).split('\n')[0].replace('\'', '')
		exec_mapping = MAPPINGS[NAME_EXEC]


		data_section = gdb.execute("maintenance info sections | grep .data", False, True)
		DATA_SEGMENT_ADDR = int(data_section.split('\n')[2].split()[1].split('-')[0].replace('\'',''), 0)

		for i in range(len(exec_mapping)):
			SIZE += exec_mapping[i].getSize()

		BASE_EXEC = exec_mapping[0].getStartAddr()
		END_EXEC = BASE_EXEC + SIZE
		logging.info(f"Loading the binary at path {binaryPath}..")
		import lief
		binary = lief.parse(binaryPath)
		if binary is None:
			assert False, f"Path to binary not found {binaryPath}"
			exit(0)

		text = binary.get_section(".text")
		codeSection_begin = text.file_offset
		codeSection_end = codeSection_begin + text.size

		if outEntryFuncAddr is None:
			logging.info(f"Findind the exported function of interest {binaryPath}..")
			res = binary.exported_functions
			for function in res:
				if entryfuncName in function.name:
					outEntryFuncAddr = function.address
					logging.info(f"Function of interest found at address {outEntryFuncAddr}")
					break
		assert outEntryFuncAddr != None, "Exported function wasn't found"

		if RiverTracer.castGDBValue(outEntryFuncAddr) < RiverTracer.castGDBValue(BASE_EXEC):
			outEntryFuncAddr = RiverTracer.castGDBValue(outEntryFuncAddr) + RiverTracer.castGDBValue(BASE_EXEC)
		else:
			IS_NORMAL = False

		for tracerIndex, tracer in enumerate(tracersInstances):
			tracersInstances[tracerIndex].entryFuncAddr = outEntryFuncAddr
			tracersInstances[tracerIndex].codeSection_begin = codeSection_begin
			tracersInstances[tracerIndex].codeSection_end = codeSection_end

			phdrs = binary.segments
			for phdr in phdrs:
				size = phdr.physical_size
				vaddr = phdr.virtual_address


				if IS_NORMAL:
					vaddr += BASE_EXEC

				# print('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size), file=sys.stderr)
				logging.info('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
				tracersInstances[tracerIndex].context.setConcreteMemoryAreaValue(vaddr, bytes(phdr.content))
				#assert False, "Check where is stack and heap and reset them "

			RiverTracer.makeRelocation(binary, tracersInstances[tracerIndex].context)

	@staticmethod
	def makeRelocation(binary, tritonContext):
		return

	def hookingHandler(self, pc):
		# pc = self.context.getConcreteRegisterValue(self.context.registers.rip)
		for rel in customRelocation:
			if rel[2] == pc:
				print(f'Relo-entry: pc = {hex(pc)}, name = {rel[0]}')
				# Emulate the routine and the return value
				ret_value = rel[1](self.context)
				self.context.setConcreteRegisterValue(self.context.registers.rax, ret_value)
	
				# Get the return address
				ret_addr = self.context.getConcreteMemoryValue(
						MemoryAccess(self.context.getConcreteRegisterValue(self.context.registers.rsp), CPUSIZE.QWORD))
				print(f'In relo with pc={hex(pc)} ret_val={hex(ret_value)} ret_addr={hex(ret_addr)}')
	
				# Hijack RIP to skip the call
				self.context.setConcreteRegisterValue(self.context.registers.rip, ret_addr)
	
				# Restore RSP (simulate the ret)
				self.context.setConcreteRegisterValue(self.context.registers.rsp, self.context.getConcreteRegisterValue(self.context.registers.rsp)+CPUSIZE.QWORD)
		return

	@staticmethod
	def getMemoryString(addr, tritonContext):
		s = str()
		index = 0
		
		while tritonContext.getConcreteMemoryValue(addr+index):
			c = chr(tritonContext.getConcreteMemoryValue(addr+index))
			if c not in string.printable: c = ""
			s += c
			index  += 1
		
		return s

	# Simulate the strlen() function
	@staticmethod
	def strlenHandler(tritonContext):
		print('[+] Strlen hooked')
		# Get arguments
		arg1 = RiverTracer.getMemoryString(tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi), tritonContext)
		
		# Return value
		return len(arg1)

	@staticmethod
	def getenvHandler(tritonContext):
		print('[+] Getenv hooked')
		# Get arguments
		key = RiverTracer.getMemoryString(tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi), tritonContext)

		value = os.getenv(key)
		print(f'In getenv with arg {key} val {value}')

		if value is None:
			return 0

		value += '\0'
		size = len(value)
		addr = RiverTracer.mallocImpl(size)
		for i in range(len(value)):
			tritonContext.setConcreteMemoryValue(MemoryAccess(addr + i, CPUSIZE.BYTE), ord(value[i]))
		
		return addr

	@staticmethod
	def readHandler(tritonContext):
		print('[+] Read hooked')
		# Get arguments
		# arg1
		fd = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi)
		# arg2
		buf_addr = tritonContext.getConcreteRegisterValue(tritonContext.registers.rsi)
		# arg3
		nbytes = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdx)
		# arg4 = tritonContext.getConcreteRegisterValue(tritonContext.registers.rcx)
		# arg5 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r8)
		# arg6 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r9)
		print(f'In read with fd = {fd}, buf_addr = {hex(buf_addr)}, nbytes = {nbytes}')

		buf = os.read(fd, nbytes)

		print(f'read {buf} {len(buf)}')
		assert (len(buf) <= nbytes), f"Read {len(buf)} bytes, which is more than the max nbytes {nbytes}"
		for i in range(len(buf)):
			tritonContext.setConcreteMemoryValue(MemoryAccess(buf_addr + i, CPUSIZE.BYTE), buf[i])

		#self.context.setConcreteMemoryValue(byteAddr, value)
		#self.context.symbolizeMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))

		#tritonContext.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
		
		# Return value
		return len(buf)

	@staticmethod
	def writeHandler(tritonContext):
		print('[+] Write hooked')
		# Get arguments
		# arg1
		fd = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi)
		# arg2
		buf_addr = tritonContext.getConcreteRegisterValue(tritonContext.registers.rsi)
		# arg3
		nbytes = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdx)
		# arg4 = tritonContext.getConcreteRegisterValue(tritonContext.registers.rcx)
		# arg5 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r8)
		# arg6 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r9)
		print(f'In read with fd = {fd}, buf_addr = {hex(buf_addr)}, nbytes = {nbytes}')

		# ret = os.write(fd, array.array('B', RiverTracer.getMemoryString(buf_addr, tritonContext)))
		arr = RiverTracer.getMemoryString(buf_addr, tritonContext)
		ret = len(arr)
		print(arr)

		assert (ret <= nbytes), f"Wrote {ret} bytes, which is more than the max nbytes {nbytes}"

		# Return value
		return ret

	@staticmethod
	def getMemoryString(addr, tritonContext):
		s = str()
		index = 0

		while tritonContext.getConcreteMemoryValue(addr+index):
			c = chr(tritonContext.getConcreteMemoryValue(addr+index))
			if c not in string.printable:
				c = ""
			s += c
			index  += 1

		return s

	@staticmethod
	def openHandler(tritonContext):
		global fdes
		print('[+] Write hooked')
		# Get arguments
		# arg1
		file_name_addr = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi)
		# arg2
		oflag = tritonContext.getConcreteRegisterValue(tritonContext.registers.rsi)
		# arg3
		mode = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdx)
		# arg4 = tritonContext.getConcreteRegisterValue(tritonContext.registers.rcx)
		# arg5 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r8)
		# arg6 = tritonContext.getConcreteRegisterValue(tritonContext.registers.r9)

		# ret = os.write(fd, array.array('B', RiverTracer.getMemoryString(buf_addr, tritonContext)))
		file_name = RiverTracer.getMemoryString(file_name_addr, tritonContext)
		print(f"In open with file_name {file_name}")
		fdes = open(file_name, "w")

		# Return value
		return fdes.fileno()

	@staticmethod
	def mallocImpl(size):
		global mallocCurrentAllocation
		global mallocMaxAllocation
		global mallocBase
		global mallocChunkSize

		if size > mallocChunkSize:
			print('malloc failed: size too big')
			sys.exit(-1)

		if mallocCurrentAllocation >= mallocMaxAllocation:
			print('malloc failed: too many allocations done')
			sys.exit(-1)

		area = mallocBase + (mallocCurrentAllocation * mallocChunkSize)
		mallocCurrentAllocation += 1

		# Return value
		return area

	# Simulate the malloc() function
	@staticmethod
	def mallocHandler(tritonContext):
		print('[+] Malloc hooked')

		# Get arguments
		size = tritonContext.getConcreteRegisterValue(tritonContext.registers.rdi)
		return RiverTracer.mallocImpl(size)

	def throwStats(self, target):
		target.onAddNewStatsFromTracer(self.allBlocksFound)
		self.allBlocksFound.clear()

	def ResetMem(self):
		# TODO
		pass

# Memory mapping
BASE_PLT   = 0x10000000
BASE_ARGV  = 0x20000000
BASE_ALLOC = 0x30000000

DATA_SEGMENT_ADDR = 0

BASE_EXEC = 0
END_EXEC = 0
SIZE = 0
IS_NORMAL = True

ADDRESS_HANDLES = []
MAPPINGS = {}
NAME_EXEC = None

BASE_STACK = 0x7ffffffde000

# Allocation information used by malloc()
mallocCurrentAllocation = 0
mallocMaxAllocation     = 2048
mallocBase              = BASE_ALLOC
mallocChunkSize         = 0x00010000
fdes = None

customRelocation = [
		# ('strlen', RiverTracer.strlenHandler, 0x10000000),
		# ('read', RiverTracer.readHandler, 0x10000001),
		# ('write', RiverTracer.writeHandler, 0x10000002),
		# ('malloc', RiverTracer.mallocHandler, 0x10000003),
		# ('getenv', RiverTracer.getenvHandler, 0x10000004),
		# ('open', RiverTracer.openHandler, 0x10000005),
		]
