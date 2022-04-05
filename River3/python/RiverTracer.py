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

	def __repr__(self):
		return "start address: {}\n end address: {}\n size: {}\n offset: {}\n" \
			.format(hex(self.__startAddr), \
			hex(self.__endAddr), hex(self.__size), hex(self.__offset)) 

class RiverTracer:
	# Creates the tracer either with symbolic execution enabled or not
	# And with the given architecture
	# if a targetToReach is used, then the emulation stops when the tracer gets to that address
	def __init__(self, architecture, symbolized, maxInputSize, targetAddressToReach = None):
		self.context = TritonContext(architecture)
		self.symbolized = symbolized
		self.resetSymbolicMemoryAtEachRun = False # KEEP IT FALSE OR TELL CPADURARU WHY YOU DO OTHERWISE
		self.maxInputSize = maxInputSize

		if symbolized is False:
			self.context.enableSymbolicEngine(False)
		assert self.context.isSymbolicEngineEnabled() == symbolized

		# Define some symbolic optimizations - play around with these since maybe there are variations between the used program under test
		self.context.setMode(MODE.ALIGNED_MEMORY, True)
		if symbolized:
			self.context.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
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

	# Given a context where to emulate the binary already setup in memory with its input, and the PC address to emulate from, plus a few parameters...
	# Returns a tuple (true if the optional target address was reached, num new basic blocks found - if countBBlocks is True)
	# AND the path of basic block addresses found in this run
	def __emulate(self, pc: int, countBBlocks: bool):
		global BASE_EXEC
		global END_EXEC
		global NAME_EXEC
		global MAPPINGS

		targetAddressFound = False
		currentBBlockAddr = pc  # The basic block address that we started to analyze currently
		numNewBasicBlocks = 0  # The number of new basic blocks found by this function (only if countBBlocks was activated)
		newBasicBlocksFound = set()
		basicBlocksPathFoundThisRun = []

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

		def createMemoryDict():
			memory = {}
			info_mappings = gdb.execute("info proc mappings", False, True)
			info_mappings = info_mappings.split('\n')
			# se pastreaza tot fara header si ultimul element care este None
			info_mappings = [x.split() for x in info_mappings[4:-1]]

			for elem in info_mappings:
				page, name = createPage(elem)
				if name not in memory:
					memory[name] = []
				memory[name].append(page)

			return memory

		def updateMemory(memory, name_exec):
			update_memory = []

			for key in memory:
				if key == name_exec or key == "[stack]" or key == "[heap]":
					update_memory.extend(memory[key])
	
			for page in update_memory:
				startAddr = page.getStartAddr()
				size = int(page.getSize() / 4)
				examine_command = "x/" + str(size) + "uw " + str(hex(startAddr))
				addresses = gdb.execute(examine_command, False, True)
				addresses = [elem for elem in re.split("[\n\t]", addresses)[:-1]]
				# print(addresses)
				addresses = [int(elem).to_bytes(4, byteorder='little') for elem in addresses if ":" not in elem]
				
				for s in addresses:
					self.context.setConcreteMemoryAreaValue(startAddr, s)
					startAddr += 4


		def castGDBValue(value):
			if int(value) < 0:
				value = int(value) + (1 << 64)
			return int(value)

		def restoreContext():
			print("TYPE : " + str((gdb.parse_and_eval('$rax')).type))
			self.context.setConcreteRegisterValue(self.context.registers.rax, castGDBValue((gdb.parse_and_eval('$rax'))))
			self.context.setConcreteRegisterValue(self.context.registers.rbx, castGDBValue((gdb.parse_and_eval('$rbx'))))
			self.context.setConcreteRegisterValue(self.context.registers.rcx, castGDBValue((gdb.parse_and_eval('$rcx'))))
			self.context.setConcreteRegisterValue(self.context.registers.rdx, castGDBValue((gdb.parse_and_eval('$rdx'))))
			self.context.setConcreteRegisterValue(self.context.registers.rsp, castGDBValue(gdb.parse_and_eval('$rsp')))
			self.context.setConcreteRegisterValue(self.context.registers.rbp, castGDBValue((gdb.parse_and_eval('$rbp'))))
			self.context.setConcreteRegisterValue(self.context.registers.rdi, castGDBValue((gdb.parse_and_eval('$rdi'))))
			self.context.setConcreteRegisterValue(self.context.registers.rsi, castGDBValue((gdb.parse_and_eval('$rsi'))))
			self.context.setConcreteRegisterValue(self.context.registers.r8, castGDBValue((gdb.parse_and_eval('$r8'))))
			self.context.setConcreteRegisterValue(self.context.registers.r9, castGDBValue((gdb.parse_and_eval('$r9'))))
			self.context.setConcreteRegisterValue(self.context.registers.r10, castGDBValue((gdb.parse_and_eval('$r10'))))
			self.context.setConcreteRegisterValue(self.context.registers.r11, castGDBValue((gdb.parse_and_eval('$r11'))))
			self.context.setConcreteRegisterValue(self.context.registers.r12, castGDBValue((gdb.parse_and_eval('$r12'))))
			self.context.setConcreteRegisterValue(self.context.registers.r13, castGDBValue((gdb.parse_and_eval('$r13'))))
			self.context.setConcreteRegisterValue(self.context.registers.r14, castGDBValue((gdb.parse_and_eval('$r14'))))
			self.context.setConcreteRegisterValue(self.context.registers.r15, castGDBValue((gdb.parse_and_eval('$r15'))))
			self.context.setConcreteRegisterValue(self.context.registers.rip, castGDBValue((gdb.parse_and_eval('$rip'))))
			self.context.setConcreteRegisterValue(self.context.registers.eflags, castGDBValue(gdb.parse_and_eval('$eflags')))

		def onBasicBlockFound(addr):
			nonlocal numNewBasicBlocks
			nonlocal newBasicBlocksFound
			nonlocal basicBlocksPathFoundThisRun

			# print(f"{hex(addr)}")
			basicBlocksPathFoundThisRun.append(addr)
			# Is this a new basic block ?
			if addr not in self.allBlocksFound:
				numNewBasicBlocks += 1
				newBasicBlocksFound.add(addr)
				self.allBlocksFound.add(addr)

		onBasicBlockFound(currentBBlockAddr)

		logging.info('[+] Starting emulation.')
		# pdb.set_trace()
		# while pc and (pc >= self.codeSection_begin and pc <= self.codeSection_end):
		# pdb.set_trace()
		gdb_pc = (castGDBValue(gdb.parse_and_eval('$rip')))
		while pc < gdb_pc:
			opcode = self.context.getConcreteMemoryAreaValue(pc, 16)

			# Create the ctx instruction
			instruction = Instruction()
			instruction.setOpcode(opcode)
			instruction.setAddress(pc)

			self.context.processing(instruction)
			logging.info(instruction)

			self.hookingHandler(pc)

			# Next
			prevpc = pc
			pc = self.context.getConcreteRegisterValue(self.context.registers.rip)

		while pc:
			# Fetch opcode
			opcode = self.context.getConcreteMemoryAreaValue(pc, 16)

			# Create the ctx instruction
			instruction = Instruction()
			instruction.setOpcode(opcode)
			instruction.setAddress(pc)

			# Process
			print("Instruction: " + str(instruction) + " : " + hex(gdb.parse_and_eval('$rip')))
			self.context.processing(instruction)
			logging.info(instruction)

			self.hookingHandler(pc)

			# Next
			prevpc = pc
			pc = self.context.getConcreteRegisterValue(self.context.registers.rip)

			# ma folosesc si de contorul din gdb pentru ca Triton nu vede daca codul o ia pe aratura
			
			gdb_pc = castGDBValue(gdb.parse_and_eval('$rip'))
			print("pc :  BASE_EXEC : END_EXEC => " + hex(pc) + " : " + hex(BASE_EXEC) + " : " + hex(END_EXEC))
			b = (pc >= END_EXEC or pc <= BASE_EXEC)
			print("Bool : "  + str(	b))
			
			# if-ul asta se poate scrie mai frumos. E ceva cod duplicat.
			if (not (gdb_pc >= END_EXEC or gdb_pc <= BASE_EXEC)):
				gdb.execute("stepi")
				restoreContext()

			gdb_pc = castGDBValue(gdb.parse_and_eval('$rip'))
			if (gdb_pc >= END_EXEC or gdb_pc <= BASE_EXEC):
				pc = gdb_pc


				if gdb.block_for_pc(pc) is None:
					print("Finish " + str(hex(pc)), file=sys.stderr)
					gdb.execute("finish")
				else:
					print("Finish NEXT " + str(hex(pc)), file=sys.stderr)
					while ((pc >= END_EXEC or pc <= BASE_EXEC) and gdb.selected_inferior().pid != 0):
						gdb.execute("next")
					
					if gdb.selected_inferior().pid == 0:
						break
					pc = (castGDBValue(gdb.parse_and_eval('$rip')))


				if gdb.selected_inferior().pid == 0:
					break
				restoreContext()
				updateMemory(MAPPINGS, NAME_EXEC)

			if instruction.isControlFlow():
				currentBBlockAddr = pc
				onBasicBlockFound(currentBBlockAddr)
				print(instruction)
				print(instruction.getOperands())
				
			if self.TARGET_TO_REACH is not None and pc == self.TARGET_TO_REACH:
				targetAddressFound = True

		logging.info('[+] Emulation done.')
		if countBBlocks:
			logging.info(f'===== New basic blocks found: {[hex(intBlock) for intBlock in newBasicBlocksFound]}')

		if basicBlocksPathFoundThisRun[-1] == 0: # ret instruction
			basicBlocksPathFoundThisRun = basicBlocksPathFoundThisRun[:-1]
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
			byteAddr = INPUT_BUFFER_ADDRESS + byteIndex

			if symbolized:
				# If not needed to reset symbolic state, just take the variable from the cache store and set its current value
				if self.resetSymbolicMemoryAtEachRun: # Not used anymore
					self.context.setConcreteMemoryValue(byteAddr, value)
					self.context.symbolizeMemory(MemoryAccess(byteAddr, CPUSIZE.BYTE))
				else:
					self.context.setConcreteVariableValue(self.symbolicVariablesCache[byteIndex], value)
					assert self.context.getConcreteMemoryValue(MemoryAccess(byteAddr, CPUSIZE.BYTE)) == value

		# Continuous area level
		def symbolizeAndConcretizeArea(addr, values):
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
		return self.__emulate(self.entryFuncAddr, countBBlocks=countBBlocks)

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

		def createMemoryDict():
			memory = {}
			info_mappings = gdb.execute("info proc mappings", False, True)
			info_mappings = info_mappings.split('\n')
			# se pastreaza tot fara header si ultimul element care este None
			info_mappings = [x.split() for x in info_mappings[4:-1]]

			for elem in info_mappings:
				page, name = createPage(elem)
				if name not in memory:
					memory[name] = []
				memory[name].append(page)

			return memory

		outEntryFuncAddr = None
		# gdb.execute("set args /home/ubuntu/Desktop/licenta/river/River3/TestPrograms/libxml2-v2.9.2/input-files/emptyArray")
		# gdb.execute("set args elite")
		gdb.execute("start")

		# gdb.execute("set scheduler-locking on")

		MAPPINGS = createMemoryDict()

		info_exec = gdb.execute("info proc exe", False, True)
		NAME_EXEC = (info_exec.split("exe = ")[1]).split('\n')[0].replace('\'', '')
		exec_mapping = MAPPINGS[NAME_EXEC]

		for i in range(len(exec_mapping)):
			SIZE += exec_mapping[i].getSize()

		BASE_EXEC = exec_mapping[0].getStartAddr()
		print("BASE : " + hex(BASE_EXEC))
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

		print(hex(outEntryFuncAddr))
		print(hex(outEntryFuncAddr + BASE_EXEC))
		if hex(outEntryFuncAddr) < hex(BASE_EXEC):
			outEntryFuncAddr = outEntryFuncAddr + BASE_EXEC
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
				logging.info('[+] Loading 0x%06x - 0x%06x' % (vaddr, vaddr + size))
				tracersInstances[tracerIndex].context.setConcreteMemoryAreaValue(vaddr, phdr.content)
				#assert False, "Check where is stack and heap and reset them "

			RiverTracer.makeRelocation(binary, tracersInstances[tracerIndex].context)

	@staticmethod
	def makeRelocation(binary, tritonContext):
		import lief
		global BASE_EXEC
		# ldd <binary>
		# linux-vdso.so.1 (0x00007ffe3a524000)
		# libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007fc961d59000)
		# libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fc9619bb000)
		# libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fc9617a3000)
		# libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fc9613b2000)
		# /lib64/ld-linux-x86-64.so.2 (0x00007fc96212d000)

		# libc = lief.parse("/usr/lib/x86_64-linux-gnu/libc.so.6")

		# phdrs  = libc.segments
		# for phdr in phdrs:
		# 	size = phdr.physical_size
		# 	vaddr  = BASE_EXEC + phdr.virtual_address
		# 	print('Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
		# 	tritonContext.setConcreteMemoryAreaValue(vaddr, phdr.content)

		# phdrs  = libstdc.segments
		# for phdr in phdrs:
		# 	size = phdr.physical_size
		# 	vaddr  = BASE_LIBSTDC + phdr.virtual_address
		# 	print('Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
		# 	tritonContext.setConcreteMemoryAreaValue(vaddr, phdr.content)

		# phdrs  = ld.segments
		# for phdr in phdrs:
		# 	size = phdr.physical_size
		# 	vaddr  = BASE_LD + phdr.virtual_address
		# 	print('Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
		# 	tritonContext.setConcreteMemoryAreaValue(vaddr, phdr.content)

		# phdrs  = libgcc.segments
		# for phdr in phdrs:
		# 	size = phdr.physical_size
		# 	vaddr  = BASE_LIBGCC + phdr.virtual_address
		# 	print('Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
		# 	tritonContext.setConcreteMemoryAreaValue(vaddr, phdr.content)

		# phdrs  = libm.segments
		# for phdr in phdrs:
		# 	size = phdr.physical_size
		# 	vaddr  = BASE_LIBM + phdr.virtual_address
		# 	print('Loading 0x%06x - 0x%06x' %(vaddr, vaddr+size))
		# 	tritonContext.setConcreteMemoryAreaValue(vaddr, phdr.content)

		# let_bind = [
		# 	"printf",
		# 	"dprintf",
		# 	"strlen",
		# 	"vprintf",
		# 	"psiginfo",
		# 	"strchrnul",
		# 	"strchr",
		# 	"j_strchrnul"
		# ]

		# relocations = []
		# for rel in binary.relocations:
			# relocations.append(rel)
		# relocations = [x for x in binary.pltgot_relocations]
		# relocations.extend([x for x in binary.dynamic_relocations])

		# for rel in [x for x in libc.pltgot_relocations]:
		# 	if rel.has_symbol:
		# 		print(str(rel.symbol))
		# 	else:
		# 		print(rel.type)
		# relocations.extend([x for x in libc.dynamic_relocations])
		# Perform our own relocations
		# for rel in relocations:
		# 	symbolName = rel.symbol.name
		# 	symbolRelo = rel.address
		# 	if symbolName in let_bind:
		# 		print(f"Hooking {symbolName}")
		# 		libc_sym_addr = libc.get_symbol(symbolName).value
		# 		print(f"name {symbolName} addr {hex(libc_sym_addr)} res {hex(BASE_EXEC + libc_sym_addr)}")
		# 		tritonContext.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), BASE_LIBC + libc_sym_addr)
		# 	else:
		# 		for crel in customRelocation:
		# 			if symbolName == crel[0]:
		# 				print('[+] Hooking %s' %(symbolName))
		# 				tritonContext.setConcreteMemoryValue(MemoryAccess(symbolRelo, CPUSIZE.QWORD), crel[2])
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

BASE_EXEC = 0
END_EXEC = 0
SIZE = 0
IS_NORMAL = True

MAPPINGS = {}
NAME_EXEC = None

BASE_STACK = 0x9fffffff

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
