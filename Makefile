# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.5

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ciprian/testtools/river

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ciprian/testtools/river

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/usr/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: install/local

.PHONY : install/local/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/usr/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components

.PHONY : list_install_components/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ciprian/testtools/river/CMakeFiles /home/ciprian/testtools/river/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/ciprian/testtools/river/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named binloader

# Build rule for target.
binloader: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 binloader
.PHONY : binloader

# fast build rule for target.
binloader/fast:
	$(MAKE) -f BinLoader/CMakeFiles/binloader.dir/build.make BinLoader/CMakeFiles/binloader.dir/build
.PHONY : binloader/fast

#=============================================================================
# Target rules for targets named virtualmemory

# Build rule for target.
virtualmemory: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 virtualmemory
.PHONY : virtualmemory

# fast build rule for target.
virtualmemory/fast:
	$(MAKE) -f VirtualMemory/CMakeFiles/virtualmemory.dir/build.make VirtualMemory/CMakeFiles/virtualmemory.dir/build
.PHONY : virtualmemory/fast

#=============================================================================
# Target rules for targets named wrappersetup

# Build rule for target.
wrappersetup: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 wrappersetup
.PHONY : wrappersetup

# fast build rule for target.
wrappersetup/fast:
	$(MAKE) -f wrapper.setup/CMakeFiles/wrappersetup.dir/build.make wrapper.setup/CMakeFiles/wrappersetup.dir/build
.PHONY : wrappersetup/fast

#=============================================================================
# Target rules for targets named revtracerwrapper

# Build rule for target.
revtracerwrapper: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 revtracerwrapper
.PHONY : revtracerwrapper

# fast build rule for target.
revtracerwrapper/fast:
	$(MAKE) -f revtracer-wrapper/CMakeFiles/revtracerwrapper.dir/build.make revtracer-wrapper/CMakeFiles/revtracerwrapper.dir/build
.PHONY : revtracerwrapper/fast

# Manual pre-install relink rule for target.
revtracerwrapper/preinstall:
	$(MAKE) -f revtracer-wrapper/CMakeFiles/revtracerwrapper.dir/build.make revtracer-wrapper/CMakeFiles/revtracerwrapper.dir/preinstall
.PHONY : revtracerwrapper/preinstall

#=============================================================================
# Target rules for targets named revtracer

# Build rule for target.
revtracer: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 revtracer
.PHONY : revtracer

# fast build rule for target.
revtracer/fast:
	$(MAKE) -f revtracer/CMakeFiles/revtracer.dir/build.make revtracer/CMakeFiles/revtracer.dir/build
.PHONY : revtracer/fast

#=============================================================================
# Target rules for targets named ipc

# Build rule for target.
ipc: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 ipc
.PHONY : ipc

# fast build rule for target.
ipc/fast:
	$(MAKE) -f ipclib/CMakeFiles/ipc.dir/build.make ipclib/CMakeFiles/ipc.dir/build
.PHONY : ipc/fast

#=============================================================================
# Target rules for targets named execution

# Build rule for target.
execution: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 execution
.PHONY : execution

# fast build rule for target.
execution/fast:
	$(MAKE) -f Execution/CMakeFiles/execution.dir/build.make Execution/CMakeFiles/execution.dir/build
.PHONY : execution/fast

# Manual pre-install relink rule for target.
execution/preinstall:
	$(MAKE) -f Execution/CMakeFiles/execution.dir/build.make Execution/CMakeFiles/execution.dir/preinstall
.PHONY : execution/preinstall

#=============================================================================
# Target rules for targets named loader

# Build rule for target.
loader: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 loader
.PHONY : loader

# fast build rule for target.
loader/fast:
	$(MAKE) -f loader/CMakeFiles/loader.dir/build.make loader/CMakeFiles/loader.dir/build
.PHONY : loader/fast

# Manual pre-install relink rule for target.
loader/preinstall:
	$(MAKE) -f loader/CMakeFiles/loader.dir/build.make loader/CMakeFiles/loader.dir/preinstall
.PHONY : loader/preinstall

#=============================================================================
# Target rules for targets named symbolicenvironment

# Build rule for target.
symbolicenvironment: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 symbolicenvironment
.PHONY : symbolicenvironment

# fast build rule for target.
symbolicenvironment/fast:
	$(MAKE) -f SymbolicEnvironment/CMakeFiles/symbolicenvironment.dir/build.make SymbolicEnvironment/CMakeFiles/symbolicenvironment.dir/build
.PHONY : symbolicenvironment/fast

#=============================================================================
# Target rules for targets named fmi

# Build rule for target.
fmi: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 fmi
.PHONY : fmi

# fast build rule for target.
fmi/fast:
	$(MAKE) -f benchmarking-payload/fmi/CMakeFiles/fmi.dir/build.make benchmarking-payload/fmi/CMakeFiles/fmi.dir/build
.PHONY : fmi/fast

#=============================================================================
# Target rules for targets named logger

# Build rule for target.
logger: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 logger
.PHONY : logger

# fast build rule for target.
logger/fast:
	$(MAKE) -f river.format/logger/CMakeFiles/logger.dir/build.make river.format/logger/CMakeFiles/logger.dir/build
.PHONY : logger/fast

#=============================================================================
# Target rules for targets named format.handler

# Build rule for target.
format.handler: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 format.handler
.PHONY : format.handler

# fast build rule for target.
format.handler/fast:
	$(MAKE) -f river.format/format.handler/CMakeFiles/format.handler.dir/build.make river.format/format.handler/CMakeFiles/format.handler.dir/build
.PHONY : format.handler/fast

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... install/local"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... install"
	@echo "... list_install_components"
	@echo "... binloader"
	@echo "... virtualmemory"
	@echo "... wrappersetup"
	@echo "... revtracerwrapper"
	@echo "... revtracer"
	@echo "... ipc"
	@echo "... execution"
	@echo "... loader"
	@echo "... symbolicenvironment"
	@echo "... fmi"
	@echo "... logger"
	@echo "... format.handler"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

