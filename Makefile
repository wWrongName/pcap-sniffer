# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

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
CMAKE_SOURCE_DIR = /home/john/repos/pcap-sniffer

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/john/repos/pcap-sniffer

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "No interactive CMake dialog available..."
	/usr/bin/cmake -E echo No\ interactive\ CMake\ dialog\ available.
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/john/repos/pcap-sniffer/CMakeFiles /home/john/repos/pcap-sniffer/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/john/repos/pcap-sniffer/CMakeFiles 0
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
# Target rules for targets named s_func

# Build rule for target.
s_func: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 s_func
.PHONY : s_func

# fast build rule for target.
s_func/fast:
	$(MAKE) -f CMakeFiles/s_func.dir/build.make CMakeFiles/s_func.dir/build
.PHONY : s_func/fast

#=============================================================================
# Target rules for targets named sniffer

# Build rule for target.
sniffer: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 sniffer
.PHONY : sniffer

# fast build rule for target.
sniffer/fast:
	$(MAKE) -f CMakeFiles/sniffer.dir/build.make CMakeFiles/sniffer.dir/build
.PHONY : sniffer/fast

s_func.o: s_func.c.o

.PHONY : s_func.o

# target to build an object file
s_func.c.o:
	$(MAKE) -f CMakeFiles/s_func.dir/build.make CMakeFiles/s_func.dir/s_func.c.o
.PHONY : s_func.c.o

s_func.i: s_func.c.i

.PHONY : s_func.i

# target to preprocess a source file
s_func.c.i:
	$(MAKE) -f CMakeFiles/s_func.dir/build.make CMakeFiles/s_func.dir/s_func.c.i
.PHONY : s_func.c.i

s_func.s: s_func.c.s

.PHONY : s_func.s

# target to generate assembly for a file
s_func.c.s:
	$(MAKE) -f CMakeFiles/s_func.dir/build.make CMakeFiles/s_func.dir/s_func.c.s
.PHONY : s_func.c.s

sniff.o: sniff.c.o

.PHONY : sniff.o

# target to build an object file
sniff.c.o:
	$(MAKE) -f CMakeFiles/sniffer.dir/build.make CMakeFiles/sniffer.dir/sniff.c.o
.PHONY : sniff.c.o

sniff.i: sniff.c.i

.PHONY : sniff.i

# target to preprocess a source file
sniff.c.i:
	$(MAKE) -f CMakeFiles/sniffer.dir/build.make CMakeFiles/sniffer.dir/sniff.c.i
.PHONY : sniff.c.i

sniff.s: sniff.c.s

.PHONY : sniff.s

# target to generate assembly for a file
sniff.c.s:
	$(MAKE) -f CMakeFiles/sniffer.dir/build.make CMakeFiles/sniffer.dir/sniff.c.s
.PHONY : sniff.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... s_func"
	@echo "... rebuild_cache"
	@echo "... sniffer"
	@echo "... s_func.o"
	@echo "... s_func.i"
	@echo "... s_func.s"
	@echo "... sniff.o"
	@echo "... sniff.i"
	@echo "... sniff.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

