# x86_64 Cross-Compilation Toolchain for Mandalorian Project

# Set the system name
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Specify the cross compiler
set(CMAKE_C_COMPILER x86_64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER x86_64-linux-gnu-g++)

# Set the sysroot if needed
# set(CMAKE_SYSROOT /path/to/x86_64/sysroot)

# Specify the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Set compiler flags for x86_64
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=x86-64 -mtune=generic -m64" CACHE STRING "C compiler flags")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -m64" CACHE STRING "CXX compiler flags")

# Set linker flags
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--gc-sections" CACHE STRING "Executable linker flags")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--gc-sections" CACHE STRING "Shared linker flags")

# Define the target triple
set(TARGET_TRIPLE "x86_64-linux-gnu")

message(STATUS "Cross-compiling for x86_64 using ${CMAKE_C_COMPILER}")
