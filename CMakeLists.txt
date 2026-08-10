cmake_minimum_required(VERSION 3.16)
project(MandalorianProject VERSION 1.0.0 LANGUAGES C)

#
# Host build.
#
# This configures the parts of the system that run on a normal machine:
# BeskarCore, Helm, Aegis, VeridianOS and the Mandalorian gate, plus their
# demos and tests. It does NOT build the seL4/CAmkES target image — that needs
# the seL4 toolchain and is driven from beskarcore/Makefile.
#
# The previous root CMakeLists did `add_subdirectory(beskarcore/seL4)`, which
# is the submodule checkout and has no CMakeLists of its own, so `cmake -B
# build` failed at configure time on every clean clone.
#

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_SANITIZERS "Build with AddressSanitizer and UBSan" OFF)
option(ENABLE_COVERAGE "Build with coverage instrumentation" OFF)
option(BUILD_DEMOS "Build the demo executables" ON)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
endif()

if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

if(ENABLE_COVERAGE)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

find_package(Threads REQUIRED)

add_subdirectory(beskarcore)
add_subdirectory(helm)
add_subdirectory(aegis)
add_subdirectory(veridianos)
add_subdirectory(mandalorian)

enable_testing()
add_subdirectory(tests)
