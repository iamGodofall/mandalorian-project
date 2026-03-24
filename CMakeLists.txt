cmake_minimum_required(VERSION 3.10)
project(MandalorianProject)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add subdirectories with CMakeLists.txt
add_subdirectory(mandalorian)
add_subdirectory(beskarcore/seL4)
add_subdirectory(tests)
