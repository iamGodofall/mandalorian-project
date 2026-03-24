# CMakeLists.txt for Comprehensive Test Suite

cmake_minimum_required(VERSION 3.16)
project(MandalorianTests VERSION 1.0.0 LANGUAGES C)

# Options
option(ENABLE_FUZZING "Enable fuzzing tests" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan" OFF)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings (GCC/Clang only)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
elseif(MSVC)
    add_compile_options(/W4 /WX)
endif()


# Sanitizers
if(ENABLE_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# Coverage
if(ENABLE_COVERAGE)
    add_compile_options(--coverage)
    add_link_options(--coverage)
endif()

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/../beskarcore/include
    ${CMAKE_SOURCE_DIR}/../veridianos/include
    ${CMAKE_SOURCE_DIR}/../aegis/include
    ${CMAKE_SOURCE_DIR}/../helm/include
    ${CMAKE_SOURCE_DIR}/../mandalorian
)


# Test executable
add_executable(simple_test comprehensive/simple_test.c)
target_link_libraries(simple_test)
add_test(NAME SimpleTest COMMAND simple_test)

add_executable(comprehensive_test comprehensive/test_suite.c)\ntarget_link_libraries(comprehensive_test mandalorian_core beskarcore)\nadd_test(NAME ComprehensiveTest COMMAND comprehensive_test)\n\nadd_executable(test_mandalorian_gate comprehensive/test_mandalorian_gate.c)\ntarget_link_libraries(test_mandalorian_gate mandalorian_core beskarcore)\nadd_test(NAME MandalorianGateTest COMMAND test_mandalorian_gate)

# Fuzzing executable
if(ENABLE_FUZZING)
    add_executable(fuzz_vault fuzz/fuzz_vault.c)
    target_compile_options(fuzz_vault PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_vault PRIVATE -fsanitize=fuzzer)
endif()

# Fuzzing test (runs for limited time)
if(ENABLE_FUZZING)
    add_test(NAME FuzzVault COMMAND fuzz_vault -max_total_time=30)
endif()


# Custom targets
add_custom_target(run-tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS comprehensive_test
)

add_custom_target(run-fuzzing
    COMMAND fuzz_vault -max_total_time=300
    DEPENDS fuzz_vault
)

add_custom_target(coverage-report
    COMMAND lcov --capture --directory . --output-file coverage.info
    COMMAND lcov --remove coverage.info '/usr/*' --output-file coverage.info
    COMMAND lcov --list coverage.info
    DEPENDS run-tests
)
