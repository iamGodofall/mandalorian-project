# Test suite.
#
# The previous version of this file had three add_executable/target_link/add_test
# groups written on one line with literal "\n" characters between them, which is
# a CMake parse error — so `cmake -B build` failed at the root for everyone.
#
# The cmocka-based tests under unit/ need a vendored cmocka at external/cmocka
# that is not in the repository and is not fetched by anything, so they are
# built only when cmocka is actually found rather than breaking the build.

# ---------------------------------------------------------------------------
# Tests with no external dependencies. These run everywhere, including CI.
# ---------------------------------------------------------------------------

add_executable(test_sha3_vectors unit/test_sha3_vectors.c)
target_link_libraries(test_sha3_vectors PRIVATE beskarcore)
add_test(NAME Sha3Vectors COMMAND test_sha3_vectors)

add_executable(test_secure_random unit/test_secure_random.c)
target_link_libraries(test_secure_random PRIVATE beskarcore)
add_test(NAME SecureRandom COMMAND test_secure_random)

add_executable(test_gate_enforcement unit/test_gate_enforcement.c)
target_link_libraries(test_gate_enforcement PRIVATE mandalorian_core)
add_test(NAME GateEnforcement COMMAND test_gate_enforcement)

# simple_test.c links no project code at all — every assertion in it compares
# literals (`int guardian = 0; TEST_ASSERT(guardian == 0, ...)`) with the real
# call commented out. It is kept because it exercises the harness itself, but
# it is NOT evidence that anything in the project works, and the README badge
# should not be read as if it were.
add_executable(simple_test comprehensive/simple_test.c)
add_test(NAME SimpleHarnessSelfCheck COMMAND simple_test)

# ---------------------------------------------------------------------------
# Demo executables run as smoke tests: each returns non-zero on failure.
# ---------------------------------------------------------------------------

if(BUILD_DEMOS)
    add_test(NAME GateDemo COMMAND constrained-agent-demo)
    add_test(NAME BeskarCoreDemo COMMAND demo)
    add_test(NAME VaultDemo COMMAND demo_beskar_vault)
    add_test(NAME LinkDemo COMMAND demo_beskar_link)
    add_test(NAME EnterpriseDemo COMMAND demo_beskar_enterprise)
    add_test(NAME GuardianDemo COMMAND demo_continuous_guardian)
    add_test(NAME HelmDemo COMMAND demo_helm)
endif()

# ---------------------------------------------------------------------------
# cmocka-based tests, only if cmocka is present.
# ---------------------------------------------------------------------------

find_library(CMOCKA_LIBRARY cmocka)
find_path(CMOCKA_INCLUDE_DIR cmocka.h)

if(CMOCKA_LIBRARY AND CMOCKA_INCLUDE_DIR)
    message(STATUS "cmocka found - building unit tests that depend on it")
    foreach(t test_crypto test_ledger test_runtime test_security test_performance)
        add_executable(${t} unit/${t}.c)
        target_include_directories(${t} PRIVATE ${CMOCKA_INCLUDE_DIR})
        target_link_libraries(${t} PRIVATE beskarcore veridianos aegis ${CMOCKA_LIBRARY})
        add_test(NAME ${t} COMMAND ${t})
    endforeach()
else()
    message(STATUS "cmocka not found - skipping unit/test_{crypto,ledger,runtime,security,performance}.c")
endif()

# ---------------------------------------------------------------------------
# Fuzzing, opt-in and clang-only.
# ---------------------------------------------------------------------------

option(ENABLE_FUZZING "Build libFuzzer targets (requires clang)" OFF)

if(ENABLE_FUZZING)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_executable(fuzz_vault fuzz/fuzz_vault.c)
        target_link_libraries(fuzz_vault PRIVATE beskarcore)
        target_compile_options(fuzz_vault PRIVATE -fsanitize=fuzzer,address)
        target_link_options(fuzz_vault PRIVATE -fsanitize=fuzzer,address)
        add_test(NAME FuzzVault COMMAND fuzz_vault -max_total_time=30)
    else()
        message(WARNING "ENABLE_FUZZING requires clang; skipping fuzz targets")
    endif()
endif()
