# Mandalorian Core - the capability gate.
#
# The previous version of this file listed a helm-mandalorian-test target
# pointing at tests/helm_gate_test.c, which does not exist, and linked against
# a `beskarcore` target that no CMakeLists in the tree defined. Both made the
# configure step fail.
#
# libsodium is no longer looked for: nothing here uses it. Capability and
# receipt authentication is HMAC-SHA3-256 over the project's own SHA3, which
# removes the optional-dependency branch that previously decided at build time
# whether the crypto was real.

add_library(mandalorian_core STATIC
    core/gate.c
    core/verifier.c
    core/policy.c
    core/receipt.c
    capabilities/issuer.c
    runtime/executor.c
    agent/openclaw-adapter.c
    crypto/hmac_sha3.c
    stubs.c
)

target_include_directories(mandalorian_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/capabilities
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
)

target_link_libraries(mandalorian_core PUBLIC beskarcore)

if(BUILD_DEMOS)
    add_executable(constrained-agent-demo examples/constrained-agent-demo.c)
    target_link_libraries(constrained-agent-demo PRIVATE mandalorian_core)
endif()

install(TARGETS mandalorian_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)
