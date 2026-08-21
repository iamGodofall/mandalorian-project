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
#
# hmac_sha3 moved to beskarcore, next to the SHA3 it is built on. It had been
# here, one layer above beskarcore, which left beskarcore unable to use it —
# so beskar_vault.c hand-rolled SHA3(data || key) instead of calling the
# reviewed and tested MAC that already existed in the tree.

add_library(mandalorian_core STATIC
    core/gate.c
    core/verifier.c
    core/policy.c
    core/receipt.c
    capabilities/issuer.c
    runtime/executor.c
    agent/openclaw-adapter.c
    stubs.c
)

target_include_directories(mandalorian_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/capabilities
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
