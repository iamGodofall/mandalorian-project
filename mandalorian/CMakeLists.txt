cmake_minimum_required(VERSION 3.10)
project(MandalorianCore)

# Find libsodium (optional - stubs used if missing)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(SODIUM QUIET libsodium)
endif()
if(NOT SODIUM_FOUND)
  # Try vcpkg
  find_package(libsodium CONFIG)
  if(libsodium_FOUND)
    set(SODIUM_INCLUDE_DIRS ${libsodium_INCLUDE_DIRS})
    set(SODIUM_LIBRARIES ${libsodium_LIBRARIES})
  else()
    # Fallback find_library for Windows
    find_library(SODIUM_LIBRARY sodium HINTS "C:/vcpkg/installed/x64-windows/lib")
    find_path(SODIUM_INCLUDE_DIR sodium.h HINTS "C:/vcpkg/installed/x64-windows/include")
    if(SODIUM_LIBRARY AND SODIUM_INCLUDE_DIR)
      set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
      set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    else()
      message(WARNING "libsodium not found. Using crypto stubs.")
      add_definitions(-DUSE_CRYPTO_STUBS)
    endif()
  endif()
endif()

# Mandalorian core library
add_library(mandalorian_core STATIC
    capabilities/issuer.c
    core/gate.c
    core/verifier.c
    core/policy.c
    core/receipt.c
    runtime/executor.c
    agent/openclaw-adapter.c
    stubs.c # stubs.h compiled as c
)

target_include_directories(mandalorian_core PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(mandalorian_core 
    ${SODIUM_LIBRARIES}
    beskarcore # Link to BeskarCore libs
)

target_compile_options(mandalorian_core PRIVATE ${SODIUM_CFLAGS_OTHER})

# Demo executable
add_executable(constrained-agent-demo examples/constrained-agent-demo.c)
target_link_libraries(constrained-agent-demo mandalorian_core)

# Helm integration test
add_executable(helm-mandalorian-test tests/helm_gate_test.c)
target_link_libraries(helm-mandalorian-test mandalorian_core helm)

# Install
install(TARGETS mandalorian_core constrained-agent-demo
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

