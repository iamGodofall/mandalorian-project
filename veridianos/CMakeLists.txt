# VeridianOS - Android/iOS sandbox runtime (host build).

add_library(veridianos STATIC
    src/u_runtime.c
    src/android_runtime.c
    src/app_sandbox.c
)

target_include_directories(veridianos PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(veridianos PUBLIC beskarcore)

if(BUILD_DEMOS)
    add_executable(veridianos_demo demo.c)
    target_link_libraries(veridianos_demo PRIVATE veridianos aegis)

    # simple_demo defines its own local stand-ins for the runtime and aegis
    # entry points, so it deliberately links against neither.
    add_executable(veridianos_simple_demo simple_demo.c)
endif()
