# Helm - post-quantum sovereign attestation co-processor (host build).

add_library(helm STATIC
    src/attestation.c
    src/helm.c
    src/capability.c
    src/monitoring.c
)

target_include_directories(helm
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# capability.c calls into the Mandalorian gate, and helm.h includes gate.h.
target_link_libraries(helm PUBLIC beskarcore mandalorian_core)

if(BUILD_DEMOS)
    add_executable(demo_helm demo_helm.c)
    target_link_libraries(demo_helm PRIVATE helm)
endif()
