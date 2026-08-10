# BeskarCore - seL4-based betrayal-resistant foundation (host build).

add_library(beskarcore STATIC
    src/sha3.c
    src/merkle_ledger.c
    src/logging.c
    src/monitoring.c
    src/performance.c
    src/error_recovery.c
    src/verified_boot.c
    src/continuous_guardian.c
    src/beskar_vault.c
    src/beskar_app_guard.c
    src/beskar_link.c
    src/beskar_enterprise.c
    src/boot_rom.c
    src/dummy_app.c
)

target_include_directories(beskarcore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(beskarcore PUBLIC Threads::Threads)

if(BUILD_DEMOS)
    foreach(d demo demo_beskar_vault demo_beskar_link demo_beskar_enterprise demo_continuous_guardian)
        add_executable(${d} ${d}.c)
        target_link_libraries(${d} PRIVATE beskarcore)
    endforeach()

    # The system entry point. Named beskarcore_main so it does not collide
    # with any other target called "main".
    add_executable(beskarcore_main src/main.c)
    target_link_libraries(beskarcore_main PRIVATE beskarcore)
endif()
