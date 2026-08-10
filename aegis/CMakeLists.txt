# Aegis - IPC monitoring and consent enforcement (host build).

add_library(aegis STATIC
    src/monitor.c
    src/shield_ledger_adapter.c
)

target_include_directories(aegis PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(aegis PUBLIC beskarcore helm)
