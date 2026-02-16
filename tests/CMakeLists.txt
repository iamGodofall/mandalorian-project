cmake_minimum_required(VERSION 3.10)
project(MandalorianTests)

# Find CMocka package
find_package(cmocka REQUIRED)

# Glob test sources
file(GLOB UNIT_TEST_SOURCES "unit/*.c")
file(GLOB PERFORMANCE_TEST_SOURCES "performance/*.c")
file(GLOB INTEGRATION_TEST_SOURCES "integration/*.c")

# Create unit test executable
add_executable(unit_tests ${UNIT_TEST_SOURCES})
target_link_libraries(unit_tests PRIVATE cmocka::cmocka)

# Create performance test executable
add_executable(performance_tests ${PERFORMANCE_TEST_SOURCES})
target_link_libraries(performance_tests PRIVATE cmocka::cmocka)

# Create integration test executable
add_executable(integration_tests ${INTEGRATION_TEST_SOURCES})
target_link_libraries(integration_tests PRIVATE cmocka::cmocka)

# Add test targets
add_test(NAME unit_tests COMMAND unit_tests)
add_test(NAME performance_tests COMMAND performance_tests)
add_test(NAME integration_tests COMMAND integration_tests)
