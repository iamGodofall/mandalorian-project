# Mandalorian Project Test Suite
# Build and run all tests

CMOCKA_DIR = ../external/cmocka
BUILD_DIR = build
SRC_DIR = ..

# Compiler flags
CFLAGS = -I$(CMOCKA_DIR)/include -I$(SRC_DIR)/beskarcore/include -I$(SRC_DIR)/veridianos/include -I$(SRC_DIR)/aegis/include
LDFLAGS = -L$(CMOCKA_DIR)/lib -lcmocka

# Test executables
UNIT_TESTS = $(BUILD_DIR)/test_crypto $(BUILD_DIR)/test_ledger $(BUILD_DIR)/test_runtime
INTEGRATION_TESTS = $(BUILD_DIR)/test_system_integration
PERFORMANCE_TESTS = $(BUILD_DIR)/test_performance

.PHONY: all unit integration performance clean

all: unit integration performance

unit: $(UNIT_TESTS)
	@echo "Running unit tests..."
	@for test in $(UNIT_TESTS); do \
		if [ -f $$test ]; then \
			echo "Running $$test..."; \
			$$test || exit 1; \
		fi; \
	done

integration: $(INTEGRATION_TESTS)
	@echo "Running integration tests..."
	@for test in $(INTEGRATION_TESTS); do \
		if [ -f $$test ]; then \
			echo "Running $$test..."; \
			$$test || exit 1; \
		fi; \
	done

performance: $(PERFORMANCE_TESTS)
	@echo "Running performance tests..."
	@for test in $(PERFORMANCE_TESTS); do \
		if [ -f $$test ]; then \
			echo "Running $$test..."; \
			$$test || exit 1; \
		fi; \
	done

$(BUILD_DIR)/test_crypto: unit/test_crypto.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_ledger: unit/test_ledger.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_runtime: unit/test_runtime.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_system_integration: integration/test_system.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_performance: performance/test_performance.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_security: unit/test_security.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR)/test_system: integration/test_system.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

# Test coverage (requires gcov)
coverage: CFLAGS += -fprofile-arcs -ftest-coverage
coverage: LDFLAGS += -lgcov
coverage: clean all
	@echo "Generating coverage report..."
	@lcov --capture --directory $(BUILD_DIR) --output-file coverage.info
	@genhtml coverage.info --output-directory coverage_report
	@echo "Coverage report generated in coverage_report/"

# Valgrind memory checks
memcheck: all
	@echo "Running memory checks..."
	@for test in $(UNIT_TESTS) $(INTEGRATION_TESTS); do \
		if [ -f $$test ]; then \
			echo "Checking $$test..."; \
			valgrind --leak-check=full --error-exitcode=1 $$test || exit 1; \
		fi; \
	done

# Static analysis
analyze:
	@echo "Running static analysis..."
	@cppcheck --enable=all --std=c99 --platform=unix64 \
		-I$(SRC_DIR)/beskarcore/include \
		-I$(SRC_DIR)/veridianos/include \
		-I$(SRC_DIR)/aegis/include \
		$(SRC_DIR)/beskarcore/src/ \
		$(SRC_DIR)/veridianos/src/ \
		$(SRC_DIR)/aegis/src/ \
		--suppress=missingIncludeSystem

# Fuzz testing (requires AFL)
fuzz:
	@echo "Building fuzz tests..."
	# AFL instrumentation would be added here
