# BeskarCore v1.0 Makefile
# Build for seL4 + CAmkES on RISC-V

SEL4_DIR = seL4
CAmkES_DIR = CAmkES
BUILD_DIR = build
TEST_DIR = ../tests
COVERAGE_DIR = coverage
ANALYSIS_DIR = analysis

# Default target: simulation
all: simulate

# Build for QEMU simulation (RISC-V 64-bit)
simulate: $(BUILD_DIR)/Makefile
	@echo "Building BeskarCore for QEMU simulation..."
	cd $(BUILD_DIR) && make -j$(nproc)
	@echo "Simulation build complete. Run with: make run_simulate"

# Configure build for simulation
$(BUILD_DIR)/Makefile:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake \
		-DCMAKE_TOOLCHAIN_FILE=../$(SEL4_DIR)/gcc.cmake \
		-DSEL4_PLATFORM=riscv64:qemu \
		-DCAmkES_ROOT=../$(CAmkES_DIR) \
		-DCAmkES_APP=../CAmkES/system.camkes \
		-DCAmkES_SEL4_CONFIG=../$(SEL4_DIR)/configs/RISCV64_verified.cmake \
		..

# Run simulation in QEMU
run_simulate: simulate
	@echo "Running BeskarCore in QEMU..."
	cd $(BUILD_DIR) && ./simulate

# Build for hardware (JH7110)
hardware: $(BUILD_DIR)/Makefile
	@echo "Building BeskarCore for JH7110 hardware..."
	cd $(BUILD_DIR) && make -j$(nproc)
	@echo "Hardware build complete"

# Build with debug symbols
debug: $(BUILD_DIR)/Makefile
	@echo "Building BeskarCore with debug symbols..."
	cd $(BUILD_DIR) && make -j$(nproc) VERBOSE=1 CMAKE_BUILD_TYPE=Debug
	@echo "Debug build complete"

# Build with optimizations
release: $(BUILD_DIR)/Makefile
	@echo "Building BeskarCore with optimizations..."
	cd $(BUILD_DIR) && make -j$(nproc) CMAKE_BUILD_TYPE=Release
	@echo "Release build complete"

# Run unit tests
test: $(BUILD_DIR)/Makefile
	@echo "Running unit tests..."
	cd $(BUILD_DIR) && make test
	@echo "Unit tests complete"

# Run tests with coverage
coverage: $(BUILD_DIR)/Makefile
	@echo "Building with coverage instrumentation..."
	cd $(BUILD_DIR) && make -j$(nproc) CMAKE_BUILD_TYPE=Coverage
	cd $(BUILD_DIR) && make test
	@echo "Generating coverage report..."
	cd $(BUILD_DIR) && make coverage
	@echo "Coverage report generated in $(BUILD_DIR)/coverage/"

# Static analysis
analyze: $(BUILD_DIR)/Makefile
	@echo "Running static analysis..."
	mkdir -p $(ANALYSIS_DIR)
	cppcheck --enable=all --std=c99 --platform=unix64 \
		-Iinclude \
		--xml \
		--xml-version=2 \
		src/ CAmkES/ 2> $(ANALYSIS_DIR)/cppcheck_results.xml
	@echo "Static analysis results saved to $(ANALYSIS_DIR)/cppcheck_results.xml"

# Memory checking with Valgrind (requires running system)
memcheck: simulate
	@echo "Running memory checks..."
	# Note: This would require a running system with Valgrind support
	@echo "Memory checking requires seL4 with Valgrind integration"

# Cross-compilation targets
cross-arm64: $(BUILD_DIR)/Makefile
	@echo "Cross-compiling for ARM64..."
	cd $(BUILD_DIR) && make -j$(nproc) CMAKE_TOOLCHAIN_FILE=../toolchains/arm64.cmake
	@echo "ARM64 cross-compilation complete"

cross-x86_64: $(BUILD_DIR)/Makefile
	@echo "Cross-compiling for x86_64..."
	cd $(BUILD_DIR) && make -j$(nproc) CMAKE_TOOLCHAIN_FILE=../toolchains/x86_64.cmake
	@echo "x86_64 cross-compilation complete"

# Dependency management
deps:
	@echo "Checking dependencies..."
	@command -v riscv64-unknown-elf-gcc >/dev/null 2>&1 || { echo "RISC-V toolchain not found. Install with: sudo apt install gcc-riscv64-unknown-elf"; exit 1; }
	@command -v cmake >/dev/null 2>&1 || { echo "CMake not found. Install with: sudo apt install cmake"; exit 1; }
	@command -v ninja-build >/dev/null 2>&1 || { echo "Ninja not found. Install with: sudo apt install ninja-build"; exit 1; }
	@echo "All dependencies satisfied"

# Update submodules
update-submodules:
	@echo "Updating git submodules..."
	git submodule update --init --recursive
	@echo "Submodules updated"

# Package for distribution
package: release
	@echo "Creating distribution package..."
	mkdir -p dist
	cd $(BUILD_DIR) && make package
	cp $(BUILD_DIR)/*.tar.gz dist/
	@echo "Package created in dist/"

# Install to system (requires root)
install: release
	@echo "Installing BeskarCore to system..."
	cd $(BUILD_DIR) && make install
	@echo "Installation complete"

# Uninstall from system (requires root)
uninstall:
	@echo "Uninstalling BeskarCore from system..."
	cd $(BUILD_DIR) && make uninstall
	@echo "Uninstallation complete"

# Documentation generation
docs:
	@echo "Generating documentation..."
	doxygen Doxyfile
	@echo "Documentation generated in docs/"

# Code formatting
format:
	@echo "Formatting code..."
	find src/ include/ -name "*.c" -o -name "*.h" | xargs clang-format -i
	@echo "Code formatting complete"

# Code linting
lint:
	@echo "Running code linter..."
	find src/ include/ -name "*.c" -o -name "*.h" | xargs clang-tidy --quiet
	@echo "Linting complete"

# Benchmarking
benchmark: simulate
	@echo "Running benchmarks..."
	# This would run performance benchmarks on the built system
	@echo "Benchmarking requires running system with benchmark suite"

# Security audit
audit:
	@echo "Running security audit..."
	mkdir -p $(ANALYSIS_DIR)
	# Run security-focused static analysis
	cppcheck --enable=warning,performance,information \
		--std=c99 --platform=unix64 \
		-Iinclude \
		--suppress=missingIncludeSystem \
		--check-config \
		src/ 2> $(ANALYSIS_DIR)/security_audit.txt
	@echo "Security audit results saved to $(ANALYSIS_DIR)/security_audit.txt"

# Development setup
setup-dev: deps update-submodules
	@echo "Development environment setup complete"
	@echo "Run 'make simulate' to build for QEMU"
	@echo "Run 'make hardware' to build for JH7110"

# CI/CD targets
ci-build: deps simulate test
	@echo "CI build complete"

ci-deploy: package
	@echo "CI deployment package ready"

# Help target
help:
	@echo "BeskarCore Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build for simulation (default)"
	@echo "  simulate         - Build for QEMU simulation"
	@echo "  run_simulate     - Run simulation in QEMU"
	@echo "  hardware         - Build for JH7110 hardware"
	@echo "  debug            - Build with debug symbols"
	@echo "  release          - Build with optimizations"
	@echo "  test             - Run unit tests"
	@echo "  coverage         - Generate test coverage report"
	@echo "  analyze          - Run static analysis"
	@echo "  memcheck         - Run memory checks (requires Valgrind)"
	@echo "  cross-arm64      - Cross-compile for ARM64"
	@echo "  cross-x86_64     - Cross-compile for x86_64"
	@echo "  deps             - Check build dependencies"
	@echo "  update-submodules- Update git submodules"
	@echo "  package          - Create distribution package"
	@echo "  install          - Install to system (requires root)"
	@echo "  uninstall        - Uninstall from system (requires root)"
	@echo "  docs             - Generate documentation"
	@echo "  format           - Format code with clang-format"
	@echo "  lint             - Run clang-tidy linter"
	@echo "  benchmark        - Run performance benchmarks"
	@echo "  audit            - Run security audit"
	@echo "  setup-dev        - Set up development environment"
	@echo "  ci-build         - CI build pipeline"
	@echo "  ci-deploy        - CI deployment pipeline"
	@echo "  clean            - Clean build artifacts"
	@echo "  help             - Show this help message"

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR) $(COVERAGE_DIR) $(ANALYSIS_DIR)

# Distclean - clean everything including dependencies
distclean: clean
	rm -rf seL4/ CAmkES/
	@echo "Full cleanup complete"

.PHONY: all simulate run_simulate hardware debug release test coverage analyze memcheck cross-arm64 cross-x86_64 deps update-submodules package install uninstall docs format lint benchmark audit setup-dev ci-build ci-deploy clean distclean help
