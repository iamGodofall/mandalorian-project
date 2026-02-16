#!/bin/bash

# Mandalorian Project - Dependency Setup Script
# This script sets up all required dependencies for building and testing

set -e

echo "Mandalorian Project - Setting up dependencies..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install package on Ubuntu/Debian
install_ubuntu() {
    local package=$1
    if command_exists apt-get; then
        echo "Installing $package..."
        sudo apt-get update
        sudo apt-get install -y "$package"
    else
        echo "apt-get not found. Please install $package manually."
        exit 1
    fi
}

# Function to install package on macOS
install_macos() {
    local package=$1
    if command_exists brew; then
        echo "Installing $package..."
        brew install "$package"
    else
        echo "Homebrew not found. Please install Homebrew first: https://brew.sh/"
        exit 1
    fi
}

# Function to install package on Windows (using Chocolatey or manual)
install_windows() {
    local package=$1
    if command_exists choco; then
        echo "Installing $package..."
        choco install "$package" -y
    else
        echo "Chocolatey not found. Please install manually or use WSL."
        echo "For $package, visit: https://www.msys2.org/ or install manually."
        exit 1
    fi
}

# Install build essentials
echo "Installing build essentials..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "build-essential"
    install_ubuntu "cmake"
    install_ubuntu "ninja-build"
    install_ubuntu "pkg-config"
elif [[ "$OS" == "macos" ]]; then
    install_macos "cmake"
    install_macos "ninja"
    install_macos "pkg-config"
elif [[ "$OS" == "windows" ]]; then
    install_windows "cmake"
    install_windows "ninja"
fi

# Install RISC-V toolchain
echo "Installing RISC-V toolchain..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "gcc-riscv64-unknown-elf"
    install_ubuntu "gdb-multiarch"
elif [[ "$OS" == "macos" ]]; then
    install_macos "riscv64-elf-gcc"
    install_macos "gdb"
elif [[ "$OS" == "windows" ]]; then
    echo "Please install RISC-V toolchain manually from: https://github.com/xpack-dev-tools/riscv-none-elf-gcc-xpack/releases"
fi

# Install Python (for build scripts)
echo "Installing Python..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "python3"
    install_ubuntu "python3-pip"
elif [[ "$OS" == "macos" ]]; then
    # Python comes pre-installed on macOS
    if ! command_exists python3; then
        install_macos "python3"
    fi
elif [[ "$OS" == "windows" ]]; then
    # Python installer will be handled by user
    echo "Please ensure Python 3.6+ is installed."
fi

# Install testing dependencies
echo "Installing testing dependencies..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "cmocka"
    install_ubuntu "lcov"
    install_ubuntu "cppcheck"
    install_ubuntu "clang-tidy"
    install_ubuntu "clang-format"
    install_ubuntu "valgrind"
elif [[ "$OS" == "macos" ]]; then
    install_macos "cmocka"
    install_macos "lcov"
    install_macos "cppcheck"
    install_macos "clang-tidy"
    install_macos "clang-format"
    install_macos "valgrind"
elif [[ "$OS" == "windows" ]]; then
    echo "Testing dependencies need to be installed manually on Windows."
    echo "Consider using WSL for full development environment."
fi

# Install documentation tools
echo "Installing documentation tools..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "doxygen"
    install_ubuntu "graphviz"
elif [[ "$OS" == "macos" ]]; then
    install_macos "doxygen"
    install_macos "graphviz"
elif [[ "$OS" == "windows" ]]; then
    echo "Documentation tools need to be installed manually on Windows."
fi

# Install QEMU for simulation
echo "Installing QEMU..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "qemu-system-riscv64"
elif [[ "$OS" == "macos" ]]; then
    install_macos "qemu"
elif [[ "$OS" == "windows" ]]; then
    echo "Please install QEMU manually from: https://www.qemu.org/download/"
fi

# Install Git (usually pre-installed)
if ! command_exists git; then
    echo "Installing Git..."
    if [[ "$OS" == "linux" ]]; then
        install_ubuntu "git"
    elif [[ "$OS" == "macos" ]]; then
        install_macos "git"
    elif [[ "$OS" == "windows" ]]; then
        install_windows "git"
    fi
fi

# Install additional development tools
echo "Installing additional development tools..."
if [[ "$OS" == "linux" ]]; then
    install_ubuntu "vim"
    install_ubuntu "tmux"
    install_ubuntu "htop"
    install_ubuntu "tree"
elif [[ "$OS" == "macos" ]]; then
    install_macos "vim"
    install_macos "tmux"
    install_macos "htop"
elif [[ "$OS" == "windows" ]]; then
    echo "Additional tools need to be installed manually on Windows."
fi

# Setup Python virtual environment for development
echo "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt 2>/dev/null || echo "requirements.txt not found, skipping Python dependencies"

# Initialize and update submodules
echo "Initializing git submodules..."
if [[ -f ".gitmodules" ]]; then
    git submodule update --init --recursive
else
    echo "No .gitmodules file found, skipping submodule initialization"
fi

# Create necessary directories
echo "Creating necessary directories..."
mkdir -p build
mkdir -p dist
mkdir -p docs/generated
mkdir -p tests/build
mkdir -p tests/coverage

# Verify installation
echo "Verifying installation..."

# Check critical tools
critical_tools=("cmake" "ninja" "python3")
for tool in "${critical_tools[@]}"; do
    if command_exists "$tool"; then
        echo "✓ $tool found: $($tool --version | head -1)"
    else
        echo "✗ $tool not found"
        exit 1
    fi
done

# Check RISC-V tools
if command_exists "riscv64-unknown-elf-gcc" || command_exists "riscv64-elf-gcc"; then
    echo "✓ RISC-V toolchain found"
else
    echo "✗ RISC-V toolchain not found"
    echo "Please ensure RISC-V GCC is in your PATH"
fi

# Check QEMU
if command_exists "qemu-system-riscv64"; then
    echo "✓ QEMU found"
else
    echo "✗ QEMU not found"
fi

echo ""
echo "Dependency setup complete!"
echo ""
echo "Next steps:"
echo "1. Run 'make setup-dev' in the beskarcore directory"
echo "2. Run 'make simulate' to build for QEMU"
echo "3. Run 'make test' to run unit tests"
echo ""
echo "For detailed build instructions, see README.md"
