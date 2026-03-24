# Mandalorian Build Fix Plan - Windows Compatibility
Current working directory: d:/mandalorian-project

## Approved Plan Steps (Phase 1: Best Native Windows + WSL Fallback)

### Step 1: [IN PROGRESS] Install pkg-config and libsodium on Windows (native fix)
- Execute commands to install via Chocolatey/Scoop/vcpkg
- Verify PKG_CONFIG_EXECUTABLE

### Step 2: [PENDING] Update CMakeLists.txt for robust Windows libsodium detection
- Add fallback find_library if pkg-config fails
- Preserve Linux pkg-config path

### Step 3: [PENDING] Enhance README.md and scripts/setup-dependencies.sh
- Add Windows-specific install steps
- Update build matrix

### Step 4: [PENDING] Clean rebuild mandalorian/
- rm -rf mandalorian/build
- mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release
- cmake --build . --config Release

### Step 5: [PENDING] Test demo and ctest
- ./Release/constrained-agent-demo.exe
- ctest -C Release -V

### Step 6: [PENDING] WSL2 Setup (full project support)
- Install WSL2 Ubuntu
- Clone project, make deps simulate

## Progress Tracking
- Step 1: Starting now...

Updated after each step completion.

