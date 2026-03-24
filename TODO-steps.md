# Mandalorian Improvement TODO
## Breakdown of Approved Plan (Do Best, incl. README)

### 1. Commit Local Upgrades [ ]
- git add .
- git commit -m "Phase10 upgrades: docs+201, tests, ledger/helm"
- git push origin master

### 2. Windows Deps (Phase1) [ ]
- choco install pkgconfiglite vcpkg
- vcpkg install libsodium:x64-windows

### 3. Fix CMakeLists.txt [ ]
- Add Windows libsodium fallback

### 4. Clean Rebuilds [ ]
- rm -rf */build build*/
- mkdir build && cd build && cmake .. -B . -DCMAKE_BUILD_TYPE=Release

### 5. Tests & Fuzz [ ]
- ctest -V
- ./tests/fuzz/fuzz_vault

### 6. Security Audit [ ]
- ./scripts/security-audit.sh

### 7. CI Workflow [ ]
- Create .github/workflows/ci.yml

### 8. Docs Polish (README etc.) [ ]
- Update CHANGELOG v0.2.1
- Enhance README quickstart

Progress: Updated after each.
