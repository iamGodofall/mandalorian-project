# Contributing to the Mandalorian Project

Thank you for your interest in contributing to the world's first betrayal-resistant mobile computing platform! This document provides guidelines for contributing.

## 🎯 Core Principles

Before contributing, understand our non-negotiable principles:

1. **No Backdoors, Ever**: Any code enabling third-party access without explicit real-time user consent is rejected immediately
2. **Provable Sovereignty**: All security claims must be verifiable, not marketing
3. **Transparency**: All code must be reproducibly buildable and auditable
4. **User Control**: The user has absolute authority over their device

## 🚀 Getting Started

### Prerequisites

```bash
# Install build dependencies
sudo apt-get install cmake ninja-build gcc-riscv64-linux-gnu

# Install seL4 tools
pip install sel4-deps

# Clone with submodules
git clone --recursive https://github.com/iamGodofall/mandalorian-project.git
cd mandalorian-project
```

### Build and Test

```bash
# Build tests
cd tests && mkdir build && cd build
cmake .. && cmake --build .

# Run tests
./Debug/comprehensive_test.exe  # Windows
./comprehensive_test            # Linux/macOS

# Run security audit
./scripts/security-audit.sh
```

## 📝 Contribution Process

### 1. Before You Start

- Check existing issues and PRs to avoid duplication
- Discuss major changes in an issue first
- Ensure your change aligns with project principles

### 2. Making Changes

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes
# ... edit code ...

# Test thoroughly
cd tests/build && cmake --build . && ./comprehensive_test

# Run security audit
../../scripts/security-audit.sh
```

### 3. Code Standards

#### C Code Requirements

```c
// ✅ DO: Clear, documented code with bounds checking
int process_data(const uint8_t *input, size_t input_len, 
                 uint8_t *output, size_t output_max) {
    if (!input || !output || input_len == 0) {
        return -1;  // Input validation
    }
    
    if (input_len > output_max) {
        return -1;  // Bounds check
    }
    
    // Use safe string functions
    strncpy(output, input, output_max - 1);
    output[output_max - 1] = '\0';
    
    return 0;
}

// ❌ DON'T: Unsafe, undocumented code
void process(char *in, char *out) {
    strcpy(out, in);  // Buffer overflow risk!
}
```

#### Security Requirements

1. **All crypto code must be constant-time**
   ```c
   // Use constant-time comparison
   if (secure_memcmp(a, b, len) != 0) { ... }
   ```

2. **All bounds must be checked**
   ```c
   if (len > BUFFER_SIZE) return -1;
   ```

3. **No secrets in logs**
   ```c
   // ❌ DON'T
   LOG_INFO("Key: %s", key);
   
   // ✅ DO
   LOG_INFO("Key operation completed");
   ```

4. **Secure memory handling**
   ```c
   // Clear sensitive data after use
   secure_memzero(key, sizeof(key));
   ```

### 4. Testing Requirements

Every contribution must include:

- [ ] Unit tests for new functions
- [ ] Integration tests for component interactions
- [ ] Security tests for crypto/permission code
- [ ] Documentation updates

```c
// Example test
int test_new_feature(void) {
    // Setup
    uint8_t test_data[32] = {0};
    
    // Execute
    int result = new_feature(test_data, sizeof(test_data));
    
    // Verify
    TEST_ASSERT(result == 0, "Feature should succeed");
    TEST_ASSERT(test_data[0] != 0, "Data should be modified");
    
    return 0;
}
```

### 5. Documentation

Update relevant documentation:

- **README.md**: User-facing changes
- **docs/api/**: API documentation
- **docs/security/**: Security implications
- **CHANGELOG.md**: Version history

### 6. Commit Messages

Use clear, descriptive commit messages:

```
✅ GOOD:
Add hardware abstraction layer for BeskarVault

- Separates simulation from production code
- Supports ATECC608B and secure enclave modes
- Prevents accidental use of simulation crypto in production

❌ BAD:
fix stuff
```

Format:
```
<type>: <short summary>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Tests only
- `refactor`: Code restructuring
- `security`: Security fix
- `perf`: Performance improvement

### 7. Pull Request

```markdown
## Description
Brief description of changes

## Security Impact
- [ ] No security impact
- [ ] Security fix (describe threat model)
- [ ] New crypto code (requires review)

## Testing
- [ ] Unit tests added
- [ ] Integration tests pass
- [ ] Security audit passes
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] Tests pass
- [ ] Security audit passes
- [ ] No backdoors introduced
```

## 🔒 Security Review Process

All contributions undergo security review:

1. **Automated Checks**
   - Static analysis (Clang Static Analyzer, Frama-C)
   - Fuzzing (libFuzzer, AFL++)
   - Security audit script

2. **Manual Review**
   - Code review by maintainers
   - Security review for crypto/auth code
   - Architecture review for major changes

3. **Required for Crypto Changes**
   - Timing analysis (dudect)
   - Formal verification where possible
   - Third-party audit for critical code

## 🐛 Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email: security@mandalorian-project.org
2. Encrypt with PGP key (in docs/security/)
3. Allow 90 days for fix before disclosure

## 📜 License

By contributing, you agree that your contributions will be licensed under the Mandalorian Sovereignty License v1.0.

## 🎖️ Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Invited to security advisory board (significant contributions)

## ❓ Questions?

- Discord: #dev-contributors
- Matrix: #mandalorian-dev:matrix.org
- Email: dev@mandalorian-project.org

## "This is the way."

Thank you for helping build truly sovereign computing!
