#!/bin/bash
#
# Security Audit Script for Mandalorian Project
#
# This script performs comprehensive security checks on the codebase
# to ensure no backdoors, vulnerabilities, or security regressions.
#

set -e

echo "=========================================="
echo "  MANDALORIAN PROJECT SECURITY AUDIT"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

FAILED=0
WARNINGS=0

# Function to report failure
fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
    FAILED=$((FAILED + 1))
}

# Function to report success
pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
}

# Function to report warning
warn() {
    echo -e "${YELLOW}⚠️  WARN: $1${NC}"
    WARNINGS=$((WARNINGS + 1))
}

echo "1. Checking for backdoor keywords..."
echo "-----------------------------------"

# Check for backdoor-related terms
BACKDOOR_TERMS="backdoor|emergency.*key|law.*enforcement|lawful.*access|master.*key|skeleton.*key|golden.*key"

if grep -riE "$BACKDOOR_TERMS" beskarcore/ veridianos/ aegis/ helm/ \
    --include="*.c" --include="*.h" --include="*.py" --include="*.sh" 2>/dev/null; then
    fail "Found potential backdoor keywords"
else
    pass "No backdoor keywords found"
fi

echo ""
echo "2. Checking for dangerous functions..."
echo "-------------------------------------"

# Check for unsafe C functions
DANGEROUS_FUNCS="strcpy|sprintf|gets|scanf|strcat|wcscpy|_tcscpy|_mbscpy|StrCpy|StrCat|gets_s"

if grep -rE "$DANGEROUS_FUNCS" beskarcore/src/ veridianos/src/ aegis/src/ helm/src/ \
    --include="*.c" 2>/dev/null | grep -v "strncpy\|snprintf"; then
    fail "Found dangerous functions (strcpy, sprintf, gets, etc.)"
else
    pass "No dangerous functions found"
fi

echo ""
echo "3. Checking for printf in production code..."
echo "---------------------------------------------"

# Check for printf (should use logging system)
if grep -r "printf(" beskarcore/src/ --include="*.c" | \
    grep -v "demo" | grep -v "SIMULATION" | grep -v "//" 2>/dev/null; then
    warn "Found printf in production code (should use logging system)"
else
    pass "No printf in production code"
fi

echo ""
echo "4. Checking for hardcoded secrets..."
echo "-------------------------------------"

# Check for hardcoded keys, passwords, tokens
SECRET_PATTERNS="password.*=.*['\"]|secret.*=.*['\"]|api_key.*=.*['\"]|private_key.*=.*['\"]"

if grep -riE "$SECRET_PATTERNS" beskarcore/ veridianos/ aegis/ helm/ \
    --include="*.c" --include="*.h" --include="*.py" --include="*.json" 2>/dev/null; then
    fail "Found potential hardcoded secrets"
else
    pass "No hardcoded secrets found"
fi

echo ""
echo "5. Checking for TODO/FIXME in security code..."
echo "-----------------------------------------------"

# Check for TODO/FIXME in security-critical files
SECURITY_FILES="beskarcore/src/beskar_vault.c beskarcore/src/beskar_app_guard.c beskarcore/src/continuous_guardian.c"

for file in $SECURITY_FILES; do
    if [ -f "$file" ]; then
        if grep -i "TODO\|FIXME\|XXX" "$file" 2>/dev/null; then
            warn "Found TODO/FIXME in $file"
        fi
    fi
done

pass "Security code TODO check complete"

echo ""
echo "6. Checking for buffer overflow risks..."
echo "-----------------------------------------"

# Check for potential buffer overflows
if grep -r "char.*\[.*\].*=.*{" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null | \
    grep -v "const" | head -5; then
    warn "Found potential stack buffers (review for overflow risks)"
else
    pass "No obvious buffer overflow risks"
fi

echo ""
echo "7. Checking for integer overflow risks..."
echo "------------------------------------------"

# Check for potential integer overflows
if grep -rE "malloc.*\*|calloc.*[0-9].*\*|realloc.*\*" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null; then
    warn "Found multiplication in allocation (check for overflow)"
else
    pass "No obvious integer overflow risks"
fi

echo ""
echo "8. Checking for race conditions..."
echo "-----------------------------------"

# Check for potential race conditions
if grep -r "access\|stat\|chmod" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null; then
    warn "Found file operations (check for TOCTOU race conditions)"
else
    pass "No obvious race condition risks"
fi

echo ""
echo "9. Checking for format string vulnerabilities..."
echo "------------------------------------------------"

# Check for format string issues
if grep -r "printf.*%s.*," beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null | \
    grep -v "printf(\"%s\", " | head -5; then
    warn "Potential format string issues (use printf(\"%s\", var))"
else
    pass "No obvious format string vulnerabilities"
fi

echo ""
echo "10. Checking for memory leak risks..."
echo "--------------------------------------"

# Check for malloc without free
MALLOC_COUNT=$(grep -r "malloc\|calloc" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null | wc -l)
FREE_COUNT=$(grep -r "free(" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null | wc -l)

echo "   malloc/calloc calls: $MALLOC_COUNT"
echo "   free calls: $FREE_COUNT"

if [ "$MALLOC_COUNT" -gt "$FREE_COUNT" ]; then
    warn "More allocations than frees (potential memory leaks)"
else
    pass "Allocation/free balance looks good"
fi

echo ""
echo "11. Checking for simulation code markers..."
echo "------------------------------------------"

# Verify simulation code is clearly marked
SIMULATION_MARKERS="SIMULATION ONLY|NOT FOR PRODUCTION|FAKE|MOCK"

if grep -riE "$SIMULATION_MARKERS" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null; then
    pass "Simulation code is clearly marked"
else
    warn "Some simulation code may not be clearly marked"
fi

echo ""
echo "12. Checking for proper error handling..."
echo "----------------------------------------"

# Check for ignored return values
if grep -r "malloc\|calloc\|realloc\|fopen\|socket" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null | \
    grep -v "if\|assert\|CHECK\|VERIFY" | head -5; then
    warn "Some function return values may not be checked"
else
    pass "Return values appear to be checked"
fi

echo ""
echo "13. Checking for cryptographic best practices..."
echo "-------------------------------------------------"

# Check for weak crypto
WEAK_CRYPTO="MD5|SHA1|DES|RC4|RSA.*1024|rand\(\)|srand\(\)"

if grep -riE "$WEAK_CRYPTO" beskarcore/src/ veridianos/src/ --include="*.c" 2>/dev/null; then
    fail "Found weak cryptographic primitives"
else
    pass "No weak cryptographic primitives found"
fi

echo ""
echo "14. Checking file permissions..."
echo "---------------------------------"

# Check for overly permissive files
if find . -type f -perm /o+w 2>/dev/null | grep -v ".git" | head -5; then
    warn "Found world-writable files"
else
    pass "File permissions look good"
fi

echo ""
echo "15. Checking for dependency vulnerabilities..."
echo "---------------------------------------------"

# Check requirements.txt if it exists
if [ -f "requirements.txt" ]; then
    echo "   Python dependencies found - run 'pip-audit' for detailed check"
    pass "Dependency file exists"
else
    pass "No Python dependencies"
fi

echo ""
echo "=========================================="
echo "           AUDIT SUMMARY"
echo "=========================================="
echo -e "Failed:    ${RED}$FAILED${NC}"
echo -e "Warnings:  ${YELLOW}$WARNINGS${NC}"
echo "Passed:    $((15 - FAILED - WARNINGS))"
echo "=========================================="

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}❌ SECURITY AUDIT FAILED${NC}"
    echo "Fix the failed checks before proceeding."
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}⚠️  SECURITY AUDIT PASSED WITH WARNINGS${NC}"
    echo "Review warnings and address if necessary."
    exit 0
else
    echo -e "${GREEN}✅ SECURITY AUDIT PASSED${NC}"
    echo "No security issues found."
    exit 0
fi
