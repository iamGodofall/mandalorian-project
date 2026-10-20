#!/usr/bin/env python3
"""Fail CI when core security-contract assumptions regress."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise AssertionError(f"required file missing: {path}")
    return p.read_text(encoding="utf-8")

checks = {
    "gate has a distinct simulated result": ("mandalorian/core/gate.h", r"\bGATE_SIMULATED\b"),
    "gate handles simulated execution separately": ("mandalorian/core/gate.c", r"if\s*\(exec_res\s*==\s*EXEC_SIMULATED\)"),
    "executor marks both file operations simulated": ("mandalorian/runtime/executor.c", r"return EXEC_SIMULATED;"),
    "OpenClaw never maps simulation to ordinary success": ("mandalorian/agent/openclaw-adapter.c", r"case GATE_SIMULATED:\s*return -14"),
    "policy state is synchronized": ("mandalorian/core/policy.c", r"pthread_mutex_t policy_mutex"),
    "policy compares complete agent IDs": ("mandalorian/core/policy.c", r"agents\[i\]\.agent_id\s*==\s*agent_id"),
    "policy rejects unterminated request fields": ("mandalorian/core/policy.c", r"request_fields_terminated"),
    "verifier key state is synchronized": ("mandalorian/core/verifier.c", r"pthread_mutex_t cap_key_mutex"),
    "receipt key and ID state is synchronized": ("mandalorian/core/receipt.c", r"pthread_mutex_t receipt_mutex"),
    "README labels target architecture honestly": ("README.md", r"Target Architecture \(Not Yet Delivered\)"),
}
failed = []
for label, (path, pattern) in checks.items():
    content = read(path)
    if not re.search(pattern, content, re.MULTILINE):
        failed.append(label)
        print(f"FAIL: {label}")
    else:
        print(f"PASS: {label}")

readme = read("README.md").lower()
for unsupported in ("world's first", "mathematically incapable", "provable sovereignty"):
    if unsupported in readme:
        failed.append(f"README contains unsupported absolute claim: {unsupported}")
        print(f"FAIL: README contains unsupported absolute claim: {unsupported}")

# Guard the single host executor entry point. Definitions and declarations are
# expected; only gate.c may call it as a function.
callers = set()
for p in (ROOT / "mandalorian").rglob("*.c"):
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        if re.search(r"\bexecutor_perform\s*\(", stripped):
            if p.as_posix().endswith("/core/gate.c"):
                callers.add("gate")
            elif p.as_posix().endswith("/runtime/executor.c"):
                callers.add("definition")
            else:
                failed.append(f"unexpected executor reference in {p.relative_to(ROOT)}")
                print(f"FAIL: unexpected executor reference in {p.relative_to(ROOT)}")
if callers != {"gate", "definition"}:
    failed.append(f"executor call-site set unexpected: {sorted(callers)}")
    print(f"FAIL: executor call-site set unexpected: {sorted(callers)}")
else:
    print("PASS: executor implementation has one gate call site")

if failed:
    print(f"\n{len(failed)} security contract check(s) failed.")
    sys.exit(1)
print(f"\nAll {len(checks) + 1} security contract groups passed.")
