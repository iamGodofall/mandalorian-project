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
    "executor marks simulated operations": ("mandalorian/runtime/executor.c", r"return EXEC_SIMULATED;"),
    "OpenClaw never maps simulation to ordinary success": ("mandalorian/agent/openclaw-adapter.c", r"case GATE_SIMULATED:\s*return -14"),
    "policy state is synchronized": ("mandalorian/core/policy.c", r"pthread_mutex_t policy_mutex"),
    "policy windows use monotonic time": ("mandalorian/core/policy.c", r"CLOCK_MONOTONIC"),
    "policy compares complete agent IDs": ("mandalorian/core/policy.c", r"agents\[i\]\.agent_id\s*==\s*agent_id"),
    "policy rejects unterminated request fields": ("mandalorian/core/policy.c", r"request_fields_terminated"),
    "quiet hours cover file_write adapter actions": ("mandalorian/core/policy.c", r'strcmp\(req->action, "file_write"\) == 0'),
    "issuer key state is synchronized": ("mandalorian/capabilities/issuer.c", r"pthread_mutex_t issuer_key_mutex"),
    "verifier key state is synchronized": ("mandalorian/core/verifier.c", r"pthread_mutex_t cap_key_mutex"),
    "receipt key and ID state is synchronized": ("mandalorian/core/receipt.c", r"pthread_mutex_t receipt_mutex"),
    "gate docs disclose host isolation limit": ("docs/architecture/gate.md", r"not an OS isolation boundary"),
    "messaging docs disclose non-production status": ("docs/architecture/link.md", r"not production end-to-end encryption"),
    "README labels target architecture honestly": ("README.md", r"Target Architecture \(Not Yet Delivered\)"),
}
failed = []
for label, (path, pattern) in checks.items():
    if not re.search(pattern, read(path), re.MULTILINE):
        failed.append(label)
        print(f"FAIL: {label}")
    else:
        print(f"PASS: {label}")

public_docs = ["README.md", "PROJECT_REPORT.md", "docs/index.md", "docs/architecture/overview.md"]
for path in public_docs:
    content = read(path).lower()
    for unsupported in ("world's first", "mathematically incapable", "provable sovereignty", "no bypass paths"):
        if unsupported in content:
            failed.append(f"{path} contains unsupported absolute claim: {unsupported}")
            print(f"FAIL: {path} contains unsupported absolute claim: {unsupported}")

# Definitions are allowed; the only call site must be the gate.
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
