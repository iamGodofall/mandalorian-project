# Mandalorian Unified Architecture

## High-Level Flow
```
User goal → capkit issues cap → OpenClaw plans → Adapter → Gate → Policy → Executor → Receipt → Result
```

## Components Mapping
| Design | Implementation |
|--------|----------------|
| capkit | helm/capabilities + issuer |
| Mandalorian Core | core/gate + policy |
| OpenClaw Adapter | agent/openclaw-adapter |
| Executor | runtime/executor |
| Receipts | Extend Shield Ledger |

## Invariants
- Gate is single access point
- All actions produce receipts
- Capabilities time-bound + scoped

See full design in root task.
