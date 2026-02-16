# OpenSwiftUI: Clean-Room SwiftUI/UIKit for VeridianOS

## Goal
Reimplement **only the public APIs** needed to run open-source iOS apps (e.g., Signal, Proton) — **without Apple's code, binaries, or licenses**.

> Inspired by Wine (Windows API on Linux) — but for mobile sovereignty.

## Scope (v1.0)
| Component | Status | Notes |
|----------|--------|-------|
| `UIWindow` | ✅ Planned | Basic window management |
| `UIViewController` | ⚠️ Partial | Only `viewDidLoad`, `viewWillAppear` |
| `UILabel`, `UIButton` | ✅ Planned | Render via Skia (open graphics) |
| `NSURLSession` | ✅ Critical | **Blocks telemetry domains by default** |
| `UserDefaults` | ✅ Planned | Encrypted storage (user key) |
| Core Data | ❌ Out of scope | Use SQLite instead |

## Anti-Betrayal Guarantees
- **No iCloud**: All data stored locally, encrypted
- **No App Store APIs**: No `SKStoreReviewController`, etc.
- **Network hardening**: `NSURLSession` blocks:
  - `graph.facebook.com`
  - `api.mixpanel.com`
  - `crashlytics.com`
  - (Full list in `blocklist.txt`)

## Legal Safety
- **No Apple code**: All code written from public documentation (Apple Developer Docs)
- **No reverse engineering**: Only public APIs
- **License**: Apache 2.0

## How to Use
1. Clone open-source iOS app (e.g., `github.com/signalapp/Signal-iOS`)
2. Replace `import SwiftUI` → `import OpenSwiftUI`
3. Build with VeridianOS SDK:
   ```bash
   veridian-build --target ios-app signal-ios/
   ```

> "This is not emulation. It's liberation."
