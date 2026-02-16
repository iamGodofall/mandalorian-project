# Waydroid Hardening Guide for VeridianOS

## Goal
Run Android apps **without Google, without trackers, without betrayal**.

## Steps

### 1. Start with Pure AOSP
- Use **Waydroid vanilla image** (no Google)
- Base: Android 11 (minimal attack surface)

### 2. Replace Google Services
- Install **microG** (open reimplementation of Play Services)
  - Only enable **GmsCore** (no UnifiedNlp, no DroidGuard)
- Disable all microG telemetry:
  ```xml
  <!-- /etc/microg/settings.xml -->
  <bool name="gms_core_telemetry">false</bool>
  ```

### 3. Network Filtering
- Use `iptables` to block known trackers:
  ```bash
  # Block Facebook trackers
  iptables -A OUTPUT -d 31.13.64.0/18 -j DROP
  iptables -A OUTPUT -d 157.240.0.0/16 -j DROP
  # Full list: veridianos/blocklists/android-trackers.txt
  ```
- Route all traffic through **Aegis proxy** (logs + blocks)

### 4. Permission Mediation
- Disable Android's permission system
- All permissions granted via **Aegis prompt**:
  - "WhatsApp wants contacts. Allow? (Y/N)"
  - Session-scoped — revocable

### 5. Storage Isolation
- App data encrypted with **user's BeskarCore key**
- No shared storage — each app gets isolated sandbox

## Validation
- Install WhatsApp → verify:
  - No calls to `facebook.com`
  - Contacts access requires explicit approval
  - Data encrypted on disk

> "Android apps, without the empire."
