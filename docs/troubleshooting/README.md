# Troubleshooting Guide

This guide helps diagnose and resolve common issues with the Mandalorian Project.

## Build Issues

### seL4 Build Failures

**Symptom**: CMake configuration fails with seL4 errors
```
CMake Error: Could not find seL4
```

**Solution**:
```bash
# Ensure seL4 is properly cloned and initialized
cd beskarcore/seL4
git submodule update --init --recursive

# Clean and reconfigure
cd ..
rm -rf build
make simulate
```

**Symptom**: RISC-V toolchain not found
```
riscv64-unknown-elf-gcc: command not found
```

**Solution**:
```bash
# Install RISC-V toolchain
sudo apt install gcc-riscv64-unknown-elf

# Or build from source
git clone https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
./configure --prefix=/opt/riscv
make
```

### CMake Configuration Issues

**Symptom**: Platform configuration fails
```
Platform riscv64:qemu not supported
```

**Solution**:
```bash
# Check available platforms
cd beskarcore/seL4
./init-build.sh --list-platforms

# Use correct platform name
cd ..
make PLATFORM=riscv64:jh7110 hardware
```

## Runtime Issues

### Boot Failures

**Symptom**: System hangs during boot
```
[    0.000000] seL4 Boot Info:
[    0.000000]   Kernel logging is enabled
[    0.000000]   Bootup failed
```

**Solution**:
1. Check hardware connections
2. Verify flashed image integrity
3. Enable verbose logging:
```bash
make VERBOSE=1 hardware
```

**Symptom**: Verified boot fails
```
ERROR: Kernel integrity check failed
```

**Solution**:
```c
// Check kernel hash
uint8_t expected_hash[32] = { /* expected SHA3-256 */ };
uint8_t actual_hash[32];
sha3_256(actual_hash, kernel_data, kernel_size);
if (memcmp(expected_hash, actual_hash, 32) != 0) {
    LOG_ERROR("Kernel hash mismatch");
}
```

### Application Runtime Issues

**Symptom**: Android app fails to start
```
ART: Failed to initialize runtime
```

**Solution**:
```bash
# Check APK integrity
apksigner verify app.apk

# Verify runtime permissions
u_runtime_check_permissions(runtime, app_id);
```

**Symptom**: iOS app crashes on startup
```
IPA: Invalid bundle structure
```

**Solution**:
```bash
# Validate IPA structure
unzip -l app.ipa

# Check entitlements
codesign -d --entitlements - app.ipa
```

### Sandbox Issues

**Symptom**: App exceeds resource quotas
```
SANDBOX: Resource limit exceeded
```

**Solution**:
```c
// Adjust quotas based on app requirements
sandbox_set_quotas(sandbox,
    cpu_quota + 5,    // Increase CPU by 5%
    mem_quota * 1.2,  // Increase memory by 20%
    io_quota + 100);  // Increase I/O by 100 ops/sec
```

## Security Issues

### Verification Failures

**Symptom**: Cryptographic verification fails
```
CRYPTO: Signature verification failed
```

**Solution**:
```c
// Debug signature verification
int debug_verify(const uint8_t *sig, const uint8_t *msg, size_t len, const uint8_t *pub_key) {
    LOG_DEBUG("Signature: %s", hex_encode(sig, 64));
    LOG_DEBUG("Message: %s", hex_encode(msg, len));
    LOG_DEBUG("Public key: %s", hex_encode(pub_key, 32));

    return ed25519_verify(sig, msg, len, pub_key);
}
```

**Symptom**: Ledger integrity compromised
```
LEDGER: Merkle tree verification failed
```

**Solution**:
```c
// Rebuild ledger from trusted backup
ledger_rebuild_from_backup("/path/to/backup");
ledger_verify_integrity();
```

### Permission Issues

**Symptom**: App permission denied
```
AEGIS: Permission request denied
```

**Solution**:
```c
// Check permission policy
permission_t perm = PERMISSION_STORAGE;
if (service_request_permission(perm, app_id) != 0) {
    // Request user approval
    aegis_request_user_approval(perm, app_id);
}
```

## Performance Issues

### Memory Problems

**Symptom**: Out of memory errors
```
ERROR: Out of memory
```

**Solution**:
```c
// Monitor memory usage
size_t used = get_memory_usage();
size_t total = get_total_memory();
LOG_INFO("Memory usage: %zu/%zu bytes (%.1f%%)",
         used, total, (float)used/total * 100);

// Implement memory cleanup
if (used > total * 0.9) {
    garbage_collect();
}
```

### IPC Performance

**Symptom**: Slow inter-process communication
```
IPC: Timeout on message send
```

**Solution**:
```c
// Optimize IPC buffer sizes
ipc_set_buffer_size(64 * 1024);  // 64KB buffer

// Use shared memory for large data
shared_memory_t *shm = ipc_create_shared_memory(size);
ipc_send_shared(shm);
```

### CPU Usage

**Symptom**: High CPU utilization
```
CPU: Usage above 90%
```

**Solution**:
```c
// Profile CPU usage
profile_start();
run_workload();
profile_stop();
profile_print_report();

// Optimize hot paths
#pragma GCC optimize("O3")
void hot_function() {
    // Optimized implementation
}
```

## Networking Issues

### Connection Problems

**Symptom**: Network requests fail
```
NETWORK: Connection timeout
```

**Solution**:
```c
// Check network configuration
network_config_t config = get_network_config();
LOG_INFO("IP: %s, Gateway: %s", config.ip, config.gateway);

// Test connectivity
if (ping_test("8.8.8.8") != 0) {
    LOG_ERROR("No internet connectivity");
}
```

## Logging and Debugging

### Log Analysis

**Symptom**: Insufficient logging information
```
LOG: No debug information available
```

**Solution**:
```c
// Enable comprehensive logging
logger_init(LOG_LEVEL_DEBUG, LOG_OUTPUT_CONSOLE | LOG_OUTPUT_FILE, "debug.log");
logger_set_timestamp(1);
logger_set_file_info(1);
logger_set_level_prefix(1);

// Add debug logging
LOG_DEBUG("Variable x = %d", x);
LOG_DEBUG("Function %s called with arg %p", __FUNCTION__, arg);
```

### Debug Tools

**GDB Debugging**:
```bash
# Attach to running process
gdb build/binary
(gdb) target remote :1234
(gdb) break main
(gdb) continue
```

**Valgrind Memory Checking**:
```bash
# Run with memory checking
valgrind --leak-check=full --track-origins=yes ./test_binary
```

**SystemTap Tracing**:
```bash
# Trace function calls
stap -e 'probe process("/path/to/binary").function("function_name") { println("Called") }'
```

## Hardware-Specific Issues

### VisionFive 2 Issues

**Symptom**: USB devices not recognized
```
USB: Device enumeration failed
```

**Solution**:
```bash
# Check USB controller
lsusb
dmesg | grep usb

# Reset USB subsystem
echo 0 > /sys/bus/pci/devices/0000:00:14.0/remove
echo 1 > /sys/bus/pci/rescan
```

**Symptom**: GPIO access fails
```
GPIO: Permission denied
```

**Solution**:
```bash
# Grant GPIO access
sudo usermod -a -G gpio $USER

# Or run with sudo
sudo ./application
```

## Recovery Procedures

### Emergency Recovery

**Boot into Recovery Mode**:
```bash
# Interrupt boot sequence
# Press ESC during boot to enter recovery

# From recovery shell
mount /dev/mmcblk0p1 /mnt
chroot /mnt
# Perform recovery operations
```

### Data Recovery

**Recover from Backup**:
```bash
# Mount backup device
mount /dev/sdb1 /backup

# Restore system
rsync -av /backup/system/ /

# Restore ledger
cp /backup/ledger.dat /var/mandalorian/
ledger_verify_integrity()
```

### System Reset

**Factory Reset**:
```bash
# Wipe all data
dd if=/dev/zero of=/dev/mmcblk0 bs=1M count=100

# Reinstall from recovery image
dd if=recovery.img of=/dev/mmcblk0
reboot
```

## Getting Help

### Diagnostic Information

**System Information**:
```bash
# Collect system info
uname -a
cat /proc/cpuinfo
free -h
df -h

# Project version
cat /etc/mandalorian/version

# Component versions
beskarcore --version
veridianos --version
```

### Log Collection

**Gather Logs**:
```bash
# System logs
journalctl -u mandalorian > system.log

# Application logs
find /var/log -name "*.log" -exec cat {} \; > app_logs.txt

# Kernel logs
dmesg > kernel.log
```

### Support Resources

- **Issue Tracker**: https://github.com/mandalorian-project/issues
- **Documentation**: https://docs.mandalorian-project.org
- **Community Forum**: https://forum.mandalorian-project.org
- **Security Issues**: security@mandalorian-project.org

### Escalation Procedures

1. **Check Documentation**: Search existing issues and documentation
2. **Gather Information**: Collect logs and system information
3. **File Issue**: Create detailed issue report with reproduction steps
4. **Contact Support**: Escalate to maintainers if critical
