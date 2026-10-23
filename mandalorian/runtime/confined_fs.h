/*
 * Bounded host filesystem operations rooted at a trusted directory descriptor.
 *
 * These functions perform real file I/O, unlike executor_perform(). They are
 * NOT a process sandbox and are NOT wired into mandalorian_execute(). Callers
 * must independently enforce authorization and establish OS isolation.
 */
#ifndef MANDALORIAN_CONFINED_FS_H
#define MANDALORIAN_CONFINED_FS_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Read a regular file beneath root_fd into caller-owned memory.
 * Returns 0 on success, -1 on error. Fails with EFBIG if the file cannot fit.
 * *bytes_read is set only on success. No NUL terminator is added.
 */
int mandalorian_confined_read(int root_fd, const char *relative_path,
                              void *buffer, size_t buffer_capacity,
                              size_t *bytes_read);

/*
 * Replace the contents of an existing regular file beneath root_fd.
 * Does not create files. Writes from offset zero and truncates to data_len.
 * This operation is NOT atomic: on I/O failure, the file may be partially
 * modified. Callers must treat an error as an uncertain outcome and must not
 * blindly retry non-idempotent workflows.
 */
int mandalorian_confined_write_existing(int root_fd, const char *relative_path,
                                        const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif
#endif
