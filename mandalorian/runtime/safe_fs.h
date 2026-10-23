/*
 * Safe relative file opening beneath a pre-opened directory descriptor.
 *
 * This is a filesystem-race mitigation primitive, NOT a process sandbox or a
 * substitute for an OS-enforced execution boundary. The caller must obtain
 * root_fd from a trusted directory, retain it, and enforce authorization.
 */
#ifndef MANDALORIAN_SAFE_FS_H
#define MANDALORIAN_SAFE_FS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MANDALORIAN_FS_READ = 0,
    MANDALORIAN_FS_WRITE_EXISTING = 1
} mandalorian_fs_access_t;

/*
 * Open a regular file beneath root_fd without following symlinks.
 *
 * relative_path must be a non-empty relative path with no empty, "." or ".."
 * components and no backslashes. Intermediate components are opened one at a
 * time relative to already-open directory descriptors, so renames of ancestor
 * pathnames cannot redirect subsequent traversal. The final file must already
 * exist and be a regular file. No create/truncate operation is performed.
 * Write access rejects files whose inode has multiple hard links at the
 * time of the check, because an alias may exist outside the trusted tree.
 * This check is not race-proof against concurrent link-count changes and does
 * not constrain mount points or replace OS-enforced process isolation.
 *
 * Returns a close-on-exec file descriptor on success, or -1 with errno set.
 */
int mandalorian_safe_openat(int root_fd, const char *relative_path,
                            mandalorian_fs_access_t access);

#ifdef __cplusplus
}
#endif

#endif
