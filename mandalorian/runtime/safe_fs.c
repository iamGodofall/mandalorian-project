#define _POSIX_C_SOURCE 200809L

#include "safe_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY)
#error "safe_fs requires O_CLOEXEC, O_NOFOLLOW, and O_DIRECTORY support"
#endif

static bool path_is_safe_relative(const char *path)
{
    const char *component;
    const char *cursor;

    if (path == NULL || path[0] == '\0' || path[0] == '/') {
        return false;
    }

    component = path;
    for (cursor = path;; cursor++) {
        if (*cursor == '\\') {
            return false;
        }
        if (*cursor == '/' || *cursor == '\0') {
            size_t length = (size_t)(cursor - component);
            if (length == 0 ||
                (length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' && component[1] == '.')) {
                return false;
            }
            if (*cursor == '\0') {
                return true;
            }
            component = cursor + 1;
        }
    }
}

int mandalorian_safe_openat(int root_fd, const char *relative_path,
                            mandalorian_fs_access_t access)
{
    int current_fd = -1;
    int next_fd = -1;
    int final_fd = -1;
    int open_flags;
    const char *component;
    const char *slash;
    struct stat st;

    if (root_fd < 0 || !path_is_safe_relative(relative_path) ||
        (access != MANDALORIAN_FS_READ &&
         access != MANDALORIAN_FS_WRITE_EXISTING)) {
        errno = EINVAL;
        return -1;
    }

    if (fstat(root_fd, &st) != 0) {
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    current_fd = fcntl(root_fd, F_DUPFD_CLOEXEC, 0);
    if (current_fd < 0) {
        return -1;
    }

    component = relative_path;
    for (;;) {
        slash = strchr(component, '/');
        if (slash == NULL) {
            break;
        }

        {
            size_t length = (size_t)(slash - component);
            char name[256];

            /* NAME_MAX is commonly 255; reject rather than truncate. */
            if (length == 0 || length >= sizeof(name)) {
                errno = ENAMETOOLONG;
                goto fail;
            }
            memcpy(name, component, length);
            name[length] = '\0';

            next_fd = openat(current_fd, name,
                             O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                             O_DIRECTORY | O_NONBLOCK);
        }
        if (next_fd < 0) {
            goto fail;
        }

        close(current_fd);
        current_fd = next_fd;
        next_fd = -1;
        component = slash + 1;
    }

    open_flags = (access == MANDALORIAN_FS_READ) ? O_RDONLY : O_WRONLY;
    final_fd = openat(current_fd, component,
                      open_flags | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (final_fd < 0) {
        goto fail;
    }

    if (fstat(final_fd, &st) != 0) {
        goto fail;
    }
    if (!S_ISREG(st.st_mode)) {
        errno = EACCES;
        goto fail;
    }

    close(current_fd);
    return final_fd;

fail:
    {
        int saved_errno = errno;
        if (final_fd >= 0) {
            close(final_fd);
        }
        if (next_fd >= 0) {
            close(next_fd);
        }
        if (current_fd >= 0) {
            close(current_fd);
        }
        errno = saved_errno;
    }
    return -1;
}
