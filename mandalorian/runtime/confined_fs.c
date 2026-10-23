#define _POSIX_C_SOURCE 200809L

#include "confined_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

#include "safe_fs.h"

int mandalorian_confined_read(int root_fd, const char *relative_path,
                              void *buffer, size_t buffer_capacity,
                              size_t *bytes_read)
{
    int fd;
    size_t total = 0;
    unsigned char extra;
    ssize_t n;

    if (relative_path == NULL || bytes_read == NULL ||
        (buffer == NULL && buffer_capacity != 0)) {
        errno = EINVAL;
        return -1;
    }

    fd = mandalorian_safe_openat(root_fd, relative_path, MANDALORIAN_FS_READ);
    if (fd < 0) {
        return -1;
    }

    while (total < buffer_capacity) {
        n = read(fd, (unsigned char *)buffer + total, buffer_capacity - total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) {
            close(fd);
            *bytes_read = total;
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    /* Distinguish an exact fit from a truncated result. */
    do {
        n = read(fd, &extra, 1);
    } while (n < 0 && errno == EINTR);

    if (n > 0) {
        close(fd);
        errno = EFBIG;
        return -1;
    }
    if (n < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    close(fd);
    *bytes_read = total;
    return 0;
}

int mandalorian_confined_write_existing(int root_fd, const char *relative_path,
                                        const void *data, size_t data_len)
{
    int fd;
    size_t total = 0;
    ssize_t n;

    if (relative_path == NULL || (data == NULL && data_len != 0) ||
        data_len > (size_t)INT64_MAX) {
        errno = EINVAL;
        return -1;
    }

    fd = mandalorian_safe_openat(root_fd, relative_path,
                                 MANDALORIAN_FS_WRITE_EXISTING);
    if (fd < 0) {
        return -1;
    }

    while (total < data_len) {
        n = pwrite(fd, (const unsigned char *)data + total,
                   data_len - total, (off_t)total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n == 0) {
            errno = EIO;
        }
        {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (ftruncate(fd, (off_t)data_len) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) != 0) {
        return -1;
    }
    return 0;
}
