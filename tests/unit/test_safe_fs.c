#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "runtime/safe_fs.h"

static int failures;
static int checks;

static void check(const char *name, int condition)
{
    checks++;
    if (!condition) {
        fprintf(stderr, "FAIL: %s (errno=%d: %s)\n", name, errno,
                strerror(errno));
        failures++;
    } else {
        printf("PASS: %s\n", name);
    }
}

int main(void)
{
    char root_template[] = "/tmp/mandalorian-safe-fs-XXXXXX";
    char *root_path = mkdtemp(root_template);
    char nested[512];
    char file_path[512];
    char link_path[512];
    char external_template[] = "/tmp/mandalorian-safe-fs-outside-XXXXXX";
    const char *external_path = external_template;
    int external_created_fd = -1;
    int root_fd = -1;
    int file_fd = -1;
    int outside_fd = -1;
    char buf[16] = {0};
    ssize_t n;

    if (root_path == NULL) {
        perror("mkdtemp root");
        return 2;
    }
    snprintf(nested, sizeof(nested), "%s/nested", root_path);
    snprintf(file_path, sizeof(file_path), "%s/nested/data.txt", root_path);
    snprintf(link_path, sizeof(link_path), "%s/escape", root_path);

    check("create nested directory", mkdir(nested, 0700) == 0);
    file_fd = open(file_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    check("create regular test file", file_fd >= 0);
    if (file_fd >= 0) {
        check("write regular test file", write(file_fd, "inside", 6) == 6);
        close(file_fd);
        file_fd = -1;
    }

    external_created_fd = mkstemp(external_template);
    check("create outside file", external_created_fd >= 0);
    if (external_created_fd >= 0) {
        outside_fd = external_created_fd;
        (void)write(outside_fd, "outside", 7);
        close(outside_fd);
        check("create symlink pointing outside root",
              symlink(external_path, link_path) == 0);
    }

    root_fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check("open trusted root directory", root_fd >= 0);

    if (root_fd >= 0) {
        file_fd = mandalorian_safe_openat(root_fd, "nested/data.txt",
                                          MANDALORIAN_FS_READ);
        check("open regular file beneath root", file_fd >= 0);
        if (file_fd >= 0) {
            n = read(file_fd, buf, sizeof(buf));
            check("read expected content through returned descriptor",
                  n == 6 && memcmp(buf, "inside", 6) == 0);
            close(file_fd);
            file_fd = -1;
        }

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "../mandalorian-safe-fs-outside",
                                          MANDALORIAN_FS_READ);
        check("reject parent traversal", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "/etc/passwd",
                                          MANDALORIAN_FS_READ);
        check("reject absolute path", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested/../nested/data.txt",
                                          MANDALORIAN_FS_READ);
        check("reject embedded parent component", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested//data.txt",
                                          MANDALORIAN_FS_READ);
        check("reject repeated separator", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested/./data.txt",
                                          MANDALORIAN_FS_READ);
        check("reject dot component", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "escape",
                                          MANDALORIAN_FS_READ);
        check("reject final symlink", file_fd < 0 &&
              (errno == ELOOP || errno == EACCES));
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "escape/child",
                                          MANDALORIAN_FS_READ);
        check("reject symlink in intermediate component", file_fd < 0 &&
              (errno == ELOOP || errno == ENOTDIR || errno == EACCES));
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "",
                                          MANDALORIAN_FS_READ);
        check("reject empty path", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested/",
                                          MANDALORIAN_FS_READ);
        check("reject trailing separator", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested\\\\data.txt",
                                          MANDALORIAN_FS_READ);
        check("reject backslash path separator", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested/new-file.txt",
                                          MANDALORIAN_FS_WRITE_EXISTING);
        check("write-existing mode never creates missing files",
              file_fd < 0 && errno == ENOENT);
        if (file_fd >= 0) close(file_fd);

        file_fd = mandalorian_safe_openat(root_fd, "nested/data.txt",
                                          MANDALORIAN_FS_WRITE_EXISTING);
        check("open existing regular file for write", file_fd >= 0);
        if (file_fd >= 0) {
            check("write-existing mode does not truncate on open",
                  fstat(file_fd, &(struct stat){0}) == 0);
            check("write existing file content",
                  write(file_fd, "changed", 7) == 7);
            close(file_fd);
            file_fd = mandalorian_safe_openat(root_fd, "nested/data.txt",
                                              MANDALORIAN_FS_READ);
            memset(buf, 0, sizeof(buf));
            n = file_fd >= 0 ? read(file_fd, buf, sizeof(buf)) : -1;
            check("write-existing changes only the opened regular file",
                  n == 7 && memcmp(buf, "changed", 7) == 0);
            if (file_fd >= 0) close(file_fd);
        }

        errno = 0;
        file_fd = mandalorian_safe_openat(root_fd, "nested/data.txt",
                                          (mandalorian_fs_access_t)99);
        check("reject unknown access mode", file_fd < 0 && errno == EINVAL);
        if (file_fd >= 0) close(file_fd);

        close(root_fd);
        root_fd = -1;
    }

    if (external_created_fd >= 0) {
        unlink(link_path);
        unlink(external_path);
    }
    unlink(file_path);
    rmdir(nested);
    rmdir(root_path);

    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
