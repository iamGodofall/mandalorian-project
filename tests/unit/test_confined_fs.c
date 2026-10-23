#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "runtime/confined_fs.h"

static int failures;
static int checks;

static void check(const char *name, int ok)
{
    ++checks;
    if (ok) {
        printf("PASS: %s\n", name);
    } else {
        fprintf(stderr, "FAIL: %s (errno=%d: %s)\n",
                name, errno, strerror(errno));
        ++failures;
    }
}

int main(void)
{
    char root_template[] = "/tmp/mandalorian-confined-fs-XXXXXX";
    char *root = mkdtemp(root_template);
    char path[512];
    char buf[32] = {0};
    size_t got = 999;
    int root_fd = -1;
    int fd = -1;
    int rc;

    if (root == NULL) {
        perror("mkdtemp");
        return 2;
    }
    (void)snprintf(path, sizeof(path), "%s/data", root);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    check("create fixture file", fd >= 0);
    if (fd >= 0) {
        check("write fixture", write(fd, "original-long", 13) == 13);
        close(fd);
    }
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check("open trusted root", root_fd >= 0);

    if (root_fd >= 0) {
        rc = mandalorian_confined_read(root_fd, "data", buf, sizeof(buf), &got);
        check("read existing file", rc == 0 && got == 13 &&
              memcmp(buf, "original-long", 13) == 0);

        got = 999;
        errno = 0;
        rc = mandalorian_confined_read(root_fd, "data", buf, 4, &got);
        check("reject read that would silently truncate", rc == -1 &&
              errno == EFBIG && got == 999);

        rc = mandalorian_confined_write_existing(root_fd, "data", "new", 3);
        check("write existing file", rc == 0);
        memset(buf, 0, sizeof(buf));
        got = 0;
        rc = mandalorian_confined_read(root_fd, "data", buf, sizeof(buf), &got);
        check("write replaces old tail", rc == 0 && got == 3 &&
              memcmp(buf, "new", 3) == 0);

        rc = mandalorian_confined_write_existing(root_fd, "data", NULL, 0);
        check("empty write truncates existing file", rc == 0);
        got = 999;
        rc = mandalorian_confined_read(root_fd, "data", buf, sizeof(buf), &got);
        check("empty file reads as zero bytes", rc == 0 && got == 0);

        errno = 0;
        rc = mandalorian_confined_write_existing(root_fd, "missing", "x", 1);
        check("write does not create a missing file", rc == -1 && errno == ENOENT);

        errno = 0;
        rc = mandalorian_confined_read(root_fd, "../etc/passwd", buf,
                                       sizeof(buf), &got);
        check("read rejects parent traversal", rc == -1 && errno == EINVAL);

        errno = 0;
        rc = mandalorian_confined_read(root_fd, "data", NULL, 4, &got);
        check("read rejects null output buffer", rc == -1 && errno == EINVAL);

        errno = 0;
        rc = mandalorian_confined_write_existing(root_fd, "data", NULL, 1);
        check("write rejects null input buffer", rc == -1 && errno == EINVAL);

        /* Symlink targets must never be followed, even when the target is
         * a regular file inside the temporary test tree. */
        {
            char link_path[512];
            (void)snprintf(link_path, sizeof(link_path), "%s/alias", root);
            check("create symlink fixture", symlink("data", link_path) == 0);
            errno = 0;
            rc = mandalorian_confined_read(root_fd, "alias", buf,
                                           sizeof(buf), &got);
            check("read rejects final-component symlink",
                  rc == -1 && (errno == ELOOP || errno == EACCES));
            errno = 0;
            rc = mandalorian_confined_write_existing(root_fd, "alias", "bad", 3);
            check("write rejects final-component symlink",
                  rc == -1 && (errno == ELOOP || errno == EACCES));
            unlink(link_path);
        }

        /* A hard link creates an alias outside the trusted directory. */
        {
            char outside_path[] = "/tmp/mandalorian-hardlink-XXXXXX";
            int outside_fd = mkstemp(outside_path);
            if (outside_fd >= 0) {
                close(outside_fd);
                unlink(outside_path);
                check("create hard-link fixture",
                      link(path, outside_path) == 0);
                errno = 0;
                rc = mandalorian_confined_write_existing(root_fd, "data", "bad", 3);
                check("write rejects multiply-linked inode",
                      rc == -1 && errno == EMLINK);
                unlink(outside_path);
            } else {
                check("create hard-link fixture", 0);
            }
        }

        /* Invalid roots fail closed instead of being treated as directories. */
        {
            int file_fd = open(path, O_RDONLY | O_CLOEXEC);
            if (file_fd >= 0) {
                errno = 0;
                rc = mandalorian_confined_read(file_fd, "data", buf,
                                               sizeof(buf), &got);
                check("reject non-directory root descriptor",
                      rc == -1 && errno == ENOTDIR);
                close(file_fd);
            } else {
                check("open root-validation fixture", 0);
            }
        }

        close(root_fd);
    }

    unlink(path);
    rmdir(root);
    printf("%d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
