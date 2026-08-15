/**
 * @file secure_random.c
 * @brief OS CSPRNG access. See secure_random.h for why this exists.
 */

#include "secure_random.h"

#include <string.h>

#include "logging.h"

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#  define BESKAR_RANDOM_WINDOWS 1
#elif defined(__linux__)
#  include <errno.h>
#  include <unistd.h>
#  include <sys/syscall.h>
#  if defined(SYS_getrandom)
#    define BESKAR_RANDOM_GETRANDOM 1
#  endif
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
      defined(__NetBSD__)
#  include <stdlib.h>
#  define BESKAR_RANDOM_ARC4 1
#endif

#include <stdio.h>

/* Which source actually satisfied the last successful request. Set once the
 * first call succeeds so logs say what is really in use rather than what the
 * build was configured to prefer. */
static const char *active_source = "none";

#if defined(BESKAR_RANDOM_GETRANDOM)
static int fill_getrandom(uint8_t *buffer, size_t len)
{
    size_t filled = 0;

    while (filled < len) {
        /* getrandom() can return short, and can be interrupted. Neither is an
         * error; treating a short read as success is how partially-initialised
         * keys happen. */
        long r = syscall(SYS_getrandom, buffer + filled, len - filled, 0);

        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            return -1;
        }
        filled += (size_t)r;
    }

    active_source = "getrandom(2)";
    return 0;
}
#endif

#if defined(BESKAR_RANDOM_ARC4)
static int fill_arc4(uint8_t *buffer, size_t len)
{
    arc4random_buf(buffer, len);
    active_source = "arc4random_buf(3)";
    return 0;
}
#endif

#if defined(BESKAR_RANDOM_WINDOWS)
static int fill_windows(uint8_t *buffer, size_t len)
{
    if (BCryptGenRandom(NULL, buffer, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        return -1;
    }
    active_source = "BCryptGenRandom";
    return 0;
}
#endif

#if !defined(_WIN32)
static int fill_dev_urandom(uint8_t *buffer, size_t len)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got;

    if (f == NULL) {
        return -1;
    }

    /* Unbuffered: no reason to let libc copy entropy through a second buffer
     * that then sits in freed heap. */
    setvbuf(f, NULL, _IONBF, 0);

    got = fread(buffer, 1, len, f);
    fclose(f);

    if (got != len) {
        return -1;
    }

    active_source = "/dev/urandom";
    return 0;
}
#endif

int secure_random_bytes(uint8_t *buffer, size_t len)
{
    if (buffer == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

#if defined(BESKAR_RANDOM_GETRANDOM)
    if (fill_getrandom(buffer, len) == 0) {
        return 0;
    }
#endif
#if defined(BESKAR_RANDOM_ARC4)
    if (fill_arc4(buffer, len) == 0) {
        return 0;
    }
#endif
#if defined(BESKAR_RANDOM_WINDOWS)
    if (fill_windows(buffer, len) == 0) {
        return 0;
    }
#endif
#if !defined(_WIN32)
    if (fill_dev_urandom(buffer, len) == 0) {
        return 0;
    }
#endif

    /* Fail closed. There is deliberately no rand() fallback: a caller that
     * ignores this return value gets zeros, which is obviously broken, rather
     * than plausible bytes, which is silently broken. */
    memset(buffer, 0, len);
    LOG_ERROR("secure_random: no entropy source available; refusing to "
              "generate predictable bytes");
    return -1;
}

int secure_random_available(void)
{
    uint8_t probe[8];

    if (secure_random_bytes(probe, sizeof(probe)) != 0) {
        return 0;
    }

    memset(probe, 0, sizeof(probe));
    return 1;
}

const char *secure_random_source_name(void)
{
    return active_source;
}

void secure_zero(void *buffer, size_t len)
{
    /* volatile through the write, so the store cannot be treated as dead. */
    volatile uint8_t *p = (volatile uint8_t *)buffer;

    if (buffer == NULL) {
        return;
    }
    while (len--) {
        *p++ = 0;
    }
}
