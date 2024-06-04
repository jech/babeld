/*
Copyright 2007, 2008 by Grégoire Henry, Julien Cristau and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <sys/utsname.h>
#include <sys/time.h>
#include <sys/param.h>
#include <time.h>

#include "babeld.h"

#if defined(MOCKED_KERNEL)
#include "mocked_kernel.c"
#elif defined(__linux)
#include "kernel_netlink.c"
#else
#include "kernel_socket.c"
#endif

/* Like gettimeofday, but returns monotonic time.  If POSIX clocks are not
   available, falls back to gettimeofday but enforces monotonicity. */
int
gettime(struct timeval *tv)
{
    int rc;
    static time_t offset = 0, previous = 0;

#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 && defined(CLOCK_MONOTONIC)
    static int have_posix_clocks = -1;

    if(UNLIKELY(have_posix_clocks < 0)) {
        struct timespec ts;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0) {
            have_posix_clocks = 0;
        } else {
            have_posix_clocks = 1;
        }
    }

    if(have_posix_clocks) {
        struct timespec ts;
        int rc;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0)
            return rc;
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
        return rc;
    }
#endif

    rc = gettimeofday(tv, NULL);
    if(rc < 0)
        return rc;
    tv->tv_sec += offset;
    if(UNLIKELY(previous > tv->tv_sec)) {
        offset += previous - tv->tv_sec;
        tv->tv_sec = previous;
    }
    previous = tv->tv_sec;
    return rc;
}

/* If /dev/urandom doesn't exist, this will fail with ENOENT, which the
   caller will deal with gracefully. */

int
read_random_bytes(void *buf, int len)
{
    int fd, rc;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd < 0) {
        errno = ENOSYS;
        return -1;
    }

    rc = read(fd, buf, len);
    if(rc < len)
        rc = -1;

    close(fd);

    return rc;
}

int
add_import_table(int table)
{
    if(table < 0 || table > 0xFFFF) return -1;
    if(import_table_count > MAX_IMPORT_TABLES - 1) return -2;
    import_tables[import_table_count++] = table;
    return 0;
}

int
kernel_older_than(const char *sysname, int version, int sub_version)
{
    struct utsname un;
    int rc;
    int v = 0;
    int sub_v = 0;
    rc = uname(&un);
    if(rc < 0)
        return -1;
    if(strcmp(sysname, un.sysname) != 0)
        return -1;
    rc = sscanf(un.release, "%d.%d", &v, &sub_v);
    if(rc < 2)
        return -1;
    return (v < version || (v == version && sub_v < sub_version));
}
