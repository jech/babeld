#include <sys/time.h>
#include <time.h>

#ifdef __APPLE__
#include "kernel_socket.c"
#else
#include "kernel_netlink.c"
#endif

/* Like gettimeofday, but should return monotonic time.  If POSIX clocks
   are not available, falls back to gettimeofday. */
int
gettime(struct timeval *tv)
{
#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 && defined(CLOCK_MONOTONIC)
    static int have_posix_clocks = -1;

    if(have_posix_clocks < 0) {
        struct timespec ts;
        int rc;
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

    return gettimeofday(tv, NULL);
}
