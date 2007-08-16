
#ifdef __APPLE__
#include "kernel_socket.c"
#else
#include "kernel_netlink.c"
#endif
