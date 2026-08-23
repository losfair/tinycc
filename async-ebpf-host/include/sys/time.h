#ifndef TCC_EBPF_SYS_TIME_H
#define TCC_EBPF_SYS_TIME_H
#include <time.h>
struct timeval { long tv_sec; long tv_usec; };
int gettimeofday(struct timeval *, void *);
#endif
