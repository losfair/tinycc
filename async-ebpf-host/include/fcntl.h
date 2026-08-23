#ifndef TCC_EBPF_FCNTL_H
#define TCC_EBPF_FCNTL_H
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#ifdef TCC_EBPF_HOST
#include <tcc-ebpf-format.h>
int tcc_ebpf_open(const char *, int, int);
#define TCC_EBPF_OPEN_0(name, flags) tcc_ebpf_open((name), (flags), 0)
#define TCC_EBPF_OPEN_1(name, flags, mode) \
    tcc_ebpf_open((name), (flags), (mode))
#define open(name, flags, ...) \
    TCC_EBPF_FMT_CAT(TCC_EBPF_OPEN_, TCC_EBPF_FMT_NARG(__VA_ARGS__)) \
        (name, flags, ##__VA_ARGS__)
#else
int open(const char *, int, ...);
#endif
#endif
