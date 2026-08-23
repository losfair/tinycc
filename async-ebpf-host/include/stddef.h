#ifndef TCC_EBPF_STDDEF_H
#define TCC_EBPF_STDDEF_H
typedef unsigned long size_t;
typedef long ptrdiff_t;
#define NULL ((void *)0)
#define offsetof(type, member) __builtin_offsetof(type, member)
#endif
