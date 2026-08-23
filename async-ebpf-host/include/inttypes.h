#ifndef TCC_EBPF_INTTYPES_H
#define TCC_EBPF_INTTYPES_H
#include <stdint.h>
typedef int64_t intmax_t;
typedef uint64_t uintmax_t;
#define PRId64 "ld"
#define PRIu64 "lu"
#define PRIx64 "lx"
#endif
