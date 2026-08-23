#ifndef TCC_EBPF_FORMAT_MACROS_H
#define TCC_EBPF_FORMAT_MACROS_H

#define TCC_EBPF_FMT_ARGS_0() ((const unsigned long *)0)
#define TCC_EBPF_FMT_ARGS_1(a) ((const unsigned long[]){(unsigned long)(a)})
#define TCC_EBPF_FMT_ARGS_2(a, b) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b)})
#define TCC_EBPF_FMT_ARGS_3(a, b, c) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c)})
#define TCC_EBPF_FMT_ARGS_4(a, b, c, d) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c), (unsigned long)(d)})
#define TCC_EBPF_FMT_ARGS_5(a, b, c, d, e) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c), (unsigned long)(d), \
                             (unsigned long)(e)})
#define TCC_EBPF_FMT_ARGS_6(a, b, c, d, e, f) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c), (unsigned long)(d), \
                             (unsigned long)(e), (unsigned long)(f)})
#define TCC_EBPF_FMT_ARGS_7(a, b, c, d, e, f, g) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c), (unsigned long)(d), \
                             (unsigned long)(e), (unsigned long)(f), \
                             (unsigned long)(g)})
#define TCC_EBPF_FMT_ARGS_8(a, b, c, d, e, f, g, h) \
    ((const unsigned long[]){(unsigned long)(a), (unsigned long)(b), \
                             (unsigned long)(c), (unsigned long)(d), \
                             (unsigned long)(e), (unsigned long)(f), \
                             (unsigned long)(g), (unsigned long)(h)})

#define TCC_EBPF_FMT_NARG_I(_0, _1, _2, _3, _4, _5, _6, _7, _8, n, ...) n
#define TCC_EBPF_FMT_NARG(...) \
    TCC_EBPF_FMT_NARG_I(_, ##__VA_ARGS__, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define TCC_EBPF_FMT_CAT_I(a, b) a##b
#define TCC_EBPF_FMT_CAT(a, b) TCC_EBPF_FMT_CAT_I(a, b)
#define TCC_EBPF_FMT_ARGS(...) \
    TCC_EBPF_FMT_CAT(TCC_EBPF_FMT_ARGS_, TCC_EBPF_FMT_NARG(__VA_ARGS__)) \
        (__VA_ARGS__)

#define TCC_EBPF_FMT_CALL1(fn, a, ...) \
    (fn)((a), TCC_EBPF_FMT_ARGS(__VA_ARGS__), TCC_EBPF_FMT_NARG(__VA_ARGS__))
#define TCC_EBPF_FMT_CALL2(fn, a, b, ...) \
    (fn)((a), (b), TCC_EBPF_FMT_ARGS(__VA_ARGS__), TCC_EBPF_FMT_NARG(__VA_ARGS__))
#define TCC_EBPF_FMT_CALL3(fn, a, b, c, ...) \
    (fn)((a), (b), (c), TCC_EBPF_FMT_ARGS(__VA_ARGS__), \
         TCC_EBPF_FMT_NARG(__VA_ARGS__))

#endif
