#ifndef TCC_EBPF_ASSERT_H
#define TCC_EBPF_ASSERT_H
#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
void tcc_ebpf_assert_fail(const char *, const char *, int);
#define assert(expr) ((expr) ? (void)0 : tcc_ebpf_assert_fail(#expr, __FILE__, __LINE__))
#endif
#endif
