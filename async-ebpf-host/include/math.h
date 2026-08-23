#ifndef TCC_EBPF_MATH_H
#define TCC_EBPF_MATH_H
#define HUGE_VAL (__builtin_huge_val())
#define HUGE_VALL (__builtin_huge_vall())
double ldexp(double, int);
long double ldexpl(long double, int);
#endif
