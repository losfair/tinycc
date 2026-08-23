#ifndef TCC_EBPF_SETJMP_H
#define TCC_EBPF_SETJMP_H
typedef struct { unsigned long opaque[8]; } jmp_buf[1];
int setjmp(jmp_buf);
void longjmp(jmp_buf, int);
#endif
