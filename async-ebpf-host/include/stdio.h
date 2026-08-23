#ifndef TCC_EBPF_STDIO_H
#define TCC_EBPF_STDIO_H
#include <stddef.h>
#include <stdarg.h>
#ifdef TCC_EBPF_HOST
#include <tcc-ebpf-format.h>
#endif
typedef struct TccEbpfFile FILE;
extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;
#define EOF (-1)
#ifdef TCC_EBPF_HOST
int tcc_ebpf_printf(const char *, const unsigned long *, unsigned);
int tcc_ebpf_fprintf(FILE *, const char *, const unsigned long *, unsigned);
int tcc_ebpf_sprintf(char *, const char *, const unsigned long *, unsigned);
int tcc_ebpf_snprintf(char *, size_t, const char *, const unsigned long *, unsigned);
#define printf(fmt,...) TCC_EBPF_FMT_CALL1(tcc_ebpf_printf,fmt,##__VA_ARGS__)
#define fprintf(fp,fmt,...) TCC_EBPF_FMT_CALL2(tcc_ebpf_fprintf,fp,fmt,##__VA_ARGS__)
#define sprintf(dst,fmt,...) TCC_EBPF_FMT_CALL2(tcc_ebpf_sprintf,dst,fmt,##__VA_ARGS__)
#define snprintf(dst,size,fmt,...) TCC_EBPF_FMT_CALL3(tcc_ebpf_snprintf,dst,size,fmt,##__VA_ARGS__)
#else
int printf(const char *, ...);
int fprintf(FILE *, const char *, ...);
int sprintf(char *, const char *, ...);
int snprintf(char *, size_t, const char *, ...);
#endif
int vfprintf(FILE *, const char *, va_list);
int vsnprintf(char *, size_t, const char *, va_list);
int fputs(const char *, FILE *);
int fputc(int, FILE *);
int fgetc(FILE *);
int fseek(FILE *, long, int);
long ftell(FILE *);
int remove(const char *);
size_t fread(void *, size_t, size_t, FILE *);
size_t fwrite(const void *, size_t, size_t, FILE *);
FILE *fopen(const char *, const char *);
FILE *fdopen(int, const char *);
int fclose(FILE *);
int fflush(FILE *);
#endif
