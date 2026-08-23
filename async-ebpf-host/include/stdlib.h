#ifndef TCC_EBPF_STDLIB_H
#define TCC_EBPF_STDLIB_H
#include <stddef.h>
void *malloc(size_t);
void *calloc(size_t, size_t);
void *realloc(void *, size_t);
void free(void *);
void exit(int);
int atoi(const char *);
long strtol(const char *, char **, int);
unsigned long strtoul(const char *, char **, int);
long long strtoll(const char *, char **, int);
unsigned long long strtoull(const char *, char **, int);
double strtod(const char *, char **);
float strtof(const char *, char **);
long double strtold(const char *, char **);
void qsort(void *, size_t, size_t, int (*)(const void *, const void *));
char *realpath(const char *, char *);
char *getenv(const char *);
#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1
#endif
