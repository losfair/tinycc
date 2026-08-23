#ifndef TCC_EBPF_UNISTD_H
#define TCC_EBPF_UNISTD_H
#include <stddef.h>
typedef long ssize_t;
typedef long off_t;
#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2
ssize_t read(int, void *, size_t);
ssize_t write(int, const void *, size_t);
off_t lseek(int, off_t, int);
int close(int);
int unlink(const char *);
char *getcwd(char *, size_t);
#endif
