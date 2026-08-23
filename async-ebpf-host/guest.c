/* TinyCC compiled as an eBPF guest, while retaining the current host as its
   code-generation target. This translation unit is intentionally separate
   from bpf-gen.c: Clang compiles the compiler itself to eBPF. */
#define ONE_SOURCE 1
#define CONFIG_TCC_STATIC 1
#define CONFIG_TCC_BACKTRACE 0
#define CONFIG_TCC_BCHECK 0
#define CONFIG_TCC_SEMLOCK 0
#define NDEBUG 1
#define TCC_EBPF_HOST 1

#ifndef TCC_EBPF_STACK_SIZE
#define TCC_EBPF_STACK_SIZE (8UL * 1024 * 1024)
#endif
#define TCC_EBPF_CALL_SPACE (64UL * 1024)
#define TCC_EBPF_CALLDATA_SIZE 512UL

static unsigned char *arena_next;
static unsigned char *arena_limit;

#if TCC_EBPF_STACK_SIZE <= TCC_EBPF_CALL_SPACE + TCC_EBPF_CALLDATA_SIZE
#error "TCC_EBPF_STACK_SIZE must leave room for calldata and local calls"
#endif

extern unsigned long tcc_ebpf_input_copy(void *data, unsigned long len);
extern unsigned long tcc_ebpf_write(const void *data, unsigned long len);

__attribute__((noinline, optnone))
int tcc_ebpf_sdiv_i32(int a, int b)
{
    unsigned ua = a < 0 ? 0U - (unsigned)a : (unsigned)a;
    unsigned ub = b < 0 ? 0U - (unsigned)b : (unsigned)b;
    unsigned q = ua / ub;
    return (a < 0) != (b < 0) ? (int)(0U - q) : (int)q;
}

__attribute__((noinline, optnone))
long tcc_ebpf_sdiv_i64(long a, long b)
{
    unsigned long ua = a < 0 ? 0UL - (unsigned long)a : (unsigned long)a;
    unsigned long ub = b < 0 ? 0UL - (unsigned long)b : (unsigned long)b;
    unsigned long q = ua / ub;
    return (a < 0) != (b < 0) ? (long)(0UL - q) : (long)q;
}

__attribute__((noinline, optnone))
int tcc_ebpf_srem_i32(int a, int b)
{
    unsigned ua = a < 0 ? 0U - (unsigned)a : (unsigned)a;
    unsigned ub = b < 0 ? 0U - (unsigned)b : (unsigned)b;
    unsigned r = ua % ub;
    return a < 0 ? (int)(0U - r) : (int)r;
}

__attribute__((noinline, optnone))
long tcc_ebpf_srem_i64(long a, long b)
{
    unsigned long ua = a < 0 ? 0UL - (unsigned long)a : (unsigned long)a;
    unsigned long ub = b < 0 ? 0UL - (unsigned long)b : (unsigned long)b;
    unsigned long r = ua % ub;
    return a < 0 ? (long)(0UL - r) : (long)r;
}

void *tcc_ebpf_reallocator(void *old, unsigned long size)
{
    unsigned long *header;
    unsigned long old_size, aligned, available;
    unsigned char *result;
    if (!size)
        return 0;
    if (size > (unsigned long)-1 - 7)
        return 0;
    aligned = (size + 7) & ~7UL;
    if (arena_next > arena_limit)
        return 0;
    available = (unsigned long)(arena_limit - arena_next);
    if (available < sizeof(unsigned long) ||
        aligned > available - sizeof(unsigned long))
        return 0;
    header = (unsigned long *)arena_next;
    *header = size;
    result = (unsigned char *)(header + 1);
    arena_next = result + aligned;
    if (old) {
        unsigned long i;
        old_size = ((unsigned long *)old)[-1];
        if (old_size > size)
            old_size = size;
        for (i = 0; i < old_size; ++i)
            result[i] = ((unsigned char *)old)[i];
    }
    return result;
}

#include "../libtcc.h"

static int tcc_ebpf_compile(TCCState *, const char *);

unsigned long long entry(const char *calldata)
{
    TCCState *s;
    unsigned long source_len = *(const unsigned long *)calldata;
    unsigned char *stack_bottom = (unsigned char *)calldata +
                                  TCC_EBPF_CALLDATA_SIZE - TCC_EBPF_STACK_SIZE;
    char *source = (char *)stack_bottom;
    int rc;

    if (!source_len ||
        source_len > TCC_EBPF_STACK_SIZE - TCC_EBPF_CALL_SPACE -
                     TCC_EBPF_CALLDATA_SIZE)
        return 1;
    arena_next = stack_bottom + ((source_len + 7) & ~7UL);
    arena_limit = (unsigned char *)calldata - TCC_EBPF_CALL_SPACE;
    if (!tcc_ebpf_input_copy(source, source_len))
        return 1;
    s = tcc_new();
    if (!s)
        return 1;
    rc = tcc_ebpf_compile(s, source);
    tcc_delete(s);
    return rc ? (unsigned)rc : 1;
}

#include "../libtcc.c"

#undef text_section

static int tcc_ebpf_compile(TCCState *s, const char *source)
{
    int rc;
    s->nostdinc = 1;
    s->nostdlib = 1;
    rc = tcc_set_output_type(s, TCC_OUTPUT_OBJ);
    if (!rc)
        rc = tcc_compile_string(s, source);
    if (!rc) {
        rc = tcc_output_file(s, "tinycc-bootstrap.o");
    }
    return rc ? (unsigned)rc : 1;
}

static __attribute__((always_inline)) int
format_put(char *dst, unsigned long cap, unsigned long *pos, char ch)
{
    if (dst && *pos + 1 < cap)
        dst[*pos] = ch;
    ++*pos;
    return 0;
}

static __attribute__((always_inline)) int
format_unsigned(char *dst, unsigned long cap, unsigned long *pos,
                           unsigned long value, unsigned base, int upper,
                           int width, int zero, int negative)
{
    char tmp[32];
    int n = 0, total, i;
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    do {
        tmp[n++] = digits[value % base];
        value /= base;
    } while (value && n < (int)sizeof(tmp));
    total = n + negative;
    if (!zero)
        while (total++ < width)
            format_put(dst, cap, pos, ' ');
    if (negative)
        format_put(dst, cap, pos, '-');
    if (zero)
        while (total++ < width)
            format_put(dst, cap, pos, '0');
    for (i = n - 1; i >= 0; --i)
        format_put(dst, cap, pos, tmp[i]);
    return 0;
}

static int format_fixed(char *dst, unsigned long cap, const char *fmt,
                        const unsigned long *args, unsigned nargs)
{
    unsigned ai = 0;
    unsigned long pos = 0;
    while (*fmt) {
        int zero = 0, width = 0, precision = -1;
        char conv;
        unsigned long value;
        if (*fmt != '%') {
            format_put(dst, cap, &pos, *fmt++);
            continue;
        }
        ++fmt;
        if (*fmt == '%') {
            format_put(dst, cap, &pos, *fmt++);
            continue;
        }
        while (*fmt == '-' || *fmt == '+' || *fmt == ' ' || *fmt == '#')
            ++fmt;
        if (*fmt == '0')
            zero = 1, ++fmt;
        if (*fmt == '*')
            width = ai < nargs ? (int)args[ai++] : 0, ++fmt;
        else
            while (*fmt >= '0' && *fmt <= '9')
                width = width * 10 + *fmt++ - '0';
        if (*fmt == '.') {
            ++fmt;
            precision = 0;
            if (*fmt == '*')
                precision = ai < nargs ? (int)args[ai++] : 0, ++fmt;
            else
                while (*fmt >= '0' && *fmt <= '9')
                    precision = precision * 10 + *fmt++ - '0';
        }
        while (*fmt == 'h' || *fmt == 'l' || *fmt == 'L' || *fmt == 'z' || *fmt == 't')
            ++fmt;
        conv = *fmt ? *fmt++ : 0;
        value = ai < nargs ? args[ai++] : 0;
        if (conv == 's') {
            const char *s = (const char *)value;
            int n = 0;
            if (!s)
                s = "(null)";
            while (s[n] && (precision < 0 || n < precision))
                ++n;
            while (n < width--)
                format_put(dst, cap, &pos, ' ');
            while (n--)
                format_put(dst, cap, &pos, *s++);
        } else if (conv == 'c') {
            format_put(dst, cap, &pos, (char)value);
        } else if (conv == 'd' || conv == 'i') {
            long signed_value = (long)value;
            int negative = signed_value < 0;
            unsigned long magnitude = negative ? 0UL - (unsigned long)signed_value : value;
            format_unsigned(dst, cap, &pos, magnitude, 10, 0, width, zero, negative);
        } else if (conv == 'u') {
            format_unsigned(dst, cap, &pos, value, 10, 0, width, zero, 0);
        } else if (conv == 'x' || conv == 'X' || conv == 'p') {
            format_unsigned(dst, cap, &pos, value, 16, conv == 'X', width, zero, 0);
        } else if (conv == 'o') {
            format_unsigned(dst, cap, &pos, value, 8, 0, width, zero, 0);
        } else {
            format_put(dst, cap, &pos, '?');
        }
    }
    if (dst && cap)
        dst[pos < cap ? pos : cap - 1] = 0;
    return (int)pos;
}

int tcc_ebpf_printf(const char *fmt, const unsigned long *args, unsigned nargs)
{
    return format_fixed(0, 0, fmt, args, nargs);
}

int tcc_ebpf_fprintf(FILE *fp, const char *fmt, const unsigned long *args, unsigned nargs)
{
    (void)fp;
    return format_fixed(0, 0, fmt, args, nargs);
}

int tcc_ebpf_sprintf(char *dst, const char *fmt, const unsigned long *args, unsigned nargs)
{
    return format_fixed(dst, (unsigned long)-1, fmt, args, nargs);
}

int tcc_ebpf_snprintf(char *dst, size_t size, const char *fmt,
                      const unsigned long *args, unsigned nargs)
{
    return format_fixed(dst, size, fmt, args, nargs);
}

struct TccEbpfFile { int fd; };
static struct TccEbpfFile ebpf_stdout;
static struct TccEbpfFile ebpf_output;
FILE *stdin;
FILE *stdout = &ebpf_stdout;
FILE *stderr = &ebpf_stdout;
int errno;

void *memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        ((unsigned char *)dst)[i] = ((const unsigned char *)src)[i];
    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    size_t i;
    if (dst < src)
        return memcpy(dst, src, n);
    for (i = n; i; --i)
        ((unsigned char *)dst)[i - 1] = ((const unsigned char *)src)[i - 1];
    return dst;
}

void *memset(void *dst, int value, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i)
        ((unsigned char *)dst)[i] = (unsigned char)value;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        int d = ((const unsigned char *)a)[i] - ((const unsigned char *)b)[i];
        if (d)
            return d;
    }
    return 0;
}

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p)
        ++p;
    return p - s;
}

char *strcpy(char *dst, const char *src)
{
    char *out = dst;
    while ((*dst++ = *src++))
        ;
    return out;
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b)
        ++a, ++b;
    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    while (n && *a && *a == *b)
        ++a, ++b, --n;
    return n ? (unsigned char)*a - (unsigned char)*b : 0;
}

char *strchr(const char *s, int ch)
{
    do {
        if (*s == (char)ch)
            return (char *)s;
    } while (*s++);
    return 0;
}

char *strrchr(const char *s, int ch)
{
    const char *found = 0;
    do {
        if (*s == (char)ch)
            found = s;
    } while (*s++);
    return (char *)found;
}

char *strstr(const char *s, const char *needle)
{
    size_t n = strlen(needle);
    if (!n)
        return (char *)s;
    for (; *s; ++s)
        if (!strncmp(s, needle, n))
            return (char *)s;
    return 0;
}

char *strpbrk(const char *s, const char *accept)
{
    const char *a;
    for (; *s; ++s)
        for (a = accept; *a; ++a)
            if (*s == *a)
                return (char *)s;
    return 0;
}

static unsigned long parse_unsigned(const char *s, char **end, int base)
{
    unsigned long value = 0;
    int digit;
    while (*s == ' ' || *s == '\t')
        ++s;
    if (!base)
        base = s[0] == '0' && (s[1] == 'x' || s[1] == 'X') ? 16 : 10;
    if (base == 16 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (;;) {
        if (*s >= '0' && *s <= '9')
            digit = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            digit = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            digit = *s - 'A' + 10;
        else
            break;
        if (digit >= base)
            break;
        value = value * (unsigned)base + (unsigned)digit;
        ++s;
    }
    if (end)
        *end = (char *)s;
    return value;
}

unsigned long strtoul(const char *s, char **end, int base)
{
    int neg = *s == '-';
    if (*s == '-' || *s == '+')
        ++s;
    return neg ? 0UL - parse_unsigned(s, end, base) : parse_unsigned(s, end, base);
}

unsigned long long strtoull(const char *s, char **end, int base)
{
    return strtoul(s, end, base);
}

long strtol(const char *s, char **end, int base)
{
    return (long)strtoul(s, end, base);
}

int atoi(const char *s)
{
    return (int)strtol(s, 0, 10);
}

int setjmp(jmp_buf env)
{
    (void)env;
    return 0;
}

void longjmp(jmp_buf env, int value)
{
    (void)env;
    (void)value;
}

void exit(int status)
{
    (void)status;
}

int tcc_ebpf_open(const char *name, int flags, int mode)
{
    (void)name;
    (void)flags;
    (void)mode;
    return 1;
}

int close(int fd)
{
    (void)fd;
    return 0;
}

int unlink(const char *name)
{
    (void)name;
    return 0;
}

int remove(const char *name)
{
    (void)name;
    return 0;
}

ssize_t read(int fd, void *dst, size_t n)
{
    (void)fd;
    (void)dst;
    (void)n;
    return -1;
}

off_t lseek(int fd, off_t off, int whence)
{
    (void)fd;
    (void)off;
    (void)whence;
    return -1;
}

int fputs(const char *s, FILE *f)
{
    (void)f;
    return (int)strlen(s);
}
int fputc(int ch, FILE *f)
{
    unsigned char byte = ch;
    (void)f;
    return tcc_ebpf_write(&byte, 1) == 1 ? ch : EOF;
}
size_t fwrite(const void *data, size_t size, size_t count, FILE *f)
{
    unsigned long len = size * count;
    (void)f;
    return tcc_ebpf_write(data, len) == len ? count : 0;
}
int fgetc(FILE *f)
{
    (void)f;
    return EOF;
}

int fseek(FILE *f, long offset, int whence)
{
    (void)f;
    (void)offset;
    (void)whence;
    return -1;
}

long ftell(FILE *f)
{
    (void)f;
    return -1;
}

FILE *fdopen(int fd, const char *mode)
{
    (void)fd;
    (void)mode;
    return &ebpf_output;
}

int fclose(FILE *f)
{
    (void)f;
    return 0;
}

int fflush(FILE *f)
{
    (void)f;
    return 0;
}

time_t time(time_t *out)
{
    if (out)
        *out = 0;
    return 0;
}

struct tm *localtime(const time_t *value)
{
    (void)value;
    return 0;
}

char *realpath(const char *path, char *out)
{
    (void)path;
    (void)out;
    return 0;
}

char *getcwd(char *out, size_t size)
{
    if (size)
        *out = 0;
    return out;
}

char *getenv(const char *name)
{
    (void)name;
    return 0;
}
void qsort(void *base, size_t n, size_t size,
           int (*compare)(const void *, const void *))
{
    unsigned char *data = base;
    size_t i, j, k;

    /* TinyCC only needs a small, freestanding sort here.  Swapping adjacent
       elements avoids another allocator dependency and works for all element
       widths used by its code generator. */
    for (i = n; i > 1; --i) {
        int swapped = 0;
        for (j = 1; j < i; ++j) {
            unsigned char *left = data + (j - 1) * size;
            unsigned char *right = left + size;
            if (compare(left, right) > 0) {
                for (k = 0; k < size; ++k) {
                    unsigned char byte = left[k];
                    left[k] = right[k];
                    right[k] = byte;
                }
                swapped = 1;
            }
        }
        if (!swapped)
            break;
    }
}
