#ifdef TARGET_DEFS_ONLY

#define EM_TCC_TARGET EM_BPF

#define R_DATA_32  R_BPF_64_64
#define R_DATA_PTR R_BPF_64_64
#define R_JMP_SLOT R_BPF_NONE
#define R_GLOB_DAT R_BPF_NONE
#define R_COPY     R_BPF_NONE
#define R_RELATIVE R_BPF_NONE

#define R_NUM      R_BPF_NUM

#define ELF_START_ADDR 0
#define ELF_PAGE_SIZE  0x1000

#define PCRELATIVE_DLLPLT 0
#define RELOCATE_DLLPLT 0

#else

#define USING_GLOBALS
#include "tcc.h"

ST_FUNC int code_reloc(int reloc_type)
{
    switch (reloc_type) {
    case R_BPF_64_32:
        return 1;
    case R_BPF_NONE:
    case R_BPF_64_64:
        return 0;
    }
    return -1;
}

ST_FUNC int gotplt_entry_type(int reloc_type)
{
    switch (reloc_type) {
    case R_BPF_NONE:
    case R_BPF_64_64:
    case R_BPF_64_32:
        return NO_GOTPLT_ENTRY;
    }
    return -1;
}

ST_FUNC unsigned create_plt_entry(TCCState *s1, unsigned got_offset,
                                  struct sym_attr *attr)
{
    return 0;
}

ST_FUNC void relocate_plt(TCCState *s1)
{
}

ST_FUNC void relocate(TCCState *s1, ElfW_Rel *rel, int type,
                      unsigned char *ptr, addr_t addr, addr_t val)
{
    switch (type) {
    case R_BPF_NONE:
        break;
    case R_BPF_64_64:
        write32le(ptr + 4, (uint32_t)val);
        write32le(ptr + 12, (uint32_t)(val >> 32));
        break;
    case R_BPF_64_32:
        write32le(ptr + 4, (uint32_t)((val - addr) / 8 - 1));
        break;
    default:
        tcc_error_noabort("unsupported bpf relocation type %d", type);
        break;
    }
}

#endif
