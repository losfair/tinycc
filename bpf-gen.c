#ifdef TARGET_DEFS_ONLY

#define NB_REGS 10

#define RC_INT  (1 << 0)
#define RC_FLOAT (1 << 1)
#define RC_R(x) (1 << (2 + (x)))

#define RC_IRET RC_R(0)
#define RC_IRE2 RC_R(1)

#define REG_IRET 0
#define REG_IRE2 1
#define REG_FRET 0

#define PTR_SIZE 8
#define LDOUBLE_SIZE 8
#define LDOUBLE_ALIGN 8
#define MAX_ALIGN 8

#else

#define USING_GLOBALS
#include "tcc.h"
#include <assert.h>

#define BPF_LD     0x00
#define BPF_LDX    0x01
#define BPF_STX    0x03
#define BPF_ALU    0x04
#define BPF_JMP    0x05
#define BPF_JMP32  0x06
#define BPF_ALU64  0x07

#define BPF_W      0x00
#define BPF_H      0x08
#define BPF_B      0x10
#define BPF_DW     0x18
#define BPF_IMM    0x00
#define BPF_MEM    0x60

#define BPF_ADD    0x00
#define BPF_SUB    0x10
#define BPF_MUL    0x20
#define BPF_DIV    0x30
#define BPF_OR     0x40
#define BPF_AND    0x50
#define BPF_LSH    0x60
#define BPF_RSH    0x70
#define BPF_MOD    0x90
#define BPF_XOR    0xa0
#define BPF_MOV    0xb0
#define BPF_ARSH   0xc0

#define BPF_JA     0x00
#define BPF_JEQ    0x10
#define BPF_JGT    0x20
#define BPF_JGE    0x30
#define BPF_JNE    0x50
#define BPF_JSGT   0x60
#define BPF_JSGE   0x70
#define BPF_CALL   0x80
#define BPF_EXIT   0x90
#define BPF_JLT    0xa0
#define BPF_JLE    0xb0
#define BPF_JSLT   0xc0
#define BPF_JSLE   0xd0

#define BPF_K      0x00
#define BPF_X      0x08

#define BPF_FP     10
#define BPF_CMP32  0x8000

ST_DATA const char * const target_machine_defs =
    "__BPF__ 1\0"
    "__bpf__ 1\0"
    ;

ST_DATA const int reg_classes[NB_REGS] = {
    RC_INT | RC_R(0),
    RC_INT | RC_R(1),
    RC_INT | RC_R(2),
    RC_INT | RC_R(3),
    RC_INT | RC_R(4),
    RC_INT | RC_R(5),
    RC_INT | RC_R(6),
    RC_INT | RC_R(7),
    RC_INT | RC_R(8),
    RC_INT | RC_R(9),
};

#if defined(CONFIG_TCC_BCHECK)
ST_DATA int func_bound_add_epilog;
#endif

static int bpf_cpu(void)
{
    return tcc_state->bpf_cpu_version ? tcc_state->bpf_cpu_version : 3;
}

static int is32_type(int t)
{
    t &= VT_BTYPE;
    return t != VT_LLONG && t != VT_PTR && t != VT_FUNC;
}

static void obpf(uint8_t code, int dst, int src, int off, int imm)
{
    int ind1 = ind + 8;
    if (nocode_wanted)
        return;
    if (ind1 > cur_text_section->data_allocated)
        section_realloc(cur_text_section, ind1);
    cur_text_section->data[ind + 0] = code;
    cur_text_section->data[ind + 1] = (dst & 15) | ((src & 15) << 4);
    write16le(cur_text_section->data + ind + 2, off);
    write32le(cur_text_section->data + ind + 4, imm);
    ind = ind1;
}

static void o_alu(int cls, int op, int dst, int src)
{
    obpf(cls | op | BPF_X, dst, src, 0, 0);
}

static void o_alui(int cls, int op, int dst, int imm)
{
    obpf(cls | op | BPF_K, dst, 0, 0, imm);
}

static void o_mov(int cls, int dst, int src)
{
    if (dst != src)
        o_alu(cls, BPF_MOV, dst, src);
}

static void o_ldimm64(int dst, int64_t imm)
{
    obpf(BPF_LD | BPF_DW | BPF_IMM, dst, 0, 0, (uint32_t)imm);
    obpf(0, 0, 0, 0, (uint32_t)(imm >> 32));
}

static void o_ldsym64(int dst, Sym *sym, int64_t addend)
{
    greloca(cur_text_section, sym, ind, R_BPF_64_64, addend);
    o_ldimm64(dst, 0);
}

static int bpf_size(int size)
{
    return size == 1 ? BPF_B : size == 2 ? BPF_H : size == 4 ? BPF_W : BPF_DW;
}

static void check_off(int off)
{
    if (off < -32768 || off > 32767)
        tcc_error("bpf stack/access offset out of range");
}

static void sx_reg(int r, int bits)
{
    int cls = bpf_cpu() >= 3 ? BPF_ALU : BPF_ALU64;
    int sh = (cls == BPF_ALU) ? 32 - bits : 64 - bits;
    o_alui(cls, BPF_LSH, r, sh);
    o_alui(cls, BPF_ARSH, r, sh);
}

static int load_ptr_base(int r, SValue *sv, int *off)
{
    int fr = sv->r;
    int v = fr & VT_VALMASK;
    *off = sv->c.i;
    if (fr & VT_SYM) {
        o_ldsym64(r, sv->sym, sv->c.i);
        *off = 0;
        return r;
    }
    if (v == VT_LOCAL)
        return BPF_FP;
    if (v == VT_LLOCAL) {
        check_off(*off);
        obpf(BPF_LDX | BPF_DW | BPF_MEM, r, BPF_FP, *off, 0);
        *off = 0;
        return r;
    }
    if (v < VT_CONST) {
        *off = 0;
        return v;
    }
    if (v == VT_CONST) {
        o_ldimm64(r, sv->c.i);
        *off = 0;
        return r;
    }
    tcc_error("unsupported bpf lvalue");
    return r;
}

ST_FUNC void load(int r, SValue *sv)
{
    int fr = sv->r;
    int v = fr & VT_VALMASK;
    int bt = sv->type.t & VT_BTYPE;
    int align, size, off, base, cls;

    if (fr & VT_LVAL) {
        size = type_size(&sv->type, &align);
        if (bt == VT_PTR || bt == VT_FUNC)
            size = PTR_SIZE;
        if (size > 8)
            tcc_error("unsupported bpf load size");
        base = load_ptr_base(r, sv, &off);
        check_off(off);
        obpf(BPF_LDX | bpf_size(size) | BPF_MEM, r, base, off, 0);
        if (size == 1 && !(sv->type.t & VT_UNSIGNED))
            sx_reg(r, 8);
        else if (size == 2 && !(sv->type.t & VT_UNSIGNED))
            sx_reg(r, 16);
        return;
    }

    if (v == VT_CONST) {
        if (fr & VT_SYM)
            o_ldsym64(r, sv->sym, sv->c.i);
        else if (is32_type(sv->type.t) && bpf_cpu() >= 3)
            o_alui(BPF_ALU, BPF_MOV, r, sv->c.i);
        else if (sv->c.i == (int32_t)sv->c.i)
            o_alui(BPF_ALU64, BPF_MOV, r, sv->c.i);
        else
            o_ldimm64(r, sv->c.i);
    } else if (v == VT_LOCAL) {
        o_mov(BPF_ALU64, r, BPF_FP);
        if (sv->c.i)
            o_alui(BPF_ALU64, BPF_ADD, r, sv->c.i);
    } else if (v < VT_CONST) {
        cls = is32_type(sv->type.t) && bpf_cpu() >= 3 ? BPF_ALU : BPF_ALU64;
        o_mov(cls, r, v);
    } else if (v == VT_CMP) {
        int op = sv->cmp_op;
        int a = sv->cmp_r & 0x0f;
        int b = (sv->cmp_r >> 8) & 0x0f;
        int jcls = (sv->cmp_r & BPF_CMP32) ? BPF_JMP32 : BPF_JMP;
        switch (op) {
        case TOK_EQ:  op = BPF_JEQ; break;
        case TOK_NE:  op = BPF_JNE; break;
        case TOK_ULT: op = BPF_JLT; break;
        case TOK_ULE: op = BPF_JLE; break;
        case TOK_UGT: op = BPF_JGT; break;
        case TOK_UGE: op = BPF_JGE; break;
        case TOK_LT:  op = BPF_JSLT; break;
        case TOK_LE:  op = BPF_JSLE; break;
        case TOK_GT:  op = BPF_JSGT; break;
        case TOK_GE:  op = BPF_JSGE; break;
        default: tcc_error("unsupported bpf compare");
        }
        obpf(jcls | op | BPF_X, a, b, 2, 0);
        o_alui(BPF_ALU64, BPF_MOV, r, 0);
        gjmp_addr(ind + 16);
        o_alui(BPF_ALU64, BPF_MOV, r, 1);
    } else if ((v & ~1) == VT_JMP) {
        int t = v & 1;
        o_alui(BPF_ALU64, BPF_MOV, r, t);
        gjmp_addr(ind + 16);
        gsym(sv->c.i);
        o_alui(BPF_ALU64, BPF_MOV, r, t ^ 1);
    } else {
        tcc_error("unsupported bpf load");
    }
}

ST_FUNC void store(int r, SValue *sv)
{
    int bt = sv->type.t & VT_BTYPE;
    int align, size = type_size(&sv->type, &align);
    int off, base, tmp = 9;
    if (bt == VT_PTR || bt == VT_FUNC)
        size = PTR_SIZE;
    if (bt == VT_STRUCT || size > 8)
        tcc_error("unsupported bpf store size");
    base = load_ptr_base(tmp, sv, &off);
    check_off(off);
    obpf(BPF_STX | bpf_size(size) | BPF_MEM, base, r, off, 0);
}

static int invert_jop(int op)
{
    switch (op) {
    case TOK_EQ: return BPF_JNE;
    case TOK_NE: return BPF_JEQ;
    case TOK_ULT: return BPF_JGE;
    case TOK_ULE: return BPF_JGT;
    case TOK_UGT: return BPF_JLE;
    case TOK_UGE: return BPF_JLT;
    case TOK_LT: return BPF_JSGE;
    case TOK_LE: return BPF_JSGT;
    case TOK_GT: return BPF_JSLE;
    case TOK_GE: return BPF_JSLT;
    }
    tcc_error("unsupported bpf branch");
    return BPF_JA;
}

ST_FUNC void gsym_addr(int t, int a)
{
    while (t) {
        unsigned char *p = cur_text_section->data + t;
        int next = read32le(p + 4);
        int off = (a - t) / 8 - 1;
        check_off(off);
        write16le(p + 2, off);
        write32le(p + 4, 0);
        t = next;
    }
}

ST_FUNC int gjmp(int t)
{
    if (nocode_wanted)
        return t;
    obpf(BPF_JMP | BPF_JA, 0, 0, 0, t);
    return ind - 8;
}

ST_FUNC void gjmp_addr(int a)
{
    int off = (a - ind) / 8 - 1;
    check_off(off);
    obpf(BPF_JMP | BPF_JA, 0, 0, off, 0);
}

ST_FUNC int gjmp_cond(int op, int t)
{
    int a = vtop->cmp_r & 0x0f;
    int b = (vtop->cmp_r >> 8) & 0x0f;
    int jcls = (vtop->cmp_r & BPF_CMP32) ? BPF_JMP32 : BPF_JMP;
    obpf(jcls | invert_jop(op) | BPF_X, a, b, 1, 0);
    return gjmp(t);
}

ST_FUNC int gjmp_append(int n, int t)
{
    if (n) {
        int n1 = n, n2;
        unsigned char *p;
        while ((n2 = read32le((p = cur_text_section->data + n1) + 4)))
            n1 = n2;
        write32le(p + 4, t);
        t = n;
    }
    return t;
}

static void gen_opil(int op, int is64)
{
    int a, b, d, cls = is64 ? BPF_ALU64 : BPF_ALU;
    if (!is64 && bpf_cpu() < 3)
        cls = BPF_ALU64;
    gv2(RC_INT, RC_INT);
    a = vtop[-1].r;
    b = vtop[0].r;
    vtop -= 2;
    d = get_reg(RC_INT);
    vtop++;
    vtop[0].r = d;
    switch (op) {
    case '+': o_mov(cls, d, a); o_alu(cls, BPF_ADD, d, b); break;
    case '-': o_mov(cls, d, a); o_alu(cls, BPF_SUB, d, b); break;
    case '*': o_mov(cls, d, a); o_alu(cls, BPF_MUL, d, b); break;
    case '&': o_mov(cls, d, a); o_alu(cls, BPF_AND, d, b); break;
    case '|': o_mov(cls, d, a); o_alu(cls, BPF_OR, d, b); break;
    case '^': o_mov(cls, d, a); o_alu(cls, BPF_XOR, d, b); break;
    case TOK_SHL: o_mov(cls, d, a); o_alu(cls, BPF_LSH, d, b); break;
    case TOK_SHR: o_mov(cls, d, a); o_alu(cls, BPF_RSH, d, b); break;
    case TOK_SAR: o_mov(cls, d, a); o_alu(cls, BPF_ARSH, d, b); break;
    case TOK_UDIV:
    case TOK_PDIV:
        o_mov(cls, d, a); o_alu(cls, BPF_DIV, d, b); break;
    case TOK_UMOD:
        o_mov(cls, d, a); o_alu(cls, BPF_MOD, d, b); break;
    case '/':
    case '%':
        tcc_error("bpf does not support signed division or modulo");
        break;
    default:
        if (op >= TOK_ULT && op <= TOK_GT) {
            vset_VT_CMP(op);
            vtop->cmp_r = a | (b << 8) | (cls == BPF_ALU ? BPF_CMP32 : 0);
        } else {
            tcc_error("unsupported bpf operation");
        }
        break;
    }
}

ST_FUNC void gen_opi(int op)
{
    gen_opil(op, 0);
}

ST_FUNC void gen_opl(int op)
{
    gen_opil(op, 1);
}

ST_FUNC void gen_opf(int op)
{
    tcc_error("bpf does not support floating point");
}

ST_FUNC void gen_cvt_csti(int t)
{
    int r = gv(RC_INT);
    int bits = (t & VT_BTYPE) == VT_SHORT ? 16 : 8;
    if (t & VT_UNSIGNED)
        o_alui(BPF_ALU64, BPF_AND, r, (1 << bits) - 1);
    else
        sx_reg(r, bits);
}

ST_FUNC void gen_cvt_sxtw(void)
{
    int r = gv(RC_INT);
    sx_reg(r, 32);
}

ST_FUNC void gen_cvt_itof(int t)
{
    tcc_error("bpf does not support floating point");
}

ST_FUNC void gen_cvt_ftoi(int t)
{
    tcc_error("bpf does not support floating point");
}

ST_FUNC void gen_cvt_ftof(int t)
{
    tcc_error("bpf does not support floating point");
}

ST_FUNC void gfunc_call(int nb_args)
{
    int i;
    if (nb_args > 5)
        tcc_error("bpf supports at most five call arguments");
    for (i = 0; i < nb_args; i++) {
        vrotb(nb_args - i);
        gv(RC_R(i + 1));
        vrott(nb_args - i);
    }
    vrotb(nb_args + 1);
    save_regs(nb_args + 1);
    if ((vtop->r & (VT_VALMASK | VT_LVAL)) == VT_CONST) {
        if (vtop->r & VT_SYM) {
            int imm = -1;
            if (vtop->sym->c) {
                ElfSym *esym = elfsym(vtop->sym);
                if (esym->st_shndx == cur_text_section->sh_num)
                    imm = esym->st_value / 8 - 1;
            }
            greloca(cur_text_section, vtop->sym, ind, R_BPF_64_32, 0);
            obpf(BPF_JMP | BPF_CALL, 0, 1, 0, imm);
        } else {
            obpf(BPF_JMP | BPF_CALL, 0, 0, 0, vtop->c.i);
        }
    } else {
        tcc_error("bpf does not support indirect calls");
    }
    vtop -= nb_args + 1;
}

ST_FUNC void gfunc_prolog(Sym *func_sym)
{
    CType *func_type = &func_sym->type;
    Sym *sym = func_type->ref;
    int arg = 1, align, size;
    loc = 0;
    func_vc = 0;
    while ((sym = sym->next) != NULL) {
        size = type_size(&sym->type, &align);
        if (size > 8 || (sym->type.t & VT_BTYPE) == VT_STRUCT)
            tcc_error("unsupported bpf parameter type");
        if (arg > 5)
            tcc_error("bpf supports at most five function parameters");
        loc -= 8;
        obpf(BPF_STX | BPF_DW | BPF_MEM, BPF_FP, arg, loc, 0);
        gfunc_set_param(sym, loc, 0);
        arg++;
    }
}

ST_FUNC void gfunc_epilog(void)
{
    obpf(BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
}

ST_FUNC int gfunc_sret(CType *vt, int variadic, CType *ret,
                       int *ret_align, int *regsize)
{
    int align, size = type_size(vt, &align);
    *ret_align = 1;
    *regsize = 8;
    ret->t = size <= 4 ? VT_INT : VT_LLONG;
    ret->ref = NULL;
    return size <= 8 && (vt->t & VT_BTYPE) != VT_STRUCT ? 1 : 0;
}

ST_FUNC void gen_fill_nops(int bytes)
{
    if (bytes & 7)
        tcc_error("bpf code alignment is not a multiple of 8");
    while (bytes > 0) {
        obpf(BPF_ALU64 | BPF_MOV | BPF_X, 0, 0, 0, 0);
        bytes -= 8;
    }
}

ST_FUNC void gen_va_start(void)
{
    tcc_error("bpf does not support varargs");
}

ST_FUNC void gen_vla_sp_save(int addr)
{
    tcc_error("bpf does not support vla");
}

ST_FUNC void gen_vla_sp_restore(int addr)
{
    tcc_error("bpf does not support vla");
}

ST_FUNC void gen_vla_alloc(CType *type, int align)
{
    tcc_error("bpf does not support vla");
}

ST_FUNC void ggoto(void)
{
    tcc_error("bpf does not support computed goto");
}

ST_FUNC void gen_increment_tcov(SValue *sv)
{
    tcc_error("bpf does not support test coverage");
}

#endif
