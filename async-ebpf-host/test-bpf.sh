#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
async_worktree=${ASYNC_EBPF_WORKTREE:-"$(dirname -- "$root")/async-ebpf"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
TCC_EBPF_TARGET=bpf TCC_EBPF_VFS=0 TCC_EBPF_STACK_SIZE=8388608 \
  "$root/async-ebpf-host/build.sh" "$work/compiler.bpf"

fails=0

run_guest() {
  ( cd "$async_worktree" && TCC_EBPF_STACK_SIZE=8388608 \
      cargo run --quiet --features testing --example tinycc_host -- "$@" )
}

# Compile one program with the eBPF-hosted compiler, run the result under
# async-ebpf and compare what it returns against the expected value.
check() {
  name=$1
  want=$2
  src=$3
  printf '%s' "$src" > "$work/case.c"
  if ! run_guest "$work/compiler.bpf" "$work/case.c" "$work/case.o" \
       > "$work/compile.log" 2>&1; then
    echo "FAIL $name: compilation failed"
    head -3 "$work/compile.log" | sed 's/^/    /'
    fails=$((fails + 1))
    return 0
  fi
  # The guest returns 1 when it emitted an object and -1 when it gave up, so a
  # rejected program has to be caught here rather than at execution time.
  if ! grep -q '^tinycc result: 0x1$' "$work/compile.log"; then
    echo "FAIL $name: compiler rejected the program"
    grep '^tinycc' "$work/compile.log" | sed 's/^/    /'
    fails=$((fails + 1))
    return 0
  fi
  if ! run_guest "$work/case.o" unused > "$work/run.log" 2>&1; then
    echo "FAIL $name: execution failed"
    head -3 "$work/run.log" | sed 's/^/    /'
    fails=$((fails + 1))
    return 0
  fi
  got=$(sed -n 's/^tinycc result: //p' "$work/run.log")
  if [ "$got" = "$want" ]; then
    echo "ok   $name"
  else
    echo "FAIL $name: got $got, want $want"
    fails=$((fails + 1))
  fi
  return 0
}

check 'mutable global' 0x2a \
  'volatile long zero; long main(void) { return ++zero + 41; }'

# A global symbol referenced at a non-zero constant offset.  BPF relocations
# carry no addend field, so the offset has to reach the instruction stream
# some other way.
check 'global + constant offset, store and load' 0x7 \
  'static char buf[64]; long main(void) { buf[5] = 7; return buf[5]; }'
check 'global + constant offset, word array' 0x2a \
  'static long arr[8]; long main(void) { arr[1] = 41; return arr[1] + 1; }'
check 'global + constant offset, pointer arithmetic' 0x9 \
  'static char buf[64]; long main(void) { buf[1] = 9; return *(buf + 1); }'
check 'global + constant offset, struct field' 0x2a \
  'struct S { unsigned long a, b; }; static struct S s;
   long main(void) { s.b = 42; return (long)s.b; }'
check 'global + constant offset, read-only data' 0x62 \
  'static const char C[] = "abc"; long main(void) { return C[1]; }'
check 'global + constant offset, address of element' 0x5 \
  'static char buf[64]; static char *p;
   long main(void) { p = &buf[1]; *p = 5; return buf[1]; }'

# Pointer initializers in static storage need a data relocation the loader
# actually applies, with the addend held in the relocated word.
check 'pointer initializer is not null' 0x4e \
  'static char buf[8]; static char *P = buf;
   long main(void) { return P == 0 ? 77 : 78; }'
check 'pointer initializer to a string literal' 0x65 \
  'static const char *S = "hello"; long main(void) { return S[1]; }'
check 'pointer initializer with an offset' 0x2a \
  'static char buf[8]; static char *Q = buf + 3;
   long main(void) { buf[3] = 42; return *Q; }'
check 'array of pointer initializers' 0x62 \
  'static const char *T[2] = {"a", "bb"};
   long main(void) { unsigned i = 1; return T[i][1]; }'

# A statically false condition must skip only its own branch.  The jump over
# the dead branch can sit at text offset 0, which must still be a usable
# jump label.
check 'constant false if, dead call' 0x2a \
  'long side(void); long main(void) { if (0 > 0) side(); return 42; }
   long side(void) { return 1; }'
check 'constant false if, no call' 0x2a \
  'long main(void) { if (0) { } return 42; }'
check 'constant false comparison of literals' 0x2a \
  'long side(void); long main(void) { if (1 > 2) side(); return 42; }
   long side(void) { return 1; }'
check 'constant false while' 0x2a \
  'long side(void); long main(void) { while (0) { side(); } return 42; }
   long side(void) { return 1; }'
check 'constant false if with else' 0x2a \
  'long side(void); long other(void);
   long main(void) { if (0 > 0) { side(); } else { other(); } return 42; }
   long side(void) { return 1; } long other(void) { return 2; }'
check 'live branch still runs' 0x2b \
  'long main(void) { if (1) return 43; return 42; }'

if [ "$fails" -ne 0 ]; then
  echo "$fails eBPF compiler output test(s) failed" >&2
  exit 1
fi
echo 'eBPF compiler output executed successfully'
