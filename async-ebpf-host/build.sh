#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=${1:-"$root/async-ebpf-host/tinycc-host.o"}
stack_size=${TCC_EBPF_STACK_SIZE:-8388608}
work=$(mktemp -d "${TMPDIR:-/tmp}/tinycc-ebpf.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

case $(uname -m) in
  x86_64|amd64) host_define=TCC_TARGET_X86_64 ;;
  aarch64|arm64) host_define=TCC_TARGET_ARM64 ;;
  *) echo "unsupported async-ebpf host architecture: $(uname -m)" >&2; exit 1 ;;
esac

clang -DC2STR "$root/conftest.c" -o "$work/c2str"
"$work/c2str" "$root/include/tccdefs.h" "$work/tccdefs_.h"

clang -target bpf -mcpu=v3 -O2 -g0 -fno-builtin -fno-stack-protector \
  -nostdinc -I"$work" -I"$root/async-ebpf-host/include" -I"$root" \
  -D"$host_define" "-DTCC_EBPF_STACK_SIZE=${stack_size}UL" '-DTCC_EBPF_TCCDEFS=<tccdefs_.h>' \
  -emit-llvm -c "$root/async-ebpf-host/guest.c" \
  -o "$work/guest.bc"
llvm-dis "$work/guest.bc" -o "$work/guest.ll"
perl "$root/async-ebpf-host/lower-signed-div.pl" "$work/guest.ll" > "$work/lowered.ll"
llvm-as "$work/lowered.ll" -o "$work/lowered.bc"
opt -passes='internalize,globaldce' -internalize-public-api-list=entry \
  "$work/lowered.bc" -o "$work/dce.bc"
llvm-dis "$work/dce.bc" -o "$work/dce.ll"

# async-ebpf enters a code section at slot zero. Keep the public entry function
# first while retaining every local function in the same section.
perl -0777 -e '
  $s = <>;
  $s =~ s/(^define[^\n]*\@entry\([^\n]*\).*?^}\n)//ms or die "entry not found\n";
  $entry = $1;
  $s =~ s/^(define )/$entry$1/m or die "first function not found\n";
  print $s;
' "$work/dce.ll" > "$work/final.ll"
llvm-as "$work/final.ll" -o "$work/final.bc"
llc -march=bpf -mcpu=v3 --float-abi=soft -bpf-stack-size=4096 \
  -filetype=obj "$work/final.bc" -o "$work/guest.o"

# async-ebpf maps file-backed ELF contents. Materialize zero-fill storage so
# mutable compiler globals have backing bytes in that mapping.
llvm-objcopy --set-section-flags=.bss=alloc,data,contents "$work/guest.o" "$output"
echo "$output"
