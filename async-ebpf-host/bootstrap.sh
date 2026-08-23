#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
async_worktree=${ASYNC_EBPF_WORKTREE:-"$(dirname -- "$root")/async-ebpf-tinycc"}
stack_size=${TCC_EBPF_STACK_SIZE:-67108864}
work=$(mktemp -d "${TMPDIR:-/tmp}/tinycc-bootstrap.XXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM

case $(uname -m) in
  aarch64|arm64)
    target_define=TCC_TARGET_ARM64
    target_name=AArch64
    ;;
  x86_64|amd64)
    target_define=TCC_TARGET_X86_64
    target_name=x86-64
    ;;
  *)
    echo "bootstrap comparison requires an AArch64 or x86-64 host" >&2
    exit 1
    ;;
esac

test -f "$async_worktree/Cargo.toml" || {
  echo "async-ebpf worktree not found: $async_worktree" >&2
  exit 1
}

make -s -C "$root" tcc

clang -DC2STR "$root/conftest.c" -o "$work/c2str"
"$work/c2str" "$root/include/tccdefs.h" "$work/tccdefs_.h"

# Compile the same freestanding TinyCC variant that runs as the eBPF guest.
# Suppressing line markers makes this one self-contained translation unit.
clang -E -P -Wno-macro-redefined -nostdinc \
  -I"$work" -I"$root/async-ebpf-host/include" -I"$root" \
  -U__aarch64__ -U__x86_64__ -U__x86_64 -U__amd64__ -U__amd64 \
  -DONE_SOURCE=1 -D"$target_define"=1 \
  -DTCC_EBPF_HOST=1 -DCONFIG_TCC_STATIC=1 -DCONFIG_TCC_SEMLOCK=0 \
  '-DTCC_EBPF_TCCDEFS=<tccdefs_.h>' \
  "$root/tcc.c" -o "$work/<string>"

# tcc_compile_string records <string> as the ELF STT_FILE symbol. Giving the
# direct compiler an actual file with that name normalizes the sole input-name
# difference without post-processing either artifact.
(
  cd "$work"
  "$root/tcc" -nostdinc -nostdlib -c '<string>' -o direct.o
)

TCC_EBPF_STACK_SIZE=$stack_size \
  "$root/async-ebpf-host/build.sh" "$work/tinycc-guest.o" >/dev/null

(
  cd "$async_worktree"
  TCC_EBPF_STACK_SIZE=$stack_size cargo run --quiet --features testing \
    --example tinycc_host -- \
    "$work/tinycc-guest.o" "$work/<string>" "$work/async-ebpf.o"
)

cmp "$work/direct.o" "$work/async-ebpf.o"

if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$work/direct.o" | awk '{print $1}')
else
  digest=$(shasum -a 256 "$work/direct.o" | awk '{print $1}')
fi

bytes=$(wc -c < "$work/direct.o" | tr -d ' ')
echo "bootstrap artifacts are identical"
echo "target: $target_name ELF relocatable"
echo "bytes: $bytes"
echo "sha256: $digest"
