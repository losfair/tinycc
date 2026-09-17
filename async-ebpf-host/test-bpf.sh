#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
async_worktree=${ASYNC_EBPF_WORKTREE:-"$(dirname -- "$root")/async-ebpf"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
TCC_EBPF_TARGET=bpf TCC_EBPF_VFS=0 TCC_EBPF_STACK_SIZE=8388608 \
  "$root/async-ebpf-host/build.sh" "$work/compiler.bpf"
(
  cd "$async_worktree"
  TCC_EBPF_STACK_SIZE=8388608 cargo run --quiet --features testing --example tinycc_host -- \
    "$work/compiler.bpf" 'volatile long zero; long main(void) { return ++zero + 41; }' "$work/program.o"
  TCC_EBPF_STACK_SIZE=8388608 cargo run --quiet --features testing --example tinycc_host -- \
    "$work/program.o" unused > "$work/result"
)
cat "$work/result"
grep -q 'tinycc result: 0x2a' "$work/result"
echo 'eBPF compiler output executed successfully'
