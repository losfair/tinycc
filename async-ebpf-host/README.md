# TinyCC hosted in async-ebpf

This port compiles TinyCC itself with Clang's eBPF target. TinyCC continues to
generate code for the machine running `async-ebpf`; it does not use
`bpf-gen.c`.

The current guest is intentionally integer-only. Floating-point literals and
constant folding require host floating-point operations, which eBPF does not
provide. Source is copied through a helper into the bottom of a configurable
guest stack; TinyCC's allocator follows it upward while local-call frames grow
downward from the calldata at the top.

Build it with:

```sh
async-ebpf-host/build.sh /tmp/tinycc-guest.o
```

It requires Clang and the LLVM tools `opt`, `llc`, `llvm-as`, `llvm-dis`, and
`llvm-objcopy`. The paired `async-ebpf` runner uses `Program::run_mut`, because
the compiler keeps persistent mutable globals in its ELF data.

With the paired runner example, the guest emits the complete generated ELF
object through a registered helper. The second argument may be literal source
or the path to a source file:

```sh
cd /path/to/async-ebpf-tinycc
cargo run --features testing --example tinycc_host -- \
  /tmp/tinycc-guest.o \
  'int add(int a, int b) { return a + b; }' \
  /tmp/add.o
```

On an AArch64 host, `/tmp/add.o` is an AArch64 relocatable ELF object.

The bootstrap comparison builds the freestanding TinyCC one-source unit once
with the native TinyCC executable and once with TinyCC running inside
`async-ebpf`, then requires the two AArch64 ELF artifacts to be byte-identical:

```sh
ASYNC_EBPF_WORKTREE=/path/to/async-ebpf-tinycc \
  async-ebpf-host/bootstrap.sh
```

It uses a 64 MiB guest stack by default. Override both the guest build and the
runner with `TCC_EBPF_STACK_SIZE` if a different size is needed.
