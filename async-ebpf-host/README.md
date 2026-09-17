# TinyCC hosted in async-ebpf

This port compiles TinyCC itself with Clang's eBPF target. By default it generates
code for the machine running `async-ebpf`. Select the BPF backend with
`TCC_EBPF_TARGET=bpf` to compile eBPF programs inside eBPF instead.

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

The generated object targets the machine running `async-ebpf` (AArch64 or
x86-64).

The bootstrap comparison builds the freestanding TinyCC one-source unit once
with the native TinyCC executable and once with TinyCC running inside
`async-ebpf`, then requires the two ELF artifacts for the current host target
to be byte-identical. Both AArch64 and x86-64 hosts are supported:

```sh
ASYNC_EBPF_WORKTREE=/path/to/async-ebpf-tinycc \
  async-ebpf-host/bootstrap.sh
```

It uses a 64 MiB guest stack by default. Override both the guest build and the
runner with `TCC_EBPF_STACK_SIZE` if a different size is needed.

## Select the generated architecture

`TCC_EBPF_TARGET` selects `native` (default), `x86_64`, `aarch64`, or `bpf`
(`bpfel` is an alias). The compiler itself always runs as eBPF. For example:

```sh
TCC_EBPF_TARGET=bpf async-ebpf-host/build.sh /tmp/compiler.bpf
```

The BPF output mode materializes zero-fill sections and disables common symbols
so the result can be loaded directly by async-ebpf. Its backend supports integer
operations, but rejects signed division/modulo and floating point. The default
native-target bootstrap comparison remains unchanged.

## Virtual source files and diagnostics

Set `TCC_EBPF_VFS=1` at compiler build time to compile a named virtual source file
instead of the source string. The calldata and input-copy ABI stay the same, but
the NUL-terminated input is now a filename, for example `/src/main.c`. TinyCC
adds `/src` to its include search path; quoted includes also resolve relative to
the including file. The embedder provides these additional helpers:

| Helper | Arguments | Result |
| --- | --- | --- |
| `tcc_ebpf_open_file` | path pointer, byte length (no NUL), open flags | Read-only virtual descriptor or -1; descriptor 1 is reserved for ELF output. |
| `tcc_ebpf_read_file` | descriptor, destination pointer, capacity | Bytes read, zero at EOF, or -1. |
| `tcc_ebpf_close_file` | descriptor | Zero on success or -1. |
| `tcc_ebpf_diagnostic` | UTF-8 message pointer, byte length | Host-defined acknowledgement; return value is ignored. |

All helper arguments use the existing eBPF integer/pointer ABI. The embedder must
validate guest memory, resolve filenames only within its virtual source bundle,
track descriptor offsets, bound output/diagnostics and handle resource exhaustion.
No host filesystem access is necessary or implied by these helpers. Fatal errors
still use `tcc_ebpf_fatal`, which must stop the invocation. Nonfatal diagnostics
are available in VFS mode. Each compilation needs fresh mutable compiler state.

```sh
TCC_EBPF_TARGET=bpf TCC_EBPF_VFS=1 \
  async-ebpf-host/build.sh /tmp/compiler-with-vfs.bpf
```

The ordinary three-helper string-input runner and `bootstrap.sh` continue to work
without VFS. `test-bpf.sh` exercises the eBPF-output mode, including materialized
zero globals, using the existing async-ebpf example runner.
