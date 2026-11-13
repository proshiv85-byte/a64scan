# a64scan

Find AArch64 instructions that a target CPU can't execute.

When you port an Android ROM (or any AArch64 userspace) built for a newer SoC to
an older one, every instruction from an extension the old core lacks is a
`SIGILL` waiting to happen. `a64scan` walks a directory tree, reads the executable
sections of every AArch64 ELF (including ART `.odex`/`.oat` files) and tells you which
files use what: LSE atomics, RCpc, FP16, dot product, SVE/SVE2, SME, MTE, BF16,
I8MM, MOPS, PAuth, ... up to ARMv9.6.

It decodes instruction encodings directly: no objdump, about 0.2 s for the 2000
ELF files of a full Android 17 system image.

```
$ a64scan --allow crc,crypto,lse,rcpc,fp16,dotprod system/
target: armv8.0 + crc, crypto, lse, fp16, dotprod, rcpc

FILE                                     sha3    sve  pauth    mte   i8mm  ...  suspect
system/lib64/libjxl.so                      5  14737      2     13      ·          312
system/lib64/libandroid_servers.so          ·      ·      8      ·      ·
...
EXTENSION   SINCE      INSNS  FILES  SUSPECT  description
sve         v8.2       39146     27    54075  Scalable Vector Extension (SVE/SVE2)
pauth       v8.3          17      2       22  pointer authentication, non-hint forms (RETAA, ...)
...
```

## Build

```
cargo build --release      # target/release/a64scan
cargo test --release       # encoding tests (tests/fixtures/vectors.tsv)
```

## Usage

```
a64scan [OPTIONS] PATH...

  -a, --allow LIST     extensions the target runs, natively or emulated
                       (default: crc,crypto; "none" for a bare ARMv8.0 core)
      --upto VERSION   also allow everything up to v8.x / v9.x (includes optional
                       extensions such as SVE at v8.2; combine with --deny)
      --deny LIST      report these even if --allow/--upto allowed them
      --hints          also count PACIASP/AUTIASP/BTI (hint space: NOPs on old cores)
  -l, --list           list every hit: address, word, extension, symbol
      --max-list N     hits listed per file (default 20, 0 = all)
  -s, --suspect        also show files whose only hits look like data
      --top N          only the N files with the most hits
      --json           machine-readable output
      --follow-symlinks
  -j, --jobs N
      --decode HEX...  classify single words
      --decode-file F  classify hex words, one per line ("-" = stdin)
```

Exit status: `0` nothing beyond the target, `1` unsupported instructions found
(suspect hits don't count), `2` error. Good for a build-script check:

```
a64scan -a crc,crypto,lse,rcpc,fp16,dotprod out/system || echo "won't run on the old phone"
```

Extension names: `crc crypto lse rdm fp16 dotprod sha3 sve rcpc pauth jscvt fcma
rcpc2 flagm frint sb mte bf16 i8mm ls64 mops cssc sme lor hbc rcpc3 cpa fp8 lsui
cmpbr fhm lsfe lse128 hint-pauth hint-bti`.

## Reading the results

**A hit is not always a crash.** Many libraries ship code for several CPUs and pick
one at run time (`getauxval(AT_HWCAP)`, ifuncs): bionic's `memcpy` has MOPS and MTE
variants, libvpx/dav1d/libjxl/highway carry SVE and I8MM kernels next to NEON ones.
The scanner can't see that dispatch. Hits in a library that otherwise looks like
base ARMv8.0 code (a handful of SVE/SME/MOPS instructions in libc, the linker or
codecs) are usually such variants. Hits spread through ordinary code, like `retaa`
at the end of every function in a library built with `-march=armv8.3-a`, are real
and will fault.

**Suspect** hits are words that decode as an extension instruction but probably are
data inside `.text`:

- next to UDF/BRK, reserved encodings (small integers), ASCII text, or float/double
  constants (top byte `0x3E/0x3F/0xBE/0xBF`);
- after an unconditional branch/return and before the next direct branch target,
  symbol or function entry: literal pools, jump tables, padding;
- function prefix data: right after a terminator and right before a function entry
  (KCFI type hashes); the `-fsanitize=function` signature (`0xc105cafe` + hash) is
  skipped outright.

When an ELF still has ARM mapping symbols (`$x`/`$d`, unstripped objects), they are
used instead and data is skipped exactly (shown as `($x/$d)`).

Real code reached only through a function pointer (an SVE ifunc variant, say) loses
the instructions before its first internal branch target to "suspect"; the rest of
its body still counts, so the file is still reported.

## Accuracy

`tests/difftest.py` checks the classifier against LLVM's disassembler: a word needs
an extension if `llvm-objdump --mcpu=cortex-a53` (ARMv8.0 + CRC + Crypto) can't
decode it but `llvm-objdump` with all extensions can.

```
python3 tests/difftest.py --random 3000000 target/release/a64scan /path/to/system/lib64/*.so
```

On 3.0 M distinct words from 1450 One UI 9 libraries plus 3.0 M random words
(LLVM 23):

| | |
|---|---|
| words that need an extension (LLVM) | 312,516 |
| missed (false negatives) | 637 (0.2 %) |
| flagged although ARMv8.0 (false positives) | 0 |

The misses are all ARMv9.5/9.6 additions: TME `tchangef/tchangeb/tenter` (EL1 only),
FP8 2-way `fdot`, FPRCVT scalar conversions (`fcvtzs s, d`), FP8 `fmmla` with size
10, RCpc3 `ldap1/stl1`. Words that are unallocated everywhere may get a label (they
fault on every CPU anyway).

Known simplifications: SVE and SVE2 are reported together (`sve`); SME, SME2 and
the SME instructions in the MSR space (SMSTART/SMSTOP) together (`sme`); 32-bit ARM
ELFs are counted and skipped; compressed APEX/zip payloads must be extracted first.

## Origin

Written while porting Samsung One UI 9 (Galaxy S24+, Exynos 2400) to the Galaxy
S8+ (Exynos 8895, ARMv8.0 + CRC + Crypto) with a kernel that emulates LSE, RCpc,
FP16 and dot product for userspace. Its first finding: `retaa` (ARMv8.3 PAuth,
not emulated) in `libandroid_servers.so`, which system_server loads.

## License

MIT or Apache-2.0, at your option.
