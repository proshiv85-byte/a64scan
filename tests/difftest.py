#!/usr/bin/env python3
"""Differential test of a64scan's classifier against LLVM's disassembler.

Ground truth for each 32-bit word:
  base  = llvm-objdump --mcpu=cortex-a53 (ARMv8.0 + CRC + Crypto) decodes it
  full  = llvm-objdump (all extensions)       decodes it
  needs an extension  <=>  full and not base

Compared with `a64scan --decode-file` (extension other than crc/crypto/hints
= "needs an extension"). Words come from the executable sections of the given
ELF files (deduplicated) plus uniformly random words.

Usage: difftest.py [--random N] [--max-words N] A64SCAN ELF...
Needs: llvm-objdump, aarch64-linux-gnu-as, aarch64-linux-gnu-objcopy.
"""
import argparse, collections, os, random, re, struct, subprocess, sys, tempfile

BASE_OK = {"-", "crc", "crypto", "hint-pauth", "hint-bti"}
# LLVM prints MSR SVCR* as SMSTART/SMSTOP aliases even for cortex-a53; still UNDEFINED on v8.0
LLVM_BASE_ALIASES = ("smstart", "smstop")


def text_words(path, limit):
    with tempfile.NamedTemporaryFile() as t:
        r = subprocess.run(["aarch64-linux-gnu-objcopy", "-O", "binary", "--only-section=.text", path, t.name],
                           capture_output=True)
        if r.returncode:
            return []
        data = open(t.name, "rb").read()
    n = len(data) // 4
    return list(struct.unpack_from("<%dI" % n, data))[:limit]


def disasm(words, extra, tmp):
    """word -> decodes (bool), in input order."""
    src = os.path.join(tmp, "w.S")
    obj = os.path.join(tmp, "w.o")
    with open(src, "w") as f:
        f.write(".text\n")
        f.writelines(".inst 0x%08x\n" % w for w in words)
    subprocess.run(["aarch64-linux-gnu-as", src, "-o", obj], check=True)
    out = subprocess.run(["llvm-objdump", "-d", "--no-show-raw-insn", *extra, obj],
                         capture_output=True, text=True, check=True).stdout
    res, mnem = [], []
    for line in out.splitlines():
        m = re.match(r"\s+[0-9a-f]+:\s+(.*)", line)
        if m:
            ins = m.group(1).strip()
            res.append(not ins.startswith("<unknown>"))
            mnem.append(ins)
    assert len(res) == len(words), (len(res), len(words))
    return res, mnem


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--random", type=int, default=500000)
    ap.add_argument("--max-words", type=int, default=3000000)
    ap.add_argument("--per-file", type=int, default=200000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("a64scan")
    ap.add_argument("elfs", nargs="*")
    a = ap.parse_args()

    words = set()
    for p in a.elfs:
        words.update(text_words(p, a.per_file))
        if len(words) >= a.max_words:
            break
    real = len(words)
    rnd = random.Random(a.seed)
    while len(words) < real + a.random:
        words.add(rnd.getrandbits(32))
    words = sorted(words)
    print("words: %d from %d ELF files + %d random" % (real, len(a.elfs), len(words) - real))

    with tempfile.TemporaryDirectory() as tmp:
        base, _ = disasm(words, ["--mcpu=cortex-a53"], tmp)
        full, mnem = disasm(words, [], tmp)
        out = subprocess.run([a.a64scan, "--decode-file", "-"], input="".join("%08x\n" % w for w in words),
                             capture_output=True, text=True, check=True).stdout.split("\n")
    ours = [l.split()[1] for l in out if l]

    fp, fn, unalloc = collections.Counter(), collections.Counter(), collections.Counter()
    ex_fp, ex_fn = collections.defaultdict(list), collections.defaultdict(list)
    needs = 0
    for w, b, f, o, mn in zip(words, base, full, ours, mnem):
        ext = (f and not b) or mn.split()[0] in LLVM_BASE_ALIASES
        needs += ext
        if not f:
            if o not in BASE_OK:
                unalloc[o] += 1
        elif ext and o in BASE_OK:
            k = mn.split()[0]
            fn[k] += 1
            ex_fn[k].append("%08x %s" % (w, mn))
        elif not ext and o not in BASE_OK:
            k = "%s<-%s" % (o, mn.split()[0])
            fp[k] += 1
            ex_fp[k].append("%08x %s" % (w, mn))

    print("need an extension (LLVM): %d" % needs)
    print("false negatives (we say v8.0, LLVM needs an extension): %d" % sum(fn.values()))
    for k, n in fn.most_common(40):
        print("  %6d %-12s e.g. %s" % (n, k, ex_fn[k][0]))
    print("false positives (we flag, LLVM decodes it with cortex-a53): %d" % sum(fp.values()))
    for k, n in fp.most_common(40):
        print("  %6d %-24s e.g. %s" % (n, k, ex_fp[k][0]))
    print("unallocated words we label (harmless, SIGILL everywhere): %d %s" % (sum(unalloc.values()), dict(unalloc.most_common(8))))
    sys.exit(1 if fn or fp else 0)


if __name__ == "__main__":
    main()
