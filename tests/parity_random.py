#!/usr/bin/env python3
"""Randomized whole-archive parity: our encoder vs sbc.exe.

The corpus cases are few and hand-picked; this tool generates file sets whose
content covers the encoder's branches (random bytes, runs, cycles, ASCII text,
code, raw 24-bit images, record-like data, mixes) and compares the two archives
byte for byte, so a mismatch names the branch that is still missing.

Every vendor run deletes the target archive first (`sbc.exe` asks before
overwriting) and passes `-y` to auto-answer any other prompt.

Usage: python3 tools/parity_random.py [--sets N] [--seed S] [--bytes-target N]
                                      [--opts "m1,m2,m3"] [-v]
"""
import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
VENDOR = os.path.join(ROOT, "sbc.exe")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def gen(kind, n, rng):
    if kind == "rand":
        return bytes(rng.randrange(256) for _ in range(n))
    if kind == "zero":
        return bytes(n)
    if kind == "ff":
        return b"\xff" * n
    if kind == "cycle":
        p = rng.choice([2, 3, 4, 5, 7, 16, 17, 31, 32, 64])
        pat = bytes(rng.randrange(256) for _ in range(p))
        return (pat * (n // p + 1))[:n]
    if kind == "text":
        words = ["the", "quick", "brown", "fox", "jumps", "over", "lazy",
                 "dog", "and", "then", "some", "more", "words", "here"]
        out = []
        total = 0
        while total < n:
            line = " ".join(rng.choice(words) for _ in range(rng.randint(4, 12)))
            line += "\n"
            out.append(line)
            total += len(line)
        return "".join(out).encode()[:n]
    if kind == "code":
        lines = []
        total = 0
        while total < n:
            i = rng.randrange(1000)
            s = ("    if (value_%d >= limit_%d) {\n"
                 "        result[%d] = compute_%d(value_%d, 0x%x);\n"
                 "    } else {\n"
                 "        result[%d] = value_%d * %d;\n"
                 "    }\n") % (i, rng.randrange(9), i, i, i, rng.randrange(256),
                                 i, i, rng.randrange(9))
            lines.append(s)
            total += len(s)
        return "".join(lines).encode()[:n]
    if kind == "image":
        w = rng.choice([64, 100, 128, 160, 200, 256, 300, 320])
        row = bytearray()
        base = [rng.randrange(256) for _ in range(3)]
        for x in range(w):
            for c in range(3):
                base[c] = (base[c] + rng.choice([-1, 0, 0, 1])) & 0xFF
                row.append(base[c])
        rows = max(1, n // len(row))
        out = bytearray()
        cur = bytes(row)
        for _ in range(rows):
            out += cur
            cur = bytes((b + rng.choice([-1, 0, 0, 1])) & 0xFF for b in cur)
        return bytes(out)[:n]
    if kind == "records":
        out = bytearray()
        while len(out) < n:
            rec = bytes(rng.randrange(256) for _ in range(rng.randint(8, 40)))
            out += rec * rng.randint(2, 40)
        return bytes(out)[:n]
    if kind == "mixed":
        out = bytearray()
        while len(out) < n:
            k = rng.choice(["rand", "zero", "text", "cycle"])
            out += gen(k, rng.randint(200, 4000), rng)
        return bytes(out)[:n]
    raise ValueError(kind)


KINDS = ["rand", "zero", "ff", "cycle", "text", "code", "image", "records",
         "mixed"]


def run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, env=env)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--opts", default="m1,m2,m3")
    ap.add_argument("--files", type=int, default=0,
                    help="files per set (default: random 1..4)")
    ap.add_argument("--maxsize", type=int, default=400000)
    ap.add_argument("--keep", default="", help="keep the sets in this dir")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    ourenv = dict(os.environ, SBC_POLICY="1")
    opts = ["-" + o for o in a.opts.split(",") if o]
    ok = bad = 0
    fails = []
    for si in range(a.sets):
        d = tempfile.mkdtemp(prefix="pr-")
        try:
            nf = a.files or rng.randint(1, 4)
            names = []
            for fi in range(nf):
                kind = rng.choice(KINDS)
                n = rng.choice([rng.randint(1, 600), rng.randint(600, 4000),
                                rng.randint(4000, a.maxsize // 3)])
                if n > a.maxsize:
                    n = a.maxsize
                name = "%s%d.dat" % (kind, fi)
                with open(os.path.join(d, name), "wb") as fh:
                    fh.write(gen(kind, n, rng))
                names.append(name)
            if a.keep:
                kd = os.path.join(a.keep, "set%d" % si)
                shutil.rmtree(kd, ignore_errors=True)
                shutil.copytree(d, kd)
            for o in opts:
                v = os.path.join(d, "v.sbc")
                p = os.path.join(d, "o.sbc")
                for q in (v, p):
                    if os.path.exists(q):
                        os.remove(q)
                rv = run_vendor(["c", "v.sbc", "-y", o] + names, d,
                                produces=[v])
                ro = run([OURS, "c", "o.sbc", o] + names, d, ourenv)
                tag = "set%d %s [%s]" % (si, o, " ".join(names))
                if rv.returncode != 0 or not os.path.exists(v):
                    print("SKIP  %s (vendor failed)" % tag)
                    continue
                if ro.returncode != 0 or not os.path.exists(p):
                    print("FAIL  %s (encoder failed)" % tag)
                    bad += 1
                    fails.append(tag)
                    continue
                vb = open(v, "rb").read()
                ob = open(p, "rb").read()
                if vb == ob:
                    ok += 1
                    if a.verbose:
                        print("OK    %s (%d B)" % (tag, len(vb)))
                else:
                    bad += 1
                    fails.append(tag)
                    first = next((i for i in range(min(len(vb), len(ob)))
                                  if vb[i] != ob[i]), min(len(vb), len(ob)))
                    print("FAIL  %s: %d vs %d bytes, first diff %d" %
                          (tag, len(ob), len(vb), first))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print("\n%d identical, %d different" % (ok, bad))
    if fails:
        print("differing: " + " ".join(fails[:20]))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
