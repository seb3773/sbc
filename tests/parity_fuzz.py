#!/usr/bin/env python3
"""Random-archive parity: our encoder against sbc.exe on generated inputs.

``tools/vendor_parity.py`` covers the fixed corpus; this tool generates the
shapes the corpus does not have: prose with every line geometry the mode-4
chooser can reach (blank lines, wide/narrow/tabbed lines, CRLF, no trailing
break, long lines), uppercase text, cycles, images and random data, at sizes
from the 600-byte text gate up to a few blocks.  Every sample is packed twice
-- once by ``sbc.exe`` under Wine, once by us with ``SBC_POLICY=1`` -- and the
archives are compared byte for byte.

Usage: python3 tools/parity_fuzz.py [--count N] [--levels 1,2,3] [--seed S]
                                    [--keep DIR] [--only NAME]

Exit status is 0 only when every archive is identical.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402

WORDS = ("the quick brown fox jumps over a lazy dog while several other "
         "animals watch from behind the fence and wonder what happens next "
         "when nobody is looking at them at all").split()


def prose(rng, nlines, lo=1, hi=14, blank=0, trailing=True, indent=0,
          tab=0):
    out = []
    for i in range(nlines):
        if blank and rng.randrange(blank) == 0:
            out.append("")
            continue
        k = rng.randint(lo, hi)
        words = [rng.choice(WORDS) for _ in range(k + 1)]
        line = " ".join(words)
        if indent and rng.randrange(indent) == 0:
            line = " " * rng.randint(1, 4) + line
        if tab and rng.randrange(tab) == 0:
            line = "\t" + line
        out.append(line)
    s = "\n".join(out)
    if trailing:
        s += "\n"
    return s.encode()


def regular(k, nlines, trailing=True):
    line = " ".join(["word"] * (k + 1))
    s = (line + "\n") * nlines
    return (s[:-1] if not trailing else s).encode()


def crlf(data):
    return data.replace(b"\n", b"\r\n")


def mixed(rng, n):
    """Mostly printable with token-rich words, but not text-like overall."""
    out = bytearray()
    while len(out) < n:
        if rng.randrange(5):
            out += (rng.choice(WORDS) + " ").encode()
        else:
            out += bytes(rng.randrange(1, 0x100) for _ in range(rng.randint(1, 8)))
    return bytes(out[:n])


def cycle(period, n):
    base = bytes((0x41 + (i * 7) % 26) for i in range(period))
    return (base * (n // period + 1))[:n]


def samples(rng):
    s = []
    for i in range(6):
        nl = rng.choice([20, 60, 140])
        s.append(("prose%d" % i, prose(rng, nl, lo=rng.choice([2, 4, 6]),
                                      hi=rng.choice([8, 12, 20, 25]),
                                      blank=rng.choice([0, 5, 3]),
                                      indent=rng.choice([0, 7]),
                                      tab=rng.choice([0, 9]))))
    s.append(("wide", prose(rng, 40, lo=26, hi=40)))
    s.append(("narrow", prose(rng, 400, lo=1, hi=3)))
    s.append(("notrail", prose(rng, 120, trailing=False)))
    s.append(("crlf", crlf(prose(rng, 90))))
    s.append(("blanks", b"\n".join([b"" if i % 3 == 0 else
                                    prose(rng, 1, trailing=False)
                                    for i in range(300)]) + b"\n"))
    s.append(("big", prose(rng, 600)))
    s.append(("bigger", prose(rng, 1500)))
    for k in (4, 7, 12, 24):
        s.append(("reg%02d" % k, regular(k, 120)))
    s.append(("at600", prose(rng, 40)[:600]))
    s.append(("at4096", prose(rng, 200)[:4096]))
    s.append(("at4097", prose(rng, 200)[:4097]))
    s.append(("upper", prose(rng, 300).upper()))
    s.append(("cycl20", cycle(20, 9000)))
    s.append(("cycl25", cycle(25, 9000)))
    s.append(("mixed", mixed(rng, 30000)))
    s.append(("random", bytes(rng.randrange(256) for _ in range(20000))))
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=0,
                    help="keep only the first N samples")
    ap.add_argument("--levels", default="1,2,3")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keep", default="")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    if not os.path.exists(VENDOR):
        print("sbc.exe not found")
        return 2
    rng = random.Random(a.seed)
    cases = samples(rng)
    if a.only:
        want = set(a.only.split(","))
        cases = [c for c in cases if c[0] in want]
    if a.count:
        cases = cases[:a.count]
    levels = ["-m" + x for x in a.levels.split(",") if x]
    work = a.keep or tempfile.mkdtemp(prefix="fuzz-")
    os.makedirs(work, exist_ok=True)
    ok = bad = 0
    fails = []
    try:
        for name, data in cases:
            src = os.path.join(work, name + ".bin")
            with open(src, "wb") as f:
                f.write(data)
            for lv in levels:
                tag = "%-9s %s" % (name, lv)
                v = os.path.join(work, "v.sbc")
                o = os.path.join(work, "o.sbc")
                rv = run_vendor(["c", "v.sbc", lv, name + ".bin"], work,
                                produces=[v])
                ro = subprocess.run([OURS, "c", "o.sbc", lv, name + ".bin"],
                                    cwd=work, capture_output=True,
                                    env=dict(os.environ, SBC_POLICY="1"))
                if rv.returncode != 0 or not os.path.exists(v):
                    print("SKIP  %s (vendor failed)" % tag)
                    continue
                if ro.returncode != 0 or not os.path.exists(o):
                    print("FAIL  %s (encoder failed)" % tag)
                    bad += 1
                    fails.append(tag)
                    continue
                vb = open(v, "rb").read()
                ob = open(o, "rb").read()
                if vb == ob:
                    ok += 1
                    print("OK    %s (%d B)" % (tag, len(vb)))
                else:
                    bad += 1
                    fails.append(tag)
                    first = next((i for i in range(min(len(vb), len(ob)))
                                  if vb[i] != ob[i]), None)
                    print("FAIL  %s (ours %d, vendor %d, first diff %s)" %
                          (tag, len(ob), len(vb), first))
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    print("\n%d identical, %d different" % (ok, bad))
    if fails:
        print("differing: " + " ".join(fails))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
