#!/usr/bin/env python3
"""Which prose blocks get the line model?  Read the vendor's ctrl/e2 back.

Mode 4 comes in two shapes: `ctrl = 0xAC` (one space is stored after every LF
and dropped by the decoder) and `ctrl = 0xBC`, which turns some line breaks
into 1-byte marker spaces and carries the 19-symbol line code in `e2`.  The
line model saves a byte per folded line, so a cost rule would always prefer
it -- yet the corpus `code.c` (600 lines, every one foldable, 592 bytes to
save) gets 0xAC.  This probe varies one geometry property at a time, packs the
sample with ``sbc.exe`` and reads the record back with ``SBC_DBG2=1``, so the
real trigger can be seen instead of guessed.

Usage: python3 tools/m4_ctrl_probe.py [--levels 1] [--out DIR]
"""
import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "sbc.exe"
OURS = ROOT / "sbc"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vendor_run import run_vendor  # noqa: E402

WORDS = ("the quick brown fox jumps over a lazy dog while several other "
         "animals watch from behind the fence and wonder what happens").split()


def line_of(rng, k, lo=3, hi=8):
    """A line carrying exactly `k` spaces."""
    words = [rng.choice(WORDS) for _ in range(k + 1)]
    if k:
        words[0] = words[0][:rng.randint(4, 6)]
    return " ".join(words)


def text_fixed(rng, k, nlines, trailing=True, jitter=0):
    out = []
    for _ in range(nlines):
        kk = k if not jitter else max(1, k + rng.randint(-jitter, jitter))
        out.append(line_of(rng, kk))
    s = "\n".join(out)
    if trailing:
        s += "\n"
    return s.encode()


def text_regular(k, nlines, trailing=True):
    """Every line identical: the `code.c` shape."""
    line = " ".join(["word"] * (k + 1))
    s = (line + "\n") * nlines
    if not trailing:
        s = s[:-1]
    return s.encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="1")
    ap.add_argument("--bin", default=str(OURS))
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    if not VENDOR.exists():
        print("sbc.exe not found")
        return 2
    rng = random.Random(11)
    cases = {}
    # one space count at a time, irregular lines
    for k in (4, 6, 7, 8, 10, 14, 20, 24, 25, 30):
        cases["k%02d" % k] = text_fixed(rng, k, 120)
    # regular lines (identical every time), like code.c
    for k in (4, 7, 14, 24):
        cases["reg%02d" % k] = text_regular(k, 120)
    # few lines, many lines
    for n in (2, 8, 40, 400):
        cases["n%03d" % n] = text_fixed(rng, 12, n)
    # blank lines, no trailing break, mixed widths
    cases["blank"] = b"\n".join(
        [text_fixed(rng, 12, 1, trailing=False) if i % 4 else b""
         for i in range(200)]) + b"\n"
    cases["notrail"] = text_fixed(rng, 12, 120, trailing=False)
    cases["jitter8"] = text_fixed(rng, 12, 200, jitter=8)
    cases["one-line"] = text_fixed(rng, 12, 1, trailing=False)
    cases["one-space"] = text_fixed(rng, 1, 600)
    cases["all-long"] = text_fixed(rng, 30, 60)
    levels = [x for x in a.levels.split(",") if x]
    work = Path(a.out) if a.out else Path(tempfile.mkdtemp(prefix="sbcm4ctrl-"))
    work.mkdir(parents=True, exist_ok=True)
    try:
        for name, data in cases.items():
            src = work / (name + ".txt")
            src.write_bytes(data)
            for lv in levels:
                arc = work / ("%s-m%s.sbc" % (name, lv))
                v = run_vendor(["c", arc.name, "-m" + lv, src.name], work,
                               produces=[arc])
                if v.returncode != 0 or not arc.exists():
                    print("%-10s -m%s VENDOR FAIL" % (name, lv))
                    continue
                q = subprocess.run([a.bin, str(arc), str(work / "out")],
                                   capture_output=True, text=True,
                                   env=dict(os.environ, SBC_DBG2="1"))
                rec = ""
                for ln in q.stderr.splitlines():
                    if ln.startswith("RECS") or "mode=" in ln:
                        rec = ln
                        break
                print("%-10s -m%s n=%6d %s" % (name, lv, len(data), rec))
    finally:
        if not a.out:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    return 0


if __name__ == "__main__":
    sys.exit(main())
