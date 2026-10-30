#!/usr/bin/env python3
"""Regression: the mode-0 filter's tail byte (FORMAT §13 item 1, now closed).

This case was filed as a tail-entropy (PPM, stage 1/2) problem: the corpus
files concatenated, doubled and truncated to 469,838 bytes, packed by sbc.exe
with `-m2`, gave a third block (`vlq=2716`, `primary=1946`, `flag3=1`) the
vendor wrote as `e1=719` and we wrote as `e1=718`, and our decoder rejected the
vendor's stream.

The real cause was one byte of the filter *record*: the mode-0 adaptive filter
has a third cut site (0x425e9a) that ends a chunk once the running slot's score
gets `min(pos >> 4, 32)` points ahead of the copy slot's, past the first 128
bytes.  That leaves a one-byte chunk, the selector gives it slot 0, and the
record's last byte is stored verbatim (`... 02 ff 43`); filtering it with the
running slot (`... 02 ff ff`) shifts the whole coded stream.  With the cut in
`sbc_m0adv.h` the archives are byte-identical (155,004 B).

The tool prints the archive sizes, the first differing offset, both block
layouts and whether our decoder reproduces the input; `--keep DIR` keeps all
files, and a differing archive exits non-zero.

Usage: python3 tools/tail_repro.py [--keep DIR] [--no-vendor]
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
CORPUS = os.path.join(ROOT, "corpus")
FILES = ("code.c", "eng.txt", "records.bin", "image.raw", "image24.raw",
         "biased.bin", "mixed.bin", "random.bin")
LIMIT = 469838

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402


def build_input():
    blob = b"".join(open(os.path.join(CORPUS, f), "rb").read()
                    for f in FILES if os.path.exists(os.path.join(CORPUS, f)))
    return (blob + blob)[:LIMIT]


def blocks(path, level=None):
    """The decoder's block listing for one archive (SBC_DBG2, on stderr)."""
    outdir = os.path.join(os.path.dirname(path), "x-" + os.path.basename(path))
    os.makedirs(outdir, exist_ok=True)
    r = subprocess.run([OURS, path, outdir], capture_output=True, text=True,
                       env=dict(os.environ, SBC_DBG2="1"))
    text = (r.stdout or "") + (r.stderr or "")
    lines = [l for l in text.splitlines() if l.startswith("BLK pos=")]
    st = [l for l in text.splitlines() if l.startswith("st=")]
    return lines, (st[0] if st else "?")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", default="/tmp/tail-repro")
    ap.add_argument("--no-vendor", action="store_true",
                    help="only rebuild the input and pack with our encoder")
    a = ap.parse_args()
    os.makedirs(a.keep, exist_ok=True)
    src = os.path.join(a.keep, "in.bin")
    data = build_input()
    with open(src, "wb") as f:
        f.write(data)
    print("input: %s (%d bytes)" % (src, len(data)))
    arcs = {}
    if not a.no_vendor:
        v = os.path.join(a.keep, "v.sbc")
        r = run_vendor(["c", "v.sbc", "-m2", "in.bin"], a.keep, produces=[v])
        if r.returncode != 0 or not os.path.exists(v):
            print("vendor failed: rc=%s %s" % (r.returncode,
                                               (r.stdout or b"")[-300:]))
            return 2
        arcs["vendor"] = v
    o = os.path.join(a.keep, "o.sbc")
    subprocess.run([OURS, "c", o, "-m2", "in.bin"], cwd=a.keep,
                   capture_output=True)
    arcs["ours"] = o
    for name, path in arcs.items():
        print("%-7s %s  %d bytes" % (name, os.path.basename(path),
                                     os.path.getsize(path)))
    same = True
    if not a.no_vendor:
        vb = open(arcs["vendor"], "rb").read()
        ob = open(arcs["ours"], "rb").read()
        first = next((i for i in range(min(len(vb), len(ob))) if vb[i] != ob[i]),
                     None)
        same = vb == ob
        print("archives: %s (first diff %s)" %
              ("identical" if same else "different", first))
    for name, path in arcs.items():
        blks, st = blocks(path)
        print("%s: %s" % (name, st))
        for b in blks:
            print("   " + b)
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main())
