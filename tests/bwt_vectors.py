#!/usr/bin/env python3
"""Capture (BWT input, L, primary) vectors for the vendor's small-BWT path.

For every probe input this packs it with sbc.exe, decodes the archive with our
decoder and stores the layer the vendor's BWT consumed (02_lzp), the BWT string
it produced (01_bwt) and the primary from the block header.  Those three are
exactly what a forward-BWT reimplementation has to reproduce, so they make a
self-contained test set for the suffix-sort port.

Usage: python3 tools/bwt_vectors.py OUTDIR [--level 1]
"""
import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402
from bwt_probe_small import probes  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--level", type=int, default=1)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)
    rows = []
    for name, data in probes():
        src = os.path.join(a.outdir, name + ".bin")
        with open(src, "wb") as f:
            f.write(data)
        arc = os.path.join(a.outdir, name + ".sbc")
        rv = run_vendor(["c", arc, "-m%d" % a.level, name + ".bin"],
                        a.outdir, produces=[arc], timeout=900)
        if rv.returncode != 0 or not os.path.exists(arc):
            print("SKIP %s (vendor)" % name)
            continue
        d = os.path.join(a.outdir, "dump-" + name)
        os.makedirs(d, exist_ok=True)
        subprocess.run([OURS, arc, os.path.join(a.outdir, "out-" + name)],
                       env=dict(os.environ, SBC_DUMP=d), capture_output=True)
        hdr = os.path.join(d, "blk000_hdr.txt")
        lzp = os.path.join(d, "blk000_02_lzp.bin")
        bwt = os.path.join(d, "blk000_01_bwt.bin")
        if not (os.path.exists(hdr) and os.path.exists(lzp)):
            print("SKIP %s (no layers)" % name)
            continue
        txt = open(hdr).read()
        m = re.search(r"primary=(\d+)", txt)
        e1 = re.search(r"e1=(\d+)", txt)
        if not m:
            print("SKIP %s (no primary)" % name)
            continue
        n = os.path.getsize(lzp)
        prim = int(m.group(1))
        # a stored block (e1 == 0) does not expose the vendor's L in the dump
        have_L = e1 and int(e1.group(1)) != 0
        rows.append((name, n, prim, have_L))
        if have_L:
            print("OK   %-14s n=%-6d primary=%-6d L %s"
                  % (name, n, prim, os.path.getsize(bwt)))
        else:
            print("PART %-14s n=%-6d primary=%-6d (stored block, no L)"
                  % (name, n, prim))
    with open(os.path.join(a.outdir, "vectors.txt"), "w") as f:
        for name, n, prim, have_L in rows:
            f.write("%s %d %d %d\n" % (name, n, prim, 1 if have_L else 0))
    print("\n%d vectors (dump-<name>/blk000_02_lzp.bin + vectors.txt)"
          % len(rows))


if __name__ == "__main__":
    main()
