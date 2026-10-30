#!/usr/bin/env python3
"""Probe the vendor's forward BWT on small repetitive inputs.

The vendor picks between two suffix sorts at n < 0x8000 (421ac0) and above
(421cc0); the small path is the one whose *tie* order (which of several equal
cyclic rotations ends up where) decides `primary` -- the class of input that
`reg04` belongs to.  For every probe this packs the input with sbc.exe, decodes
the archive with our own decoder (SBC_DUMP) to read the block's `primary` and
the layer it fed to the BWT, then runs our forward BWT on that layer and
compares the two primaries.

Only `primary` is checked: the dump files are the layers *before* the BWT, so
there is no L to compare against (the archive comparison suites cover L).

Usage: python3 tools/bwt_probe_small.py [--level 1] [--keep DIR]
"""
import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402


def probes():
    out = []

    def add(name, data):
        out.append((name, data))

    def rep(unit, n):
        return (unit * (n // len(unit) + 1))[:n]

    add("zeros3000", bytes(3000))
    add("zeros2000", bytes(2000))
    add("ab3000", rep(b"ab", 3000))
    add("abc3000", rep(b"abc", 3000))
    add("abcd3000", rep(b"abcd", 3000))
    add("ab5_3000", rep(b"ababa", 3000))
    add("ab7_3000", rep(b"abababa", 3000))
    add("word3000", rep(b"word word word word word\n", 3000))
    add("word1500", rep(b"word word word word word\n", 1500))
    add("word6000", rep(b"word word word word word\n", 6000))
    add("cyc25_3000", rep(bytes((0x41 + (i * 7) % 26) for i in range(25)), 3000))
    add("cyc25_9000", rep(bytes((0x41 + (i * 7) % 26) for i in range(25)), 9000))
    add("cyc16_4096", rep(bytes(range(16)) * 4, 4096))
    add("aa_10000", rep(b"a", 10000))
    r = random.Random(3)
    add("rand3000", bytes(r.randrange(256) for _ in range(3000)))
    add("rand3000b", bytes(random.Random(9).choice((0, 1)) for _ in range(3000)))
    add("low3000", bytes(random.Random(11).choice(b"abcde") for _ in range(3000)))
    add("low3000_2", bytes(random.Random(12).choice(b"ab") for _ in range(3000)))
    add("low3000_3", bytes(random.Random(13).choice(b"abcdefgh") for _ in range(3000)))
    add("low3000_4", bytes(random.Random(14).choice(b"ab") for _ in range(2000)))
    add("saw3000", bytes((i * 37) & 0xFF for i in range(3000)))
    add("saw16_3000", bytes(i & 0xF for i in range(3000)))
    for n in (2000, 4000, 8000, 16000, 32000):
        add("zeros%d" % n, bytes(n))
        add("ab%d" % n, rep(b"ab", n))
        add("word%d" % n, rep(b"word word word word word\n", n))
    return out


def vendor_primary_and_layers(work, name, data, level, keep):
    src = os.path.join(work, name + ".bin")
    with open(src, "wb") as f:
        f.write(data)
    v = os.path.join(work, name + ".sbc")
    rv = run_vendor(["c", v, "-m%d" % level, name + ".bin"], work,
                    produces=[v], timeout=600)
    if rv.returncode != 0 or not os.path.exists(v):
        return None
    d = os.path.join(work, "dump-" + name)
    os.makedirs(d, exist_ok=True)
    env = dict(os.environ, SBC_DUMP=d)
    subprocess.run([OURS, v, os.path.join(work, "out-" + name)], env=env,
                   capture_output=True)
    hdr = os.path.join(d, "blk000_hdr.txt")
    lzp = os.path.join(d, "blk000_02_lzp.bin")
    bwt = os.path.join(d, "blk000_01_bwt.bin")
    if not (os.path.exists(hdr) and os.path.exists(lzp)):
        return None
    txt = open(hdr).read()
    m = re.search(r"primary=(\d+)", txt)
    flag3 = re.search(r"flag3=(\d+)", txt)
    if not m:
        return None
    return {"primary": int(m.group(1)), "flag3": int(flag3.group(1)),
            "lzp": lzp, "bwt": bwt, "dump": d}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, default=1)
    ap.add_argument("--keep", default="")
    a = ap.parse_args()
    work = a.keep or tempfile.mkdtemp(prefix="bwtprobe-")
    os.makedirs(work, exist_ok=True)
    bad_prim = ok = 0
    print("%-14s %8s %8s %8s  %s" % ("case", "vendor", "ours", "delta", ""))
    for name, data in probes():
        info = vendor_primary_and_layers(work, name, data, a.level, a.keep)
        if info is None:
            print("%-14s SKIP" % name)
            continue
        vp = info["primary"]
        r = subprocess.run([OURS, "t6", info["lzp"], info["bwt"], str(vp)],
                           capture_output=True, text=True)
        line = (r.stdout or "").strip()
        m = re.search(r"prim=(\d+)/", line)
        if not m:
            print("%-14s ?  %s" % (name, line))
            continue
        op = int(m.group(1))
        if op != vp:
            bad_prim += 1
        else:
            ok += 1
        print("%-14s %8d %8d %8d  %s"
              % (name, vp, op, op - vp, "" if op == vp else "PRIMARY"))
    print("\n%d identical, %d primary mismatches" % (ok, bad_prim))
    if a.keep:
        print("work dir:", work)
    else:
        shutil.rmtree(work, ignore_errors=True)
    return 0 if bad_prim == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
