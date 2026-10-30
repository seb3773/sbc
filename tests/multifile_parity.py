#!/usr/bin/env python3
"""Randomized multi-file parity: our encoder against sbc.exe on file sets.

``tools/vendor_parity.py`` packs a fixed four-file set; this tool generates
the shapes the corpus does not have: two to six files of mixed content
(random, zeros, prose, periodic text, image-like) and mixed sizes, packed at
all three levels with the vendor's default block structure (``-oz``) and with
explicit structures (``-on``/``-of``/``-oa``/``-oz``/``-os``).

For every case it prints the vendor's file order and block layout (decoded
with our own decoder) so a mismatch can be attributed: a different *order*
means the partial-solid grouping differs, the same order but different blocks
means the splitter differs, and identical layout with different bytes points
at a filter/payload bug.

Usage: python3 tools/multifile_parity.py [--count N] [--levels 1,3]
                                        [--struct on,of,oa,oz,os]
                                        [--seed S] [--keep DIR] [--verbose]
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
VENDOR = os.path.join(ROOT, "sbc.exe")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402

SENT = (b"the quick brown fox jumps over the lazy dog and then some more "
        b"words here\n")
LOREM = (b"lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
         b"eiusmod\n")

KINDS = ("rnd", "zero", "text", "pat", "prose2", "img")


def content(rng, kind, n):
    if kind == "rnd":
        return bytes(rng.randrange(256) for _ in range(n))
    if kind == "zero":
        return b"\x00" * n
    if kind == "text":
        return (SENT * (n // len(SENT) + 1))[:n]
    if kind == "pat":
        return (b"abcdefghij" * (n // 10 + 1))[:n]
    if kind == "prose2":
        return (LOREM * (n // len(LOREM) + 1))[:n]
    if kind == "img":
        return bytes(((i // 13) * 7 + (i % 13) * 3) & 0xFF for i in range(n))
    raise ValueError(kind)


def layout(archive, work):
    """Decode `archive` and return (file order, [(block, records)])."""
    d = os.path.join(work, "lay")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    subprocess.run([OURS, archive, os.path.join(d, "x")], capture_output=True,
                   env=dict(os.environ, SBC_DUMP=d))
    order = []
    arc = os.path.join(d, "arc.txt")
    if os.path.exists(arc):
        for line in open(arc):
            m = re.search(r"name=(\S+)", line)
            if line.startswith("file") and m:
                order.append(m.group(1))
    blocks = []
    for name in sorted(os.listdir(d)):
        m = re.match(r"blk(\d+)_recs\.txt$", name)
        if not m:
            continue
        recs = [l for l in open(os.path.join(d, name)).read().split("\n")[1:]
                if l.strip()]
        blocks.append((int(m.group(1)), recs))
    return order, blocks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=6)
    ap.add_argument("--levels", default="1,2,3")
    ap.add_argument("--struct", default="default,on,of,oa,oz,os,ub")
    ap.add_argument("--seed", type=int, default=21)
    ap.add_argument("--keep", default="")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    if not os.path.exists(VENDOR):
        print("sbc.exe not found")
        return 2
    rng = random.Random(a.seed)
    levels = ["-m" + x for x in a.levels.split(",") if x]
    structs = [None if s == "default" else "-" + s
               for s in a.struct.split(",") if s]
    work = a.keep or tempfile.mkdtemp(prefix="mf-")
    os.makedirs(work, exist_ok=True)
    ok = bad = 0
    fails = []
    try:
        for trial in range(a.count):
            nf = rng.randint(2, 5)
            files = []
            for i in range(nf):
                kind = rng.choice(KINDS)
                n = rng.choice([300, 900, 1500, 4000, 9000])
                name = "%d_%s.dat" % (i, kind)
                with open(os.path.join(work, name), "wb") as f:
                    f.write(content(rng, kind, n))
                files.append(name)
            for st in structs:
                for lv in levels:
                    tag = "t%d %s %s" % (trial, st or "def", lv)
                    v = os.path.join(work, "v.sbc")
                    o = os.path.join(work, "o.sbc")
                    for p in (v, o):
                        if os.path.exists(p):
                            os.remove(p)
                    rv = run_vendor(["c", "v.sbc", lv] + ([st] if st else []) +
                                    files, work, produces=[v])
                    ro = subprocess.run([OURS, "c", "o.sbc", lv] +
                                        ([st] if st else []) + files,
                                        cwd=work, capture_output=True,
                                        env=dict(os.environ, SBC_POLICY="1"))
                    if rv.returncode or not os.path.exists(v):
                        print("SKIP  %s (vendor failed)" % tag)
                        continue
                    if ro.returncode or not os.path.exists(o):
                        fails.append(tag)
                        bad += 1
                        print("FAIL  %s (encoder rejected the options)" % tag)
                        continue
                    vb = open(v, "rb").read()
                    ob = open(o, "rb").read()
                    if vb == ob:
                        ok += 1
                        if a.verbose:
                            print("OK    %s" % tag)
                        continue
                    bad += 1
                    fails.append(tag)
                    vo, vb_ = layout(v, work)
                    oo, ob_ = layout(o, work)
                    why = "payload"
                    if vo != oo:
                        why = "order"
                    elif [(i, len(r)) for i, r in vb_] != \
                            [(i, len(r)) for i, r in ob_]:
                        why = "blocks"
                    print("FAIL  %s (%s: %d vs %d bytes)" %
                          (tag, why, len(ob), len(vb)))
                    if why == "order":
                        print("      vendor order %s" % vo)
                        print("      ours   order %s" % oo)
                    elif why == "blocks":
                        print("      vendor blocks %s" %
                              [(i, len(r)) for i, r in vb_])
                        print("      ours   blocks %s" %
                              [(i, len(r)) for i, r in ob_])
            for f in files:
                os.remove(os.path.join(work, f))
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
