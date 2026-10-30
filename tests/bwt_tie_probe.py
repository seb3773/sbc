#!/usr/bin/env python3
"""Measure the vendor's BWT primary on exactly periodic blocks.

A block made of a whole number of repeats has one rotation class whose members
are equal, so any rank inside it decodes to the same text: the payload and the
BWT string are identical, only `primary` differs.  The vendor's sort is not
stable (ENCODER.md 6.8 item 1), so its pick cannot be derived from ours; this
tool records it as data for whoever reproduces the sort.

For every repeat count it packs the same line with ``sbc.exe``, decodes the
archive's first block header with our decoder (``SBC_DBG=1``) and prints the
vendor's primary next to ours, plus the offset inside the equal class.

The offset is content-dependent (ENCODER.md 6.8 item 1): the default
near-periodic line gives non-zero offsets, while a random line of the same
length usually stays at the class start, and all-equal / period-2 input always
does.  ``--line`` takes C-style escapes, so a newline-terminated line can be
written as ``--line 'mmgtfhheycixmqvwrctpgnxt\n'``.

Usage: python3 tools/bwt_tie_probe.py [--line TEXT] [--counts 8-40]
                                      [--level m1|m2|m3] [--keep DIR]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402

DEFAULT_LINE = "word word word word word\n"


def block_primary(archive):
    q = subprocess.run([OURS, archive], capture_output=True, text=True,
                       env=dict(os.environ, SBC_DBG="1", SBC_LEVEL="2"))
    m = re.search(r"BLK pos=\d+ vlq=\d+ prim=(\d+)", q.stderr)
    return int(m.group(1)) if m else None


def counts(spec):
    out = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        elif part:
            out.append(int(part))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--line", default=DEFAULT_LINE)
    ap.add_argument("--counts", default="8-40")
    ap.add_argument("--level", default="m3", choices=["m1", "m2", "m3"])
    ap.add_argument("--keep", default="")
    a = ap.parse_args()
    line = (a.line.encode("utf-8").decode("unicode_escape")
            .encode("latin1"))
    if not os.path.exists(os.path.join(ROOT, "sbc.exe")):
        print("sbc.exe not found")
        return 2
    work = a.keep or tempfile.mkdtemp(prefix="bwtie-")
    os.makedirs(work, exist_ok=True)
    print("repeats  bytes  vendor  ours  offset")
    rows = []
    try:
        for r in counts(a.counts):
            data = line * r
            with open(os.path.join(work, "x.bin"), "wb") as f:
                f.write(data)
            v = os.path.join(work, "v.sbc")
            o = os.path.join(work, "o.sbc")
            rv = run_vendor(["c", "v.sbc", "-" + a.level, "x.bin"], work,
                            produces=[v])
            if rv.returncode or not os.path.exists(v):
                print("%7d  SKIP (vendor failed)" % r)
                continue
            subprocess.run([OURS, "c", "o.sbc", "-" + a.level, "x.bin"],
                           cwd=work, capture_output=True,
                           env=dict(os.environ, SBC_POLICY="1"))
            vp = block_primary(v)
            op = block_primary(o) if os.path.exists(o) else None
            if vp is None or op is None:
                print("%7d  SKIP (no coded block)" % r)
                continue
            rows.append((r, vp, op))
            print("%7d  %5d  %6d  %4d  %6d" % (r, len(data), vp, op, vp - op))
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    if rows:
        print("\noffsets: " + ", ".join(str(v - o) for _, v, o in rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
