#!/usr/bin/env python3
"""Ask the vendor encoder which filter mode it picks for synthetic inputs.

The mode policy (ENCODER.md 6.4) is a classifier, not a cost comparison, and it
depends on byte *values* as much as on structure: a 16-byte cycle of ASCII
letters is filtered at -m1/-m2 and copied at -m3, while the same cycle built
from pseudo-random bytes is copied at -m1 already, and a 32-byte cycle comes
out as mode 6 (the repeat filter).

This script builds such inputs, packs them with ``sbc.exe`` under Wine and
prints the mode of the single record our own parser sees, so the map can be
extended without writing throw-away shell.  One Wine start-up per case: about
6 s each on the machine this was written on.

Usage: python3 tools/mode_probe.py [--periods 2,4,8,16,32] [--levels 1,2,3]
                                   [--size 200000] [--ascii]
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
VENDOR = os.path.join(ROOT, "sbc.exe")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def unit_bytes(period, ascii_):
    if ascii_:
        return bytes(0x41 + (i % 26) for i in range(period))
    return bytes((i * 37 + 11) & 0xFF for i in range(period))


def vendor_mode(d, level, size, unit):
    data = (unit * (size // len(unit) + 1))[:size]
    name = "d.bin"
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)
    out = os.path.join(d, "v%d.sbc" % level)
    # run_vendor removes `out` first, so the overwrite prompt cannot appear
    r = run_vendor(["c", os.path.basename(out), "-m%d" % level, name], d,
                   produces=[out], timeout=180)
    if r.returncode == -9:
        return "timeout"
    if r.returncode != 0 or not os.path.exists(out):
        return "vendor failed"
    q = subprocess.run([OURS, out], capture_output=True, text=True,
                       env=dict(os.environ, SBC_DBG2="1"))
    m = re.search(r"mode=(\d+)", q.stderr)
    return m.group(1) if m else "?"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--periods", default="2,4,8,16,32")
    ap.add_argument("--levels", default="1,2,3")
    ap.add_argument("--size", type=int, default=200000)
    ap.add_argument("--ascii", action="store_true",
                    help="build each cycle from 'A'.. instead of raw bytes")
    a = ap.parse_args()
    periods = [int(x) for x in a.periods.split(",")]
    levels = [int(x) for x in a.levels.split(",")]
    d = tempfile.mkdtemp(prefix="sbcprobe-")
    try:
        for per in periods:
            unit = unit_bytes(per, a.ascii)
            modes = []
            for lv in levels:
                modes.append("m%d=%s" % (lv, vendor_mode(d, lv, a.size, unit)))
            print("period %-3d %s" % (per, " ".join(modes)))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
