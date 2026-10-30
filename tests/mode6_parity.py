#!/usr/bin/env python3
"""Mode-6 (repeat) parity: whole archives, our encoder against sbc.exe.

Mode 6 is the filter the vendor picks for periodic and uppercase text, so these
are the shapes that exercise `sbc_enc_mode6()` and the policy around it: the
4 kB gate, the `-m1` fallback when the simple filter gives up, the `-m2` "when
it applies" rule and the `-m3` payload comparison.

Each case is packed at all three levels and the two archives are compared byte
for byte (header included).  Every vendor run goes through `vendor_run`, which
deletes the target and closes stdin, so the overwrite prompt cannot stall the
run.

Usage: python3 tools/mode6_parity.py [--cycles 20,24,32] [--sizes 5000,20000]
                                     [--seed N] [-v]
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
CORPUS = os.path.join(ROOT, "corpus")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def cycle(n, period, rng, ascii_only=False):
    if ascii_only:
        pat = bytes(rng.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                    for _ in range(period))
    else:
        pat = bytes(rng.randrange(256) for _ in range(period))
    return (pat * (n // period + 2))[:n]


def uppercase(n):
    return open(os.path.join(CORPUS, "code.c"), "rb").read().upper()[:n]


def compare(name, data, levels, keep, verbose):
    """Pack `data` with both encoders at every level; return (ok, bad)."""
    ok = bad = 0
    d = tempfile.mkdtemp(prefix="m6-")
    try:
        src = os.path.join(d, name)
        with open(src, "wb") as fh:
            fh.write(data)
        for lv in levels:
            v = os.path.join(d, "v.sbc")
            o = os.path.join(d, "o.sbc")
            rv = run_vendor(["c", "v.sbc", "-y", lv, name], d, produces=[v])
            ro = subprocess.run([OURS, "c", "o.sbc", lv, name], cwd=d,
                                capture_output=True,
                                env=dict(os.environ, SBC_POLICY="1"))
            tag = "%-14s %s" % (name, lv)
            if rv.returncode or not os.path.exists(v):
                print("SKIP  %s (vendor rc=%d)" % (tag, rv.returncode))
                continue
            if ro.returncode or not os.path.exists(o):
                print("FAIL  %s (encoder rc=%d)" % (tag, ro.returncode))
                bad += 1
                continue
            if open(v, "rb").read() == open(o, "rb").read():
                ok += 1
                if verbose:
                    print("OK    %s (%d B)" % (tag, os.path.getsize(v)))
            else:
                bad += 1
                print("FAIL  %s (%d vs %d bytes)" %
                      (tag, os.path.getsize(o), os.path.getsize(v)))
        if keep:
            shutil.rmtree(keep, ignore_errors=True)
            shutil.copytree(d, keep)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return ok, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cycles", default="20,32,48",
                    help="cycle periods to pack")
    ap.add_argument("--sizes", default="8000",
                    help="sizes for the periodic cases")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keep", default="", help="keep the last case here")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    levels = ["-m1", "-m2", "-m3"]
    ok = bad = 0
    cases = []
    for per in [int(x) for x in a.cycles.split(",") if x]:
        for n in [int(x) for x in a.sizes.split(",") if x]:
            cases.append(("cyc-r%02d-%d.bin" % (per, n),
                          cycle(n, per, rng, False)))
            cases.append(("cyc-a%02d-%d.bin" % (per, n),
                          cycle(n, per, rng, True)))
    for n in (4200, 4097, 45270):
        cases.append(("upper-%d.txt" % n, uppercase(n)))
    for name, data in cases:
        o, b = compare(name, data, levels, a.keep, a.verbose)
        ok += o
        bad += b
    print("\n%d identical, %d different" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
