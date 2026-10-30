#!/usr/bin/env python3
"""Compare our encoder with sbc.exe on random multi-file inputs.

For each generated file set the vendor archiver and our encoder are run for
-m1/-m2/-m3 with -hr (default) and -hn, and the two archives are compared byte
for byte.  Wine is needed for the vendor side; ``--ours-only`` skips it.

Usage: python3 tools/enc_matrix.py [--sets N] [--seed S] [--vendor]
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
OURS = ROOT / "sbc"
VENDOR = ROOT / "sbc.exe"
WINEPREFIX = ROOT / "_work" / "wineprefix"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def make_set(rng, d, large=False):
    """Create a random file set whose total stays in the single-block range.

    By default every file stays below 1 kB: the vendor only merges such files
    into one block.  Files of 1 kB and more are placed in blocks of their own
    by its analysis, a heuristic that is not reproduced yet (see ENCODER.md),
    so they are opt-in via --large. """
    n = rng.randint(1, 6)
    sizes = []
    total = 0
    pool = [1, 2, 3, 7, 100, 511, 512, 513, 1000]
    if large:
        pool += [1024, 4096, 20000, 60000]
    for _ in range(n):
        s = rng.choice(pool)
        if total + s > 480000:
            break
        sizes.append(s)
        total += s
    if not sizes:
        sizes = [1]
    names = []
    for i, s in enumerate(sizes):
        name = "f%d" % i
        data = bytes(rng.randrange(256) for _ in range(s))
        (Path(d) / name).write_bytes(data)
        names.append(name)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", type=int, default=6)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--vendor", action="store_true",
                    help="also run sbc.exe and diff the two archives")
    ap.add_argument("--large", action="store_true",
                    help="include files >= 1 kB (known to differ, see module doc)")
    a = ap.parse_args()
    rng = random.Random(a.seed)
    ok = bad = 0
    for si in range(a.sets):
        d = tempfile.mkdtemp(prefix="encm-")
        try:
            names = make_set(rng, d, a.large)
            for m in ("1", "2", "3"):
                for h in ("r", "n", "c", "a", "s", "m", "1", "2"):
                    ours = Path(d) / ("o%s%s.sbc" % (m, h))
                    r = subprocess.run([str(OURS), "c", str(ours), "-m" + m,
                                        "-h" + h] + names,
                                       cwd=d, capture_output=True)
                    tag = "set %d m%s -h%s (%d file(s))" % (si, m, h,
                                                            len(names))
                    if r.returncode != 0:
                        bad += 1
                        print("FAIL  %s: encoder exit %d" % (tag, r.returncode))
                        continue
                    if not a.vendor:
                        ok += 1
                        continue
                    vend = Path(d) / ("v%s%s.sbc" % (m, h))
                    v = run_vendor(["c", str(vend), "-m" + m, "-h" + h] +
                                   names, d, produces=[vend])
                    if v.returncode != 0 or not vend.exists():
                        print("SKIP  %s: vendor failed" % tag)
                        continue
                    if ours.read_bytes() == vend.read_bytes():
                        ok += 1
                    else:
                        bad += 1
                        print("DIFF  %s: vendor %d bytes, ours %d bytes" %
                              (tag, vend.stat().st_size, ours.stat().st_size))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print("\n%d OK, %d FAIL" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
