#!/usr/bin/env python3
"""Large multi-block archives with -ad: compare our encoder with sbc.exe.

`-ad` (no adaptive block size reduction) makes the block layout deterministic,
one block per (block size - 1) bytes, so the whole archive must be identical.
That is the case where the encoder is exact beyond 512 kB.

Usage: python3 tools/enc_big.py [--sets N] [--seed S]
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


def make_files(rng, d, sizes):
    names = []
    for i, s in enumerate(sizes):
        name = "b%d.bin" % i
        (Path(d) / name).write_bytes(bytes(rng.randrange(256) for _ in range(s)))
        names.append(name)
    return names


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", type=int, default=2)
    ap.add_argument("--seed", type=int, default=3)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    shapes = [
        [900000],                 # one block with the default b5
        [1400000],                # two blocks with b1
        [2200000, 300000],        # file boundary inside the stream
        [3100000],
    ]
    levels = ["1", "2"]
    hs = ["n", "c"]
    bs = ["1", "5"]
    ok = bad = 0
    for si in range(a.sets):
        d = tempfile.mkdtemp(prefix="big-")
        try:
            for sizes in shapes:
                names = make_files(rng, d, sizes)
                for m in levels:
                    for b in bs:
                        for h in hs:
                            o = Path(d) / "o.sbc"
                            v = Path(d) / "v.sbc"
                            for p in (o, v):
                                if p.exists():
                                    p.unlink()
                            args = ["c", str(o), "-m" + m, "-h" + h, "-ad",
                                    "-b" + b] + names
                            r = subprocess.run([str(OURS)] + args, cwd=d,
                                               capture_output=True)
                            vv = run_vendor(["c", str(v), "-m" + m, "-h" + h,
                                             "-ad", "-b" + b] + names, d,
                                            produces=[v])
                            tag = "%s m%s -h%s -b%s" % (
                                "+".join(str(s) for s in sizes), m, h, b)
                            if r.returncode or vv.returncode or not v.exists():
                                bad += 1
                                print("FAIL  %-28s ours rc=%d vendor rc=%d" %
                                      (tag, r.returncode, vv.returncode))
                                continue
                            if o.read_bytes() == v.read_bytes():
                                ok += 1
                                print("OK    %-28s %d B" % (tag, o.stat().st_size))
                            else:
                                bad += 1
                                print("DIFF  %-28s ours %d vendor %d" %
                                      (tag, o.stat().st_size,
                                       v.stat().st_size))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    print("\n%d OK, %d FAIL" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
