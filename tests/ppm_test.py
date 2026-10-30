#!/usr/bin/env python3
"""Check the shadow encoder against every compressed block of an archive.

The decoder can replay each coded value it reads through the range encoder
(``SBC_PPMTEST=1``), which must reproduce the payload bytes the archive
stores.  This validates the coding layer of the future PPM encoder -- models,
rescales, the raw bit channel and the flush -- independently of the encoder's
(not yet reproduced) decisions.

Usage: python3 tools/ppm_test.py [--bin PATH] [archive...]
       (default: every packed_corpus/*.sbc)

Exit status is non-zero as soon as a block differs.
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = re.compile(r"PPM shadow: (\d+) block\(s\), (\d+) identical, "
                     r"(\d+) different")


def run(bin_path, arc):
    env = dict(os.environ)
    env["SBC_PPMTEST"] = "1"
    tmp = Path(tempfile.mkdtemp(prefix="sbcp-"))
    try:
        r = subprocess.run([bin_path, str(arc), str(tmp)], env=env,
                           capture_output=True, text=True)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=str(ROOT / "sbc"))
    ap.add_argument("--verbose", action="store_true",
                    help="print one line per archive, matches included")
    ap.add_argument("archives", nargs="*")
    a = ap.parse_args()
    arcs = ([Path(p) for p in a.archives] if a.archives else
            sorted((ROOT / "packed_corpus").glob("*.sbc")))
    blocks = same = diff = 0
    for arc in arcs:
        r = run(a.bin, arc)
        m = SUMMARY.search(r.stdout)
        if not m:
            print("FAIL  %-24s no shadow summary (exit %d)" %
                  (arc.name, r.returncode))
            diff += 1
            continue
        b, s, d = (int(x) for x in m.groups())
        blocks += b
        same += s
        diff += d
        detail = [ln for ln in r.stdout.splitlines()
                  if ln.startswith("PPM blk") or ln.strip().startswith("!=")]
        if d or a.verbose:
            print("%-24s %d block(s), %d identical, %d different" %
                  (arc.name, b, s, d))
            for ln in detail:
                print("    " + ln)
    print("\n%d compressed block(s): %d identical, %d different" %
          (blocks, same, diff))
    return 0 if diff == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
