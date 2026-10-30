#!/usr/bin/env python3
"""Regression for the two late decoder gaps.

* ``ereal0-m3.sbc`` / ``ereal1-m3.sbc`` are vendor-made ``flag3=2`` archives
  with one and two extra LZP passes (``extra16 = 0`` and ``1``).  They were
  produced with the encoder's output-capacity check relaxed under winedbg;
  see RE_report.md section 22.
* ``big3-m3.sbc`` is a single 3 MB block whose records all have ``sub=0``
  (mode 6 + stage 2); ``big-m3.sbc`` / ``big-m3-hn.sbc`` are the 36 MB
  uppercase ``code.c`` archives with the same block-0 shape.

Usage: python3 tools/cascade_test.py [path/to/decoder]
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "sbc"
CASES = [
    ("_work/f32/ereal0-m3.sbc", "_work/f32/e.bin", "extra16=0"),
    ("_work/f32/ereal1-m3.sbc", "_work/f32/e.bin", "extra16=1"),
    ("_work/gtbig/big3-m3.sbc", "_work/gtbig/big3.txt", "big3-m3"),
    ("_work/gtbig/big3-m3-hr.sbc", "_work/gtbig/big3.txt", "big3-m3-hr"),
    ("_work/gtbig/big-m3.sbc", "_work/gtbig/big.txt", "big-m3"),
    ("_work/gtbig/big-m3-hn.sbc", "_work/gtbig/big.txt", "big-m3-hn"),
]


def main():
    ok = bad = 0
    for arc_name, want_name, label in CASES:
        arc = ROOT / arc_name
        want = ROOT / want_name
        if not arc.exists() or not want.exists():
            print("SKIP  %-12s missing %s" % (label, arc if not arc.exists() else want))
            continue
        tmp = Path(tempfile.mkdtemp(prefix="sbccas-"))
        try:
            r = subprocess.run([str(BIN), str(arc), str(tmp)],
                               capture_output=True)
            got = [p for p in tmp.rglob("*") if p.is_file()]
            same = (r.returncode == 0 and len(got) == 1 and
                    got[0].read_bytes() == want.read_bytes())
            if same:
                ok += 1
                print("OK    %-12s %s" % (label, got[0].name))
            else:
                bad += 1
                detail = "exit=%d files=%d" % (r.returncode, len(got))
                if len(got) == 1:
                    detail += " len=%d/%d" % (got[0].stat().st_size,
                                              want.stat().st_size)
                print("FAIL  %-12s %s" % (label, detail))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d OK, %d FAIL" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
