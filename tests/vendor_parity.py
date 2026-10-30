#!/usr/bin/env python3
"""Whole-archive parity: our encoder against sbc.exe on the same inputs.

The corpus archives under ``packed_corpus`` were packed at some point in the
past, and the header carries each file's DOS date/time, so comparing against
them only works while the inputs keep their mtime.  This tool instead packs the
same file twice -- once with ``sbc.exe`` under Wine, once with our encoder and
``SBC_POLICY=1`` -- and compares the two files byte for byte, header included.

Usage: python3 tools/vendor_parity.py [--files a,b] [--levels 1,2,3]
                                      [--multi] [--keep DIR]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
VENDOR = os.path.join(ROOT, "sbc.exe")
CORPUS = os.path.join(ROOT, "corpus")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)

FILES = ["hello.txt", "empty.dat", "code.c", "eng.txt", "zeros.bin",
         "pattern.bin", "image.raw", "image24.raw", "image7.raw",
         "records.bin", "biased.bin", "mixed.bin", "random.bin"]


def run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, env=env)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", default=",".join(FILES))
    ap.add_argument("--levels", default="1,2,3")
    ap.add_argument("--multi", action="store_true",
                    help="also pack a multi-file set")
    a = ap.parse_args()
    names = [f for f in a.files.split(",") if f]
    levels = ["-m" + x for x in a.levels.split(",") if x]
    ok = bad = 0
    fails = []
    d = tempfile.mkdtemp(prefix="parity-")
    try:
        for name in names:
            src = os.path.join(CORPUS, name)
            if not os.path.exists(src):
                print("SKIP  %s (missing)" % name)
                continue
            shutil.copy2(src, os.path.join(d, name))
            for lv in levels:
                v = os.path.join(d, "v.sbc")
                o = os.path.join(d, "o.sbc")
                for p in (v, o):
                    if os.path.exists(p):
                        os.remove(p)
                rv = run_vendor(["c", "v.sbc", lv, name], d, produces=[v])
                ro = run([OURS, "c", "o.sbc", lv, name], d,
                         dict(os.environ, SBC_POLICY="1"))
                tag = "%-14s %s" % (name, lv)
                if rv.returncode != 0 or not os.path.exists(v):
                    print("SKIP  %s (vendor failed)" % tag)
                    continue
                if ro.returncode != 0 or not os.path.exists(o):
                    print("FAIL  %s (encoder failed)" % tag)
                    bad += 1
                    fails.append(tag)
                    continue
                vb = open(v, "rb").read()
                ob = open(o, "rb").read()
                if vb == ob:
                    ok += 1
                    print("OK    %s (%d bytes)" % (tag, len(vb)))
                else:
                    bad += 1
                    fails.append(tag)
                    first = next((i for i in range(min(len(vb), len(ob)))
                                  if vb[i] != ob[i]), None)
                    print("FAIL  %s (%d vs %d bytes, first diff %s)" %
                          (tag, len(ob), len(vb), first))
        if a.multi:
            names2 = ["code.c", "eng.txt", "zeros.bin", "records.bin"]
            sub = os.path.join(d, "multi")
            os.makedirs(sub, exist_ok=True)
            for n in names2:
                shutil.copy2(os.path.join(CORPUS, n), os.path.join(sub, n))
            for lv in levels:
                v = os.path.join(sub, "v.sbc")
                o = os.path.join(sub, "o.sbc")
                for p in (v, o):
                    if os.path.exists(p):
                        os.remove(p)
                rv = run_vendor(["c", "v.sbc", lv] + names2, sub,
                                produces=[v])
                ro = run([OURS, "c", "o.sbc", lv] + names2, sub,
                         dict(os.environ, SBC_POLICY="1"))
                tag = "multi(%d) %s" % (len(names2), lv)
                if rv.returncode or not os.path.exists(v):
                    print("SKIP  %s (vendor failed)" % tag)
                    continue
                if ro.returncode or not os.path.exists(o):
                    print("FAIL  %s (encoder failed)" % tag)
                    bad += 1
                    continue
                if open(v, "rb").read() == open(o, "rb").read():
                    ok += 1
                    print("OK    %s" % tag)
                else:
                    bad += 1
                    fails.append(tag)
                    print("FAIL  %s (%d vs %d bytes)" %
                          (tag, os.path.getsize(o), os.path.getsize(v)))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print("\n%d identical, %d different" % (ok, bad))
    if fails:
        print("differing: " + " ".join(fails))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
