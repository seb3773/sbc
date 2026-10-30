#!/usr/bin/env python3
"""Single-file parity against sbc.exe for the photographic (mode-7) records.

Usage: python3 tools/m7_parity.py [--files a,b,c] [--levels 2,3] [--ad]

Every case packs the file with the vendor and with ours (same switches) and
compares the two archives byte for byte, reporting the first difference and
the mode/width our policy picked (SBC_M7DBG on stderr).
"""
import argparse
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
VENDOR = os.path.join(ROOT, "sbc.exe")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402


def one(path, level, ad, extra=()):
    name = os.path.basename(path)
    with tempfile.TemporaryDirectory() as td:
        local = os.path.join(td, name)
        with open(path, "rb") as fr, open(local, "wb") as fw:
            fw.write(fr.read())
        vout = os.path.join(td, "v.sbc")
        oout = os.path.join(td, "o.sbc")
        opts = ["-m%d" % level] + (["-ad"] if ad else []) + list(extra)
        r = run_vendor(["c", "Z:\\" + vout.replace("/", "\\")[1:]] + opts +
                       [name], td, produces=[vout], timeout=600)
        if r.returncode != 0:
            return False, "vendor rc %d" % r.returncode, ""
        env = dict(os.environ)
        env["SBC_M7DBG"] = "1"
        p = subprocess.run([OURS, "c", oout] + opts + [name], cwd=td, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if p.returncode != 0:
            return False, "ours rc %d" % p.returncode, ""
        dbg = "".join(l for l in p.stdout.decode("latin1").splitlines(True)
                      if l.startswith("m7 ") or l.startswith("m0 "))
        with open(vout, "rb") as f1, open(oout, "rb") as f2:
            a, b = f1.read(), f2.read()
        if a == b:
            return True, "identical (%d bytes)" % len(a), dbg.strip()
        i = 0
        while i < min(len(a), len(b)) and a[i] == b[i]:
            i += 1
        return False, ("first diff at %d (vendor %d bytes, ours %d)"
                       % (i, len(a), len(b))), dbg.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", default=None)
    ap.add_argument("--levels", default="3")
    ap.add_argument("--ad", action="store_true")
    ap.add_argument("--extra", default="")
    args = ap.parse_args()
    if args.files:
        files = [f if os.path.isabs(f) else os.path.join(ROOT, f)
                 for f in args.files.split(",")]
    else:
        files = [os.path.join(ROOT, "corpus", n) for n in
                 ("image24.raw", "image7.raw", "image.raw", "eng.txt",
                  "biased.bin", "zeros.bin", "records.bin", "pattern.bin")]
    levels = [int(x) for x in args.levels.split(",")]
    extra = args.extra.split(",") if args.extra else []
    bad = 0
    for f in files:
        for lv in levels:
            ok, msg, dbg = one(f, lv, args.ad, extra)
            if not ok:
                bad += 1
            print("%-28s -m%d%-4s %-6s %s%s" % (os.path.basename(f), lv,
                  " -ad" if args.ad else "", "OK" if ok else "DIFF", msg,
                  ("\n    " + dbg.replace("\n", "\n    ")) if dbg else ""))
    print("%d failure(s)" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
