#!/usr/bin/env python3
"""Cross-check encrypted archives: every cipher, both directions.

For each cipher the vendor offers (`-ca` AES, `-cb` Blowfish, `-cc` CAST-128,
`-cd` 3DES, `-cs` Serpent, `-ct` Twofish) this packs the same corpus file with
``sbc.exe`` and with our encoder, then

* decodes the vendor archive with ``sbc`` (must reproduce the file), and
* extracts our archive with ``unsbc.exe`` (must reproduce the file).

Usage: python3 tools/crypt_parity.py [--files code.c,mixed.bin] [--level -m3]
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
CORPUS = os.path.join(ROOT, "corpus")
WINEPREFIX = os.path.join(ROOT, "_work", "wineprefix")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402

CIPHERS = [("a", "AES"), ("b", "Blowfish"), ("c", "CAST-128"), ("d", "3DES"),
           ("s", "Serpent"), ("t", "Twofish")]
PW = "s3cret pass"


def wine(args, cwd):
    env = dict(os.environ)
    env["WINEPREFIX"] = WINEPREFIX
    env["WINEDEBUG"] = "-all"
    cmd = ["wine", os.path.join(ROOT, "unsbc.exe")] + args
    return subprocess.run(cmd, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=900)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", default="code.c,mixed.bin,image24.raw")
    ap.add_argument("--level", default="-m3")
    a = ap.parse_args()
    names = [f for f in a.files.split(",") if f]
    ok = bad = 0
    for name in names:
        src = os.path.join(CORPUS, name)
        if not os.path.exists(src):
            print("SKIP  %s (missing)" % name)
            continue
        want = open(src, "rb").read()
        for letter, label in CIPHERS:
            tag = "%-10s %-8s %s" % (label, a.level, name)
            d = tempfile.mkdtemp(prefix="crypt-")
            try:
                for sub in ("v", "o", "x"):
                    os.makedirs(os.path.join(d, sub))
                for sub in ("v", "o"):
                    shutil.copy2(src, os.path.join(d, sub, name))
                v = os.path.join(d, "v", "v.sbc")
                o = os.path.join(d, "o", "o.sbc")
                rv = run_vendor(["c", "v.sbc", a.level, "-c" + letter,
                                 "-np" + PW, name], os.path.join(d, "v"),
                                produces=[v])
                ro = subprocess.run([OURS, "c", "o.sbc", a.level,
                                     "-c" + letter, "-s" + PW, name],
                                    cwd=os.path.join(d, "o"),
                                    env=dict(os.environ, SBC_POLICY="1"),
                                    capture_output=True)
                if rv.returncode or not os.path.exists(v):
                    print("SKIP  %s (vendor pack failed)" % tag)
                    continue
                if ro.returncode or not os.path.exists(o):
                    print("FAIL  %s (our pack failed)" % tag)
                    bad += 1
                    continue
                # 1. vendor archive -> our decoder
                ex = subprocess.run([OURS, v, os.path.join(d, "x")],
                                    env=dict(os.environ, SBC_PASS=PW),
                                    capture_output=True)
                got = os.path.join(d, "x", name)
                ours_ok = ex.returncode == 0 and os.path.exists(got) and \
                    open(got, "rb").read() == want
                # 2. our archive -> vendor extractor (fresh cwd)
                os.makedirs(os.path.join(d, "w"))
                shutil.move(o, os.path.join(d, "w", "o.sbc"))
                rx = wine(["x", "o.sbc", "-np" + PW], os.path.join(d, "w"))
                gotv = os.path.join(d, "w", name)
                vend_ok = rx.returncode == 0 and os.path.exists(gotv) and \
                    open(gotv, "rb").read() == want
                if ours_ok and vend_ok:
                    ok += 1
                    print("OK    %s" % tag)
                else:
                    bad += 1
                    print("FAIL  %s (ours=%s vendor=%s) %s" %
                          (tag, ours_ok, vend_ok,
                           rx.stdout.decode("latin-1")[-200:].replace("\r", "")
                           if not vend_ok else ""))
            finally:
                shutil.rmtree(d, ignore_errors=True)
    print("\n%d ok, %d failed" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
