#!/usr/bin/env python3
"""Text-variant round-trip: LF, CRLF and uppercase sources through the vendor.

The mode 4 control word changes with the content (LF text -> 0xAC/0x8C, CRLF ->
0xEC, large blocks drop 0x08 -> 0xA4), so the corpus alone does not protect the
filter.  This builds three variants of ``corpus/code.c`` repeated to ~300 kB,
packs them with ``sbc.exe`` at every level, decodes them with ours and compares
the bytes.

Uppercase text makes the vendor pick filter **mode 6** (repeat-from-context),
which is now reversed: every variant must decode byte-exactly.  The `marker`
variant additionally sprinkles literal `7B F0` pairs into the uppercase text so
the encoder has to use mode 6's `7B F0 00` escape for a literal marker pair.

Usage: python3 tools/text_variants.py [--bin PATH] [--size N] [--keep]
Requires wine for the vendor side, like tools/enc_matrix.py.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "sbc.exe"
WINEPREFIX = ROOT / "_work" / "wineprefix"
SRC = ROOT / "corpus" / "code.c"


def variants(size):
    base = SRC.read_bytes()
    lf = (base * (size // len(base) + 2))[:size]
    upper = lf.upper()
    # literal marker pairs: the mode-6 encoder must escape them as `7B F0 00`
    marked = bytearray()
    for i, ch in enumerate(upper):
        if i and i % 5000 == 0:
            marked += b"{\xf0"
        marked.append(ch)
    return {
        "lf": lf,
        "crlf": lf.replace(b"\n", b"\r\n")[:size],
        "upper": upper,
        # mode 6 for both: uppercase is what selects it
        "upper_crlf": upper.replace(b"\n", b"\r\n")[:size],
        "marker": bytes(marked[:size]),
    }


sys.path.insert(0, str(Path(__file__).resolve().parent))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=str(ROOT / "sbc"))
    ap.add_argument("--size", type=int, default=300000)
    ap.add_argument("--keep", action="store_true",
                    help="keep the work directory")
    a = ap.parse_args()
    if not VENDOR.exists():
        print("sbc.exe not found")
        return 2
    work = Path(tempfile.mkdtemp(prefix="sbcvar-"))
    ok = bad = 0
    try:
        for name, data in variants(a.size).items():
            src = work / (name + ".txt")
            src.write_bytes(data)
            for m in ("1", "2", "3"):
                arc = work / ("%s-m%s.sbc" % (name, m))
                v = run_vendor(["c", str(arc), "-m" + m, src.name], work,
                               produces=[arc])
                if v.returncode != 0 or not arc.exists():
                    print("SKIP  %-12s -m%s: vendor failed" % (name, m))
                    continue
                out = work / ("out-%s-m%s" % (name, m))
                out.mkdir(exist_ok=True)
                r = subprocess.run([a.bin, str(arc), str(out)],
                                   capture_output=True)
                got = out / (name + ".txt")
                same = (r.returncode == 0 and got.exists() and
                        got.read_bytes() == data)
                if same:
                    ok += 1
                    print("OK    %-12s -m%s (%d bytes)" % (name, m, len(data)))
                else:
                    bad += 1
                    print("FAIL  %-12s -m%s: exit %d, %s" % (
                        name, m, r.returncode,
                        "no output" if not got.exists() else "bytes differ"))
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    print("\n%d OK, %d FAIL" % (ok, bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
