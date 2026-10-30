#!/usr/bin/env python3
"""Build prose samples, pack them with the vendor, and dump their line code.

The mode-4 prose pass (0x408060) only shows up on text-ish blocks, and the
symbol rule depends on the line geometry (spaces per line, blank lines, long
lines, the final line, CRLF versus LF).  This generates a spread of geometries,
packs each with ``sbc.exe``, decodes the archives with our binary while dumping
every block's line-stage input and the vendor's `e2`
(``SBC_LINEDUMP``), then runs ``tools/m4_line_parity.py`` over the result.

Usage: python3 tools/m4_line_samples.py [--keep] [--size N] [--seed N]
Requires wine for the vendor side, like tools/enc_matrix.py.
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
VENDOR = ROOT / "sbc.exe"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from vendor_run import run_vendor  # noqa: E402

WORDS = ("the quick brown fox jumps over a lazy dog while several other "
         "animals watch from behind the fence and wonder what happens next").split()


def make_text(rng, size, maxspaces, crlf=False, trailing=True, seedline=None):
    out = []
    n = 0
    while n < size:
        k = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                        maxspaces, maxspaces - 1, rng.randint(0, maxspaces)])
        words = [rng.choice(WORDS) for _ in range(k + 1)]
        line = " ".join(words)
        if rng.random() < 0.05:
            line = "    " + line if rng.random() < 0.5 else line + " "
        out.append(line)
        n += len(line) + 1
    text = ("\r\n" if crlf else "\n").join(out)
    if trailing:
        text += "\r\n" if crlf else "\n"
    if seedline is not None:
        text += " ".join(["tail"] + ["x"] * seedline) + "\n"
    return text.encode()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default=str(ROOT / "sbc"))
    ap.add_argument("--size", type=int, default=20000)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not VENDOR.exists():
        print("sbc.exe not found")
        return 2
    rng = random.Random(a.seed)
    work = Path(tempfile.mkdtemp(prefix="sbclines-"))
    dump = work / "dump"
    dump.mkdir()
    samples = {
        "short": make_text(rng, a.size, 6),
        "mid": make_text(rng, a.size, 14),
        "long": make_text(rng, a.size, 28),
        "mid-notrail": make_text(rng, a.size, 12, trailing=False),
        "crlf": make_text(rng, a.size, 10, crlf=True),
        "crlf-long": make_text(rng, a.size, 26, crlf=True),
        "tail7": make_text(rng, a.size, 9, seedline=7),
        "tail20": make_text(rng, a.size, 9, seedline=20),
    }
    ok = bad = 0
    try:
        for name, data in samples.items():
            src = work / (name + ".txt")
            src.write_bytes(data)
            for m in ("1", "2", "3"):
                arc = work / ("%s-m%s.sbc" % (name, m))
                v = run_vendor(["c", str(arc), "-m" + m, src.name], work,
                               produces=[arc])
                if v.returncode != 0 or not arc.exists():
                    print("SKIP  %-12s -m%s" % (name, m))
                    continue
                outdir = dump / ("%s-m%s" % (name, m))
                outdir.mkdir()
                # the source text, so the parity check can rebuild `ks` without
                # relying on the (lossy on these files) replay
                (outdir / "src.bin").write_bytes(data)
                env = dict(os.environ, SBC_LINEDUMP=str(outdir))
                r = subprocess.run([a.bin, str(arc), str(outdir / "out")],
                                   capture_output=True, env=env)
                n = len(list(outdir.glob("*_e2.bin")))
                if r.returncode != 0 or n == 0:
                    print("NODUMP %-12s -m%s rc=%d blocks=%d"
                          % (name, m, r.returncode, n))
                    continue
                ok += 1
                print("DUMP  %-12s -m%s blocks=%d" % (name, m, n))
        parity_script = (ROOT / "tests" / "m4_line_parity.py" if (ROOT / "tests" / "m4_line_parity.py").exists()
                         else ROOT / "tools" / "m4_line_parity.py")
        res = subprocess.run([sys.executable,
                              str(parity_script),
                              str(dump)], capture_output=True, text=True)
        sys.stdout.write(res.stdout)
        bad = res.returncode
    finally:
        if not a.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("work dir:", work)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
