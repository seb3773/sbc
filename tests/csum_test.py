#!/usr/bin/env python3
"""Regression test for the eight -h checksum types (no wine needed).

For every digest type the encoder builds an archive, the decoder must extract
it byte-exactly, and a payload byte flipped in the middle must be rejected
instead of silently extracted.

Usage: python3 tools/csum_test.py [--big N]
"""
import argparse
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / "sbc"
WIDTH = {"n": 0, "r": 2, "c": 4, "a": 4, "s": 4, "m": 16, "1": 20, "2": 32}


def encode(d, name, data, flag):
    (d / name).write_bytes(data)
    arc = d / ("o%s.sbc" % flag)
    r = subprocess.run([str(BIN), "c", str(arc), "-m1", "-h" + flag, name],
                       cwd=d, capture_output=True)
    return arc, r


def extract(arc, out, d):
    out.mkdir(exist_ok=True)
    r = subprocess.run([str(BIN), str(arc), str(out)], cwd=d,
                       capture_output=True, text=True)
    return r


def case(flag, data, label):
    d = Path(tempfile.mkdtemp(prefix="csum-"))
    try:
        arc, r = encode(d, "f.bin", data, flag)
        if r.returncode != 0:
            return "encode failed: %s" % r.stderr.decode()[:80]
        out = d / "out"
        got = extract(arc, out, d)
        if got.returncode != 0:
            return "decode rejected (%s)" % got.stdout.strip().split("\n")[0]
        back = (out / "f.bin").read_bytes()
        if back != data:
            return "round-trip mismatch"
        if flag == "n":
            return None               # no digest, nothing can be verified
        blob = bytearray(arc.read_bytes())
        # last payload byte: archive = ... payload, verify record, 5-byte trailer
        pos = len(blob) - 6 - WIDTH[flag]
        if pos <= 5:
            return "no payload to corrupt"
        blob[pos] ^= 0x40
        bad = d / "bad.sbc"
        bad.write_bytes(blob)
        res = extract(bad, d / "outbad", d)
        if res.returncode == 0:
            return "corruption at %d not detected" % pos
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--big", type=int, default=700000,
                    help="size of the multi-block sample")
    a = ap.parse_args()
    rng = random.Random(11)
    big = bytes(rng.randrange(256) for _ in range(a.big))
    samples = [("small 4 B", b"abcd"),
               ("small 37 B", bytes(range(37))),
               ("blocksize-1", bytes(rng.randrange(256) for _ in range(511))),
               ("multi-block", big)]
    types = [("n", "none"), ("r", "CRC16"), ("c", "CRC32"), ("a", "Adler32"),
             ("s", "Sum32"), ("m", "MD5"), ("1", "SHA1"), ("2", "SHA256")]
    bad = 0
    for flag, name in types:
        for label, data in samples:
            err = case(flag, data, label)
            if err:
                bad += 1
                print("FAIL  -h%-2s %-12s %s" % (flag, label, err))
            else:
                print("OK    -h%-2s %-12s %-8s %d B" % (flag, label, name,
                                                        len(data)))
    print("\n%d failure(s)" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
