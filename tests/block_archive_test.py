#!/usr/bin/env python3
"""Whole-archive check for the compressed-block writer.

The vendor's *filter policy* is not reproduced yet (ENCODER.md 6.4), so this
test supplies the mode each corpus archive uses and then compares everything
else byte for byte: with ``SBC_COMP=<mode>`` our encoder runs the real
pipeline (filter -> LZP -> BWT -> stage2), applies the vendor's store/compress
decision and writes the block header, record list, payload and checksums.

Only archives whose blocks all resolve to a single mode-0/mode-5 record are
listed; the rest need modes we cannot pick yet (mode 4/7 text and image
filters, the second-stage `sub` filter, dictionaries).

The comparison starts at the first block: the archive header carries each
file's DOS date/time, so it only matches when the corpus file's mtime is the
one the vendor saw, which is not what this test is about (``tools/enc_matrix.py``
covers headers by packing freshly written files with both encoders).
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBC = os.path.join(ROOT, "sbc")
CORPUS = os.path.join(ROOT, "corpus")
PACKED = os.path.join(ROOT, "packed_corpus")

# (corpus file, level, filter mode of the single record)
CASES = [
    ("hello.txt", "m1", 5),
    ("zeros.bin", "m1", 0),
    ("zeros.bin", "m2", 5),
    ("zeros.bin", "m3", 5),
    ("pattern.bin", "m1", 0),
    ("pattern.bin", "m2", 0),
    ("pattern.bin", "m3", 5),
    ("image24.raw", "m1", 0),
    ("image24.raw", "m2", 0),
    ("image.raw", "m1", 0),
    ("image.raw", "m2", 0),
    ("image.raw", "m3", 0),
    ("records.bin", "m1", 5),
    ("records.bin", "m2", 5),
    ("records.bin", "m3", 0),
    ("biased.bin", "m1", 0),
    ("biased.bin", "m2", 5),
    ("biased.bin", "m3", 5),
    ("mixed.bin", "m2", 5),
    ("random.bin", "m1", 5),
]


def block_start(path):
    q = subprocess.run([SBC, path], capture_output=True, text=True,
                       env=dict(os.environ, SBC_DBG2="1"))
    m = re.search(r"BLK pos=(\d+)", q.stderr)
    if not m:
        raise SystemExit("no block in %s: %s" % (path, q.stderr.strip()))
    return int(m.group(1))


def body(path):
    with open(path, "rb") as f:
        data = f.read()
    return data[block_start(path):]


def main():
    # --policy: let the encoder pick the mode itself (SBC_POLICY=1) instead of
    # supplying the vendor's, which shows how far the measured rules go.
    policy = "--policy" in sys.argv
    ok = bad = 0
    for name, level, mode in CASES:
        ref = os.path.join(PACKED, "%s-%s.sbc" % (os.path.splitext(name)[0], level))
        stem = os.path.splitext(name)[0]
        out = "/tmp/bt_%s_%s.sbc" % (stem, level)
        env = dict(os.environ)
        if policy:
            env["SBC_POLICY"] = "1"
        else:
            env["SBC_COMP"] = str(mode)
        q = subprocess.run([SBC, "c", out, "-" + level, name], cwd=CORPUS,
                           env=env, capture_output=True, text=True)
        if q.returncode != 0:
            bad += 1
            print("FAIL run  %-18s %s %s" % (name, level, q.stderr.strip()))
            continue
        mine, want = body(out), body(ref)
        if mine == want:
            ok += 1
            print("OK        %-18s %s mode %d (%d bytes)" %
                  (name, level, mode, len(mine)))
        else:
            bad += 1
            first = next((i for i in range(min(len(mine), len(want)))
                          if mine[i] != want[i]), None)
            print("FAIL body %-18s %s mode %d: %d vs %d bytes, first diff %s"
                  % (name, level, mode, len(mine), len(want), first))
    print("compressed archive bodies: %d ok, %d bad%s" %
          (ok, bad, " (policy picked the mode)" if policy else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
