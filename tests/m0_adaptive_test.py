#!/usr/bin/env python3
"""Adaptive mode-0 round trip (the vendor's 0x425200 object).

``sbc_m0adv.h`` holds one controller used by both directions: the encoder
writes ``residual = original - predictor`` and the decoder rebuilds
``original = residual + predictor``.  Running ``sbc t0`` over the corpus
therefore exercises the selector (FUN_004248c0), the lag pool
(FUN_00424c70), the 257-byte cuts and the table ageing for both vendor
instances (``-m2``: nmod 3, first 768; ``-m3``: nmod 10, first 600) without
needing the vendor binary.

The byte-exact comparison against the vendor's own filter stream is done by
``tools/parity_random.py``; this test only guards the round trip.

Usage: python3 tools/m0_adaptive_test.py [-v]
Exit status is 0 when every corpus sample round-trips.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")

# >= min + 0xC35 for both instances (11317 bytes); the corpus files also cover
# images, biased noise, text, cycles and random data.
FILES = [
    "corpus/image.raw",
    "corpus/image7.raw",
    "corpus/image24.raw",
    "corpus/biased.bin",
    "corpus/code.c",
    "corpus/mixed.bin",
    "corpus/pattern.bin",
    "corpus/random.bin",
    "corpus/records.bin",
    "corpus/zeros.bin",
]


def main(argv):
    verbose = "-v" in argv
    bad = 0
    for rel in FILES:
        path = os.path.join(ROOT, rel)
        if not os.path.exists(path):
            print("SKIP  %-24s missing" % rel)
            continue
        r = subprocess.run([OURS, "t0", path], capture_output=True, text=True)
        out = (r.stdout or "") + (r.stderr or "")
        ok = r.returncode == 0 and out.count("roundtrip OK") == 2
        if not ok:
            bad += 1
        print("%-5s %-24s %s" % ("OK" if ok else "FAIL", rel,
                                 out.strip().replace("\n", " | ")
                                 if verbose or not ok else ""))
    print("\n%d sample(s), %d failure(s)" % (len(FILES), bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
