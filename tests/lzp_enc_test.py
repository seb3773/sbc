#!/usr/bin/env python3
"""Check ./sbc t4 (forward LZP) against every vendor 02_lzp.bin layer dump.

A block uses LZP when 02_lzp.bin differs from 03_filter.bin (the decoder only
writes 02_lzp when flag3 != 0).  For each such block the C encoder must
reproduce the vendor stream byte for byte; the result is also fed through the
Python/decoder-side LZP pass to make sure it inverts.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from lzp_enc_proto import vendor_tokens  # noqa: E402

SBC = os.path.join(ROOT, "sbc")
LAYERS = os.path.join(ROOT, "_work", "layers")


def main():
    ok = bad = 0
    fails = []
    for d in sorted(os.listdir(LAYERS)):
        p = os.path.join(LAYERS, d)
        if not os.path.isdir(p):
            continue
        for f in sorted(os.listdir(p)):
            if not f.endswith("_02_lzp.bin"):
                continue
            k = f[: -len("_02_lzp.bin")]
            filt = os.path.join(p, k + "_03_filter.bin")
            lzp = os.path.join(p, f)
            a = open(filt, "rb").read()
            b = open(lzp, "rb").read()
            if a == b:
                continue  # no LZP on this block
            out = os.path.join("/tmp", "lzp_enc_test.bin")
            if os.path.exists(out):
                os.unlink(out)
            env = dict(os.environ, SBC_T4OUT=out)
            r = subprocess.run([SBC, "t4", filt, lzp], capture_output=True,
                               text=True, env=env)
            got = open(out, "rb").read() if os.path.exists(out) else b""
            good = r.returncode == 0 and got == b
            if good:
                # decoder round-trip
                _, n, dec = vendor_tokens(b, len(a))
                good = bytes(dec[:len(a)]) == a and n == len(a)
            if good:
                ok += 1
            else:
                bad += 1
                fails.append((d, k, r.stdout.strip()))
                print("FAIL", d, k, r.stdout.strip())
    print("lzp encoder: %d/%d blocks identical" % (ok, ok + bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
