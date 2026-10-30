#!/usr/bin/env python3
"""Rebuild every compressed payload from its BWT string and compare.

For each corpus archive the decoder dumps the stage2 output (``SBC_DSTOUT``),
one file per compressed block; ``tools/layer_dump.py`` already stored the
vendor payload per block in ``_work/layers/<archive>/blkNNN_00_payload.bin``.
``./sbc t2 S payload`` then re-encodes that string and must reproduce the
vendor bytes exactly.

Usage: python3 tools/stage2_payload_test.py [archive.sbc ...]
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBC = os.path.join(ROOT, "sbc")


def blocks(layer_dir):
    """Return [(prefix, fields)] for every compressed block of an archive."""
    out = []
    for hdr in sorted(glob.glob(os.path.join(layer_dir, "blk*_hdr.txt"))):
        kv = {}
        for tok in open(hdr).read().split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
        if int(kv.get("e1", "0")) > 0:
            out.append((hdr[: -len("_hdr.txt")], kv))
    return out


def main():
    args = sys.argv[1:]
    archives = args or sorted(glob.glob(os.path.join(ROOT, "packed_corpus", "*.sbc")))
    ok = bad = skip = 0
    for arc in archives:
        name = os.path.basename(arc)[:-4]
        lay = os.path.join(ROOT, "_work", "layers", name)
        if not os.path.isdir(lay):
            print("%-16s no layer dump" % name)
            skip += 1
            continue
        comp = blocks(lay)
        if not comp:
            continue
        tmp = tempfile.mkdtemp(prefix="s2p-")
        env = dict(os.environ, SBC_DSTOUT=tmp)
        subprocess.run([os.path.join(ROOT, "sbc"), arc], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       cwd=ROOT, check=False)
        dumps = sorted(glob.glob(os.path.join(tmp, "*.bin")))
        # A block can be decoded more than once (level/strategy fallbacks), so
        # match dumps to blocks by the vlq length instead of by position.
        used = 0
        picked = []
        for pref, kv in comp:
            want = int(kv.get("vlq", "0"))
            while used < len(dumps) and os.path.getsize(dumps[used]) != want:
                used += 1
            if used >= len(dumps):
                print("%-16s %-6s no dump for vlq=%d"
                      % (name, os.path.basename(pref), want))
                bad += 1
                picked.append(None)
                continue
            picked.append(dumps[used])
            used += 1
        for i, ((pref, kv), s) in enumerate(zip(comp, picked)):
            if s is None:
                continue
            pay = pref + "_00_payload.bin"
            r = subprocess.run([os.path.join(ROOT, "sbc"), "t2", s, pay],
                               capture_output=True, text=True, cwd=ROOT)
            line = r.stdout.strip()
            tag = "ok" if r.returncode == 0 else "FAIL"
            if r.returncode == 0:
                ok += 1
            else:
                bad += 1
            print("%-16s blk%03d e1=%-6s %-5s %s"
                  % (name, i, kv.get("e1"), tag, line))
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d identical, %d failed, %d skipped" % (ok, bad, skip))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
