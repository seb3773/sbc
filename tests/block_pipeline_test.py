#!/usr/bin/env python3
"""Run the C compressed-block pipeline (./sbc t8) on every single-record
mode 0/5 block and compare all four stages with the vendor layer dumps."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBC = os.path.join(ROOT, "sbc")
LAYERS = os.path.join(ROOT, "_work", "layers")


def kv(path):
    d = {}
    for line in open(path):
        for t in line.split():
            if "=" in t:
                k, v = t.split("=", 1)
                d[k] = v
    return d


def main():
    ok = bad = skip = 0
    for d in sorted(os.listdir(LAYERS)):
        p = os.path.join(LAYERS, d)
        if not os.path.isdir(p):
            continue
        level = 2 if "-m3" in d else 1 if "-m2" in d else 0
        for f in sorted(os.listdir(p)):
            if not f.endswith("_hdr.txt"):
                continue
            k = f[: -len("_hdr.txt")]
            h = kv(os.path.join(p, f))
            if int(h.get("e1", "0")) == 0:
                continue  # stored block
            recs = [l for l in open(os.path.join(p, k + "_recs.txt"))
                    if l.startswith("len=")]
            if len(recs) != 1:
                skip += 1
                continue
            r = kv(os.path.join(p, k + "_recs.txt"))
            lst = open(os.path.join(p, k + "_recs.txt")).read()
            first = [l for l in lst.splitlines() if l.startswith("len=")][0]
            r = dict(t.split("=", 1) for t in first.split() if "=" in t)
            if r.get("mode") not in ("0", "5") or r.get("sub") == "1" \
                    or r.get("dict") == "1":
                skip += 1
                continue
            blk = os.path.join(p, k + "_04_block.bin")
            out = "/tmp/bp_%s_%s" % (d, k)
            q = subprocess.run([SBC, "t8", str(level), r["mode"], "0", blk, out],
                               capture_output=True, text=True)
            if q.returncode != 0:
                bad += 1
                print("FAIL run", d, k, q.stderr.strip())
                continue
            want = {
                "f": os.path.join(p, k + "_03_filter.bin"),
                "l": os.path.join(p, k + "_02_lzp.bin"),
                "b": os.path.join(p, k + "_01_bwt.bin"),
                "p": os.path.join(p, k + "_00_payload.bin"),
            }
            probes = {}
            for t in q.stdout.split():
                if "=" in t:
                    a, b = t.split("=", 1)
                    probes[a] = b
            fail = []
            for tag, ref in want.items():
                mine = out + "_" + tag + ".bin"
                if open(mine, "rb").read() != open(ref, "rb").read():
                    fail.append(tag)
            if probes["flag3"] != h["flag3"]:
                fail.append("flag3")
            if int(probes["vlq"]) != int(h["vlq"]):
                fail.append("vlq")
            if int(probes["primary"]) != int(h["primary"]):
                fail.append("primary")
            if fail:
                bad += 1
                print("FAIL", d, k, ",".join(fail), q.stdout.strip())
            else:
                ok += 1
    print("block pipeline: %d ok, %d bad, %d skipped" % (ok, bad, skip))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
