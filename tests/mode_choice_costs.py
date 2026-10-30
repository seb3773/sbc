#!/usr/bin/env python3
"""What does the vendor's mode choice optimise?

For every compressed corpus block with a single record, run our pipeline once
per candidate filter (copy = mode 5, mode 0 with the level's variant, mode 7
with the vendor's own 12-bit parameter when the record carries one) and print
the four stage sizes next to the mode the vendor actually wrote.

The point is to test the obvious hypothesis -- "the analysis picks the cheapest
candidate" -- against the vendor's own output.  It does not hold: see
ENCODER.md 6.4, the choice regularly lands on a payload larger than another
candidate's (``nested-m1`` blk006: mode 0 at 45795 bytes against copy at
35828).

Usage: python3 tools/mode_choice_costs.py [--verbose]
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SBC = os.path.join(ROOT, "sbc")
LAYERS = os.path.join(ROOT, "_work", "layers")


def kv(text):
    return dict(t.split("=", 1) for t in text.split() if "=" in t)


def rec_lines(path):
    return [l for l in open(path) if l.startswith("len=")]


def run(level, mode, m7, blk):
    q = subprocess.run([SBC, "t8", str(level), str(mode), str(m7), blk,
                        "/tmp/mcc"], capture_output=True, text=True)
    return kv(q.stdout) if q.returncode == 0 else None


def main():
    verbose = "--verbose" in sys.argv
    agree = disagree = 0
    rows = []
    for d in sorted(os.listdir(LAYERS)):
        p = os.path.join(LAYERS, d)
        if not os.path.isdir(p):
            continue
        level = 2 if "-m3" in d else 1 if "-m2" in d else 0
        for f in sorted(os.listdir(p)):
            if not f.endswith("_hdr.txt"):
                continue
            k = f[: -len("_hdr.txt")]
            h = kv(open(os.path.join(p, f)).read())
            if int(h.get("e1", "0")) == 0:
                continue
            lines = rec_lines(os.path.join(p, k + "_recs.txt"))
            if len(lines) != 1:
                continue
            r = kv(lines[0])
            if r.get("dict") == "1" or r.get("sub") == "1":
                continue
            blk = os.path.join(p, k + "_04_block.bin")
            pick = int(r["mode"])
            if pick not in (0, 5, 7):
                continue
            cand = {}
            for mode in (5, 0, 7):
                m7 = int(r["m7"]) if (mode == 7 and r.get("m7")) else 257
                out = run(level, mode, m7, blk)
                if out:
                    cand[mode] = out
            if pick not in cand:
                continue
            best = min(cand, key=lambda m: int(cand[m]["plen"]))
            if int(cand[best]["plen"]) == int(cand[pick]["plen"]):
                agree += 1
            else:
                disagree += 1
            rows.append((d, k, level, os.path.getsize(blk), pick, cand, best))

    for d, k, level, n, pick, cand, best in rows:
        cols = []
        for m in (0, 5, 7):
            if m in cand:
                c = cand[m]
                cols.append("m%d f=%-6s l=%-6s b=%-6s p=%-6s%s" %
                            (m, c["filter"], c["lzp"], c["vlq"], c["plen"],
                             " *" if m == pick else "  "))
        tag = "" if best == pick else "  <- pick is not the cheapest"
        print("%-20s %-6s L%d n=%-6d  %s%s" %
              (d, k, level, n, "  ".join(cols), tag))
        if verbose and best != pick:
            print("      cheapest: mode %d (%s bytes) vs chosen mode %d (%s)" %
                  (best, cand[best]["plen"], pick, cand[pick]["plen"]))
    print("\n%d block(s): pick is the cheapest candidate %d, not %d" %
          (len(rows), agree, disagree))
    return 0


if __name__ == "__main__":
    sys.exit(main())
