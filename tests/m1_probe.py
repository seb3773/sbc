#!/usr/bin/env python3
"""Hunt for the level rules the corpus does not cover.

The corpus and the randomized suites already agree with the vendor, so a rule
study needs inputs that are *not* in them: the battery below builds short
cycles, mixed ASCII/binary, counter and record data, sparse and narrow-range
noise, and size variants straddling the filter thresholds (0x2400 and 11317).
Every case is packed by ``sbc.exe`` and by our encoder at each requested level
and the two archives are compared byte for byte; the record mode both sides
wrote is printed next to the verdict, so a disagreement names the rule that
broke.

Usage: python3 tools/m1_probe.py [--levels 1,2,3] [--jobs 2] [--only substring]
                                 [--ad]
"""
import argparse
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OURS = os.path.join(ROOT, "sbc")
CORPUS = os.path.join(ROOT, "corpus")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vendor_run import run_vendor  # noqa: E402  (deletes target, no stdin)


def rnd(n, seed):
    r = random.Random(seed)
    return bytes(r.randrange(256) for _ in range(n))


def build_battery():
    """(name, bytes) pairs, deterministically generated."""
    out = []

    def add(name, data):
        out.append((name, data))

    def cycle(period, n, ascii_):
        unit = (bytes(0x41 + (i % 26) for i in range(period)) if ascii_
                else bytes((i * 37 + 11) & 0xFF for i in range(period)))
        return (unit * (n // period + 1))[:n]

    for p in (3, 4, 8, 16, 17, 32, 64):
        add("ascii%d" % p, cycle(p, 200000, True))
        add("raw%d" % p, cycle(p, 200000, False))
    add("ramp256", bytes(i & 0xFF for i in range(200000)))
    add("ramp7", bytes((i * 7) & 0xFF for i in range(200000)))
    add("ramp3", bytes((i * 3) & 0xFF for i in range(200000)))
    add("zeros", bytes(200000))
    add("ones", b"\xff" * 200000)
    add("alt", (b"\x00\xff" * 100000))
    add("rand200k", rnd(200000, 1))
    for n in (4000, 8000, 9216, 9217, 10000, 11316, 11317, 12000, 16384,
              16385, 40000):
        add("rand%d" % n, rnd(n, n))
    for n in (9216, 11316, 11317, 16384, 40000, 200000):
        add("ascii16_%d" % n, cycle(16, n, True))
        add("raw16_%d" % n, cycle(16, n, False))
    # The weak-accept repeat stage (0x412af0's tail, the record's `adv` bit):
    # 512 random bytes, then a 6000-byte `ab` run the simple filter only codes
    # weakly (verdict 1), then a 1000-byte random block repeated -- the mode-6
    # transform compresses that tail, so at -m1 the vendor stores 7628 bytes
    # with `adv=1` instead of the 120000-byte filter output.
    r = random.Random(31)
    adv = bytearray(r.randrange(256) for _ in range(512))
    adv += b"ab" * 3000
    blk = bytes(r.randrange(256) for _ in range(1000))
    adv += (blk * 200)[:120000 - 6512]
    add("advweak", bytes(adv))
    add("walk", None)          # filled below
    r = random.Random(7)
    w = bytearray(200000)
    v = 128
    for i in range(200000):
        v = max(0, min(255, v + r.choice((-1, 0, 0, 0, 1))))
        w[i] = v
    out[-1] = ("walk", bytes(w))
    sp = bytearray(200000)
    r = random.Random(8)
    for i in range(200000):
        if r.random() < 0.01:
            sp[i] = r.randrange(1, 256)
    add("sparse", bytes(sp))
    add("lowent", bytes(random.Random(9).choice((0, 1, 2)) for _ in range(200000)))
    add("hi4", bytes((b & 0x0F) << 4 for b in rnd(200000, 10)))
    cnt = bytearray()
    for i in range(50000):
        cnt += i.to_bytes(4, "little")
    add("count32", bytes(cnt))
    rec = bytearray()
    r = random.Random(11)
    for i in range(3125):
        rec += (b"REC%08d" % i) + bytes(r.randrange(256) for _ in range(56))
    add("records64", bytes(rec))
    csv = bytearray()
    r = random.Random(12)
    for i in range(8000):
        csv += b"%d,%d,%s,%d\n" % (i, i * 37 % 1000,
                                   bytes(r.choice(b"abcdefgh") for _ in range(8)),
                                   r.randrange(100000))
    add("csv", bytes(csv))
    wide = bytearray()
    for b in b"the quick brown fox jumps over the lazy dog. " * 4500:
        wide += bytes((b, 0))
    add("wide", bytes(wide[:200000]))
    for f in ("code.c", "eng.txt", "records.bin", "image.raw", "image24.raw",
              "image7.raw", "biased.bin", "pattern.bin", "mixed.bin",
              "random.bin", "zeros.bin"):
        p = os.path.join(CORPUS, f)
        if os.path.exists(p):
            add(os.path.splitext(f)[0], open(p, "rb").read())
    up = open(os.path.join(CORPUS, "code.c"), "rb").read().upper()
    add("upper", up)
    half = cycle(16, 100000, True) + rnd(100000, 13)
    add("ascii_mixed", half)
    tile = rnd(512, 14)
    add("tiles512", (tile * 400)[:200000])
    r = random.Random(15)
    nt = bytearray(rnd(200000, 16))
    for i in range(200000):
        nt[i] = (nt[i] + (i >> 9)) & 0xFF
    add("noise_trend", bytes(nt))
    add("sorted", bytes(sorted(rnd(200000, 17))))
    return out


def modes_of(path):
    q = subprocess.run([OURS, path], capture_output=True, text=True,
                       env=dict(os.environ, SBC_DBG2="1"))
    ms = re.findall(r"mode=(\d+)", q.stderr or q.stdout)
    return ",".join(ms) if ms else "?"


def one_case(job):
    d, name, data, level, ad = job
    sub = os.path.join(d, "%s-m%d" % (name, level))
    os.makedirs(sub, exist_ok=True)
    fn = name + ".bin"
    with open(os.path.join(sub, fn), "wb") as f:
        f.write(data)
    v = os.path.join(sub, "v.sbc")
    o = os.path.join(sub, "o.sbc")
    extra = ["-ad"] if ad else []
    rv = run_vendor(["c", "v.sbc", "-m%d" % level] + extra + [fn], sub,
                    produces=[v], timeout=600)
    ro = subprocess.run([OURS, "c", "o.sbc", "-m%d" % level] + extra + [fn],
                        cwd=sub, capture_output=True, text=True)
    tag = "%-14s -m%d" % (name, level)
    if rv.returncode != 0 or not os.path.exists(v):
        return tag, "SKIP", "vendor failed", "", ""
    if ro.returncode != 0 or not os.path.exists(o):
        return tag, "FAIL", "encoder failed", "", ""
    vb = open(v, "rb").read()
    ob = open(o, "rb").read()
    vm, om = modes_of(v), modes_of(o)
    if vb == ob:
        return tag, "OK", "%d B" % len(vb), vm, om
    first = next((i for i in range(min(len(vb), len(ob))) if vb[i] != ob[i]),
                 None)
    return (tag, "FAIL", "%d vs %d B, diff@%s" % (len(ob), len(vb), first),
            vm, om)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="1,2,3")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--only", default="")
    ap.add_argument("--ad", action="store_true")
    a = ap.parse_args()
    levels = [int(x) for x in a.levels.split(",")]
    battery = [(n, d) for n, d in build_battery()
               if not a.only or a.only in n]
    d = tempfile.mkdtemp(prefix="m1probe-")
    jobs = [(d, n, data, lv, a.ad) for n, data in battery for lv in levels]
    print("%d cases (%d inputs x %d levels), %d jobs" %
          (len(jobs), len(battery), len(levels), a.jobs))
    lock = threading.Lock()
    bad = 0
    try:
        with ThreadPoolExecutor(max_workers=a.jobs) as ex:
            for tag, verdict, note, vm, om in ex.map(one_case, jobs):
                with lock:
                    if verdict == "FAIL":
                        bad += 1
                    print("%-6s %-22s %-22s %s" %
                          (verdict, tag, "v:" + vm + " o:" + om, note))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    print("\n%d failures" % bad)
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
