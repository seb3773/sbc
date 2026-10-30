#!/usr/bin/env python3
"""Stage-2 sub-filter (vendor 0x423c60), reconstructed from the disassembly.

Reversed layout of the object (byte offsets):

    0x4004  flag        0: 3-byte prologue + 17-bit hash of 3 bytes
                        1: 8-byte prologue + 21-bit hash of 8 bytes
    0x4008  ring size   wrap distance for the history buffer
    0x400c  table       uint32[131072] (flag 0) / [524288] (flag 1)
    0x4010  ring        history buffer
    0x4014  lbase       1 + the 5-bit field of the record  (length base)
    0x4018  unused here (lbase + 0x3fffe)
    0x4020  disabled flag (return 0 without output when set)
    0x4028  marker 1
    0x4029  marker 2
    0x402a  alignment flag (only when set are copies 4-byte aligned)

Vectors: ``_work/subfilter/in*.bin`` -> ``out*.bin`` captured from unsbc.exe
on the 9 MB ``-m2`` set (call 0: 2305 -> 2890273, call 1: 2635 -> 3018000).

Usage: python3 tools/sub_test.py [dumpdir]
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUB = ROOT / "_work" / "subfilter"


class Ctx:
    def __init__(self, ring, table, flag=0, lbase=4, m1=0x03, m2=0xC5,
                 align=0, disabled=0):
        self.ring = ring          # bytearray, size = wrap distance
        self.table = table        # list[int]
        self.flag = flag
        self.lbase = lbase
        self.m1 = m1
        self.m2 = m2
        self.align = align
        self.disabled = disabled


def expand(ctx, src, out_cap=None):
    """Mirror of 0x423c60.  Returns the produced bytes."""
    n = len(src)
    if n == 0 or ctx.disabled:
        return b""
    ring = ctx.ring
    size = len(ring)
    flag = ctx.flag
    prologue = 8 if flag else 3
    out = bytearray(out_cap or max(n * 4, 1 << 22))
    op = 0
    # prologue: the first min(prologue, n) bytes are literals
    for i in range(min(prologue, n) - 1, -1, -1):
        out[i] = src[i]
    op = min(prologue, n)
    ip = prologue
    lbase = ctx.lbase - 1
    while ip < n:
        c = src[ip]
        if c != ctx.m1:
            out[op] = c
            op += 1
            ip += 1
            continue
        if ip + 1 >= n or src[ip + 1] != ctx.m2:
            out[op] = c
            op += 1
            ip += 1
            continue
        if ip + 2 >= n:
            out[op] = c
            op += 1
            ip += 1
            continue
        L = src[ip + 2]
        if L == 0:                      # escape: the two marker bytes
            out[op] = ctx.m1
            out[op + 1] = ctx.m2
            op += 2
            ip += 2 if flag else 3
            continue
        if L < 0x80:
            length = L + lbase
            ip += 3
        elif L <= 0xBF:
            length = (L & 0x3F) + lbase + (src[ip + 3] << 6)
            ip += 4
        else:
            length = (L & 0x3F) + lbase + (src[ip + 3] << 6) + (src[ip + 4] << 14)
            ip += 5
        if flag:
            h = ((out[op - 4] ^ ((out[op - 4] >> 13) & 0x7FFFF)) ^
                 (((out[op - 8] ^ ((out[op - 8] >> 15) & 0x1FFFF)) << 11) & 0xFFFFFFFF))
            h &= 0x1FFFFF
        else:
            h = ((out[op - 3] << 13) ^ (out[op - 2] << 8) ^ out[op - 1]) & 0x1FFFF
        pos = ctx.table[h]
        words = length
        p = pos
        for _ in range(words):
            w = ring[p:p + 4]
            if len(w) < 4:                      # crosses the ring end
                w = w + ring[:4 - len(w)]
            out[op] = w[0]
            out[op + 1] = w[1]
            out[op + 2] = w[2]
            out[op + 3] = w[3]
            p += 4
            if p >= size:                       # vendor wraps after the read
                p -= size
            op += 4
    return bytes(out[:op])


def load_ctx(dumpdir):
    d = Path(dumpdir)
    ring = bytearray((d / "ring.bin").read_bytes())
    raw = (d / "tbl.bin").read_bytes()
    table = list(struct.unpack("<%dI" % (len(raw) // 4), raw))
    return Ctx(ring, table)


def main():
    ctx = load_ctx(sys.argv[1] if len(sys.argv) > 1 else "/tmp/rt/dump")
    ok = True
    for i in (1, 2):
        src = (SUB / ("in%d.bin" % i)).read_bytes()
        want = (SUB / ("out%d.bin" % i)).read_bytes()
        got = expand(ctx, src, out_cap=len(want) + 64)
        same = got == want
        print("call %d: %d -> %d (want %d) %s" %
              (i - 1, len(src), len(got), len(want), "OK" if same else "DIFF"))
        if not same:
            ok = False
            if len(got) == len(want):
                for j in range(len(want)):
                    if got[j] != want[j]:
                        print("  first diff at %d: got %02x want %02x" %
                              (j, got[j], want[j]))
                        break
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
