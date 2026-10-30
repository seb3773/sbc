#!/usr/bin/env python3
"""Trace the vendor LZP stream of one block and compare with the correct
filter stream (the one our own archive of the same input decodes to).

Usage: python3 tools/lzp_dbg.py VENDOR_BWT CORRECT_FILTER [--at N]
"""
import sys

MASK = 0xFFFFF


def decode(src, outcap, at=None):
    src = bytes(src)
    inlen = len(src)
    dst = bytearray(outcap + 65536)
    table = [0] * (MASK + 1)
    ncopy = min(inlen, 70)
    dst[0:ncopy] = src[0:ncopy]
    esi = ebx = ncopy
    ebp = 0
    nxt = 0
    events = []

    def h4(pos):
        w = int.from_bytes(bytes(dst[pos - 4:pos]), "little")
        return ((w >> 0x13) ^ w) & MASK

    step = 0
    while ebx < inlen:
        step += 1
        if step > 200000000:
            raise RuntimeError("loop")
        c = src[ebx]
        if c == 2 and ebx + 2 < inlen and src[ebx + 1] == 0xC5:
            sel = src[ebx + 2]
            nxt = ebx + 2
            if sel == 0:
                if ebp == 0:
                    p = esi - 66
                    table[h4(p)] = p
                    dst[esi] = 2
                    b2 = esi + 1
                    p2 = b2 - 66
                    table[h4(p2)] = p2
                    dst[b2] = 0xC5
                    esi = b2 + 1
                    ebx = nxt + 1
                    ebp = 0
                    kind = "esc0"
                else:
                    b2 = esi + 1
                    dst[esi] = 2
                    if ebp == 1:
                        ebp = 0
                        p2 = b2 - 66
                        table[h4(p2)] = p2
                        dst[b2] = 0xC5
                        esi = b2 + 1
                    else:
                        ebp -= 2
                        dst[b2] = 0xC5
                        esi = b2 + 1
                    ebx = nxt + 1
                    kind = "escP"
                events.append((esi, ebx, kind, 0, None))
            else:
                if sel & 0x80:
                    if sel <= 0xBF:
                        nxt = ebx + 3
                        length = (sel & 0x3F) + 14 + (src[ebx + 3] << 6)
                    else:
                        nxt = ebx + 4
                        length = ((sel & 0x3F) + 14 + (src[ebx + 3] << 6)
                                  + (src[ebx + 4] << 14))
                else:
                    length = sel + 14
                sp = table[h4(esi)]
                start = esi
                for _ in range(length):
                    dst[esi:esi + 4] = dst[sp:sp + 4]
                    sp += 4
                    esi += 4
                ebx = nxt + 1
                ebp = 66
                events.append((start, ebx, "match", length, src[ebx - 1]))
        else:
            if ebp == 0:
                p = esi - 66
                table[h4(p)] = p
                dst[esi] = src[ebx]
                ebx += 1
                esi += 1
            else:
                ebp -= 1
                dst[esi] = src[ebx]
                ebx += 1
                esi += 1
    return esi, dst, events, table


def main():
    vb = open(sys.argv[1], "rb").read()
    correct = open(sys.argv[2], "rb").read()
    at = 23336
    if "--at" in sys.argv:
        at = int(sys.argv[sys.argv.index("--at") + 1])
    n, dst, ev, table = decode(vb, len(correct) + 64)
    out = bytes(dst[:n])
    print("decoded", n, "correct", len(correct))
    first = next((i for i in range(min(n, len(correct))) if out[i] != correct[i]),
                 None)
    print("first diff", first)
    if first is None:
        return
    # events are keyed by output start; find the token covering `first`
    for k, (start, end_in, kind, length, sel) in enumerate(ev):
        if start <= first < start + (length * 4 if kind == "match" else 8):
            print("event", k, "start", start, "kind", kind, "len", length,
                  "inpos", end_in)
            for j in range(max(0, k - 3), min(len(ev), k + 3)):
                print("  ev", j, ev[j])
            print("  correct around:", correct[first - 8:first + 12].hex())
            print("  ours    around:", out[first - 8:first + 12].hex())
            print("  vendor input around:", vb[max(0, end_in - 24):end_in + 8].hex())
            break


if __name__ == "__main__":
    main()
