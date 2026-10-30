import sys
sys.path.insert(0, "/workspace")
import sbc_proto as P

MASK = 0xFFFFF


def lzp_decode(src, outcap, window=66, skip=66, lbase=15, mark1=2, mark2=0xC5, trace=False):
    src = bytes(src)
    inlen = len(src)
    dst = bytearray(outcap + 64)
    table = [0] * (MASK + 1)
    ncopy = min(inlen, window + 4)
    dst[0:ncopy] = src[0:ncopy]
    esi = ncopy
    ebx = ncopy
    src_end = inlen
    if ebx >= src_end:
        return esi, dst
    ebp = 0
    nxt = 0

    def h4(pos):
        word = int.from_bytes(bytes(dst[pos - 4:pos]), "little")
        return (((word >> 0x13) ^ word) & MASK)

    def lit_hash():
        nonlocal ebx, esi
        p = esi - window
        table[h4(p)] = p
        dst[esi] = src[ebx]
        ebx += 1
        esi += 1

    def lit_copy():
        nonlocal ebx, esi
        dst[esi] = src[ebx]
        ebx += 1
        esi += 1

    def do_copy(length):
        nonlocal ebx, esi, ebp
        sp = table[h4(esi)]
        for _ in range(length):
            dst[esi:esi + 4] = dst[sp:sp + 4]
            sp += 4
            esi += 4
        ebx = nxt + 1
        ebp = skip

    def case0_zero():
        nonlocal ebx, esi, ebp
        p = esi - window
        table[h4(p)] = p
        dst[esi] = mark1
        b2 = esi + 1
        p2 = b2 - window
        table[h4(p2)] = p2
        dst[b2] = mark2
        esi = b2 + 1
        ebx = nxt + 1
        ebp = 0

    def marker_pending():
        nonlocal ebx, esi, ebp
        dst[esi] = mark1
        b2 = esi + 1
        if ebp == 1:
            ebp = 0
            p2 = b2 - window
            table[h4(p2)] = p2
            dst[b2] = mark2
            esi = b2 + 1
        else:
            ebp -= 2
            dst[b2] = mark2
            esi = b2 + 1
        ebx = nxt + 1

    step = 0
    while True:
        step += 1
        if step < 40 and trace:
            print("it", step, "ebx", ebx, "esi", esi, "ebp", ebp,
                  "c", hex(src[ebx]), "nxt", nxt)
        c = src[ebx]
        if c == mark1 and ebx + 2 < src_end and src[ebx + 1] == mark2:
            sel = src[ebx + 2]
            nxt = ebx + 2
            if sel == 0:
                if ebp == 0:
                    case0_zero()
                else:
                    marker_pending()
            else:
                if sel & 0x80:
                    if sel <= 0xBF:
                        nxt = ebx + 3
                        length = (sel & 0x3F) + (lbase - 1) + (src[ebx + 3] << 6)
                    else:
                        nxt = ebx + 4
                        length = ((sel & 0x3F) + (lbase - 1)
                                  + (src[ebx + 3] << 6) + (src[ebx + 4] << 14))
                else:
                    length = (sel & 0xFF) + (lbase - 1)
                if trace and step < 40:
                    print("   MATCH len_dw", length, "nxt", nxt)
                do_copy(length)
        else:
            if ebp == 0:
                lit_hash()
            else:
                ebp -= 1
                lit_copy()
        if src_end <= ebx:
            return esi, dst


if __name__ == "__main__":
    import stage2_test as S
    data = open("/workspace/packed_corpus/zeros-m1.sbc", "rb").read()
    hdr = P.parse_header(data)
    rdr = hdr["rdr"]; rdr.pos = P.payload_start(hdr)
    vlq = P.read_vlq(rdr); rc = P.RC(rdr)
    primary = rc.decode_large(vlq); nbits = rc.decode_int_maxbits(0x14)
    P.copy_bits(rc, nbits); rc.u(3)
    ex = P.Extra(rc, nsyms=P.size_to_nsyms(P.window_size(hdr["method"])))
    ex.decode_extra(); ex.decode_extra()
    payload = data[rdr.pos:len(data) - 7]
    rc2 = P.RC(P.ByteReader(payload, 1)); bits = P.BitReader(payload, reverse=True)
    ctx = S.Ctx(); S.model_init(ctx, vlq, rc2); ctx.bits = bits
    pos = [0] * 512; dst = bytearray(vlq)
    M = S.stage1(ctx, pos, vlq, dst); S.run_stage2(ctx, dst, vlq, M, pos)
    L = bytes(dst)
    B = P.ibwt(L, primary)
    n, out = lzp_decode(B, 200000, trace=True)
    print("ret", n, "first", out[:8].hex(), "nonzero", sum(1 for x in out[:200000] if x))
    exp = open("/workspace/corpus/zeros.bin", "rb").read()
    print("match", bytes(out[:len(exp)]) == exp, "explen", len(exp))
