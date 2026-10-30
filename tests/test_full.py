import sys, os
sys.path.insert(0, "/workspace")
sys.path.insert(0, "/tmp/opencode")
import sbc_proto as P
import stage2_test as S
import lzp_test as LZ


def run(name):
    data = open("/workspace/packed_corpus/" + name, "rb").read()
    hdr = P.parse_header(data)
    rdr = hdr["rdr"]
    start = P.payload_start(hdr)
    rdr.pos = start
    vlq = P.read_vlq(rdr)
    usize = hdr["files"][0]["sz"]
    if vlq == 0:
        return None, {}
    rc = P.RC(rdr)
    primary = rc.decode_large(vlq)
    nbits = rc.decode_int_maxbits(0x14)
    bits_buf = P.copy_bits(rc, nbits)
    flag3 = rc.u(3)
    extra16 = rc.u(0x10) if flag3 == 2 else None
    win = P.window_size(hdr["method"])
    nsyms = P.size_to_nsyms(win)
    extra = P.Extra(rc, nsyms=20, inc=1, cap_freq=0x4000, cap_tot=0x4000)
    e1 = extra.decode_extra()
    e2 = extra.decode_extra()
    rc_pos = rdr.pos
    recs, bit_used = P.parse_filters(bits_buf, nbits, usize)
    info = dict(vlq=vlq, primary=primary, nbits=nbits, flag3=flag3,
                e1=e1, e2=e2, rc_pos=rc_pos, usize=usize, filters=recs)
    if e1 == 0:
        return None, info
    payload = data[len(data) - 7 - e1:len(data) - 7]
    rc2 = P.RC(P.ByteReader(payload, 0))
    bits = P.BitReader(payload, reverse=True)
    ctx = S.Ctx()
    S.model_init(ctx, vlq, rc2)
    ctx.bits = bits
    pos = [0] * 512
    dst = bytearray(vlq)
    M = S.stage1(ctx, pos, vlq, dst)
    out = S.run_stage2(ctx, dst, vlq, M, pos)
    info["M"] = M
    info["out"] = out
    info["rc_err"] = rc2.err
    L = bytes(dst)
    raw = P.ibwt(L, primary)
    if flag3 == 1:
        nn, db = LZ.lzp_decode(raw, usize)
        raw = bytes(db[:nn])
    else:
        raw = P.flag3_expand(raw, flag3, usize)
    outb = P.apply_filters(raw, recs)
    if usize and len(outb) > usize:
        outb = outb[:usize]
    return outb, info


if __name__ == "__main__":
    for name in ["hello-m1.sbc", "empty-m1.sbc", "zeros-m1.sbc", "zeros-m2.sbc",
                 "biased-m1.sbc", "biased-m2.sbc", "biased-m3.sbc",
                 "code-m1.sbc", "code-m2.sbc", "code-m3.sbc"]:
        data = open("/workspace/packed_corpus/" + name, "rb").read()
        hdr = P.parse_header(data)
        fn = hdr["files"][0]["name"].decode("ascii")
        try:
            outb, info = run(name)
        except Exception as ex:
            print(name, "EXC", repr(ex))
            continue
        expect = open("/workspace/corpus/" + fn, "rb").read()
        ok = outb == expect if outb is not None else False
        print("%-14s vlq=%-7s prim=%-6s flag3=%s e1=%-8s e2=%-8s M=%s out=%s L=%s %s" % (
            name, info.get("vlq"), info.get("primary"), info.get("flag3"),
            info.get("e1"), info.get("e2"), info.get("M"), info.get("out"),
            len(outb) if outb is not None else None, "MATCH" if ok else "no"))
