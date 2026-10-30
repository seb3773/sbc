import sys
sys.path.insert(0,"/workspace"); sys.path.insert(0,"/tmp/opencode")
import sbc_proto as P, stage2_test as S, lzp_test as LZ

def crc16_arc(data, init=0xFFFF):
    c=init
    for b in data:
        c^=b
        for _ in range(8):
            c=(c>>1)^0xA001 if c&1 else c>>1
    return c&0xFFFF

def stored_crc(data):
    return int.from_bytes(data[-7:-5],"big") if len(data)>=7 else None

def run(data, lv):
    hdr=P.parse_header(data); rdr=hdr["rdr"]; start=P.payload_start(hdr)
    rdr.pos=start; vlq=P.read_vlq(rdr); usize=hdr["files"][0]["sz"]
    if vlq==0: return b"", {"vlq":0}
    rc=P.RC(rdr); primary=rc.decode_large(vlq)
    nbits=rc.decode_int_maxbits(0x14); bits_buf=P.copy_bits(rc,nbits)
    flag3=rc.u(3); extra16=rc.u(0x10) if flag3==2 else None
    win=P.window_size(hdr["method"]); nsyms=P.size_to_nsyms(win)
    extra=P.Extra(rc,nsyms=20,inc=1,cap_freq=0x4000,cap_tot=0x4000)
    e1=extra.decode_extra(); e2=extra.decode_extra(); rc_pos=rdr.pos
    recs,bit_used=P.parse_filters(bits_buf,nbits,usize)
    info=dict(vlq=vlq,primary=primary,flag3=flag3,e1=e1,e2=e2,rc_pos=rc_pos,usize=usize,filters=recs,f3=flag3)
    if e1==0:
        return None, info
    payload=data[len(data)-7-e1:len(data)-7]
    rc2=P.RC(P.ByteReader(payload,0)); bits=P.BitReader(payload,reverse=True)
    ctx=S.Ctx(); S.model_init(ctx,vlq,rc2); ctx.bits=bits
    pos=[0]*512; dst=bytearray(vlq)
    M=S.stage1(ctx,pos,vlq,dst); out=S.run_stage2(ctx,dst,vlq,M,pos)
    L=bytes(dst); raw=P.ibwt(L,primary)
    if flag3==1:
        nn,db=LZ.lzp_decode(raw,usize); raw=bytes(db[:nn])
    else:
        raw=P.flag3_expand(raw,flag3,usize)
    outb=P.apply_filters(raw,recs,lv)
    if usize and len(outb)>usize: outb=outb[:usize]
    info["raw"]=raw; info["out"]=outb; info["L"]=L
    return outb, info

if __name__=="__main__":
    import glob,os
    os.chdir("/workspace")
    srcmap={'pattern':'pattern.bin','records':'records.bin','image24':'image24.raw','biased':'biased.bin','hello':'hello.txt','zeros':'zeros.bin','code':'code.c','image':'image.raw'}
    for f in sorted(glob.glob("packed_corpus/*-m[123].sbc")):
        base=f.split('/')[-1].rsplit('-m',1)[0]
        sp=srcmap.get(base)
        exp=open('corpus/'+sp,'rb').read() if sp else None
        d=open(f,'rb').read(); sc=stored_crc(d)
        got=None; lv=None
        for l in (0,1,2):
            try: outb,info=run(d,l)
            except Exception as e:
                print(f.split('/')[-1],'lv',l,'EXC',repr(e)); continue
            if outb is None:
                print(f.split('/')[-1],'lv',l,'none e1',info.get('e1'),'f3',info.get('flag3')); break
            c=crc16_arc(outb)^0xFFFF
            if c==sc:
                got=outb; lv=l; break
        print(f"{f.split('/')[-1]:18s} stored={sc:04x} lv={lv} ok={None if exp is None else (got==exp) if got is not None else False}")
