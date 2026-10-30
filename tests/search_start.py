import sys; sys.path.insert(0,'/workspace'); sys.path.insert(0,'/tmp/opencode')
import sbc_proto as P, stage2_test as S, lzp_test as LZ
from auto import crc16_arc, stored_crc

def decode_at(data, hdr, start, lv):
    rdr=hdr['rdr']; rdr.pos=start; vlq=P.read_vlq(rdr); usize=hdr['files'][0]['sz']
    if vlq==0: return b''
    rc=P.RC(rdr); primary=rc.decode_large(vlq); nbits=rc.decode_int_maxbits(0x14)
    bits=P.copy_bits(rc,nbits); flag3=rc.u(3); x16=rc.u(0x10) if flag3==2 else None
    extra=P.Extra(rc,nsyms=20,inc=1,cap_freq=0x4000,cap_tot=0x4000)
    e1=extra.decode_extra(); e2=extra.decode_extra()
    recs,_=P.parse_filters(bits,nbits,usize)
    if e1==0: return None
    pay=data[len(data)-7-e1:len(data)-7]
    rc2=P.RC(P.ByteReader(pay,0)); b2=P.BitReader(pay,reverse=True)
    ctx=S.Ctx(); S.model_init(ctx,vlq,rc2); ctx.bits=b2
    pos=[0]*512; dst=bytearray(vlq)
    M=S.stage1(ctx,pos,vlq,dst); S.run_stage2(ctx,dst,vlq,M,pos)
    raw=P.ibwt(bytes(dst),primary)
    if flag3==1:
        nn,db=LZ.lzp_decode(raw,usize); raw=bytes(db[:nn])
    elif flag3==0: raw=P.flag3_expand(raw,0,usize)
    else: return None
    out=P.apply_filters(raw,recs,lv)
    return out[:usize] if usize else out

for f in ('image-m1','image-m2','image-m3','eng-m1','eng-m2','eng-m3','code-m1'):
    d=open(f'/workspace/packed_corpus/{f}.sbc','rb').read(); h=P.parse_header(d); sc=stored_crc(d)
    print('==',f,'pos',h['pos'],'x3',h['extra3'],'stored',hex(sc),'ps',P.payload_start(h))
    found=[]
    for off in range(-8,25):
        st=P.payload_start(h)+off
        if st<5 or st>=len(d): continue
        for lv in (0,1,2):
            try: o=decode_at(d,h,st,lv)
            except Exception as e: continue
            if o and (crc16_arc(o)^0xFFFF)==sc:
                found.append((off,lv,len(o)))
    print('  found',found[:10])
