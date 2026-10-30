import sys
sys.path.insert(0,'/workspace'); sys.path.insert(0,'/tmp/opencode')
import sbc_proto as P, stage2_test as S, lzp_test as LZ

def pipeline(name):
    data=open('/workspace/packed_corpus/'+name+'.sbc','rb').read()
    hdr=P.parse_header(data); rdr=hdr['rdr']; start=P.payload_start(hdr); rdr.pos=start
    vlq=P.read_vlq(rdr); usize=hdr['files'][0]['sz']
    rc=P.RC(rdr); primary=rc.decode_large(vlq); nbits=rc.decode_int_maxbits(0x14)
    bits_buf=P.copy_bits(rc,nbits); flag3=rc.u(3)
    if flag3==2: rc.u(0x10)
    ex=P.Extra(rc,nsyms=20,inc=1,cap_freq=0x4000,cap_tot=0x4000)
    e1=ex.decode_extra(); e2=ex.decode_extra()
    recs,used=P.parse_filters(bits_buf,nbits,usize)
    payload=data[len(data)-7-e1:len(data)-7]
    rc2=P.RC(P.ByteReader(payload,0)); bits=P.BitReader(payload,reverse=True)
    ctx=S.Ctx(); S.model_init(ctx,vlq,rc2); ctx.bits=bits
    pos=[0]*512; dst=bytearray(vlq); M=S.stage1(ctx,pos,vlq,dst)
    out=S.run_stage2(ctx,dst,vlq,M,pos); raw=P.ibwt(bytes(dst),primary)
    return raw,usize,recs,flag3,primary

def traced(src,outcap,lo,hi,window=66,skip=66,lbase=15,mark1=2,mark2=0xC5):
    MASK=LZ.MASK
    src=bytes(src); inlen=len(src); dst=bytearray(outcap+64); table=[0]*(MASK+1)
    ncopy=min(inlen,window+4); dst[0:ncopy]=src[0:ncopy]; esi=ncopy; ebx=ncopy; src_end=inlen
    if ebx>=src_end: return esi,dst
    ebp=0; nxt=0
    def h4(pos):
        word=int.from_bytes(bytes(dst[pos-4:pos]),'little'); return (((word>>0x13)^word)&MASK)
    def log(kind,*a):
        if lo<=esi<=hi: print("  out=%d in=%d ebp=%d"% (esi,ebx,ebp),kind,*a)
    def logs(kind,span,*a):
        if esi+span>=lo and esi<=hi: print("  out=%d in=%d ebp=%d"% (esi,ebx,ebp),kind,*a)
    def lit_hash():
        nonlocal ebx,esi
        p=esi-window; table[h4(p)]=p; logs("LITH",1,1,"ch",hex(src[ebx])); dst[esi]=src[ebx]; ebx+=1; esi+=1
    def lit_copy():
        nonlocal ebx,esi
        logs("LITC",1,1,"ch",hex(src[ebx])); dst[esi]=src[ebx]; ebx+=1; esi+=1
    def do_copy(length):
        nonlocal ebx,esi,ebp
        sp=table[h4(esi)]; logs("COPY",length,length,"sp",sp,"bytes",bytes(dst[sp:sp+min(length,12)]).hex())
        for _ in range(length):
            dst[esi:esi+4]=dst[sp:sp+4]; sp+=4; esi+=4
        ebx=nxt+1; ebp=skip
    def case0_zero():
        nonlocal ebx,esi,ebp
        p=esi-window; table[h4(p)]=p; dst[esi]=mark1; b2=esi+1; p2=b2-window; table[h4(p2)]=p2; dst[b2]=mark2
        log("ZERO",hex(mark1),hex(mark2)); esi=b2+1; ebx=nxt+1; ebp=0
    def marker_pending():
        nonlocal ebx,esi,ebp
        dst[esi]=mark1; b2=esi+1
        if ebp==1:
            ebp=0; p2=b2-window; table[h4(p2)]=p2; dst[b2]=mark2; esi=b2+1
        else:
            ebp-=2; dst[b2]=mark2; esi=b2+1
        log("PEND",hex(mark1),hex(mark2)); ebx=nxt+1
    step=0
    while True:
        step+=1
        c=src[ebx]
        if c==mark1 and ebx+2<src_end and src[ebx+1]==mark2:
            sel=src[ebx+2]; nxt=ebx+2
            if sel==0:
                if ebp==0: case0_zero()
                else: marker_pending()
            else:
                if sel&0x80:
                    if sel<=0xBF:
                        nxt=ebx+3; length=(sel&0x3F)+(lbase-1)+(src[ebx+3]<<6)
                    else:
                        nxt=ebx+4; length=((sel&0x3F)+(lbase-1)+(src[ebx+3]<<6)+(src[ebx+4]<<14))
                else:
                    length=(sel&0xFF)+(lbase-1)
                log("MATCH",length,"sel",hex(sel))
                do_copy(length)
        else:
            if ebp==0: lit_hash()
            else: ebp-=1; lit_copy()
        if src_end<=ebx: return esi,dst

if __name__=='__main__':
    name=sys.argv[1]
    raw,usize,recs,flag3,primary=pipeline(name)
    exp=open('/workspace/corpus/'+('pattern.bin' if name.startswith('pattern') else 'x'),'rb').read() if name.startswith('pattern') else None
    print("vlq/rawlen",len(raw),"usize",usize,"flag3",flag3,"recs",recs,"primary",primary)
    # compare LZSS output to expected at key positions
    n,dst=traced(raw,usize,150,290)
    got=bytes(dst[:n])
    print("outlen",n)
    if exp is not None:
        i=0
        while i<min(len(got),len(exp)) and got[i]==exp[i]: i+=1
        print("first diff",i)
        print("got",got[max(0,i-8):i+24].hex())
        print("exp",exp[max(0,i-8):i+24].hex())
