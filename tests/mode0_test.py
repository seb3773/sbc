import sys
sys.path.insert(0,'/workspace'); sys.path.insert(0,'/tmp/opencode')
import sbc_proto as P, stage2_test as S
from wtable import W
W=[x if x<0x80000000 else x-0x100000000 for x in W]

def mode0(src):
    n=len(src)
    if n<=0x23ff:
        return bytes(src)
    dst=bytearray(src)
    inp=0x200; outp=0x200; end=n
    s34=s38=s3c=s40=s44=s48=0
    state=0; pen=0; s20=0; s28=0
    while inp < end:
        bl=src[inp]
        if state:
            p=dst[outp-state]
            e=(p+bl)&0xff
            dst[outp]=e
            d=e-p
            if (d+0x17)&0xffffffff > 0x2e:
                pen+=5
                if pen>0x100:
                    s34=s38=s3c=s40=s44=s48=0
                    pen=0; state=0
            else:
                if pen>0: pen-=3
            inp+=1; outp+=1
        else:
            dst[outp]=bl
            s28=s20+1
            if s20>0x3fff:
                dst[outp:outp+(end-inp)]=src[inp:end]
                return bytes(dst)
            for off in (2,3,4,6,8,13):
                d=(bl-dst[outp-off])&0xff
                w=W[d]
                if off==2: s34+=w; 
                elif off==3: s38+=w
                elif off==4: s3c+=w
                elif off==6: s40+=w
                elif off==8: s44+=w
                else: s48+=w
            if s34>0x3e80: state=2
            if s38>0x3e80: state=3
            if s3c>0x3e80: state=4
            if s40>0x3e80: state=6
            if s44>0x3e80: state=8
            if s48>0x3e80: state=0xd
            s20=s28; inp+=1; outp+=1
    return bytes(dst)

def raw_for(name):
    data=open("/workspace/packed_corpus/"+name,"rb").read(); hdr=P.parse_header(data); rdr=hdr["rdr"]
    rdr.pos=P.payload_start(hdr); vlq=P.read_vlq(rdr); usize=hdr["files"][0]["sz"]
    rc=P.RC(rdr); prim=rc.decode_large(vlq); nb=rc.decode_int_maxbits(0x14); bits=P.copy_bits(rc,nb)
    f3=rc.u(3)
    if f3==2: rc.u(0x10)
    ex=P.Extra(rc,nsyms=20,inc=1,cap_freq=0x4000,cap_tot=0x4000); e1=ex.decode_extra(); e2=ex.decode_extra()
    payload=data[len(data)-7-e1:len(data)-7]
    rc2=P.RC(P.ByteReader(payload,0)); bitsb=P.BitReader(payload,reverse=True)
    ctx=S.Ctx(); S.model_init(ctx,vlq,rc2); ctx.bits=bitsb
    pos=[0]*512; dst=bytearray(vlq); M=S.stage1(ctx,pos,vlq,dst)
    S.REFDUMP=None; S.STORE_LOG=None
    out=S.run_stage2(ctx,dst,vlq,M,pos)
    L=bytes(dst); raw=P.ibwt(L,prim)
    return raw,f3,e1,e2,M,out

for name in ["biased-m1.sbc","zeros-m1.sbc"]:
    raw,f3,e1,e2,M,out=raw_for(name)
    print(name,"rawlen",len(raw),"f3",f3,"M",M,"out",out)
    if name.startswith("biased"):
        dec=mode0(raw)
        exp=open("/workspace/corpus/biased.bin","rb").read()
        d=next((i for i in range(min(len(dec),len(exp))) if dec[i]!=exp[i]),None)
        print("  mode0 len",len(dec),"match",dec==exp,"firstdiff",d, dec[d:d+16].hex() if d is not None else "", exp[d:d+16].hex() if d is not None else "")
        rawf=open("/tmp/opencode/raw_biased.bin","wb"); rawf.write(raw); rawf.close()
