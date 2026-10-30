import sys
sys.path.insert(0,'/tmp/opencode'); sys.path.insert(0,'/workspace')
import sbc_proto as P
import stage2_test as S

data = open("/workspace/packed_corpus/biased-m1.sbc","rb").read()
hdr = P.parse_header(data)
rdr = hdr["rdr"]
rdr.pos = P.payload_start(hdr)
vlq = P.read_vlq(rdr)
rc = P.RC(rdr)
primary = rc.decode_large(vlq)
nbits = rc.decode_int_maxbits(0x14)
P.copy_bits(rc,nbits)
flag3 = rc.u(3)
win = P.window_size(hdr["method"])
nsyms = P.size_to_nsyms(win)
extra = P.Extra(rc, nsyms=nsyms, inc=1, cap_freq=0x4000, cap_tot=0x4000)
e1 = extra.decode_extra(); e2 = extra.decode_extra()
n = vlq
pstart = len(data)-7-45795
payload = data[pstart:len(data)-7]
print("n",n,"prim",primary,"pstart",pstart,"payload",len(payload),"rc_pos",rdr.pos)
rc2 = P.RC(P.ByteReader(payload,0))
bits = P.BitReader(payload, reverse=True)
ctx = S.Ctx(); S.model_init(ctx,n,rc2); ctx.bits=bits
pos=[0]*512; dst=bytearray(n)
M=S.stage1(ctx,pos,n,dst)
print("M",M,"pos",pos[:M+1])
S.STORE_LOG = []
S.REFDUMP = open("/tmp/opencode/Ldump_biased.bin","rb").read()
out=S.run_stage2(ctx,dst,n,M,pos)
print("out",out)
