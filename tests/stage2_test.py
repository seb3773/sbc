import sys, struct, os
DEBUG = False
REFDUMP = None
STORE_LOG = None
TRACE_LEN = None
DBG2 = int(os.environ.get("DBG2", "0"))
sys.path.insert(0, "/workspace")
import sbc_proto as P

T360 = [0,1,1,2,2,3,4,5,6,7,8,9,10,11,12,13,14,15,15,16,16,17,17,18,18,18,18,19,19,19,19,19]
T368 = T360[2:]
LOG2 = P.LOG2

from tables import ATAB, BTAB

APAR = [
    (10,3072,16384),(8,2048,16384),(4,1530,8192),(4,1024,8192),
    (4,786,8192),(4,512,8192),(3,384,4096),(3,320,4096),
    (3,256,4096),(3,192,4096),(3,160,2048),(3,144,2048),
    (2,128,2048),(2,128,2048),(2,112,1024),(2,112,1024),
    (1,112,1024),(1,112,1024),(1,96,1024),(1,96,1024),
]

def t3(i):
    if 0 <= i <= 30:
        return i + 1
    if -31 <= i < 0:
        return -i - 1
    return 0

def logmap(a):
    # returns the "log domain" value from 0x448fe0 mapping used in init/reinit/stage1
    a &= 0xffffffff
    if a <= 0x1ff:
        return LOG2[a]
    if a <= 0x3ffff:
        return LOG2[a >> 9] + 9
    return LOG2[(a >> 18) & 0x1ff] + 0x12


class Model:
    def __init__(self, rc, inc=1, cap_freq=0x4000, cap_tot=0x4000):
        self.rc = rc
        self.inc = inc
        self.cap_freq = cap_freq
        self.cap_tot = cap_tot
        self.freq = []
        self.total = 0
        self.cap = 0
        self.active = 0

    def resize(self, nsyms):
        nsyms &= 0xffffffff
        if nsyms > self.cap:
            self.freq = [1] * nsyms
            self.cap = nsyms
            self.active = nsyms
            self.total = nsyms
            return
        if self.active == nsyms:
            return
        if self.active < nsyms:
            while self.active < nsyms:
                self.total += self.freq[self.active]
                self.active += 1
        else:
            while self.active > nsyms:
                self.active -= 1
                self.total -= self.freq[self.active]

    def clear(self):
        self.total = 0
        for i in range(self.active):
            self.freq[i] = 1
            self.total += 1

    def set_freq(self, k, v):
        self.total -= self.freq[k]
        if v == 0:
            v = 1
        self.freq[k] = v
        self.total += v

    def add_freq(self, k, v):
        self.total += v
        self.freq[k] += v

    def rescale(self):
        while True:
            self.total = 0
            for i in range(self.active):
                f = self.freq[i]
                f -= f >> 1
                self.freq[i] = f
                self.total += f
            if self.total <= self.cap_tot:
                break

    def decode_sym(self):
        while self.total > self.cap_tot:
            self.rescale()
        v = self.rc.get(self.total)
        if v < self.freq[0]:
            sym = 0
            acc = 0
        else:
            sym = 1
            acc = 0
            while True:
                acc += self.freq[sym - 1]
                v -= self.freq[sym - 1]
                if sym < len(self.freq) and self.freq[sym] <= v:
                    sym += 1
                else:
                    break
            if sym >= self.active:
                sym = self.active - 1
        self.rc.decode(acc, self.freq[sym])
        self.total += self.inc
        self.freq[sym] += self.inc
        if self.freq[sym] > self.cap_freq:
            self.rescale()
        return sym


class Ctx:
    def __init__(self):
        self.nsyms = 0
        self.map = [0] * 256          # ctx+4
        self.c404 = [0] * 256         # ctx+0x404
        self.rc = None
        self.bits = None
        self.A = []
        self.B = []
        self.E = None


def model_init(ctx, n, rc):
    if n <= 0:
        return 1
    edx = n >> 5
    if edx > 0x1000:
        edx = 0x1000
    ctx.rc = rc
    ctx.map = [edx] * 256
    ctx.c404 = [0x10] * 256
    if n <= 0x1ff:
        nsyms = LOG2[n] + 3
    else:
        nsyms = logmap(n) + 3
    ctx.nsyms = nsyms
    ctx.E = Model(rc, inc=10, cap_freq=64, cap_tot=1024)
    ctx.E.resize(nsyms)
    ctx.E.clear()
    ctx.A = []
    for idx in range(20):
        inc, cf, ct = APAR[idx]
        m = Model(rc, inc=inc, cap_freq=cf, cap_tot=ct)
        ctx.A.append(m)
    for idx in range(20):
        m = ctx.A[idx]
        m.resize(ctx.nsyms + 1)
        m.set_freq(ctx.nsyms, 1)
        m.set_freq(ctx.nsyms - 1, 1)
        base = 28 * idx
        for k in range(ctx.nsyms - 2, -1, -1):
            m.set_freq(k, ATAB[base + k] + 1)
    ctx.B = []
    for idx in range(25):
        ctx.B.append(Model(rc, inc=1, cap_freq=0x400, cap_tot=0x4000))
    off = 184
    for idx in range(24, -1, -1):
        if idx > 2:
            ns = 8
        elif idx == 2:
            ns = 4
        else:
            ns = 2
        m = ctx.B[idx]
        m.resize(ns)
        for k in range(ns - 1, -1, -1):
            off -= 1
            m.set_freq(k, BTAB[off] + 1)
    return 0


def model_index(state):
    if state <= 1:
        return T360[state]
    a = state - 2
    return T368[logmap(a)]


def reinit(ctx, param):
    if param <= 0:
        nsyms = param + 1
        threshold = param + 1
    else:
        edx = param - 1
        if edx <= 1:
            nsyms = edx + 1
            threshold = edx + 1
        else:
            nsyms = logmap(edx - 2) + 3
            threshold = (1 << logmap(edx)) + 1
    if ctx.nsyms == nsyms:
        return threshold
    ctx.nsyms = nsyms
    addval = None
    if threshold <= 2:
        addval = 0x200 << (2 - threshold)
    for idx in range(20):
        m = ctx.A[idx]
        m.resize(ctx.nsyms + 1)
        if ctx.nsyms <= 0x10:
            m.rescale()
        if addval is not None:
            m.add_freq(ctx.nsyms, addval)
    return threshold


def stage1(ctx, pos, n, dst):
    for k in range(256):
        pos[k] = k
    M = 1
    if n == 1:
        pass
    elif n <= 0xff:
        M = ctx.rc.u(n) + 1
    else:
        if ctx.bits.peek_bit():
            M = ctx.rc.u(0xff) + 1
        else:
            M = 0x100
    E = ctx.E
    cum = 0
    i = 0
    while True:
        if M <= i:
            break
        if i > 0xfe:
            # 0x427e57: symbol = pos[255] (table 0x3fc after shifting)
            slot = 0x3fc // 4 + (0x34 - 0x34)  # placeholder
            # Actually at i>0xfe, pos array has been overwritten; use pos[255]
            idx = 0
            slot = 255
            sym = pos[slot]
            pos[slot] = pos[255]  # unclear; not used for n<=255
        else:
            idx = ctx.rc.u(0x100 - i)
            slot = i + idx
            sym = pos[slot]
            pos[slot] = pos[i]
        if i == 0:
            newpos = 0
            cum = 1
        else:
            remain = n - cum
            if remain <= 1:
                E.resize(remain)
                k = E.decode_sym()
            else:
                a = remain - 2
                E.resize(logmap(a) + 3)
                k = E.decode_sym()
            if k <= 1:
                delta = k
            else:
                esi = k - 2
                nbits = 1 if esi == 0 else esi
                lo = ctx.bits.getbits(nbits)
                delta = (((1 if esi else 0) << (esi & 31)) | lo) + 2
            newpos = cum + delta
            cum = newpos + 1
        dst[newpos] = sym
        pos[i] = newpos
        i += 1
    pos[M] = n
    return M


def stage2(ctx, dst, n, pos):
    M = pos[0]  # placeholder; real M passed separately
    pass


def run_stage2(ctx, dst, n, M, pos):
    out = 0
    threshold = 0x2000000
    pos = list(pos)
    it = 0

    def flush():
        nonlocal M
        EM = M
        esi = M - 1
        if esi <= 0:
            return True
        if ctx.rc.err:
            return True
        for edx in range(1, EM):
            pos[edx - 1] = pos[edx]
        M = esi
        pos[M] = n
        return False

    while True:
        it += 1
        global _IT
        _IT = it
        if it > 200000:
            return None
        d1 = pos[1]
        if not (threshold < n - d1):
            if n > d1:
                threshold = reinit(ctx, n - d1 - 1)
                d1 = pos[1]
        # FILL
        prev = dst[pos[0]] & 0xff
        if DEBUG and it<=25: print("IT M=%d p0=%d p1=%d out=%d prev=%d p1out=%d" % (M,pos[0],pos[1],out,prev,pos[1]), file=sys.stderr)
        gap = pos[1] - pos[0]
        avail = n - out
        if gap > avail:
            gap = avail
        if gap > 0:
            for j in range(gap):
                dst[out + j] = prev
            out += gap
        if out >= n:
            if flush():
                return out
            continue
        # DEC
        prevsym = dst[out - 1] & 0xff
        state = ctx.map[prevsym]
        aidx = model_index(state)
        t = ctx.A[aidx].decode_sym()
        if DEBUG: print("  DEC t=%d ctx0=%d aidx=%d prev=%d" % (t,ctx.nsyms,aidx,prevsym), file=sys.stderr)
        if t == ctx.nsyms:
            esi = 0x2000000
        else:
            esi = t
            if t > 1:
                if t <= 5:
                    idx = t - 2
                    bv = ctx.B[idx].decode_sym()
                    s = (1 if idx != 0 else 0) << (idx & 31)
                    esi = (bv | s) + 2
                else:
                    idx = t - 2
                    bv = ctx.B[idx].decode_sym()
                    # LEN_BIG: esi = (B<<(t-5) | 1<<(t-2) | extrabits) + 2
                    esi = bv
                    # get extrabits via bits.getbits at 0x4284c7 / 0x42aeb0
                    edi = t - 5
                    if edi > 0x18:
                        lo = ctx.bits.getbits(edi)
                        esi = (bv << (t - 5)) | (1 << (t - 2)) | lo
                    else:
                        # inline bitfetch of edi bits from bits object
                        lo = ctx.bits.getbits(edi) if edi else 0
                        esi = (bv << (t - 5)) | (1 << (t - 2)) | lo
                    esi = (esi + 2) & 0xffffffff
            # STORE adapt
            c404 = ctx.c404[prevsym]
            st = ctx.map[prevsym]
            if c404 > 4:
                h = c404 >> 1
                st = (esi * h + st) // (h + 1)
            else:
                if t > aidx + 4:
                    st = (esi + (t - aidx - 1) * st) // (t - aidx)
                elif aidx > t + 3:
                    st = (esi + st) >> 1
                elif aidx > t + 2:
                    st = (11 * esi + 21 * st) >> 5
                elif aidx > t or t > aidx + 2:
                    st = (esi + 3 * st) >> 2
                else:
                    st = (26 * st + 6 * esi) >> 5
            ctx.map[prevsym] = st
            ctx.c404[prevsym] = (c404 + t3(aidx - t)) >> 1
        if DEBUG: print("  LEN esi=%d" % esi, file=sys.stderr)
        if TRACE_LEN is not None and len(STORE_LOG) >= TRACE_LEN-6 and len(STORE_LOG) <= TRACE_LEN:
            print("CLEN stores=%d it=%d t=%s esi=%d prevsym=%d aidx=%d p0=%d p1=%d p2=%d" % (len(STORE_LOG),it,t if 't' in dir() else -1,esi,prevsym,aidx,pos[0],pos[1],pos[2]), file=sys.stderr)
        # AT2BD
        if esi >= n:
            if flush():
                return out
            continue
        esi += 1
        eax = pos[1]
        edx = pos[2]
        pos[0] = eax
        ebx = esi + eax
        k = 1
        if DEBUG and it<=3: print("   A2B eax=%d edx=%d esi=%d ebx=%d p2=%d" % (eax,edx,esi,ebx,pos[2]), file=sys.stderr)
        if DBG2 and it <= DBG2:
            print("   A2B it=%d esi=%d eax=%d edx=%d ebx=%d n=%d out=%d pos=%s" % (it,esi,eax,edx,ebx,n,out,pos[:26]), file=sys.stderr)
        if edx > ebx:
            pos[k] = ebx
        else:
            j = 2
            while True:
                if DBG2 and it <= DBG2 and j < 30:
                    print("    walk k=%d j=%d eax=%d edx=%d esi=%d" % (k,j,eax,edx,esi), file=sys.stderr)
                pos[k] = edx
                gap = edx - eax
                if j + 1 >= len(pos):
                    print("RUNAWAY it=%d esi=%d eax=%d edx=%d j=%d M=%d n=%d pos=%s" % (it,esi,eax,edx,j,M,n,pos[:min(40,len(pos))]), file=sys.stderr)
                    raise SystemExit(3)
                edx_next = pos[j + 1]
                esi -= (gap - 1)
                eax = pos[j]
                k = j
                ebx = esi + eax
                if not (ebx >= edx_next):
                    pos[k] = ebx
                    break
                edx = edx_next
                j += 1
        dst[ebx] = prev
        if STORE_LOG is not None:
            STORE_LOG.append((ebx, prev))
        if REFDUMP is not None and ebx < len(REFDUMP) and dst[ebx] != REFDUMP[ebx]:
            print("FIRSTDIFF it=%d ebx=%d got=%d ref=%d M=%d out=%d pos=%s" % (it,ebx,prev,REFDUMP[ebx],M,out,pos[:min(30,len(pos))]), file=sys.stderr)
            raise SystemExit(4)
        if DEBUG: print("  STORE pos=%d val=%d M=%d p0=%d p1=%d" % (ebx,prev,M,pos[0],pos[1]), file=sys.stderr)
    return out


def decode_zeros():
    data = open("/workspace/packed_corpus/zeros-m1.sbc", "rb").read()
    hdr = P.parse_header(data)
    rdr = hdr["rdr"]
    rdr.pos = P.payload_start(hdr)
    vlq = P.read_vlq(rdr)
    rc = P.RC(rdr)
    primary = rc.decode_large(vlq)
    nbits = rc.decode_int_maxbits(0x14)
    bits_copy = P.copy_bits(rc, nbits)
    flag3 = rc.u(3)
    extra16 = rc.u(0x10) if flag3 == 2 else None
    win = P.window_size(hdr["method"])
    nsyms = P.size_to_nsyms(win)
    extra = P.Extra(rc, nsyms=nsyms, inc=1, cap_freq=0x4000, cap_tot=0x4000)
    e1 = extra.decode_extra()
    e2 = extra.decode_extra()
    rc_pos = rdr.pos
    n = vlq
    payload = data[rc_pos:len(data) - 7]
    print("vlq", vlq, "rc_pos", rc_pos, "payload", len(payload), "e1", e1, "e2", e2, "primary", primary)
    rc2 = P.RC(P.ByteReader(payload, 1))
    bits = P.BitReader(payload, reverse=True)
    ctx = Ctx()
    model_init(ctx, n, rc2)
    ctx.bits = bits
    pos = [0] * 512
    dst = bytearray(n)
    M = stage1(ctx, pos, n, dst)
    print("M", M, "pos", pos[:M + 1])
    print("dst seeds", [(i, dst[i]) for i in [pos[k] for k in range(M)]][:20])
    out = run_stage2(ctx, dst, n, M, pos)
    print("out", out)
    exp = open("/tmp/opencode/Ldump.bin", "rb").read()
    print("L len", len(exp), "match", bytes(dst) == exp)
    if bytes(dst) != exp:
        for i in range(min(len(exp), n)):
            if dst[i] != exp[i]:
                print("first diff at", i, "got", dst[i], "exp", exp[i])
                break
        print("got", bytes(dst[:130]).hex())
        print("exp", exp[:130].hex())
    return dst, exp


if __name__ == "__main__":
    decode_zeros()
