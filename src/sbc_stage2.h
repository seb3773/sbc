#ifndef SBC_STAGE2_H
#define SBC_STAGE2_H

#include "sbc_tables.h"

static const int SBC_T360[32] = {
    0, 1, 1, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
    14, 15, 15, 16, 16, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 19
};

static const uint32_t SBC_APAR[20][3] = {
    {10, 3072, 16384}, {8, 2048, 16384}, {4, 1530, 8192}, {4, 1024, 8192},
    {4, 786, 8192}, {4, 512, 8192}, {3, 384, 4096}, {3, 320, 4096},
    {3, 256, 4096}, {3, 192, 4096}, {3, 160, 2048}, {3, 144, 2048},
    {2, 128, 2048}, {2, 128, 2048}, {2, 112, 1024}, {2, 112, 1024},
    {1, 112, 1024}, {1, 112, 1024}, {1, 96, 1024}, {1, 96, 1024}
};

static uint32_t sbc_log2_tab[8192];
static int sbc_log2_ready;

static void sbc_init_log2(void)
{
    uint32_t edx = 0, esi = 0, ebx = 1;
    if (sbc_log2_ready)
        return;
    sbc_log2_ready = 1;
    while (edx < 8192) {
        ebx += ebx;
        while (edx < ebx && edx < 8192) {
            sbc_log2_tab[edx] = esi;
            edx++;
        }
        esi++;
    }
}

static uint32_t sbc_logmap(uint32_t a)
{
    a &= 0xFFFFFFFFu;
    if (a <= 0x1FFu)
        return sbc_log2_tab[a];
    if (a <= 0x3FFFFu)
        return sbc_log2_tab[a >> 9] + 9u;
    return sbc_log2_tab[(a >> 18) & 0x1FFu] + 0x12u;
}

/* ---- reverse MSB bit reader (0x42aeb0) ---- */

typedef struct {
    const uint8_t *data;
    size_t len;
    long cur;
    uint32_t buf;
    uint32_t avail;
} SbcBits;

static void sbc_bits_init(SbcBits *b, const uint8_t *data, size_t len)
{
    b->data = data;
    b->len = len;
    b->cur = (long)len - 1;
    b->buf = 0;
    b->avail = 0;
}

static int sbc_bits_next(SbcBits *b)
{
    if (b->cur < 0)
        return -1;
    return b->data[b->cur--];
}

static uint32_t sbc_bits_getbits(SbcBits *b, uint32_t nbits)
{
    uint32_t acc = 0, mask;
    int v;
    while (nbits > 7) {
        if (b->avail <= 7) {
            v = sbc_bits_next(b);
            if (v < 0)
                break;
            b->buf = ((b->buf << 8) | (uint32_t)v) & 0xFFFFFFFFu;
            b->avail += 8;
        }
        if (b->avail > 7) {
            b->avail -= 8;
            acc = ((acc << 8) | ((b->buf >> b->avail) & 0xFFu)) & 0xFFFFFFFFu;
            nbits -= 8;
        } else {
            break;
        }
    }
    if (nbits > b->avail) {
        while (nbits > b->avail) {
            v = sbc_bits_next(b);
            if (v < 0)
                return (acc << nbits) & 0xFFFFFFFFu;
            b->buf = ((b->buf << 8) | (uint32_t)v) & 0xFFFFFFFFu;
            b->avail += 8;
        }
    }
    b->avail -= nbits;
    mask = (nbits < 32) ? ((1u << nbits) - 1u) : 0xFFFFFFFFu;
    return ((acc << nbits) | ((b->buf >> b->avail) & mask)) & 0xFFFFFFFFu;
}

static uint32_t sbc_bits_peek(SbcBits *b)
{
    int v;
    if (b->avail == 0) {
        v = sbc_bits_next(b);
        if (v < 0)
            return 0;
        b->buf = (uint32_t)v;
        b->avail = 8;
    }
    b->avail -= 1;
    return (b->buf >> b->avail) & 1u;
}

/* ---- adaptive frequency model ---- */

typedef struct {
    SbcRC *rc;
    uint32_t *freq;
    uint32_t total;
    uint32_t cap;
    uint32_t active;
    uint32_t inc;
    uint32_t cap_freq;
    uint32_t cap_tot;
} SbcModel;

static int sbc_model_init(SbcModel *m, SbcRC *rc, uint32_t inc,
                          uint32_t cap_freq, uint32_t cap_tot)
{
    memset(m, 0, sizeof(*m));
    m->rc = rc;
    m->inc = inc;
    m->cap_freq = cap_freq;
    m->cap_tot = cap_tot;
    return 0;
}

static void sbc_model_free(SbcModel *m)
{
    free(m->freq);
    m->freq = NULL;
}

static void sbc_model_resize(SbcModel *m, uint32_t nsyms)
{
    uint32_t i;
    if (nsyms > m->cap) {
        free(m->freq);
        m->freq = (uint32_t *)malloc((nsyms ? nsyms : 1) * sizeof(uint32_t));
        if (!m->freq)
            return;
        for (i = 0; i < nsyms; i++)
            m->freq[i] = 1;
        m->cap = nsyms;
        m->active = nsyms;
        m->total = nsyms;
        return;
    }
    if (m->active == nsyms)
        return;
    if (m->active < nsyms) {
        while (m->active < nsyms) {
            m->total += m->freq[m->active];
            m->active++;
        }
    } else {
        while (m->active > nsyms) {
            m->active--;
            m->total -= m->freq[m->active];
        }
    }
}

static void sbc_model_clear(SbcModel *m)
{
    uint32_t i;
    m->total = 0;
    for (i = 0; i < m->active; i++) {
        m->freq[i] = 1;
        m->total += 1;
    }
}

static void sbc_model_setf(SbcModel *m, uint32_t k, uint32_t v)
{
    m->total -= m->freq[k];
    if (v == 0)
        v = 1;
    m->freq[k] = v;
    m->total += v;
}

static void sbc_model_addf(SbcModel *m, uint32_t k, uint32_t v)
{
    m->total += v;
    m->freq[k] += v;
}

static void sbc_model_rescale(SbcModel *m)
{
    uint32_t i, f;
    for (;;) {
        m->total = 0;
        for (i = 0; i < m->active; i++) {
            f = m->freq[i];
            f -= f >> 1;
            m->freq[i] = f;
            m->total += f;
        }
        if (m->total <= m->cap_tot)
            break;
    }
}

static uint32_t sbc_model_decode_sym(SbcModel *m)
{
    uint32_t v, sym, acc;
    while (m->total > m->cap_tot)
        sbc_model_rescale(m);
    v = sbc_rc_get(m->rc, m->total);
    if (v < m->freq[0]) {
        sym = 0;
        acc = 0;
    } else {
        sym = 1;
        acc = 0;
        for (;;) {
            acc += m->freq[sym - 1];
            v -= m->freq[sym - 1];
            if (sym < m->cap && m->freq[sym] <= v)
                sym++;
            else
                break;
        }
        if (sym >= m->active)
            sym = m->active - 1;
    }
    sbc_rc_decode(m->rc, acc, m->freq[sym]);
    if (sbc_shadow && sbc_shadow->sym)
        sbc_shadow->sym(sbc_shadow->ctx, m->total, acc, m->freq[sym]);
    m->total += m->inc;
    m->freq[sym] += m->inc;
    if (m->freq[sym] > m->cap_freq)
        sbc_model_rescale(m);
    return sym;
}

/* ---- stage 2 context ---- */

typedef struct {
    uint32_t nsyms;
    uint32_t map[256];
    uint32_t c404[256];
    SbcRC *rc;
    SbcBits *bits;
    SbcModel A[20];
    SbcModel B[25];
    SbcModel E;
} SbcCtx;

static int sbc_ctx_init(SbcCtx *ctx, uint32_t n, SbcRC *rc)
{
    int i, j, base;
    uint32_t edx, nsyms;
    if (n == 0)
        return -1;
    sbc_init_log2();
    edx = n >> 5;
    if (edx > 0x1000)
        edx = 0x1000;
    ctx->rc = rc;
    ctx->bits = NULL;
    for (i = 0; i < 256; i++) {
        ctx->map[i] = edx;
        ctx->c404[i] = 0x10;
    }
    if (n <= 0xFFu)
        nsyms = sbc_log2_tab[n] + 3;
    else
        nsyms = sbc_logmap(n) + 3;
    ctx->nsyms = nsyms;
    sbc_model_init(&ctx->E, rc, 10, 64, 1024);
    sbc_model_resize(&ctx->E, nsyms);
    sbc_model_clear(&ctx->E);
    for (i = 0; i < 20; i++)
        sbc_model_init(&ctx->A[i], rc, SBC_APAR[i][0], SBC_APAR[i][1], SBC_APAR[i][2]);
    for (i = 0; i < 20; i++) {
        SbcModel *m = &ctx->A[i];
        sbc_model_resize(m, nsyms + 1);
        sbc_model_setf(m, nsyms, 1);
        sbc_model_setf(m, nsyms - 1, 1);
        base = 28 * i;
        for (j = (int)nsyms - 2; j >= 0; j--)
            sbc_model_setf(m, (uint32_t)j, (uint32_t)(SBC_ATAB[base + j] + 1));
    }
    for (i = 0; i < 25; i++)
        sbc_model_init(&ctx->B[i], rc, 1, 0x400, 0x4000);
    {
        int off = 184;
        for (i = 24; i >= 0; i--) {
            uint32_t ns = (i > 2) ? 8u : (i == 2 ? 4u : 2u);
            sbc_model_resize(&ctx->B[i], ns);
            for (j = (int)ns - 1; j >= 0; j--) {
                off--;
                sbc_model_setf(&ctx->B[i], (uint32_t)j, (uint32_t)(SBC_BTAB[off] + 1));
            }
        }
    }
    return 0;
}

static void sbc_ctx_free(SbcCtx *ctx)
{
    int i;
    sbc_model_free(&ctx->E);
    for (i = 0; i < 20; i++)
        sbc_model_free(&ctx->A[i]);
    for (i = 0; i < 25; i++)
        sbc_model_free(&ctx->B[i]);
}

static int sbc_t3(int i)
{
    if (i >= 0 && i <= 30)
        return i + 1;
    if (i >= -31 && i < 0)
        return -i - 1;
    return 0;
}

static uint32_t sbc_model_index(uint32_t state)
{
    uint32_t a;
    if (state <= 1)
        return (uint32_t)SBC_T360[state];
    a = state - 2;
    return (uint32_t)SBC_T360[2 + sbc_logmap(a)];
}

static uint32_t sbc_reinit(SbcCtx *ctx, uint32_t param)
{
    uint32_t nsyms, threshold, addval = 0;
    int addval_set = 0, i;
    if (param == 0) {
        nsyms = 1;
        threshold = 1;
    } else {
        uint32_t edx = param - 1;
        if (edx <= 1) {
            nsyms = edx + 1;
            threshold = edx + 1;
        } else {
            nsyms = sbc_logmap(edx - 2) + 3;
            threshold = (1u << sbc_logmap(edx)) + 1;
        }
    }
    if (ctx->nsyms == nsyms)
        return threshold;
    ctx->nsyms = nsyms;
    if (threshold <= 2) {
        addval_set = 1;
        addval = 0x200u << (2 - threshold);
    }
    for (i = 0; i < 20; i++) {
        SbcModel *m = &ctx->A[i];
        sbc_model_resize(m, nsyms + 1);
        if (nsyms <= 0x10)
            sbc_model_rescale(m);
        if (addval_set)
            sbc_model_addf(m, nsyms, addval);
    }
    return threshold;
}

/* SBC_TRACE=1 logs every coding decision the stream carries.  The decoder is
 * reading the vendor's own choices, so the trace is a decision log of the
 * encoder we have to mirror (keep it to small blocks). */
static int sbc_trace_on(void)
{
    static int v = -1;
    if (v < 0)
        v = getenv("SBC_TRACE") != NULL;
    return v;
}

static uint32_t sbc_stage1(SbcCtx *ctx, uint32_t *pos, uint32_t n, uint8_t *dst)
{
    int k;
    uint32_t M = 1, cum = 0, i = 0;
    int trace = sbc_trace_on();
    for (k = 0; k < 256; k++)
        pos[k] = (uint32_t)k;
    if (n == 1) {
        /* M stays 1 */
    } else if (n <= 0xFF) {
        M = sbc_u(ctx->rc, n) + 1;
    } else {
        uint32_t pk = sbc_bits_peek(ctx->bits);
        if (sbc_shadow && sbc_shadow->bits)
            sbc_shadow->bits(sbc_shadow->ctx, 1, pk);
        if (pk)
            M = sbc_u(ctx->rc, 0xFF) + 1;
        else
            M = 0x100;
    }
    if (trace)
        fprintf(stderr, "S1 n=%u M=%u\n", n, M);
    while (M > i) {
        uint32_t idx, slot, sym, newpos;
        if (i > 0xFE) {
            idx = 0;
            slot = 255;
            sym = pos[slot];
            pos[slot] = pos[255];
        } else {
            idx = sbc_u(ctx->rc, 0x100 - i);
            slot = i + idx;
            sym = pos[slot];
            pos[slot] = pos[i];
        }
        if (i == 0) {
            newpos = 0;
            cum = 1;
            if (trace)
                fprintf(stderr, "S1 i=0 idx=%u sym=%u newpos=0\n", idx, sym);
        } else {
            uint32_t remain = n - cum, kk;
            if (remain <= 1) {
                sbc_model_resize(&ctx->E, remain);
                kk = sbc_model_decode_sym(&ctx->E);
            } else {
                uint32_t a = remain - 2;
                sbc_model_resize(&ctx->E, sbc_logmap(a) + 3);
                kk = sbc_model_decode_sym(&ctx->E);
            }
            if (kk <= 1) {
                newpos = cum + kk;
            } else {
                uint32_t esi = kk - 2;
                uint32_t nbits = (esi == 0) ? 1 : esi;
                uint32_t lo = sbc_bits_getbits(ctx->bits, nbits);
                uint32_t delta = (((esi ? 1u : 0u) << (esi & 31)) | lo) + 2;
                if (sbc_shadow && sbc_shadow->bits)
                    sbc_shadow->bits(sbc_shadow->ctx, nbits, lo);
                newpos = cum + delta;
                if (trace)
                    fprintf(stderr, "S1 i=%u kk=%u esi=%u nbits=%u lo=%u "
                                    "bitpos=%ld cur=%ld avail=%u buf=%02x "
                                    "len=%zu\n",
                            i, kk, esi, nbits, lo,
                            ctx->bits ? (long)(ctx->bits->len - 1 -
                                               (size_t)ctx->bits->cur) * 8 -
                                        (long)ctx->bits->avail : -1,
                            ctx->bits ? ctx->bits->cur : -1,
                            ctx->bits ? ctx->bits->avail : 0,
                            ctx->bits ? (unsigned)(ctx->bits->buf & 0xFFu) : 0,
                            ctx->bits ? ctx->bits->len : 0);
            }
            cum = newpos + 1;
            if (trace)
                fprintf(stderr, "S1 i=%u idx=%u sym=%u newpos=%u cum=%u\n",
                        i, idx, sym, newpos, cum);
        }
        if (newpos >= n)
            return 0;
        dst[newpos] = (uint8_t)sym;
        pos[i] = newpos;
        i++;
    }
    pos[M] = n;
    if (trace) {
        uint32_t q;
        fprintf(stderr, "S1 done M=%u pos[0..%u]=", M, M < 8 ? M : 8);
        for (q = 0; q <= M && q < 9; q++)
            fprintf(stderr, " %u", pos[q]);
        fprintf(stderr, "\n");
    }
    return M;
}

static long sbc_run_stage2(SbcCtx *ctx, uint8_t *dst, uint32_t n,
                           uint32_t M, uint32_t *pos)
{
    uint32_t out = 0, threshold = 0x2000000u;
    int it = 0, trace = sbc_trace_on();
    /* Safety net only: a legit block needs at most a few iterations per output
     * byte, but a desynced stream can loop for ever. */
    long itcap = 200000L + 8L * (long)n;
    (void)M;
    for (;;) {
        int64_t nd, gap;
        uint32_t d1, prev, prevsym, state, aidx, t, esi, c404, st, h;
        int j, k;
        it++;
        if ((long)it > itcap)
            return -1;
        d1 = pos[1];
        nd = (int64_t)n - (int64_t)d1;
        if (!((int64_t)threshold < nd)) {
            if ((int64_t)n > (int64_t)d1) {
                threshold = sbc_reinit(ctx, (uint32_t)(n - d1 - 1));
                d1 = pos[1];
            }
        }
        prev = dst[pos[0]];
        gap = (int64_t)pos[1] - (int64_t)pos[0];
        if (gap > (int64_t)(n - out))
            gap = (int64_t)(n - out);
        if (gap > 0) {
            uint32_t jj;
            for (jj = 0; jj < (uint32_t)gap; jj++)
                dst[out + jj] = (uint8_t)prev;
            out += (uint32_t)gap;
        }
        if (trace)
            fprintf(stderr, "S2 it=%d out=%u d1=%u gap=%d prev=%u p0=%u p2=%u M=%u\n",
                    it, out, d1, (int)gap, prev, pos[0], pos[2], M);
        if (out >= n) {
            if (M <= 1 || ctx->rc->err)
                return (long)out;
            {
                uint32_t edx;
                for (edx = 1; edx < M; edx++)
                    pos[edx - 1] = pos[edx];
            }
            M = M - 1;
            pos[M] = n;
            continue;
        }
        prevsym = out ? dst[out - 1] : 0;
        state = ctx->map[prevsym];
        aidx = sbc_model_index(state);
        t = sbc_model_decode_sym(&ctx->A[aidx]);
        if (trace)
            fprintf(stderr, "S2 sym=%u aidx=%u t=%u\n", prevsym, aidx, t);
        if (t == ctx->nsyms) {
            esi = 0x2000000u;
        } else {
            esi = t;
            if (t > 1) {
                if (t <= 5) {
                    uint32_t idx = t - 2;
                    uint32_t bv = sbc_model_decode_sym(&ctx->B[idx]);
                    uint32_t s = (idx ? 1u : 0u) << (idx & 31);
                    esi = (bv | s) + 2;
                } else {
                    uint32_t idx = t - 2;
                    uint32_t bv = sbc_model_decode_sym(&ctx->B[idx]);
                    uint32_t edi = t - 5;
                    uint32_t lo = sbc_bits_getbits(ctx->bits, edi);
                    esi = ((bv << (t - 5)) | (1u << (t - 2)) | lo) + 2;
                    if (sbc_shadow && sbc_shadow->bits)
                        sbc_shadow->bits(sbc_shadow->ctx, edi, lo);
                }
            }
            c404 = ctx->c404[prevsym];
            st = ctx->map[prevsym];
            if (c404 > 4) {
                h = c404 >> 1;
                st = (esi * h + st) / (h + 1);
            } else {
                if (t > aidx + 4)
                    st = (esi + (t - aidx - 1) * st) / (t - aidx);
                else if (aidx > t + 3)
                    st = (esi + st) >> 1;
                else if (aidx > t + 2)
                    st = (11 * esi + 21 * st) >> 5;
                else if (aidx > t || t > aidx + 2)
                    st = (esi + 3 * st) >> 2;
                else
                    st = (26 * st + 6 * esi) >> 5;
            }
            ctx->map[prevsym] = st;
            ctx->c404[prevsym] = (c404 + (uint32_t)sbc_t3((int)aidx - (int)t)) >> 1;
        }
        if (trace)
            fprintf(stderr, "S2 esi=%u (n=%u)\n", esi, n);
        if (esi >= n) {
            if (M <= 1 || ctx->rc->err)
                return (long)out;
            {
                uint32_t edx;
                for (edx = 1; edx < M; edx++)
                    pos[edx - 1] = pos[edx];
            }
            M = M - 1;
            pos[M] = n;
            continue;
        }
        esi += 1;
        {
            uint32_t eax = pos[1];
            uint32_t edx = pos[2];
            uint32_t ebx;
            pos[0] = eax;
            ebx = esi + eax;
            k = 1;
            if (edx > ebx) {
                pos[k] = ebx;
            } else {
                j = 2;
                for (;;) {
                    uint32_t g2 = edx - eax;
                    uint32_t edx_next;
                    pos[k] = edx;
                    if (j + 1 >= 512)
                        return -1;
                    edx_next = pos[j + 1];
                    esi -= (g2 - 1);
                    eax = pos[j];
                    k = j;
                    ebx = esi + eax;
                    if (!(ebx >= edx_next)) {
                        pos[k] = ebx;
                        break;
                    }
                    edx = edx_next;
                    j++;
                }
            }
            if (ebx >= n)
                return -1;
            dst[ebx] = (uint8_t)prev;
        if (trace)
            fprintf(stderr, "S2 copy to %u (run %u) np0=%u np1=%u np2=%u\n",
                    ebx, ebx - eax, pos[0], pos[1], pos[2]);
        }
    }
}

/* ---- mode 0 adaptive delta filter (0x424150) ---- */

static int sbc_mode0_w[256];
static int sbc_mode0_ready;

static void sbc_mode0_init_w(void)
{
    static const int cnt[5] = { 2, 2, 4, 8, 112 };
    /* -64, not -256: the init arrays live at 0x45e660/0x45e674 in sbc.exe
     * ([2,2,4,8,112] counts against [15,7,3,1,-64] values).  The deeper
     * penalty decays four times slower, which is what makes the vendor engage
     * lag 3 at byte 1742 of image7.raw where the old value kept the state at
     * 0 for another few hundred bytes (and why our decoder failed on that
     * archive while every corpus block still matched). */
    static const int vals[5] = { 15, 7, 3, 1, -64 };
    int lo = 0, hi = 255, i, c;
    if (sbc_mode0_ready)
        return;
    sbc_mode0_ready = 1;
    for (i = 0; i < 5; i++) {
        for (c = 0; c < cnt[i]; c++) {
            if (lo <= hi) {
                sbc_mode0_w[lo] = vals[i];
                lo++;
            }
            if (lo <= hi) {
                sbc_mode0_w[hi] = vals[i];
                hi--;
            }
        }
    }
}

static uint8_t *sbc_apply_mode0(const uint8_t *src, size_t n)
{
    uint8_t *dst;
    size_t inp, outp;
    int s34 = 0, s38 = 0, s3c = 0, s40 = 0, s44 = 0, s48 = 0;
    int state = 0, pen = 0, s20 = 0, s28 = 0;
    static const int offs[6] = { 2, 3, 4, 6, 8, 13 };
    if (n <= 0x23FF) {
        dst = (uint8_t *)malloc(n ? n : 1);
        if (!dst)
            return NULL;
        memcpy(dst, src, n);
        return dst;
    }
    sbc_mode0_init_w();
    dst = (uint8_t *)malloc(n);
    if (!dst)
        return NULL;
    memcpy(dst, src, n);
    inp = outp = 0x200;
    while (inp < n) {
        uint8_t bl = src[inp];
        if (state) {
            int p = dst[outp - (size_t)state];
            int e = (p + (int)bl) & 0xFF;
            int d = e - p;
            dst[outp] = (uint8_t)e;
            if ((uint32_t)(d + 0x17) > 0x2Eu) {
                pen += 5;
                if ((uint32_t)pen > 0x100u) {
                    s34 = s38 = s3c = s40 = s44 = s48 = 0;
                    pen = 0;
                    state = 0;
                }
            } else {
                if (pen > 0)
                    pen -= 3;
            }
            inp++;
            outp++;
        } else {
            int oi;
            dst[outp] = bl;
            s28 = s20 + 1;
            if (s20 > 0x3FFF) {
                memmove(dst + outp, src + inp, n - inp);
                return dst;
            }
            for (oi = 0; oi < 6; oi++) {
                int off = offs[oi];
                int w = sbc_mode0_w[((int)bl - (int)dst[outp - (size_t)off]) & 0xFF];
                switch (off) {
                case 2: s34 += w; break;
                case 3: s38 += w; break;
                case 4: s3c += w; break;
                case 6: s40 += w; break;
                case 8: s44 += w; break;
                default: s48 += w; break;
                }
            }
            if (s34 > 0x3E80) state = 2;
            if (s38 > 0x3E80) state = 3;
            if (s3c > 0x3E80) state = 4;
            if (s40 > 0x3E80) state = 6;
            if (s44 > 0x3E80) state = 8;
            if (s48 > 0x3E80) state = 0xD;
            s20 = s28;
            inp++;
            outp++;
        }
    }
    return dst;
}

/* ---- LZSS / LZP (flag3 == 1) ---- */

/* Same hash, but with the table's own mask.  The mask is not a constant:
 * the vendor sizes the table from the archive window (ENCODER.md 6.16), so a
 * table smaller than the mask writes out of bounds and the index mask has to
 * travel with the table. */
static uint32_t sbc_h4m(const uint8_t *dst, size_t pos, uint32_t mask)
{
    uint32_t word = (uint32_t)dst[pos - 4] | ((uint32_t)dst[pos - 3] << 8) |
                    ((uint32_t)dst[pos - 2] << 16) | ((uint32_t)dst[pos - 1] << 24);
    return ((word >> 0x13) ^ word) & mask;
}

/* The LZP table's size follows the archive window: 0x40ecb0 builds the
 * decoder object with `1 << (bitlen(bs + 0x400) - 1)` entries, so a 1 MB
 * window gives 2^20 and 3 MB 2^21 (ENCODER.md 6.16).  sbc_lzp_mask_for_level
 * returns the mask the archive being decoded selected; a table smaller than
 * the mask would write out of bounds. */
static uint32_t sbc_lzp_mask_for_level(int level);

/* One LZP pass (0x40a7d0).  The object's parameters are passed explicitly:
 * markers m1/m2 at +0x1c/+0x1d, window/skip at +0xc/+0x10, length base 15 at
 * +0x14.  flag3==1 uses (2, 0xC5, 66, 66); the flag3==2 cascade changes all
 * of them per pass (see sbc_lzp2_decode in sbc.c). */
static int sbc_lzp_pass(const uint8_t *src, size_t inlen, size_t outcap,
                        uint8_t m1, uint8_t m2, uint32_t window,
                        uint32_t skip, uint32_t hmask, uint8_t **outp,
                        uint32_t *outn)
{
    enum { LBASE = 15 };
    const uint8_t M1 = m1, M2 = m2;
    const uint32_t WINDOW = window, SKIP = skip;
    uint32_t *table;
    uint8_t *dst, *psrc;
    size_t cap = outcap + 65536, ncopy, esi, ebx, src_end = inlen, nxt = 0;
    int ebp = 0;
    long step = 0;
    table = (uint32_t *)calloc((size_t)hmask + 1, sizeof(uint32_t));
    if (!table)
        return -1;
    dst = (uint8_t *)calloc(cap ? cap : 1, 1);
    psrc = (uint8_t *)calloc(inlen + 16, 1);
    if (!dst || !psrc) {
        free(table);
        free(dst);
        free(psrc);
        return -1;
    }
    memcpy(psrc, src, inlen);
    src = psrc;
    ncopy = inlen < (size_t)(WINDOW + 4) ? inlen : (size_t)(WINDOW + 4);
    memcpy(dst, src, ncopy);
    esi = ncopy;
    ebx = ncopy;
    if (ebx >= src_end)
        goto done;
    for (;;) {
        uint8_t c;
        step++;
        if (step > 200000000L) {
            free(table);
            free(dst);
            free(psrc);
            return -1;
        }
        if (ebx >= src_end)
            break;
        c = src[ebx];
        if (c == M1 && ebx + 2 < src_end && src[ebx + 1] == M2) {
            uint8_t sel = src[ebx + 2];
            nxt = ebx + 2;
            if (sel == 0) {
                if (ebp == 0) {
                    size_t p = esi - WINDOW;
                    table[sbc_h4m(dst, p, hmask)] = (uint32_t)p;
                    dst[esi] = M1;
                    {
                        size_t b2 = esi + 1, p2 = b2 - WINDOW;
                        table[sbc_h4m(dst, p2, hmask)] = (uint32_t)p2;
                        dst[b2] = M2;
                        esi = b2 + 1;
                    }
                    ebx = nxt + 1;
                    ebp = 0;
                } else {
                    size_t b2 = esi + 1;
                    dst[esi] = M1;
                    if (ebp == 1) {
                        size_t p2;
                        ebp = 0;
                        p2 = b2 - WINDOW;
                        table[sbc_h4m(dst, p2, hmask)] = (uint32_t)p2;
                        dst[b2] = M2;
                        esi = b2 + 1;
                    } else {
                        ebp -= 2;
                        dst[b2] = M2;
                        esi = b2 + 1;
                    }
                    ebx = nxt + 1;
                }
            } else {
                uint32_t length, kk;
                size_t sp;
                if (sel & 0x80) {
                    if (sel <= 0xBF) {
                        nxt = ebx + 3;
                        length = (uint32_t)((sel & 0x3F) + (LBASE - 1)) + ((uint32_t)src[ebx + 3] << 6);
                    } else {
                        nxt = ebx + 4;
                        length = (uint32_t)((sel & 0x3F) + (LBASE - 1)) + ((uint32_t)src[ebx + 3] << 6) + ((uint32_t)src[ebx + 4] << 14);
                    }
                } else {
                    length = (uint32_t)(sel & 0xFF) + (LBASE - 1);
                }
                sp = table[sbc_h4m(dst, esi, hmask)];
                for (kk = 0; kk < length; kk++) {
                    if (esi + 4 > cap) {
                        free(table);
                        free(dst);
                        free(psrc);
                        return -1;
                    }
                    memcpy(dst + esi, dst + sp, 4);
                    sp += 4;
                    esi += 4;
                }
                ebx = nxt + 1;
                ebp = SKIP;
            }
        } else {
            if (ebp == 0) {
                size_t p = esi - WINDOW;
                if (esi + 4 > cap) {
                    free(table);
                    free(dst);
                    free(psrc);
                    return -1;
                }
                table[sbc_h4m(dst, p, hmask)] = (uint32_t)p;
                dst[esi] = src[ebx];
                ebx++;
                esi++;
            } else {
                ebp--;
                if (esi + 4 > cap) {
                    free(table);
                    free(dst);
                    free(psrc);
                    return -1;
                }
                dst[esi] = src[ebx];
                ebx++;
                esi++;
            }
        }
        if (src_end <= ebx)
            break;
    }
done:
    free(table);
    free(psrc);
    *outp = dst;
    *outn = (uint32_t)esi;
    return 0;
}

static int sbc_lzp_decode(const uint8_t *src, size_t inlen, size_t outcap,
                          uint32_t hmask, uint8_t **outp, uint32_t *outn)
{
    return sbc_lzp_pass(src, inlen, outcap, 2, 0xC5, 66, 66, hmask, outp, outn);
}

#endif
