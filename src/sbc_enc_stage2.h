/*
 * Stage 1 / stage 2 encoder -- the mirror image of sbc_stage1/sbc_run_stage2.
 *
 * Given the BWT string S (the stage2 output of the vendor decoder), the
 * decisions are fully determined:
 *
 *   stage1  the anchors are the first occurrence of every distinct byte value,
 *           in increasing position order; M is their count.  Each anchor ships
 *           its value (index in the decoder's remaining permutation) and its
 *           position as a delta from the previous anchor.
 *   stage2  left to right: fill from the frontier to the next known position,
 *           then code the distance to the *next occurrence* of `prev` -- the
 *           rank distance over unknown positions only -- or escape (t == nsyms)
 *           when `prev` has no later occurrence.
 *
 * Verified against the vendor's own decision trace (SBC_TRACE=1) on code-m1,
 * image24-m1, biased-m1, pattern-m1, records-m1, zeros-m1 and eng-m1: every
 * stage1 entry and every stage2 step matches, and the payloads built from the
 * decisions are byte-identical.
 */

#ifndef SBC_ENC_STAGE2_H
#define SBC_ENC_STAGE2_H

/* ---- encoder-side adaptive model (mirror of SbcModel) ---- */

typedef struct {
    SbcWRC *wrc;
    uint32_t *freq;
    uint32_t total;
    uint32_t cap;
    uint32_t active;
    uint32_t inc;
    uint32_t cap_freq;
    uint32_t cap_tot;
} SbcMW;

static void sbc_mw_init(SbcMW *m, SbcWRC *w, uint32_t inc, uint32_t cap_freq,
                        uint32_t cap_tot)
{
    memset(m, 0, sizeof(*m));
    m->wrc = w;
    m->inc = inc;
    m->cap_freq = cap_freq;
    m->cap_tot = cap_tot;
}

static void sbc_mw_free(SbcMW *m)
{
    free(m->freq);
    m->freq = NULL;
}

static void sbc_mw_resize(SbcMW *m, uint32_t nsyms)
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

static void sbc_mw_clear(SbcMW *m)
{
    uint32_t i;
    m->total = 0;
    for (i = 0; i < m->active; i++) {
        m->freq[i] = 1;
        m->total += 1;
    }
}

static void sbc_mw_setf(SbcMW *m, uint32_t k, uint32_t v)
{
    m->total -= m->freq[k];
    if (v == 0)
        v = 1;
    m->freq[k] = v;
    m->total += v;
}

static void sbc_mw_addf(SbcMW *m, uint32_t k, uint32_t v)
{
    m->total += v;
    m->freq[k] += v;
}

static void sbc_mw_rescale(SbcMW *m)
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

static void sbc_mw_sym(SbcMW *m, uint32_t sym)
{
    uint32_t acc = 0, i;
    while (m->total > m->cap_tot)
        sbc_mw_rescale(m);
    if (sym >= m->active)
        sym = m->active - 1;
    for (i = 0; i < sym; i++)
        acc += m->freq[i];
    sbc_wrc_enc(m->wrc, acc, m->freq[sym], m->total);
    m->total += m->inc;
    m->freq[sym] += m->inc;
    if (m->freq[sym] > m->cap_freq)
        sbc_mw_rescale(m);
}

/* ---- encoder context (mirror of SbcCtx) ---- */

typedef struct {
    SbcWRC *wrc;
    uint32_t nsyms;
    uint32_t map[256];
    uint32_t c404[256];
    SbcMW A[20];
    SbcMW B[25];
    SbcMW E;
    /* raw bit channel: bits pushed in decoder order, MSB first */
    uint8_t *bits;
    size_t nbits, capbits;
    uint32_t acc;
    unsigned accn;
} SbcEncCtx;

static void sbc_enc_push_byte(SbcEncCtx *c, uint8_t v)
{
    if (c->nbits == c->capbits) {
        size_t ncap = c->capbits ? c->capbits * 2 : 1024;
        uint8_t *nb = (uint8_t *)realloc(c->bits, ncap);
        if (!nb)
            return;
        c->bits = nb;
        c->capbits = ncap;
    }
    c->bits[c->nbits++] = v;
}

static void sbc_enc_bit(SbcEncCtx *c, unsigned b)
{
    c->acc = (c->acc << 1) | (b & 1u);
    if (++c->accn == 8) {
        sbc_enc_push_byte(c, (uint8_t)c->acc);
        c->acc = 0;
        c->accn = 0;
    }
}

static void sbc_enc_bits(SbcEncCtx *c, uint32_t nbits, uint32_t v)
{
    while (nbits--)
        sbc_enc_bit(c, (v >> nbits) & 1u);
}

static void sbc_enc_ctx_free(SbcEncCtx *c)
{
    int i;
    sbc_mw_free(&c->E);
    for (i = 0; i < 20; i++)
        sbc_mw_free(&c->A[i]);
    for (i = 0; i < 25; i++)
        sbc_mw_free(&c->B[i]);
    free(c->bits);
    c->bits = NULL;
    c->nbits = c->capbits = 0;
}

static int sbc_enc_ctx_init(SbcEncCtx *c, uint32_t n, SbcWRC *wrc)
{
    int i, j, base, off = 184;
    uint32_t edx, nsyms, ns;
    memset(c, 0, sizeof(*c));
    if (n == 0)
        return -1;
    sbc_init_log2();
    edx = n >> 5;
    if (edx > 0x1000)
        edx = 0x1000;
    c->wrc = wrc;
    for (i = 0; i < 256; i++) {
        c->map[i] = edx;
        c->c404[i] = 0x10;
    }
    nsyms = (n <= 0xFFu) ? sbc_log2_tab[n] + 3 : sbc_logmap(n) + 3;
    c->nsyms = nsyms;
    sbc_mw_init(&c->E, wrc, 10, 64, 1024);
    sbc_mw_resize(&c->E, nsyms);
    sbc_mw_clear(&c->E);
    for (i = 0; i < 20; i++)
        sbc_mw_init(&c->A[i], wrc, SBC_APAR[i][0], SBC_APAR[i][1],
                    SBC_APAR[i][2]);
    for (i = 0; i < 20; i++) {
        SbcMW *m = &c->A[i];
        sbc_mw_resize(m, nsyms + 1);
        sbc_mw_setf(m, nsyms, 1);
        sbc_mw_setf(m, nsyms - 1, 1);
        base = 28 * i;
        for (j = (int)nsyms - 2; j >= 0; j--)
            sbc_mw_setf(m, (uint32_t)j, (uint32_t)(SBC_ATAB[base + j] + 1));
    }
    for (i = 0; i < 25; i++)
        sbc_mw_init(&c->B[i], wrc, 1, 0x400, 0x4000);
    for (i = 24; i >= 0; i--) {
        ns = (i > 2) ? 8u : (i == 2 ? 4u : 2u);
        sbc_mw_resize(&c->B[i], ns);
        for (j = (int)ns - 1; j >= 0; j--) {
            off--;
            sbc_mw_setf(&c->B[i], (uint32_t)j, (uint32_t)(SBC_BTAB[off] + 1));
        }
    }
    return 0;
}

static uint32_t sbc_enc_reinit(SbcEncCtx *c, uint32_t param)
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
    if (c->nsyms == nsyms)
        return threshold;
    c->nsyms = nsyms;
    if (threshold <= 2) {
        addval_set = 1;
        addval = 0x200u << (2 - threshold);
    }
    for (i = 0; i < 20; i++) {
        SbcMW *m = &c->A[i];
        sbc_mw_resize(m, nsyms + 1);
        if (nsyms <= 0x10)
            sbc_mw_rescale(m);
        if (addval_set)
            sbc_mw_addf(m, nsyms, addval);
    }
    return threshold;
}

/* ---- stage 1 ---- */

/* Pushes the anchor list (first occurrences, increasing) into pos[0..M-1] and
 * returns M.  pos[] keeps the decoder's dual role: during the loop pos[i..255]
 * holds the remaining byte values, pos[0..i-1] the emitted positions. */
static uint32_t sbc_enc_stage1(SbcEncCtx *c, const uint8_t *S, uint32_t n,
                               uint32_t *pos)
{
    uint32_t seen[256] = { 0 };
    uint32_t M = 0, i, cum = 0;
    uint32_t *anch;
    uint8_t *anch_sym;
    if (n == 0)
        return 0;
    anch = (uint32_t *)malloc(n * sizeof(uint32_t));
    anch_sym = (uint8_t *)malloc(n);
    for (i = 0; i < n; i++) {
        uint8_t b = S[i];
        if (!seen[b]) {
            seen[b] = 1;
            anch[M] = i;
            anch_sym[M] = b;
            M++;
        }
    }
    for (i = 0; i < 256; i++)
        pos[i] = i;
    if (n == 1) {
        /* M stays 1, nothing coded */
    } else if (n <= 0xFF) {
        sbc_wrc_u(c->wrc, n, M - 1);
    } else {
        if (M == 0x100) {
            sbc_enc_bits(c, 1, 0);
        } else {
            sbc_enc_bits(c, 1, 1);
            sbc_wrc_u(c->wrc, 0xFF, M - 1);
        }
    }
    for (i = 0; i < M; i++) {
        uint32_t idx, slot, sym, newpos;
        if (i > 0xFE) {
            idx = 0;
            slot = 255;
            sym = pos[slot];
            pos[slot] = pos[255];
        } else {
            uint32_t k;
            sym = anch_sym[i];
            for (k = i; k < 256; k++)
                if (pos[k] == sym)
                    break;
            idx = k - i;
            slot = i + idx;
            sbc_wrc_u(c->wrc, 0x100 - i, idx);
            sym = pos[slot];
            pos[slot] = pos[i];
        }
        newpos = anch[i];
        if (i == 0) {
            cum = 1;
        } else {
            uint32_t remain = n - cum, kk, delta;
            if (newpos < cum) {
                free(anch);
                free(anch_sym);
                return 0;
            }
            delta = newpos - cum;
            if (remain <= 1) {
                sbc_mw_resize(&c->E, remain);
            } else {
                uint32_t a = remain - 2;
                sbc_mw_resize(&c->E, sbc_logmap(a) + 3);
            }
            if (delta <= 1) {
                kk = delta;
            } else {
                uint32_t v = delta - 2, esi, nbits, lo;
                if (v < 2) {
                    esi = 0;
                    nbits = 1;
                } else {
                    esi = (uint32_t)sbc_bitlen(v) - 1;
                    nbits = esi;
                }
                lo = v - (esi ? (1u << esi) : 0u);
                kk = esi + 2;
                sbc_mw_sym(&c->E, kk);
                sbc_enc_bits(c, nbits, lo);
                cum = newpos + 1;
                pos[i] = newpos;
                continue;
            }
            sbc_mw_sym(&c->E, kk);
            cum = newpos + 1;
        }
        pos[i] = newpos;
    }
    pos[M] = n;
    free(anch);
    free(anch_sym);
    return M;
}

/* ---- stage 2 ---- */

static uint32_t sbc_enc_model_index(uint32_t state)
{
    uint32_t a;
    if (state <= 1)
        return (uint32_t)SBC_T360[state];
    a = state - 2;
    return (uint32_t)SBC_T360[2 + sbc_logmap(a)];
}

/* Builds the payload for a stage2 input S of n bytes into `out`: range-coded
 * stream from the front, raw bits packed MSB-first then reversed at the back.
 * Returns 0 on success. */
static int sbc_enc_stage2_payload(SbcBuf *out, const uint8_t *S, uint32_t n)
{
    SbcWRC wrc;
    SbcEncCtx ctx;
    uint32_t *pos = NULL;
    uint32_t M;
    int rc = -1, i;
    if (n == 0)
        return 0;
    sbc_wrc_init(&wrc, out);
    if (sbc_enc_ctx_init(&ctx, n, &wrc) != 0)
        return -1;
    pos = (uint32_t *)calloc(512, sizeof(uint32_t));
    if (!pos) {
        sbc_enc_ctx_free(&ctx);
        return -1;
    }
    M = sbc_enc_stage1(&ctx, S, n, pos);
    if (M == 0)
        goto done;
    {
        uint32_t outn = 0, threshold = 0x2000000u;
        long it = 0, itcap = 200000L + 8L * (long)n;
        for (;;) {
            uint32_t d1, prev, prevsym, state, aidx, t, esi;
            int64_t gap, nd;
            uint32_t T = 0xFFFFFFFFu, K = 0;
            int have_T = 0;
            if (++it > itcap)
                goto done;
            d1 = pos[1];
            nd = (int64_t)n - (int64_t)d1;
            if (!((int64_t)threshold < nd)) {
                if ((int64_t)n > (int64_t)d1) {
                    threshold = sbc_enc_reinit(&ctx, (uint32_t)(n - d1 - 1));
                    d1 = pos[1];
                }
            }
            prev = S[pos[0]];
            gap = (int64_t)pos[1] - (int64_t)pos[0];
            if (gap > (int64_t)(n - outn))
                gap = (int64_t)(n - outn);
            {
                int64_t j;
                for (j = 0; j < gap; j++)
                    if (S[outn + (uint32_t)j] != (uint8_t)prev)
                        goto done; /* inconsistent input */
            }
            outn += (uint32_t)gap;
            if (outn >= n) {
                if (M <= 1) {
                    rc = 0;
                    break;
                }
                for (i = 1; i < (int)M; i++)
                    pos[i - 1] = pos[i];
                M -= 1;
                pos[M] = n;
                continue;
            }
            prevsym = S[outn - 1];
            state = ctx.map[prevsym];
            aidx = sbc_enc_model_index(state);
            /* next occurrence of prev strictly after pos[1] */
            {
                size_t off = (size_t)pos[1] + 1;
                const uint8_t *hit = NULL;
                if (off < n)
                    hit = (const uint8_t *)memchr(S + off, (uint8_t)prev,
                                                  n - off);
                if (hit) {
                    have_T = 1;
                    T = (uint32_t)(hit - S);
                }
            }
            if (!have_T) {
                t = ctx.nsyms;
                sbc_mw_sym(&ctx.A[aidx], t);
                esi = 0x2000000u;
            } else {
                uint32_t v, idx, bv, lo_bits = 0, nbits = 0;
                {
                    uint32_t l = 0, h = (uint32_t)M + 1, m;
                    while (l < h) {
                        m = l + (h - l) / 2;
                        if (pos[m] < T)
                            l = m + 1;
                        else
                            h = m;
                    }
                    K = l - 1;
                }
                esi = T - pos[1] - K;
                if (esi >= n)
                    goto done;
                v = esi - 2;
                if (esi <= 1) {
                    t = esi;
                } else if (v < 2) {
                    t = 2;
                } else {
                    t = (uint32_t)sbc_bitlen(v) + 1;
                }
                sbc_mw_sym(&ctx.A[aidx], t);
                if (t > 1) {
                    idx = t - 2;
                    if (t <= 5) {
                        uint32_t s = (idx ? 1u : 0u) << (idx & 31);
                        bv = v & ~s;
                    } else {
                        uint32_t rem = v - (1u << (t - 2));
                        bv = rem >> (t - 5);
                        lo_bits = rem & ((1u << (t - 5)) - 1u);
                        nbits = t - 5;
                    }
                    sbc_mw_sym(&ctx.B[idx], bv);
                    if (nbits)
                        sbc_enc_bits(&ctx, nbits, lo_bits);
                }
                {
                    uint32_t c404 = ctx.c404[prevsym], st = ctx.map[prevsym];
                    if (c404 > 4) {
                        uint32_t h2 = c404 >> 1;
                        st = (esi * h2 + st) / (h2 + 1);
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
                    ctx.map[prevsym] = st;
                    ctx.c404[prevsym] =
                        (c404 + (uint32_t)sbc_t3((int)aidx - (int)t)) >> 1;
                }
            }
            if (t == ctx.nsyms) {
                if (M <= 1) {
                    rc = 0;
                    break;
                }
                for (i = 1; i < (int)M; i++)
                    pos[i - 1] = pos[i];
                M -= 1;
                pos[M] = n;
                continue;
            }
            /* shift + insert at index K */
            pos[0] = pos[1];
            for (i = 1; i < (int)K; i++)
                pos[i] = pos[i + 1];
            pos[K] = T;
        }
    }
done:
    free(pos);
    if (rc == 0) {
        size_t i2, nb;
        sbc_wrc_flush(&wrc, 4);
        if (ctx.accn)
            sbc_enc_push_byte(&ctx, (uint8_t)(ctx.acc << (8 - ctx.accn)));
        nb = ctx.nbits;
        if (getenv("SBC_T2DBG"))
            fprintf(stderr, "rc=%zu bits=%zu\n", out->n, nb);
        for (i2 = 0; i2 < nb; i2++)
            sbc_buf_put(out, ctx.bits[nb - 1 - i2]);
    }
    sbc_enc_ctx_free(&ctx);
    return rc;
}

#endif /* SBC_ENC_STAGE2_H */
