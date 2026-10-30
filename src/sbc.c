#include "sbc.h"
#include "sbc_hash.h"
#include "sbc_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#define sbc_mkdir(p) _mkdir(p)
#else
#define sbc_mkdir(p) mkdir(p, 0777)
#endif
#include <time.h>

static const uint8_t SBC_MAGIC[5] = { 'S', 'B', 'C', 0x1e, 'H' };

static const uint8_t SBC_ALPHABET[0x45] = {
    0, '-', ' ', '/', '.', '~',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '_'
};

static uint8_t sbc_rdr_get(SbcReader *r)
{
    if (r->pos >= r->len)
        return 0;
    return r->data[r->pos++];
}

static int sbc_bitlen(uint32_t n)
{
    int k;
    if (n == 0)
        return 1;
    k = 0;
    while (n) {
        k++;
        n >>= 1;
    }
    return k;
}

static void sbc_rc_shift(SbcRC *rc)
{
    rc->code = (rc->code << 8) | sbc_rdr_get(rc->rdr);
    rc->range <<= 8;
    rc->low <<= 8;
}

static void sbc_rc_init(SbcRC *rc, SbcReader *rdr)
{
    int i;
    rc->rdr = rdr;
    rc->low = 0;
    rc->range = 0xFFFFFFFFu;
    rc->code = 0;
    rc->err = 0;
    for (i = 0; i < 4; i++)
        rc->code = (rc->code << 8) | sbc_rdr_get(rdr);
}

static uint32_t sbc_rc_get(SbcRC *rc, uint32_t n)
{
    uint32_t tmp, v;
    if (n == 0) {
        rc->err = 1;
        return 0;
    }
    rc->range = rc->range / n;
    tmp = rc->code - rc->low;
    v = rc->range ? (tmp / rc->range) : 0;
    if (v >= n) {
        rc->err = 1;
        v = n - 1;
    }
    return v;
}

static void sbc_rc_decode(SbcRC *rc, uint32_t start, uint32_t freq)
{
    rc->low = rc->low + rc->range * start;
    rc->range = rc->range * freq;
    for (;;) {
        if ((rc->low ^ (rc->low + rc->range)) <= 0x00FFFFFFu) {
            sbc_rc_shift(rc);
            continue;
        }
        if (rc->range <= 0x3FFFu) {
            rc->range = ((uint32_t)(-(int32_t)rc->low)) & 0x3FFFu;
            sbc_rc_shift(rc);
            continue;
        }
        break;
    }
}

/*
 * Encoder shadow (SBC_PPMTEST=1).
 *
 * The decoder reads the vendor's coded values one by one; feeding the very
 * same (total, start, freq) to the range *encoder* must reproduce the vendor's
 * payload byte for byte.  That validates the whole coding pipeline (models,
 * rescales, bit channel, flush) without having to reproduce the encoder's
 * decisions first -- the decisions are read off the stream here.
 */
typedef struct {
    void *ctx;
    void (*sym)(void *ctx, uint32_t total, uint32_t start, uint32_t freq);
    void (*bits)(void *ctx, uint32_t nbits, uint32_t value);
    void (*reset)(void *ctx);
    void (*finish)(void *ctx, const uint8_t *payload, size_t len);
} SbcShadowHooks;

static SbcShadowHooks *sbc_shadow;     /* active (only inside a block) */
static SbcShadowHooks *sbc_shadow_cfg; /* installed by SBC_PPMTEST */

static uint32_t sbc_u(SbcRC *rc, uint32_t n)
{
    uint32_t v = sbc_rc_get(rc, n);
    sbc_rc_decode(rc, v, 1);
    if (sbc_shadow && sbc_shadow->sym)
        sbc_shadow->sym(sbc_shadow->ctx, n, v, 1);
    return v;
}

static uint32_t sbc_decode_large(SbcRC *rc, uint32_t n)
{
    uint32_t a, b;
    if (n <= 0x4000u)
        return sbc_u(rc, n);
    if (n <= 0x4000000u)
        return (sbc_u(rc, (n >> 13) + 1) << 13) | sbc_u(rc, 0x2000u);
    a = sbc_u(rc, (n >> 26) + 1);
    b = sbc_u(rc, 0x2000u);
    return (((a << 13) | b) << 13) | sbc_u(rc, 0x2000u);
}

static uint32_t sbc_decode_int(SbcRC *rc, uint32_t mx)
{
    int k = sbc_bitlen((mx - 1u) & 0xFFFFFFFFu);
    uint32_t bits, extra, hi;
    if (k <= 1)
        return sbc_decode_large(rc, 1u << k);
    bits = sbc_u(rc, (uint32_t)k);
    extra = (bits == 0) ? 2u : (1u << bits);
    hi = (bits == 0) ? 0u : extra;
    return hi | sbc_decode_large(rc, extra);
}

static uint32_t sbc_decode_int_maxbits(SbcRC *rc, uint32_t nbits)
{
    uint32_t bits, extra, hi;
    if (nbits <= 1)
        return sbc_decode_large(rc, 1u << nbits);
    bits = sbc_u(rc, nbits);
    extra = (bits == 0) ? 2u : (1u << bits);
    hi = (bits == 0) ? 0u : extra;
    return hi | sbc_decode_large(rc, extra);
}

static int sbc_extra_init(SbcExtra *ex, SbcRC *rc, uint32_t nsyms, uint32_t inc,
                          uint32_t cap_freq, uint32_t cap_tot, uint32_t boost0)
{
    uint32_t i;
    memset(ex, 0, sizeof(*ex));
    ex->rc = rc;
    ex->inc = inc;
    ex->cap_freq = cap_freq;
    ex->cap_tot = cap_tot;
    ex->nsyms = nsyms;
    ex->total = nsyms;
    if (nsyms) {
        ex->freq = (uint32_t *)malloc(nsyms * sizeof(uint32_t));
        if (!ex->freq)
            return -1;
        for (i = 0; i < nsyms; i++)
            ex->freq[i] = 1;
        if (boost0) {
            ex->freq[0] += boost0;
            ex->total += boost0;
        }
    }
    return 0;
}

static void sbc_extra_free(SbcExtra *ex)
{
    free(ex->freq);
    ex->freq = NULL;
}

static void sbc_extra_rescale(SbcExtra *ex)
{
    uint32_t i, tot = 0;
    for (i = 0; i < ex->nsyms; i++) {
        ex->freq[i] -= ex->freq[i] >> 1;
        if (ex->freq[i] < 1)
            ex->freq[i] = 1;
        tot += ex->freq[i];
    }
    ex->total = tot;
}

static uint32_t sbc_extra_decode_sym(SbcExtra *ex)
{
    uint32_t v, acc, sym, vv;
    if (ex->nsyms == 0)
        return 0;
    while (ex->total > ex->cap_tot)
        sbc_extra_rescale(ex);
    v = sbc_rc_get(ex->rc, ex->total);
    acc = 0;
    sym = 0;
    if (v >= ex->freq[0]) {
        acc = 0;
        vv = v;
        for (;;) {
            acc += ex->freq[sym];
            vv -= ex->freq[sym];
            sym++;
            if (sym >= ex->nsyms) {
                sym = ex->nsyms - 1;
                break;
            }
            if (ex->freq[sym] > vv)
                break;
        }
    }
    sbc_rc_decode(ex->rc, acc, ex->freq[sym]);
    ex->freq[sym] += ex->inc;
    ex->total += ex->inc;
    if (ex->freq[sym] > ex->cap_freq)
        sbc_extra_rescale(ex);
    return sym;
}

static uint32_t sbc_extra_k(SbcExtra *ex, uint32_t k)
{
    if (k == 0)
        return sbc_u(ex->rc, 2);
    return (1u << k) | sbc_decode_large(ex->rc, 1u << k);
}

static uint32_t sbc_decode_extra(SbcExtra *ex)
{
    uint32_t k;
    if (ex->nsyms == 0)
        return sbc_u(ex->rc, 2);
    k = sbc_extra_decode_sym(ex);
    return sbc_extra_k(ex, k);
}

static void sbc_sm_init(SbcSizeModel *sm, SbcExtra *ex)
{
    sm->extra = *ex;
    sm->last = 0;
    sm->count = 0;
    sm->c12 = 0;
}

static uint32_t sbc_sm_pack32(SbcRC *rc)
{
    uint32_t a, b, c;
    a = sbc_u(rc, 0x400);
    b = sbc_u(rc, 0x800);
    c = sbc_u(rc, 0x800);
    return ((a << 11) | b) << 11 | c;
}

static void sbc_sm_update(SbcSizeModel *sm, uint32_t neu)
{
    uint32_t d = neu - sm->last;
    uint32_t zz;
    if (d & 0x80000000u)
        zz = (((~d) & 0xFFFFFFFFu) << 1) | 1u;
    else
        zz = d << 1;
    sm->last = neu;
    sm->c12 = (sm->c12 >> 2) + (neu >> 1);
    sm->count = (sm->count >> 2) + (zz >> 1);
}

static uint32_t sbc_sm_decode(SbcSizeModel *sm)
{
    uint32_t val, d;
    uint32_t sym = sbc_extra_decode_sym(&sm->extra);
    if (sym == 0x20) {
        (void)sbc_decode_int_maxbits(sm->extra.rc, 0x20);
        return sbc_sm_pack32(sm->extra.rc);
    }
    val = sbc_extra_k(&sm->extra, sym);
    if (sm->count < sm->c12) {
        if (val & 1)
            d = ~(val >> 1);
        else
            d = val >> 1;
        val = sm->last + d;
    }
    sbc_sm_update(sm, val);
    return val;
}

static uint32_t sbc_read_vlq(SbcReader *r)
{
    uint32_t a = sbc_rdr_get(r);
    uint32_t top = a & 0xC0u;
    uint32_t b, c, d;
    if (top == 0x00)
        return a;
    if (top == 0x40)
        return ((a ^ 0x40u) << 8) | sbc_rdr_get(r);
    if (top == 0x80) {
        b = sbc_rdr_get(r);
        c = sbc_rdr_get(r);
        return (((a ^ 0x80u) << 8 | b) << 8) | c;
    }
    b = sbc_rdr_get(r);
    c = sbc_rdr_get(r);
    d = sbc_rdr_get(r);
    return (((((a ^ 0xC0u) << 8) | b) << 8 | c) << 8) | d;
}

static uint8_t *sbc_copy_bits(SbcRC *rc, uint32_t nbits, size_t *out_len)
{
    uint32_t remaining = nbits;
    size_t cap = (nbits + 7u) / 8u + 1u;
    uint8_t *buf = (uint8_t *)calloc(cap ? cap : 1, 1);
    size_t n = 0;
    uint32_t v;
    if (!buf)
        return NULL;
    while (remaining > 7) {
        buf[n++] = (uint8_t)sbc_u(rc, 0x100);
        remaining -= 8;
    }
    if (remaining) {
        v = sbc_u(rc, 1u << remaining);
        buf[n++] = (uint8_t)((v << (8 - remaining)) & 0xFF);
    }
    *out_len = n;
    return buf;
}

static uint32_t sbc_getbits(const uint8_t *p, size_t nbytes, size_t *bitpos, int n)
{
    uint32_t v = 0;
    int i;
    for (i = 0; i < n; i++) {
        size_t byte = *bitpos / 8;
        int off = 7 - (int)(*bitpos % 8);
        uint32_t bit = 0;
        if (byte < nbytes)
            bit = (p[byte] >> off) & 1u;
        v |= bit << i;
        (*bitpos)++;
    }
    return v;
}

static int sbc_ibwt(const uint8_t *L, size_t n, uint32_t primary, uint8_t *out)
{
    uint32_t count[256], C[256];
    uint32_t *T;
    uint32_t i, s, p, c;
    if (n == 0)
        return 0;
    if (primary >= n)
        return -1;
    if (n == 1) {
        out[0] = L[0];
        return 0;
    }
    T = (uint32_t *)malloc(n * sizeof(uint32_t));
    if (!T)
        return -1;
    memset(count, 0, sizeof(count));
    for (i = 0; i < n; i++)
        count[L[i]]++;
    s = 0;
    for (i = 0; i < 256; i++) {
        C[i] = s;
        s += count[i];
    }
    for (i = 0; i < n; i++) {
        c = L[i];
        T[C[c]] = i;
        C[c]++;
    }
    p = primary;
    for (i = 0; i < n; i++) {
        p = T[p];
        out[i] = L[p];
    }
    free(T);
    return 0;
}

#include "sbc_stage2.h"
#include "sbc_m0adv.h"

/* Width of the digests selected by header field 2 (0 = no checksums). */
static uint32_t sbc_csum_width(uint32_t csum)
{
    if (!csum)
        return 0;
    if (csum == 1)
        return 2;
    if (csum >= 5)
        return sbc_hash_size((int)csum - 5);
    return 4;
}

static int sbc_parse_header(const uint8_t *data, size_t len, SbcHeader *hdr, SbcReader *rdr)
{
    SbcRC rc;
    SbcExtra fn_ex, fl_ex, sm0ex, sm1ex;
    SbcSizeModel sm0, sm1;
    uint32_t i;
    int rcst;

    memset(hdr, 0, sizeof(*hdr));
    if (len < 5 || memcmp(data, SBC_MAGIC, 5) != 0) {
        hdr->err = 1;
        return -1;
    }
    rdr->data = data;
    rdr->len = len;
    rdr->pos = 5;
    sbc_rc_init(&rc, rdr);

    memset(&fn_ex, 0, sizeof(fn_ex));
    memset(&fl_ex, 0, sizeof(fl_ex));
    memset(&sm0ex, 0, sizeof(sm0ex));
    memset(&sm1ex, 0, sizeof(sm1ex));
    rcst = 0;
    rcst |= sbc_extra_init(&fn_ex, &rc, 0x45, 1, 0x4000, 0x4000, 0);
    rcst |= sbc_extra_init(&fl_ex, &rc, 8, 1, 0x200, 0x400, 0x20);
    rcst |= sbc_extra_init(&sm0ex, &rc, 0x20, 1, 0x4000, 0x4000, 0);
    rcst |= sbc_extra_init(&sm1ex, &rc, 0x21, 1, 0x4000, 0x4000, 0);
    if (rcst) {
        sbc_extra_free(&fn_ex);
        sbc_extra_free(&fl_ex);
        sbc_extra_free(&sm0ex);
        sbc_extra_free(&sm1ex);
        hdr->err = 1;
        return -1;
    }

    hdr->crypto = sbc_u(&rc, 8);
    hdr->csum = sbc_u(&rc, 8);
    hdr->solid = sbc_u(&rc, 2);
    hdr->nfiles = sbc_decode_int(&rc, 0xFFFF0000u) + 1;
    if (hdr->nfiles == 0 || hdr->nfiles > SBC_MAX_FILES) {
        sbc_extra_free(&fn_ex);
        sbc_extra_free(&fl_ex);
        sbc_extra_free(&sm0ex);
        sbc_extra_free(&sm1ex);
        hdr->err = 1;
        return -1;
    }
    hdr->files = (SbcFileEnt *)calloc(hdr->nfiles, sizeof(SbcFileEnt));
    if (!hdr->files) {
        sbc_extra_free(&fn_ex);
        sbc_extra_free(&fl_ex);
        sbc_extra_free(&sm0ex);
        sbc_extra_free(&sm1ex);
        hdr->err = 1;
        return -1;
    }
    sbc_sm_init(&sm0, &sm0ex);
    sbc_sm_init(&sm1, &sm1ex);
    for (i = 0; i < hdr->nfiles; i++) {
        char *nm = hdr->files[i].name;
        size_t nlen = 0;
        for (;;) {
            uint32_t s = sbc_extra_decode_sym(&fn_ex);
            if (s == 0)
                break;
            if (nlen + 1 < SBC_MAX_NAME)
                nm[nlen++] = (char)SBC_ALPHABET[s];
            if (nlen >= 0x200)
                break;
        }
        nm[nlen] = 0;
        hdr->files[i].flag = sbc_extra_decode_sym(&fl_ex);
        hdr->files[i].dt = sbc_sm_decode(&sm0);
        hdr->files[i].size = sbc_sm_decode(&sm1);
    }
    /* With checksums the header carries a digest of its own fields, coded as
     * one u(8) per byte right after the file entries and before method/extra3.
     * It has to be consumed to stay in sync with the stream. */
    if (hdr->csum) {
        uint32_t dw = sbc_csum_width(hdr->csum), k;
        for (k = 0; k < dw; k++)
            (void)sbc_u(&rc, 0x100);
    }
    hdr->method = sbc_u(&rc, 0x3F);
    hdr->extra3 = sbc_u(&rc, 3);
    hdr->hdr_pos = rdr->pos;
    hdr->err = rc.err;
    sbc_extra_free(&fn_ex);
    sbc_extra_free(&fl_ex);
    sbc_extra_free(&sm0.extra);
    sbc_extra_free(&sm1.extra);
    return rc.err ? -1 : 0;
}

/*
 * Mode 7: backward-adaptive predictor (0x429bd0).
 *
 * The first `3*param + 3` bytes are one row: three literal bytes then a
 * left delta (`o[i] = src[i] + o[i-3]`).  A record shorter than that is a
 * single row and stops there (0x42a28d sets edi = len and jumps into the same
 * loop).  The width is `3*param`, not `3*(param-1)`: image24 stores 257 and
 * the vendor's first row is 774 bytes, not 771.
 *
 * The body picks a predictor per byte from the already decoded output.  The
 * four candidates are left, up, the 2-D gradient and JPEG-LS' MED; a sliding
 * sum of |residual| (192 entries, four predictors) selects the cheapest, and
 * a three-state machine re-evaluates every 256 bytes whether the residual is
 * coded raw (state 0), against left (state 1) or against the selected
 * predictor (state 2).  The `src` bytes are residuals, not filtered pixels:
 * `out = src + predictor` (mod 256).
 *
 * The state machine watches three context arrays built from the last two
 * bytes of (a) the output, (b) the left residual and (c) the selected
 * residual.  Those 16-bit histories index 64 k-entry saturating counters
 * (`cnt0/1/2`); the counters c0..c2 track how many of the 4096 live contexts
 * are still below 8.  The state is chosen from those counts as in 0x42a1b0.
 *
 * image24 happens to be a horizontal gradient with zero body residuals, so
 * the old pure-gradient version matched it; real images (even image24 plus
 * +-1 noise) need this full predictor.
 */
static uint8_t *sbc_apply_mode7(const uint8_t *src, size_t n, uint32_t param)
{
    size_t W, row, i;
    uint8_t *o;
    uint16_t *ctx0, *ctx1, *ctx2;
    uint32_t *cost;              /* cost[p][ctx], 4 x 192 */
    uint8_t *cnt0, *cnt1, *cnt2;
    uint32_t sum[4] = { 0, 0, 0, 0 };
    size_t pos = 0, prev = 0, ctxi = 0;
    int c0 = 0, c1 = 0, c2 = 0;
    int state = 2, sel = 0;
    uint32_t thr = 1;

    o = (uint8_t *)malloc(n ? n : 1);
    if (!o)
        return NULL;
    if (n <= 0x1F || param <= 1) {
        memcpy(o, src, n);
        return o;
    }
    W = (size_t)3 * param;
    row = W + 3;
    if (row > n)
        row = n;
    o[0] = src[0];
    o[1] = src[1];
    o[2] = src[2];
    for (i = 3; i < row; i++)
        o[i] = (uint8_t)(src[i] + o[i - 3]);
    if (n <= W + 3)
        return o;

    ctx0 = (uint16_t *)calloc(4096, sizeof(uint16_t));
    ctx1 = (uint16_t *)calloc(4096, sizeof(uint16_t));
    ctx2 = (uint16_t *)calloc(4096, sizeof(uint16_t));
    cost = (uint32_t *)calloc(4 * 192, sizeof(uint32_t));
    cnt0 = (uint8_t *)calloc(65536, 1);
    cnt1 = (uint8_t *)calloc(65536, 1);
    cnt2 = (uint8_t *)calloc(65536, 1);
    if (!ctx0 || !ctx1 || !ctx2 || !cost || !cnt0 || !cnt1 || !cnt2) {
        free(ctx0);
        free(ctx1);
        free(ctx2);
        free(cost);
        free(cnt0);
        free(cnt1);
        free(cnt2);
        free(o);
        return NULL;
    }

    for (i = W + 3; i < n; i++) {
        int ul = o[i - W - 3], up = o[i - W], left = o[i - 3];
        int v = src[i], out, r0, r1, r2, r3, med, cst[4];
        uint32_t base;
        size_t npos;

        med = ul;
        if (ul >= up && ul >= left)
            med = up <= left ? up : left;
        else if (ul <= up && ul <= left)
            med = up >= left ? up : left;
        else
            med = (up + left - ul) & 0xFF;

        if (state == 0)
            out = v;
        else if (state == 1)
            out = (v + left) & 0xFF;
        else {
            int p;
            if (sel == 0)
                p = left;
            else if (sel == 1)
                p = up;
            else if (sel == 2)
                p = (left + up - ul) & 0xFF;
            else
                p = med;
            out = (v + p) & 0xFF;
        }
        o[i] = (uint8_t)out;

        r0 = out - left;
        r1 = out - up;
        r2 = out - (left + up - ul);
        r3 = out - med;

        /* The selector for the current byte was already used above; the
         * costs pick the predictor for the next byte.  The context update
         * below stores the residual of that new predictor (0x42a07d reads
         * esi after the selection block). */
        cst[0] = abs(r0) & 0xFF;
        cst[1] = abs(r1) & 0xFF;
        cst[2] = abs(r2) & 0xFF;
        cst[3] = abs(r3) & 0xFF;
        {
            int k;
            for (k = 0; k < 4; k++) {
                uint32_t *slot = &cost[(size_t)k * 192 + ctxi];
                sum[k] += (uint32_t)cst[k] - *slot;
                *slot = (uint32_t)cst[k];
            }
        }
        sel = sum[1] <= sum[0] ? 1 : 0;
        base = sum[sel];
        if (sum[2] < base) {
            sel = 2;
            base = sum[2];
        }
        if (sum[3] < base)
            sel = 3;

        /* retire the contexts stored at this position, then rebuild them
         * from the previous position's 16-bit history */
        {
            uint16_t a = ctx0[pos], b = ctx1[pos], c = ctx2[pos];
            uint8_t x;
            x = cnt0[a];
            if (x) {
                cnt0[a] = (uint8_t)(x - 1);
                if (x - 1 < 8)
                    c0--;
            }
            x = cnt1[b];
            if (x) {
                cnt1[b] = (uint8_t)(x - 1);
                if (x - 1 < 8)
                    c1--;
            }
            x = cnt2[c];
            if (x) {
                cnt2[c] = (uint8_t)(x - 1);
                if (x - 1 < 8)
                    c2--;
            }
        }
        ctx0[pos] = (uint16_t)(((uint32_t)ctx0[prev] << 8) | (uint32_t)out);
        ctx1[pos] = (uint16_t)(((uint32_t)ctx1[prev] << 8) | ((uint32_t)r0 & 0xFF));
        ctx2[pos] = (uint16_t)(((uint32_t)ctx2[prev] << 8) |
                               ((uint32_t)(sel == 0 ? r0 : sel == 1 ? r1 :
                                           sel == 2 ? r2 : r3) & 0xFF));
        {
            uint8_t x;
            x = cnt0[ctx0[pos]];
            if (x != 0xFF) {
                cnt0[ctx0[pos]] = (uint8_t)(x + 1);
                if (x < 8)
                    c0++;
            }
            x = cnt1[ctx1[pos]];
            if (x != 0xFF) {
                cnt1[ctx1[pos]] = (uint8_t)(x + 1);
                if (x < 8)
                    c1++;
            }
            x = cnt2[ctx2[pos]];
            if (x != 0xFF) {
                cnt2[ctx2[pos]] = (uint8_t)(x + 1);
                if (x < 8)
                    c2++;
            }
        }

        npos = (pos + 1) & 0xFFF;
        if ((npos & 0xFF) == 0xFF) {
            int m = c1 <= c2 ? c1 : c2;
            state = 0;
            if (c0 >= m) {
                if ((int)c2 + (int)thr < c1 + 0x15) {
                    thr >>= 2;
                    if (!thr)
                        thr = 1;
                    state = 2;
                } else {
                    uint32_t t = thr + 0x40, cap = thr * 8;
                    if (t > cap)
                        t = cap;
                    if (t > 0x174)
                        t = 0x174;
                    thr = t;
                    state = 1;
                }
            }
        }
        prev = pos;
        pos = npos;
        ctxi = (ctxi + 1) % 192;
    }

    free(ctx0);
    free(ctx1);
    free(ctx2);
    free(cost);
    free(cnt0);
    free(cnt1);
    free(cnt2);
    return o;
}

static const uint8_t SBC_MODE4_MAP[256] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, 0x0Bu, 0x0Cu, 0x0Eu, 0x0Fu, 0x10u, 0x11u, 0x12u,
    0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u, 0x19u, 0x5Eu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x1Au, 0x23u, 0x39u, 0x38u,
    0x37u, 0x36u, 0x35u, 0x34u, 0x33u, 0x32u, 0x31u, 0x30u, 0xFEu, 0xFFu, 0x55u, 0x41u, 0x45u, 0x59u, 0x49u, 0x4Fu,
    0x42u, 0x48u, 0x47u, 0x52u, 0x44u, 0x4Cu, 0x4Du, 0x4Eu, 0x4Au, 0x4Bu, 0x51u, 0x50u, 0x57u, 0x5Au, 0x56u, 0x46u,
    0x53u, 0x43u, 0x58u, 0x54u, 0x75u, 0x61u, 0x65u, 0x79u, 0x69u, 0x6Fu, 0x62u, 0x67u, 0x68u, 0x72u, 0x64u, 0x6Cu,
    0x6Du, 0x6Eu, 0x6Au, 0x6Bu, 0x71u, 0x70u, 0x77u, 0x76u, 0x66u, 0x63u, 0x78u, 0x7Au, 0x74u, 0x73u, 0x26u, 0x2Au,
    0x2Bu, 0x2Du, 0x3Du, 0x2Fu, 0x21u, 0x2Eu, 0x2Cu, 0x3Fu, 0x3Au, 0x3Bu, 0x20u, 0x0Au, 0x0Du, 0x1Bu, 0x29u, 0x3Eu,
    0x5Du, 0x7Du, 0x28u, 0x3Cu, 0x5Bu, 0x7Bu, 0x09u, 0x22u, 0x27u, 0x60u, 0x24u, 0x25u, 0x40u, 0x5Cu, 0x5Fu, 0x7Cu,
    0x7Eu, 0x7Fu, 0x80u, 0x81u, 0x82u, 0xFCu, 0x83u, 0x84u, 0xFDu, 0x85u, 0x86u, 0x87u, 0x88u, 0x89u, 0x8Au, 0x8Bu,
    0x8Cu, 0x8Du, 0x8Eu, 0x8Fu, 0x90u, 0x91u, 0x92u, 0x93u, 0x94u, 0x95u, 0x96u, 0x97u, 0x98u, 0x99u, 0x9Au, 0x9Bu,
    0x9Cu, 0x9Du, 0x9Eu, 0x9Fu, 0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u, 0xA8u, 0xA9u, 0xAAu, 0xABu,
    0xACu, 0xADu, 0xAEu, 0xAFu, 0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u, 0xB6u, 0xB7u, 0xB8u, 0xB9u, 0xBAu, 0xBBu,
    0xBCu, 0xBDu, 0xBEu, 0xBFu, 0xC0u, 0xC1u, 0xC2u, 0xC3u, 0xC4u, 0xC5u, 0xC6u, 0xC7u, 0xC8u, 0xC9u, 0xCAu, 0xCBu,
    0xCCu, 0xCDu, 0xCEu, 0xCFu, 0xD0u, 0xD1u, 0xD2u, 0xD3u, 0xD4u, 0xD5u, 0xD6u, 0xD7u, 0xD8u, 0xD9u, 0xDAu, 0xDBu,
    0xDCu, 0xDDu, 0xDEu, 0xDFu, 0xE0u, 0xE1u, 0xE2u, 0xE3u, 0xE4u, 0xE5u, 0xE6u, 0xE7u, 0xE8u, 0xE9u, 0xEAu, 0xEBu,
    0xECu, 0xEDu, 0xEEu, 0xEFu, 0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u, 0xF8u, 0xF9u, 0xFAu, 0xFBu,
};

/* 0x406f20's jump table has 126 entries: codes 0x80..0xFD.  The vendor's
 * compressor only ever emits 0x80..0xFC (its tokenizer matches 125 words;
 * every corpus dump confirms it), but the decompressor expands 0xFD as `wh`
 * too, so the decoder table carries it. */
#define SBC_MODE4_NTOK 126
static const char *const SBC_MODE4_TOKENS[SBC_MODE4_NTOK] = {
    "from",
    "have",
    "said",
    "that",
    "this",
    "tion",
    "were",
    "whic",
    "with",
    "all",
    "and",
    "any",
    "are",
    "but",
    "cou",
    "had",
    "dow",
    "for",
    "hav",
    "her",
    "him",
    "his",
    "man",
    "mor",
    "not",
    "out",
    "now",
    "one",
    "you",
    "she",
    "the",
    "was",
    "whe",
    "wer",
    "whi",
    "wit",
    "ad",
    "al",
    "ac",
    "ai",
    "am",
    "an",
    "ar",
    "as",
    "at",
    "ea",
    "en",
    "ec",
    "ed",
    "ee",
    "el",
    "er",
    "es",
    "in",
    "et",
    "id",
    "ie",
    "ig",
    "il",
    "io",
    "is",
    "it",
    "of",
    "on",
    "oo",
    "ol",
    "or",
    "os",
    "ou",
    "ow",
    "ul",
    "un",
    "ur",
    "us",
    "ba",
    "be",
    "ca",
    "co",
    "ce",
    "ch",
    "di",
    "de",
    "ge",
    "gh",
    "ha",
    "he",
    "hi",
    "ho",
    "ra",
    "re",
    "ro",
    "ri",
    "rs",
    "la",
    "li",
    "le",
    "lo",
    "ld",
    "ll",
    "ly",
    "si",
    "se",
    "so",
    "sh",
    "st",
    "ss",
    "ma",
    "mi",
    "me",
    "ne",
    "nc",
    "nd",
    "ng",
    "nt",
    "pe",
    "pa",
    "ta",
    "ti",
    "te",
    "th",
    "to",
    "tr",
    "wa",
    "ve",
    "what",
    "wh",
};

/*
 * Mode-4 prose line reconstruction (0x408060).
 *
 * The encoder replaces the line break of a prose line with a space and stores
 * the target length (7..10 words, plus 0x12 = "do not break") in a tiny
 * 19-symbol range-coded model.  The code is raw e2 bytes in the block payload
 * (the first byte is always zero and implicit); the vendor's decoder walks it
 * backwards.  The model starts uniform (freq 1, total 19) and adapts with
 * increment 7, halving once a frequency passes 768 or the total passes 8192.
 *
 * `target` is the byte the encoder wrote for each line break: LF normally, CR
 * when header ctrl bit 0x40 is set (the vendor sees ctrl>>1).  A space is
 * rewritten when the line already has `min(sym+7, 24)` spaces; symbol 0x12 at
 * that point means "leave it".  A target byte drops the single space that
 * follows it.
 */
typedef struct {
    const uint8_t *data;
    size_t len, pos;
    uint32_t code, low, range;
    uint32_t freq[19];
    uint32_t total;
} SbcLineModel;

static uint32_t sbc_line_next(SbcLineModel *m)
{
    if (!m->pos)
        return 0;
    return m->data[--m->pos];
}

static void sbc_line_init(SbcLineModel *m, const uint8_t *data, size_t len)
{
    int i;
    memset(m, 0, sizeof(*m));
    m->data = data;
    m->len = len;
    m->pos = len;
    for (i = 0; i < 4; i++)
        m->code = (m->code << 8) | sbc_line_next(m);
    m->range = 0xFFFFFFFFu;
    for (i = 0; i < 19; i++)
        m->freq[i] = 1;
    m->total = 19;
}

static void sbc_line_rescale(SbcLineModel *m)
{
    for (;;) {
        uint32_t total = 0;
        int i;
        for (i = 0; i < 19; i++) {
            m->freq[i] -= m->freq[i] >> 1;
            total += m->freq[i];
        }
        m->total = total;
        if (total <= 8192)
            return;
    }
}

static uint32_t sbc_line_decode(SbcLineModel *m)
{
    uint32_t unit, value, cum = 0, sym = 0;
    int i;
    if (m->total > 8192)
        sbc_line_rescale(m);
    unit = m->range / m->total;
    value = unit ? (m->code - m->low) / unit : m->total - 1;
    if (value >= m->total)
        value = m->total - 1;
    for (i = 0; i < 19; i++) {
        if (value < cum + m->freq[i]) {
            sym = (uint32_t)i;
            break;
        }
        cum += m->freq[i];
    }
    if (i == 19) {
        sym = 18;
        cum = m->total - m->freq[sym];
    }
    m->low += unit * cum;
    m->range = unit * m->freq[sym];
    for (;;) {
        uint32_t top = (m->low + m->range) ^ m->low;
        if (top <= 0xFFFFFFu) {
            /* the top byte is settled: pull one more byte */
        } else if (m->range <= 0x3FFFu) {
            m->range = (0u - m->low) & 0x3FFFu;
        } else {
            break;
        }
        m->code = (m->code << 8) | sbc_line_next(m);
        m->range <<= 8;
        m->low <<= 8;
    }
    m->freq[sym] += 7;
    m->total += 7;
    if (m->freq[sym] > 768)
        sbc_line_rescale(m);
    return sym;
}

static uint8_t *sbc_mode4_lines(const uint8_t *src, size_t n, uint8_t target,
                                const uint8_t *code, size_t code_len,
                                size_t *out_len)
{
    static const uint8_t zero = 0;
    SbcLineModel m;
    uint8_t *out = (uint8_t *)malloc(n ? n : 1);
    size_t i = 0, used = 0;
    uint32_t cnt = 0, sym = 0x13;
    if (!out)
        return NULL;
    sbc_line_init(&m, code ? code : &zero, code ? code_len : 0);
    while (i < n) {
        uint8_t c = src[i++];
        out[used++] = c;
        for (;;) {
            uint32_t thr;
            if (c == ' ') {
                if (sym == 0x13)
                    sym = sbc_line_decode(&m);
                thr = sym + 7;
                if (thr > 0x18)
                    thr = 0x18;
                if (cnt >= thr) {
                    if (sym != 0x12)
                        out[used - 1] = target;
                    sym = 0x13;
                    cnt = 0;
                } else {
                    cnt++;
                }
                break;
            }
            if (c != target)
                break;
            cnt = 0;
            if (i >= n)
                break;
            c = src[i++];
            if (c == ' ')
                break;      /* the space after a line break is not stored */
            out[used++] = c; /* vendor 0x4081b5: copy then re-classify */
        }
    }
    *out_len = used;
    return out;
}

/* Mode-4 helpers, transcribed from unsbc.exe 0x406940 and its callees. */

/* 0x4079f0: copy, dropping the single space that follows a `target` byte. */
static uint8_t *sbc_m4_drop_space(const uint8_t *src, size_t n, uint8_t target,
                                  size_t *out_len)
{
    uint8_t *out = (uint8_t *)malloc(n ? n : 1);
    size_t i, used = 0;

    if (!out)
        return NULL;
    for (i = 0; i < n; i++) {
        out[used++] = src[i];
        if (src[i] == target && i + 1 < n && src[i + 1] == ' ')
            i++;                /* 0x4079f0: `p += 1 + (p[1] == ' ')` */
    }
    *out_len = used;
    return out;
}

/* The CR fold exists in two forms in 0x406940 and they are not the same:
 *
 *  - after the prose pass (0x406b68) it is a copy loop that *appends* an LF
 *    after every CR and keeps the following byte -- the prose output has no
 *    CR/LF pairs, its next byte is the first byte of the next line;
 *  - in the no-prose branch (0x407a50) it is in place: `p[1] = LF` and the
 *    input advances by two, so the byte after the CR is consumed.
 *
 * The corpus only ever exercised the second form; tools/m4_forge.py's
 * `salt-line` case covers the first. */
static uint8_t *sbc_m4_fold_cr_add(const uint8_t *src, size_t n,
                                   size_t *out_len)
{
    uint8_t *out = (uint8_t *)malloc(n * 2 + 1);
    size_t i, used = 0;

    if (!out)
        return NULL;
    for (i = 0; i < n; i++) {
        out[used++] = src[i];
        if (src[i] == '\r')
            out[used++] = '\n';
    }
    *out_len = used;
    return out;
}

static uint8_t *sbc_m4_fold_cr_eat(const uint8_t *src, size_t n,
                                   size_t *out_len)
{
    uint8_t *out = (uint8_t *)malloc(n * 2 + 1);
    size_t i, used = 0;

    if (!out)
        return NULL;
    for (i = 0; i < n; i++) {
        out[used++] = src[i];
        if (src[i] == '\r') {
            out[used++] = '\n';
            i++;                /* the follower is overwritten by the LF */
        }
    }
    *out_len = used;
    return out;
}

/* 0x406f20: expand the 126 token codes (0x80..0xFD).  `esc` marks the next
 * byte as literal: the marker is dropped and that byte is copied verbatim,
 * even when it lies in the token range. */
static uint8_t *sbc_m4_expand(const uint8_t *src, size_t n, uint8_t esc,
                              size_t *out_len)
{
    uint8_t *out = (uint8_t *)malloc(n * 4 + 1);
    size_t i, used = 0;

    if (!out)
        return NULL;
    for (i = 0; i < n; i++) {
        uint8_t c = src[i];
        if (c >= 0x80 && c <= 0xFD) {
            const char *tok = SBC_MODE4_TOKENS[c - 0x80];
            size_t len = strlen(tok);
            memcpy(out + used, tok, len);
            used += len;
        } else if (c == esc && i + 1 < n) {
            out[used++] = src[++i];     /* escaped literal, not a token */
        } else {
            out[used++] = c;
        }
    }
    *out_len = used;
    return out;
}

/* 0x406ed0: the capital marker.  `mark` plus the next byte becomes that byte
 * XOR 0x20, which is what turns the lowercased token stream back into text. */
static uint8_t *sbc_m4_caps(const uint8_t *src, size_t n, uint8_t mark,
                            size_t *out_len)
{
    uint8_t *out = (uint8_t *)malloc(n ? n : 1);
    size_t i = 0, used = 0;

    if (!out)
        return NULL;
    while (i < n) {
        if (src[i] == mark) {
            if (i + 1 < n) {
                out[used++] = (uint8_t)(src[i + 1] ^ 0x20);
                i += 2;
                continue;
            }
            i++;                /* lone marker at the end: read past, as the vendor does */
            continue;
        }
        out[used++] = src[i++];
    }
    *out_len = used;
    return out;
}

static uint8_t *sbc_apply_mode4(const uint8_t *src, size_t n, uint32_t ctrl,
                                const uint8_t *linecode, size_t linecode_len,
                                size_t *out_len)
{
    /*
     * The record stores ctrl = vendor word << 1 | dict, so 0x406940 receives
     * `ctrl >> 1` and its bits are:
     *   0x01  derive the two markers from the salt (see below)
     *   0x02  0x4079d0 byte map (SBC_MODE4_MAP)
     *   0x04  0x406ed0 capital marker
     *   0x08  0x408060 prose-line reconstruction (needs the e2 code)
     *   0x10  drop the space after LF (0x4079f0)
     *   0x20  drop the space after CR (0x4079f0)
     *   0x30  both: the CR/CRLF fold (0x407a50) replaces the drops
     *   0x40  0x406f20 token expansion
     *
     * Every observed vendor record carries map|capital (the corpus shapes are
     * 0x56, 0x46 and 0x06), but the function implements the whole word, and
     * the low bits are not a "refusal" any more: the encoder can salt the
     * marker bytes so they never collide with the text.  The prologue of
     * 0x406940 picks them as
     *   bit 0 clear: marker0 = 0xFF (capital), marker1 = 0xFE (escape)
     *   bit 0 set:   marker0 = ((v >> 8) ^ 0xFF) & 0xFF,
     *                marker1 = (marker0 - ((v >> 16) & 0xFF) - 1) & 0xFF
     * and the two salt bytes are the vendor word's bytes 1 and 2.  The
     * markers are not output; they only name the capital byte and the token
     * escape, so a salted record can keep the token stage even when the text
     * itself contains 0xFF/0xFE.  tools/m4_forge.py drives every branch of
     * this function against unsbc.exe.
     */
    uint32_t v = ctrl >> 1;             /* 0x406940's arg5 */
    uint8_t marker0 = 0xFF, marker1 = 0xFE;
    uint8_t *cur, *tmp;
    size_t i, ln = n;

    if ((v & 1u) != 0) {
        marker0 = (uint8_t)(((v >> 8) & 0xFFu) ^ 0xFFu);
        marker1 = (uint8_t)(marker0 - (uint8_t)((v >> 16) & 0xFFu) - 1u);
    }
    cur = (uint8_t *)malloc(n ? n : 1);
    if (!cur)
        return NULL;
    if (n)
        memcpy(cur, src, n);
    if (getenv("SBC_M4SRC"))
        fprintf(stderr, "M4SRC n=%zu ctrl=%02x v=%06x m0=%02x m1=%02x e2=%u\n",
                n, ctrl, v, marker0, marker1,
                linecode_len ? (unsigned)linecode_len - 1 : 0u);
    /* 0x4079d0: the 256-byte permutation.  Every corpus record carries it
     * (header 0x04), but the bit is not a precondition: the vendor just
     * skips the pass when it is clear. */
    if ((v & 0x02u) != 0)
        for (i = 0; i < n; i++)
            cur[i] = SBC_MODE4_MAP[cur[i]];
    /* 0x408060 replaces the two space drops when it runs. */
    if ((v & 0x08u) != 0) {
        if (linecode && linecode_len > 1) {
            const char *ld = getenv("SBC_LINEDUMP");
            if (ld) {
                /* the line model's input and the vendor code, for
                 * tools/m4_line_parity.py */
                static int ldn;
                char lp[1200];
                FILE *f;
                snprintf(lp, sizeof(lp), "%s/%03d_in.bin", ld, ldn);
                f = fopen(lp, "wb");
                if (f) {
                    if (ln)
                        fwrite(cur, 1, ln, f);
                    fclose(f);
                }
                snprintf(lp, sizeof(lp), "%s/%03d_e2.bin", ld, ldn);
                f = fopen(lp, "wb");
                if (f) {
                    if (linecode_len > 1)
                        fwrite(linecode + 1, 1, linecode_len - 1, f);
                    fclose(f);
                }
                snprintf(lp, sizeof(lp), "%s/%03d_tag.txt", ld, ldn);
                f = fopen(lp, "wb");
                if (f) {
                    fprintf(f, "n=%zu target=%u ctrl=%02x\n", n,
                            (unsigned)((v & 0x20u) ? '\r' : '\n'), ctrl);
                    fclose(f);
                }
                ldn++;
            }
            tmp = sbc_mode4_lines(cur, ln, (v & 0x20u) ? '\r' : '\n',
                                  linecode, linecode_len, &i);
            free(cur);
            if (!tmp)
                return NULL;
            cur = tmp;
            ln = i;
        }
        if ((v & 0x30u) == 0x30u) {
            tmp = sbc_m4_fold_cr_add(cur, ln, &i);
            free(cur);
            if (!tmp)
                return NULL;
            cur = tmp;
            ln = i;
        }
    } else if ((v & 0x30u) == 0x30u) {
        tmp = sbc_m4_fold_cr_eat(cur, ln, &i);
        free(cur);
        if (!tmp)
            return NULL;
        cur = tmp;
        ln = i;
    } else {
        if ((v & 0x10u) != 0) {
            tmp = sbc_m4_drop_space(cur, ln, '\n', &i);
            free(cur);
            if (!tmp)
                return NULL;
            cur = tmp;
            ln = i;
        }
        if ((v & 0x20u) != 0) {
            tmp = sbc_m4_drop_space(cur, ln, '\r', &i);
            free(cur);
            if (!tmp)
                return NULL;
            cur = tmp;
            ln = i;
        }
    }
    if ((v & 0x40u) != 0) {
        tmp = sbc_m4_expand(cur, ln, marker1, &i);
        free(cur);
        if (!tmp)
            return NULL;
        cur = tmp;
        ln = i;
    }
    if ((v & 0x04u) != 0) {
        tmp = sbc_m4_caps(cur, ln, marker0, &i);
        free(cur);
        if (!tmp)
            return NULL;
        cur = tmp;
        ln = i;
    }
    *out_len = ln;
    return cur;
}
/*
 * Mode 6 (0x40...): repeat-from-context filter, chosen for uppercase text.
 *
 * The filtered stream is a mix of literals and `7B F0 <len>` codes:
 *   sel < 0x80            L = sel + 16
 *   sel in 0x80..0xBF     L = (sel & 0x3F) + (b1 << 6) + 16
 *   sel >= 0xC0           L = (sel & 0x3F) + (b1 << 6) + (b2 << 14) + 16
 * A code copies L bytes from the last position recorded for the **two-byte
 * context** = the last two bytes of the output.  Only literals update that
 * table (positions p >= 2, key out[p-2..p-1]), copies do not -- that is what
 * makes the encoder pick an older, literal-born source instead of the copy it
 * just emitted.  Verified byte-exactly on `rep1` (110000 B), `line2`
 * (96000 B) and uppercased `code.c` (300000 B).
 *
 * `7B F0 00` is the escape for a literal `7B F0` pair: the vendor routine
 * (unsbc.exe 0x4083a0, args obj/src/dst/len) emits the two marker bytes and
 * records both output positions in the table.  Everything above is read off
 * that routine: the marker bytes are obj->[0xc]/[0xd], the minimum length is
 * obj->[4]-1 (17, i.e. L = sel + 16), the table is an array of 32-bit output
 * positions indexed by the 16-bit context `*(dst-1)*256 + *(dst-2)` and a
 * copy is a plain forward byte loop (so overlaps expand like an LZ run).
 * The marker pair and the minimum length are fields of that object, so they
 * are block/level parameters rather than constants.
 *
 * The table and its positions are **block-wide**, not record-wide: the vendor
 * decodes every record of a block into its own 512 kB slot of one contiguous
 * output buffer (call site 0x408bc4 passes `out + k*0x80000`), the table holds
 * absolute pointers into that buffer, and it is not reset between records.  A
 * record therefore resolves contexts stored by the earlier ones, which is what
 * the 3 MB `-m3` uppercase text needs.  `base` is the block buffer, `dst` the
 * slot the current record starts at, and the table stores offsets into `base`.
 */
static size_t sbc_mode6_decode(const uint8_t *src, size_t n, uint32_t *table,
                               uint8_t *base, uint8_t *dst, size_t outcap)
{
    size_t i = 0, used = 0;
    size_t dpos = (size_t)(dst - base);
    size_t pre;

    /* the vendor copies the first two bytes unconditionally and without a
     * table store (0x4083ca), marks or not, and only then enters the loop */
    pre = n > 2 ? 2 : n;
    if (pre > outcap)
        pre = outcap;
    if (pre) {
        memcpy(dst, src, pre);
        used = pre;
        i = pre;
    }
    while (i < n && used < outcap) {
        if (src[i] == 0x7B && i + 1 < n && src[i + 1] == 0xF0) {
            uint32_t v, len;
            size_t sp;
            uint32_t sel;
            i += 2;
            if (i >= n)
                break;
            sel = src[i++];
            if (sel == 0) {
                /* escaped literal marker pair */
                size_t p;
                if (used + 2 > outcap)
                    break;
                p = dpos + used;
                dst[used++] = 0x7B;
                if (used >= 2)
                    table[(uint32_t)base[p - 2] |
                          ((uint32_t)base[p - 1] << 8)] = (uint32_t)p;
                p = dpos + used;
                dst[used++] = 0xF0;
                if (used >= 2)
                    table[(uint32_t)base[p - 2] |
                          ((uint32_t)base[p - 1] << 8)] = (uint32_t)p;
                continue;
            }
            if (!(sel & 0x80)) {
                v = sel;
            } else if (sel <= 0xBF) {
                if (i >= n)
                    break;
                v = (sel & 0x3F) + ((uint32_t)src[i++] << 6);
            } else {
                if (i + 1 >= n)
                    break;
                v = (sel & 0x3F) + ((uint32_t)src[i] << 6) +
                    ((uint32_t)src[i + 1] << 14);
                i += 2;
            }
            len = v + 16;
            sp = 0;
            if (used >= 2)
                sp = table[(uint32_t)base[dpos + used - 2] |
                           ((uint32_t)base[dpos + used - 1] << 8)];
            while (len-- && used < outcap && sp < dpos + used) {
                dst[used++] = base[sp++];
            }
        } else {
            size_t p = dpos + used;
            dst[used++] = src[i++];
            if (used >= 2)
                table[(uint32_t)base[p - 2] | ((uint32_t)base[p - 1] << 8)] =
                    (uint32_t)p;
        }
    }
    return used;
}

/* Standalone form for records that own a second-stage filter: those keep the
 * old isolated buffer and a throw-away table. */
static uint8_t *sbc_apply_mode6(const uint8_t *src, size_t n, size_t outcap,
                                size_t *out_len)
{
    uint32_t *table;
    uint8_t *out;

    *out_len = 0;
    table = (uint32_t *)calloc(1u << 16, sizeof(uint32_t));
    out = (uint8_t *)malloc(outcap ? outcap : 1);
    if (!table || !out) {
        free(table);
        free(out);
        return NULL;
    }
    *out_len = sbc_mode6_decode(src, n, table, out, out, outcap);
    free(table);
    return out;
}

typedef struct {
    uint32_t flen;
    uint32_t coded;
    uint32_t mode;
    uint32_t ctrl;
    uint32_t opts;
    uint32_t dict;   /* record copies a previous (ptr,len) pair: unsupported */
    uint32_t adv;    /* mode 0/2: adaptive (0x425200) variant selected      */
    uint32_t sub;    /* record has a second filter stage (0x408980)        */
    uint32_t sub_idx;/* that stage's variant, 1..32                        */
    uint32_t sub_flag;
    uint32_t m7;     /* mode 7: 12-bit parameter (the predictor width)     */
    uint32_t dref;   /* dict reference: index in the (ptr,len) ring        */
    uint32_t dlen;   /* dict reference: byte count copied (25 bits)        */
} SbcRec;

/* The record loop keeps the (ptr,len) of every record it has produced in a
 * 2048-slot ring (vendor 0x408f0d; the capacity is the field the index width
 * is derived from, `bitlen(2048)` = 12 bits).  A record whose `dict` bit is
 * set copies `dlen` bytes out of one of those earlier outputs instead of
 * decoding anything (see sbc_apply_recs). */
enum { SBC_DICT_CAP = 2048, SBC_DICT_IDX_BITS = 12 };

typedef struct {
    uint32_t vlq, primary, nbits, flag3, extra16, e1, e2;
    uint8_t *bits;
    size_t bits_len;
    size_t data_pos;
    size_t data_len;
    size_t next_pos;
} SbcBlock;

/*
 * Filter records (0x408e90), exactly as the vendor reads them (GDB trace on
 * code-m1/m2, image-m2 and the 9 MB set-m2 archive):
 *
 *     flen(25) coded(1)
 *     coded: mode(3) dict(1)
 *            mode 4:   ctrl(24)
 *            mode 7:   param(12)       the gradient predictor width
 *            mode 0/2: adv(1)          "advanced mode 0" selector
 *            level >= 1: sub(1)        second filter stage present (-m2/-m3)
 *                        sub: flag(1) idx(5)      idx+1, see 0x4231a0
 *
 * Nothing in the stream says whether the trailing `sub` bit exists: it is a
 * property of the archive (the sub-filter object exists at -m2/-m3 only, the
 * `level` argument), so the parser needs it.  The list is terminated by 25
 * one-bits.  `ctrl` keeps the historical convention of including the dict bit
 * as its low bit (= vendor ctrl << 1), which is what the mode-4 filter tests.
 */
static int sbc_recs_try(const uint8_t *bits, size_t bits_len, size_t term,
                        size_t pos, SbcRec *recs, int nrec, int max,
                        int has_sub)
{
    uint32_t flen, coded, mode, ctrl, dict, adv, sub, subidx, subflag, m7;
    uint32_t dref = 0, dlen = 0;
    size_t p = pos;
    int o, r;

    if (p == term)
        return nrec;
    if (p > term || nrec >= max || p + 26 > bits_len * 8)
        return -1;
    flen = sbc_getbits(bits, bits_len, &p, 25);
    if (flen == 0x1FFFFFFu)
        return -1;
    coded = sbc_getbits(bits, bits_len, &p, 1);
    mode = 5;
    ctrl = 0;
    dict = adv = sub = subidx = subflag = m7 = 0;
    if (coded) {
        mode = sbc_getbits(bits, bits_len, &p, 3);
        dict = sbc_getbits(bits, bits_len, &p, 1);
        if (dict) {
            /* Dictionary reference: index into the ring, then a 25-bit byte
             * count.  The record's own mode bits follow the two dictionary
             * fields (measured on the vendor's `-of` single-extension block,
             * seed 77 t8: `flen=5779 coded mode=4 dict=1 dref=0 dlen=1500`
             * and then 24 bits holding the line code, ctrl 0x56).  A copy
             * record (mode 5) has no such bits, so the old layout still
             * describes every whole-file reference. */
            if (p + SBC_DICT_IDX_BITS + 25 > bits_len * 8)
                return -1;
            dref = sbc_getbits(bits, bits_len, &p, SBC_DICT_IDX_BITS);
            dlen = sbc_getbits(bits, bits_len, &p, 25);
            if (dlen == 0x1FFFFFFu)
                return -1;
            if (mode == 4) {
                if (p + 24 > bits_len * 8)
                    return -1;
                ctrl = sbc_getbits(bits, bits_len, &p, 24);
                ctrl = (ctrl << 1) | dict;
            }
            if (mode == 7) {
                if (p + 12 > bits_len * 8)
                    return -1;
                m7 = sbc_getbits(bits, bits_len, &p, 12);
            }
            if (mode == 0 || mode == 2)
                adv = sbc_getbits(bits, bits_len, &p, 1);
            if (has_sub) {
                sub = sbc_getbits(bits, bits_len, &p, 1);
                if (sub) {
                    subflag = sbc_getbits(bits, bits_len, &p, 1);
                    subidx = sbc_getbits(bits, bits_len, &p, 5) + 1;
                }
            }
        } else {
            if (flen == 0)
                return -1;
            if (mode == 4) {
                if (p + 24 > bits_len * 8)
                    return -1;
                ctrl = sbc_getbits(bits, bits_len, &p, 24);
                ctrl = (ctrl << 1) | dict;
            }
            if (mode == 7) {
                if (p + 12 > bits_len * 8)
                    return -1;
                m7 = sbc_getbits(bits, bits_len, &p, 12);
            }
            if (mode == 0 || mode == 2)
                adv = sbc_getbits(bits, bits_len, &p, 1);
            if (has_sub) {
                sub = sbc_getbits(bits, bits_len, &p, 1);
                if (sub) {
                    subflag = sbc_getbits(bits, bits_len, &p, 1);
                    subidx = sbc_getbits(bits, bits_len, &p, 5) + 1;
                }
            }
        }
    } else if (flen == 0) {
        return -1;
    }
    for (o = 0; o <= 4; o++) {
        if (!coded && o)
            break;
        if (p + (size_t)o > term)
            break;
        recs[nrec].flen = flen;
        recs[nrec].coded = coded;
        recs[nrec].mode = mode;
        recs[nrec].ctrl = ctrl;
        recs[nrec].opts = (uint32_t)o;
        recs[nrec].dict = dict;
        recs[nrec].adv = adv;
        recs[nrec].sub = sub;
        recs[nrec].sub_idx = subidx;
        recs[nrec].sub_flag = subflag;
        recs[nrec].m7 = m7;
        recs[nrec].dref = dref;
        recs[nrec].dlen = dlen;
        r = sbc_recs_try(bits, bits_len, term, p + (size_t)o, recs, nrec + 1,
                         max, has_sub);
        if (r >= 0)
            return r;
    }
    return -1;
}

static int sbc_parse_recs_exact(const uint8_t *bits, size_t bits_len,
                                SbcRec *recs, int max, int has_sub)
{
    size_t nbits = bits_len * 8;
    size_t start, p;
    int r;

    for (start = 0; start + 25 <= nbits; start++) {
        p = start;
        if (sbc_getbits(bits, bits_len, &p, 25) != 0x1FFFFFFu)
            continue;
        r = sbc_recs_try(bits, bits_len, start, 0, recs, 0, max, has_sub);
        if (r >= 0)
            return r;
    }
    return -1;
}

static int sbc_parse_recs_greedy(const uint8_t *bits, size_t bits_len,
                                 SbcRec *recs, int max, int has_sub)
{
    size_t p = 0, nbits = bits_len * 8;
    int nrec = 0;

    while (p + 26 <= nbits && nrec < max) {
        uint32_t flen = sbc_getbits(bits, bits_len, &p, 25);
        uint32_t coded, mode = 5, ctrl = 0, dict = 0, adv = 0, sub = 0;
        uint32_t subidx = 0, subflag = 0, m7 = 0, dref = 0, dlen = 0;
        if (flen == 0x1FFFFFFu)
            break;
        coded = sbc_getbits(bits, bits_len, &p, 1);
        if (coded) {
            mode = sbc_getbits(bits, bits_len, &p, 3);
            dict = sbc_getbits(bits, bits_len, &p, 1);
            if (dict) {
                if (p + SBC_DICT_IDX_BITS + 25 > nbits)
                    break;
                dref = sbc_getbits(bits, bits_len, &p, SBC_DICT_IDX_BITS);
                dlen = sbc_getbits(bits, bits_len, &p, 25);
                if (dlen == 0x1FFFFFFu)
                    break;
                /* the tail's own mode bits follow the dictionary fields */
                if (mode == 4) {
                    if (p + 24 > nbits)
                        break;
                    ctrl = sbc_getbits(bits, bits_len, &p, 24);
                    ctrl = (ctrl << 1) | dict;
                }
                if (mode == 7)
                    m7 = sbc_getbits(bits, bits_len, &p, 12);
                if (mode == 0 || mode == 2)
                    adv = sbc_getbits(bits, bits_len, &p, 1);
                if (has_sub) {
                    sub = sbc_getbits(bits, bits_len, &p, 1);
                    if (sub) {
                        subflag = sbc_getbits(bits, bits_len, &p, 1);
                        subidx = sbc_getbits(bits, bits_len, &p, 5) + 1;
                    }
                }
            } else {
                if (flen == 0)
                    break;
                if (mode == 4) {
                    if (p + 24 > nbits)
                        break;
                    ctrl = sbc_getbits(bits, bits_len, &p, 24);
                    ctrl = (ctrl << 1) | dict;
                }
                if (mode == 7)
                    m7 = sbc_getbits(bits, bits_len, &p, 12);
                if (mode == 0 || mode == 2)
                    adv = sbc_getbits(bits, bits_len, &p, 1);
                if (has_sub) {
                    sub = sbc_getbits(bits, bits_len, &p, 1);
                    if (sub) {
                        subflag = sbc_getbits(bits, bits_len, &p, 1);
                        subidx = sbc_getbits(bits, bits_len, &p, 5) + 1;
                    }
                }
            }
        } else if (flen == 0) {
            break;
        }
        recs[nrec].flen = flen;
        recs[nrec].coded = coded;
        recs[nrec].mode = mode;
        recs[nrec].ctrl = ctrl;
        recs[nrec].opts = 0;
        recs[nrec].dict = dict;
        recs[nrec].adv = adv;
        recs[nrec].sub = sub;
        recs[nrec].sub_idx = subidx;
        recs[nrec].sub_flag = subflag;
        recs[nrec].m7 = m7;
        recs[nrec].dref = dref;
        recs[nrec].dlen = dlen;
        nrec++;
        if (p >= nbits)
            break;
    }
    return nrec;
}

/*
 * One payload block: [vlq][range-coded header][compressed data][2 bytes].
 * ``data_pos`` is where the compressed bytes start (validated against the
 * vendor stream cursor), ``next_pos`` is the next block's header.
 */
static int sbc_block_read(const uint8_t *data, size_t len, size_t pos,
                          SbcExtra *extra, uint32_t nsyms, uint32_t usize_max,
                          uint32_t rec_w, SbcBlock *b)
{
    SbcReader rdr;
    SbcRC rc;
    uint32_t vlq;

    memset(b, 0, sizeof(*b));
    rdr.data = data;
    rdr.len = len;
    rdr.pos = pos;
    if (pos >= len)
        return -1;
    vlq = sbc_read_vlq(&rdr);
    if (vlq == 0)
        return 0;
    if (rdr.pos >= len)
        return -1;
    sbc_rc_init(&rc, &rdr);
    b->vlq = vlq;
    b->primary = sbc_decode_large(&rc, vlq);
    b->nbits = sbc_decode_int_maxbits(&rc, 0x14);
    b->bits = sbc_copy_bits(&rc, b->nbits, &b->bits_len);
    if (!b->bits)
        return -1;
    b->flag3 = sbc_u(&rc, 3);
    b->extra16 = 0;
    if (b->flag3 == 2)
        b->extra16 = sbc_u(&rc, 0x10);
    if (!extra->freq) {
        if (sbc_extra_init(extra, &rc, nsyms, 1, 0x4000, 0x4000, 0))
            return -1;
    } else {
        extra->rc = &rc;
    }
    b->e1 = sbc_decode_extra(extra);
    b->e2 = sbc_decode_extra(extra);
    /* With checksums every payload is bracketed by an integrity record before
     * it and a verify record after it (2 bytes for CRC16, 4 for CRC32/
     * Adler32/Sum32); -hn archives have neither. */
    b->data_pos = rc.rdr->pos + rec_w;
    b->data_len = b->e1 ? b->e1 : vlq;
    /* e2 is the raw line-length code of a mode-4 prose record (the first
     * byte, always 0, is implicit).  It sits right after the e1 tail, before
     * the block's trailing integrity record. */
    b->next_pos = b->data_pos + b->data_len + b->e2 + rec_w;
    /* BWT blocks never expand, so anything bigger than the chunk we still
     * need is a mis-parsed header from a wrong stream offset. */
    if (usize_max && vlq > usize_max)
        return -1;
    if (b->data_pos > len || b->data_len > len - b->data_pos)
        return -1;
    if (b->e2 > len - b->data_pos - b->data_len)
        return -1;
    if (b->next_pos > len)
        return -1;
    if (getenv("SBC_DBG2"))
        fprintf(stderr,
                "BLK pos=%zu vlq=%u nbits=%u flag3=%u e1=%u e2=%u "
                "data=%zu+%zu next=%zu\n",
                pos, b->vlq, b->nbits, b->flag3, b->e1, b->e2,
                b->data_pos, (size_t)b->data_len, b->next_pos);
    return 1;
}

/*
 * Second-stage filter (vendor object 0x40 of the record parser: 0x408980 sets
 * it up, 0x4231a0 configures it, 0x423c60 expands a record and 0x423540 feeds
 * decoded bytes back into the history ring).
 *
 * A record carrying the `sub` bit is decoded in two stages: the mode filter
 * produces its usual output, which this filter then expands.  Matches are
 * addressed by a hash of the last output bytes; the table holds ring offsets,
 * so the history must be fed back exactly like the vendor does -- this is the
 * only filter with cross-block state.
 *
 * Vendor object layout, for reference:
 *   0x4004 flag   0: 3-byte prologue, 17-bit hash of 3 bytes, 1.5 MB ring
 *                 1: 8-byte prologue, 21-bit hash of 8 bytes, 24 MB ring
 *   0x4008 ring size, 0x400c table, 0x4010 ring
 *   0x4014 lbase = 5-bit record field (verbatim), 0x4024 write position
 *   0x401c bytes fed so far, 0x4020 disabled, 0x402a 4-byte alignment
 */
typedef struct {
    uint8_t *ring;      /* `size` bytes, plus the 16 bytes the vendor ends up
                         * hashing when the feed restarts at offset 0 */
    uint32_t size;
    uint32_t *table;
    uint32_t mask;
    uint32_t wp;
    uint32_t total;
    uint32_t lbase;
    uint8_t m1, m2;
    int flag;
    int align;
    int ready;
} SbcSub;

#define SBC_SUB_PREFIX 16
static SbcSub g_sub;
static int g_sub_level = -1;
static void sbc_sub_use_level(int level);

/* Hashes the vendor computes on 4-byte words for flag == 1. */
static uint32_t sbc_sub_hash(const uint8_t *p, int flag, uint32_t mask)
{
    if (flag) {
        uint32_t d4, d8, h;
        memcpy(&d4, p - 4, 4);
        memcpy(&d8, p - 8, 4);
        h = (d4 ^ (d4 >> 13)) ^ ((d8 ^ (d8 >> 15)) << 11);
        return h & mask;
    }
    return (((uint32_t)p[-3] << 13) ^ ((uint32_t)p[-2] << 8) ^
            (uint32_t)p[-1]) & mask;
}

static void sbc_sub_free(void)
{
    if (g_sub.ring)
        free(g_sub.ring - SBC_SUB_PREFIX);
    free(g_sub.table);
    memset(&g_sub, 0, sizeof(g_sub));
}

static int sbc_sub_init(int level)
{
    sbc_sub_free();
    g_sub.flag = level >= 2 ? 1 : 0;   /* levels are 0-based: 2 = -m3 */
    g_sub.size = g_sub.flag ? 0x1800000u : 0x180000u;
    g_sub.mask = g_sub.flag ? 0x1FFFFFu : 0x1FFFFu;
    g_sub.m1 = 0x03;
    g_sub.m2 = 0xC5;
    g_sub.lbase = 4;
    g_sub.ring = (uint8_t *)calloc((size_t)g_sub.size + SBC_SUB_PREFIX + 16, 1);
    g_sub.table = (uint32_t *)calloc((size_t)g_sub.mask + 1, sizeof(uint32_t));
    if (!g_sub.ring || !g_sub.table) {
        sbc_sub_free();
        return -1;
    }
    g_sub.ring += SBC_SUB_PREFIX;
    g_sub.ready = 1;
    return 0;
}

static void sbc_sub_release(void)
{
    sbc_sub_free();
    g_sub_level = -1;
}

/* 0x4231a0: idx = the record's 5-bit field (SbcRec.sub_idx), flag = the
 * record's 1 bit.  The vendor copies idx into 0x4014 and uses 0x4014 - 1 as
 * the length base, so lbase here keeps the same convention. */
static void sbc_sub_config(uint32_t idx, int flag)
{
    if (!g_sub.ready)
        return;
    g_sub.lbase = idx;
    g_sub.m1 = 0x03;
    g_sub.m2 = 0xC5;
    g_sub.align = flag ? 1 : 0;
}

/* 0x423c60: expand one record.  Returns the produced length (0 on overflow,
 * which the vendor also reports as "nothing produced"). */
static size_t sbc_sub_expand(const uint8_t *src, size_t n, uint8_t *dst,
                             size_t cap)
{
    size_t ip, op, lbase;
    uint32_t pro;
    int dumped = 0;

    if (!g_sub.ready || n == 0)
        return 0;
    {
        static int dumps;
        const char *dir = getenv("SBC_SUBDUMP");
        const char *at = getenv("SBC_SUBAT");
        int mine = 1;
        if (at && *at) {
            /* one call only: a 24 MB ring per call would swamp the disk */
            mine = (dumps == atoi(at));
        }
        if (dir && mine) {
            char path[1200];
            FILE *fp;
            snprintf(path, sizeof(path), "%s/ring.bin", dir);
            if ((fp = fopen(path, "wb")) != NULL) {
                fwrite(g_sub.ring, 1, g_sub.size, fp);
                fclose(fp);
            }
            snprintf(path, sizeof(path), "%s/tbl.bin", dir);
            if ((fp = fopen(path, "wb")) != NULL) {
                fwrite(g_sub.table, 4, (size_t)g_sub.mask + 1, fp);
                fclose(fp);
            }
            snprintf(path, sizeof(path), "%s/src.bin", dir);
            if ((fp = fopen(path, "wb")) != NULL) {
                fwrite(src, 1, n, fp);
                fclose(fp);
            }
            snprintf(path, sizeof(path), "%s/meta.txt", dir);
            if ((fp = fopen(path, "w")) != NULL) {
                fprintf(fp, "call=%d flag=%d size=%u mask=%u lbase=%u "
                        "align=%d total=%u wp=%u n=%zu\n",
                        dumps, g_sub.flag, g_sub.size, g_sub.mask,
                        g_sub.lbase, g_sub.align, g_sub.total, g_sub.wp, n);
                fclose(fp);
            }
            dumped = 1;
        }
        dumps++;
    }
    lbase = (size_t)(g_sub.lbase - 1);
    pro = g_sub.flag ? 8u : 3u;
    if (n < pro)
        pro = (uint32_t)n;
    {
        size_t i;
        for (i = pro; i-- > 0;)
            dst[i] = src[i];
    }
    ip = g_sub.flag ? 8u : 3u;
    op = pro;
    while (ip < n) {
        uint32_t c = src[ip];
        uint32_t len, h, p, k;
        if (c != g_sub.m1 || ip + 2 >= n || src[ip + 1] != g_sub.m2) {
            if (op + 1 > cap)
                return 0;
            dst[op++] = (uint8_t)c;
            ip++;
            continue;
        }
        if (src[ip + 2] == 0) {                 /* escaped marker pair */
            if (op + 2 > cap)
                return 0;
            dst[op++] = g_sub.m1;
            dst[op++] = g_sub.m2;
            ip += g_sub.align ? 6 : 3;
            if (ip > n)
                ip = n;
            continue;
        }
        {
            uint32_t L = src[ip + 2];
            if (L < 0x80) {
                len = L + (uint32_t)lbase;
                ip += 3;
            } else if (L <= 0xBF) {
                if (ip + 3 >= n)
                    return 0;
                len = (L & 0x3F) + (uint32_t)lbase + ((uint32_t)src[ip + 3] << 6);
                ip += 4;
            } else {
                if (ip + 4 >= n)
                    return 0;
                len = (L & 0x3F) + (uint32_t)lbase +
                      ((uint32_t)src[ip + 3] << 6) +
                      ((uint32_t)src[ip + 4] << 14);
                ip += 5;
            }
        }
        if (op < (size_t)pro)
            return 0;
        h = sbc_sub_hash(dst + op, g_sub.flag, g_sub.mask);
        p = g_sub.table[h];
        if (op + (size_t)len * 4 > cap)
            return 0;
        for (k = 0; k < len; k++) {
            uint32_t w = 0;
            if (p + 4 <= g_sub.size) {
                memcpy(&w, g_sub.ring + p, 4);
            } else {
                size_t a = g_sub.size - p, j;
                for (j = 0; j < 4; j++)
                    w |= (uint32_t)(j < a ? g_sub.ring[p + j]
                                          : g_sub.ring[j - a]) << (8 * j);
            }
            memcpy(dst + op, &w, 4);
            p += 4;
            if (p >= g_sub.size)
                p -= g_sub.size;
            op += 4;
        }
    }
    if (dumped) {
        char path[1200];
        FILE *fp;
        snprintf(path, sizeof(path), "%s/dst.bin", getenv("SBC_SUBDUMP"));
        if ((fp = fopen(path, "wb")) != NULL) {
            fwrite(dst, 1, op, fp);
            fclose(fp);
        }
    }
    return op;
}

/* 0x4232c0: zero the table and rehash the whole ring. */
static void sbc_sub_rebuild(void)
{
    uint32_t i, mask = g_sub.mask;
    const uint8_t *r = g_sub.ring;
    uint32_t start = g_sub.flag ? 8u : 3u;

    memset(g_sub.table, 0, ((size_t)mask + 1) * sizeof(uint32_t));
    for (i = start; i < g_sub.size; i++)
        g_sub.table[sbc_sub_hash(r + i, g_sub.flag, mask)] = i;
}

/* 0x423540: append decoded bytes to the history ring. */
static void sbc_sub_feed(const uint8_t *data, size_t n)
{
    size_t start, end, i;
    uint32_t size = g_sub.size;
    uint32_t pro = g_sub.flag ? 8u : 3u;
    int wrapped = 0;

    if (!g_sub.ready || n <= 0x7Fu)
        return;
    if (g_sub.wp >= size)
        g_sub.wp = 0;
    if (n > size) {
        data += n - size;
        n = size;
    }
    g_sub.total += (uint32_t)n;
    if (n + 0x400u >= size) {
        memcpy(g_sub.ring, data, n);
        start = 0;
        g_sub.wp = (n + 0x400u < size) ? (uint32_t)n : 0u;
        end = n;
    } else if ((size_t)g_sub.wp + n <= size) {
        memcpy(g_sub.ring + g_sub.wp, data, n);
        start = g_sub.wp;
        g_sub.wp += (uint32_t)n;
        end = g_sub.wp;
    } else {
        size_t first = size - g_sub.wp;
        memcpy(g_sub.ring + g_sub.wp, data, first);
        memcpy(g_sub.ring, data + first, n - first);
        start = g_sub.wp;
        g_sub.wp = (uint32_t)(n - first);
        end = g_sub.wp;
        wrapped = 1;
    }
    /* the vendor mirrors the first 8 bytes past the ring end, which is what a
     * read straddling the wrap point sees */
    memcpy(g_sub.ring + size, g_sub.ring, 8);
    if (g_sub.total > 3u * size) {
        sbc_sub_rebuild();
        return;
    }
    /* The vendor hashes the newly written positions only, starting after the
     * prologue (0x423676 clamps the start to ring + 3/8).  A wrapped write is
     * hashed in two runs: the tail [start,size) and the head [pro,wp). */
    if (start < pro)
        start = pro;
    if (wrapped) {
        for (i = start; i < size; i++)
            g_sub.table[sbc_sub_hash(g_sub.ring + i, g_sub.flag, g_sub.mask)] =
                (uint32_t)i;
        for (i = pro; i < end; i++)
            g_sub.table[sbc_sub_hash(g_sub.ring + i, g_sub.flag, g_sub.mask)] =
                (uint32_t)i;
    } else {
        for (i = start; i < end; i++)
            g_sub.table[sbc_sub_hash(g_sub.ring + i, g_sub.flag, g_sub.mask)] =
                (uint32_t)i;
    }
}

/* The vendor does not feed a block's output as a whole: 0x408980 registers
 * the (ptr,len) of every record output and 0x4238a0 flushes that list at
 * block end (0x423540 per entry).  Dictionary references are not registered,
 * so they never reach the history - the 9 MB -m2 set shows it: after block 0
 * (a 3,000,000-byte mode-6 record plus a 145,727-byte dict reference) the
 * vendor ring holds the last 1.5 MB of the mode-6 output only. */
typedef struct {
    size_t off;
    size_t len;
} SbcFeed;

#define SBC_FEED_CAP 64

/* Mode-0 inverse for the level that wrote the record: the simple filter at
 * -m1, the adaptive object at -m2/-m3. */
static uint8_t *sbc_mode0_inv(const uint8_t *src, size_t n, int level)
{
    if (level >= 2)
        return sbc_m0_adaptive(src, n, &sbc_m0_params_l2, 0);
    if (level == 1)
        return sbc_m0_adaptive(src, n, &sbc_m0_params_l1, 0);
    return sbc_apply_mode0(src, n);
}

static uint8_t *sbc_apply_recs(const uint8_t *raw, size_t rn, const SbcRec *recs,
                               int nrec, size_t usize, int level,
                               const uint8_t *linecode, size_t linecode_len,
                               size_t *out_len, SbcFeed *feeds, int *nfeeds)
{
    size_t cap = rn * 4 + usize + 64;
    size_t pos = 0, used = 0;
    uint8_t *out;
    uint32_t *m6tab = NULL;
    /* (offset,len) of every record produced so far, for dict references */
    uint32_t doff[SBC_DICT_CAP];
    uint32_t dlen[SBC_DICT_CAP];
    uint32_t dcount = 0;
    int i;

    *out_len = 0;
    if (nfeeds)
        *nfeeds = 0;
    if (getenv("SBC_RAWOUT")) {
        FILE *rf = fopen(getenv("SBC_RAWOUT"), "wb");
        if (rf) {
            fwrite(raw, 1, rn, rf);
            fclose(rf);
        }
    }
    out = (uint8_t *)calloc(cap, 1);
    if (!out)
        return NULL;
    if (nrec <= 0) {
        memcpy(out, raw, rn);
        *out_len = rn;
        return out;
    }
    memset(doff, 0, sizeof(doff));
    memset(dlen, 0, sizeof(dlen));
    for (i = 0; i < nrec; i++) {
        size_t n = recs[i].flen;
        const uint8_t *rec_out;
        uint8_t *f = NULL;
        size_t fn = 0, produced;
        int inplace = 0;
        if (recs[i].dict) {
            /* a record that replays `dlen` bytes of an earlier record's
             * output, then appends its own `flen` bytes as literals (mode 5,
             * which is why the filtered stream is dlen+flen long).  The
             * 9 MB/`t3` cases have flen 0; `t4` block 1 is the general one:
             * copy the 1500-byte previous file, then 2500 new bytes. */
            size_t dl = recs[i].dlen;
            uint32_t slot = recs[i].dref % SBC_DICT_CAP;
            if (n > rn - pos)
                n = rn - pos;
            /* the tail is filtered like any other record: the vendor's `-of`
             * t8 block has a mode-4 dict record (ctrl 0x56) whose 5779 stream
             * bytes expand to the 7500-byte tail after `dlen` copied bytes */
            if (n && recs[i].coded && recs[i].mode == 4)
                f = sbc_apply_mode4(raw + pos, n, recs[i].ctrl & ~1u,
                                    linecode, linecode_len, &fn);
            else if (n && recs[i].coded && recs[i].mode == 0) {
                if (recs[i].adv) {
                    /* the tail's stream is the mode-6 transform of the
                     * filter's output: expand it first (0x408a00) */
                    uint32_t *tab = (uint32_t *)calloc(1u << 16, 4);
                    uint8_t *sb = (uint8_t *)malloc(usize ? usize : 1);
                    size_t m;
                    if (!tab || !sb) {
                        free(tab);
                        free(sb);
                        free(out);
                        return NULL;
                    }
                    m = sbc_mode6_decode(raw + pos, n, tab, sb, sb, usize);
                    if (!m) {
                        free(tab);
                        free(sb);
                        free(out);
                        return NULL;
                    }
                    f = sbc_mode0_inv(sb, m, level);
                    fn = m;
                    free(tab);
                    free(sb);
                } else {
                    f = sbc_mode0_inv(raw + pos, n, level);
                }
            }
            else if (n && recs[i].coded && recs[i].mode == 7)
                f = sbc_apply_mode7(raw + pos, n, recs[i].m7);
            if (f) {
                if (recs[i].mode != 4 &&
                    !(recs[i].mode == 0 && recs[i].adv))
                    fn = n;
            } else {
                fn = n;
            }
            if (used + dl + fn > cap) {
                size_t ncap = used + dl + fn + 65536u;
                uint8_t *np = (uint8_t *)realloc(out, ncap);
                if (!np) {
                    free(f);
                    free(out);
                    return NULL;
                }
                memset(np + cap, 0, ncap - cap);
                out = np;
                cap = ncap;
            }
            if (dl) {
                size_t avail = used - doff[slot];
                size_t cp = dl < avail ? dl : avail;
                memcpy(out + used, out + doff[slot], cp);
            }
            if (n) {
                if (f)
                    memcpy(out + used + dl, f, fn);
                else
                    memcpy(out + used + dl, raw + pos, n);
                pos += n;
                free(f);
            }
            doff[dcount % SBC_DICT_CAP] = (uint32_t)used;
            dlen[dcount % SBC_DICT_CAP] = (uint32_t)(dl + fn);
            dcount++;
            used += dl + fn;
            continue;
        }
        if (n > rn - pos)
            n = rn - pos;
        if (!n)
            continue;
        /* stage 1: the mode filter, as if the record carried no sub bit */
        if (!recs[i].coded || recs[i].mode == 5) {
            rec_out = raw + pos;
            fn = n;
        } else if (recs[i].mode == 0) {
            if (recs[i].adv) {
                /* 0x408a00: expand the record's mode-6 stream into the block
                 * buffer first (the table is the block-wide one, like a mode-6
                 * record's), then run the filter's inverse over the whole
                 * expansion -- the record's output is the expanded length. */
                size_t m;
                if (!m6tab && !(m6tab = (uint32_t *)calloc(1u << 16, 4))) {
                    free(out);
                    return NULL;
                }
                m = sbc_mode6_decode(raw + pos, n, m6tab, out, out + used,
                                     usize > used ? usize - used : 0);
                if (!m) {
                    free(out);
                    return NULL;
                }
                f = sbc_mode0_inv(out + used, m, level);
                fn = m;
            } else {
                f = sbc_mode0_inv(raw + pos, n, level);
                fn = n;
            }
        } else if (recs[i].mode == 4) {
            f = sbc_apply_mode4(raw + pos, n, recs[i].ctrl, linecode,
                                linecode_len, &fn);
        } else if (recs[i].mode == 6 && !recs[i].sub) {
            /* straight into the block buffer, with the block-wide table: the
             * vendor's positions are absolute in it and survive records */
            if (!m6tab && !(m6tab = (uint32_t *)calloc(1u << 16, 4))) {
                free(out);
                return NULL;
            }
            if (used >= cap) {
                free(out);
                return NULL;
            }
            fn = sbc_mode6_decode(raw + pos, n, m6tab, out, out + used,
                                  cap - used);
            inplace = 1;
            rec_out = out + used;
        } else if (recs[i].mode == 6) {
            f = sbc_apply_mode6(raw + pos, n, cap - used, &fn);
        } else if (recs[i].mode == 7) {
            f = sbc_apply_mode7(raw + pos, n, recs[i].m7);
            fn = n;
        } else {
            free(out);
            return NULL;
        }
        if (recs[i].mode != 5 && recs[i].coded && !f && !inplace) {
            if (getenv("SBC_DBG"))
                fprintf(stderr, "RECFAIL i=%d mode=%u n=%zu used=%zu cap=%zu\n",
                        i, recs[i].mode, n, used, cap);
            free(out);
            return NULL;
        }
        if (!inplace)
            rec_out = f ? f : raw + pos;
        pos += n;
        /* stage 2: the second-stage filter expands the record to its final
         * size and remembers it for the following records and blocks */
        if (inplace) {
            produced = fn; /* sbc_mode6_decode wrote it at out + used */
        } else if (recs[i].sub) {
            size_t sn;
            sbc_sub_config(recs[i].sub_idx, (int)recs[i].sub_flag);
            if (used + fn * 0x1000u + 4096u > cap) {
                size_t ncap = used + fn * 0x1000u + 65536u;
                uint8_t *np = (uint8_t *)realloc(out, ncap);
                if (!np) {
                    free(f);
                    free(out);
                    return NULL;
                }
                memset(np + cap, 0, ncap - cap);
                out = np;
                cap = ncap;
            }
            sn = sbc_sub_expand(rec_out, fn, out + used, cap - used);
            if (!sn) {
                if (getenv("SBC_DBG"))
                    fprintf(stderr, "SUBFAIL i=%d fn=%zu used=%zu cap=%zu\n",
                            i, fn, used, cap);
                free(f);
                free(out);
                return NULL;
            }
            produced = sn;
        } else {
            if (used + fn > cap) {
                if (getenv("SBC_DBG"))
                    fprintf(stderr, "CAPFAIL i=%d fn=%zu used=%zu cap=%zu\n",
                            i, fn, used, cap);
                free(f);
                free(out);
                return NULL;
            }
            memcpy(out + used, rec_out, fn);
            produced = fn;
        }
        if (getenv("SBC_DBG3"))
            fprintf(stderr, "REC i=%d mode=%u flen=%zu produced=%zu used=%zu\n",
                    i, recs[i].mode, n, produced, used);
        doff[dcount % SBC_DICT_CAP] = (uint32_t)used;
        dlen[dcount % SBC_DICT_CAP] = (uint32_t)produced;
        dcount++;
        if (feeds && nfeeds && *nfeeds < SBC_FEED_CAP) {
            feeds[*nfeeds].off = used;
            feeds[*nfeeds].len = produced;
            (*nfeeds)++;
        }
        used += produced;
        free(f);
        if (used > cap) {
            free(out);
            return NULL;
        }
    }
    free(m6tab);
    *out_len = used;
    return out;
}

/*
 * Per-block layer dumps (SBC_DUMP=<dir>), for the encoder work.
 *
 * The decoder walks the encoder's pipeline backwards, so every intermediate
 * buffer it builds is exactly the input of one encoder stage.  Writing them
 * out turns "does the encoder match?" into one comparison per layer:
 *
 *   00_payload.bin  bytes stored in the archive (stage1/stage2 output)
 *   01_bwt.bin      BWT string        = stage2 output / stored payload
 *   02_lzp.bin      LZP output        = input of the BWT
 *   03_filter.bin   filter output     = input of the LZP
 *   04_block.bin    decoded block     = input of the filter chain
 *   hdr.txt / recs.txt   block fields and the parsed filter records
 *
 * Layers are numbered by the encoder stage that *produces* them, so an
 * encoder-side dump of the same stage can be diffed directly.
 */
typedef struct {
    uint8_t *payload;
    size_t payload_len;
    uint8_t *bwt;
    size_t bwt_len;
    uint8_t *lzp;
    size_t lzp_len;
    uint8_t *filter;
    size_t filter_len;
    uint8_t *block;
    size_t block_len;
    char hdr[1200];
    char recs[4096];
} SbcLayers;

static void sbc_layer_set(uint8_t **dst, size_t *dst_len, const void *src,
                          size_t n)
{
    uint8_t *p = (uint8_t *)malloc(n ? n : 1);
    if (!p)
        return;
    if (n)
        memcpy(p, src, n);
    free(*dst);
    *dst = p;
    *dst_len = n;
}

static void sbc_layers_free(SbcLayers *l)
{
    if (!l)
        return;
    free(l->payload);
    free(l->bwt);
    free(l->lzp);
    free(l->filter);
    free(l->block);
    memset(l, 0, sizeof(*l));
}

static void sbc_layers_move(SbcLayers *dst, SbcLayers *src)
{
    sbc_layers_free(dst);
    *dst = *src;
    memset(src, 0, sizeof(*src));
}

static void sbc_dump_bytes(const char *dir, uint32_t idx, const char *name,
                           const void *data, size_t n)
{
    char path[1200];
    FILE *f;
    snprintf(path, sizeof(path), "%s/blk%03u_%s", dir, idx, name);
    f = fopen(path, "wb");
    if (!f)
        return;
    if (n)
        fwrite(data, 1, n, f);
    fclose(f);
}

static void sbc_dump_layers(const char *dir, uint32_t idx,
                            const SbcLayers *l)
{
    sbc_dump_bytes(dir, idx, "00_payload.bin", l->payload, l->payload_len);
    sbc_dump_bytes(dir, idx, "01_bwt.bin", l->bwt, l->bwt_len);
    sbc_dump_bytes(dir, idx, "02_lzp.bin", l->lzp, l->lzp_len);
    sbc_dump_bytes(dir, idx, "03_filter.bin", l->filter, l->filter_len);
    sbc_dump_bytes(dir, idx, "04_block.bin", l->block, l->block_len);
    sbc_dump_bytes(dir, idx, "hdr.txt", l->hdr, strlen(l->hdr));
    sbc_dump_bytes(dir, idx, "recs.txt", l->recs, strlen(l->recs));
}

/*
 * The LZP table is sized from the archive's window, not from the level.
 * 0x40ecb0 builds the object through `1 << (bitlen(bs + 0x400) - 1)` entries
 * (0x42c530 then 0x40a730), with bs the window the header's `method` names:
 * a 1 MB window gives mask 0xFFFFF, a 3 MB one 0x1FFFFF.  Measured at runtime
 * on a 4 MB random archive (3 MB window, ~530 kB blocks: mask 0x1FFFFF) and
 * on the 36 MB `-m3` text archive's 3 MB block (same), against 0xFFFFF for
 * every 1 MB-window archive.  `SBC_LZPMASK` still overrides it for probes.
 */
static uint32_t sbc_lzp_hmask = 0xFFFFFu;

static uint32_t sbc_lzp_mask_for_level(int level)
{
    (void)level;
    return sbc_lzp_hmask;
}

static uint32_t sbc_lzp_mask_for_window(uint32_t method)
{
    uint32_t bs = (method << 19) + 0x100000u;
    int bits = sbc_bitlen(bs + 0x400u) - 1;
    if (bits < 0)
        bits = 0;
    return bits >= 32 ? 0xFFFFFFFFu : ((1u << bits) - 1u);
}

/*
 * flag3 == 2 (0x40ea90): an iterated LZP cascade.  The record header carries
 * `extra16 = extra_passes - 1`; the decoder inverts the extra passes in
 * reverse order (i = extra16 down to 0), then runs the default pass last.
 * Pass i uses the marker pair `(i - 0x5865) & 0xffff`, window `(i+1)<<20`
 * and skip `min(window, 0x400)` (0x40a690/0x40a6e0/0x40a710).  The encoder
 * runs default first, then passes i = 0..extra16 while each one shrinks the
 * buffer (0x41f250/0x416790); flag3==1 is the default pass alone.
 */
static int sbc_lzp2_decode(const uint8_t *src, size_t inlen, size_t outcap,
                           uint32_t extra16, uint32_t hmask, uint8_t **outp,
                           uint32_t *outn)
{
    uint8_t *cur = NULL, *next = NULL;
    uint32_t curlen = (uint32_t)inlen, nextlen = 0;
    size_t cap = outcap;
    uint32_t i;

    cur = (uint8_t *)malloc(inlen ? inlen : 1);
    if (!cur)
        return -1;
    if (inlen)
        memcpy(cur, src, inlen);
    /* The encoded stream is default(BWT) followed by extra passes 0..N, so
     * the decoder applies them backwards: marker extra16 first, then down
     * to marker 0xA79B, and the default (2, 0xC5, 66, 66) pass last.  The
     * window is not clamped (0x40a6e0 writes `(i+1)<<20` into +0xc); only
     * the skip field is capped at 0x400. */
    for (i = extra16 + 1; i-- > 0;) {
        uint32_t m = (i - 0x5865u) & 0xFFFFu;
        uint32_t w = (i + 1u) << 20;
        uint32_t skip = w > 0x400 ? 0x400 : w;
        if (sbc_lzp_pass(cur, curlen, cap, (uint8_t)m, (uint8_t)(m >> 8),
                         w, skip, hmask, &next, &nextlen)) {
            free(cur);
            free(next);
            return -1;
        }
        free(cur);
        cur = next;
        next = NULL;
        curlen = nextlen;
    }
    if (sbc_lzp_pass(cur, curlen, cap, 2, 0xC5, 66, 66, hmask, &next, &nextlen)) {
        free(cur);
        free(next);
        return -1;
    }
    free(cur);
    *outp = next;
    *outn = nextlen;
    return 0;
}

static int sbc_block_decode_inner(const uint8_t *data, size_t len,
                                  const SbcBlock *b, uint32_t usize, int level,
                                  uint8_t **out, size_t *out_len,
                                  SbcLayers *lay, SbcFeed *feeds, int *nfeeds)
{
    uint8_t *raw = NULL, *dst = NULL, *filt;
    uint8_t *linecode = NULL;
    size_t rn = 0, fn = 0, linecode_len = 0;
    SbcRec recs[64];
    int nrec;
    uint32_t st1_M = 0;

    *out = NULL;
    *out_len = 0;
    (void)len;
    if (lay)
        memset(lay, 0, sizeof(*lay));
    if (sbc_shadow && sbc_shadow->reset)
        sbc_shadow->reset(sbc_shadow->ctx);
    if (b->flag3 > 2)
        return -2;

    if (b->e1 == 0) {
        raw = (uint8_t *)malloc(b->vlq ? b->vlq : 1);
        if (!raw)
            return -1;
        if (sbc_ibwt(data + b->data_pos, b->vlq, b->primary, raw)) {
            free(raw);
            return -1;
        }
        rn = b->vlq;
        if (lay) {
            sbc_layer_set(&lay->payload, &lay->payload_len,
                          data + b->data_pos, b->data_len);
            sbc_layer_set(&lay->bwt, &lay->bwt_len, raw, rn);
        }
    } else {
        SbcReader pr;
        SbcRC rc2;
        SbcBits bs;
        SbcCtx ctx;
        uint32_t pos[512];
        uint32_t M;
        long sout;

        pr.data = data + b->data_pos;
        pr.len = b->data_len;
        pr.pos = 0;
        sbc_rc_init(&rc2, &pr);
        sbc_bits_init(&bs, pr.data, pr.len);
        memset(pos, 0, sizeof(pos));
        dst = (uint8_t *)calloc(b->vlq ? b->vlq : 1, 1);
        if (!dst)
            return -1;
        if (sbc_ctx_init(&ctx, b->vlq, &rc2)) {
            free(dst);
            return -1;
        }
        ctx.bits = &bs;
        M = sbc_stage1(&ctx, pos, b->vlq, dst);
        st1_M = M;
        if (lay)
            sbc_layer_set(&lay->payload, &lay->payload_len,
                          data + b->data_pos, b->data_len);
        if (getenv("SBC_DBG"))
            fprintf(stderr, "DBG vlq=%u prim=%u e1=%u flag3=%u M=%u nsyms=%u\n",
                    b->vlq, b->primary, b->e1, b->flag3, M, ctx.nsyms);
        if (M == 0) {
            sbc_ctx_free(&ctx);
            free(dst);
            return -2;
        }
        sout = sbc_run_stage2(&ctx, dst, b->vlq, M, pos);
        if (getenv("SBC_DSTOUT")) {
            static int dst_idx;
            char dpath[1200];
            FILE *df;
            snprintf(dpath, sizeof(dpath), "%s/%03d.bin", getenv("SBC_DSTOUT"),
                     dst_idx++);
            df = fopen(dpath, "wb");
            if (df) { fwrite(dst, 1, b->vlq, df); fclose(df); }
        }
        if (getenv("SBC_DBG"))
            fprintf(stderr, "DBG stage2=%ld\n", sout);
        sbc_ctx_free(&ctx);
        if (sout < 0) {
            free(dst);
            return -2;
        }
        /* the BWT string is only complete once stage 2 has filled the gaps
         * stage 1 left, so the layer copy has to happen here (it used to be
         * taken right after stage 1, which dumped a half-filled buffer). */
        if (lay)
            sbc_layer_set(&lay->bwt, &lay->bwt_len, dst, b->vlq);
        raw = (uint8_t *)malloc(b->vlq ? b->vlq : 1);
        if (!raw) {
            free(dst);
            return -1;
        }
        if (sbc_ibwt(dst, b->vlq, b->primary, raw)) {
            free(dst);
            free(raw);
            return -1;
        }
        free(dst);
        rn = b->vlq;
    }

    if (lay)
        sbc_layer_set(&lay->lzp, &lay->lzp_len, raw, rn);
    if (getenv("SBC_BWTOUT")) {
        FILE *wf = fopen(getenv("SBC_BWTOUT"), "wb");
        if (wf) {
            fwrite(raw, 1, rn, wf);
            fclose(wf);
        }
    }
    if (b->flag3 == 1 || b->flag3 == 2) {
        uint8_t *lo = NULL;
        uint32_t on = 0;
        uint32_t hmask = sbc_lzp_mask_for_level(level);
        const char *mo = getenv("SBC_LZPMASK");
        if (mo && *mo)
            hmask = (uint32_t)strtoul(mo, NULL, 0);
        int lr = (b->flag3 == 2)
                     ? sbc_lzp2_decode(raw, rn, usize, b->extra16, hmask,
                                       &lo, &on)
                     : sbc_lzp_decode(raw, rn, usize, hmask, &lo, &on);
        if (lr != 0) {
            free(raw);
            return -1;
        }
        free(raw);
        raw = lo;
        rn = on;
    }
    if (getenv("SBC_LZPOUT")) {
        static int lz_idx;
        char lp[1200];
        FILE *lf;
        snprintf(lp, sizeof(lp), "%s.%d", getenv("SBC_LZPOUT"), lz_idx++);
        lf = fopen(lp, "wb");
        if (lf) {
            fwrite(raw, 1, rn, lf);
            fclose(lf);
        }
    }
    if (lay)
        sbc_layer_set(&lay->filter, &lay->filter_len, raw, rn);

    /* the trailing `sub` bit only exists for archives that own a second-stage
     * filter object, i.e. -m2/-m3 (decode level 2 and 3). */
    /* The vendor reads the list forward from bit 0 and stops when the next
     * 25-bit length is the 0x1FFFFFF terminator (0x408e90): there is no
     * search for a terminator position.  Parsing forward first matters for
     * blocks whose records are long: a 25-one run can occur *inside* a length
     * field (big-m3 block 5 has one at bit 106, while the real terminator is
     * at 111), and the old terminator scan then accepted a two-record parse
     * whose second record overran the filtered stream.  The scan is kept only
     * as a fallback for streams that do not follow the plain forward shape. */
    nrec = sbc_parse_recs_greedy(b->bits, b->bits_len, recs, 64, level >= 1);
    if (nrec <= 0)
        nrec = sbc_parse_recs_exact(b->bits, b->bits_len, recs, 64, level >= 1);
    /* The record loop in the vendor (0x408e90) stops as soon as the records
     * have consumed the block's filtered stream: there is no trailing marker
     * it relies on, so a record whose flen overruns what is left cannot be
     * part of the list (a mis-parse that the terminator search sometimes
     * accepts, e.g. the 9 MB multi-file -m2 set). */
    if (nrec > 0) {
        size_t consumed = 0;
        int k;
        for (k = 0; k < nrec; k++) {
            if (recs[k].flen > rn - consumed)
                break;
            consumed += recs[k].flen;
        }
        nrec = k;
    }
    if (lay) {
        int k, o = 0;
        o += snprintf(lay->hdr + o, sizeof(lay->hdr) - (size_t)o,
                      "vlq=%u primary=%u nbits=%u flag3=%u extra16=%u "
                      "e1=%u e2=%u usize=%u stage1_M=%u bits_len=%zu bits=",
                      b->vlq, b->primary, b->nbits, b->flag3, b->extra16,
                      b->e1, b->e2, usize, st1_M, b->bits_len);
        for (k = 0; k < (int)b->bits_len && o < (int)sizeof(lay->hdr) - 4;
             k++)
            o += snprintf(lay->hdr + o, sizeof(lay->hdr) - (size_t)o, "%02x",
                          b->bits[k]);
        snprintf(lay->hdr + o, sizeof(lay->hdr) - (size_t)o, "\n");
        o = 0;
        o += snprintf(lay->recs + o, sizeof(lay->recs) - (size_t)o,
                      "nrec=%d\n", nrec);
        for (k = 0; k < nrec && o < (int)sizeof(lay->recs) - 80; k++)
            o += snprintf(lay->recs + o, sizeof(lay->recs) - (size_t)o,
                          "len=%u coded=%u mode=%u ctrl=%06x opts=%u"
                          " dict=%u adv=%u m7=%u sub=%u idx=%u flag=%u\n",
                          recs[k].flen, recs[k].coded, recs[k].mode,
                          recs[k].ctrl, recs[k].opts, recs[k].dict,
                          recs[k].adv, recs[k].m7, recs[k].sub,
                          recs[k].sub_idx, recs[k].sub_flag);
    }
    if (getenv("SBC_DBG2")) {
        int q;
        fprintf(stderr, "RECS n=%d:", nrec);
        for (q = 0; q < nrec; q++)
            fprintf(stderr, " [len=%u coded=%u mode=%u ctrl=%06x opts=%u"
                    " dict=%u adv=%u m7=%u dref=%u dlen=%u sub=%u idx=%u"
                    " flag=%u]",
                    recs[q].flen, recs[q].coded, recs[q].mode, recs[q].ctrl,
                    recs[q].opts, recs[q].dict, recs[q].adv, recs[q].m7,
                    recs[q].dref, recs[q].dlen, recs[q].sub,
                    recs[q].sub_idx, recs[q].sub_flag);
        fprintf(stderr, " bits=");
        for (q = 0; q < (int)b->bits_len; q++)
            fprintf(stderr, "%02x", b->bits[q]);
        fprintf(stderr, "\n");
    }
    /* The filter object belongs to the archive, not to the attempt: it is set
     * up once from the header's level and then keeps its history, so a
     * fallback attempt at another level must not recreate it. */
    if (level >= 1 && !g_sub.ready)
        sbc_sub_use_level(level);
    if (level >= 1 && !g_sub.ready) {
        free(raw);
        return -1;
    }
    /* Mode-4 prose records keep their line-length code as e2 raw bytes right
     * after the e1 PPM tail, without the implicit leading zero. */
    if (b->e1 && b->e2) {
        linecode = (uint8_t *)calloc(1, (size_t)b->e2 + 1);
        if (!linecode) {
            free(raw);
            return -1;
        }
        memcpy(linecode + 1, data + b->data_pos + b->e1, b->e2);
        linecode_len = (size_t)b->e2 + 1;
    }
    if (lay && linecode_len > 1 && getenv("SBC_DUMP")) {
        char lp[1200];
        FILE *lf;
        snprintf(lp, sizeof(lp), "%s/e2code.bin", getenv("SBC_DUMP"));
        lf = fopen(lp, "wb");
        if (lf) {
            fwrite(linecode + 1, 1, linecode_len - 1, lf);
            fclose(lf);
        }
    }
    filt = sbc_apply_recs(raw, rn, recs, nrec, usize, level,
                          linecode, linecode_len, &fn, feeds, nfeeds);
    free(linecode);
    free(raw);
    if (!filt)
        return -2;
    if (lay)
        sbc_layer_set(&lay->block, &lay->block_len, filt, fn);
    if (getenv("SBC_BLOCKOUT")) {
        static int bcounter;
        char bp[1200];
        FILE *bf;
        snprintf(bp, sizeof(bp), "%s.%d", getenv("SBC_BLOCKOUT"), bcounter++);
        bf = fopen(bp, "wb");
        if (bf) {
            fwrite(filt, 1, fn, bf);
            fclose(bf);
        }
    }
    /* the shadow replayed every coded value of this block: compare its output
     * with the payload the archive actually stores (compressed blocks only) */
    if (sbc_shadow && sbc_shadow->finish && b->e1 != 0) {
        sbc_shadow->finish(sbc_shadow->ctx, data + b->data_pos, b->data_len);
        sbc_shadow->reset(sbc_shadow->ctx);
    }
    if (usize && fn > usize)
        fn = usize;
    *out = filt;
    *out_len = fn;
    return 0;
}

/* ---- CRC32 (IEEE) and Adler32, the 32-bit -h digests ---- */
static uint32_t sbc_crc32_ieee(const uint8_t *d, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    size_t i;
    for (i = 0; i < n; i++) {
        int k;
        c ^= d[i];
        for (k = 0; k < 8; k++)
            c = (c & 1) ? ((c >> 1) ^ 0xEDB88320u) : (c >> 1);
    }
    return c ^ 0xFFFFFFFFu;
}

static uint32_t sbc_adler32(const uint8_t *d, size_t n)
{
    uint32_t a = 1, b = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        a += d[i];
        if (a >= 65521u)
            a -= 65521u;
        b += a;
        if (b >= 65521u)
            b -= 65521u;
    }
    return (b << 16) | a;
}

/* One-shot MD5/SHA-1/SHA-256 over a buffer, for verifying -hm/-h1/-h2. */
static void sbc_hash_oneshot(int alg, const uint8_t *d, size_t n, uint8_t *out)
{
    SbcHash c;
    sbc_hash_init(&c, alg);
    sbc_hash_upd(&c, alg, d, n);
    sbc_hash_final(&c, alg, out);
}

/*
 * Sum32, the -hs digest (type 4).  The vendor keeps two accumulators A (=1)
 * and B (=0) plus a partial word; every four bytes make a little-endian word
 * that does B += A, A += word.  The last partial word is completed with
 * zero bytes and the value is (A + B) ^ length.
 */
static uint32_t sbc_sum32(const uint8_t *d, size_t n)
{
    uint32_t a = 1, b = 0, word = 0, cnt = 0;
    size_t i, padded = (n + 3u) & ~(size_t)3u;
    for (i = 0; i < padded; i++) {
        word = (i < n ? ((uint32_t)d[i] << 24) : 0u) | (word >> 8);
        if (++cnt == 4) {
            b += a;
            a += word;
            cnt = 0;
        }
    }
    return (a + b) ^ (uint32_t)n;
}

/*
 * Payload stream: blocks are stored back to back, each one followed by a
 * 2-byte field, and the block outputs are concatenated in archive order to
 * rebuild every file.  One adaptive "extra" model is shared by all blocks.
 */
/* ---- CRC16/ARC (poly 0xA001, init 0xFFFF, xorout 0xFFFF) ---- */
static uint16_t sbc_crc16_arc(const uint8_t *d, size_t n)
{
    uint16_t c = 0xFFFF;
    size_t i;
    for (i = 0; i < n; i++) {
        int k;
        c ^= d[i];
        for (k = 0; k < 8; k++)
            c = (uint16_t)((c & 1) ? ((c >> 1) ^ 0xA001) : (c >> 1));
    }
    return (uint16_t)(c ^ 0xFFFF);
}

/*
 * The level is an archive-wide property, but the decoder finds it by trying
 * the three variants against the block checksum.  The second-stage filter is
 * the one stateful stage, and its variant depends on the level, so:
 *   - the state is rebuilt whenever the attempt uses another level, and
 *   - a level that passed the checksum is remembered and tried first on the
 *     following blocks, which keeps a failed attempt from touching the state.
 */
static int g_lock_level = -1;

static void sbc_sub_use_level(int level)
{
    if (level < 1) {
        g_sub_level = -1;
        return;
    }
    if (g_sub_level != level) {
        sbc_sub_init(level);
        g_sub_level = level;
    }
}

static int sbc_block_decode(const uint8_t *data, size_t len, const SbcBlock *b,
                            uint32_t usize, int level, uint8_t **out,
                            size_t *out_len, SbcLayers *lay, SbcFeed *feeds,
                            int *nfeeds, int use_shadow)
{
    int r;
    sbc_shadow = (use_shadow && sbc_shadow_cfg) ? sbc_shadow_cfg : NULL;
    r = sbc_block_decode_inner(data, len, b, usize, level, out, out_len, lay,
                               feeds, nfeeds);
    sbc_shadow = NULL;
    return r;
}

/*
 * Every block ends with a big-endian CRC16 (poly 0xA001, init/out 0xFFFF) of
 * the block's decoded output, so the mode-0 filter variant can be picked per
 * block instead of guessed per archive.
 */
static int sbc_decode_stream(const uint8_t *data, size_t len,
                             const SbcHeader *hdr, size_t start, uint32_t nsyms,
                             int strict, int span, SbcExtracted *files)
{
    SbcExtra extra;
    size_t pos = start, filled = 0;
    uint32_t fi = 0, guard = 0, bidx = 0;
    const char *dump_dir = getenv("SBC_DUMP");
    int st = 0;
    /* record width around a payload: 0 = none, 2 = CRC16, 4 = the 32-bit
     * digests (CRC32, Adler32, Sum32), 16/20/32 = MD5/SHA1/SHA256 */
    uint32_t rec_w = sbc_csum_width(hdr->csum);

    memset(&extra, 0, sizeof(extra));
    /* every pass starts a fresh archive: the second-stage filter history is
     * archive-local and so is the level discovered for it */
    sbc_sub_release();
    g_lock_level = (hdr->extra3 <= 2) ? (int)hdr->extra3 : -1;
    /* the header states the level as `extra3` (0/1/2 = -m1/-m2/-m3): set the
     * second-stage filter up before the first block feeds it */
    sbc_sub_use_level(g_lock_level);
    while (fi < hdr->nfiles) {
        SbcBlock blk;
        uint32_t want = hdr->files[fi].size;
        uint32_t rem, cap;
        uint8_t *best = NULL;
        size_t bestlen = 0, take;
        uint16_t crc_want = 0;
        uint32_t crc32_want = 0;
        uint8_t dig_want[32];
        int have_crc = 0, have_dig = 0, matched = 0, any = 0, lv, r;
        int best_lv = -1, lvi, nlv = 3;
        int best_nfeed = 0, nfeed = 0;
        SbcFeed feeds[SBC_FEED_CAP], best_feeds[SBC_FEED_CAP];
        SbcLayers lay, best_lay;

        memset(&lay, 0, sizeof(lay));
        memset(&best_lay, 0, sizeof(best_lay));
        memset(dig_want, 0, sizeof(dig_want));

        if (guard++ > 100000u) {
            st = -2;
            break;
        }
        if (filled >= want) {
            fi++;
            filled = 0;
            continue;
        }
        rem = want - (uint32_t)filled;
        cap = rem;
        if (span) {
            uint32_t j;
            for (j = fi + 1; j < hdr->nfiles; j++)
                cap += hdr->files[j].size;
        }
        r = sbc_block_read(data, len, pos, &extra, nsyms, cap, rec_w, &blk);
        if (r <= 0) {
            free(blk.bits);
            st = (r == 0) ? -3 : -1;
            break;
        }
        /* only the digests we know how to compute can be verified */
        if (rec_w && blk.data_pos + blk.data_len + blk.e2 + rec_w <= len) {
            size_t tp = blk.data_pos + blk.data_len + blk.e2;
            if (hdr->csum >= 5) {
                memcpy(dig_want, data + tp, rec_w);
                have_dig = 1;
            } else {
                crc_want = (uint16_t)((uint16_t)data[tp] << 8 | data[tp + 1]);
                crc32_want = ((uint32_t)data[tp] << 24) |
                             ((uint32_t)data[tp + 1] << 16) |
                             ((uint32_t)data[tp + 2] << 8) | data[tp + 3];
                have_crc = 1;
            }
        }
        {
            const char *lvonly = getenv("SBC_LEVEL");
            if (lvonly)
                g_lock_level = atoi(lvonly), nlv = 1;
            else
                nlv = 3;
        }
        for (lvi = 0; lvi < nlv; lvi++) {
            uint8_t *o = NULL;
            /* the level is archive-wide and stated by the header; the other
             * two are only tried as a fallback */
            lv = (lvi == 0 && g_lock_level >= 0) ? g_lock_level : lvi;
            uint8_t dig_tmp[32];
            size_t n = 0;
            int dig_ok = 0;
            nfeed = 0;
            r = sbc_block_decode(data, len, &blk, cap, lv, &o, &n,
                                 dump_dir ? &lay : NULL, feeds, &nfeed, 0);
            if (r != 0) {
                if (getenv("SBC_DBG"))
                    fprintf(stderr, "BLKDEC lv=%d rc=%d\n", lv, r);
                sbc_layers_free(&lay);
                continue;
            }
            any = 1;
            if (have_dig) {
                sbc_hash_oneshot((int)hdr->csum - 5, o, n, dig_tmp);
                dig_ok = memcmp(dig_tmp, dig_want, rec_w) == 0;
            }
            if ((have_crc &&
                 ((rec_w == 2 && sbc_crc16_arc(o, n) == crc_want) ||
                  (rec_w == 4 && hdr->csum == 2 &&
                   sbc_crc32_ieee(o, n) == crc32_want) ||
                  (rec_w == 4 && hdr->csum == 3 &&
                   sbc_adler32(o, n) == crc32_want) ||
                  (rec_w == 4 && hdr->csum == 4 &&
                   sbc_sum32(o, n) == crc32_want))) || dig_ok) {
                free(best);
                best = o;
                bestlen = n;
                matched = 1;
                best_lv = lv;
                best_nfeed = nfeed;
                memcpy(best_feeds, feeds, sizeof(best_feeds));
                g_lock_level = lv;
                if (dump_dir)
                    sbc_layers_move(&best_lay, &lay);
                break;
            }
            if (!best) {
                best = o;
                bestlen = n;
                best_lv = lv;
                best_nfeed = nfeed;
                memcpy(best_feeds, feeds, sizeof(best_feeds));
                if (dump_dir)
                    sbc_layers_move(&best_lay, &lay);
            } else {
                free(o);
            }
        }
        sbc_layers_free(&lay);
        /* The history is fed once per record output, in order (vendor
         * 0x4238a0 flushes the (ptr,len) list that 0x408980 fills), and only
         * after the block was accepted: a rejected attempt must not leak
         * into the filter state.  Dictionary references are not in the list.
         * Archives built with -hn carry no checksum, so `matched` stays 0 even
         * though the first decoded attempt is the one that is kept; it must
         * still be fed, otherwise the next block's sub filter starts from an
         * empty ring (9 MB uppercase -m3 -hn, block 1). */
        {
            const char *fs = getenv("SBC_SUBFEED");
            int do_feed = fs ? atoi(fs) : 1;
            if (do_feed && (matched || (!have_crc && !have_dig)) && best &&
                bestlen) {
                int k;
                for (k = 0; k < best_nfeed; k++)
                    sbc_sub_feed(best + best_feeds[k].off, best_feeds[k].len);
            }
        }
        /* The shadow encoder must replay the values of the attempt that is
         * actually kept, and only that one: the other `lv` tries (and the
         * span pass) decode the same block against wrong sizes. */
        if (sbc_shadow_cfg && blk.e1 != 0 && best_lv >= 0 &&
            (matched || (!have_crc && !have_dig))) {
            uint8_t *so = NULL;
            size_t sn = 0;
            if (sbc_block_decode(data, len, &blk, cap, best_lv, &so, &sn,
                                 NULL, NULL, NULL, 1) == 0)
                free(so);
        }
        free(blk.bits);
        if (getenv("SBC_DBG"))
            fprintf(stderr, "BLK pos=%zu vlq=%u prim=%u nbits=%u e1=%u flag=%u crc=%04x any=%d matched=%d out=%zu\n",
                    pos, blk.vlq, blk.primary, blk.nbits, blk.e1, blk.flag3,
                    crc_want, any, matched, bestlen);
        if (dump_dir)
            sbc_dump_layers(dump_dir, bidx++, &best_lay);
        sbc_layers_free(&best_lay);
        if (!any) {
            st = -2;
            break;
        }
        if (strict && (have_crc || have_dig) && !matched) {
            free(best);
            st = -4;
            break;
        }
        take = bestlen;
        if (!span && take > rem) {
            free(best);
            st = -2;
            break;
        }
        /* In span mode a single block may cover several files: distribute its
         * output in archive order across the file boundaries. */
        if (take) {
            size_t off = 0;
            while (off < take && fi < hdr->nfiles) {
                size_t room = (size_t)hdr->files[fi].size - filled;
                size_t n = take - off < room ? take - off : room;
                memcpy(files[fi].data + filled, best + off, n);
                off += n;
                filled += n;
                if (filled == hdr->files[fi].size) {
                    fi++;
                    filled = 0;
                }
            }
        }
        free(best);
        pos = blk.next_pos;
        st = 0;
    }
    sbc_extra_free(&extra);
    if (st == 0 && fi < hdr->nfiles)
        st = -3;
    return st;
}

static int sbc_decode_files(const uint8_t *data, size_t len,
                            const SbcHeader *hdr, SbcExtracted **out,
                            uint32_t *n_out)
{
    static const uint32_t deltas[] = { 2, 3, 0, 1, 4, 5, 6 };
    uint32_t di, nsyms;
    uint32_t cand[3];
    int ncand = 0, ci;
    int pass, sp;

    *out = NULL;
    *n_out = 0;
    /* sp = 0: every block belongs to one file.  sp = 1 ("solid" archives):
     * a block may cover several files, so it is decoded against the whole
     * remaining size and its output is spread across the file boundaries. */
    for (sp = 0; sp <= 1; sp++) {
        if (sp && hdr->nfiles < 2)
            break;
        ncand = 0; /* candidates are rebuilt for each solid/non-solid pass */
    /* nsyms follows the header's window bucket: bitlen((method<<19)+0xFFFFF).
     * Keep the two historical values as fallbacks for older probes. */
    {
        uint32_t w = ((hdr->method & 0xFFu) << 19) + 0xFFFFFu;
        uint32_t guess = sbc_bitlen(w);
        if (guess < 2 || guess > 32)
            guess = 20;
        cand[ncand++] = guess;
        if (guess != 20)
            cand[ncand++] = 20;
        if (guess != 21)
            cand[ncand++] = 21;
        /* SBC_NSYMS pins the shared Extra model width, for probing archives
         * whose method byte gives a wrong guess. */
        if (getenv("SBC_NSYMS")) {
            cand[0] = (uint32_t)atoi(getenv("SBC_NSYMS"));
            ncand = 1;
        }
    }
    /* pass 1 = strict (a block whose checksum does not match is rejected),
     * pass 0 = lenient.  Archives whose digests we can verify must not fall
     * back to the lenient pass: that would hide corruption the vendor
     * reports as a checksum error. */
    for (pass = 1; pass >= 0; pass--) {
        if (!pass && hdr->csum >= 1 && hdr->csum <= 7)
            break;
        for (ci = 0; ci < ncand; ci++) {
            nsyms = cand[ci];
            for (di = 0; di <= sizeof(deltas) / sizeof(deltas[0]); di++) {
                SbcExtracted *ex;
                uint32_t i;
                size_t start = hdr->hdr_pos + (di == 0 ? 0 : deltas[di - 1]);
                int st;

                if (start >= len)
                    continue;
                ex = (SbcExtracted *)calloc(hdr->nfiles ? hdr->nfiles : 1,
                                            sizeof(SbcExtracted));
                if (!ex)
                    return -1;
                for (i = 0; i < hdr->nfiles; i++) {
                    memcpy(ex[i].name, hdr->files[i].name, sizeof(ex[i].name));
                    ex[i].name[sizeof(ex[i].name) - 1] = 0;
                    ex[i].len = hdr->files[i].size;
                    ex[i].dt = hdr->files[i].dt;
                    ex[i].data = (uint8_t *)calloc(ex[i].len ? ex[i].len : 1, 1);
                    if (!ex[i].data)
                        break;
                }
                if (i < hdr->nfiles) {
                    sbc_free_extracted(ex, hdr->nfiles);
                    return -1;
                }
                st = sbc_decode_stream(data, len, hdr, start, nsyms, pass, sp, ex);
                if (st == 0) {
                    *out = ex;
                    *n_out = hdr->nfiles;
                    return 0;
                }
                sbc_free_extracted(ex, hdr->nfiles);
            }
        }
    }
    }
    return -1;
}

void sbc_free_extracted(SbcExtracted *files, uint32_t n)
{
    uint32_t i;
    if (!files)
        return;
    for (i = 0; i < n; i++)
        free(files[i].data);
    free(files);
}

int sbc_decode_archive(const uint8_t *data, size_t len,
                       SbcExtracted **out, uint32_t *n_out)
{
    SbcHeader hdr;
    SbcReader rdr;
    int st;

    *out = NULL;
    *n_out = 0;
    /* Encrypted archives carry 'H' + cipher id in the 5th magic byte; the
     * whole body is CBC-encrypted, so decrypt it first and retry the parse on
     * the plaintext.  The body is padded to a whole 16-byte block, so every
     * possible trailing pad length is tried and the block checksums pick the
     * right one. */
    if (len >= 5 && sbc_crypt_id(data, len) != 0) {
        const char *pw = getenv("SBC_PASS");
        uint8_t *plain = NULL;
        size_t plen = 0, pad;
        int rc;
        if (!pw || !*pw) {
            fprintf(stderr, "archive is encrypted (cipher %d); set SBC_PASS\n",
                    sbc_crypt_id(data, len));
            return -3;
        }
        rc = sbc_crypt_decrypt(data, len, pw, &plain, &plen);
        if (rc != 0) {
            if (rc == -2)
                fprintf(stderr, "cannot set up cipher %d\n",
                        sbc_crypt_id(data, len));
            else if (rc == -3)
                fprintf(stderr, "wrong passphrase\n");
            else
                fprintf(stderr, "malformed encrypted archive\n");
            return rc;
        }
        st = -1;
        for (pad = 0; pad < 16 && plen >= 5 + pad; pad++) {
            st = sbc_decode_archive(plain, plen - pad, out, n_out);
            if (st == 0)
                break;
        }
        free(plain);
        return st;
    }
    if (sbc_parse_header(data, len, &hdr, &rdr) != 0) {
        free(hdr.files);
        return -1;
    }
    sbc_lzp_hmask = sbc_lzp_mask_for_window(hdr.method);
    if (getenv("SBC_DBG"))
        fprintf(stderr, "HDR nfiles=%u csum=%u method=%u solid=%u extra3=%u\n",
                hdr.nfiles, hdr.csum, hdr.method, hdr.solid, hdr.extra3);
    if (getenv("SBC_DUMP")) {
        char path[1200], txt[8192];
        uint32_t i;
        int o = 0;
        FILE *f;
        o += snprintf(txt + o, sizeof(txt) - (size_t)o,
                      "nfiles=%u csum=%u method=%u solid=%u extra3=%u\n",
                      hdr.nfiles, hdr.csum, hdr.method, hdr.solid,
                      hdr.extra3);
        for (i = 0; i < hdr.nfiles && o < (int)sizeof(txt) - 200; i++)
            o += snprintf(txt + o, sizeof(txt) - (size_t)o,
                          "file %u name=%s size=%u dt=%08x flag=%u\n", i,
                          hdr.files[i].name, hdr.files[i].size,
                          hdr.files[i].dt, hdr.files[i].flag);
        snprintf(path, sizeof(path), "%s/arc.txt", getenv("SBC_DUMP"));
        f = fopen(path, "wb");
        if (f) {
            fwrite(txt, 1, strlen(txt), f);
            fclose(f);
        }
    }
    st = sbc_decode_files(data, len, &hdr, out, n_out);
    free(hdr.files);
    return st;
}

#include "sbc_enc.h"
#include "sbc_enc_stage2.h"
#include "sbc_enc_filters.h"
#include "sbc_enc_sub.h"
#include "sbc_enc_lzp.h"
#include "sbc_enc_block.h"
#include "sbc_enc_pss.h"

/*
 * Shadow encoder: replays every value the decoder just read back through the
 * range encoder, so the payload it produces must match the vendor's bytes.
 * Enabled with SBC_PPMTEST=1; SBC_PPMTEST_VERBOSE also prints the matches.
 */
typedef struct {
    SbcBuf rc;
    SbcWRC w;
    uint8_t *bits;
    size_t nbits_bytes, cap_bits_bytes;
    uint32_t bitacc;
    unsigned bitn;
    size_t blocks, ok, bad;
    SbcShadowHooks hooks;
} SbcPpmShadow;

static SbcPpmShadow sbc_ps;

static void sbc_ps_byte(SbcPpmShadow *p, uint8_t v)
{
    if (p->nbits_bytes == p->cap_bits_bytes) {
        size_t cap = p->cap_bits_bytes ? p->cap_bits_bytes * 2 : 4096;
        uint8_t *nb = (uint8_t *)realloc(p->bits, cap);
        if (!nb)
            return;
        p->bits = nb;
        p->cap_bits_bytes = cap;
    }
    p->bits[p->nbits_bytes++] = v;
}

static void sbc_ps_pushbit(SbcPpmShadow *p, unsigned b)
{
    p->bitacc = (p->bitacc << 1) | b;
    if (++p->bitn == 8) {
        sbc_ps_byte(p, (uint8_t)p->bitacc);
        p->bitacc = 0;
        p->bitn = 0;
    }
}

static void sbc_ps_sym(void *c, uint32_t total, uint32_t start,
                       uint32_t freq)
{
    SbcPpmShadow *p = (SbcPpmShadow *)c;
    sbc_wrc_enc(&p->w, start, freq, total);
}

static void sbc_ps_bits(void *c, uint32_t nbits, uint32_t value)
{
    SbcPpmShadow *p = (SbcPpmShadow *)c;
    while (nbits--)
        sbc_ps_pushbit(p, (value >> nbits) & 1u);
}

static void sbc_ps_reset(void *c)
{
    SbcPpmShadow *p = (SbcPpmShadow *)c;
    p->rc.n = 0;
    sbc_wrc_init(&p->w, &p->rc);
    p->nbits_bytes = 0;
    p->bitacc = 0;
    p->bitn = 0;
}

static void sbc_ps_finish(void *c, const uint8_t *payload, size_t len)
{
    SbcPpmShadow *p = (SbcPpmShadow *)c;
    size_t i, nb, total;
    long first = -1;
    uint8_t *cmp;

    sbc_wrc_flush(&p->w, 4);
    if (p->bitn) {
        sbc_ps_byte(p, (uint8_t)(p->bitacc << (8 - p->bitn)));
        p->bitacc = 0;
        p->bitn = 0;
    }
    nb = p->nbits_bytes;
    total = p->rc.n + nb;
    cmp = (uint8_t *)malloc(total ? total : 1);
    if (!cmp)
        return;
    if (p->rc.n)
        memcpy(cmp, p->rc.p, p->rc.n);
    for (i = 0; i < nb; i++)
        cmp[p->rc.n + i] = p->bits[nb - 1 - i];
    for (i = 0; i < len && i < total; i++) {
        if (cmp[i] != payload[i]) {
            first = (long)i;
            break;
        }
    }
    if (first < 0 && total != len)
        first = (long)(total < len ? total : len);
    p->blocks++;
    if (first < 0) {
        p->ok++;
        if (getenv("SBC_PPMTEST_VERBOSE"))
            printf("PPM blk%02zu OK payload=%zu (rc=%zu bits=%zu)\n",
                   p->blocks - 1, len, p->rc.n, nb);
    } else {
        size_t k;
        p->bad++;
        printf("PPM blk%02zu DIFF vendor=%zu ours=%zu first=%ld (rc=%zu "
               "bits=%zu)\n", p->blocks - 1, len, total, first, p->rc.n, nb);
        for (k = (size_t)first > 8 ? (size_t)first - 8 : 0;
             k < (size_t)first + 8 && k < total; k++)
            printf("    %3zu %s %02x / vendor %02x\n", k,
                   cmp[k] == payload[k] ? "  " : "!=", cmp[k],
                   k < len ? payload[k] : 0);
    }
    free(cmp);
}

static void sbc_ps_enable(void)
{
    sbc_ps.hooks.ctx = &sbc_ps;
    sbc_ps.hooks.sym = sbc_ps_sym;
    sbc_ps.hooks.bits = sbc_ps_bits;
    sbc_ps.hooks.reset = sbc_ps_reset;
    sbc_ps.hooks.finish = sbc_ps_finish;
    sbc_shadow_cfg = &sbc_ps.hooks;
}

static uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    if (sz && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *len = (size_t)sz;
    return buf;
}

/* The LZP table is sized from the archive window (0x40ecb0 -> 0x42c530 ->
 * 0x40a730): -b3 selects a 2 MB window whose mask is 0x1FFFFF instead of the
 * 1 MB default 0xFFFFF.  Building and decoding such an archive round-trips
 * through both sides of the sizing rule; before the window-derived mask the
 * encoder wrote 0xFFFFF entries into a 0x1FFFFF-indexed stream and the decode
 * failed. */
static int test_lzp_window(void)
{
    enum { N = 1600000 };
    SbcEncFile f;
    SbcBuf out;
    SbcExtracted *ex = NULL;
    uint32_t n = 0;
    uint8_t *data;
    int fail = 0;

    data = (uint8_t *)malloc(N);
    if (!data)
        return 1;
    /* numbered lines, not a cycle: a periodic block with a truncated tail is
     * the one BWT shape the vendor sorter handles slowly. */
    {
        size_t o = 0;
        unsigned k = 0;
        while (o < (size_t)N) {
            int w = snprintf((char *)data + o, (size_t)N - o,
                             "STATIC INT FUNC_%u(INT A, INT B) { RETURN A * %u + B; }\n",
                             k, k);
            if (w <= 0)
                break;
            if ((size_t)w >= (size_t)N - o) {
                o = (size_t)N;
                break;
            }
            o += (size_t)w;
            k++;
        }
        if (o < (size_t)N)
            memset(data + o, '\n', (size_t)N - o);
    }
    memset(&f, 0, sizeof(f));
    f.name = "win.txt";
    f.flag = 0;
    f.dt = 0x50000000u;
    f.size = N;
    f.data = data;
    memset(&out, 0, sizeof(out));
    if (sbc_enc_archive_ex(&out, &f, 1, 2, 1, 20, 4, 3, 0, 0, NULL, 0) != 0) {
        fail = 1;
    } else if (sbc_enc_lzp_hmask != 0x1FFFFFu) {
        printf("lzp window mask %08x, want 001fffff\n", sbc_enc_lzp_hmask);
        fail = 1;
    } else if (sbc_decode_archive(out.p, out.n, &ex, &n) != 0 || n != 1 ||
               ex[0].len != N || memcmp(ex[0].data, data, N) != 0) {
        fail = 1;
    }
    printf("lzp window -b3 round trip: %s (mask %08x)\n",
           fail ? "FAIL" : "MATCH", sbc_enc_lzp_hmask);
    sbc_free_extracted(ex, n);
    free(out.p);
    free(data);
    return fail;
}

static int test_one(const char *sbc_path, const char *expect_path)
{
    size_t slen = 0, elen = 0;
    uint8_t *sbc, *expect = NULL;
    SbcExtracted *ex = NULL;
    uint32_t n = 0;
    int st, ok;
    sbc = read_file(sbc_path, &slen);
    if (!sbc) {
        printf("FAIL read %s\n", sbc_path);
        return 1;
    }
    st = sbc_decode_archive(sbc, slen, &ex, &n);
    if (expect_path)
        expect = read_file(expect_path, &elen);
    ok = (st == 0 && n >= 1 && ex && ex[0].len == elen &&
          (elen == 0 || (ex[0].data && expect && memcmp(ex[0].data, expect, elen) == 0)));
    printf("%s st=%d n=%u name=%s len=%zu expect=%zu %s\n",
           sbc_path, st, n, (ex && n) ? ex[0].name : "",
           (ex && n) ? ex[0].len : 0, elen, ok ? "MATCH" : "MISMATCH");
    sbc_free_extracted(ex, n);
    free(sbc);
    free(expect);
    return ok ? 0 : 1;
}

/* The `-of` group key: the vendor's extension hash (FUN_00409c10).  It folds
 * the extension characters (after the last dot of the last path component)
 * case-folded into a word from the last one up, keeping the *last four*, and
 * stores it so that the extension reads as a big-endian field at the top of
 * the word; the sort key is the complement.  `` (no dot, a leading dot, a
 * one-character name, or a trailing dot) is 0xffffffff, i.e. the first key.
 * Ties are two names with the same last four extension characters, which is
 * what the vendor groups together -- not the same string comparison: `abcx`
 * and `abcdef` both have the key of `bcx`/`cdef`. */
static uint32_t sbc_enc_ext_hash(const char *name)
{
    const char *base = name, *p;
    size_t len, i, keep;
    uint32_t h = 0, be = 0;

    for (p = name; *p; p++)
        if (*p == '/' || *p == '\\')
            base = p + 1;
    len = strlen(base);
    if (len < 2 || base[len - 1] == '.')
        return 0xffffffffu;
    for (i = len; i > 0; i--)
        if (base[i - 1] == '.')
            break;
    if (i == 0)
        return 0xffffffffu; /* no dot at all */
    p = base + i; /* first extension character */
    len = strlen(p);
    keep = len < 4 ? len : 4;
    for (i = len - keep; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c >= 'A' && c <= 'Z')
            c += 'a' - 'A';
        be = (be << 8) | c;
    }
    h = be << (8 * (4 - keep));
    return ~h;
}

/* The vendor's file list is put in ascending *name length* order before any
 * structure-specific sort (FUN_00408e00): a Shell sort with the gap sequence
 * `gap = n*10/13` (9 and 10 become 11), repeated while the gap is above 5,
 * followed by one plain insertion pass.  Every comparison is strict, so two
 * names of the same length keep the order they were given in -- and since the
 * structure sorter then works on that array, equal-size ties follow the name
 * lengths, not the command line.  Reproduced here exactly, because the gaps
 * decide which equal-length names swap in a bigger set. */
static void sbc_enc_name_len_sort(SbcEncFile *fs, uint32_t n)
{
    uint32_t i, gap, prev;

    if (n < 2)
        return;
    if (n == 2) {
        if (strlen(fs[1].name) < strlen(fs[0].name)) {
            SbcEncFile t = fs[0];
            fs[0] = fs[1];
            fs[1] = t;
        }
        return;
    }
    prev = n;
    do {
        gap = (prev * 10) / 13;
        if (gap == 9 || gap == 10)
            gap = 11;
        for (i = 0; i + gap < n; i++) {
            if (strlen(fs[i + gap].name) < strlen(fs[i].name)) {
                SbcEncFile t = fs[i];
                fs[i] = fs[i + gap];
                fs[i + gap] = t;
            }
        }
        prev = gap;
    } while (gap > 5);
    for (i = 1; i < n; i++) {
        SbcEncFile t = fs[i];
        uint32_t j = i;
        while (j > 0 && strlen(t.name) < strlen(fs[j - 1].name)) {
            fs[j] = fs[j - 1];
            j--;
        }
        fs[j] = t;
    }
}

/* `sbc c <out.sbc> [-m1|-m2|-m3] [-hn|-hr] <file>...` */
static int enc_main(int argc, char **argv)
{
    SbcBuf out;
    SbcEncFile *fs = NULL;
    uint32_t nf = 0;
    /* Header fields 1 and 2 hold the integrity/verify checksum types:
     * 0 = none, 1 = CRC16 (the vendor's default).  Only the CRC16 records are
     * reproduced so far; the other -hX digests (CRC32, Adler32, MD5, ...) are
     * rejected instead of producing an archive we cannot vouch for. */
    int i, level = 0, csum = 1, bad_csum = 0;
    int bsize_code = 5, adaptive = 1, bad_opt = 0, per_file = 0;
    int uniform = 0; /* -ub: one record per block */
    /* the vendor's default structure is -oz (its own progress line reads
     * "blocks: 1.0 MB/analysis+name"); -oa selects analysis only */
    int struct_mode = 2; /* 1 = -oa (analysis), 2 = -oz (analysis+name) */
    int cipher = 0;      /* 0 = none, else the vendor's cipher id */
    const char *pass = NULL;
    uint8_t *group = NULL;
    const char *out_path = NULL;
    FILE *of;

    memset(&out, 0, sizeof(out));
    sbc_enc_block_init();
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        size_t len = 0;
        uint8_t *data;
        struct stat st;
        if (a[0] == '-' && a[1]) {
            if (a[1] == 'b') {
                bsize_code = (int)strtol(a + 2, NULL, 10);
                if (bsize_code < 1 || bsize_code > 63 || a[2] == 0)
                    bad_opt = 1;
            } else if (a[1] == 'a' && a[2]) {
                if (a[2] == 'd')
                    adaptive = 0; /* no adaptive block size reduction */
                else if (a[2] == 'b' || a[2] == 'f')
                    adaptive = 1; /* analysis-driven (not reproduced yet) */
                else
                    bad_opt = 1;
            } else if (a[1] == 'o' && a[2] == 'n' && !a[3]) {
                /* normal: no analysis reordering, one file per block */
                per_file = 1;
                struct_mode = 0;
            } else if (a[1] == 'o' && a[2] == 'z' && !a[3]) {
                struct_mode = 2;
            } else if (a[1] == 'o' && a[2] == 'a' && !a[3]) {
                struct_mode = 1;
            } else if (a[1] == 'o' && a[2] == 'f' && !a[3]) {
                struct_mode = 3; /* partial-solid: extension groups */
            } else if (a[1] == 'o' && a[2] == 's' && !a[3]) {
                struct_mode = 4; /* solid: every file in one stream */
            } else if (a[1] == 'u' && a[2] == 'b' && !a[3]) {
                /* uniform-block: the -oz ordering and block boundaries, one
                 * record per block instead of one per file */
                struct_mode = 5;
                uniform = 1;
            } else if (a[1] == 'm' && a[2] >= '1' && a[2] <= '3')
                level = a[2] - '1';
            else if (a[1] == 'c' && a[2] && !a[3]) {
                /* the vendor's cipher letters; all six are implemented */
                if (a[2] == 'a')
                    cipher = 1;
                else if (a[2] == 'b')
                    cipher = 2;
                else if (a[2] == 'c')
                    cipher = 3;
                else if (a[2] == 'd')
                    cipher = 4;
                else if (a[2] == 's')
                    cipher = 5;
                else if (a[2] == 't')
                    cipher = 6;
                else
                    bad_opt = 1;
            } else if (a[1] == 's' && a[2]) {
                pass = a + 2;
            } else if (a[1] == 'n' && a[2] == 'p') {
                pass = a + 3; /* -np<passphrase>, as the vendor's help says */
                if (!*pass)
                    pass = NULL;
            } else if (a[1] == 'h') {
                if (a[2] == 'r')
                    csum = 1; /* CRC16 */
                else if (a[2] == 'n')
                    csum = 0; /* none */
                else if (a[2] == 'c')
                    csum = 2; /* CRC32 */
                else if (a[2] == 'a')
                    csum = 3; /* Adler32 */
                else if (a[2] == 's')
                    csum = 4; /* Sum32 */
                else if (a[2] == 'm')
                    csum = 5; /* MD5 */
                else if (a[2] == '1')
                    csum = 6; /* SHA1 */
                else if (a[2] == '2')
                    csum = 7; /* SHA256 */
                else
                    bad_csum = 1;
            } else
                bad_opt = 1; /* solid structures, ciphers, ... */
            continue;
        }
        if (!out_path) {
            out_path = a;
            continue;
        }
        data = read_file(a, &len);
        if (!data) {
            fprintf(stderr, "cannot read %s\n", a);
            free(fs);
            return 1;
        }
        if (stat(a, &st) != 0 || len > 0xFFFFFFFFu) {
            fprintf(stderr, "cannot stat %s\n", a);
            free(data);
            free(fs);
            return 1;
        }
        fs = (SbcEncFile *)realloc(fs, (nf + 1) * sizeof(*fs));
        memset(&fs[nf], 0, sizeof(fs[nf]));
        fs[nf].name = a;
        fs[nf].flag = 0;
        fs[nf].dt = sbc_dos_datetime(st.st_mtime);
        fs[nf].size = (uint32_t)len;
        fs[nf].data = data;
        nf++;
    }
    if (!out_path || nf == 0) {
        fprintf(stderr, "usage: sbc c <out.sbc> [-m1|-m2|-m3] [-hX] [-bN] "
                        "[-ad] [-on|-of|-oa|-oz|-os|-ub] <file>...\n");
        return 1;
    }
    if (bad_csum) {
        fprintf(stderr, "unknown -h switch (use -hn/-hr/-hc/-ha/-hs/-hm/-h1/-h2)\n");
        return 1;
    }
    if (bad_opt) {
        fprintf(stderr, "unsupported option (use -bN with N in 1..63, "
                        "-ad/-ab/-af, -on/-of/-oa/-oz/-os/-ub, -ca..-ct, "
                        "-s<pw> or -np<pw>)\n");
        return 1;
    }
    if (cipher && !pass) {
        fprintf(stderr, "cipher selected but no passphrase (use -s<pw>)\n");
        return 1;
    }
    /* Empty files are legal: they contribute a header entry and no payload
     * bytes, so an archive of only empty files is the header alone. */
    /* The vendor reorders the file list by name length before it chooses the
     * structure, so that is the base order every later sort starts from. */
    sbc_enc_name_len_sort(fs, nf);
    /* Then the structure sort: descending size ("Sorting files..."). */
    if (nf > 1 && struct_mode != 3) {
        uint32_t a, b;
        for (a = 1; a < nf; a++) {
            SbcEncFile t = fs[a];
            b = a;
            while (b > 0 && fs[b - 1].size < t.size) {
                fs[b] = fs[b - 1];
                b--;
            }
            fs[b] = t;
        }
    }
    if (struct_mode == 3) {
        /* -of: a stable sort by the extension hash above, and every run of
         * equal keys is one partial-solid group.  The order inside a group is
         * whatever the name-length sort above produced -- that is the vendor's
         * file-table order, and it is what makes two `.dat` files of the same
         * size come out in the vendor's order rather than the argv one. */
        uint32_t a, b;
        uint32_t *key = (uint32_t *)malloc((nf ? nf : 1) * sizeof(*key));
        if (!key)
            return 1;
        for (a = 0; a < nf; a++)
            key[a] = sbc_enc_ext_hash(fs[a].name);
        for (a = 1; a < nf; a++) {
            SbcEncFile t = fs[a];
            uint32_t k = key[a];
            b = a;
            while (b > 0 && key[b - 1] > k) {
                fs[b] = fs[b - 1];
                key[b] = key[b - 1];
                b--;
            }
            fs[b] = t;
            key[b] = k;
        }
        group = (uint8_t *)calloc(nf ? nf : 1, 1);
        if (!group) {
            free(key);
            return 1;
        }
        group[0] = 1;
        for (a = 1; a < nf; a++)
            group[a] = key[a] != key[a - 1];
        free(key);
    }
    if (struct_mode == 4) {
        /* -os: solid.  Every file joins the same stream, so the splitter is
         * free to cut inside a file and the following files reference the
         * previous one's bytes; the header is still sorted by size (the
         * vendor's progress line reads "blocks: 2.5 MB/solid"). */
        group = (uint8_t *)calloc(nf ? nf : 1, 1);
        if (!group)
            return 1;
        group[0] = 1;
    }
    if (struct_mode == 1 || struct_mode == 2 || struct_mode == 5) {
        /* -oa/-oz: the vendor's analysis sorter (0x40a9d0) decides both the
         * header order and the block groups; -oz also feeds the extension
         * hash into the similarity metric.  -ub keeps that same order. */
        SbcPssFile *pf = (SbcPssFile *)malloc((nf ? nf : 1) * sizeof(*pf));
        uint32_t *po = (uint32_t *)malloc((nf ? nf : 1) * sizeof(*po));
        SbcEncFile *ns = (SbcEncFile *)malloc((nf ? nf : 1) * sizeof(*ns));
        uint8_t *pg = (uint8_t *)calloc(nf ? nf : 1, 1);
        int rc = -1;
        if (pf && po && ns && pg) {
            for (i = 0; i < (int)nf; i++) {
                pf[i].data = fs[i].data;
                pf[i].size = fs[i].size;
                pf[i].name = fs[i].name;
            }
            rc = sbc_pss_order(pf, nf,
                               struct_mode == 2 || struct_mode == 5, po, pg);
            if (rc == 0) {
                for (i = 0; i < (int)nf; i++)
                    ns[i] = fs[po[i]];
                free(fs);
                fs = ns;
                ns = NULL;
                group = pg;
                pg = NULL;
            }
        }
        free(pf);
        free(po);
        free(ns);
        free(pg);
        if (rc != 0) {
            fprintf(stderr, "analysis ordering failed\n");
            return 1;
        }
    }
    {
        const char *e_ns = getenv("SBC_ENC_NSYMS");
        const char *e_fl = getenv("SBC_ENC_FLUSH");
        uint32_t nsyms = e_ns ? (uint32_t)atoi(e_ns) : 20;
        int flush = e_fl ? atoi(e_fl) : 4;
        /* the second-stage history lives for one archive only */
        if (level >= 1)
            sbc_enc_sub_reset(level);
        else
            sbc_enc_sub_release();
        if (sbc_enc_archive_ex(&out, fs, nf, (uint32_t)level, (uint32_t)csum,
                               nsyms, flush, (uint32_t)bsize_code,
                               adaptive, per_file, group, uniform) != 0) {
            fprintf(stderr, "encode failed\n");
            return 1;
        }
    }
    if (cipher) {
        uint8_t *enc = NULL;
        size_t encn = 0;
        if (sbc_crypt_encode(out.p, out.n, cipher, pass, &enc, &encn) != 0) {
            fprintf(stderr, "cannot set up cipher %d\n", cipher);
            return 1;
        }
        free(out.p);
        out.p = enc;
        out.n = encn;
    }
    of = fopen(out_path, "wb");
    if (!of) {
        fprintf(stderr, "cannot write %s\n", out_path);
        return 1;
    }
    fwrite(out.p, 1, out.n, of);
    fclose(of);
    printf("wrote %s (%zu bytes, %u file(s))\n", out_path, out.n, nf);
    for (i = 0; i < (int)nf; i++)
        free((void *)fs[i].data);
    free(fs);
    free(group);
    free(out.p);
    return 0;
}

/* test hook: ./sbc t2 S.bin payload.bin */
static int sbc_stage2_selftest(const char *spath, const char *ppath)
{
    size_t sn = 0, pn = 0, i, n, first = (size_t)-1;
    uint8_t *S = read_file(spath, &sn);
    uint8_t *P = read_file(ppath, &pn);
    SbcBuf out;
    int r;
    if (!S || !P) {
        fprintf(stderr, "cannot read %s / %s\n", spath, ppath);
        return 2;
    }
    memset(&out, 0, sizeof(out));
    r = sbc_enc_stage2_payload(&out, S, (uint32_t)sn);
    n = out.n < pn ? out.n : pn;
    for (i = 0; i < n; i++) {
        if (out.p[i] != P[i]) {
            first = i;
            break;
        }
    }
    if (first == (size_t)-1 && out.n != pn)
        first = n;
    printf("stage2 n=%zu payload=%zu ours=%zu %s", sn, pn, out.n,
           (first == (size_t)-1) ? "MATCH" : "DIFF");
    if (first != (size_t)-1)
        printf(" first=%zu", first);
    printf("\n");
    if (getenv("SBC_T2OUT") && out.n) {
        FILE *f = fopen(getenv("SBC_T2OUT"), "wb");
        if (f) {
            fwrite(out.p, 1, out.n, f);
            fclose(f);
        }
    }
    free(out.p);
    free(S);
    free(P);
    return (first == (size_t)-1 && r == 0) ? 0 : 1;
}

/* test hook: ./sbc t3 <param> data.bin filtered.bin  (forward mode 7) */
static int sbc_mode7_selftest(const char *dpath, const char *fpath,
                              uint32_t param)
{
    size_t dn = 0, fn = 0, i, first = (size_t)-1;
    uint8_t *D = read_file(dpath, &dn);
    uint8_t *F = read_file(fpath, &fn);
    uint8_t *R;
    int rc;
    if (!D || !F) {
        fprintf(stderr, "cannot read %s / %s\n", dpath, fpath);
        return 2;
    }
    R = (uint8_t *)malloc(dn ? dn : 1);
    if (!R)
        return 2;
    rc = sbc_enc_mode7(D, dn, param, R);
    for (i = 0; i < dn && i < fn; i++) {
        if (R[i] != F[i]) {
            first = i;
            break;
        }
    }
    if (first == (size_t)-1 && dn != fn)
        first = dn < fn ? dn : fn;
    printf("mode7 n=%zu param=%u filtered=%zu %s", dn, param, fn,
           (rc == 0 && first == (size_t)-1) ? "MATCH" : "DIFF");
    if (first != (size_t)-1)
        printf(" first=%zu (ours %02x vendor %02x)", first,
               first < dn ? R[first] : 0, first < fn ? F[first] : 0);
    printf("\n");
    free(R);
    free(D);
    free(F);
    return (rc == 0 && first == (size_t)-1) ? 0 : 1;
}

/* test hook: ./sbc t4 filtered.bin lzp.bin  (forward LZP, flag3 == 1) */
static int sbc_lzp_selftest(const char *dpath, const char *lpath)
{
    size_t dn = 0, ln = 0, on = 0, i, first = (size_t)-1;
    uint8_t *D = read_file(dpath, &dn);
    uint8_t *L = read_file(lpath, &ln);
    uint8_t *R;
    SbcLzpParams pp;
    int rc;
    if (!D || !L) {
        fprintf(stderr, "cannot read %s / %s\n", dpath, lpath);
        return 2;
    }
    R = (uint8_t *)malloc(dn + 0x400 + 8);
    if (!R)
        return 2;
    sbc_lzp_params_default(&pp);
    rc = sbc_lzp_encode(D, dn, R, dn + 0x400, &on, &pp);
    for (i = 0; i < on && i < ln; i++) {
        if (R[i] != L[i]) {
            first = i;
            break;
        }
    }
    if (first == (size_t)-1 && on != ln)
        first = on < ln ? on : ln;
    printf("lzp n=%zu out=%zu vendor=%zu %s", dn, on, ln,
           (rc == 0 && first == (size_t)-1) ? "MATCH" : "DIFF");
    if (first != (size_t)-1)
        printf(" first=%zu (ours %02x vendor %02x)", first,
               first < on ? R[first] : 0, first < ln ? L[first] : 0);
    printf("\n");
    if (getenv("SBC_T4OUT") && rc == 0 && on) {
        FILE *wf = fopen(getenv("SBC_T4OUT"), "wb");
        if (wf) {
            fwrite(R, 1, on, wf);
            fclose(wf);
        }
    }
    free(R);
    free(D);
    free(L);
    return (rc == 0 && first == (size_t)-1) ? 0 : 1;
}

static void show_banner(void)
{
    printf("SBC Archiver 0.970\n");
    printf("Copyright (C) 2000-2002 Sami\n");
    printf("pure C reimplementation by seb3773\n");
    printf("https://github.com/seb3773/sbc\n\n");
}

static void print_usage(void)
{
    show_banner();
    printf("Usage: SBC <cmd> [-<switch>] <archive[.sbc]> [<file/wildcard> <fileN> -<swN>]\n");
    printf("Macros for archive filename: %%D = Day, %%M = Month, %%Y = Year, %%L = Month in 3 letters\n\n");
    printf("<Commands>\n");
    printf("c: Create archive                        l: List files in archive\n");
    printf("x: Extract archive                       i: Info about archive or file\n");
    printf("t: Test archive integrity                v: Test and verify archive content\n\n");
    printf("<Switches> ( %% = may improve or impair compression, $ = increase/decr. Mem. use)\n");
    printf("m: Compression method [1 2 3] (%%$)       c: Cipher/encrypt archive [a b c d s t]\n");
    printf("  m1: Basic (fast)                         ca: AES/Rijndael | cd: Triple-DES\n");
    printf("  m2: Improved (default, +2MB mem. use)    cb: Blowfish     | cs: Serpent\n");
    printf("  m3: Advanced (slow, +32MB mem. use)      cc: CAST-128     | ct: Twofish\n");
    printf("b: Block size [1-63] (N+1)*512kB (%%$)    s: Secret encryption (use with -c[x])\n");
    printf("  b1: 1MB (mem. use: 6.0MB)              o: Block structure [n f a z s] (%%)\n");
    printf("  b5: 3MB (mem. use: 18.0MB, default)      on: Normal: block per file\n");
    printf("a: Adaptive block size reduct. [d b f] (%%) of: Partial-solid: sort by filename\n");
    printf("  ad: Disabled (for homogeneous data)      oa: Partial-solid: analysis\n");
    printf("  ab: Basic analysis                       oz: Partial-solid: analysis+name (def.)\n");
    printf("  af: Basic analysis + fname. (default)    os: Solid: force full blocks\n");
    printf("d: Disable internal disk cache ($)       ub: Uniform-block mode (%%)\n");
    printf("h: Integrity: Verify [n r c a s m 1 2]   r: Recurse subdirectories\n");
    printf("   checksums. The default is -hr:        p: Pathname conversion [n r]\n");
    printf("  hn: None/disabled | hr: CRC16            pn: No paths\n");
    printf("  hc: CRC32         | ha: Adler32          pr: Relative (default)\n");
    printf("  hs: Sum32         | hm: MD5            x: Exclude file(s) [<file/wildcard>]\n");
    printf("  h1: SHA1          | h2: SHA256         vc: Verify archive after creation\n");
    printf("t: Specify output path [<path>]          ic: Ignore checksum (verify) errors\n");
    printf("f: Filename conversion [c b a u l]       ns: Do not suggest unsbc <ver> call\n");
    printf("  fc: Compatible    | fb: Basic          np: Do not prompt [<passph>] (insecure)\n");
    printf("  fa: Autodetect (default)               u: Create multivolumes size of [n] kB\n");
    printf("  fu: Force uppercase| fl: Lowercase       u1420: A floppy disk sized volumes\n");
    printf("v: Verbose (display filenames)           @: Read more args. From file [<file>@]\n");
    printf("y: Auto-answer yes to all queries        @@: Add switches from \"sbc.cfg\" file\n");
    printf("\n<Modern Options>\n");
    printf("  -u, --unix       Format paths as Unix relative paths (/ slashes, lowercase)\n");
    printf("  -1, --bare       Bare listing (one path per line, script/pipe friendly)\n");
}

/* Check for path traversal: reject absolute paths, Windows drive letters, and components navigating above root */
static int is_safe_relpath(const char *path)
{
    if (!path || !path[0])
        return 0;
    if (path[0] == '/' || path[0] == '\\')
        return 0;
    if (isalpha((unsigned char)path[0]) && path[1] == ':')
        return 0;

    int depth = 0;
    const char *p = path;
    while (*p) {
        while (*p == '/' || *p == '\\')
            p++;
        if (!*p)
            break;
        const char *start = p;
        while (*p && *p != '/' && *p != '\\')
            p++;
        size_t len = (size_t)(p - start);
        if (len == 1 && start[0] == '.') {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.') {
            depth--;
            if (depth < 0)
                return 0;
        } else {
            depth++;
        }
    }
    return 1;
}

/* Format path: optionally convert to unix relative path (/ slashes, lowercase) */
static void format_path(char *dst, size_t dst_sz, const char *src, int unix_mode)
{
    if (!dst || dst_sz == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i + 1 < dst_sz) {
        char c = src[i];
        if (unix_mode) {
            if (c == '\\')
                c = '/';
            c = (char)tolower((unsigned char)c);
        }
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

/* Sanitize path for filesystem extraction: convert DOS backslashes to forward slashes, optional lowercase */
static void sanitize_extract_path(char *dst, size_t dst_sz, const char *src, int unix_mode)
{
    if (!dst || dst_sz == 0)
        return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (src[i] && i + 1 < dst_sz) {
        char c = src[i];
        if (c == '\\')
            c = '/';
        if (unix_mode)
            c = (char)tolower((unsigned char)c);
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

static int test_path_safety(void)
{
    /* Safe paths */
    if (!is_safe_relpath("hello.txt")) return 1;
    if (!is_safe_relpath("dir/sub/file.bin")) return 1;
    if (!is_safe_relpath("dir\\sub\\file.bin")) return 1;
    if (!is_safe_relpath("a/b/../c/file.txt")) return 1;

    /* Unsafe paths */
    if (is_safe_relpath(NULL)) return 1;
    if (is_safe_relpath("")) return 1;
    if (is_safe_relpath("/etc/passwd")) return 1;
    if (is_safe_relpath("\\windows\\system32")) return 1;
    if (is_safe_relpath("c:/boot.ini")) return 1;
    if (is_safe_relpath("D:\\autoexec.bat")) return 1;
    if (is_safe_relpath("../evil.txt")) return 1;
    if (is_safe_relpath("..\\evil.txt")) return 1;
    if (is_safe_relpath("dir/../../evil.txt")) return 1;
    if (is_safe_relpath("dir\\..\\..\\evil.txt")) return 1;

    return 0;
}

static int run_selftest(void)
{
    int fail = 0;
    struct stat st;
    int kb = sbc_crypto_selftest();
    int pt = test_path_safety();
    printf("crypto KAT (AES/BF/CAST/DES/3DES/Serpent/Twofish) %s\n",
           kb ? "FAIL" : "MATCH");
    printf("path traversal & zip-slip protection: %s\n", pt ? "FAIL" : "MATCH");
    fail += kb ? 1 : 0;
    fail += pt ? 1 : 0;
    fail += test_lzp_window();
    if (stat("packed_corpus", &st) == 0 && S_ISDIR(st.st_mode)) {
        fail += test_one("packed_corpus/hello-m1.sbc", "corpus/hello.txt");
        fail += test_one("packed_corpus/hello-m2.sbc", "corpus/hello.txt");
        fail += test_one("packed_corpus/hello-m3.sbc", "corpus/hello.txt");
        fail += test_one("packed_corpus/empty-m1.sbc", "corpus/empty.dat");
        fail += test_one("packed_corpus/empty-m2.sbc", "corpus/empty.dat");
        fail += test_one("packed_corpus/empty-m3.sbc", "corpus/empty.dat");
        fail += test_one("packed_corpus/pattern-m1.sbc", "corpus/pattern.bin");
        fail += test_one("packed_corpus/pattern-m2.sbc", "corpus/pattern.bin");
        fail += test_one("packed_corpus/pattern-m3.sbc", "corpus/pattern.bin");
        fail += test_one("packed_corpus/records-m1.sbc", "corpus/records.bin");
        fail += test_one("packed_corpus/records-m2.sbc", "corpus/records.bin");
        fail += test_one("packed_corpus/records-m3.sbc", "corpus/records.bin");
        fail += test_one("packed_corpus/image24-m1.sbc", "corpus/image24.raw");
        fail += test_one("packed_corpus/image24-m2.sbc", "corpus/image24.raw");
        fail += test_one("packed_corpus/image24-m3.sbc", "corpus/image24.raw");
        fail += test_one("packed_corpus/biased-m1.sbc", "corpus/biased.bin");
        fail += test_one("packed_corpus/biased-m2.sbc", "corpus/biased.bin");
        fail += test_one("packed_corpus/biased-m3.sbc", "corpus/biased.bin");
        fail += test_one("packed_corpus/zeros-m1.sbc", "corpus/zeros.bin");
        fail += test_one("packed_corpus/zeros-m2.sbc", "corpus/zeros.bin");
        fail += test_one("packed_corpus/zeros-m3.sbc", "corpus/zeros.bin");
        fail += test_one("packed_corpus/code-m1.sbc", "corpus/code.c");
        fail += test_one("packed_corpus/code-m2.sbc", "corpus/code.c");
        fail += test_one("packed_corpus/code-m3.sbc", "corpus/code.c");
        fail += test_one("packed_corpus/image7-m3.sbc", "corpus/image7.raw");
    }
    return fail ? 1 : 0;
}

static int cmd_list(const char *arc_path, int unix_paths, int bare_list)
{
    SbcExtracted *ex = NULL;
    uint32_t n = 0, i;
    size_t slen = 0, total_bytes = 0;
    uint8_t *sbc;
    int st;

    sbc = read_file(arc_path, &slen);
    if (!sbc) {
        fprintf(stderr, "cannot read %s\n", arc_path);
        return 1;
    }

    st = sbc_decode_archive(sbc, slen, &ex, &n);
    if (st != 0) {
        fprintf(stderr, "Error decoding archive %s (status %d)\n", arc_path, st);
        free(sbc);
        return 1;
    }

    if (bare_list) {
        for (i = 0; i < n; i++) {
            char p[1024];
            format_path(p, sizeof(p), ex[i].name, unix_paths);
            printf("%s\n", p);
        }
        sbc_free_extracted(ex, n);
        free(sbc);
        return 0;
    }

    show_banner();
    printf("Processing archive: \"%s\"...\n", arc_path);
    printf("Filename                Size       Date       Time     Attr.\n");
    printf("=============================================================\n");
    for (i = 0; i < n; i++) {
        char p[1024];
        format_path(p, sizeof(p), ex[i].name, unix_paths);
        uint32_t dt = ex[i].dt;
        uint32_t date = dt >> 16;
        uint32_t time = dt & 0xFFFF;
        int year = (int)(((date >> 9) & 0x7F) + 1980);
        int month = (int)((date >> 5) & 0x0F);
        int day = (int)(date & 0x1F);
        int hour = (int)((time >> 11) & 0x1F);
        int min = (int)((time >> 5) & 0x3F);
        int sec = (int)((time & 0x1F) * 2);
        total_bytes += ex[i].len;
        if (year >= 1980 && year <= 2100 && month >= 1 && month <= 12 && day >= 1 && day <= 31) {
            printf("%-20s %10zu %02d/%02d/%04d   %02d:%02d:%02d     A\n",
                   p, ex[i].len, month, day, year, hour, min, sec);
        } else {
            printf("%-20s %10zu\n", p, ex[i].len);
        }
    }
    printf("\nThe whole archive contains %u files, %zu bytes of original data.\n", n, total_bytes);
    sbc_free_extracted(ex, n);
    free(sbc);
    return 0;
}

static int cmd_test(const char *arc_path)
{
    SbcExtracted *ex = NULL;
    uint32_t n = 0;
    size_t slen = 0;
    uint8_t *sbc;
    int st;

    sbc = read_file(arc_path, &slen);
    if (!sbc) {
        fprintf(stderr, "cannot read %s\n", arc_path);
        return 1;
    }
    show_banner();
    printf("Processing archive: \"%s\"...\n", arc_path);
    printf("Checksums (integrity/verify): CRC16/CRC16...\n");
    printf("Testing archive blocks...\n");

    st = sbc_decode_archive(sbc, slen, &ex, &n);
    sbc_free_extracted(ex, n);
    free(sbc);
    if (st == 0) {
        printf("Archive testing finished. No media errors were detected.\n");
        return 0;
    } else {
        printf("Archive testing failed. Errors detected.\n");
        return 1;
    }
}

static int cmd_extract(const char *arc_path, const char *dest_dir, int raw_compat, int unix_paths)
{
    SbcExtracted *ex = NULL;
    uint32_t n = 0, i;
    size_t slen = 0, total_bytes = 0;
    uint8_t *sbc;
    int st;

    sbc = read_file(arc_path, &slen);
    if (!sbc) {
        fprintf(stderr, "cannot read %s\n", arc_path);
        return 1;
    }
    if (!raw_compat) {
        show_banner();
        printf("Processing archive: \"%s\"...\n", arc_path);
    }

    st = sbc_decode_archive(sbc, slen, &ex, &n);
    if (raw_compat) {
        printf("st=%d n=%u\n", st, n);
    }
    if (st != 0) {
        if (!raw_compat)
            fprintf(stderr, "Error decoding archive %s (status %d)\n", arc_path, st);
        free(sbc);
        return 1;
    }

    for (i = 0; i < n; i++)
        total_bytes += ex[i].len;

    if (!raw_compat) {
        printf("Archive contains %u file(s), total of %zu bytes.\n", n, total_bytes);
        printf("Extracting, please wait...\n");
    }

    for (i = 0; i < n; i++) {
        char clean_name[1024];
        char path[1200];
        FILE *of;
        size_t k;

        /* Validate against path traversal attacks (zip-slip) */
        if (!is_safe_relpath(ex[i].name)) {
            fprintf(stderr, "Security warning: skipping unsafe path traversal: %s\n", ex[i].name);
            continue;
        }

        sanitize_extract_path(clean_name, sizeof(clean_name), ex[i].name, unix_paths);

        if (dest_dir) {
            snprintf(path, sizeof(path), "%s/%s", dest_dir, clean_name);
        } else {
            snprintf(path, sizeof(path), "%s", clean_name);
        }
        for (k = 0; path[k]; k++) {
            if (path[k] == '/') {
                path[k] = 0;
                sbc_mkdir(path);
                path[k] = '/';
            }
        }
        of = fopen(path, "wb");
        if (of) {
            if (ex[i].len)
                fwrite(ex[i].data, 1, ex[i].len, of);
            fclose(of);
        }
        if (raw_compat) {
            printf("  %s len=%zu\n", ex[i].name, ex[i].len);
        } else {
            char display_name[1024];
            format_path(display_name, sizeof(display_name), ex[i].name, unix_paths);
            printf("  extracted: %s (%zu bytes)\n", display_name, ex[i].len);
        }
    }
    if (!raw_compat) {
        printf("* Output: %zu bytes.\n", total_bytes);
    }

    sbc_free_extracted(ex, n);
    free(sbc);
    if (sbc_shadow_cfg)
        printf("PPM shadow: %zu block(s), %zu identical, %zu different\n",
               sbc_ps.blocks, sbc_ps.ok, sbc_ps.bad);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage();
        return 0;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "/?") == 0 ||
        strcmp(argv[1], "help") == 0) {
        print_usage();
        return 0;
    }
    if (strcmp(argv[1], "--selftest") == 0 || strcmp(argv[1], "--test") == 0) {
        return run_selftest();
    }
    if (argc >= 3 && strcmp(argv[1], "subtest") == 0)
        return sbc_enc_sub_selftest(argv[2]);
    if (argc >= 4 && strcmp(argv[1], "t2") == 0)
        return sbc_stage2_selftest(argv[2], argv[3]);
    if (argc >= 5 && strcmp(argv[1], "t3") == 0)
        return sbc_mode7_selftest(argv[3], argv[4],
                                  (uint32_t)strtoul(argv[2], NULL, 0));
    if (argc >= 3 && strcmp(argv[1], "t9") == 0) {
        /* ./sbc t9 data.bin -- simple filter report (state machine outcome) */
        size_t dn = 0;
        uint8_t *D = read_file(argv[2], &dn);
        uint8_t *R = (uint8_t *)malloc(dn ? dn : 1);
        int rc;
        if (!D || !R)
            return 2;
        rc = sbc_enc_mode0_simple(D, dn, R);
        printf("simple n=%zu rc=%d final_state=%d trial_exhausted=%d "
               "identical=%d\n", dn, rc, sbc_enc_m0_state, sbc_enc_m0_trial,
               dn && memcmp(D, R, dn) == 0);
        free(R);
        free(D);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "tc") == 0) {
        /* ./sbc tc data.bin -- the mode-4 ctrl chooser (0x40cb80) on one
         * segment, printed as the vendor's internal word and the ctrl the
         * record would carry (the chooser's word shifted left by one). */
        size_t dn = 0;
        uint8_t *D = read_file(argv[2], &dn);
        uint32_t c;
        if (!D)
            return 2;
        c = sbc_enc_m4_ctrl(D, dn);
        printf("n=%zu ctrl=%08x header=%08x\n", dn, c, c << 1);
        free(D);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "t11") == 0) {
        /* ./sbc t11 data.bin -- the 0x443e20 width estimator on one buffer */
        size_t dn = 0;
        uint8_t *D = read_file(argv[2], &dn);
        int w;
        if (!D)
            return 2;
        w = sbc_enc_m7_search(D, dn);
        printf("m7 width search n=%zu width=%d\n", dn, w);
        free(D);
        return 0;
    }
    if (argc >= 4 && strcmp(argv[1], "t4") == 0)
        return sbc_lzp_selftest(argv[2], argv[3]);
    if (argc >= 7 && strcmp(argv[1], "t8") == 0) {
        /* ./sbc t8 <level> <mode> <arg> data.bin outprefix
         *   arg = mode-7 width for mode 7, the record ctrl for mode 4 */
        size_t dn = 0;
        uint8_t *D = read_file(argv[5], &dn);
        SbcEncBlock b;
        int level = atoi(argv[2]), mode = atoi(argv[3]);
        uint32_t m7 = (uint32_t)strtoul(argv[4], NULL, 0);
        char path[1200];
        FILE *f;
        if (!D)
            return 2;
        if (sbc_enc_pipeline(&b, D, dn, level, mode, m7,
                             mode == 4 ? m7 : 0)) {
            fprintf(stderr, "pipeline failed\n");
            return 2;
        }
        snprintf(path, sizeof(path), "%s_f.bin", argv[6]);
        if ((f = fopen(path, "wb")) != NULL) {
            fwrite(b.filter, 1, b.flen, f);
            fclose(f);
        }
        snprintf(path, sizeof(path), "%s_l.bin", argv[6]);
        if ((f = fopen(path, "wb")) != NULL) {
            fwrite(b.lzp, 1, b.lzplen, f);
            fclose(f);
        }
        snprintf(path, sizeof(path), "%s_b.bin", argv[6]);
        if ((f = fopen(path, "wb")) != NULL) {
            fwrite(b.bwt, 1, b.bwtlen, f);
            fclose(f);
        }
        snprintf(path, sizeof(path), "%s_p.bin", argv[6]);
        if ((f = fopen(path, "wb")) != NULL) {
            fwrite(b.payload.p, 1, b.payload.n, f);
            fclose(f);
        }
        printf("flag3=%d vlq=%zu primary=%u plen=%zu filter=%zu lzp=%zu\n",
               b.flag3, b.bwtlen, b.primary, b.payload.n, b.flen, b.lzplen);
        sbc_enc_block_free(&b);
        free(D);
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "t0") == 0) {
        /* ./sbc t0 data.bin -- adaptive mode-0 round trip, both instances.
         * Encoder and decoder share sbc_m0adv.h, so this catches a broken
         * controller in either direction. */
        size_t dn = 0, i;
        uint8_t *D = read_file(argv[2], &dn);
        const SbcM0Params *ps[2] = { &sbc_m0_params_l1, &sbc_m0_params_l2 };
        int k, fail = 0;
        if (!D)
            return 2;
        for (k = 0; k < 2; k++) {
            uint8_t *res = sbc_m0_adaptive(D, dn, ps[k], 1);
            uint8_t *back = res ? sbc_m0_adaptive(res, dn, ps[k], 0) : NULL;
            if (!res || !back) {
                printf("inst%d: REFUSED (n=%zu)\n", k, dn);
                free(res);
                free(back);
                fail = 1;
                continue;
            }
            for (i = 0; i < dn && back[i] == D[i]; i++)
                ;
            printf("inst%d: roundtrip %s n=%zu\n", k,
                   i == dn ? "OK" : "DIFF", dn);
            if (i != dn) {
                printf("  first=%zu (got %02x want %02x)\n", i, back[i],
                       D[i]);
                fail = 1;
            }
            free(res);
            free(back);
        }
        free(D);
        return fail;
    }
    if (argc >= 5 && strcmp(argv[1], "t7") == 0) {
        /* ./sbc t7 <level> data.bin filtered.bin  (forward mode 0) */
        size_t dn = 0, fn = 0, i, first = (size_t)-1;
        uint8_t *D = read_file(argv[3], &dn);
        uint8_t *F = read_file(argv[4], &fn);
        uint8_t *R = (uint8_t *)malloc(dn ? dn : 1);
        int level = atoi(argv[2]), rc;
        if (!D || !F || !R)
            return 2;
        if (level <= 0)
            rc = sbc_enc_mode0_simple(D, dn, R);
        else if (level == 1)
            rc = sbc_enc_mode0_advanced(D, dn, 24, 3, 768, R);
        else
            rc = sbc_enc_mode0_advanced(D, dn, 53, 10, 600, R);
        for (i = 0; i < dn && i < fn; i++)
            if (R[i] != F[i]) {
                first = i;
                break;
            }
        printf("mode0 level=%d n=%zu vendor=%zu rc=%d %s", level, dn, fn, rc,
               (first == (size_t)-1 && dn == fn) ? "MATCH" : "DIFF");
        if (first != (size_t)-1)
            printf(" first=%zu (ours %02x vendor %02x)", first, R[first],
                   first < fn ? F[first] : 0);
        printf("\n");
        free(R);
        free(D);
        free(F);
        return (first == (size_t)-1 && dn == fn) ? 0 : 1;
    }
    if (argc >= 5 && strcmp(argv[1], "t6") == 0) {
        /* ./sbc t6 lzp.bin vendor_bwt.bin primary  (forward BWT check) */
        size_t sn = 0, ln = 0, i, first = (size_t)-1;
        uint8_t *S = read_file(argv[2], &sn);
        uint8_t *L = read_file(argv[3], &ln);
        uint32_t prim = 0, want = (uint32_t)strtoul(argv[4], NULL, 0);
        uint8_t *R = sbc_bwt(S, sn, &prim);
        if (!S || !L || !R)
            return 2;
        for (i = 0; i < sn && i < ln; i++)
            if (R[i] != L[i]) {
                first = i;
                break;
            }
        printf("bwt n=%zu prim=%u (want %u) %s\n", sn, prim, want,
               (first == (size_t)-1 && sn == ln && prim == want) ? "MATCH"
                                                                 : "DIFF");
        if (getenv("SBC_T6OUT")) {
            FILE *wf = fopen(getenv("SBC_T6OUT"), "wb");
            if (wf) {
                fwrite(R, 1, sn, wf);
                fclose(wf);
            }
        }
        return (first == (size_t)-1 && sn == ln && prim == want) ? 0 : 1;
    }
    if (argc >= 5 && strcmp(argv[1], "t5") == 0) {
        size_t sn = 0, ln = 0, i, first = (size_t)-1;
        uint8_t *S = read_file(argv[2], &sn);
        uint8_t *L = read_file(argv[4], &ln);
        uint8_t *R = (uint8_t *)malloc(sn ? sn : 1);
        uint32_t prim = (uint32_t)strtoul(argv[3], NULL, 0);
        if (!S || !L || !R)
            return 2;
        if (sbc_ibwt(S, sn, prim, R) != 0)
            return 2;
        for (i = 0; i < sn && i < ln; i++)
            if (R[i] != L[i]) {
                first = i;
                break;
            }
        printf("ibwt n=%zu prim=%u %s", sn, prim,
               first == (size_t)-1 && sn == ln ? "MATCH" : "DIFF");
        if (first != (size_t)-1)
            printf(" first=%zu (ours %02x want %02x)", first, R[first],
                   first < ln ? L[first] : 0);
        printf("\n");
        return first == (size_t)-1 && sn == ln ? 0 : 1;
    }

    if (getenv("SBC_PPMTEST"))
        sbc_ps_enable();

    /* If command is create 'c', delegate to enc_main directly */
    if (strcmp(argv[1], "c") == 0) {
        if (argc < 3) {
            fprintf(stderr, "sbc: missing archive or files to create\n");
            return 1;
        }
        return enc_main(argc - 1, argv + 1);
    }

    {
        int opt_unix = 0;
        int opt_bare = 0;
        const char *pos_args[64];
        int n_pos = 0;
        int k;

        /* Parse flags and positional arguments */
        for (k = 1; k < argc; k++) {
            const char *arg = argv[k];
            if (strcmp(arg, "-u") == 0 || strcmp(arg, "--unix") == 0) {
                opt_unix = 1;
            } else if (strcmp(arg, "-1") == 0 || strcmp(arg, "--bare") == 0) {
                opt_bare = 1;
            } else if (strcmp(arg, "-u1") == 0 || strcmp(arg, "-1u") == 0) {
                opt_unix = 1;
                opt_bare = 1;
            } else {
                if (n_pos < 64)
                    pos_args[n_pos++] = arg;
            }
        }

        if (n_pos == 0) {
            print_usage();
            return 0;
        }

        /* Standard SBC CLI commands */
        if (strcmp(pos_args[0], "l") == 0 || strcmp(pos_args[0], "v") == 0 || strcmp(pos_args[0], "i") == 0) {
            if (n_pos < 2) {
                fprintf(stderr, "sbc: missing archive to list\n");
                return 1;
            }
            return cmd_list(pos_args[1], opt_unix, opt_bare);
        }
        if (strcmp(pos_args[0], "t") == 0) {
            if (n_pos < 2) {
                fprintf(stderr, "sbc: missing archive to test\n");
                return 1;
            }
            return cmd_test(pos_args[1]);
        }
        if (strcmp(pos_args[0], "x") == 0 || strcmp(pos_args[0], "e") == 0) {
            if (n_pos < 2) {
                fprintf(stderr, "sbc: missing archive to extract\n");
                return 1;
            }
            return cmd_extract(pos_args[1], n_pos >= 3 ? pos_args[2] : NULL, 0, opt_unix);
        }

        /* If bare listing was requested directly: ./sbc -1 archive.sbc */
        if (opt_bare) {
            return cmd_list(pos_args[0], opt_unix, 1);
        }

        /* Fallback: if pos_args[0] is an archive path (e.g. from tests verify_all.py or tail_repro.py) */
        {
            FILE *fp = fopen(pos_args[0], "rb");
            if (fp) {
                fclose(fp);
                return cmd_extract(pos_args[0], n_pos >= 2 ? pos_args[1] : NULL, 1, opt_unix);
            }
        }

        fprintf(stderr, "sbc: unknown command or file '%s'\n\n", pos_args[0]);
        print_usage();
        return 1;
    }
}
