/*
 * SBC encoder core -- mirror image of the decoder in sbc.c.
 *
 * The range coder here is the exact symmetric counterpart of sbc_rc_get /
 * sbc_rc_decode: same normalisation conditions, same order, so a stream written
 * by sbc_wrc_enc() is read back bit-for-bit by sbc_rc_decode().
 */

#include "sbc_hash.h"

typedef struct {
    uint8_t *p;
    size_t n, cap;
    int err;
} SbcBuf;

static void sbc_buf_reserve(SbcBuf *b, size_t extra)
{
    size_t need = b->n + extra;
    if (need <= b->cap)
        return;
    {
        size_t cap = b->cap ? b->cap : 4096;
        uint8_t *np;
        while (cap < need)
            cap *= 2;
        np = (uint8_t *)realloc(b->p, cap);
        if (!np) {
            b->err = 1;
            return;
        }
        b->p = np;
        b->cap = cap;
    }
}

static void sbc_buf_put(SbcBuf *b, uint8_t v)
{
    sbc_buf_reserve(b, 1);
    if (b->err)
        return;
    b->p[b->n++] = v;
}

static void sbc_buf_write(SbcBuf *b, const void *p, size_t n)
{
    sbc_buf_reserve(b, n);
    if (b->err)
        return;
    memcpy(b->p + b->n, p, n);
    b->n += n;
}

/* ---- range encoder ---- */

typedef struct {
    SbcBuf *out;
    uint32_t low, range;
} SbcWRC;

static void sbc_wrc_init(SbcWRC *w, SbcBuf *out)
{
    w->out = out;
    w->low = 0;
    w->range = 0xFFFFFFFFu;
}

static FILE *sbc_wrclog_fp(void)
{
    static FILE *f;
    static int init;
    if (!init) {
        const char *p = getenv("SBC_WRCLOG");
        init = 1;
        if (p)
            f = fopen(p, "w");
    }
    return f;
}

static void sbc_wrc_enc(SbcWRC *w, uint32_t start, uint32_t freq, uint32_t tot)
{
    {
        FILE *lf = sbc_wrclog_fp();
        if (lf)
            fprintf(lf, "%u %u %u\n", tot, start, freq);
    }
    if (tot == 0 || freq == 0) {
        w->out->err = 1;
        return;
    }
    w->range /= tot;
    w->low += start * w->range;
    w->range *= freq;
    for (;;) {
        if ((w->low ^ (w->low + w->range)) <= 0x00FFFFFFu) {
            sbc_buf_put(w->out, (uint8_t)(w->low >> 24));
            w->low <<= 8;
            w->range <<= 8;
            continue;
        }
        if (w->range <= 0x3FFFu) {
            w->range = ((uint32_t)(-(int32_t)w->low)) & 0x3FFFu;
            sbc_buf_put(w->out, (uint8_t)(w->low >> 24));
            w->low <<= 8;
            w->range <<= 8;
            continue;
        }
        break;
    }
}

static void sbc_wrc_flush(SbcWRC *w, int nbytes)
{
    int i;
    for (i = 0; i < nbytes; i++) {
        sbc_buf_put(w->out, (uint8_t)(w->low >> 24));
        w->low <<= 8;
    }
}

static void sbc_wrc_u(SbcWRC *w, uint32_t n, uint32_t v)
{
    sbc_wrc_enc(w, v, 1, n);
}

static void sbc_wrc_large(SbcWRC *w, uint32_t n, uint32_t v)
{
    if (n <= 0x4000u) {
        sbc_wrc_u(w, n, v);
        return;
    }
    if (n <= 0x4000000u) {
        sbc_wrc_u(w, (n >> 13) + 1, v >> 13);
        sbc_wrc_u(w, 0x2000u, v & 0x1FFFu);
        return;
    }
    sbc_wrc_u(w, (n >> 26) + 1, v >> 26);
    sbc_wrc_u(w, 0x2000u, (v >> 13) & 0x1FFFu);
    sbc_wrc_u(w, 0x2000u, v & 0x1FFFu);
}

/* Inverse of sbc_decode_int(): value v (< mx) is written the way the decoder
 * reconstructs it: hi = 0 for v in {0,1}, else 1<<b with b = bitlen(v)-1. */
static void sbc_wrc_int(SbcWRC *w, uint32_t mx, uint32_t v)
{
    int k = sbc_bitlen((mx - 1u) & 0xFFFFFFFFu);
    if (k <= 1) {
        sbc_wrc_large(w, 1u << k, v);
        return;
    }
    if (v < 2) {
        sbc_wrc_u(w, (uint32_t)k, 0);
        sbc_wrc_large(w, 2, v);
    } else {
        int b = sbc_bitlen(v) - 1;
        sbc_wrc_u(w, (uint32_t)k, (uint32_t)b);
        sbc_wrc_large(w, 1u << b, v - (1u << b));
    }
}

static void sbc_wrc_int_maxbits(SbcWRC *w, uint32_t nbits, uint32_t v)
{
    if (nbits <= 1) {
        sbc_wrc_large(w, 1u << nbits, v);
        return;
    }
    if (v < 2) {
        sbc_wrc_u(w, nbits, 0);
        sbc_wrc_large(w, 2, v);
    } else {
        int b = sbc_bitlen(v) - 1;
        sbc_wrc_u(w, nbits, (uint32_t)b);
        sbc_wrc_large(w, 1u << b, v - (1u << b));
    }
}

/* ---- encoder-side versions of the adaptive models ---- */

typedef struct {
    SbcWRC *wrc;
    uint32_t *freq;
    uint32_t nsyms;
    uint32_t total;
    uint32_t inc;
    uint32_t cap_freq;
    uint32_t cap_tot;
} SbcWExtra;

static void sbc_wex_init(SbcWExtra *ex, SbcWRC *wrc, uint32_t nsyms,
                         uint32_t inc, uint32_t cap_freq, uint32_t cap_tot,
                         uint32_t boost0)
{
    uint32_t i;
    memset(ex, 0, sizeof(*ex));
    ex->wrc = wrc;
    ex->inc = inc;
    ex->cap_freq = cap_freq;
    ex->cap_tot = cap_tot;
    ex->nsyms = nsyms;
    ex->total = nsyms;
    ex->freq = (uint32_t *)malloc(nsyms * sizeof(uint32_t));
    for (i = 0; i < nsyms; i++)
        ex->freq[i] = 1;
    if (boost0) {
        ex->freq[0] += boost0;
        ex->total += boost0;
    }
}

static void sbc_wex_free(SbcWExtra *ex)
{
    free(ex->freq);
    ex->freq = NULL;
}

static void sbc_wex_rescale(SbcWExtra *ex)
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

/* Mirror of sbc_extra_decode_sym(). */
static void sbc_wex_sym(SbcWExtra *ex, uint32_t sym)
{
    uint32_t acc = 0, i;
    if (sym >= ex->nsyms)
        sym = ex->nsyms - 1;
    while (ex->total > ex->cap_tot)
        sbc_wex_rescale(ex);
    for (i = 0; i < sym; i++)
        acc += ex->freq[i];
    sbc_wrc_enc(ex->wrc, acc, ex->freq[sym], ex->total);
    ex->freq[sym] += ex->inc;
    ex->total += ex->inc;
    if (ex->freq[sym] > ex->cap_freq)
        sbc_wex_rescale(ex);
}

/* Mirror of sbc_extra_k()/sbc_decode_extra(). */
static void sbc_wex_k(SbcWExtra *ex, uint32_t v)
{
    if (v < 2) {
        sbc_wex_sym(ex, 0);
        sbc_wrc_u(ex->wrc, 2, v);
        return;
    }
    {
        int k = sbc_bitlen(v) - 1;
        sbc_wex_sym(ex, (uint32_t)k);
        sbc_wrc_large(ex->wrc, 1u << k, v - (1u << k));
    }
}

typedef struct {
    SbcWExtra extra;
    uint32_t last;
    uint32_t count;
    uint32_t c12;
} SbcWSize;

static void sbc_ws_init(SbcWSize *sm, SbcWExtra *tpl)
{
    sm->extra = *tpl;
    sm->last = 0;
    sm->count = 0;
    sm->c12 = 0;
}

/* Mirror of sbc_sm_decode()/sbc_sm_update(). */
static void sbc_ws_encode(SbcWSize *sm, uint32_t neu)
{
    uint32_t d = neu - sm->last;
    uint32_t zz, coded;
    if (d & 0x80000000u)
        zz = (((~d) & 0xFFFFFFFFu) << 1) | 1u;
    else
        zz = d << 1;
    coded = (sm->count < sm->c12) ? zz : neu;
    sbc_wex_k(&sm->extra, coded);
    sm->last = neu;
    sm->c12 = (sm->c12 >> 2) + (neu >> 1);
    sm->count = (sm->count >> 2) + (zz >> 1);
}

/* ---- BWT: the vendor's rotation sort (FORMAT 5, ENCODER 6.8) ----------
 *
 * `sbc_bwt` mirrors the vendor's sorter rather than doing a canonical suffix
 * sort: `primary` on an exactly periodic block only comes out right when the
 * same passes run in the same order.
 *
 *   1. `0x421ac0`: a stable first-byte bucket pass.  A single bucket holding
 *      all n rotations returns unsorted (the all-equal case).
 *   2. Per segment, the skip pre-check: if every element is preceded by the
 *      same byte and none of them is 0, the segment is left alone -- its
 *      order cannot change the BWT column, which only depends on those bytes.
 *   3. `0x423010`: Bentley-McIlroy three-way quicksort, keys equal to the
 *      pivot gathered at both ends and vecswapped to the middle, with the
 *      pivot parked in a[hi] (the spare slot) during the partition.  Cutoff
 *      11 goes to an insertion sort, the pivot is the median of
 *      a[lo]/a[mid]/a[hi-1] below 36 elements and a ninther above.  Ties
 *      follow the vendor's priority: a[lo] wins over a[mid], then a[hi-1]
 *      wins over either -- on an all-equal segment the pivot *slot* decides
 *      the permutation, so a plain median is not equivalent.
 *   4. The equal band recurses one byte deeper, and from depth 6 it switches
 *      to the vendor's 4-byte-key path (word keys at the depth, equal bands
 *      two bytes deeper -- the step must be recomputed when the path
 *      changes, or the depth lands on the last odd byte of a periodic block).
 *
 * `sbc_bwt_seg` iterates on the largest of the three pieces and recurses on
 * the other two, so the stack stays O(log n) even for periodic input where
 * the equal band is the whole segment at every depth.
 */

typedef struct {
    const uint8_t *b;      /* s + s[:min(n,0x1000)] */
    uint32_t blen;         /* its length */
    uint32_t end;          /* vendor compare limit (exclusive byte index) */
    uint32_t n;            /* rotation count (the wrap period) */
    uint32_t per;          /* smallest period of the input, n when none */
} SbcBwtBuf;

/* The vendor normalises an index past the compare limit by subtracting n
 * (0x424e1d: `cmp limit,%eax / jl / sub n`), so a rotation near the end of the
 * doubled buffer keeps comparing its true cyclic bytes instead of the zeros
 * after it.  Without this the 4-byte keys of the last few rotations pick up
 * the padding and an all-equal band splits where the vendor's does not. */
static uint8_t sbc_bb(const SbcBwtBuf *k, uint32_t i)
{
    if (i >= k->end)
        i -= k->n;
    return i < k->blen ? k->b[i] : 0;
}

/* byte key / 4-byte big-endian word key; returns -1, 0 or 1 */
static int sbc_bwt_kcmp(const SbcBwtBuf *k, uint32_t x, uint32_t y,
                        uint32_t d, int is4)
{
    int i, nb = is4 ? 4 : 1;
    for (i = 0; i < nb; i++) {
        uint8_t p = sbc_bb(k, x + d + (uint32_t)i);
        uint8_t q = sbc_bb(k, y + d + (uint32_t)i);
        if (p != q)
            return p < q ? -1 : 1;
    }
    return 0;
}

/* full byte compare over [d, limit) -- the insertion handler's comparator */
static int sbc_bwt_cmp1(const SbcBwtBuf *k, uint32_t x, uint32_t y,
                        uint32_t d, uint32_t limit)
{
    uint32_t i;
    for (i = d; i < limit; i++) {
        uint8_t p = sbc_bb(k, x + i), q = sbc_bb(k, y + i);
        if (p != q)
            return p < q ? -1 : 1;
    }
    return 0;
}

/* stable insertion sort; the vendor compares at most end - max(a[i]) - 1 */
static void sbc_bwt_ins(uint32_t *a, uint32_t lo, uint32_t hi, uint32_t d,
                        const SbcBwtBuf *k)
{
    uint32_t i, m, limit;
    if (hi - lo < 2)
        return;
    limit = k->end;
    for (m = lo; m < hi; m++) {
        uint32_t e = k->end > a[m] ? k->end - a[m] : 0;
        if (e < limit)
            limit = e;
    }
    if (limit > 0)
        limit--;
    for (i = lo + 1; i < hi; i++) {
        uint32_t x = a[i], j = i;
        while (j > lo && limit > d &&
               sbc_bwt_cmp1(k, a[j - 1], x, d, limit) > 0) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = x;
    }
}

/* median of three slots by key at depth d, with the vendor's tie priority:
 * x wins when it ties y, then z wins when it ties either -- the *slot* the
 * pivot comes from decides the tie order, so equal keys cannot use a plain
 * median.  (0x423138 / 0x4231a0 ladder) */
static uint32_t sbc_bwt_med3(const uint32_t *a, const SbcBwtBuf *k, uint32_t x,
                             uint32_t y, uint32_t z, uint32_t d, int is4)
{
    int xy = sbc_bwt_kcmp(k, a[x], a[y], d, is4);
    int zx, zy;
    if (xy == 0)
        return x;
    zx = sbc_bwt_kcmp(k, a[z], a[x], d, is4);
    if (zx == 0)
        return z;
    zy = sbc_bwt_kcmp(k, a[z], a[y], d, is4);
    if (zy == 0)
        return z;
    if (xy < 0)
        return zy > 0 ? y : (zx < 0 ? x : z);
    return zy < 0 ? y : (zx < 0 ? z : x);
}

static void sbc_bwt_swapn(uint32_t *a, uint32_t i, uint32_t j, uint32_t n)
{
    while (n--) {
        uint32_t t = a[i];
        a[i++] = a[j];
        a[j++] = t;
    }
}

/* the vendor's skip pre-check (0x423010 / 0x424f90 head) */
static int sbc_bwt_skip(const uint32_t *a, uint32_t lo, uint32_t hi,
                        const SbcBwtBuf *k, uint32_t n)
{
    uint32_t i, first;
    if (hi - lo < 2)
        return 1;
    if (a[lo] == 0)
        return 0;
    first = k->b[a[lo] - 1];
    for (i = lo + 1; i < hi; i++) {
        if (a[i] == 0 || k->b[a[i] - 1] != first)
            return 0;
    }
    (void)n;
    return 1;
}

/* one 3-way partition; fills the three band sizes */
static void sbc_bwt_part(uint32_t *a, uint32_t lo, uint32_t hi, uint32_t d,
                         const SbcBwtBuf *k, int is4, uint32_t *p_less,
                         uint32_t *p_eq, uint32_t *p_greater)
{
    uint32_t size = hi - lo;
    uint32_t p, spare = hi, eqL, eqR, i, j, carry, x, k1, k2;
    uint8_t v8 = 0;
    uint32_t v4 = 0;
    int nb = is4 ? 4 : 1, t;

    if (size < 36) {
        p = sbc_bwt_med3(a, k, lo, lo + size / 2, hi - 1, d, is4);
    } else {
        uint32_t s = size / 8;
        p = sbc_bwt_med3(
            a, k,
            sbc_bwt_med3(a, k, lo, lo + s, lo + 2 * s, d, is4),
            sbc_bwt_med3(a, k, lo + size / 2 - s, lo + size / 2,
                         lo + size / 2 + s, d, is4),
            sbc_bwt_med3(a, k, hi - 1 - 2 * s, hi - 1 - s, hi - 1, d, is4),
            d, is4);
    }
    for (t = 0; t < nb; t++) {
        uint8_t c = sbc_bb(k, a[p] + d + (uint32_t)t);
        if (is4)
            v4 = (v4 << 8) | c;
        else
            v8 = c;
    }
    x = a[lo];
    a[lo] = a[p];
    a[p] = x;
    eqL = lo + 1;
    eqR = hi - 1;
    carry = a[lo];
    a[lo] = a[spare];
    a[spare] = carry;
    i = lo;
    j = spare;
    for (;;) {
        x = a[i];
        a[i] = carry;
        a[j] = x;
        j--;
        i++;
        if (i > j)
            break;
        while (i <= j) {
            uint32_t c = 0;
            int q, eq;
            for (q = 0; q < nb; q++) {
                uint8_t b = sbc_bb(k, a[i] + d + (uint32_t)q);
                c = (c << 8) | b;
            }
            eq = is4 ? (c == v4) : ((c & 0xFF) == v8);
            if (is4 ? (c > v4) : ((c & 0xFF) > v8))
                break;
            if (eq) {
                uint32_t tmp = a[eqL];
                a[eqL] = a[i];
                a[i] = tmp;
                eqL++;
            }
            i++;
        }
        while (i <= j) {
            uint32_t c = 0;
            int q, eq;
            for (q = 0; q < nb; q++) {
                uint8_t b = sbc_bb(k, a[j] + d + (uint32_t)q);
                c = (c << 8) | b;
            }
            eq = is4 ? (c == v4) : ((c & 0xFF) == v8);
            if (is4 ? (c < v4) : ((c & 0xFF) < v8))
                break;
            if (eq) {
                uint32_t tmp = a[eqR];
                a[eqR] = a[j];
                a[j] = tmp;
                eqR--;
            }
            j--;
        }
        if (j < i)
            break;
        carry = a[j];
    }
    k1 = i - eqL < eqL - lo ? i - eqL : eqL - lo;
    sbc_bwt_swapn(a, lo, i - k1, k1);
    k2 = (hi - eqR) - 1;
    if (eqR - j < k2)
        k2 = eqR - j;
    sbc_bwt_swapn(a, i, hi - k2, k2);
    *p_less = i - eqL;
    *p_eq = (eqL - lo) + (hi - eqR) - 1;
    *p_greater = eqR - j;
}

static void sbc_bwt_seg(uint32_t *a, uint32_t lo, uint32_t hi, uint32_t d,
                        const SbcBwtBuf *k, int is4, uint32_t n);

/* sort [lo,hi) at depth d; `is4` selects the vendor's 4-byte-key path */
static void sbc_bwt_seg(uint32_t *a, uint32_t lo, uint32_t hi, uint32_t d,
                        const SbcBwtBuf *k, int is4, uint32_t n)
{
    for (;;) {
        uint32_t size = hi - lo, less, eq, greater;
        /* recomputed per iteration: the equal band's step changes from 1 to 2
         * when it moves to the 4-byte-key path */
        uint32_t step = is4 ? 2 : 1;
        /* A p-periodic input repeats its keys every p bytes, so a band that
         * survived to depth p is a set of identical rotations: every deeper
         * partition would be all-equal and leave the order alone (see the
         * carousel trace in FORMAT 5).  Stopping here keeps exactly periodic
         * blocks linear-ish instead of running one no-op pass per byte. */
        if (d >= k->per)
            return;
        if (sbc_bwt_skip(a, lo, hi, k, n))
            return;
        if (size < 11) {
            sbc_bwt_ins(a, lo, hi, d, k);
            return;
        }
        sbc_bwt_part(a, lo, hi, d, k, is4, &less, &eq, &greater);
        /* from depth 6 the vendor's equal band uses 4-byte keys */
        {
            uint32_t nd = d + step;
            int n4 = is4;
            if (!is4 && nd >= 6)
                n4 = 1;
            if (nd > n)
                n4 = is4;
            if (eq <= 1) {
                eq = 0;
            } else if (nd > n) {
                eq = 0;
            }
            /* iterate on the largest piece, recurse on the other two */
            if (eq && eq >= less && eq >= greater) {
                if (less > 1)
                    sbc_bwt_seg(a, lo, lo + less, d, k, is4, n);
                if (greater > 1)
                    sbc_bwt_seg(a, hi - greater, hi, d, k, is4, n);
                lo = lo + less;
                hi = lo + eq;
                d = nd;
                is4 = n4;
            } else if (less && less >= greater) {
                if (eq > 1)
                    sbc_bwt_seg(a, lo + less, lo + less + eq, nd, k, n4, n);
                if (greater > 1)
                    sbc_bwt_seg(a, hi - greater, hi, d, k, is4, n);
                hi = lo + less;
            } else if (greater > 1) {
                if (less > 1)
                    sbc_bwt_seg(a, lo, lo + less, d, k, is4, n);
                if (eq > 1)
                    sbc_bwt_seg(a, lo + less, lo + less + eq, nd, k, n4, n);
                lo = hi - greater;
            } else {
                if (less > 1)
                    sbc_bwt_seg(a, lo, lo + less, d, k, is4, n);
                if (eq > 1)
                    sbc_bwt_seg(a, lo + less, lo + less + eq, nd, k, n4, n);
                return;
            }
        }
    }
}

/* smallest period of the input, or n when it has none (KMP failure walk) */
static uint32_t sbc_bwt_period(const uint8_t *s, uint32_t n)
{
    uint32_t *f, i, k = 0, p;
    if (n < 2)
        return n;
    f = (uint32_t *)malloc((n + 1) * sizeof(uint32_t));
    if (!f)
        return n;
    f[0] = 0;
    for (i = 1; i < n; i++) {
        while (k && s[i] != s[k])
            k = f[k - 1];
        if (s[i] == s[k])
            k++;
        f[i] = k;
    }
    p = n - f[n - 1];
    free(f);
    return n % p ? n : p;
}

static uint8_t *sbc_bwt(const uint8_t *src, size_t n, uint32_t *primary)
{
    SbcBwtBuf k;
    uint32_t *a, cnt[256], sum, i, c;
    uint8_t *L, *buf;
    size_t cp;

    *primary = 0;
    L = (uint8_t *)malloc(n ? n : 1);
    if (!L)
        return NULL;
    if (n == 0)
        return L;
    if (n == 1) {
        L[0] = src[0];
        return L;
    }
    cp = n < 0x1000 ? n : 0x1000;
    buf = (uint8_t *)calloc(n + cp + 64, 1);
    a = (uint32_t *)malloc((n + 1) * sizeof(uint32_t));
    if (!buf || !a) {
        free(buf);
        free(a);
        free(L);
        return NULL;
    }
    memcpy(buf, src, n);
    memcpy(buf + n, src, cp);
    k.b = buf;
    k.blen = (uint32_t)(n + cp);
    k.n = (uint32_t)n;
    k.end = (uint32_t)n + (cp > 7 ? (uint32_t)cp - 7 : (uint32_t)cp);
    k.per = sbc_bwt_period(src, (uint32_t)n);

    memset(cnt, 0, sizeof(cnt));
    for (i = 0; i < n; i++)
        cnt[src[i]]++;
    sum = 0;
    for (c = 0; c < 256; c++) {
        uint32_t t = cnt[c];
        cnt[c] = sum;
        sum += t;
    }
    for (i = 0; i < n; i++)
        a[cnt[src[i]]++] = i;
    /* cnt[] now holds the bucket ends; recount for the boundaries */
    memset(cnt, 0, sizeof(cnt));
    for (i = 0; i < n; i++)
        cnt[src[i]]++;
    sum = 0;
    for (c = 0; c < 256; c++) {
        uint32_t sz = cnt[c];
        if (sz && sz != n)
            sbc_bwt_seg(a, sum, sum + sz, 1, &k, 0, (uint32_t)n);
        sum += sz;
    }
    for (i = 0; i < n; i++) {
        if (a[i] == 0)
            *primary = i;
        L[i] = src[(a[i] + n - 1) % n];
    }
    free(a);
    free(buf);
    return L;
}

/* ---- filter-record bit stream (LSB first, like sbc_getbits) ---- */

typedef struct {
    uint8_t *p;
    size_t nbits, cap;
} SbcBitsW;

static void sbc_sbw_put(SbcBitsW *b, uint32_t v, int n)
{
    int i;
    for (i = 0; i < n; i++) {
        size_t byte = b->nbits >> 3;
        int off = (int)(b->nbits & 7);
        if (byte >= b->cap) {
            size_t cap = b->cap ? b->cap * 2 : 64;
            uint8_t *np = (uint8_t *)realloc(b->p, cap);
            if (!np)
                return;
            b->p = np;
            b->cap = cap;
        }
        if (off == 0)
            b->p[byte] = 0;
        if ((v >> i) & 1u)
            b->p[byte] |= (uint8_t)(1u << (7 - off));
        b->nbits++;
    }
}

/* A block whose filter list is a single "copy" record.  The vendor writes it
 * either as flen(25) coded(1)=0 + terminator (51 bits) or explicitly as
 * flen(25) coded=1 mode=5 + one option bit + terminator (55 bits); `explicit`
 * selects the second form (used by the vendor for small blocks). */

/* The vendor emits one record per *file*, even when all files share a block:
 * files of 512 bytes or more get the compact copy form, smaller ones the
 * explicit coded=1/mode=5 form (which carries the filter parameter bits).
 * At -m3 (level 2) the analysis caps every record at 0x80000 bytes, so a
 * longer segment becomes several records (measured: 524288 stays a single
 * record, 524289 gives 524288 + 1, a 600000-byte block gives 524288 + 75712
 * and a 2 MB one four records; -m1/-m2 keep one record for the whole block).
 * The end-of-list marker closes the block. */
static void sbc_recs_segs(SbcBitsW *b, const uint32_t *segs, uint32_t nsegs,
                          uint32_t level)
{
    uint32_t i;
    int filt_bits = level > 0 ? 1 : 0;
    for (i = 0; i < nsegs; i++) {
        uint32_t left = segs[i];
        do {
            uint32_t piece = left;
            if (level >= 2 && piece > 0x80000u)
                piece = 0x80000u;
            sbc_sbw_put(b, piece, 25);
            if (piece < 0x200) {
                sbc_sbw_put(b, 1, 1);
                sbc_sbw_put(b, 5, 3);
                sbc_sbw_put(b, 0, 1 + filt_bits);
            } else {
                sbc_sbw_put(b, 0, 1);
            }
            left -= piece;
        } while (left);
    }
    sbc_sbw_put(b, 0x1FFFFFFu, 25);
}

/* ---- header ---- */

typedef struct {
    const char *name;
    uint32_t flag;
    uint32_t dt;
    uint32_t size;
    const uint8_t *data;
} SbcEncFile;

/* DOS packed date/time, exactly like the legacy archiver stores it:
 * date = ((y-1980)<<9)|(m<<5)|d, time = (h<<11)|(min<<5)|(sec/2).
 *
 * The clock is **standard time**, not local time: the vendor runs under Wine
 * and its DOS conversion ignores daylight saving, so a summer file is dated one
 * hour earlier than `localtime()` reports.  Measured with a 1000-byte file at
 * 2026-07-01 12:00 (headers differ by an hour with localtime) and 2026-01-05
 * 12:00 (they match), and it is what made every October corpus header differ.
 */
static uint32_t sbc_dos_datetime(time_t t)
{
    struct tm tmv;
    uint32_t date, tim;
    {
        struct tm *lt = localtime(&t);
        if (!lt)
            return 0;
        tmv = *lt;
        if (tmv.tm_isdst > 0) {
            /* re-read at the standard-time instant */
            time_t t2 = t - 3600;
            struct tm *st = localtime(&t2);
            if (st)
                tmv = *st;
        }
    }
    {
        int y = tmv.tm_year + 1900;
        if (y < 1980)
            y = 1980;
        date = ((uint32_t)(y - 1980) << 9) | ((uint32_t)(tmv.tm_mon + 1) << 5) |
               (uint32_t)tmv.tm_mday;
    }
    tim = ((uint32_t)tmv.tm_hour << 11) | ((uint32_t)tmv.tm_min << 5) |
          ((uint32_t)(tmv.tm_sec / 2));
    return (date << 16) | tim;
}

/*
 * CRC16/ARC (poly 0xA001) as a running state: same byte loop as
 * sbc_crc16_arc() in sbc.c, but without the final xor, so a digest can be
 * accumulated over several buffers (header fields, then block payload).
 */
static uint32_t sbc_enc_crc16_upd(uint32_t c, const uint8_t *d, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        int k;
        c ^= d[i];
        for (k = 0; k < 8; k++)
            c = (c & 1) ? ((c >> 1) ^ 0xA001) : (c >> 1);
    }
    return c;
}

/*
 * The header and the per-block records use the same digest selected by the
 * -h switch: 1 = CRC16/ARC, 2 = CRC32 (IEEE), 3 = Adler32, 4 = Sum32.
 * All of them are stored big-endian, 2 bytes for CRC16 and 4 for the rest.
 */
typedef struct {
    uint32_t type;
    uint32_t crc;
    uint32_t a, b;
    uint32_t n;    /* Sum32: bytes fed so far */
    uint32_t cnt;  /* Sum32: bytes of the pending little-endian word */
    uint32_t word; /* Sum32: pending word, built MSB first */
    SbcHash hash;  /* MD5/SHA1/SHA256 */
} SbcWDig;

static uint32_t sbc_enc_dig_width(uint32_t type)
{
    if (type >= 5)
        return sbc_hash_size((int)type - 5);
    return type == 1 ? 2u : (type ? 4u : 0u);
}

static void sbc_enc_dig_init(SbcWDig *d, uint32_t type)
{
    d->type = type;
    d->crc = (type == 1) ? 0xFFFFu : 0xFFFFFFFFu;
    d->a = 1;
    d->b = 0;
    d->n = 0;
    d->cnt = 0;
    d->word = 0;
    if (type >= 5)
        sbc_hash_init(&d->hash, (int)type - 5);
}

static void sbc_enc_dig_upd(SbcWDig *d, const uint8_t *p, size_t n)
{
    size_t i;
    if (d->type == 1) {
        d->crc = sbc_enc_crc16_upd(d->crc, p, n);
        return;
    }
    if (d->type == 2) {
        for (i = 0; i < n; i++) {
            int k;
            d->crc ^= p[i];
            for (k = 0; k < 8; k++)
                d->crc = (d->crc & 1) ? ((d->crc >> 1) ^ 0xEDB88320u)
                                      : (d->crc >> 1);
        }
        return;
    }
    if (d->type == 3) {
        for (i = 0; i < n; i++) {
            d->a += p[i];
            if (d->a >= 65521u)
                d->a -= 65521u;
            d->b += d->a;
            if (d->b >= 65521u)
                d->b -= 65521u;
        }
        return;
    }
    if (d->type >= 5) {
        sbc_hash_upd(&d->hash, (int)d->type - 5, p, n);
        return;
    }
    if (d->type == 4) {
        /* Sum32: each group of four bytes is assembled MSB first (so it ends
         * up as the little-endian word of the four bytes), then B += A and
         * A += word.  A ends as 1 + sum of the words, B as the sum of the
         * earlier A values; the final value is (A + B) ^ total length. */
        d->n += (uint32_t)n;
        for (i = 0; i < n; i++) {
            d->word = ((uint32_t)p[i] << 24) | (d->word >> 8);
            if (++d->cnt == 4) {
                d->b += d->a;
                d->a += d->word;
                d->cnt = 0;
            }
        }
    }
}

static uint32_t sbc_enc_dig_final(const SbcWDig *d)
{
    if (d->type == 1)
        return d->crc ^ 0xFFFFu;
    if (d->type == 2)
        return d->crc ^ 0xFFFFFFFFu;
    if (d->type == 3)
        return (d->b << 16) | d->a;
    if (d->type == 4) {
        /* A trailing partial word is completed with zeros, which shifts the
         * bytes it already holds into the low end; the length used for the
         * final xor is the one before that padding. */
        uint32_t n = d->n;
        if (d->cnt) {
            SbcWDig t = *d;
            uint32_t k;
            for (k = 0; k < 4u - d->cnt; k++) {
                t.word = t.word >> 8;
                if (++t.cnt == 4) {
                    t.b += t.a;
                    t.a += t.word;
                    t.cnt = 0;
                }
            }
            return (t.a + t.b) ^ n;
        }
        return (d->a + d->b) ^ n;
    }
    return 0;
}

/*
 * Serialize a finished digest big-endian, sbc_enc_dig_width() bytes.  The
 * header field and the integrity/verify records all go through this.
 */
static void sbc_enc_dig_out(const SbcWDig *d, uint8_t *out)
{
    uint32_t w = sbc_enc_dig_width(d->type), j;
    if (d->type >= 5) {
        SbcHash t = d->hash;
        sbc_hash_final(&t, (int)d->type - 5, out);
        return;
    }
    if (w) {
        uint32_t v = sbc_enc_dig_final(d);
        for (j = 0; j < w; j++)
            out[j] = (uint8_t)(v >> (8 * (w - 1 - j)));
    }
}

/*
 * Write an archive header.  Field order mirrors sbc_parse_header().
 * Returns 0 on success; the payload starts at out->n after the RC flush.
 */
static int sbc_enc_header(SbcBuf *out, const SbcEncFile *files, uint32_t nfiles,
                          uint32_t crypto, uint32_t csum, uint32_t solid,
                          uint32_t method, uint32_t extra3)
{
    SbcWRC w;
    SbcWExtra fn_ex, fl_ex, sm0_ex, sm1_ex;
    SbcWSize sm0, sm1;
    uint32_t i;
    SbcWDig hdig;

    sbc_buf_write(out, SBC_MAGIC, 5);
    sbc_wrc_init(&w, out);
    sbc_wex_init(&fn_ex, &w, 0x45, 1, 0x4000, 0x4000, 0);
    sbc_wex_init(&fl_ex, &w, 8, 1, 0x200, 0x400, 0x20);
    sbc_wex_init(&sm0_ex, &w, 0x20, 1, 0x4000, 0x4000, 0);
    sbc_wex_init(&sm1_ex, &w, 0x21, 1, 0x4000, 0x4000, 0);
    sbc_ws_init(&sm0, &sm0_ex);
    sbc_ws_init(&sm1, &sm1_ex);

    sbc_wrc_u(&w, 8, crypto);
    sbc_wrc_u(&w, 8, csum);
    sbc_wrc_u(&w, 2, solid);
    sbc_wrc_int(&w, 0xFFFF0000u, nfiles ? nfiles - 1 : 0);

    /* With checksums the header ends with a digest of its own fields, fed the
     * same way the vendor does: LE32(nfiles) first, then per file the name
     * symbols, the flag, LE32(dt), LE32(size) and four zero bytes. */
    sbc_enc_dig_init(&hdig, csum);
    if (csum) {
        uint8_t b[4];
        b[0] = (uint8_t)nfiles;
        b[1] = (uint8_t)(nfiles >> 8);
        b[2] = (uint8_t)(nfiles >> 16);
        b[3] = (uint8_t)(nfiles >> 24);
        sbc_enc_dig_upd(&hdig, b, 4);
    }

    for (i = 0; i < nfiles; i++) {
        const uint8_t *nm = (const uint8_t *)files[i].name;
        size_t k;
        if (files[i].name[0] == 0)
            sbc_wex_sym(&fn_ex, 0);
        else {
            for (k = 0; nm[k]; k++) {
                int s;
                for (s = 0; s < 0x45; s++)
                    if (SBC_ALPHABET[s] == nm[k])
                        break;
                if (s == 0x45) {
                    sbc_wex_free(&fn_ex);
                    sbc_wex_free(&fl_ex);
                    sbc_wex_free(&sm0_ex);
                    sbc_wex_free(&sm1_ex);
                    return -1;
                }
                sbc_wex_sym(&fn_ex, (uint32_t)s);
                if (csum) {
                    uint8_t sb = (uint8_t)s;
                    sbc_enc_dig_upd(&hdig, &sb, 1);
                }
            }
            sbc_wex_sym(&fn_ex, 0);
        }
        sbc_wex_sym(&fl_ex, files[i].flag);
        sbc_ws_encode(&sm0, files[i].dt);
        sbc_ws_encode(&sm1, files[i].size);
        if (csum) {
            uint8_t b[5]; /* flag, then dt/size/extra as LE32 */
            int j;
            b[0] = (uint8_t)files[i].flag;
            sbc_enc_dig_upd(&hdig, b, 1);
            for (j = 0; j < 4; j++)
                b[j] = (uint8_t)(files[i].dt >> (8 * j));
            sbc_enc_dig_upd(&hdig, b, 4);
            for (j = 0; j < 4; j++)
                b[j] = (uint8_t)(files[i].size >> (8 * j));
            sbc_enc_dig_upd(&hdig, b, 4);
            b[0] = 0;
            b[1] = 0;
            b[2] = 0;
            b[3] = 0;
            sbc_enc_dig_upd(&hdig, b, 4);
        }
    }
    if (csum) {
        uint8_t dg[32];
        uint32_t di, nw = sbc_enc_dig_width(csum);
        sbc_enc_dig_out(&hdig, dg);
        for (di = 0; di < nw; di++)
            sbc_wrc_u(&w, 0x100, dg[di]);
    }
    sbc_wrc_u(&w, 0x3F, method);
    sbc_wrc_u(&w, 3, extra3);
    sbc_wrc_flush(&w, 4);

    sbc_wex_free(&fn_ex);
    sbc_wex_free(&fl_ex);
    sbc_wex_free(&sm0_ex);
    sbc_wex_free(&sm1_ex);
    return out->err ? -1 : 0;
}

/*
 * Archive trailer hash (0x41f920 / 0x421330 in sbc.exe).  The 32-bit state
 * starts at (block_size - 1) + 0xFF80 and is folded once per block with
 *     v = ror(x ^ ((~x) >> 23), 25) + (block_len ^ nibrev(primary))
 * The final state is written big-endian after a vlq(0) end marker.
 */
static uint32_t sbc_enc_nibrev(uint32_t v)
{
    /* nibble bit-reversal table of the binary (entry 0xD is 0xD there) */
    static const uint8_t tab[16] = { 0x0, 0x8, 0x4, 0xC, 0x2, 0xA, 0x6, 0xE,
                                     0x1, 0x9, 0x5, 0xD, 0x3, 0xD, 0x7, 0xF };
    uint32_t r = (uint32_t)tab[v & 0xF] << 28;
    int sh = 28;
    while (v > 0xF) {
        v >>= 4;
        sh -= 4;
        r |= (uint32_t)tab[v & 0xF] << sh;
    }
    return r;
}

/*
 * With -hr the binary writes two CRC16 records per block:
 *   "integrity" (before the payload) = CRC16 over LE32(primary), two zero
 *      bytes, the ceil(nbits/8) record-bit bytes and then the payload itself;
 *   "verify" (after the payload)     = CRC16 of the block's decoded output.
 * Both are stored big-endian.  The zero bytes are the block's e1/e2 coding
 * fields, always 0 for a stored block.
 */

/*
 * Block-emission hook: sbc_enc_block.h installs a dispatcher that may write a
 * compressed block instead of the stored one.  Kept as a function pointer so
 * the archive writer stays above the pipeline headers in the include order.
 */
typedef int (*SbcEncBlockFn)(SbcBuf *out, const uint8_t *data, size_t n,
                             const uint32_t *segs, uint32_t nsegs,
                             uint32_t csum, SbcWExtra *extra, uint32_t nsyms,
                             int flush_bytes, uint32_t *hash, uint32_t level);
static SbcEncBlockFn sbc_enc_block_fn;

/* Block window limit (bs - 1) of the archive being written.  The mode-4 filter
 * uses it to decide the record ctrl bit 0x08: the vendor (0x40c670) clears the
 * bit when the filtered stream, plus the room the line model needs, would not
 * fit the window -- `n + n/512` for n up to 1 MB, `n + 0x800` above (measured
 * at -b1 and -b5, both boundaries exact). */
static uint64_t sbc_enc_blk_limit = ~(uint64_t)0;

/* LZP hash-table mask of the archive being written.  The vendor sizes the
 * table from the archive window: `bitlen(bs + 0x400) - 1` bits (0x40ecb0 ->
 * 0x42c530 -> 0x40a730), so the default 1 MB window gives 2^20 entries and a
 * 3 MB one 2^21.  `sbc_enc_archive_ex()` sets it from the block size it
 * picked; the standalone pipeline tests keep the 1 MB default. */
static uint32_t sbc_enc_lzp_hmask = 0xFFFFFu;

static uint32_t sbc_enc_lzp_mask_for_bs(uint32_t bs)
{
    int bits = sbc_bitlen(bs + 0x400u) - 1;
    if (bits < 0)
        bits = 0;
    return bits >= 32 ? 0xFFFFFFFFu : ((1u << bits) - 1u);
}

/*
 * One payload block holding `n` bytes "stored": BWT only, no range-coded
 * payload (e1 == 0).  Mirrors sbc_block_read()/sbc_block_decode().
 */
static int sbc_enc_stored_block(SbcBuf *out, const uint8_t *data, size_t n,
                                const uint32_t *segs, uint32_t nsegs,
                                uint32_t csum, SbcWExtra *extra,
                                uint32_t nsyms, int flush_bytes,
                                uint32_t *hash, uint32_t level)
{
    SbcWRC w;
    uint8_t *L;
    uint32_t primary = 0, vlq = (uint32_t)n;
    SbcBitsW recs;
    size_t nb, k;
    SbcWDig idig, vdig;
    uint32_t dw = sbc_enc_dig_width(csum);

    L = sbc_bwt(data, n, &primary);
    if (!L)
        return -1;

    if (hash) {
        uint32_t x = *hash;
        uint32_t m = x ^ (((~x) & 0xFFFFFFFFu) >> 23);
        *hash = ((m >> 25) | (m << 7)) + ((uint32_t)n ^ sbc_enc_nibrev(primary));
    }

    /* vlq is a plain VLQ byte sequence, not range coded */
    if (vlq < 0x40)
        sbc_buf_put(out, (uint8_t)vlq);
    else if (vlq < 0x4000) {
        sbc_buf_put(out, (uint8_t)(0x40 | (vlq >> 8)));
        sbc_buf_put(out, (uint8_t)(vlq & 0xFF));
    } else if (vlq < 0x400000) {
        sbc_buf_put(out, (uint8_t)(0x80 | (vlq >> 16)));
        sbc_buf_put(out, (uint8_t)((vlq >> 8) & 0xFF));
        sbc_buf_put(out, (uint8_t)(vlq & 0xFF));
    } else {
        sbc_buf_put(out, (uint8_t)(0xC0 | (vlq >> 24)));
        sbc_buf_put(out, (uint8_t)((vlq >> 16) & 0xFF));
        sbc_buf_put(out, (uint8_t)((vlq >> 8) & 0xFF));
        sbc_buf_put(out, (uint8_t)(vlq & 0xFF));
    }

    sbc_wrc_init(&w, out);
    sbc_wrc_large(&w, vlq, primary);
    memset(&recs, 0, sizeof(recs));
    /* one record per file: explicit "copy" (coded=1, mode=5) below 512
     * bytes, compact coded=0 from 512 on */
    sbc_recs_segs(&recs, segs, nsegs, level);
    nb = recs.nbits;
    sbc_wrc_int_maxbits(&w, 0x14, (uint32_t)nb);
    /* the bit buffer is transferred byte by byte through the range coder */
    for (k = 0; k < (nb + 7) / 8; k++) {
        size_t rem = nb - k * 8;
        if (rem >= 8)
            sbc_wrc_u(&w, 0x100, recs.p[k]);
        else
            sbc_wrc_u(&w, 1u << rem, recs.p[k] >> (8 - rem));
    }
    sbc_enc_dig_init(&idig, csum);
    if (csum) {
        uint8_t four[6];
        four[0] = (uint8_t)primary;
        four[1] = (uint8_t)(primary >> 8);
        four[2] = (uint8_t)(primary >> 16);
        four[3] = (uint8_t)(primary >> 24);
        four[4] = 0; /* e1 */
        four[5] = 0; /* e2 */
        sbc_enc_dig_upd(&idig, four, 6);
        sbc_enc_dig_upd(&idig, recs.p, (nb + 7) / 8);
    }
    free(recs.p);
    sbc_wrc_u(&w, 3, 0);              /* flag3 */
    if (!extra->freq) {
        /* first block: the shared adaptive model is created here */
        sbc_wex_init(extra, &w, nsyms, 1, 0x4000, 0x4000, 0);
    } else {
        extra->wrc = &w;
    }
    sbc_wex_k(extra, 0); /* e1 = 0 -> stored */
    sbc_wex_k(extra, 0); /* e2 */
    sbc_wrc_flush(&w, flush_bytes);

    if (csum) {
        uint8_t dg[32];
        uint32_t j;
        sbc_enc_dig_upd(&idig, L, n);
        sbc_enc_dig_out(&idig, dg);
        for (j = 0; j < dw; j++)
            sbc_buf_put(out, dg[j]);
    }
    sbc_buf_write(out, L, n);
    free(L);
    if (csum) {
        uint8_t dg[32];
        uint32_t j;
        sbc_enc_dig_init(&vdig, csum);
        sbc_enc_dig_upd(&vdig, data, n);
        sbc_enc_dig_out(&vdig, dg);
        for (j = 0; j < dw; j++)
            sbc_buf_put(out, dg[j]);
    }
    return out->err ? -1 : 0;
}

static int sbc_enc_emit_block(SbcBuf *out, const uint8_t *data, size_t n,
                              const uint32_t *segs, uint32_t nsegs,
                              uint32_t csum, SbcWExtra *extra, uint32_t nsyms,
                              int flush_bytes, uint32_t *hash, uint32_t level)
{
    if (sbc_enc_block_fn)
        return sbc_enc_block_fn(out, data, n, segs, nsegs, csum, extra, nsyms,
                                flush_bytes, hash, level);
    return sbc_enc_stored_block(out, data, n, segs, nsegs, csum, extra, nsyms,
                                flush_bytes, hash, level);
}

/* -ub: "uniform-block mode" makes every block a single record.  The vendor
 * keeps the -oz order and the same block boundaries; only the record list
 * changes (its 5-file t3 set is one 1614-byte mode-6 record instead of five
 * per-file ones).  Wrapper for the fixed-size (-ad) path; the adaptive path
 * builds its segments itself. */
static int sbc_enc_emit_block_ub(SbcBuf *out, const uint8_t *data, size_t n,
                                 const uint32_t *segs, uint32_t nsegs,
                                 uint32_t csum, SbcWExtra *extra,
                                 uint32_t nsyms, int flush_bytes,
                                 uint32_t *hash, uint32_t level, int uniform)
{
    uint32_t one = (uint32_t)n;
    if (uniform)
        return sbc_enc_emit_block(out, data, n, &one, 1, csum, extra, nsyms,
                                  flush_bytes, hash, level);
    return sbc_enc_emit_block(out, data, n, segs, nsegs, csum, extra, nsyms,
                              flush_bytes, hash, level);
}

/*
 * Block size selection.  The vendor keeps -bN as an upper bound: (N+1)*512 kB,
 * further reduced to a value derived from the total input size, rounded up to
 * 0.5 MB (an exact multiple still moves to the next bucket).  The resulting
 * size also fixes the header's window bucket and the trailer hash seed.
 */
static uint32_t sbc_enc_bsize(uint64_t total, uint32_t code)
{
    const uint64_t half = 0x80000u;
    uint64_t bn = (uint64_t)(code + 1) * half;
    uint64_t bt = ((total + half) / half + 1) * half;
    uint64_t bs = bn < bt ? bn : bt;
    if (bs < 0x100000u)
        bs = 0x100000u;
    return (uint32_t)bs;
}

/*
 * The vendor's adaptive block splitter (sbc.exe 0x407ae0).  It walks the
 * concatenated stream byte by byte, keeping a histogram of the 65536 possible
 * 16-bit contexts, and returns the length of the next block.
 *
 * Two rules meet here:
 *   - a score counts how long the data has looked "compressible enough": it
 *     is incremented while (distinct>>6)+0x22 (or (distinct>>7)+0x36 below
 *     64 kB) is at least the current score, and decremented when the context
 *     density test fails.  When the score overtakes the threshold the block
 *     ends on that byte -- this is what cuts random data at ~530 kB;
 *   - at the end of a file, a block only continues into the next one when the
 *     finished file fits in the current block (size <= i + 1 kB) and the next
 *     file is small (< 1 kB); otherwise the block ends there.
 * If the first phase reaches its limit (len_arg - len_arg/32) with data that
 * looks only mildly compressible (1000 < distinct <= base/2) the block ends,
 * else the splitter keeps going up to len_arg.
 * `counts` is the 256 kB scratch table, `idx`/`fpos` the cursor into the file
 * list (offset inside the current file, like the vendor's obj+0x58/0x40).
 */
static uint64_t sbc_enc_split_next(const uint8_t *cat, const uint64_t *starts,
                                   const uint32_t *sizes, uint32_t nfiles,
                                   uint32_t bs, uint32_t *counts,
                                   uint32_t *idx, uint64_t *fpos, int solid)
{
    uint32_t len_arg = bs - 1u;
    uint32_t base = ((len_arg >> 21) * 200u) + 0x1770u;
    uint32_t limit = len_arg - (len_arg >> 5);
    uint32_t i = 0, distinct = 0, score = 0, ctx = 0;
    int eof = 0;

    memset(counts, 0, 65536 * sizeof(*counts));
    while (i < limit) {
        uint32_t k = *idx;
        uint64_t f = *fpos;
        uint32_t c;
        uint8_t b;

        while (k < nfiles && f >= sizes[k]) {
            k++;
            f = 0;
        }
        if (k >= nfiles) {
            eof = 1;
            break;
        }
        b = cat[starts[k] + f];
        f++;
        *idx = k;
        *fpos = f;
        ctx = ((ctx << 8) | b) & 0xFFFFu;
        /* end of a file: the block ends here when it was started inside
         * this file, or when this file and the next one are both large
         * enough to stand alone (1 kB); small files merge into their
         * neighbour.  The last file just runs out (eof). */
        if (f >= sizes[k] &&
            (sizes[k] > i + 0x400u ||
             (!solid && sizes[k] >= 1024u && k + 1 < nfiles &&
              sizes[k + 1] >= 1024u)))
            limit = i;
        c = ++counts[ctx];
        if (c == 1)
            distinct++;
        if (i > 0x3FFFu) {
            if ((distinct >> 13) + c > (i >> 15)) {
                if (score)
                    score--;
                i++;
                continue;
            }
            if ((i > 0xFFFFu ? (distinct >> 6) + 0x22u
                             : (distinct >> 7) + 0x36u) >= score) {
                score++;
            } else {
                limit = i;      /* content cut, this byte included */
                i++;
                break;
            }
        }
        i++;
    }
    if (!eof && i + 0x400u <= len_arg && i == limit) {
        /* the first phase exhausted its limit: go on to the full window
         * unless the data turned out to be barely compressible */
        if (distinct > 0x3E7u && 2u * distinct <= base)
            return i;
        limit = len_arg;
        while (i < limit) {
            uint32_t k = *idx;
            uint64_t f = *fpos;
            uint32_t c;
            uint8_t b;

            while (k < nfiles && f >= sizes[k]) {
                k++;
                f = 0;
            }
            if (k >= nfiles)
                break;
            b = cat[starts[k] + f];
            f++;
            *idx = k;
            *fpos = f;
            ctx = ((ctx << 8) | b) & 0xFFFFu;
            if (f >= sizes[k] &&
                (sizes[k] > i + 0x400u ||
                 (!solid && (k + 1 >= nfiles || sizes[k + 1] < 1024u))))
                limit = i;
            c = ++counts[ctx];
            if (c == 1)
                distinct++;
            if (i > 0x3FFFu) {
                if ((distinct >> 13) + c > (i >> 15)) {
                    if (score)
                        score--;
                    i++;
                    continue;
                }
                if ((i > 0xFFFFu ? (distinct >> 6) + 0x22u
                                 : (distinct >> 7) + 0x36u) >= score) {
                    score++;
                } else {
                    limit = i;
                    i++;
                    break;
                }
            }
            i++;
        }
    }
    return i;
}

/* Emit the blocks of an adaptive archive: the splitter chooses their sizes,
 * and each block carries one filter record per file fragment it covers. */
static int sbc_enc_emit_adaptive(SbcBuf *out, const uint8_t *cat,
                                 const uint32_t *sizes, uint32_t nfiles,
                                 uint64_t total, uint32_t bs, uint32_t level,
                                 uint32_t csum, SbcWExtra *extra,
                                 uint32_t nsyms, int flush_bytes,
                                 uint32_t *hash, int merge_files,
                                 int uniform)
{
    uint64_t *starts, pos = 0;
    uint32_t *counts, idx = 0, k = 0;
    uint64_t fpos = 0;
    uint64_t one_start = 0;
    uint32_t one_size = 0;
    int rc = 0;

    starts = (uint64_t *)malloc((nfiles ? nfiles : 1) * sizeof(*starts));
    counts = (uint32_t *)malloc(65536 * sizeof(*counts));
    if (!starts || !counts) {
        free(starts);
        free(counts);
        return -1;
    }
    /* A partial-solid group is one solid stream: the splitter still walks
     * the file list (so it knows where a file ends) but only closes a block
     * at a boundary when the block started inside that file.  Otherwise the
     * files stay together and the next one references the previous bytes. */
    (void)one_start;
    (void)one_size;
    {
        uint64_t off = 0;
        uint32_t j;
        for (j = 0; j < nfiles; j++) {
            starts[j] = off;
            off += sizes[j];
        }
    }
    while (pos < total && rc == 0) {
        uint64_t blen = sbc_enc_split_next(cat, starts, sizes, nfiles, bs,
                                          counts, &idx, &fpos, merge_files);
        uint32_t *segs = NULL, nsegs = 0;
        uint64_t done = 0, p = pos;

        if (!blen)
            break;
        if (uniform) {
            /* -ub: the whole block is one record, so its files are filtered
             * as a single stream (the vendor's 5-file t3 set comes out as one
             * 1614-byte mode-6 record covering all 4882 filtered bytes). */
            segs = (uint32_t *)malloc(sizeof(*segs));
            if (segs) {
                segs[0] = (uint32_t)blen;
                nsegs = 1;
                done = blen;
            }
        }
        while (done < blen) {
            uint64_t avail, take;
            uint32_t *np;

            while (k < nfiles && starts[k] + sizes[k] <= p)
                k++;
            if (k >= nfiles)
                break;
            avail = starts[k] + sizes[k] - p;
            take = blen - done < avail ? blen - done : avail;
            np = (uint32_t *)realloc(segs, (nsegs + 1) * sizeof(*segs));
            if (!np)
                break;
            segs = np;
            segs[nsegs++] = (uint32_t)take;
            done += take;
            p += take;
        }
        if (done != blen)
            rc = -1;
        else if (sbc_enc_emit_block(out, cat + (size_t)pos, (size_t)blen,
                                    segs, nsegs, csum, extra, nsyms,
                                    flush_bytes, hash, level) != 0)
            rc = -1;
        free(segs);
        pos += blen;
    }
    free(starts);
    free(counts);
    return rc;
}

static int sbc_enc_archive_ex(SbcBuf *out, const SbcEncFile *files,
                              uint32_t nfiles, uint32_t level, uint32_t csum,
                              uint32_t nsyms, int flush_bytes,
                              uint32_t bsize_code, int adaptive, int per_file,
                              const uint8_t *group, int uniform)
{
    SbcWExtra extra;
    uint64_t total = 0;
    uint32_t i, hash, method, bs;
    memset(&extra, 0, sizeof(extra));
    for (i = 0; i < nfiles; i++)
        total += files[i].size;
    bs = sbc_enc_bsize(total, bsize_code);
    sbc_enc_blk_limit = (uint64_t)bs - 1u;
    sbc_enc_lzp_hmask = sbc_enc_lzp_mask_for_bs(bs);
    /* The header's "method" byte is the window bucket: window_size(method)
     * = (method << 19) + 0xFFFFF, i.e. the block size in 512 kB steps above
     * 1 MB.  It in turn fixes the shared model's symbol count. */
    method = (bs - 0x100000u) >> 19;
    if (!getenv("SBC_ENC_NSYMS"))
        nsyms = sbc_bitlen(((method << 19) + 0xFFFFFu));
    hash = bs - 1u + 0xFF80u;
    /* the two 8-bit header fields are the integrity and verify checksum
     * types, not "crypto/csum" as the names in sbc_parse_header suggest:
     * the vendor writes 1/1 for -hr and 2/2 for -hc. */
    if (sbc_enc_header(out, files, nfiles, csum, csum, 0, method, level) != 0)
        return -1;
    /* A non-solid archive still packs every file into one concatenated
     * stream, split into blocks of the size chosen above. */
    {
        /* -ad: no adaptive reduction, so a block is the whole window, one
         * byte short of the selected block size.  In the default (-af/-ab)
         * mode the vendor's splitter picks the boundaries instead. */
        uint64_t blk = (uint64_t)bs - 1u;
        uint8_t *cat = (uint8_t *)malloc((size_t)total ? (size_t)total : 1);
        size_t off = 0;
        uint32_t *sizes = (uint32_t *)malloc((nfiles ? nfiles : 1) *
                                             sizeof(*sizes));
        if (!cat || !sizes) {
            free(cat);
            free(sizes);
            return -1;
        }
        for (i = 0; i < nfiles; i++) {
            memcpy(cat + off, files[i].data, files[i].size);
            off += files[i].size;
            sizes[i] = files[i].size;
        }
        if (adaptive) {
            int rc = 0;
            if (per_file) {
                /* -on: every file is its own solid stream.  The splitter
                 * still cuts inside a large file (a 1.3 MB file becomes
                 * 530240 + 530093 + 270867 at -b5), but never across a file
                 * boundary, which is exactly what the vendor does. */
                for (i = 0; i < nfiles && rc == 0; i++) {
                    uint32_t one = files[i].size;
                    if (one == 0)
                        continue;
                    rc = sbc_enc_emit_adaptive(out, files[i].data, &one, 1,
                                               one, bs, level, csum, &extra,
                                               nsyms, flush_bytes, &hash, 0, 0);
                }
            } else if (group) {
                /* -oa/-oz: one adaptive stream per partial-solid group, so a
                 * block never straddles a group boundary. */
                uint32_t g = 0;
                uint64_t off = 0;
                while (g < nfiles && rc == 0) {
                    uint32_t e = g + 1;
                    uint64_t gsize = sizes[g];
                    while (e < nfiles && !group[e]) {
                        gsize += sizes[e];
                        e++;
                    }
                    rc = sbc_enc_emit_adaptive(out, cat + (size_t)off,
                                               sizes + g, e - g, gsize, bs,
                                               level, csum, &extra, nsyms,
                                               flush_bytes, &hash, 1, uniform);
                    off += gsize;
                    g = e;
                }
            } else {
                rc = sbc_enc_emit_adaptive(out, cat, sizes, nfiles, total, bs,
                                           level, csum, &extra, nsyms,
                                           flush_bytes, &hash, 0, uniform);
            }
            free(cat);
            free(sizes);
            if (rc != 0)
                return -1;
            goto trailer;
        }
        free(sizes);
        /* Blocks are cut inside the concatenated stream, but a file boundary
         * is only a block boundary when both files around it are at least
         * 1 kB: smaller files are merged into the neighbouring block
         * (measured: 1023+data and 1000+1200 merge, 1024+1024 splits, and a
         * 400000-byte file followed by a 100-byte one stays one block while
         * 400000+2000 splits).  A file whose data crosses a block limit is
         * split and records one segment per fragment. */
        {
            uint64_t bstart = 0, blen = 0, pos = 0;
            uint32_t *segs = NULL, nsegs = 0;
            int failed = 0;

            for (i = 0; i < nfiles && !failed; i++) {
                uint64_t remain = files[i].size;
                while (remain && !failed) {
                    uint64_t take = blk - blen;
                    if (take > remain)
                        take = remain;
                    segs = (uint32_t *)realloc(segs,
                                               (nsegs + 1) * sizeof(*segs));
                    segs[nsegs++] = (uint32_t)take;
                    blen += take;
                    pos += take;
                    remain -= take;
                    if (blen == blk) {
                        if (sbc_enc_emit_block_ub(out, cat + (size_t)bstart,
                                                  (size_t)blen, segs, nsegs,
                                                  csum, &extra, nsyms,
                                                  flush_bytes, &hash,
                                                  level, uniform) != 0)
                            failed = 1;
                        segs = NULL;
                        nsegs = 0;
                        blen = 0;
                        bstart = pos;
                    }
                }
                /* A file of 1 kB or more ends the pending block unless the
                 * next file is a small one, which would then sit alone at
                 * the start of the next block (measured on 1023/1024-byte
                 * boundaries and on 400000 + 100 / 400000 + 2000). */
                if (files[i].size >= 1024u && blen &&
                    i + 1 < nfiles && files[i + 1].size >= 1024u) {
                    if (sbc_enc_emit_block_ub(out, cat + (size_t)bstart,
                                              (size_t)blen, segs, nsegs,
                                              csum, &extra, nsyms,
                                              flush_bytes, &hash, level,
                                              uniform) != 0)
                        failed = 1;
                    segs = NULL;
                    nsegs = 0;
                    blen = 0;
                    bstart = pos;
                }
            }
            if (!failed && blen) {
                if (sbc_enc_emit_block_ub(out, cat + (size_t)bstart,
                                          (size_t)blen, segs, nsegs, csum,
                                          &extra, nsyms, flush_bytes, &hash,
                                          level, uniform) != 0)
                    failed = 1;
            }
            free(segs);
            if (failed) {
                free(cat);
                return -1;
            }
        }
        free(cat);
    }
trailer:
    sbc_wex_free(&extra);
    /* end-of-blocks marker + 32-bit trailer hash, big-endian */
    sbc_buf_put(out, 0);
    sbc_buf_put(out, (uint8_t)(hash >> 24));
    sbc_buf_put(out, (uint8_t)(hash >> 16));
    sbc_buf_put(out, (uint8_t)(hash >> 8));
    sbc_buf_put(out, (uint8_t)hash);
    return out->err ? -1 : 0;
}

