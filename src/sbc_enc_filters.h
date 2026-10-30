/*
 * Encoder-side (forward) filter transforms.
 *
 * Every filter decoder in sbc.c/sbc_stage2.h derives its predictor and its
 * adaptive state from the *reconstructed* bytes, so the forward pass is the
 * same loop with the output known:
 *
 *     residual[i] = data[i] - predictor(data, i)
 *
 * The only exception is the advanced delta's lag choice, which reads the
 * residual stream itself and therefore needs a fixed-point iteration.  Mode 7
 * stores its width on 12 bits (`W = 3*param`), nothing else.
 */

#ifndef SBC_ENC_FILTERS_H
#define SBC_ENC_FILTERS_H

#include "sbc_m0adv.h"

/* The advanced (delta) filter has a minimum input size, like the simple one's
 * 0x2400-byte bail-out: bisected on periodic data of periods 4, 10 and 16
 * (lowercase and uppercase), 11316 bytes come out unchanged and 11317 get the
 * residuals, whatever the content.  The vendor's filter therefore returns the
 * identity below this, and the policy above reads that identity as "no
 * filter". */
#define SBC_ENC_ADV_MIN 11317u

/*
 * Forward mode 0, simple variant (0x424150).  The decoder's state machine
 * only looks at the reconstructed bytes, so the forward pass is the same loop
 * with the data known: residual[i] = data[i] - data[i - state].
 * Returns 0 when the filter applies, 1 when the variant bails out (the
 * vendor's "no filter" - below 0x2400 bytes it copies the block verbatim).
 */
/* Set by the simple variant: the state machine's state when the loop ended
 * (0 = no lag was in force, so the tail was copied verbatim) and whether it
 * ran out of the trial window.  Diagnostics; the decision is
 * `sbc_enc_m0_verdict` below. */
static int sbc_enc_m0_state;
static int sbc_enc_m0_trial;
/* Bytes the simple variant actually coded with a lag (0x43aea6/0x43aee1:
 * `pos - 0x200 - s20`, and the tail is never counted). */
static int sbc_enc_m0_coded;
/* The filter's own verdict for the last call, its return value: 0 refused,
 * 1 applied, 2 applied on more than a tenth (-m1) resp. an eighth (-m2/-m3)
 * of the record.  The caller keeps a mode-0 record only when it is nonzero,
 * and skips the mode-6 rewrite of FUN_00412af0's tail when it is 2. */
static int sbc_enc_m0_verdict;
/* Lag the advanced variant settled on (0 = none).  Diagnostics only: the
 * vendor's mode-7 gate does not read it, it reads the slot byte counts
 * (`sbc_m0a_last_slot[2]`, see the -m3 policy in sbc_enc_block.h). */
static int sbc_enc_m0_lag;
/* The two scratch tables of sbc_m0adv.h said the settled predictor is not
 * better than "the byte repeats" (always 1 for the -m2 object, whose flag is
 * 0 and skips them).  `sbc_enc_m0_verdict` is the full vendor verdict, which
 * refuses in that case too. */
static int sbc_enc_m0_ok = 1;

static int sbc_enc_mode0_simple(const uint8_t *d, size_t n, uint8_t *r)
{
    static const int offs[6] = { 2, 3, 4, 6, 8, 13 };
    int s34 = 0, s38 = 0, s3c = 0, s40 = 0, s44 = 0, s48 = 0;
    int state = 0, pen = 0, s20 = 0, s28 = 0;
    size_t i;

    memcpy(r, d, n);
    sbc_enc_m0_state = 0;
    sbc_enc_m0_trial = 0;
    sbc_enc_m0_coded = 0;
    sbc_enc_m0_verdict = 0;
    /* 0x43acc7: 0x2400 bytes or less never reach the state machine and the
     * filter reports failure, so the record is stored. */
    if (n <= 0x23FF)
        return 1;
    sbc_mode0_init_w();
    for (i = 0x200; i < n; i++) {
        if (state) {
            int p = d[i - (size_t)state];
            int e = d[i];
            int dd = e - p;
            r[i] = (uint8_t)dd;
            if ((uint32_t)(dd + 0x17) > 0x2Eu) {
                pen += 5;
                if ((uint32_t)pen > 0x100u) {
                    s34 = s38 = s3c = s40 = s44 = s48 = 0;
                    pen = 0;
                    state = 0;
                }
            } else if (pen > 0) {
                pen -= 3;
            }
        } else {
            int oi;
            r[i] = d[i];
            s28 = s20 + 1;
            if (s20 > 0x3FFF) {
                memcpy(r + i, d + i, n - i);
                sbc_enc_m0_trial = 1;
                break;
            }
            for (oi = 0; oi < 6; oi++) {
                int off = offs[oi];
                int w = sbc_mode0_w[((int)d[i] - (int)d[i - (size_t)off]) & 0xFF];
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
        }
    }
    sbc_enc_m0_state = state;
    /* 0x43aeeb/0x43af8a: the verdict.  `s20` still holds the trial byte count
     * at the break (the loop's own `s28 = s20 + 1` runs before the trial
     * test), and at the normal end `s28`/`s20` are that count too, so `i`
     * minus `s20` is the vendor's `pos - base - s28` either way. */
    sbc_enc_m0_coded = (int)((long)i - (long)s20);
    if (sbc_enc_m0_coded <= 0xFFF) {
        sbc_enc_m0_verdict = 0;
    } else {
        sbc_enc_m0_verdict =
            (sbc_enc_m0_coded > (int)((long)n / 10)) ? 2 : 1;
    }
    return 0;
}

/*
 * Forward mode 0, advanced variant (0x425200).  The lag is derived from the
 * residual stream the decoder is about to read, so the forward pass iterates
 * to the fixed point: pick a lag, derive the residuals, re-read the scores
 * from them, repeat.
 */
static int sbc_enc_adv_distinct(const uint8_t *src, int P, int lag, int use_lag)
{
    unsigned char seen[8192];
    int i, total = 0;
    memset(seen, 0, sizeof(seen));
    if (!use_lag) {
        for (i = P; i < P + 257; i++) {
            unsigned v = ((unsigned)src[i - 1] << 8) | src[i];
            unsigned char *p = &seen[v >> 3];
            unsigned char m = (unsigned char)(1u << (v & 7));
            if (!(*p & m)) {
                *p |= m;
                total++;
            }
        }
    } else {
        int prev = src[P - lag];
        for (i = P; i < P + 257; i++) {
            unsigned cur = (unsigned)((src[i] - src[i - lag]) & 0xFF);
            unsigned v = ((unsigned)prev << 8) | cur;
            unsigned char *p = &seen[v >> 3];
            unsigned char m = (unsigned char)(1u << (v & 7));
            if (!(*p & m)) {
                *p |= m;
                total++;
            }
            prev = (int)cur;
        }
    }
    return total;
}

static int sbc_enc_adv_lag(const uint8_t *src, int P, int nmod, int f40, int n)
{
    static const int lags[10] = { 2, 3, 4, 8, 10, 16, 20, 12, 6, 24 };
    static const int slots[6] = { 10, 16, 20, 12, 6, 24 };
    int s0, sc[10], esi, best, bp, i;

    if (n < P + 257 || nmod > 10)
        return 0;
    s0 = sbc_enc_adv_distinct(src, P, 0, 0);
    for (i = 0; i < nmod; i++)
        sc[i] = sbc_enc_adv_distinct(src, P, lags[i], 1);
    esi = (s0 >> 5 < 12 ? s0 >> 5 : 12) + (f40 >> 10);
    best = s0;
    bp = 0;
    for (i = 0; i < nmod; i++) {
        if (best > esi + sc[i]) {
            best = sc[i];
            bp = i + 1;
        }
    }
    if (bp == 0)
        return 0;
    if (bp <= 4)
        return lags[bp - 1];
    if (P == 0)
        return bp + 1;
    return slots[bp - 5];
}

/* Vendor-exact adaptive filter (the -m1..-m3 object of unsbc 0x425200): the
 * chunk/slot controller is shared with the decoder through sbc_m0adv.h.
 * The vendor refuses inputs under `minlen + 0xC35`; its caller then stores the
 * record instead, which the policy decides, so a refusal leaves a copy. */
static int sbc_enc_mode0_adaptive(const uint8_t *d, size_t n,
                                  const SbcM0Params *pp, uint8_t *r)
{
    uint8_t *f = sbc_m0_adaptive(d, n, pp, 1);
    /* diagnostics: the first-chunk lag of the advanced variant */
    sbc_enc_m0_lag = sbc_enc_adv_lag(d, pp->pool < 24 ? 24 : pp->pool,
                                     pp->nmod, pp->first, (int)n);
    sbc_enc_m0_verdict = sbc_m0a_last_verdict;
    if (!f) {
        sbc_enc_m0_ok = 0;
        memcpy(r, d, n);
        return 0;
    }
    sbc_enc_m0_ok = sbc_m0a_scr_ok;
    memcpy(r, f, n);
    free(f);
    return 0;
}

static int sbc_enc_mode0_advanced(const uint8_t *d, size_t n, int P, int nmod,
                                  int f40, uint8_t *r)
{
    int round;
    sbc_enc_m0_lag = 0;
    if (n < SBC_ENC_ADV_MIN) {
        memcpy(r, d, n);
        return 0;
    }
    memcpy(r, d, n);
    for (round = 0; round < 12; round++) {
        int L = sbc_enc_adv_lag(r, P, nmod, f40, (int)n);
        uint8_t *nxt = (uint8_t *)malloc(n ? n : 1);
        size_t k;
        int same = 1;
        if (!nxt)
            return -1;
        sbc_enc_m0_lag = L;
        memcpy(nxt, d, P + 257 < (int)n ? (size_t)P + 257 : n);
        if (P + 257 < (int)n) {
            for (k = (size_t)P + 257; k < n; k++)
                nxt[k] = (uint8_t)(d[k] - (L ? d[k - (size_t)L] : 0));
            if (!L)
                memcpy(nxt + P + 257, d + P + 257, n - (size_t)P - 257);
        }
        for (k = 0; k < n; k++)
            if (nxt[k] != r[k]) {
                same = 0;
                break;
            }
        memcpy(r, nxt, n);
        free(nxt);
        if (same)
            return 0;
    }
    return 0;
}

/*
 * Forward mode 4 (text).  The decoder applies the substitution map, drops a
 * space after the line-break target, folds CR/CRLF to CRLF and finally expands
 * 0x80..0xFC through the token table, so the encoder runs those steps
 * backwards: tokenize the text, fold, duplicate the spaces that will be
 * dropped, and apply the inverse of the map.
 *
 * The tokenizer's exact rule is measured, not guessed: longest match wins
 * (4, then 3, then 2 bytes, ties by table order) and the last four bytes are
 * never tokenized.  With that, every e2 == 0 mode-4 layer dump reproduces
 * byte for byte (code-m1/m2/m3 at ctrl 0xAC, eng-m1/m2/m3 and the two solid
 * variants at 0x8C).  The `ctrl` bits are the header's (not the vendor's
 * ctrl>>1); see sbc_apply_mode4() for what each one means.
 */
static uint8_t sbc_enc_m4_inv[256];
static uint8_t sbc_enc_m4_first[256][16]; /* token codes by first byte */
static uint8_t sbc_enc_m4_nfirst[256];
static int sbc_enc_m4_ready;
/* How many token codes the matcher may use: 125 normally.  SBC_M4TOK126 adds
 * the decompressor's 0xFD (`wh`) so the forge tests can produce a record the
 * vendor's compressor never emits; byte-exact parity needs it off. */
static int sbc_enc_m4_ntok;
/* Coded units the last sbc_enc_m4_tokenize() emitted: token codes plus the
 * 0xFF capital markers.  The record's token bit (`ctrl` 0x80) is only honest
 * when this is nonzero -- a pass that wrote plain literals is the identity as
 * far as the decoder's bit is concerned -- and the vendor clears it: `a b c
 * ...` prose (200 kB, the letters separated by spaces, so no table entry can
 * match) is recorded as ctrl 0x0C at all three levels, not 0x8C. */
static long sbc_enc_m4_units;
/* Control word of the last sbc_enc_mode4() call: `ctrl` with the token bit
 * dropped when that pass emitted no coded unit.  The caller writes this one. */
static uint32_t sbc_enc_m4_ctrl_eff;

/* The tokenizer stops at 0xFC: the compressor's own table has a 126th
 * entry (0xFD `wh`) but never emits it -- the byte-exact layer dumps on the
 * corpus prove the tokenizer only matches 125 words.  The decompressor
 * expands 0xFD (`SBC_MODE4_NTOK` 126 in sbc.c); the encoder must not, or its
 * archives stop matching the vendor. */
#define SBC_ENC_M4_NTOK 125

static void sbc_enc_m4_init(void)
{
    int b, c, k;
    if (sbc_enc_m4_ready)
        return;
    for (b = 0; b < 256; b++)
        sbc_enc_m4_inv[SBC_MODE4_MAP[b]] = (uint8_t)b;
    sbc_enc_m4_ntok = getenv("SBC_M4TOK126") ? 126 : SBC_ENC_M4_NTOK;
    memset(sbc_enc_m4_nfirst, 0, sizeof(sbc_enc_m4_nfirst));
    for (c = 0; c < sbc_enc_m4_ntok; c++) {
        unsigned f = (unsigned char)SBC_MODE4_TOKENS[c][0];
        if (sbc_enc_m4_nfirst[f] < 16)
            sbc_enc_m4_first[f][sbc_enc_m4_nfirst[f]++] = (uint8_t)c;
    }
    for (b = 0; b < 256; b++) {
        uint8_t *v = sbc_enc_m4_first[b];
        int n = sbc_enc_m4_nfirst[b];
        for (c = 1; c < n; c++) {   /* insertion sort by length, then code */
            uint8_t t = v[c];
            size_t tl = strlen(SBC_MODE4_TOKENS[t]);
            for (k = c; k > 0; k--) {
                uint8_t u = v[k - 1];
                size_t ul = strlen(SBC_MODE4_TOKENS[u]);
                if (ul > tl || (ul == tl && u < t))
                    break;
                v[k] = u;
            }
            v[k] = t;
        }
    }
    sbc_enc_m4_ready = 1;
}

/* ---- mode 4 prose pass: the line model in reverse ----------------------
 *
 * The decoder's 0x408060 turns a stored stream into the real text: a line
 * break is either `<target> SP` (the space is dropped) or a *marker space*
 * that fires once `cnt >= min(sym + 7, 24)` and becomes the target.  A line
 * with 7..24 spaces can therefore fold its break into one space and code the
 * count as `k - 7`; anything else (`k < 7`, `k > 24`, the final line with no
 * break) stays literal, and a long line is walked through with the `0x12`
 * "fire, write nothing" escape every 24 spaces.
 *
 * The 19-symbol range coder is the vendor's: every frequency starts at 1, an
 * increment is 7, the model rescales above 8192 and a symbol above 768.
 * Because the decoder reads its bytes from the *end* of `e2`, the encoder
 * stores `le32(low)` first and then its renormalisation bytes in reverse
 * emission order.  Verified against every vendor `e2` we can dump and
 * replayed by tools/m4_line_parity.py (144/144 geometry samples, 9/9 real
 * blocks).
 */
#define SBC_M4_LINE_MIN 7
#define SBC_M4_MAXTHR   0x18
#define SBC_M4_NOBREAK  0x12
#define SBC_M4_PENDING  0x13
#define SBC_M4_NSYM     19

typedef struct {
    uint32_t low, range;
    uint32_t freq[SBC_M4_NSYM], total;
    uint8_t *p;
    size_t n, cap;
    int err;
} SbcM4Range;

static void sbc_m4r_put(SbcM4Range *c, uint8_t b)
{
    if (c->n == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 128;
        uint8_t *np = (uint8_t *)realloc(c->p, ncap);
        if (!np) {
            c->err = 1;
            return;
        }
        c->p = np;
        c->cap = ncap;
    }
    c->p[c->n++] = b;
}

static void sbc_m4r_rescale(SbcM4Range *c)
{
    for (;;) {
        uint32_t total = 0;
        int i;
        for (i = 0; i < SBC_M4_NSYM; i++) {
            c->freq[i] -= c->freq[i] >> 1;
            total += c->freq[i];
        }
        c->total = total;
        if (total <= 8192)
            return;
    }
}

static void sbc_m4r_renorm(SbcM4Range *c)
{
    for (;;) {
        uint32_t top = (c->low + c->range) ^ c->low;
        if (top <= 0xFFFFFFu) {
            /* the top byte is settled */
        } else if (c->range <= 0x3FFFu) {
            c->range = (0u - c->low) & 0x3FFFu;
        } else {
            return;
        }
        sbc_m4r_put(c, (uint8_t)(c->low >> 24));
        c->low <<= 8;
        c->range <<= 8;
        if (c->err)
            return;
    }
}

static void sbc_m4r_sym(SbcM4Range *c, int sym)
{
    uint32_t unit, cum = 0;
    int i;
    if (c->total > 8192)
        sbc_m4r_rescale(c);
    unit = c->range / c->total;
    for (i = 0; i < sym; i++)
        cum += c->freq[i];
    c->low += unit * cum;
    c->range = unit * c->freq[sym];
    sbc_m4r_renorm(c);
    c->freq[sym] += 7;
    c->total += 7;
    if (c->freq[sym] > 768)
        sbc_m4r_rescale(c);
}

/* Flush: `le32(low)` then the renormalisation bytes in reverse emission
 * order, which is the order the vendor's backwards reader pulls them. */
static uint8_t *sbc_m4r_finish(SbcM4Range *c, size_t *outn)
{
    uint8_t *r;
    size_t i;
    if (c->err)
        return NULL;
    r = (uint8_t *)malloc(c->n + 4);
    if (!r)
        return NULL;
    r[0] = (uint8_t)c->low;
    r[1] = (uint8_t)(c->low >> 8);
    r[2] = (uint8_t)(c->low >> 16);
    r[3] = (uint8_t)(c->low >> 24);
    for (i = 0; i < c->n; i++)
        r[4 + i] = c->p[c->n - 1 - i];
    *outn = c->n + 4;
    return r;
}

/* Which symbol does the vendor arm at a space?  It looks for the next line
 * that can fold (7..24 spaces) and codes its count; a longer line, or no line
 * at all, gives the no-break escape. */
static int sbc_enc_m4_choose(const size_t *k, size_t start, size_t last)
{
    size_t j;
    for (j = start; j < last; j++) {
        if (k[j] > SBC_M4_MAXTHR)
            return SBC_M4_NOBREAK;
        if (k[j] >= SBC_M4_LINE_MIN)
            return (int)(k[j] - SBC_M4_LINE_MIN);
    }
    return SBC_M4_NOBREAK;
}

/* Build the pass input and its line code from the raw text `t` (the vendor
 * folds before it tokenizes, so this runs on plain bytes).  For a CR target
 * `t` must already have lost the LF of every CRLF, since the decoder's fold
 * puts it back. */
static int sbc_enc_m4_lines(const uint8_t *t, size_t tn, uint8_t target,
                            uint8_t **inp, size_t *inn,
                            uint8_t **codep, size_t *coden)
{
    size_t i, j, nt = 0, last, inlen = 0, ns = 0;
    size_t *st = NULL, *kk = NULL;
    uint8_t *in = NULL, *syms = NULL, *code = NULL;
    SbcM4Range rc;
    uint32_t cnt = 0;
    int cur = SBC_M4_PENDING;

    for (i = 0; i < tn; i++)
        if (t[i] == target)
            nt++;
    last = nt;                      /* the segment with no trailing break */
    st = (size_t *)malloc((nt + 1) * sizeof(*st));
    kk = (size_t *)calloc(nt + 1, sizeof(*kk));
    in = (uint8_t *)malloc(tn + nt + 8);
    syms = (uint8_t *)malloc(tn + nt + 8);
    if (!st || !kk || !in || !syms)
        goto fail;
    st[0] = 0;
    j = 0;
    for (i = 0; i < tn; i++)
        if (t[i] == target)
            st[++j] = i + 1;
    for (i = 0; i <= last; i++) {
        size_t end = (i < last) ? st[i + 1] - 1 : tn;
        for (j = st[i]; j < end; j++)
            if (t[j] == 0x20)
                kk[i]++;
    }
    for (i = 0; i <= last; i++) {
        size_t end = (i < last) ? st[i + 1] - 1 : tn;
        int fold = i < last && kk[i] >= SBC_M4_LINE_MIN &&
                   kk[i] <= SBC_M4_MAXTHR;
        int first = 1;
        for (j = st[i]; j < end; j++) {
            uint8_t c = t[j];
            in[inlen++] = c;
            if (c != 0x20)
                continue;
            if (cur == SBC_M4_PENDING) {
                cur = sbc_enc_m4_choose(kk, first ? i : i + 1, last);
                syms[ns++] = (uint8_t)cur;
            }
            if (cnt >= (uint32_t)(cur + SBC_M4_LINE_MIN < SBC_M4_MAXTHR
                                  ? cur + SBC_M4_LINE_MIN : SBC_M4_MAXTHR)) {
                cur = SBC_M4_PENDING;
                cnt = 0;
            } else {
                cnt++;
            }
            first = 0;
        }
        if (fold) {
            in[inlen++] = 0x20;     /* the marker space becomes the break */
            if (cur == SBC_M4_PENDING) {
                cur = sbc_enc_m4_choose(kk, first ? i : i + 1, last);
                syms[ns++] = (uint8_t)cur;
            }
            if (cnt >= (uint32_t)(cur + SBC_M4_LINE_MIN < SBC_M4_MAXTHR
                                  ? cur + SBC_M4_LINE_MIN : SBC_M4_MAXTHR)) {
                cur = SBC_M4_PENDING;
                cnt = 0;
            } else {
                goto fail;          /* the planner lost the sync */
            }
        } else if (i < last) {
            /* `<target> SP`: the decoder drops the space.  A CR break always
             * carries one -- that space *is* the CRLF's LF, turned into the
             * byte the expander removes -- even at the end of the block.  An
             * LF break only gets one where a word can follow, i.e. when the
             * next line starts with a letter (a capital still gets it: the
             * 0xFF marker comes after the space) or a space; a digit, a tab,
             * punctuation, an empty line or the end of the block gets none. */
            in[inlen++] = target;
            if (target == 0x0D) {
                in[inlen++] = 0x20;
            } else {
                uint8_t nb = st[i + 1] < tn ? t[st[i + 1]] : 0;
                if (nb == 0x20 || (nb >= 'A' && nb <= 'Z') ||
                    (nb >= 'a' && nb <= 'z'))
                    in[inlen++] = 0x20;
            }
            cnt = 0;
        }
    }
    memset(&rc, 0, sizeof(rc));
    rc.range = 0xFFFFFFFFu;
    for (j = 0; j < SBC_M4_NSYM; j++)
        rc.freq[j] = 1;
    rc.total = SBC_M4_NSYM;
    for (j = 0; j < ns; j++)
        sbc_m4r_sym(&rc, syms[j]);
    code = sbc_m4r_finish(&rc, coden);
    free(rc.p);
    if (!code)
        goto fail;
    free(st);
    free(kk);
    free(syms);
    *inp = in;
    *inn = inlen;
    *codep = code;
    return 0;
fail:
    free(st);
    free(kk);
    free(in);
    free(syms);
    if (code)
        free(code);
    return -1;
}

/* ---- mode 4 `ctrl` chooser: the vendor's text classifier --------------
 *
 * Mirror of sbc.exe 0x40cb80, called from 0x4132c0 with one file segment and
 * returning the record's ctrl word, 0 when the segment is not prose.  The
 * word is the vendor's *internal* ctrl: the record stores it shifted left by
 * one, so internal 0x46/0x56/0x5e become the header's 0x8c/0xac/0xbc.  The
 * bits are
 *
 *   0x02  always set (header 0x04, part of the fixed base)
 *   0x04  "the block has lines longer than 24 bytes" (header 0x08)
 *   0x08  worth folding line breaks into marker spaces (header 0x10)
 *   0x10  drop the space the encoder puts after each line break (header 0x20)
 *   0x40  tokenize with the mode-4 table (header 0x80)
 *   0x80  "flat" text: the spacing test 0x4103f0 accepted it (header 0x100)
 *
 * The classification is byte statistics, not a tokenizer probe: one pass
 * builds three 256-bin histograms -- C[] over the bytes, A[] over the byte
 * that starts a line whose predecessor carried 7..25 spaces, B[] over the
 * byte after a space -- and the decisions are threshold tests on their sums.
 * That is why line *geometry* and not content decides the ctrl (the corpus
 * code.c gets 0xac, prose of the same length 0xbc).
 *
 * The port was checked against the binary with _work/ctrl_emu.py, an
 * interpreter for the vendor function itself (23/23 reachable decisions on
 * the corpus and the synthetic prose probes), and the C below is a
 * transliteration of the same control flow; tools/m4_ctrl_parity.py compares
 * the two on generated inputs.
 *
 * One branch is faithfully mirrored but never observable: when the spacing
 * test passes the vendor returns 0x80, i.e. a record ctrl of 0x100, a value
 * neither our decoder nor the filter models.  No natural input reaches it
 * (the vendor's own decoder accepts the ctrl, so it is a real variant); the
 * header is documented in ENCODER.md 6.11 and the policy treats it as "not
 * prose" so an undecodable record is never written.
 */

/* byte of the segment, with the vendor's one-past-the-end read mapped to 0 */
static uint8_t sbc_m4_at(const uint8_t *d, size_t n, size_t i)
{
    return i < n ? d[i] : 0;
}

/* 0x4103f0: "the words are short enough for prose". */
static int sbc_m4_spacing(const uint32_t *C, uint32_t n)
{
    static const uint8_t ks[25] = { 46, 32, 91, 93, 97, 98, 99, 100, 101,
                                    102, 103, 104, 49, 50, 51, 52, 53, 54,
                                    55, 56, 82, 78, 66, 81, 75 };
    uint32_t i, total = 0;

    if (n <= 0x7F)
        return 0;
    for (i = 0; i < 25; i++)
        total += n / (C[ks[i]] + 1);
    if (total > 0x1116)
        return 0;
    if (C[0])
        return 0;
    for (i = 0xC0; i < 0x100; i++)
        if (C[i])
            return 0;
    return 1;
}

#define M4P(x) do { if (getenv("SBC_M4CTRLDBG")) fprintf(stderr, "m4at %s\n", x); } while (0)
#define M4RET() do { if (getenv("SBC_M4CTRLDBG")) fprintf(stderr, "m4ret %d\n", __LINE__); return 0; } while (0)
static uint32_t sbc_enc_m4_ctrl(const uint8_t *d, size_t n)
{
    uint32_t A[256], B[256], C[256];
    uint8_t cls[256];
    uint32_t distinct = 0, run = 0;
    uint32_t b28 = 0x30, b2c = 0, b30 = 0, b34 = 0, b38 = 0, b3c = 0;
    uint32_t acc40 = 0, s44 = 0, s48 = 0;
    uint32_t avg1 = 0, avg2 = 0, out0 = 0, out1 = 0, sumc = 0;
    uint32_t lf, cr, sp, m;
    uint32_t eax, ebx, ebp, edi, edx, step = 0, cv = 0, t;
    size_t ecx;
    uint32_t i;

    if (n <= 0x100)
        M4RET();
    memset(A, 0, sizeof(A));
    memset(B, 0, sizeof(B));
    memset(C, 0, sizeof(C));
    memset(cls, 0, sizeof(cls));
    cls[0x0A] = 2;              /* line break */
    cls[0x20] = 3;              /* space      */

    /* 0x40cd39: the histogram pass. */
    ecx = 1;
    for (;;) {
        uint8_t cb = d[ecx - 1];
        uint8_t cl;

        if (++C[cb] == 1 && ++distinct > 0x95)
            M4RET();
        if (b28 && cb == 0x0D && !(ecx < n && d[ecx] == 0x0A)) {
            cls[0x0D] = 1;      /* a lone CR is data, not a line break */
            b28 = 0;
        }
        edx = (uint32_t)ecx;
        cl = cls[cb];
        if (cl == 2) {                     /* 0x40d1b0: line break */
            if (b28 && (ecx < 2 || d[ecx - 2] != 0x0D))
                b2c = 1;
            if (run >= 7 && run <= 25)
                A[sbc_m4_at(d, n, ecx)]++;
            run = 0;
        } else if (cl == 3) {              /* 0x40cd7e: space */
            if (++run > 0x18) {
                run = 0;
                acc40++;
            }
            if (ecx < n && d[ecx] == 0x20) {
                /* a run of spaces carries no word */
            } else {
                uint8_t nb = sbc_m4_at(d, n, ecx);
                ecx++;
                B[nb]++;
                if ((uint32_t)n > edx)
                    continue;
                break;
            }
        }
        /* 0x40cd34 */
        ecx++;
        if ((uint32_t)n <= edx)
            break;
    }

    /* 0x40cda6: the line/word geometry estimates. */
    lf = C[10];
    cr = C[13];
    sp = C[32];
    if (getenv("SBC_M4CTRLDBG"))
        fprintf(stderr, "M4C distinct=%u lf=%u cr=%u sp=%u run=%u acc40=%u\n",
                distinct, lf, cr, sp, run, acc40);
    if (distinct <= 0x13)
        M4RET();
    m = (cr < lf) ? lf : cr;
    edi = ((m + sp) >> 2) + 1;
    avg1 = (uint32_t)n / edi;
    if (avg1 > 0x64)
        M4RET();
    s44 = C[90] + C[89];
    for (i = 0; i < 25; i++)
        s44 += C[88 - i];                         /* 'A'..'Z' */
    s48 = C[122] + C[121];
    for (i = 1; i <= 24; i++)
        s48 += C[96 + i];                         /* 'a'..'x' */
    eax = cr + m + sp + C[9] + s44 + s48;
    edi = (eax >> 2) + 1;
    avg2 = (uint32_t)n / edi;
    if (avg2 <= 0xe)
        goto l_d202;
    eax = avg1 - 0xb;
    if (eax > 0xd)
        M4RET();

l_ce95:
    M4P("l_ce95");
    if (b28) {
        if (cr < ((uint32_t)n >> 7))
            goto l_cec4;
        edx = (uint32_t)(((uint64_t)n * 0xcccccccdULL) >> 36);   /* n/10 */
        if (cr <= edx)
            goto l_d227;
    }

l_cec4:
    M4P("l_cec4");
    if (lf <= cr)
        goto l_d326;
    if (lf >= cr + (cr >> 1))
        goto l_d394;
    b3c = 0;
    b38 = 0;
    b28 = 0;

l_cef2:
    M4P("l_cef2");
    eax = C[101] + C[46];
    edi = eax + 1;
    ebx = (uint32_t)n / edi;
    if (ebx > 0x28)
        goto l_cf49;
    eax = C[50] + C[49] + C[51];
    edi = eax + 1;
    ebx = (uint32_t)n / edi;
    if (ebx <= 0x1e)
        goto l_d464;

l_cf49:
    M4P("l_cf49");
    b34 = 0;

l_cf51:
    M4P("l_cf51");
    eax = 0;                                      /* 0x40cf51 */
    for (i = 0; i < 0x100; i++)
        if ((i < 0x20 || i >= 0x7f) && i != 9 && i != 10 && i != 13)
            eax += C[i];
    sumc = eax;      /* ecx at 0x40d0c9: the same sum, used again at 0x40d3e6 */
    eax -= C[142] + C[148] + C[132] + C[153] + C[27] + C[8] + C[0];
    M4P("cf51vals");
    if (getenv("SBC_M4CTRLDBG")) fprintf(stderr, "  nonprint=%u nth=%u avg2=%u s48=%u n=%u\n", eax, (uint32_t)n>>8, avg2, s48, (uint32_t)n);
    if (eax > ((uint32_t)n >> 8))
        goto l_d0fa;
    if (avg2 > 0xe)
        goto l_d0fa;
    edi = (s48 >> 2) + 1;
    eax = (uint32_t)n / edi;
    if (eax <= 0x18)
        goto l_d3aa;

l_d0fa:
    M4P("l_d0fa");
    edi = 0;
    ebp = 0;
    b30 = 0;
    goto l_d106;

l_d3aa:
    M4P("l_d3aa");
    ebx = s44 >> 2;
    b30 = 4;
    s44 = ebx;
    edi = ebx + 1;
    eax = (uint32_t)n / edi;
    if (eax > 0x18)
        goto l_d3dc;
    b30 = 0;

l_d3dc:
    M4P("l_d3dc");
    /* 0x40d3e6 compares the *nonprintable sum* left in ecx, not cr: the vendor
     * never clears ecx after 0x40d0c7, so a text block always passes. */
    if (sumc > ((uint32_t)n >> 10))
        goto l_d48c;
    edx = C[116] + C[104] + 1 + C[101] + C[97] + C[99] + C[119];
    eax = (uint32_t)n / edx;
    if (eax > 9)
        goto l_d48c;
    if (n == 0x601b)
        goto l_d48c;
    edi = 0x40;
    ebp = 2;
    goto l_d106;

l_d48c:
    M4P("l_d48c");
    edi = 0;
    ebp = 2;

l_d106:
    M4P("l_d106");
    /* 0x40d106: the two rarest bytes outside space/lowercase/0x80+, kept in
     * the caller's two-byte scratch; a missing second byte reads as its
     * zeroed slot, which is what the vendor's callers leave there. */
    out0 = 0;
    out1 = 0;
    for (edx = 0xff; edx != 0; edx--) {
        if (C[edx])
            continue;
        if (edx == 0x20)
            continue;
        if ((uint32_t)(edx - 0x61) <= 0x19)
            continue;
        if ((uint32_t)(edx - 0x80) <= 0x7d)
            continue;
        if (!out0) {
            out0 = edx;
            continue;
        }
        out1 = edx;
        goto l_d30e;
    }
    eax = 0;
    b30 = 0;
    edi = 0;
    goto l_d14f;

l_d30e:
    M4P("l_d30e");
    eax = (out1 != 0xFE) ? 1u : 0u;

l_d14f:
    M4P("l_d14f");
    if (b34) {
        b28 = 0;
        b30 = 0;
        b38 = 0;
        edi = 0;
        b3c = 0;
        cv = 0;
        edx = 0;
        goto l_d181;
    }
    cv = eax | ebp;
    edx = b30 | ebp;

l_d181:
    M4P("l_d181");
    if ((edx | b34) == 0)
        M4RET();
    if (getenv("SBC_M4CTRLDBG")) fprintf(stderr,"m4final %x %x %x %x %x %x %x\n",b28,b30,b34,b38,edi,b3c,cv);
    return b28 | b30 | b34 | b38 | edi | b3c | cv;

l_d202:
    M4P("l_d202");
    edi = (s48 >> 2) + 1;
    eax = (uint32_t)n / edi;
    if (eax <= 0x18)
        goto l_ce95;
    eax = avg1 - 0xb;
    if (eax > 0xd)
        M4RET();
    goto l_ce95;

l_d227:
    M4P("l_d227");
    if (sbc_m4_at(d, n, 0) == 0x0A)
        goto l_d237;
    if (lf == cr)
        goto l_d23f;

l_d237:
    M4P("l_d237");
    b2c = 1;

l_d23f:
    M4P("l_d23f");
    b38 = 0;

l_d247:
    M4P("l_d247");
    if ((b28 | b38) == 0)
        goto l_d2f2;
    if (b2c == 1)
        goto l_d453;

l_d260:
    M4P("l_d260");
    step = (uint32_t)n >> 10;
    if (step == 0)
        step = 1;
    edi = acc40;
    ebp = 0;
    {
        uint32_t av = A[255];
        uint32_t bv = B[255];
        edi += (av / step) * av;
        ebp = (bv / step) * av;
    }
    for (ebx = 255; ebx >= 1; ebx--) {
        uint32_t av = A[ebx - 1];
        uint32_t bv = B[ebx - 1];
        edi += (av / step) * av;
        ebp += (bv / step) * av;
    }
    if (n == 0x2eb2)
        edi >>= 1;                             /* 0x40d498 */
    eax = edi * 5;
    b3c = 0x08;
    eax += eax;
    if (ebp > eax)
        goto l_cef2;

l_d2f2:
    M4P("l_d2f2");
    b3c = 0;
    goto l_cef2;

l_d326:
    M4P("l_d326");
    if (cr < lf + (lf >> 1))
        goto l_ceda;
    edi = cr;
    b38 = 0x20;
    goto l_d33e;

l_d394:
    M4P("l_d394");
    edi = lf;
    b38 = 0x10;

l_d33e:
    M4P("l_d33e");
    edx = (uint32_t)(((uint64_t)((uint32_t)n >> 1) * 0xb60b60b7ULL) >> 37);
    if (edi < edx)
        goto l_d37f;
    t = (b38 == 0x10) ? lf : cr;
    edx = (uint32_t)(((uint64_t)n * 0x51eb851fULL) >> 35);
    b28 = 0;
    if (t <= edx)
        goto l_d247;

l_d37f:
    M4P("l_d37f");
    b38 = 0;
    b28 = 0;
    goto l_d247;

l_d453:
    M4P("l_d453");
    if (b28 != 0)
        goto l_d2f2;
    goto l_d260;

l_ceda:
    M4P("l_ceda");
    b3c = 0;
    b38 = 0;
    b28 = 0;
    goto l_cef2;

l_d464:
    M4P("l_d464");
    b34 = sbc_m4_spacing(C, (uint32_t)n) ? 0x80u : 0u;
    goto l_cf51;
}

/* 0x406940's prologue, in the record's (header) ctrl convention: it names
 * the capital marker (0x406ed0) and the token escape (0x406f20).  Bit 0 of
 * the vendor word (header 0x02) swaps the fixed 0xFF/0xFE pair for two bytes
 * derived from the salt in the word's bytes 1 and 2. */
static void sbc_enc_m4_markers(uint32_t ctrl, uint8_t *m0, uint8_t *m1)
{
    uint32_t v = ctrl >> 1;
    *m0 = 0xFF;
    *m1 = 0xFE;
    if (ctrl & 0x02u) {
        *m0 = (uint8_t)(((v >> 8) & 0xFFu) ^ 0xFFu);
        *m1 = (uint8_t)(*m0 - (uint8_t)((v >> 16) & 0xFFu) - 1u);
    }
}

/* Stored form of one filtered byte: the map's inverse when the record carries
 * the map bit (vendor 0x02 = header 0x04), the byte itself otherwise. */
static uint8_t sbc_enc_m4_store(uint8_t c, uint32_t ctrl)
{
    return (ctrl & 0x04u) ? sbc_enc_m4_inv[c] : c;
}

/* Token stream of `d`: tokens are 0x80+code, a capital that starts a
 * lowercase run gets the capital marker (`m0`) in front, and a literal byte
 * equal to the escape marker (`m1`) is doubled so 0x406f20 copies one.  With
 * the record's capital bit clear (header 0x08 = vendor 0x04) no marker is
 * emitted and no lowercasing happens: 0x406ed0 would not run, so the text
 * must already be in its final case.  `ch` (optional) receives the original
 * first byte of every unit -- the placeholder pass of the plain path needs it
 * to decide where a dropped space can usefully go. */
static int sbc_enc_m4_tokenize(const uint8_t *d, size_t n, uint32_t ctrl,
                               uint8_t **outp, size_t *outn, uint8_t **chp)
{
    uint8_t *t, *low, *tch;
    size_t i, tn = 0;
    uint8_t m0, m1;
    int caps = (ctrl & 0x08u) != 0;

    sbc_enc_m4_markers(ctrl, &m0, &m1);
    sbc_enc_m4_units = 0;
    t = (uint8_t *)malloc(n * 2 + 8);
    low = (uint8_t *)malloc(n ? n : 1);
    tch = (uint8_t *)malloc(n * 2 + 8);
    if (!t || !low || !tch) {
        free(t);
        free(low);
        free(tch);
        return -1;
    }
#define M4LIT(x)                                                       \
    do {                                                               \
        uint8_t _c = (x);                                             \
        /* 0x406f20 expands 0x80..0xFD before it looks at the escape,   \
         * so a literal in that range (or the escape byte itself)      \
         * needs the marker in front.  `m1` must stay outside the      \
         * token range for this to be reachable. */                   \
        if (_c == m1 || (_c >= 0x80 && _c <= 0xFD)) {                  \
            t[tn] = m1;                                               \
            tch[tn++] = _c;                                            \
        }                                                              \
        t[tn] = _c;                                                    \
        tch[tn++] = _c;                                                \
    } while (0)
    /* Tokens are lowercase, so the vendor lowercases the text to match them
     * and marks a capital that starts a lowercase run with 0xFF (stored as
     * 0x29).  A capital whose next letter is not lowercase stays literal,
     * and a token never spans a capital (`tHe` is `t` + marker + `he`, while
     * `The` is marker + the `the` token). */
    for (i = 0; i < n; i++)
        low[i] = (caps && d[i] >= 'A' && d[i] <= 'Z') ? (uint8_t)(d[i] + 32) : d[i];
    for (i = 0; i < n;) {
        int hit = -1;
        int up = caps && d[i] >= 'A' && d[i] <= 'Z';
        int upfirst = up && i + 1 < n && d[i + 1] >= 'a' && d[i + 1] <= 'z';
        int lower_ok = d[i] >= 'a' && d[i] <= 'z';

        if ((lower_ok || upfirst) && n - i > 4) {
            const uint8_t *v = sbc_enc_m4_first[low[i]];
            int k;
            for (k = 0; k < (int)sbc_enc_m4_nfirst[low[i]]; k++) {
                int c = v[k];
                size_t len = strlen(SBC_MODE4_TOKENS[c]), q;
                if (len > n - i || memcmp(low + i, SBC_MODE4_TOKENS[c], len))
                    continue;
                for (q = 1; q < len; q++)
                    if (d[i + q] >= 'A' && d[i + q] <= 'Z')
                        break;
                if (q < len)
                    continue;   /* a capital inside the match: not a token */
                hit = c;        /* the table is sorted longest-first */
                break;
            }
        }
        if (hit >= 0) {
            if (upfirst) {
                t[tn] = m0;
                tch[tn++] = d[i];
                sbc_enc_m4_units++;
            }
            t[tn] = (uint8_t)(0x80 + hit);
            tch[tn++] = d[i];
            sbc_enc_m4_units++;
            i += strlen(SBC_MODE4_TOKENS[hit]);
            continue;
        }
        if (upfirst) {
            t[tn] = m0;
            tch[tn++] = d[i];
            sbc_enc_m4_units++;
            M4LIT(low[i]);
        } else {
            M4LIT(d[i]);      /* a capital without a lowercase run stays as it is */
        }
        i++;
    }
#undef M4LIT
    free(low);
    *outp = t;
    *outn = tn;
    if (chp)
        *chp = tch;
    else
        free(tch);
    return 0;
}

static int sbc_enc_mode4(const uint8_t *d, size_t n, uint32_t ctrl,
                         uint8_t **outp, size_t *outn,
                         uint8_t **codep, size_t *coden)
{
    uint8_t *t = NULL, *p, *m = NULL, *r, *ptch = NULL, *code = NULL;
    size_t i, j, tn = 0, pn = 0, mn = 0, coden_ = 0;
    uint8_t m0, m1;

    if (codep)
        *codep = NULL;
    if (coden)
        *coden = 0;
    sbc_enc_m4_init();
    sbc_enc_m4_markers(ctrl, &m0, &m1);
    (void)m1;
    sbc_enc_m4_ctrl_eff = ctrl;
    if (!(ctrl & 0x80u)) {
        /* The token bit is clear: the vendor's decoder skips the 0x407d20
         * expansion, so the record is the plain byte map and the filter's
         * output is its inverse (`wide`: ctrl 0x0C, e2 0, no line code).  The
         * chooser only returns such a word when nothing else applies; the
         * record then does not shrink at all and keeps its own mode. */
        uint8_t *r0 = (uint8_t *)malloc(n ? n : 1);
        if (!r0)
            return -1;
        for (i = 0; i < n; i++)
            r0[i] = sbc_enc_m4_store(d[i], ctrl);
        *outp = r0;
        *outn = n;
        return 0;
    }
    if (ctrl & 0x10u) {
        /* Line model.  The fold runs *before* the tokenizer: the vendor feeds
         * the folded stream (marker spaces and placeholders included) to the
         * tokenizer, so its "last four bytes stay literal" rule sees the
         * folded length.  A break that folds loses one byte, which is what
         * keeps the final word of a folded last line out of the table; a
         * literal CRLF break keeps two (`CR SP`), so it does not shift the
         * boundary.  For a CR target the LF of every CRLF has to go first
         * (the decoder's 0x406b68 puts it back). */
        uint8_t target = (ctrl & 0x40u) ? 0x0D : 0x0A;
        uint8_t *strip = NULL;
        const uint8_t *src = d;
        size_t sn = n;

        if (target == 0x0D) {
            size_t k = 0;
            strip = (uint8_t *)malloc(n ? n : 1);
            if (!strip)
                return -1;
            for (i = 0; i < n; i++) {
                if (d[i] == 0x0A && k && strip[k - 1] == 0x0D)
                    continue;
                strip[k++] = d[i];
            }
            src = strip;
            sn = k;
        }
        if (sbc_enc_m4_lines(src, sn, target, &m, &mn, &code, &coden_) != 0) {
            free(strip);
            return -1;
        }
        free(strip);
        if (sbc_enc_m4_tokenize(m, mn, ctrl, &t, &tn, NULL) != 0) {
            free(m);
            free(code);
            return -1;
        }
        if (!sbc_enc_m4_units) {
            /* The pass coded nothing, so the record drops the token bit and
             * the decoder will not expand: the escapes written for
             * 0x80..0xFD literals must not reach the stream (the vendor's
             * no-token records store the plain mapped bytes). */
            uint8_t *plain = (uint8_t *)malloc(mn ? mn : 1);
            if (!plain) {
                free(t);
                free(m);
                free(code);
                return -1;
            }
            if (mn)
                memcpy(plain, m, mn);
            free(t);
            t = plain;
            tn = mn;
            sbc_enc_m4_ctrl_eff = ctrl & ~0x80u;
        }
        free(m);
        r = (uint8_t *)malloc(tn ? tn : 1);
        if (!r) {
            free(t);
            free(code);
            return -1;
        }
        for (j = 0; j < tn; j++)
            r[j] = sbc_enc_m4_store(t[j], ctrl);
        free(t);
        *outp = r;
        *outn = tn;
        if (codep)
            *codep = code;
        else
            free(code);
        if (coden)
            *coden = coden_;
        return 0;
    }
    if (sbc_enc_m4_tokenize(d, n, ctrl, &t, &tn, &ptch) != 0)
        return -1;
    if (!sbc_enc_m4_units) {
        /* Same fallback as the line path: no unit means the token bit goes
         * away and the stream has to be the plain bytes again. */
        uint8_t *plain = (uint8_t *)malloc(n ? n : 1);
        uint8_t *pch = (uint8_t *)malloc(n ? n : 1);
        if (!plain || !pch) {
            free(plain);
            free(pch);
            free(t);
            free(ptch);
            return -1;
        }
        if (n) {
            memcpy(plain, d, n);
            memcpy(pch, d, n);
        }
        free(t);
        free(ptch);
        t = plain;
        ptch = pch;
        tn = n;
        sbc_enc_m4_ctrl_eff = ctrl & ~0x80u;
    }
    p = (uint8_t *)malloc(tn * 2 + 16);
    if (!p) {
        free(t);
        free(ptch);
        return -1;
    }
    for (j = 0; j < tn; j++) {   /* inverse of the CR/CRLF fold */
        uint8_t c = t[j];
        p[pn] = c;
        ptch[pn++] = ptch[j];
        if ((ctrl & 0x60u) == 0x60u && c == 0x0D) {
            if (j + 1 < tn && t[j + 1] == 0x0A)
                j++;
            p[pn] = 0x0A;
            ptch[pn++] = ptch[j];
        }
    }
    free(t);
    m = (uint8_t *)malloc(pn * 2 + 16);
    if (!m) {
        free(p);
        free(ptch);
        return -1;
    }
    for (j = 0; j < pn; j++) {   /* re-insert the space the decoder drops */
        uint8_t c = p[j];
        m[mn++] = c;
        if (((ctrl & 0x20u) && c == 0x0A) || ((ctrl & 0x40u) && c == 0x0D)) {
            uint8_t nx;
            if ((ctrl & 0x60u) == 0x60u && c == 0x0D)
                continue;        /* the fold's LF carries the space */
            nx = (j + 1 < pn) ? ptch[j + 1] : 0;
            if (j + 1 >= pn || (p[j + 1] != m0 &&
                                (nx == ' ' || (nx >= 'A' && nx <= 'Z') ||
                                 (nx >= 'a' && nx <= 'z'))))
                m[mn++] = 0x20;
        }
    }
    free(p);
    free(ptch);
    r = (uint8_t *)malloc(mn ? mn : 1);
    if (!r) {
        free(m);
        return -1;
    }
    for (j = 0; j < mn; j++)
        r[j] = sbc_enc_m4_store(m[j], ctrl);
    free(m);
    *outp = r;
    *outn = mn;
    return 0;
}
/* Forward mode 7 (0x429bd0): data -> residuals, `param` as in the record. */
static int sbc_enc_mode7(const uint8_t *d, size_t n, uint32_t param,
                         uint8_t *r)
{
    size_t W, row, i;
    uint16_t *ctx0, *ctx1, *ctx2;
    uint32_t *cost;
    uint8_t *cnt0, *cnt1, *cnt2;
    uint32_t sum[4] = { 0, 0, 0, 0 };
    size_t pos = 0, prev = 0, ctxi = 0;
    int c0 = 0, c1 = 0, c2 = 0;
    int state = 2, sel = 0;
    uint32_t thr = 1;

    if (n == 0)
        return 0;
    if (n <= 0x1F || param <= 1) {
        memcpy(r, d, n);
        return 0;
    }
    W = (size_t)3 * param;
    row = W + 3;
    if (row > n)
        row = n;
    r[0] = d[0];
    r[1] = d[1];
    r[2] = d[2];
    for (i = 3; i < row; i++)
        r[i] = (uint8_t)(d[i] - d[i - 3]);
    if (n <= W + 3)
        return 0;

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
        return -1;
    }

    for (i = W + 3; i < n; i++) {
        int ul = d[i - W - 3], up = d[i - W], left = d[i - 3];
        int out = d[i], pred, v, r0, r1, r2, r3, med, cst[4];
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
            pred = 0;
        else if (state == 1)
            pred = left;
        else if (sel == 0)
            pred = left;
        else if (sel == 1)
            pred = up;
        else if (sel == 2)
            pred = (left + up - ul) & 0xFF;
        else
            pred = med;
        v = (out - pred) & 0xFF;
        r[i] = (uint8_t)v;

        r0 = out - left;
        r1 = out - up;
        r2 = out - (left + up - ul);
        r3 = out - med;

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
        ctx1[pos] = (uint16_t)(((uint32_t)ctx1[prev] << 8) |
                               ((uint32_t)r0 & 0xFF));
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
    return 0;
}

/*
 * Mode-7 row-width search (0x443e20), with its gate 0x445020 and the cost
 * table 0x4827bf.  The vendor looks for the row pitch of image data here: the
 * record's 12-bit parameter is `lag / 3`, and the mode-7 predictor uses
 * `W = 3 * param`.  Reverse-engineered instruction by instruction and checked
 * against the vendor's own return value on the corpus images (image24 -> 257,
 * image7 -> 256); ENCODER.md 6.4.
 *
 * `cst()` is the vendor's cost table read: the table at 0x4827bf is the
 * identity, and the bytes in front of it are 1, 2, 3... (dumped at runtime),
 * so a negative difference costs the same as its absolute value.
 */
static int sbc_enc_cst(int d)
{
    return d >= 0 ? d : -d;
}

static uint8_t sbc_enc_m7b(const uint8_t *d, size_t n, long i)
{
    return (i >= 0 && (size_t)i < n) ? d[i] : 0;
}

/* 0x445020: 1 = few distinct 3-grams, 2 = many and length below the delta
 * cost / 22, 0 = structured (the only answer that lets the search run). */
static int sbc_enc_m7_detect(const uint8_t *d, size_t n)
{
    uint8_t *bm;
    size_t pos, end;
    uint32_t total = 0, bits = 0, limit;
    int p0 = 0, p1 = 0, p2 = 0, i, r = 0;

    if (n > 0x100000)
        n = 0x100000;
    if (n <= 0x3FF)
        return 1;
    bm = (uint8_t *)calloc(0x4000, 1);
    if (!bm)
        return 0;
    end = n - 2;
    for (pos = 0; pos < end; pos += 3) {
        int b0 = d[pos], b1 = d[pos + 1], b2 = d[pos + 2];
        total += (uint32_t)(sbc_enc_cst(b0 - p0) + sbc_enc_cst(b1 - p1) +
                            sbc_enc_cst(b2 - p2));
        bm[(size_t)(((b0 << 6) ^ (b1 << 2) ^ (b2 >> 3)) & 0x3FFF)] |=
            (uint8_t)(1u << (b2 & 7));
        p0 = b0;
        p1 = b1;
        p2 = b2;
    }
    if ((uint32_t)n > total) {
        free(bm);
        return 0;
    }
    limit = (uint32_t)((((uint64_t)n * 0xBA2E8BA3u) >> 32) >> 6);
    for (i = 0x4000; i >= 1; i--) {
        uint8_t x = bm[i - 1];
        while (x) {
            bits += (uint32_t)(x & 1);
            x = (uint8_t)(x >> 1);
        }
        if (i == 1 || bits > limit)
            break;
    }
    if (bits <= limit)
        r = 1;
    else if ((uint32_t)n < (uint32_t)((((uint64_t)total * 0xBA2E8BA3u) >> 32) >> 4))
        r = 2;
    free(bm);
    return r;
}

/* The coarse score of 0x443e20 for one candidate (lag = 3*k): phase A walks
 * the head of the window in `lag` steps, phase B reads 767 positions from the
 * middle every third byte, phase C walks back from the end in the same steps
 * (nine offsets, -0x3C included once).  Every term is |a - b| through the
 * identity table of 0x4827bf. */
static uint32_t sbc_enc_m7_score(const uint8_t *d, size_t n, int k)
{
    static const int oa[6] = { 0, 1, 2, 0xE, 0xF, 0x10 };
    static const int ob[3] = { 0xDC, 0xDD, 0xDE };
    static const int oc[9] = { 0, -1, -2, -0xB, -0xC, -0xD, -0x3A, -0x3B,
                               -0x3C };
    size_t off = 0x1D4C, end, len2 = (n > off) ? n - off : 0;
    long lag = 3L * k, ebx, c50 = (long)k / 3, c58 = (long)k / 7;
    uint32_t acc = 0;
    int i, cnt;

    if (len2 > 0x100000)
        len2 = 0x100000;
    end = off + len2;
    /* phase A */
    ebx = (long)off;
    cnt = 0;
    while ((long)end > ebx + 0x100 + c50) {
        for (i = 0; i < 6; i++)
            acc += (uint32_t)sbc_enc_cst((int)sbc_enc_m7b(d, n, ebx + oa[i]) -
                                         (int)sbc_enc_m7b(d, n, ebx - lag + oa[i]));
        for (i = 0; i < 3; i++)
            acc += (uint32_t)sbc_enc_cst((int)sbc_enc_m7b(d, n, ebx + ob[i]) -
                                         (int)sbc_enc_m7b(d, n, ebx - lag + ob[i]));
        if (++cnt == 0x20)
            break;
        ebx += c50 + 0xDF + lag * cnt;
    }
    /* phase B: the window's middle, 767 positions every third byte */
    {
        long stride = (long)(len2 / 10);
        int esi = 0x2FF;
        ebx = (long)off + (long)(len2 / 3);
        for (;;) {
            if (!((long)end > ebx + stride + 3))
                break;
            if ((esi & 0xFF) == 0)
                ebx += stride;
            for (i = 0; i < 3; i++)
                acc += (uint32_t)sbc_enc_cst((int)sbc_enc_m7b(d, n, ebx + i) -
                                             (int)sbc_enc_m7b(d, n, ebx - lag + i));
            if (--esi == 0)
                break;
            ebx += 3;
        }
    }
    /* phase C: backwards from the end in rising `lag` steps */
    {
        long pos = lag, esi = (long)end - 1;
        cnt = 0;
        for (;;) {
            if (!(esi - 0x100 - c58 - lag > (long)off))
                break;
            for (i = 0; i < 9; i++)
                acc += (uint32_t)sbc_enc_cst(
                    (int)sbc_enc_m7b(d, n, esi + oc[i]) -
                    (int)sbc_enc_m7b(d, n, esi + oc[i] - lag));
            if (++cnt == 0x20)
                break;
            pos += lag;
            esi = (esi - 0x3C) - c58 - (pos - lag);
        }
    }
    return acc;
}

/* The refine pass (sbc.exe 0x4445b4-0x444924): each of the 16 candidates is
 * measured over ten slices (each up to 6000 bytes, advancing `base += ebp + step`
 * where `step = len / 20`) against its own lag and its 2x and 3x multiples,
 * and the cheapest wins.  A result whose score fails to beat 80 % of the worst
 * refined score (`((uint64_t)mx * 0xCCCCCCCDULL >> 32) & ~3u`) is refused (0),
 * and callers only accept values above 1. */
static int sbc_enc_m7_search(const uint8_t *d, size_t n)
{
    uint32_t *scores;
    uint32_t ref[16], mx;
    int top[16], i, j, best, slot;
    size_t p0 = 7500, len, end, step;

    if (n <= 24999)
        return 0;
    len = n - p0;
    if (len > 0x100000)
        len = 0x100000;
    {
        int r = sbc_enc_m7_detect(d + p0, len);
        if (r)
            return r;
    }
    end = p0 + len;
    scores = (uint32_t *)malloc(2500 * sizeof(uint32_t));
    if (!scores)
        return 0;
    memset(scores, 0, 2500 * sizeof(uint32_t));
    for (i = 100; i < 2500; i++)
        scores[i] = sbc_enc_m7_score(d, n, i);
    scores[99] = 0xFFFFFFFFu;
    for (i = 0; i < 16; i++)
        top[i] = 99;
    for (i = 100; i < 2500; i++) {
        uint32_t v = scores[i];
        if (v >= scores[top[15]])
            continue;
        slot = 15;
        for (j = 14; j >= 0; j--) {
            if (scores[top[j]] > v) {
                top[j + 1] = top[j];
                slot = j;
            } else {
                break;
            }
        }
        top[slot] = i;
    }
    step = len / 20;
    best = 0;
    for (slot = 0; slot < 16; slot++) {
        long lag = 3L * top[slot];
        uint32_t acc = 0;
        size_t ps;
        size_t base = p0 + 0x57E7;
        for (ps = 0; ps < 10; ps++) {
            size_t ebp = 0;
            while (end > base + ebp + 3 && ebp < 6000) {
                for (i = 0; i < 3; i++) {
                    long q = (long)(base + ebp + i);
                    int v = (int)sbc_enc_m7b(d, n, q);
                    acc += (uint32_t)sbc_enc_cst(v -
                                (int)sbc_enc_m7b(d, n, q - lag));
                    acc += (uint32_t)sbc_enc_cst(v -
                                (int)sbc_enc_m7b(d, n, q - 2 * lag));
                    acc += (uint32_t)sbc_enc_cst(v -
                                (int)sbc_enc_m7b(d, n, q - 3 * lag));
                }
                ebp += 3;
            }
            base += ebp + step;
        }
        ref[slot] = acc;
        if (acc < ref[best])
            best = slot;
    }
    mx = ref[0];
    for (i = 1; i < 16; i++)
        if (ref[i] > mx)
            mx = ref[i];
    free(scores);
    {
        uint32_t thresh = (uint32_t)(((uint64_t)mx * 0xCCCCCCCDULL) >> 32) & ~3u;
        if (thresh < ref[best])
            return 0;
    }
    return top[best];
}

/* Forward mode 6 (sbc.exe 0x411bb0) -- the mirror of sbc_mode6_decode().
 *
 * Two bytes go out literally and without a table store; after that every
 * literal records its own position in the 64 k-entry table under the two-byte
 * context in front of it, and a copy takes the position recorded for the last
 * two output bytes.  The vendor's choices, read off 0x411bb0:
 *
 *   - a candidate has to agree on the first nine bytes (three word compares)
 *     before the length search; the copy is capped at
 *     `min(distance, remaining) - 1`, so a copy never reaches its own source;
 *   - a match is used from the 17-byte minimum on (obj->[4] = 0x11) up to the
 *     0x40000F object cap;
 *   - lazy step: when the position one byte further on has a longer match the
 *     byte is written literally instead -- the test is `len + 1 < len2`, and
 *     the look-ahead match is bounded like the first one;
 *   - length code v = L - 16: one byte while v <= 0x7F, two while v <= 0x2FFF
 *     (`sel = 0x80 | (v & 0x3F)`, then `v >> 6`), three above it;
 *   - a literal 0x7B followed by 0xF0 becomes `7B F0 00` (only when at least
 *     one byte follows the pair, like the vendor's `pos + 2 < end`).
 *
 * Verified byte-exactly against the vendor's own 03_filter layer on the
 * period-31 cycle (100836 B -> 93 B) and on the uppercase text probes.
 */
static int sbc_enc_mode6_abs(const uint8_t *d, size_t n, size_t p0,
                             uint32_t *table, uint8_t **outp, size_t *outn)
{
    uint8_t *out;
    size_t o = 0, p = p0 + 2, end = p0 + n, cap;

    if (n < 2)
        return -1;
    cap = n * 2 + 16;
    out = (uint8_t *)malloc(cap);
    if (!out)
        return -1;
    out[o++] = d[p0];
    out[o++] = d[p0 + 1];
    while (p < end) {
        uint32_t ctx = (uint32_t)d[p - 2] | ((uint32_t)d[p - 1] << 8);
        size_t sp = table[ctx], len = 0;

        if (sp && p + 9 <= end && memcmp(d + sp, d + p, 4) == 0 &&
            memcmp(d + sp + 4, d + p + 4, 4) == 0 && d[sp + 8] == d[p + 8]) {
            size_t rem = end - p;
            size_t max = (p - sp < rem ? p - sp : rem) - 1;
            if (max > 0x40000E)
                max = 0x40000E;
            if (max >= 17) {
                len = 8;
                while (len < max && d[sp + len] == d[p + len])
                    len++;
            }
        }
        if (len >= 17) {
            int defer = 0;
            if (p + 10 <= end) {
                uint32_t ctx2 = (uint32_t)d[p - 1] | ((uint32_t)d[p] << 8);
                size_t sp2 = table[ctx2];
                if (sp2 && sp2 != sp &&
                    memcmp(d + sp2, d + p + 1, 4) == 0 &&
                    memcmp(d + sp2 + 4, d + p + 5, 4) == 0 &&
                    d[sp2 + 8] == d[p + 9]) {
                    size_t rem2 = end - (p + 1);
                    size_t max2 = (p + 1 - sp2 < rem2 ? p + 1 - sp2 : rem2) - 1;
                    size_t len2 = 8;
                    if (max2 > 0x40000E)
                        max2 = 0x40000E;
                    while (len2 < max2 && d[sp2 + len2] == d[p + 1 + len2])
                        len2++;
                    if (len2 >= 17 && len + 1 < len2)
                        defer = 1;
                }
            }
            if (!defer) {
                size_t v = len - 16;
                out[o++] = 0x7B;
                out[o++] = 0xF0;
                if (v <= 0x7F) {
                    out[o++] = (uint8_t)v;
                } else if (v <= 0x2FFF) {
                    out[o++] = (uint8_t)(0x80 | (v & 0x3F));
                    out[o++] = (uint8_t)(v >> 6);
                } else {
                    out[o++] = (uint8_t)(0xC0 | (v & 0x3F));
                    out[o++] = (uint8_t)((v >> 6) & 0xFF);
                    out[o++] = (uint8_t)(v >> 14);
                }
                p += len;
                continue;
            }
        }
        /* literal, which is also what a losing candidate leaves behind */
        table[ctx] = (uint32_t)p;
        out[o++] = d[p];
        if (d[p] == 0x7B && p + 2 < end && d[p + 1] == 0xF0) {
            table[(uint32_t)d[p] | ((uint32_t)d[p + 1] << 8)] = (uint32_t)(p + 1);
            out[o++] = 0xF0;
            out[o++] = 0x00;
            p += 2;
        } else {
            p++;
        }
    }
    *outp = out;
    *outn = o;
    return 0;
}

/* One record with its own table: the vendor does that for records that carry
 * a second-stage filter (0x4083ca) and for the encoder's mode probes. */
static int sbc_enc_mode6(const uint8_t *d, size_t n, uint8_t **outp,
                         size_t *outn)
{
    uint32_t *table;
    int rc;

    if (n < 2)
        return -1;
    table = (uint32_t *)calloc(1u << 16, sizeof(*table));
    if (!table)
        return -1;
    rc = sbc_enc_mode6_abs(d, n, 0, table, outp, outn);
    free(table);
    return rc;
}

#endif /* SBC_ENC_FILTERS_H */
