/*
 * The vendor's adaptive mode-0 filter (unsbc.exe 0x425200), both directions.
 *
 * The object is built per level by FUN_00424fa0:
 *   -m1  simple variant, 0x424150 (not here)
 *   -m2  FUN_00424fa0(obj, mem, nmod=3, pool=3, first=768, min=8192,
 *                      ext=1024, range=0, flag=0)
 *   -m3  FUN_00424fa0(obj, mem, nmod=10, pool=6, first=600, min=6719,
 *                      ext=915, range=48, flag=1)
 *
 * The filter is a chunked delta coder.  Each chunk runs one "slot" (0 = no
 * predictor, 1..nmod = one lag each).  Per byte, every slot gets a 64 KiB
 * context table indexed by (previous delta << 8) | delta; the table cell is
 * the "age" of that context, and `score[slot]` counts how many of the chunk's
 * bytes carried a context older than the current age `state`.  Slot 0's
 * context is the previous byte instead of a delta.
 *
 * Every 257 bytes and at each chunk end the controller (FUN_004248c0) looks
 * at those scores, may switch slot, and ages every table: `state` grows by 5
 * per chunk end and wraps at 250, which clears the tables.
 *
 * With `pool != 0` (the -m3 object) lags 5..pool-1 are also scored by the
 * sum of |original - value at that distance| over the chunk; at each chunk
 * end FUN_00424c70 sorts them and hands the best ones to slots 5..nmod, so
 * the coder can settle on lags outside the fixed 2,3,4,8,10,16,20,12,6,24.
 *
 * `enc` selects the direction:
 *   0 (decode): src is the residual stream, dst the reconstruction
 *   1 (encode): src is the original data, dst the residual stream
 * Either way the *predictors* always come from the original bytes: dst in
 * decode mode, src in encode mode.
 *
 * n < min + 0xC35 makes the vendor's filter refuse (the record is stored);
 * this returns NULL in that case so callers can fall back to a copy.
 */
#ifndef SBC_M0ADV_H
#define SBC_M0ADV_H

#include <stdlib.h>
#include <string.h>

typedef struct {
    int nmod;
    int first;
    int ext;
    int minlen;
    int pool;
} SbcM0Params;

#define SBC_M0A_REFUSE_EXTRA 0xC35

static const SbcM0Params sbc_m0_params_l1 = { 3, 768, 1024, 8192, 0 };
static const SbcM0Params sbc_m0_params_l2 = { 10, 600, 915, 6719, 53 };

static void sbc_m0a_clear(unsigned char **tab, int nt)
{
    int i;
    for (i = 0; i < nt; i++)
        memset(tab[i], 0, 65536);
}

/* FUN_004248c0: pick the slot for the next chunk and age the tables. */
static int sbc_m0a_select(const SbcM0Params *pp, unsigned char **tab, int nt,
                          int active, int nmod, int flag, int *score,
                          int limit, int *state)
{
    int s0 = score[0];
    int i, thr, best, cand;

    if (active == 0 || (limit < pp->minlen / 2 && flag == 0)) {
        /* the vendor measures every candidate against slot 0, with a margin
         * of min(score[0] >> 5, 12) + limit / 1024 */
        thr = (s0 >> 5 < 12 ? s0 >> 5 : 12) + (limit >> 10);
        best = s0;
        cand = 0;
        for (i = 1; i <= nmod; i++)
            if (thr + score[i] < best) {
                best = score[i];
                cand = i;
            }
        /* switching away from a real predictor needs a 10-point win */
        if (!(active == 0 || cand == 0 || cand == active ||
              score[cand] + 10 <= score[active]))
            cand = active;
        active = cand;
        if (*state > 0xf9) {
            *state = 1;
            sbc_m0a_clear(tab, nt);
        } else {
            *state += 5;
        }
    } else if (s0 < score[active]) {
        /* slot 0 beats the running predictor: drop it */
        if (*state < 0xfa) {
            active = 0;
            *state += 5;
        } else {
            *state = 1;
            active = 0;
            sbc_m0a_clear(tab, nt);
        }
    } else if (*state < 0xfa) {
        *state += 5;
    } else {
        *state = 1;
        memset(tab[0], 0, 65536);
        if (active <= 10)
            memset(tab[active], 0, 65536);
    }
    return active;
}

/* FUN_00424c70: order lags 5..pool-1 by the chunk's |delta| weight and give
 * the best ones to slots 5..nmod (slot 5 keeps the running lag when the
 * selection is a pool slot).  Resets the weights for the next chunk. */
static int sbc_m0a_pool(int slot, int nmod, int pool, int *w, int *lag)
{
    int i4, k, best;

    if (pool == 0)
        return slot;
    w[8] = 0x100000;
    if (slot < 6) {
        i4 = (slot != 5) ? 0 : 1;
    } else {
        lag[5] = lag[slot];
        w[8] = 0x100000;
        i4 = 1;
    }
    if (i4 == 1)
        w[lag[5]] = 0x100000;
    slot = (slot >= 5) ? 5 : slot;
    for (;;) {
        best = 0x100000;
        for (k = 5; k < pool; k++)
            if (w[k] < best)
                best = w[k];
        for (k = 5; k < pool && nmod - 5 >= i4;) {
            if (w[k] != best) {
                k++;
                continue;
            }
            lag[5 + i4] = k;
            i4++;
            if (nmod - 5 < i4)
                break;
            w[k] = 0x100000;
            k++;
        }
        if (nmod - 5 < i4)
            break;
    }
    for (k = 5; k < pool; k += 8)
        memset(w + k, 0, 8 * sizeof(int));
    return slot;
}

/* The whole filter.  Returns a malloc'd buffer of n bytes, NULL on refusal
 * or allocation failure. */
/* The -m3 object carries two extra 64 KiB tables (base[0]/base[1], built by
 * the constructor after the nmod+1 slot tables) that are updated for *every*
 * byte and never cleared by the age wrap.  They count how often a context is
 * seen for the first three times (a cell saturates at 3): table 0 with
 * (previous byte, current byte), table 1 with (previous residual, the running
 * slot's context).  At the end of FUN_0043c490 the filter refuses its output
 * (returns 0) when table 1's total exceeds table 0's -- i.e. when the
 * predictor the coder settled on is not better than "the byte repeats" -- and
 * the caller then writes mode 6 or a copy record instead.  `sbc_m0a_scr_ok`
 * reports that verdict for the last call (always 1 for the -m2 object, whose
 * flag is 0 and skips the block). */
static int sbc_m0a_scr_ok = 1;

/* The two totals themselves, for the -m3 mode-7 gate (the vendor's getter at
 * 0x4552a0 index 2 returns table B's total: image24-m3 97980, image7-m3
 * 48766, image.raw-m3 0, image.raw's table A total 65132). */
static long sbc_m0a_last_cnt_a, sbc_m0a_last_cnt_b;

/* FUN_0043c490's verdict for the last call, its own return value (0/1/2):
 *
 *   0  refused.  The caller (FUN_00412af0 case 0) then writes mode 6 or a
 *      copy record instead of the mode-0 one.
 *   1  applied.
 *   2  applied with a *lot* of the record actually coded (`t54 > n / 8`);
 *      the caller then skips the mode-6 rewrite of its tail (its `bVar2`),
 *      so a record the filter took strongly is never second-guessed.
 *
 * The three refusal tests are read off 0x43db8d..0x43dc72, in this order:
 * `t6c < t70 + (t70 >> 6)`, `cntB > cntA` (the -m3 tables, skipped for the
 * -m2 object whose flag is 0) and `t54 < min(n >> 7, 0xC00)`.  `t54` is the
 * number of bytes the analysis coded with a real lag (a non-zero slot),
 * `t6c`/`t70` are the sums of `score[0]`/`score[active]` taken at every
 * chunk end (0x43d01c).  The -ad ascii_mixed mismatch was exactly the
 * `t6c`/`t70` test: mode 0 at -m1 but copy at -m2/-m3 on a mixture half of
 * which is regular data (ENCODER.md 6.16). */
static int sbc_m0a_last_verdict;
/* The same accumulators, for the diagnostics (SBC_M0DBG). */
static long sbc_m0a_last_t54, sbc_m0a_last_t6c, sbc_m0a_last_t70;
/* bytes whose context cell was already at the saturation value (the vendor's
 * own two counters, obj+0x5c and obj+0x60) */
static long sbc_m0a_last_fam_a, sbc_m0a_last_fam_b;

/* The object's array at +0x58, one entry per slot: the vendor adds the
 * current chunk limit to `arr[active]` at every chunk end (0x43cef8), so
 * `arr[s]` is how many bytes the analysis coded with slot `s` (slot 2 is the
 * fixed lag 3, i.e. one pixel row of a 24-bit image).  The mode-7 gate reads
 * `arr[2]` through the getter 0x4552a0.  Slots run 0..10 (the -m3 pool can
 * shrink nmod, but the array keeps its indices). */
static long sbc_m0a_last_slot[12];

static unsigned char *sbc_m0_adaptive(const unsigned char *src, size_t n,
                                      const SbcM0Params *pp, int enc)
{
    static const int lags0[11] = { 0, 2, 3, 4, 8, 10, 16, 20, 12, 6, 24 };
    int lag[11], ctx[11], score[11], shadow[11];
    long t54 = 0, t6c = 0, t70 = 0;
    int w[64];
    unsigned char *tab[11];
    unsigned char *dst;
    unsigned char *scrA = NULL, *scrB = NULL;
    long cntA = 0, cntB = 0, famA = 0, famB = 0;
    long slot[12];
    const unsigned char *pred;
    int i, k, P, nmod, pool, state = 1, active = 0, limit;
    int tabn;
    size_t remaining, base;
    long state0 = 0;
    int cut = 0;

    sbc_m0a_scr_ok = 1;
    sbc_m0a_last_verdict = 0;
    sbc_m0a_last_t54 = sbc_m0a_last_t6c = sbc_m0a_last_t70 = 0;
    memset(slot, 0, sizeof(slot));
    memset(sbc_m0a_last_slot, 0, sizeof(sbc_m0a_last_slot));

    if (n < (size_t)pp->minlen + SBC_M0A_REFUSE_EXTRA || pp->nmod > 10)
        return NULL;
    dst = (unsigned char *)malloc(n ? n : 1);
    if (!dst)
        return NULL;
    P = pp->pool < 24 ? 24 : pp->pool;
    base = (size_t)P;
    pred = enc ? src : dst;
    nmod = pp->nmod;
    pool = pp->pool;
    if (n < (size_t)P + 1) {
        memcpy(dst, src, n);
        return dst;
    }
    memcpy(dst, src, n);
    memset(w, 0, sizeof(w));
    for (i = 0; i < 11; i++) {
        tab[i] = (unsigned char *)calloc(65536, 1);
        if (!tab[i]) {
            for (k = 0; k < i; k++)
                free(tab[k]);
            free(dst);
            return NULL;
        }
    }
    if (pp->pool) {
        scrA = (unsigned char *)calloc(65536, 1);
        scrB = (unsigned char *)calloc(65536, 1);
        if (!scrA || !scrB) {
            free(scrA);
            free(scrB);
            for (k = 0; k < 11; k++)
                free(tab[k]);
            free(dst);
            return NULL;
        }
    }
    memset(score, 0, sizeof(score));
    memset(shadow, 0, sizeof(shadow));
    for (i = 10; i >= 1; i--) {
        lag[i] = lags0[i];
        ctx[i] = (int)src[P - lag[i]] << 8;
    }
    ctx[0] = (int)src[P - 1] << 8;
    tabn = nmod + 1;
    limit = pp->first;
    remaining = n - (size_t)P;
    if (getenv("SBC_M0TRACE"))
        fprintf(stderr, "M0 start n=%zu P=%d first=%d minlen=%d ext=%d nmod=%d "
                        "pool=%d enc=%d\n",
                n, P, pp->first, pp->minlen, pp->ext, nmod, pool, enc);
    while (remaining > 0) {
        size_t chunkpos = 0;
        int counter = 0;
        if (limit < 1)
            break;
        if (getenv("SBC_M0TRACE"))
            fprintf(stderr, "M0 chunk base=%zu limit=%d active=%d rem=%zu\n",
                    base, limit, active, remaining);
        while ((long)chunkpos < (long)limit) {
            unsigned in = src[base + chunkpos];
            int thr = (limit >> 11) + state;
            unsigned orig, resid;
            int idx, c;
            cut = 0;
            if (enc) {
                orig = in;
                resid = active ? (unsigned char)(in - pred[base + chunkpos -
                                                         lag[active]])
                               : in;
            } else {
                resid = in;
                orig = active ? (unsigned char)(in + pred[base + chunkpos -
                                                         lag[active]])
                              : in;
            }
            if (active == 0) {
                for (i = nmod; i >= 1; i--) {
                    unsigned d = (unsigned char)(orig - pred[base + chunkpos -
                                                             lag[i]]);
                    idx = (int)d | ctx[i];
                    c = tab[i][idx];
                    if (c < thr) {
                        tab[i][idx] = (unsigned char)(c < state ? state : c + 1);
                        score[i]++;
                    }
                    ctx[i] = (int)d << 8;
                }
                if (pool)
                    for (k = 5; k < pool; k++)
                        w[k] += (int)(orig >= pred[base + chunkpos - k]
                                          ? orig - pred[base + chunkpos - k]
                                          : pred[base + chunkpos - k] - orig);
                idx = (int)orig | ctx[0];
                c = tab[0][idx];
                if (c < thr) {
                    tab[0][idx] = (unsigned char)(c < state ? state : c + 1);
                    score[0]++;
                }
                ctx[0] = (int)orig << 8;
            } else {
                if (limit >= pp->minlen / 2) {
                    /* late in a long chunk the vendor only feeds the running
                     * slot (with its residual) and slot 0 */
                    idx = (int)resid | ctx[active];
                    c = tab[active][idx];
                    if (c < thr) {
                        tab[active][idx] =
                            (unsigned char)(c < state ? state : c + 1);
                        score[active]++;
                    }
                    ctx[active] = (int)resid << 8;
                } else {
                    for (i = nmod; i >= 1; i--) {
                        unsigned d = (unsigned char)(orig -
                                                     pred[base + chunkpos -
                                                          lag[i]]);
                        idx = (int)d | ctx[i];
                        c = tab[i][idx];
                        if (c < thr) {
                            tab[i][idx] =
                                (unsigned char)(c < state ? state : c + 1);
                            score[i]++;
                        }
                        ctx[i] = (int)d << 8;
                    }
                    if (pool)
                        for (k = 5; k < pool; k++)
                            w[k] += (int)(orig >= pred[base + chunkpos - k]
                                              ? orig - pred[base + chunkpos - k]
                                              : pred[base + chunkpos - k] -
                                                    orig);
                }
                idx = (int)orig | ctx[0];
                c = tab[0][idx];
                if (c < thr) {
                    tab[0][idx] = (unsigned char)(c < state ? state : c + 1);
                    score[0]++;
                }
                ctx[0] = (int)orig << 8;
            }
            /* 0x425e93..0x425ee2: the third cut site, reached by both the
             * model and the direct path of a non-zero slot.  Past the first
             * 128 bytes the chunk ends as soon as the running slot's score
             * gets min(pos >> 4, 32) points ahead of the copy slot's -- the
             * same test the selector gets as its `d` flag once the chunk is
             * over.  Unlike the other two cuts this one keeps the counter's
             * value (a later cut may still fire in the same chunk) and it
             * leaves a one-byte chunk behind, which the selector then gives
             * to slot 0 (tail block of set8 -m2: the record's last byte is
             * copy-coded). */
            if (active != 0 && counter < 0x100000 && chunkpos > 0x7F) {
                int add = (int)chunkpos >> 4;
                if (add > 0x20)
                    add = 0x20;
                if (score[0] + add < score[active]) {
                    cut = 1;
                    limit = (int)chunkpos - 1;
                }
            }
            chunkpos++;
            counter++;
            if (counter > 0x100) {
                int dact = score[active] - shadow[active];
                if (active == 0 || limit < pp->minlen / 2) {
                    int best = dact, bestslot = active;
                    for (i = nmod; i >= 1; i--) {
                        int di = score[i] - shadow[i];
                        if (di < best) {
                            best = di;
                            bestslot = i;
                        }
                        shadow[i] = score[i];
                    }
                    counter = 0;
                    /* a slot only wins if it is better than slot 0 by 9; when
                     * none is, the chunk is cut anyway so the selector can
                     * fall back to the copy slot.  The cut leaves `limit` at
                     * pos - 2 (not pos - 1): the selector reads that value and
                     * the next chunk grows its limit from it, so one byte here
                     * walks the whole chunk grid out of step (set8 -m2, byte
                     * 70718). */
                    if ((best <= score[0] + 9 - shadow[0] ? bestslot : 0) !=
                        active) {
                        cut = 1;
                        counter = 0x100000;
                        limit = (int)chunkpos - 2;
                    }
                } else {
                    counter = 0;
                    if (score[0] + 9 - shadow[0] < dact) {
                        cut = 1;
                        counter = 0x100000;
                        limit = (int)chunkpos - 2;
                    }
                    shadow[active] = score[active];
                }
                shadow[0] = score[0];
            }
            if (scrA) {
                /* FUN_0043cda6: the two scratch tables, one hit per byte */
                size_t p = base + chunkpos - 1;
                int prevb = p > 0 ? (int)pred[p - 1] : 0;
                int idxA = prevb | ((int)orig << 8);
                int idxB = (p > 0 ? (int)dst[p - 1] : 0) | ctx[active];
                unsigned char ca = scrA[idxA];
                unsigned char cb = scrB[idxB];
                if (ca < 3) {
                    scrA[idxA] = (unsigned char)(ca + 1);
                    cntA++;
                } else {
                    famA++;
                }
                if (cb < 3) {
                    scrB[idxB] = (unsigned char)(cb + 1);
                    cntB++;
                } else {
                    famB++;
                }
            }
            dst[base + chunkpos - 1] = (unsigned char)(enc ? resid : orig);
            if (cut)
                break;
        }
        if (getenv("SBC_M0TRACE"))
            fprintf(stderr, "M0 endchunk pos=%zu cut=%d active=%d limit=%d "
                            "sc0=%d scA=%d t6c=%ld t70=%ld\n",
                    chunkpos, cut, active, limit, score[0],
                    active ? score[active] : -1, t6c, t70);
        /* FUN_0043c490 0x43cef8: every chunk end adds its limit to the slot's
         * byte count, whatever produced the end (a cut included, where the
         * limit is the cut point).  This is the array the -m3 mode-7 gate
         * reads: `arr[2] > n / 3` asks whether the analysis spent a third of
         * the record on lag 3, i.e. on one 24-bit pixel row. */
        if (active >= 0 && active < 12)
            slot[active] += limit;
        remaining -= chunkpos;
        /* 0x43cf23: bytes coded with a real lag (slot 0 is the copy slot),
         * and 0x43cf11/0x43d01c: the two score sums the verdict compares.
         * 0x43cf05 skips both for the chunk that ends the record: the sums
         * cover every chunk but the last. */
        if (remaining > 0) {
            if (active != 0)
                t54 += limit;
            if (active >= 0 && active < 11) {
                t6c += score[0];
                t70 += score[active];
            }
        }
        if (remaining < 1)
            break;
        {
            int s0 = score[0];
            int d = (counter < 0x100000 && chunkpos > 0x80)
                        ? ((((int)chunkpos - 1) >> 4 > 0x20
                                ? 0x20
                                : ((int)chunkpos - 1) >> 4) +
                               s0 <
                           score[active])
                        : 0;
            int newslot = sbc_m0a_select(pp, tab, tabn, active, nmod, d,
                                         score, limit, &state);
            if (pool)
                newslot = sbc_m0a_pool(newslot, nmod, pool, w, lag);
            memset(score, 0, sizeof(score));
            if (newslot == active) {
                limit += pp->ext;
                if (pp->minlen < limit)
                    limit = pp->minlen;
            } else {
                limit = pp->first;
            }
            if (newslot == 0) {
                /* after 16 KiB of copy the vendor gives up on the pool and
                 * keeps at most six slots */
                state0 += limit;
                if (state0 > 0x3fff) {
                    nmod = pp->nmod > 4 ? 6 : 3;
                    if (nmod <= 4)
                        pool = 0;
                    tabn = nmod + 1;
                }
            }
            memset(shadow, 0, sizeof(shadow));
            if (remaining < (size_t)limit)
                limit = (int)remaining;
            active = newslot;
        }
        base += chunkpos;
    }
    for (i = 0; i < 11; i++)
        free(tab[i]);
    if (scrA) {
        /* The vendor's own test refuses a tie: the predictor has to leave
         * *fewer* new two-byte contexts in the residual than the input has
         * (FUN_0043c490's scratch tables; `cntA`/`cntB` count the contexts
         * seen at most three times, `famA`/`famB` the rest).  A tie is what
         * the lag-1 model produces on data with no real structure, and the
         * measurements say those records leave the filter: hi4 (cntA == cntB
         * == 768) is a copy record at -m3 while ramp256 (768 against 261)
         * keeps mode 0, at equal residual sizes.  The old `cntB > cntA`
         * accepted the ties and sent images, ramps and hi4 to mode 6. */
        sbc_m0a_scr_ok = (cntB < cntA);
        sbc_m0a_last_cnt_a = cntA;
        sbc_m0a_last_cnt_b = cntB;
        sbc_m0a_last_fam_a = famA;
        sbc_m0a_last_fam_b = famB;
        memcpy(sbc_m0a_last_slot, slot, sizeof(sbc_m0a_last_slot));
        free(scrA);
        free(scrB);
    } else {
        sbc_m0a_last_cnt_a = 0;
        sbc_m0a_last_cnt_b = 0;
        sbc_m0a_last_fam_a = 0;
        sbc_m0a_last_fam_b = 0;
    }
    /* 0x43db8d..0x43dc72: the verdict.  A tie refuses on the -m3 tables
     * (`cntB > cntA`, the -m2 object never builds them so both stay 0), and
     * the copy slot has to be beaten by more than 1/64 on the score sums. */
    {
        long slack = (long)(n >> 7);
        if (slack > 0xc00)
            slack = 0xc00;
        sbc_m0a_last_t54 = t54;
        sbc_m0a_last_t6c = t6c;
        sbc_m0a_last_t70 = t70;
        if (t6c < t70 + (t70 >> 6) || cntB > cntA || t54 < slack)
            sbc_m0a_last_verdict = 0;
        else
            sbc_m0a_last_verdict = (t54 > (long)(n >> 3)) ? 2 : 1;
    }
    return dst;
}

#endif
