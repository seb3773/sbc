/* sbc_enc_lzp.h — forward LZP pass (flag3 == 1), encoder side.
 *
 * Mirror of sbc_lzp_pass() in sbc_stage2.h.  The policy was read off the
 * vendor's encoder (sbc.exe 0x416ac0, configured by 0x416740):
 *
 *   - the hash table is sized from the archive window, not from the level:
 *     0x40ecb0 -> 0x42c530 -> 0x40a730 build the object with
 *     `1 << (bitlen(bs + 0x400) - 1)` entries, so a 1 MB window gives 2^20
 *     (mask 0xFFFFF), a 2-3 MB window 2^21 (0x1FFFFF) and 4-7 MB 2^22.  The
 *     caller (sbc_enc_archive_ex) sets `hmask` accordingly; measured on a
 *     36 MB `-m3` text archive, whose 3 MB blocks need 2^21.  `SBC_LZPMASK`
 *     overrides the mask on the decode side for further probes;
 *
 *   - the first min(n, window+4) bytes are copied verbatim, no table entries;
 *   - at every output position the hash of the last 4 bytes indexes a table of
 *     earlier positions (window is the *minimum* displacement, entries are
 *     inserted window bytes behind the cursor and never during the `skip`
 *     literals that follow a match);
 *   - a match is taken when at least 15 words (60 bytes) match; it is padded
 *     with the 4-byte word comparison the vendor uses (limit = min(dist,
 *     avail) - 1 words, i.e. no self-overlap), not by a byte-wise cmp;
 *   - token: 02 C5 <sel>, sel = words-15+1, 3 bytes when sel <= 0x7F,
 *     4 bytes when sel <= 0x2FFF (0x80|sel&0x3f, sel>>6), 5 bytes otherwise
 *     (0xC0|sel&0x3f, sel>>6, sel>>14) — 0x416d3c/0x416d99;
 *   - a literal 02 followed by C5 (and one more byte after them) is escaped
 *     as `02 C5 00`, which the decoder turns back into the two literals.
 *
 * `sbc_lzp_encode` returns 0 on success, 1 when the pass aborts because its
 * output would not fit under `cap` (the vendor's no-gain bail-out) and -1 on
 * allocation failure.
 */
#ifndef SBC_ENC_LZP_H
#define SBC_ENC_LZP_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SBC_LZP_MASK_BITS 20
#define SBC_LZP_HASH_MASK ((1u << SBC_LZP_MASK_BITS) - 1)

typedef struct {
    uint8_t m1, m2;
    uint32_t window; /* minimum displacement, 66 for the default pass */
    uint32_t skip;   /* literals after a match that skip table updates */
    uint32_t minlen; /* minimum match, in 4-byte words */
    uint32_t maxlen; /* absolute length cap (0x40000D by default) */
    /* The table is sized from the archive's window, not the level: the
     * vendor builds its LZP object with `1 << (bitlen(window + 1 + 0x400) - 1)`
     * entries (0x40ecb0 -> 0x42c530 -> 0x40a730), so a 1 MB window gives the
     * familiar 2^20 and a 3 MB one 2^21.  Measured at runtime: a 4 MB random
     * archive (3 MB window, ~530 kB blocks) builds mask 0x1FFFFF, and the
     * 36 MB `-m3` text archive's first 3 MB block does too. */
    uint32_t hmask;
} SbcLzpParams;

static void sbc_lzp_params_default(SbcLzpParams *p)
{
    p->m1 = 2;
    p->m2 = 0xC5;
    p->window = 66;
    p->skip = 66;
    p->minlen = 15;
    p->maxlen = 0x40000D;
    p->hmask = SBC_LZP_HASH_MASK;
}

static uint32_t sbc_lzp_h4(const uint8_t *src, size_t pos, uint32_t mask)
{
    uint32_t w = (uint32_t)src[pos - 4] | ((uint32_t)src[pos - 3] << 8) |
                 ((uint32_t)src[pos - 2] << 16) | ((uint32_t)src[pos - 1] << 24);
    return ((w >> 19) ^ w) & mask;
}

/* dst must hold at least `cap + 8` bytes (the vendor allocates n + 0x400). */
static int sbc_lzp_encode(const uint8_t *src, size_t n, uint8_t *dst,
                          size_t cap, size_t *outn, const SbcLzpParams *pp)
{
    int32_t *tab;
    size_t ip, op, ebp = 0, limit_op;
    const size_t W = pp->window;
    const uint32_t MINLEN = pp->minlen;
    const uint32_t HM = pp->hmask;

    *outn = 0;
    if (n + 0x400 <= 0xFFF) { /* vendor skips LZP below 0xC00 bytes */
        memcpy(dst, src, n);
        *outn = n;
        return 0;
    }
    tab = (int32_t *)malloc(((size_t)HM + 1) * sizeof(*tab));
    if (!tab)
        return -1;
    memset(tab, 0xFF, ((size_t)HM + 1) * sizeof(*tab));

    ip = op = n < (size_t)W + 4 ? n : (size_t)W + 4;
    memcpy(dst, src, ip);
    limit_op = (cap < n ? cap : n);
    limit_op = limit_op > 3 ? limit_op - 3 : 0;

    while (ip < n) {
        size_t sp = 0, len = 0;
        if (op >= limit_op) {
            free(tab);
            *outn = 0;
            return 1; /* no gain: vendor bails out with 0 */
        }
        {
            int32_t e = tab[sbc_lzp_h4(src, ip, HM)];
            if (e >= 0)
                sp = (size_t)e;
            else
                sp = (size_t)-1;
        }
        if (sp != (size_t)-1) {
            size_t avail = (n - ip) >> 2;
            if (avail >= MINLEN) {
                size_t dist = (ip - sp) >> 2;
                size_t limit = (dist < avail ? dist : avail) - 1;
                size_t k;
                if (limit > (size_t)pp->maxlen - 1)
                    limit = (size_t)pp->maxlen - 1;
                k = 0;
                while (k <= limit &&
                       memcmp(src + sp + 4 * k, src + ip + 4 * k, 4) == 0)
                    k++;
                len = k > limit ? limit : k;
            }
        }
        if (len >= MINLEN) {
            uint32_t sel = (uint32_t)(len - MINLEN) + 1;
            dst[op++] = pp->m1;
            dst[op++] = pp->m2;
            if (sel <= 0x7F) {
                dst[op++] = (uint8_t)sel;
            } else if (sel <= 0x2FFF) {
                dst[op++] = (uint8_t)(0x80 | (sel & 0x3F));
                dst[op++] = (uint8_t)(sel >> 6);
            } else {
                dst[op++] = (uint8_t)(0xC0 | (sel & 0x3F));
                dst[op++] = (uint8_t)((sel >> 6) & 0xFF);
                dst[op++] = (uint8_t)(sel >> 14);
            }
            ip += 4 * len;
            ebp = pp->skip;
            continue;
        }
        if (ebp == 0) {
            size_t p = ip - W;
            tab[sbc_lzp_h4(src, p, HM)] = (int32_t)p;
        } else {
            ebp--;
        }
        dst[op++] = src[ip++];
        if (dst[op - 1] == pp->m1 && ip + 1 < n && src[ip] == pp->m2) {
            if (ebp == 0) {
                size_t p2 = ip - W;
                tab[sbc_lzp_h4(src, p2, HM)] = (int32_t)p2;
            } else {
                ebp--;
            }
            dst[op++] = pp->m2;
            dst[op++] = 0;
            ip++;
        }
    }
    free(tab);
    *outn = op;
    return 0;
}

#endif
