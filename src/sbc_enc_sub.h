/* sbc_enc_sub.h — the second-stage ("sub") compressor, encoder side.
 *
 * The decoder's expander is sbc_sub_expand() in sbc.c (vendor 0x423c60); this
 * is its inverse, the vendor's 0x43a380.  A record is turned into a literal
 * stream plus `03 C5 <L>` copies of 4-byte words read from the filter's
 * history ring: the hash of the 3 (or 8) bytes in front of the cursor picks a
 * ring offset out of the 128 k (2 M) entry table, exactly like the expander.
 *
 * Measured constants (0x43a380, and the caller 0x4129b0 for the length base):
 *
 *   - the prologue is 3 bytes when the level-1 filter is in use and 8 at
 *     level 2; the copy length is `lbase` words at minimum, and `lbase` comes
 *     from the record's *mode*: 4 for 0/2/6, 9 for text (mode 4), 32 for
 *     gradient (mode 7) and for copy records longer than 4 kB, 4 with the
 *     alignment pad for mode 1.  The record then stores `lbase - 1` in its
 *     5-bit field, which is what sbc_sub_config() reads back;
 *   - the caller gives the compressor a budget of `min(len, cap) - 12`
 *     output bytes, with cap = len - len*4/5 below 82004 bytes and
 *     len - 4096 above; a record that does not fit is stored unfiltered;
 *   - the history is fed once per *block* (not per record): the compressor
 *     sees only the blocks before this one, and the table is never updated
 *     while compressing, so consecutive records cannot reference each other;
 *   - a match must agree on two 4-byte words (the vendor then tests word 2,
 *     3, ... in a loop that wraps the ring), and a literal `03` that is
 *     followed by `C5` is written as `03 C5 00` (+3 pad bytes when the
 *     record is 4-byte aligned).
 *
 * Every constant here was verified byte-exactly against vendor archives:
 * 61 records of the 36 MB `-m3` text set (all `mode=5 sub=1 idx=4`) and the
 * 24 MB ring they run on.
 */
#ifndef SBC_ENC_SUB_H
#define SBC_ENC_SUB_H

/* The vendor's caller (0x4129b0) picks the length base from the filter mode
 * the record is about to get, and the alignment pad for mode 1. */
static uint32_t sbc_enc_sub_lbase(int mode, size_t n, int *align)
{
    if (align)
        *align = 0;
    switch (mode) {
    case 4:
        return 9;
    case 7:
        return 32;
    case 1:
        if (align)
            *align = 1;
        return 4;
    case 5:
        return n > 0x1000 ? 32 : 4;
    case 3:
        return 0;            /* never compressed */
    default:
        return 4;
    }
}

/* 0x4129b0's budget: `min(len, cap) - 12` bytes of output, with
 * `cap = len - min(len/20, 0x1000)` (0x412a12: `uVar3 = 0x1000`, and below
 * 0x14014 bytes `uVar3 = len / 0x14`).  The old `len - len*4/5` refused every
 * stage whose stream was longer than a fifth of the record, which is why a
 * 2400-byte -ub record never took the stage the vendor gives it (908 B). */
static size_t sbc_enc_sub_cap(size_t n)
{
    size_t slack = 0x1000;
    if (n < 0x14014)
        slack = n / 0x14;
    return n - slack;
}

static uint32_t sbc_enc_sub_ld32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

/* 0x43a380.  Returns the compressed length, 0 when the vendor gives up (too
 * small a record, or the output does not fit the budget).  The ring and the
 * table are the decoder's g_sub object, so the two sides share one history. */
static size_t sbc_enc_sub_compress(const uint8_t *src, size_t n, uint8_t *dst,
                                   size_t cap, uint32_t lbase, int align)
{
    const uint8_t *ring;
    uint32_t mask, maxlen, size;
    size_t pro, ip, limit, op;
    int flag;

    if (!g_sub.ready || n <= 0x1F || n < (size_t)lbase * 8)
        return 0;
    if (cap > n)
        cap = n;
    if (cap <= 12)
        return 0;            /* the vendor's budget is negative here */
    limit = (n < cap ? n : cap) - 12;
    flag = g_sub.flag;
    pro = flag ? 8u : 3u;
    ring = g_sub.ring;
    size = g_sub.size;
    mask = g_sub.mask;
    maxlen = lbase + 0x3FFFFEu;
    /* the prologue bytes are copied verbatim */
    {
        size_t i;
        for (i = pro; i-- > 0;)
            dst[i] = src[i];
    }
    ip = pro;
    op = pro;
    while (ip < n) {
        uint32_t h, pos, words;
        size_t avail;

        if (flag) {
            uint32_t d4, d8;
            memcpy(&d4, src + ip - 4, 4);
            memcpy(&d8, src + ip - 8, 4);
            h = ((d4 ^ (d4 >> 13)) ^ ((d8 ^ (d8 >> 15)) << 11)) & mask;
        } else {
            h = (((uint32_t)src[ip - 3] << 13) ^
                 ((uint32_t)src[ip - 2] << 8) ^ (uint32_t)src[ip - 1]) & mask;
        }
        pos = g_sub.table[h];
        if (getenv("SBC_SUBDBG") && ip < 32)
            fprintf(stderr, "ip=%zu h=%u pos=%u ring=%02x%02x%02x%02x "
                    "src=%02x%02x%02x%02x\n", ip, h, pos, ring[pos],
                    ring[pos + 1], ring[pos + 2], ring[pos + 3], src[ip],
                    src[ip + 1], src[ip + 2], src[ip + 3]);
        words = 0;
        if (sbc_enc_sub_ld32(ring + pos) == sbc_enc_sub_ld32(src + ip) &&
            sbc_enc_sub_ld32(ring + pos + 4) ==
            sbc_enc_sub_ld32(src + ip + 4)) {
            avail = (n - ip) / 4;
            if (avail > maxlen)
                avail = maxlen;
            words = 1;
            for (;;) {
                uint32_t c;
                words++;
                c = pos + 4 * words;
                if (c >= size)
                    c -= size * (c / size);
                if (sbc_enc_sub_ld32(ring + c) !=
                    sbc_enc_sub_ld32(src + ip + 4 * words))
                    break;
                if (words >= avail)
                    break;
            }
            if (words < lbase)
                words = 0;
        }
        if (words) {
            uint32_t L = words + 1 - lbase;
            dst[op++] = 0x03;
            dst[op++] = 0xC5;
            if (L <= 0x7F) {
                dst[op++] = (uint8_t)L;
            } else if (L <= 0x2FFF) {
                dst[op++] = (uint8_t)(0x80 | (L & 0x3F));
                dst[op++] = (uint8_t)(L >> 6);
            } else {
                dst[op++] = (uint8_t)(0xC0 | (L & 0x3F));
                dst[op++] = (uint8_t)((L >> 6) & 0xFF);
                dst[op++] = (uint8_t)(L >> 14);
            }
            if (align && (op & 3)) {
                size_t pad = 4 - (op & 3);
                while (pad--)
                    dst[op++] = 0;
            }
            ip += (size_t)4 * words;
        } else {
            uint8_t c = src[ip];
            dst[op++] = c;
            if (c == 0x03 && ip + 2 < n && src[ip + 1] == 0xC5) {
                dst[op++] = 0xC5;
                dst[op++] = 0x00;
                if (align) {
                    dst[op++] = 0;
                    dst[op++] = 0;
                    dst[op++] = 0;
                }
                ip += 2;
            } else {
                ip++;
            }
        }
        if (ip >= n) {
            if (op >= limit) {
                if (getenv("SBC_SUBDBG"))
                    fprintf(stderr, "subend op=%zu limit=%zu\n", op, limit);
                return 0;
            }
            break;
        }
        if (op >= limit) {
            if (getenv("SBC_SUBDBG"))
                fprintf(stderr, "subfull op=%zu limit=%zu ip=%zu\n", op,
                        limit, ip);
            return 0;
        }
    }
    if (op >= limit)
        return 0;
    return op;
}

/* Encoder-side history.  The object and the feed are the decoder's: the
 * vendor flushes the block's record outputs once the block is written, and
 * records of 128 bytes or less never reach the ring.
 *
 * The filter starts *disabled* (0x43a060 sets 0x4020) and only the first
 * successful feed clears it (0x439d20), so a block is never compressed against
 * an empty ring: 200 kB of zeros stays a stored record at every level, and the
 * first block of an archive never carries `sub` records. */
static int g_enc_sub_armed;

static void sbc_enc_sub_reset(int level)
{
    g_enc_sub_armed = 0;
    sbc_sub_init(level);
}

static void sbc_enc_sub_release(void)
{
    g_enc_sub_armed = 0;
    sbc_sub_release();
}

static void sbc_enc_sub_feed_record(const uint8_t *p, size_t n)
{
    sbc_sub_feed(p, n);
    if (n > 0x7F)
        g_enc_sub_armed = 1;
}

static uint8_t *sbc_enc_sub_read(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf;
    long sz;
    *len = 0;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = (uint8_t *)malloc((size_t)sz ? (size_t)sz : 1);
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

/* ./sbc subtest DIR -- run the compressor on a decoder dump and compare the
 * result with the record the vendor actually wrote (DIR/src.bin). */
static int sbc_enc_sub_selftest(const char *dir)
{
    char path[1200];
    FILE *f;
    uint8_t *ring = NULL, *tbl = NULL, *src = NULL, *dst = NULL;
    uint8_t *out;
    size_t ringn = 0, ntbl = 0, sn = 0, dn = 0, got;
    int flag = 0, align = 0, call = 0, rc = 1;
    uint32_t size = 0, mask = 0, lbase = 4;

    snprintf(path, sizeof(path), "%s/meta.txt", dir);
    if ((f = fopen(path, "r")) != NULL) {
        char line[512];
        if (fgets(line, sizeof(line), f)) {
            char *tok = strtok(line, " \n");
            while (tok) {
                int v = 0;
                if (sscanf(tok, "call=%d", &v) == 1)
                    call = v;
                else if (sscanf(tok, "flag=%d", &v) == 1)
                    flag = v;
                else if (sscanf(tok, "size=%u", &size) == 1)
                    ;
                else if (sscanf(tok, "mask=%u", &mask) == 1)
                    ;
                else if (sscanf(tok, "lbase=%u", &lbase) == 1)
                    ;
                else if (sscanf(tok, "align=%d", &v) == 1)
                    align = v;
                tok = strtok(NULL, " \n");
            }
        }
        fclose(f);
    }
    snprintf(path, sizeof(path), "%s/ring.bin", dir);
    ring = sbc_enc_sub_read(path, &ringn);
    snprintf(path, sizeof(path), "%s/tbl.bin", dir);
    tbl = sbc_enc_sub_read(path, &ntbl);
    snprintf(path, sizeof(path), "%s/src.bin", dir);
    src = sbc_enc_sub_read(path, &sn);
    snprintf(path, sizeof(path), "%s/dst.bin", dir);
    dst = sbc_enc_sub_read(path, &dn);
    if (!ring || !tbl || !src || !dst)
        goto done;
    if (!size || ringn != size || ntbl != (size_t)(mask + 1) * 4) {
        fprintf(stderr, "dump does not match its meta.txt\n");
        goto done;
    }
    sbc_sub_free();
    g_sub.flag = flag;
    g_sub.size = size;
    g_sub.mask = mask;
    g_sub.lbase = lbase;
    g_sub.align = align;
    g_sub.m1 = 0x03;
    g_sub.m2 = 0xC5;
    g_sub.ring = (uint8_t *)malloc((size_t)size + SBC_SUB_PREFIX + 16);
    g_sub.table = (uint32_t *)malloc(((size_t)mask + 1) * 4);
    if (!g_sub.ring || !g_sub.table) {
        sbc_sub_free();
        goto done;
    }
    g_sub.ring += SBC_SUB_PREFIX;
    memcpy(g_sub.ring, ring, size);
    memcpy(g_sub.table, tbl, ((size_t)mask + 1) * 4);
    memcpy(g_sub.ring + size, g_sub.ring, 8);
    g_sub.ready = 1;
    out = (uint8_t *)malloc(dn + 64);
    if (!out) {
        sbc_sub_free();
        goto done;
    }
    got = sbc_enc_sub_compress(dst, dn, out, sbc_enc_sub_cap(dn), lbase,
                               align);
    printf("call %d: lbase=%u align=%d  %zu -> %zu (want %zu) %s", call,
           lbase, align, dn, got, sn, (got == sn && !memcmp(out, src, sn))
           ? "MATCH" : "DIFF");
    if (got != sn || memcmp(out, src, sn)) {
        size_t i, m = got < sn ? got : sn;
        for (i = 0; i < m; i++)
            if (out[i] != src[i])
                break;
        printf(" first=%zu", i);
        if (i < m)
            printf(" got=%02x want=%02x", out[i], src[i]);
    }
    printf("\n");
    rc = (got == sn && !memcmp(out, src, sn)) ? 0 : 1;
    free(out);
    sbc_sub_free();

done:
    free(ring);
    free(tbl);
    free(src);
    free(dst);
    return rc;
}

#endif /* SBC_ENC_SUB_H */
