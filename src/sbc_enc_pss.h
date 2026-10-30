/* Partial-solid file ordering, transcribed from sbc.exe:
 *
 *   0x40a9d0  the "-oa"/"-oz" sorter: samples each file, builds a 512-byte
 *             signature, sorts the files by how similar they are on average,
 *             then grows groups around the most similar file and chains the
 *             groups by similarity to the first one.
 *   0x40a620  the similarity of two signatures.
 *
 * The caller gets the packing order and, per file, whether it starts a new
 * block (the vendor's "flag" array, one byte per file).  Files shorter than
 * 1 kB are always pulled into the current group, which is why a small random
 * file can sit inside a group of text files.
 *
 * All constants and the odd details (the cumulative 16-bit context histogram
 * for files <= 1024 bytes, the byte-wrapping distinct counter, the extension
 * hash used by analysis+name) are the vendor's.
 */
#ifndef SBC_ENC_PSS_H
#define SBC_ENC_PSS_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef PSS_DEBUG
#include <stdio.h>
#endif

#define PSS_CAP   0x40000u   /* bytes sampled per file */
#define PSS_WIN   0x5dcu     /* 1500-file analysis window */
#define PSS_SMALL 0x3ffu     /* files this short never match on content */
#define PSS_BIG   0x1fffu    /* a group may only start on a file this big */

typedef struct {
    const uint8_t *data;
    uint32_t size;
    const char *name;
} SbcPssFile;

typedef struct {
    uint8_t freq[256];   /* scaled byte frequencies (0..255) */
    uint8_t pred[256];   /* most frequent predecessor of each byte */
    uint32_t size;
    uint32_t hash;       /* extension hash, analysis+name only */
    uint32_t key;        /* average similarity to the window */
    uint8_t distinct;    /* distinct byte values (wraps at 256) */
    uint8_t flag;        /* 1 = starts a group, 0 = follower */
} SbcPssRec;

static unsigned pss_lower(unsigned c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

/* 0x4094c0: hash of the extension (the characters after the last dot),
 * packed last character lowest and up to four characters kept. */
static uint32_t pss_name_hash(const char *name)
{
    size_t n = strlen(name), i;
    uint32_t v = 0;
    unsigned char c;

    if (n < 2)
        return 0;
    c = (unsigned char)name[n - 1];
    if (c == '/' || c == '\\' || c == '.')
        return 0;
    i = n - 1;
    for (;;) {
        uint32_t lc;
        i--;
        lc = (uint32_t)pss_lower(c);
        if (i == 0 || name[i] == '/' || name[i] == '\\')
            return 0;
        v = (v >> 8) | (lc << 24);
        c = (unsigned char)name[i];
        if (c == '.')
            return v;
    }
}

/* Read one file exactly like 0x40a9d0: at most 256 kB, 64 kB at a time, and
 * clear the histograms only when the first read is longer than 1024 bytes.
 * The 16-bit context histogram and the byte histogram are shared across the
 * files, in the order they are analysed. */
static void pss_analyse(SbcPssRec *r, const SbcPssFile *f, uint32_t *hist,
                        uint32_t *bh, uint8_t *prev)
{
    uint32_t total = 0, limit = PSS_CAP, i;
    int first = 1;
    uint32_t scale;

    memset(r->freq, 0, sizeof(r->freq));
    memset(r->pred, 0, sizeof(r->pred));
    r->size = f->size;
    r->hash = 0;
    r->key = 0;
    r->distinct = 0;
    r->flag = 0;
    while (limit) {
        uint32_t chunk = f->size - total, k, start = 0;
        if (chunk > 0x10000u)
            chunk = 0x10000u;
        if (chunk > limit)
            chunk = limit;
        if (!chunk)
            break;
        total += chunk;
        limit -= chunk;
        if (first) {
            first = 0;
            if (total - 1 > PSS_SMALL) {
                memset(hist, 0, 0x10000u * sizeof(*hist));
                memset(bh, 0, 256 * sizeof(*bh));
                *prev = f->data[0];
                bh[f->data[0]] = 1;
                start = 1;
            }
        }
        for (k = start; k < chunk; k++) {
            uint8_t b = f->data[total - chunk + k];
            hist[((uint32_t)*prev << 8) | b]++;
            if (bh[b] == 0)
                r->distinct++;
            bh[b]++;
            *prev = b;
        }
    }
    if (r->size <= PSS_SMALL)
        return;
    scale = ((r->size < PSS_CAP ? r->size : PSS_CAP) >> 12) + 1;
    for (i = 0; i < 256; i++) {
        uint32_t q = bh[i] / scale, best;
        int bv, p;
        r->freq[i] = (uint8_t)(q > 255 ? 255 : q);
        if (!q)
            continue;
        best = hist[(0xffu << 8) | i];
        bv = 0xff;
        for (p = 0xfe; p >= 0; p--) {
            uint32_t c = hist[((uint32_t)p << 8) | i];
            if (best < c) {
                best = c;
                bv = p;
            }
        }
        r->pred[i] = (uint8_t)bv;
    }
}

/* 0x40a620: how alike two sampled files are. */
static uint32_t pss_metric(const SbcPssRec *a, const SbcPssRec *b)
{
    uint32_t score = 0, sum;
    int diff, ok = 1;
    unsigned v;

    if (a == b)
        return 0;
    diff = (int)a->distinct - (int)b->distinct;
    if (diff < 0)
        diff = -diff;
    /* Too different (or too short) to compare content: the vendor jumps
     * past the scoring loop with score 0 but still reaches the hash test,
     * so two files with the same extension get the +13 bonus even when
     * their contents are completely different. */
    if (diff >= 0x12 || a->size <= PSS_SMALL || b->size <= PSS_SMALL)
        goto hash;
    for (v = 0; v < 256; v++)
        if (a->pred[v] == b->pred[v] && a->freq[v] && b->freq[v])
            score++;
    sum = (uint32_t)a->distinct + b->distinct;
    if (sum < 0xfa) {
        if (diff > 0xd)
            score >>= 1;
        else
            score += 3;
    }
    if (score > 0x80) {
        score = (score - 0x40) + (score >> 3);
        ok = score < 200;
    }
hash:
    if (ok && (a->hash || b->hash)) {
        if (a->hash == b->hash)
            return score + 0xd;
        if (score > 0xd)
            score -= 5;
    }
    return score;
}

/* The vendor's Shell sort: ascending by key, equal keys keep their order.
 * (0x40b449; the gap table lives at 0x457280.) */
static void pss_shell(uint32_t *order, uint32_t n, SbcPssRec *recs)
{
    static const uint32_t gaps[] = { 1, 3, 7, 21, 48, 112, 336, 861, 1968,
                                     4592, 13776, 33936, 91360, 289408,
                                     1021312 };
    uint32_t k, win = n;
    int gi;

    if (n == 2) {
        if (recs[order[1]].key < recs[order[0]].key) {
            uint32_t t = order[0];
            order[0] = order[1];
            order[1] = t;
        }
        return;
    }
    for (k = 0; win > gaps[k + 1]; k++)
        ;
    for (gi = (int)k; gi >= 0; gi--) {
        uint32_t gap = gaps[gi], i;
        for (i = gap; i < n; i++) {
            uint32_t cur = order[i], j = i;
            uint32_t key = recs[cur].key;
            while (j >= gap && recs[order[j - gap]].key > key) {
                order[j] = order[j - gap];
                j -= gap;
            }
            order[j] = cur;
        }
    }
}

/* Position of a new file in the descending-size array, ties after equals
 * (the binary search at 0x40adf5..0x40ae96). */
static uint32_t pss_insert_pos(const SbcPssRec *recs, const uint32_t *order,
                               uint32_t idx, uint32_t size)
{
    uint32_t lo = 0, hi = idx, u;

    for (;;) {
        u = hi;
        if (u <= lo + 1)
            break;
        for (;;) {
            uint32_t mid = (lo + hi) >> 1;
            u = mid;
            if (recs[order[mid]].size < size) {
                hi = mid;
                if (mid <= lo + 1)
                    goto done;
            } else {
                break;
            }
        }
        lo = u;
    }
done:
    if (u == 1)
        return (size <= recs[order[0]].size) ? 1 : 0;
    return u;
}

static void pss_rotate(uint32_t *order, uint32_t from, uint32_t to)
{
    uint32_t v = order[from];
    if (from == to)
        return;
    memmove(order + to + 1, order + to, (from - to) * sizeof(*order));
    order[to] = v;
}

/* Recompute the window keys and sort the window (0x40aea6..0x40b017). */
static void pss_window(SbcPssRec *recs, uint32_t *order, uint32_t n,
                       uint32_t pos, uint32_t *win_prev, uint32_t *win_rem)
{
    uint32_t rem = n - pos, win = rem < PSS_WIN ? rem : PSS_WIN;
    uint32_t i, q;

    for (i = 0; i < win; i++) {
        SbcPssRec *ri = &recs[order[pos + i]];
        uint32_t sum = 0, cnt = 0;
        for (q = 0; q < win; q++) {
            uint32_t m = pss_metric(ri, &recs[order[pos + q]]);
            if (m > 0x1b) {
                sum += m;
                cnt++;
            }
        }
        ri->key = cnt ? sum / cnt : 0;
    }
    if (rem != *win_prev)
        pss_shell(order + pos, win, recs);
    *win_prev = win;
    *win_rem = win;
}

/* Order the files for -oa (by_name = 0) or -oz (by_name = 1).  `order`
 * receives the packing order, `group` one byte per file: 1 when the file
 * starts a new block. */
static int sbc_pss_order(const SbcPssFile *files, uint32_t n, int by_name,
                         uint32_t *order, uint8_t *group)
{
    SbcPssRec *recs;
    uint32_t *hist, *bh, pos, win_prev = 0, win_rem = 0, groups = 0;
    uint32_t limit = n / 0x28, i;
    uint8_t prev = 0;
    int rc = -1;

    recs = (SbcPssRec *)calloc(n ? n : 1, sizeof(*recs));
    hist = (uint32_t *)malloc(0x10000u * sizeof(*hist));
    bh = (uint32_t *)malloc(256 * sizeof(*bh));
    if (!recs || !hist || !bh)
        goto out;
    memset(hist, 0, 0x10000u * sizeof(*hist));
    memset(bh, 0, 256 * sizeof(*bh));
    for (i = 0; i < n; i++) {
        pss_analyse(&recs[i], &files[i], hist, bh, &prev);
        if (by_name)
            recs[i].hash = pss_name_hash(files[i].name);
        /* descending size, then the vendor's insertion search */
        {
            uint32_t u = pss_insert_pos(recs, order, i, recs[i].size);
            memmove(order + u + 1, order + u, (i - u) * sizeof(*order));
            order[u] = i;
        }
    }
    if (n < 2) {
        for (i = 0; i < n; i++) {
            order[i] = i;
            group[i] = 1;
        }
        rc = 0;
        goto out;
    }
    pos = 0;
    pss_window(recs, order, n, 0, &win_prev, &win_rem);
    groups = 0;
    while (pos < n) {
        uint32_t start_off = 0, best_key = 0, k, start_pos;
        SbcPssRec *start_rec;
        if (win_rem) {
            for (k = 0; k < win_rem; k++) {
                SbcPssRec *r = &recs[order[pos + k]];
                if (best_key < r->key && r->size > PSS_BIG) {
                    best_key = r->key;
                    start_off = k;
                }
            }
        }
        if (start_off)
            pss_rotate(order, pos + start_off, pos);
        start_rec = &recs[order[pos]];
        start_rec->flag = 1;
        start_pos = pos;
        pos++;
        if (win_rem)
            win_rem--;
        while (pos < n) {
            uint32_t best_m = 0x1b, best_j = pos, j;
            int attempts = 0x80;
            for (j = pos; j < n; j++) {
                uint32_t m;
                if (j == start_pos)
                    continue;
                m = pss_metric(start_rec, &recs[order[j]]);
                if (m > best_m) {
                    best_m = m;
                    best_j = j;
                }
                attempts--;
                if (attempts < 0 && best_m > 0x1f)
                    break;
            }
            if (best_m > 0x1b) {
                pss_rotate(order, best_j, pos);
                recs[order[pos]].flag = 0;
                pos++;
                if (win_rem)
                    win_rem--;
                continue;
            }
            if (recs[order[pos]].size <= PSS_SMALL) {
                recs[order[pos]].flag = 0;
                pos++;
                if (win_rem)
                    win_rem--;
                continue;
            }
            break;
        }
        if (pos >= n)
            break;
        groups++;
        if (groups == limit || (n - pos > win_rem && win_rem <= 0x176)) {
            pss_window(recs, order, n, pos, &win_prev, &win_rem);
            groups = 0;
        }
    }
#ifdef PSS_DEBUG
    for (i = 0; i < n; i++)
        fprintf(stderr, "dbg %u %s %u key=%u flag=%u\n", i,
                files[order[i]].name, recs[order[i]].size,
                recs[order[i]].key, recs[order[i]].flag);
#endif
    /* Second pass (0x40b62e): emit the first group, then keep picking the
     * remaining group whose start is most similar to the first group's. */
    {
        uint32_t *src = (uint32_t *)malloc((n ? n : 1) * sizeof(*src));
        uint8_t *used = (uint8_t *)calloc(n ? n : 1, 1);
        uint32_t emitted = 0, cur = 0, oi = 0;
        if (!src || !used) {
            free(src);
            free(used);
            goto out;
        }
        memcpy(src, order, n * sizeof(*src));
        while (emitted < n) {
            uint32_t j, best = 0, best_j = (uint32_t)-1, e;
            group[oi] = 1;
            order[oi++] = src[cur];
            used[cur] = 1;
            emitted++;
            e = cur + 1;
            while (e < n && recs[src[e]].flag == 0) {
                group[oi] = 0;
                order[oi++] = src[e];
                used[e] = 1;
                emitted++;
                e++;
            }
            if (emitted >= n)
                break;
            for (j = 1; j < n; j++) {
                uint32_t m;
                if (used[j] || recs[src[j]].flag != 1)
                    continue;
                m = pss_metric(&recs[src[0]], &recs[src[j]]);
                if (best < m) {
                    best = m;
                    best_j = j;
                }
            }
            if (best_j == (uint32_t)-1) {
                for (j = 1; j < n; j++)
                    if (!used[j] && recs[src[j]].flag == 1) {
                        best_j = j;
                        break;
                    }
            }
            if (best_j == (uint32_t)-1)
                break;
            cur = best_j;
        }
        free(src);
        free(used);
    }
    rc = 0;
out:
    free(recs);
    free(hist);
    free(bh);
    return rc;
}

#endif /* SBC_ENC_PSS_H */
