/* sbc_enc_block.h — the compressed-block pipeline, encoder side.
 *
 *      block data --filter--> filtered --LZP--> lzp --BWT--> S --stage2--> payload
 *
 * Every stage is validated against the decoder's layer dumps (04_block ->
 * 03_filter -> 02_lzp -> 01_bwt -> 00_payload), so the pipeline can be checked
 * on a block even before the archive writer uses it.
 *
 * The block-level LZP decision mirrors 0x41f250: the pass is run with the
 * vendor's no-gain cap (len - min(len>>7, 0x1000)), and it is used only when
 * it returns a shorter buffer; otherwise flag3 stays 0 and the BWT sees the
 * filtered bytes directly.
 */
#ifndef SBC_ENC_BLOCK_H
#define SBC_ENC_BLOCK_H

typedef struct {
    uint8_t *filter;
    size_t flen;
    uint8_t *lzp;
    size_t lzplen;
    int flag3;
    uint8_t *bwt;
    size_t bwtlen;
    uint32_t primary;
    SbcBuf payload;
    /* One plan entry per file in the block: the filter each file gets, and
     * the filtered length the record must carry (the block's payload is the
     * concatenation of the filtered files). */
    uint32_t nsegs;
    uint32_t *rawsegs;   /* raw length of every record (history feed) */
    uint32_t *fsegs;
    uint32_t *modes;
    uint32_t *ctrls;
    uint32_t *m7s;
    uint32_t *advs;      /* mode 0/2 weak accept: repeat stage on the filter
                          * output (the record's `adv` bit, 0x412af0) */
    uint32_t *subs;      /* record carries a second-stage stream */
    uint32_t *subidx;    /* its length base (1..32) */
    uint32_t *subal;     /* its alignment bit */
    uint32_t *drefs;     /* dict reference: record index in the block (0=none) */
    uint32_t *dlens;     /* dict reference: bytes replayed from that record */
    uint32_t *expl5;     /* mode-5 record the *analyzer* chose (0x4134c7):
                          * written with its mode bits (coded=1) whatever its
                          * length, unlike a copy the coder refused (coded=0) */
    uint8_t *linecode;   /* mode-4 prose line code (e2), raw bytes */
    size_t linecoden;
} SbcEncBlock;

static void sbc_enc_block_free(SbcEncBlock *b)
{
    free(b->filter);
    free(b->lzp);
    free(b->bwt);
    free(b->payload.p);
    free(b->rawsegs);
    free(b->fsegs);
    free(b->modes);
    free(b->ctrls);
    free(b->m7s);
    free(b->advs);
    free(b->subs);
    free(b->subidx);
    free(b->subal);
    free(b->drefs);
    free(b->dlens);
    free(b->expl5);
    free(b->linecode);
    memset(b, 0, sizeof(*b));
}

/* mode 0 (simple/advanced by level), 4 (text, ctrl), 5 (copy) or 7
 * (gradient, m7param). */
/* `m6tab` (when not NULL) is the block-wide mode-6 table and `m6base` the
 * record's offset in the block's decoded layout: the vendor's mode-6 filter
 * stores absolute positions there and a later record can copy from an earlier
 * one (0x411bb0 writes record k at `out + k*0x80000`).  A record that carries
 * a second-stage filter gets its own table and base 0 (0x4083ca). */
static int sbc_enc_filter(const uint8_t *data, size_t n, int level, int mode,
                          uint32_t m7param, uint32_t ctrl, uint8_t **outp,
                          size_t *outn, uint8_t **codep, size_t *coden,
                          uint32_t *m6tab, size_t m6base)
{
    uint8_t *r = (uint8_t *)malloc(n ? n : 1);
    if (codep)
        *codep = NULL;
    if (coden)
        *coden = 0;
    if (!r)
        return -1;
    if (mode == 5) {
        memcpy(r, data, n);
    } else if (mode == 4) {
        free(r);
        return sbc_enc_mode4(data, n, ctrl, outp, outn, codep, coden);
    } else if (mode == 6) {
        free(r);
        if (m6tab)
            return sbc_enc_mode6_abs(data, n, m6base, m6tab, outp, outn);
        return sbc_enc_mode6(data, n, outp, outn);
    } else if (mode == 0) {
        /* SBC_M0IN dumps what the filter really sees: the second-stage stream
         * at -m2/-m3, which is what the vendor's own filter consumes. */
        const char *m0in = getenv("SBC_M0IN");
        if (m0in) {
            FILE *mf = fopen(m0in, "wb");
            if (mf) {
                fwrite(data, 1, n, mf);
                fclose(mf);
            }
        }
        if (level <= 0)
            sbc_enc_mode0_simple(data, n, r);
        else if (level == 1)
            sbc_enc_mode0_adaptive(data, n, &sbc_m0_params_l1, r);
        else
            sbc_enc_mode0_adaptive(data, n, &sbc_m0_params_l2, r);
    } else if (mode == 7) {
        sbc_enc_mode7(data, n, m7param, r);
    } else {
        free(r);
        return -1;
    }
    if (getenv("SBC_FOUT")) {
        FILE *ff = fopen(getenv("SBC_FOUT"), "wb");
        if (ff) {
            fwrite(r, 1, n, ff);
            fclose(ff);
        }
    }
    *outp = r;
    *outn = n;
    return 0;
}

/* One record of a block, as the record list will describe it.
 *
 * `off`/`len` are its place in the block's raw data (the decoded layout, and
 * what the history feed uses); `src`/`srclen` is what actually gets filtered:
 * the raw bytes, or the second-stage stream when `sub` is set. */
typedef struct {
    uint32_t off;
    uint32_t len;
    const uint8_t *src;
    size_t srclen;
    int mode;
    uint32_t ctrl;
    uint32_t m7;
    uint32_t sub;
    uint32_t subidx;
    uint32_t subal;
    /* dictionary reference: `dlen` bytes of the block's output replayed from
     * the start of record `dref` (an index in this block, 0 = none).  Only
     * the tail after the match goes to the filter stage, and the record is
     * always written as a copy record with the dict bit. */
    uint32_t dref;
    uint32_t dlen;
    /* the copy record came from the analyzer's width-1 TIFF branch, so the
     * vendor writes it with coded=1 and its mode bits even when it is large */
    uint32_t expl5;
} SbcRecPlan;

/* Runs filter -> LZP -> BWT -> stage2 on one block.
 *
 * Every record is filtered on its own (the vendor writes one record per file
 * and, at -m3, one per 512 kB chunk) and the filtered blocks are concatenated,
 * so LZP/BWT/stage2 see the whole block as a single string.  Mode-6 records
 * share one block-wide table unless they carry a second-stage stream. */
static int sbc_enc_pipeline_plan(SbcEncBlock *b, const uint8_t *data,
                                 const SbcRecPlan *plan, uint32_t nsegs,
                                 int level)
{
    SbcLzpParams pp;
    size_t cap, total = 0;
    uint32_t i;
    int rc;

    (void)data;
    memset(b, 0, sizeof(*b));
    for (i = 0; i < nsegs; i++)
        total += plan[i].srclen;
    b->rawsegs = (uint32_t *)calloc(nsegs, sizeof(*b->rawsegs));
    b->fsegs = (uint32_t *)calloc(nsegs, sizeof(*b->fsegs));
    b->modes = (uint32_t *)calloc(nsegs, sizeof(*b->modes));
    b->ctrls = (uint32_t *)calloc(nsegs, sizeof(*b->ctrls));
    b->m7s = (uint32_t *)calloc(nsegs, sizeof(*b->m7s));
    b->advs = (uint32_t *)calloc(nsegs, sizeof(*b->advs));
    b->subs = (uint32_t *)calloc(nsegs, sizeof(*b->subs));
    b->subidx = (uint32_t *)calloc(nsegs, sizeof(*b->subidx));
    b->subal = (uint32_t *)calloc(nsegs, sizeof(*b->subal));
    b->drefs = (uint32_t *)calloc(nsegs, sizeof(*b->drefs));
    b->dlens = (uint32_t *)calloc(nsegs, sizeof(*b->dlens));
    b->expl5 = (uint32_t *)calloc(nsegs, sizeof(*b->expl5));
    b->filter = (uint8_t *)malloc(total ? total : 1);
    if (!b->rawsegs || !b->fsegs || !b->modes || !b->ctrls || !b->m7s ||
        !b->advs || !b->subs || !b->subidx || !b->subal || !b->drefs ||
        !b->dlens || !b->expl5 || !b->filter)
        return -1;
    b->nsegs = nsegs;
    for (i = 0; i < nsegs; i++) {
        uint8_t *f = NULL, *code = NULL;
        size_t fl = 0, coden = 0;
        b->rawsegs[i] = plan[i].len;
        b->modes[i] = (uint32_t)plan[i].mode;
        b->ctrls[i] = plan[i].ctrl;
        b->m7s[i] = plan[i].m7;
        b->subs[i] = plan[i].sub;
        b->subidx[i] = plan[i].subidx;
        b->subal[i] = plan[i].subal;
        b->drefs[i] = plan[i].dref;
        b->dlens[i] = plan[i].dlen;
        b->expl5[i] = plan[i].expl5;
        /* only mode 4 changes the length, and it always shrinks */
        if (sbc_enc_filter(plan[i].src, plan[i].srclen, level, plan[i].mode,
                           plan[i].m7, plan[i].ctrl, &f, &fl, &code, &coden,
                           NULL, 0) != 0 ||
            fl > total - b->flen) {
            free(f);
            free(code);
            return -1;
        }
        /* The weak mode-0 accept's repeat stage (0x412af0's tail): when the
         * filter's own verdict is 1 (applied, but on less than a tenth/
         * eighth of the record) the vendor runs the mode-6 transform over the
         * filter's *output* -- cap `len - min(len>>7, 0x1000)`, fresh table --
         * and, when the whole stream fits (`out <= cap - 6`), writes that
         * stream instead and sets the record's `adv` bit.  A strong accept
         * (verdict 2) skips the stage, and a refusal runs the same transform
         * over the source as the mode-6 candidate (handled by the policy). */
        if (getenv("SBC_ADVDBG"))
            fprintf(stderr, "adv? i=%u mode=%d v=%d fl=%zu\n", i,
                    plan[i].mode, sbc_enc_m0_verdict, fl);
        if (plan[i].mode == 0 && sbc_enc_m0_verdict == 1 && fl > 0x1000) {
            uint8_t *g = NULL;
            size_t gl = 0;
            if (sbc_enc_mode6(f, fl, &g, &gl) == 0) {
                size_t slack = fl >> 7;
                if (slack > 0x1000)
                    slack = 0x1000;
                if (gl + 6 <= fl - slack) {
                    if (getenv("SBC_ADVDBG"))
                        fprintf(stderr, "adv! i=%u raw=%zu stream=%zu\n", i,
                                plan[i].srclen, gl);
                    free(f);
                    f = g;
                    fl = gl;
                    b->advs[i] = 1;
                } else {
                    if (getenv("SBC_ADVDBG"))
                        fprintf(stderr, "adv-no i=%u fl=%zu gl=%zu cap=%zu\n",
                                i, fl, gl, fl - slack);
                    free(g);
                }
            }
        }
        if (code) {
            /* the line code belongs to the block, not to the record */
            if (!b->linecode) {
                b->linecode = code;
                b->linecoden = coden;
            } else {
                free(code);
            }
        }
        memcpy(b->filter + b->flen, f, fl);
        b->flen += fl;
        b->fsegs[i] = (uint32_t)fl;
        free(f);
    }
    b->lzp = (uint8_t *)malloc(b->flen + 0x400 + 8);
    if (!b->lzp)
        return -1;
    sbc_lzp_params_default(&pp);
    pp.hmask = sbc_enc_lzp_hmask;
    cap = b->flen > (b->flen >> 7) ? b->flen - (b->flen >> 7) : 0;
    if (b->flen >> 7 > 0x1000)
        cap = b->flen - 0x1000;
    rc = sbc_lzp_encode(b->filter, b->flen, b->lzp, cap, &b->lzplen, &pp);
    if (rc == 0 && b->lzplen < b->flen) {
        b->flag3 = 1;
    } else {
        b->flag3 = 0;
        memcpy(b->lzp, b->filter, b->flen);
        b->lzplen = b->flen;
    }
    b->bwt = sbc_bwt(b->lzp, b->lzplen, &b->primary);
    if (!b->bwt)
        return -1;
    b->bwtlen = b->lzplen;
    if (sbc_enc_stage2_payload(&b->payload, b->bwt, (uint32_t)b->bwtlen) != 0)
        return -1;
    return 0;
}

/* Single-file block: the common case, and what the mode policy costs out. */
static int sbc_enc_pipeline(SbcEncBlock *b, const uint8_t *data, size_t n,
                            int level, int mode, uint32_t m7param,
                            uint32_t ctrl)
{
    SbcRecPlan p;

    memset(&p, 0, sizeof(p));
    p.len = (uint32_t)n;
    p.src = data;
    p.srclen = n;
    p.mode = mode;
    p.ctrl = ctrl;
    p.m7 = m7param;
    return sbc_enc_pipeline_plan(b, data, &p, 1, level);
}

/* Record bits for one filtered record.  The layout is the one
 * sbc_recs_try() parses: flen(25) coded(1) mode(3) dict(1) [mode bits]
 * [sub bit at -m2/-m3].  `ctrl` keeps the dict bit in its low bit, like the
 * decoder's convention, so only the upper 24 bits go to the stream. */
/* Dictionary-reference record: flen(25) coded(1) mode(3) dict(1) then the
 * 12-bit record index and the 25-bit copied length.  A whole-file copy is
 * mode 5 and carries nothing after `dlen` but the -m2/-m3 second-stage bit
 * (measured on the vendor's `t4` and 9 MB archives); when the record has a
 * tail, the tail keeps the mode it would otherwise have been given and its
 * own mode bits follow the two dictionary fields -- the vendor's `-of` t8
 * block has `flen=5779 mode=4 dict=1 dref=0 dlen=1500` followed by the
 * 24-bit line-code ctrl. */
static void sbc_enc_rec_dict(SbcBitsW *b, uint32_t flen, uint32_t dref,
                             uint32_t dlen, uint32_t mode, uint32_t ctrl,
                             uint32_t m7, uint32_t adv, uint32_t level)
{
    sbc_sbw_put(b, flen, 25);
    sbc_sbw_put(b, 1, 1);
    sbc_sbw_put(b, mode, 3);
    sbc_sbw_put(b, 1, 1);
    sbc_sbw_put(b, dref, 12);
    sbc_sbw_put(b, dlen, 25);
    if (mode == 4)
        sbc_sbw_put(b, ctrl >> 1, 24);
    if (mode == 7)
        sbc_sbw_put(b, m7, 12);
    if (mode == 0 || mode == 2)
        sbc_sbw_put(b, adv, 1);
    /* -m2/-m3 write the second-stage bit here too, always clear (the
     * decoder ignores it for a dict record, but the vendor's bit stream has
     * it: `t3` at -m2 is 124 bits against 123 without) */
    if (level >= 1)
        sbc_sbw_put(b, 0, 1);
}

static void sbc_enc_rec_mode(SbcBitsW *b, uint32_t flen, uint32_t mode,
                             uint32_t adv, uint32_t m7, uint32_t ctrl,
                             uint32_t sub, uint32_t sub_flag,
                             uint32_t sub_idx, uint32_t level)
{
    sbc_sbw_put(b, flen, 25);
    sbc_sbw_put(b, 1, 1);
    sbc_sbw_put(b, mode, 3);
    sbc_sbw_put(b, 0, 1); /* dict = 0 */
    if (mode == 4)
        sbc_sbw_put(b, ctrl >> 1, 24);
    if (mode == 7)
        sbc_sbw_put(b, m7, 12);
    if (mode == 0 || mode == 2)
        sbc_sbw_put(b, adv, 1);
    if (level >= 1) {
        sbc_sbw_put(b, sub ? 1 : 0, 1);
        if (sub) {
            sbc_sbw_put(b, sub_flag, 1);
            sbc_sbw_put(b, (sub_idx ? sub_idx : 1) - 1, 5);
        }
    }
}

/* Writes the block header and payload for a pipeline that already ran
 * (`b`), mirroring sbc_enc_stored_block().  `n`/`data` are the block's raw
 * bytes (the verify digest covers them). */
static int sbc_enc_comp_write(SbcBuf *out, SbcEncBlock *b, const uint8_t *data,
                              size_t n, uint32_t csum, SbcWExtra *extra,
                              uint32_t nsyms, int flush_bytes,
                              uint32_t *hash, uint32_t level, int store_bwt)
{
    SbcWRC w;
    SbcBitsW recs;
    size_t nb, k;
    uint32_t i;
    SbcWDig idig, vdig;
    uint32_t dw = sbc_enc_dig_width(csum);
    uint32_t vlq, primary, e1, e2 = 0, flag3, extra16 = 0;
    const uint8_t *pay;
    size_t payn;

    vlq = (uint32_t)b->bwtlen;
    primary = b->primary;
    flag3 = (uint32_t)b->flag3;
    /* e1 == 0 stores the BWT string itself, exactly like the decoder's
     * stored path; the block still carries the pipeline's filter record. */
    e1 = store_bwt ? 0 : (uint32_t)b->payload.n;
    pay = store_bwt ? b->bwt : b->payload.p;
    payn = store_bwt ? (size_t)vlq : (size_t)e1;
    /* the prose line code rides between the payload and the verify digest */
    if (b->linecoden)
        e2 = (uint32_t)b->linecoden;

    if (hash) {
        /* The block length folded into the trailer hash counts the line code
         * bytes too (`e2`), so a prose block's hash covers what it stores. */
        uint32_t x = *hash;
        uint32_t m = x ^ (((~x) & 0xFFFFFFFFu) >> 23);
        *hash = ((m >> 25) | (m << 7)) + ((vlq + e2) ^ sbc_enc_nibrev(primary));
        if (getenv("SBC_DBG3"))
            fprintf(stderr, "FOLD x=%08x n=%zu vlq=%u e2=%u prim=%u -> %08x\n",
                    x, n, vlq, e2, primary, *hash);
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
    for (i = 0; i < b->nsegs; i++) {
        uint32_t flen = b->fsegs[i], mode = b->modes[i];
        if (b->drefs[i]) {
            sbc_enc_rec_dict(&recs, flen, b->drefs[i] - 1, b->dlens[i], mode,
                             b->ctrls[i], b->m7s[i], b->advs[i], level);
        } else if (mode == 5 && flen >= 512u && !b->subs[i] &&
                   !b->expl5[i]) {
            /* plain copy the coder refused: compact flen(25) coded=0, the
             * stall path of 0x413ae7 (0x412af0 returned false).  A copy the
             * analyzer itself asked for keeps its mode bits. */
            sbc_sbw_put(&recs, flen, 25);
            sbc_sbw_put(&recs, 0, 1);
        } else {
            sbc_enc_rec_mode(&recs, flen, mode, b->advs[i], b->m7s[i],
                             b->ctrls[i], b->subs[i], b->subal[i],
                             b->subidx[i], level);
        }
    }
    sbc_sbw_put(&recs, 0x1FFFFFFu, 25);
    nb = recs.nbits;
    sbc_wrc_int_maxbits(&w, 0x14, (uint32_t)nb);
    for (k = 0; k < (nb + 7) / 8; k++) {
        size_t rem = nb - k * 8;
        if (rem >= 8)
            sbc_wrc_u(&w, 0x100, recs.p[k]);
        else
            sbc_wrc_u(&w, 1u << rem, recs.p[k] >> (8 - rem));
    }
    sbc_enc_dig_init(&idig, csum);
    if (csum) {
        uint8_t six[6];
        six[0] = (uint8_t)primary;
        six[1] = (uint8_t)(primary >> 8);
        six[2] = (uint8_t)(primary >> 16);
        six[3] = (uint8_t)(primary >> 24);
        six[4] = (uint8_t)flag3;  /* the vendor feeds flag3 then extra16 */
        six[5] = (uint8_t)extra16;
        sbc_enc_dig_upd(&idig, six, 6);
        sbc_enc_dig_upd(&idig, recs.p, (nb + 7) / 8);
        /* the prose line code is fed before the payload: measured on a
         * mode-4 block (CRC16 5aa9 = six + bits + code + payload, 5aa5
         * with the code after the payload) */
        if (b->linecoden)
            sbc_enc_dig_upd(&idig, b->linecode, b->linecoden);
    }
    free(recs.p);
    sbc_wrc_u(&w, 3, flag3);
    if (!extra->freq) {
        sbc_wex_init(extra, &w, nsyms, 1, 0x4000, 0x4000, 0);
    } else {
        extra->wrc = &w;
    }
    sbc_wex_k(extra, e1);
    sbc_wex_k(extra, e2);
    sbc_wrc_flush(&w, flush_bytes);

    if (csum) {
        uint8_t dg[32];
        uint32_t j;
        sbc_enc_dig_upd(&idig, pay, payn);
        sbc_enc_dig_out(&idig, dg);
        for (j = 0; j < dw; j++)
            sbc_buf_put(out, dg[j]);
    }
    sbc_buf_write(out, pay, payn);
    if (b->linecoden)
        sbc_buf_write(out, b->linecode, b->linecoden);
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

/* The vendor only stores a compressed block when the payload saves more than
 * eight bytes over the BWT string it would otherwise store (`e1` bytes vs
 * `vlq`).  Measured at 4 kB and 8 kB on high-entropy inputs whose mode-5
 * payload our pipeline reproduces bit for bit: a 9-byte saving is compressed,
 * an 8-byte one is stored (and the 67-byte `hello.txt`, saving 1 byte, is
 * stored too).  `hello-m1` is the corpus case for the rule, see
 * `tools/block_archive_test.py`. */
#define SBC_ENC_MIN_GAIN 8

/* A *filtered* block only has to save this many bytes over the BWT string to
 * keep its payload.  Measured on mode-6 blocks: a 1-byte saving stores the
 * BWT (`r48`, vlq 115 against payload 114) while the 4-byte saving of the
 * period-31 block (vlq 93, payload 89) is written as a payload; the fuzz's
 * `cycl25` adds the boundary itself (vlq 68, payload 65) and the vendor keeps
 * the payload there, so the test is `payload + 3 <= vlq`, i.e. a saving of 3
 * or more. */
#define SBC_ENC_FILT_GAIN 3

/* The measured mode policy (ENCODER.md 6.4).  Returns the filter mode a
 * single-record block should use, or -1 to leave it stored.
 *
 *   -m1  the simple filter's own bail-out is the signal: its state machine
 *        tries 0x4000 bytes to engage a lag and copies the rest of the block
 *        verbatim when it cannot, and the vendor then writes a copy record.
 *        This is what makes `records` copy and `zeros`/`pattern`/`biased`
 *        filter, and it matches all 10 corpus blocks plus the synthetic
 *        probes (ENCODER.md 6.4).
 *   -m2  mode 0 exactly when the advanced filter changes the block.  An
 *        identity result means its own lag test found no lag, and the vendor
 *        writes a copy record; this matches all 10 corpus blocks.
 *   -m3  cheapest of copy and mode 0 on the final payload, ties to copy, as
 *        the vendor does for `zeros` (43/43).  23 of 24 corpus blocks agree;
 *        the exception is mode 7, which is not a candidate here.
 *
 * Enabled with SBC_POLICY=1 so the stored-block guarantees stay the default.
 */

/* The vendor's own chooser (0x40cb80); its word is the header ctrl >> 1.
 * The filter (0x40c600, entry 0x40c670) then clears the word's bit 0x04
 * (= record ctrl 0x08) when the line model would not fit the block window:
 * the test is `n + (n >> 9) > limit` for n <= 1 MB and `n + 0x800 > limit`
 * above it, with `limit` the block window `bs - 1` (`blk`).  Both boundaries
 * were measured exactly: at -b5 (limit 0x2FFFFF) the bit survives 0x2FFBFF and
 * drops at 0x2FFC00; at -b1 (limit 0xFFFFF) it survives 1046530 and drops at
 * 1046533.  The bit is inert for the decoder, but the vendor's byte stream
 * depends on it, so a byte-exact archive needs it. */
static int sbc_enc_text_ctrl(const uint8_t *data, size_t n)
{
    uint32_t c = sbc_enc_m4_ctrl(data, n);
    uint64_t need = (n > 0x100000u) ? (uint64_t)n + 0x800u
                                    : (uint64_t)n + ((uint64_t)n >> 9);
    if (need > sbc_enc_blk_limit)
        c &= ~0x4u;
    return (int)(c << 1);
}

static int sbc_enc_policy_mode(int level, const uint8_t *data, size_t n,
                               size_t fulln, uint32_t *ctrl, uint32_t *m7)
{
    uint8_t *f = NULL;
    size_t fl = 0;
    int mode, m6 = 0, m0 = 0;

    *ctrl = 0;
    *m7 = 0;
    /* The text branch.  Records under 600 bytes never reach the text filter:
     * prefixes of `eng.txt` and `code.c` get a copy record at 599 bytes and
     * the mode-4 one at 600, at every level and whatever the content (§6.7).
     * The vendor's own chooser (0x40cb80) *is* the rest of the test:
     * its word is zero for a block the line code does not apply to
     * (uppercase `biased.bin`, mixed binary) and nonzero when mode 4 does,
     * and it is taken as it stands -- the old printable-ASCII + lowercase
     * heuristic plus a 5 % size gate was too strict for text whose bytes are
     * not all printable (`wide`: ASCII with a NUL after every byte, which the
     * vendor records as ctrl 0x0C without the token bit, i.e. a record that
     * does not shrink at all).  `ctrl` is the record's control word: 0x84
     * base | 0x08 (always, as the vendor writes it) | 0x20 when the text
     * carries line breaks (eng.txt has none and gets 0x8C, code.c has 600 LFs
     * and gets 0xAC).  The chooser sees the whole record (`fulln`), not the
     * analysis window: its 0x04 bit depends on the segment length
     * (sbc_enc_text_ctrl).  SBC_M4CTRL forces one of the ctrl shapes
     * (0c/8c/ac/bc/fc), which is how the cost of each variant is measured. */
    if (n >= 600) {
        const char *fm = getenv("SBC_M4CTRL");
        uint32_t c = (fm && *fm) ? (uint32_t)strtoul(fm, NULL, 16)
                                 : (uint32_t)sbc_enc_text_ctrl(data, fulln);
        if (c && sbc_enc_mode4(data, n, c, &f, &fl, NULL, NULL) == 0) {
            /* the filter reports the ctrl it actually wrote: the token bit of
             * the chooser's word is dropped when the token pass emitted no
             * code at all (`a b c ...` prose gets 0x0C, see sbc_enc_mode4) */
            *ctrl = sbc_enc_m4_ctrl_eff;
            free(f);
            return 4;
        }
    }
    /* Mode-6 candidate.  The vendor only runs the repeat filter above 4 kB
     * (`n > 0x1000`: 4096 B gets a copy record, 4097 B a mode-6 one), and the
     * transform then decides for itself: 0x411bb0 writes into
     * `dst + min(n, cap) - 6` with `cap = n - min(n/128, 0x1000)` (0x412fd2
     * builds the cap, 0x411bd5/0x411c37 apply it) and returns 0 when the
     * output does not fit, which is what the caller reads as "no repeat
     * filter".  Measured on random data with `k` copies of a 200-byte chunk
     * spliced in (n = 30000, cap slack 234): 29806 bytes come out as a copy
     * record and 29612 as a mode-6 one, i.e. the boundary is
     * `fl + 6 <= n - slack` and not a ratio.  A ratio gate (`fl*2 < n`)
     * happened to fit the corpus but rejects the sparse records the vendor
     * keeps (s120k -m2: 76645 of 120000). */
    if (n > 0x1000 && sbc_enc_mode6(data, n, &f, &fl) == 0) {
        size_t slack = n >> 7;
        if (slack > 0x1000)
            slack = 0x1000;
        m6 = (fl + 6 <= n - slack);
        free(f);
    }
    if (getenv("SBC_POLDBG"))
        fprintf(stderr, "pol level=%d n=%zu m6=%d\n", level, n, m6);
    if (level <= 0) {
        if (sbc_enc_filter(data, n, 0, 0, 0, 0, &f, &fl, NULL, NULL,
                           NULL, 0) != 0)
            return -1;
        free(f);
        m0 = (sbc_enc_m0_verdict != 0);
        if (getenv("SBC_M0DBG"))
            fprintf(stderr, "m0simp n=%zu coded=%d state=%d trial=%d v=%d\n",
                    n, sbc_enc_m0_coded, sbc_enc_m0_state, sbc_enc_m0_trial,
                    sbc_enc_m0_verdict);
        /* The simple variant's own verdict decides (0x43aeeb: at least 4096
         * bytes have to be coded with a lag, and the filter is "strong"
         * above a tenth of the record).  When it applies, mode 0 wins even if
         * the repeat filter would shrink the block further (a 256-byte cycle
         * of 0..255 at 10240 B: vendor mode 0 / e1 341, mode 6 would store
         * 0); when it refuses, mode 6 is the fallback -- a 32-byte cycle gets
         * mode 6 at 4200 B and beyond, and so does a periodic line block the
         * simple filter would have stored -- otherwise the copy record wins. */
        if (m0)
            return 0;
        if (m6)
            return 6;
        return 5;
    }
    if (level == 1) {
        /* -m2: the analysis always proposes mode 0 and the level-1 object of
         * the adaptive filter decides (0x43db8d..0x43dc72, FUN_0043c490's
         * own return value).  It refuses when its size test trips, when the
         * copy slot's score sum is not beaten by more than 1/64
         * (`t6c < t70 + (t70 >> 6)`) or when less than min(n/128, 3072) bytes
         * were coded with a real lag, and the vendor then writes the repeat
         * record if the transform applies (uppercased `code.c`, 45270 B) or
         * a copy record otherwise (random data, zeros, small `pat` files).
         * Anything else is mode 0 (periodic cycles, images, `pattern.bin`).
         *
         * It is not the lag the filter settled on: the object's controller
         * can still change the bytes when the lag search found nothing
         * (`hi4`, 200000 B of nibble values in the high half of every byte:
         * first difference at byte 538, vendor copy record), and a lag that
         * pays off on half of a mixed record is not enough either
         * (`ascii_mixed` at `-ad`, `m1_probe`).  The mode-6 candidate is only
         * consulted above 4 kB. */
        if (sbc_enc_filter(data, n, 1, 0, 0, 0, &f, &fl, NULL, NULL,
                           NULL, 0) != 0)
            return -1;
        if (getenv("SBC_M0DBG"))
            fprintf(stderr, "m2 n=%zu v=%d t54=%ld t6c=%ld t70=%ld "
                            "cntA=%ld cntB=%ld\n",
                    n, sbc_enc_m0_verdict, sbc_m0a_last_t54,
                    sbc_m0a_last_t6c, sbc_m0a_last_t70, sbc_m0a_last_cnt_a,
                    sbc_m0a_last_cnt_b);
        mode = (sbc_enc_m0_verdict == 0) ? (m6 ? 6 : 5) : 0;
        free(f);
        return mode;
    }
    /* -m3: the analysis starts a block on mode 0 and the level-2 filter's own
     * verdict decides the rest (FUN_0043c490's return value; the tests are
     * the same three as at -m2, plus the two scratch tables, which is why the
     * set8 image (84300 B, table1 17762 > table0 13783) is written as a copy
     * record while a 42000 B image (3926 < 6114) keeps mode 0).  The caller
     * then falls back to mode 6 (above 4 kB, as at -m2) or to a copy record.
     * Mode 7 is the other branch of this same handler: the width getter
     * FUN_004552a0 reads the filter object's per-slot byte counts, and a
     * third of the record on slot 2 (lag 3, one pixel row) at -m3 sends the
     * record to the estimator below instead. */
    if (sbc_enc_filter(data, n, 2, 0, 0, 0, &f, &fl, NULL, NULL, NULL, 0) != 0)
        return -1;
    if (getenv("SBC_M0DBG"))
        fprintf(stderr, "m0 n=%zu cntA=%ld cntB=%ld famA=%ld famB=%ld v=%d "
                        "t54=%ld t6c=%ld t70=%ld "
                        "arr=%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n", n,
                sbc_m0a_last_cnt_a, sbc_m0a_last_cnt_b,
                sbc_m0a_last_fam_a, sbc_m0a_last_fam_b, sbc_enc_m0_verdict,
                sbc_m0a_last_t54, sbc_m0a_last_t6c, sbc_m0a_last_t70,
                sbc_m0a_last_slot[0], sbc_m0a_last_slot[1],
                sbc_m0a_last_slot[2], sbc_m0a_last_slot[3],
                sbc_m0a_last_slot[4], sbc_m0a_last_slot[5],
                sbc_m0a_last_slot[6], sbc_m0a_last_slot[7],
                sbc_m0a_last_slot[8], sbc_m0a_last_slot[9],
                sbc_m0a_last_slot[10]);
    {
        /* mode 6 is chosen without asking what it costs: the vendor writes a
         * mode-6 record for uppercased `code.c` at -m3 even though its copy
         * payload is 226 bytes smaller (1770 against 1996), just as at -m2.
         * The 1500-byte image record of the t0 set stays copy although a
         * mode-0 payload would be 326 bytes against 593: below the filter's
         * minimum it refuses, so copy wins there. */
        int refused = (sbc_enc_m0_verdict == 0);
        /* Photographic records: the mode-0 handler of FUN_00412af0 case 0
         * continues into the width estimator when the analysis accepted the
         * record (0x412db1: for a filter that applied, the coded size is the
         * record's own length, so `> 0x4000` is the record's length test),
         * the record is longer than 0x4000, the level is -m3 (0x412dd9) and
         * the object's slot array says a third of the bytes went to slot 2 --
         * the fixed lag 3, one 24-bit pixel row (0x412df0: `get(obj, 2) >
         * n / 3`).  The estimator then names the record's row width, and a
         * return above 1 replaces mode 0 with mode 7 there and then
         * (0x412e25); it is not part of any cost comparison, and mode 6 is
         * only reached when the gate says no. */
        if (!refused && n > 0x4000 &&
            sbc_m0a_last_slot[2] > (long)(n / 3)) {
            int w = sbc_enc_m7_search(data, n);
            if (w > 1) {
                *m7 = (uint32_t)w;
                if (getenv("SBC_M7DBG"))
                    fprintf(stderr, "m7 n=%zu width=%d arr2=%ld\n", n, w,
                            sbc_m0a_last_slot[2]);
                free(f);
                return 7;
            }
        }
        free(f);
        if (refused)
            return m6 ? 6 : 5;
        /* Applied: the record is mode 0, whatever the repeat filter would
         * have saved.  A record the filter accepted never becomes mode 6 --
         * ramp256 and image.raw at -m3 keep mode 0 although their mode-6
         * records are smaller in the archive -- and the vendor does not
         * compare the mode-0 payload against a copy's either (set2 -m3:
         * 24634 bytes against a copy payload that our pipeline puts 12 kB
         * lower). */
        return 0;
    }
}

/* 0x4132c0's row-width branch.  Before a unit is cut, the vendor's analyzer
 * looks at the bytes the unit would start with: an `II`/`MM` first word that
 * is not the 0x00020000 magic takes the TIFF path (0x4134b9) and runs the
 * 0x443e20 estimator on the whole remaining span.  A width of 1 is the
 * vendor's "one-pixel image" case and becomes a copy record covering the
 * entire remainder (0x412af0 case 5, 0x4134c7); a width of 3 or more becomes
 * a mode-7 record of the same span, with the width the estimator returned
 * verbatim -- 0x4134c7 only tests `<= 2`, the multiple-of-4 rounding at
 * 0x41362f belongs to the fallback path the BMP/PNG checks reach, so a
 * 202-pixel image records `m7=202` and not 204.  Widths 0 and 2 fall back to
 * the regular 512 kB window.  The text chooser runs before this branch, so a
 * mode-4 unit still wins, and the branch needs a level above `-m1` (the
 * vendor's `uVar8 != 0` at 0x41347c, i.e. the sub-filter object of -m2/-m3):
 * `-m1` writes a mode-0 record for the same 1-pixel `MM` text. */
static int sbc_enc_analyzer_width(const uint8_t *d, size_t n)
{
    uint16_t m;

    if (n < 0x200)
        return 0;
    m = (uint16_t)(d[0] | ((uint16_t)d[1] << 8));
    if (m != 0x4949 && m != 0x4d4d)
        return 0;
    if (d[0] == 0 && d[1] == 0 && d[2] == 2 && d[3] == 0)
        return 0; /* the 0x00020000 magic takes the PNG-ish path */
    return sbc_enc_m7_search(d, n);
}

/* -m3 record size: the vendor carves every 512 kB (0x80000) of a block into
 * one record (`-m1`/`-m2` keep a whole file in one record: a 3 MB file is six
 * mode-6 records at -m3 and a single one at -m2).  This is also the slot size
 * mode 6 addresses its block-wide table with. */
#define SBC_ENC_REC_MAX 0x80000u

/* The history feed: one (ptr,len) per record output, in order.  Records of
 * 128 bytes or less never reach the ring (sbc_sub_feed's own early exit). */
static void sbc_enc_feed_segs(const uint8_t *data, const uint32_t *segs,
                              uint32_t nsegs)
{
    size_t off = 0;
    uint32_t i;
    for (i = 0; i < nsegs; i++) {
        sbc_enc_sub_feed_record(data + off, segs[i]);
        off += segs[i];
    }
}

/* Block-emission policy installed as sbc_enc_emit_block()'s hook.  SBC_COMP
 * forces a mode for validation runs and SBC_POLICY=0 turns the policy off, so
 * the block is stored; the measured policy is the default (it is the vendor's
 * own choice, and only blocks it cannot represent fall back to storage).
 * A block that holds
 * several files is planned file by file -- the vendor filters each file on its
 * own and records the choice in that file's record -- and only the concatenated
 * result goes through LZP/BWT. */
static int sbc_enc_block_dispatch(SbcBuf *out, const uint8_t *data, size_t n,
                                  const uint32_t *segs, uint32_t nsegs,
                                  uint32_t csum, SbcWExtra *extra,
                                  uint32_t nsyms, int flush_bytes,
                                  uint32_t *hash, uint32_t level)
{
    const char *f = getenv("SBC_COMP");
    const char *pol = getenv("SBC_POLICY");
    SbcEncBlock b;
    int forced = f ? atoi(f) : -1;
    int policy_on = !(pol && *pol == '0');
    SbcRecPlan *plan = NULL;
    uint8_t **owned = NULL;
    uint32_t nrec = 0, cap = 0, i, off = 0, rc;
    int failed = 0;

    if (nsegs == 0 || n == 0 || (forced < 0 && !policy_on)) {
        rc = sbc_enc_stored_block(out, data, n, segs, nsegs, csum, extra,
                                  nsyms, flush_bytes, hash, level);
        if (rc == 0 && level >= 1)
            sbc_enc_feed_segs(data, segs, nsegs);
        return rc;
    }
    /* Build the record list first.  At -m3 a record is one 512 kB window, at
     * every level, with one measured exception: when the window analsis picks
     * the text filter (mode 4) the record runs to the end of the file part in
     * the block instead.  A 3 MB block of code therefore becomes one
     * 2.7 MB mode-4 record, while images, random data and uppercase text are
     * cut into six 512 kB records (measured on `-m3 -ad` archives). */
    off = 0;
    for (i = 0; i < nsegs && !failed; i++) {
        uint32_t done = 0;
        while (done < segs[i]) {
            uint32_t rest = segs[i] - done;
            uint32_t win = rest;
            uint32_t take;
            int mode = forced >= 0 ? forced : 0;
            uint32_t ctrl = 0, m7 = 0;
            int expl5 = 0;
            if (nrec == cap) {
                cap = cap ? cap * 2 : 8;
                plan = (SbcRecPlan *)realloc(plan, cap * sizeof(*plan));
                owned = (uint8_t **)realloc(owned, cap * sizeof(*owned));
                if (!plan || !owned)
                    return -1;
            }
            if (level == 2 && win > SBC_ENC_REC_MAX)
                win = SBC_ENC_REC_MAX;
            {
                int whole = 0;
                if (forced < 0) {
                    /* the analysis sees the record's first window only */
                    mode = sbc_enc_policy_mode((int)level, data + off, win,
                                               rest, &ctrl, &m7);
                    if (mode < 0) {
                        failed = 1;
                        break;
                    }
                    /* 0x4132c0's TIFF branch runs after the text chooser and
                     * may give the record the whole remaining span.  It needs
                     * a level above -m1 (the sub-filter object): -m2 and -m3
                     * both take it. */
                    if (mode != 4 && level >= 1) {
                        int aw = sbc_enc_analyzer_width(data + off, rest);
                        if (aw == 1) {
                            mode = 5;
                            whole = 1;
                            expl5 = 1;
                        } else if (aw >= 3) {
                            mode = 7;
                            m7 = (uint32_t)aw;
                            whole = 1;
                        }
                    }
                }
                take = (level == 2 && mode != 4 && !whole) ? win : rest;
            }
            memset(&plan[nrec], 0, sizeof(plan[nrec]));
            owned[nrec] = NULL;
            plan[nrec].off = off;
            plan[nrec].len = take;
            plan[nrec].src = data + off;
            plan[nrec].srclen = take;
            plan[nrec].mode = mode;
            plan[nrec].ctrl = ctrl;
            plan[nrec].m7 = m7;
            plan[nrec].expl5 = (uint32_t)expl5;
            nrec++;
            off += take;
            done += take;
        }
    }
    /* Dictionary references.  The vendor keeps a per-block list of the
     * (offset,len) every record produced so far, and a record whose first
     * 1024 bytes or more equal the *start* of an earlier record is written as
     * a reference: the matched prefix is replayed from the ring and only the
     * tail is stored.  Measured shapes (`t3`, `t4`, 9 MB `-m2` set): a whole
     * file copied by a later one (flen 0), a 1500-byte previous file followed
     * by 2500 new bytes, and a 145727-byte prefix of a 3 MB record.  The
     * record then behaves as a copy record (mode 5) whatever filter it would
     * have taken. */
    for (i = 0; i < nrec && !failed; i++) {
        uint32_t best = 0, bestj = 0, j;
        for (j = 0; j < i; j++) {
            size_t lim = plan[j].len < plan[i].len ? plan[j].len : plan[i].len;
            size_t k = 0;
            if ((uint32_t)lim <= best)
                continue;
            while (k < lim && data[plan[j].off + k] == data[plan[i].off + k])
                k++;
            if (k > best) {
                best = (uint32_t)k;
                bestj = j;
            }
        }
        if (best >= 1024u) {
            plan[i].dref = bestj + 1; /* the decoder's list starts at 0 */
            plan[i].dlen = best;
            plan[i].src += best;
            plan[i].srclen -= best;
            /* a whole-file copy is a mode-5 record; a record with a tail
             * keeps the mode the tail's own analysis picks (the vendor's
             * `-of` t8 block has a mode-4 dict record for exactly that), and
             * the tail still goes through the filter stage */
            if (plan[i].srclen && forced < 0) {
                uint32_t c = 0, m7v = 0;
                int m = sbc_enc_policy_mode((int)level, plan[i].src,
                                            (uint32_t)plan[i].srclen,
                                            (uint32_t)plan[i].srclen, &c,
                                            &m7v);
                plan[i].mode = m < 0 ? 5 : m;
                plan[i].ctrl = c;
                plan[i].m7 = m7v;
            } else if (!plan[i].srclen) {
                plan[i].mode = 5;
                plan[i].ctrl = 0;
                plan[i].m7 = 0;
            }
        }
    }
    for (i = 0; i < nrec && !failed; i++) {
        uint32_t len = plan[i].len;
        int mode = plan[i].mode;
        if (plan[i].dref) {
            /* a dict record is a copy record and never gets a second stage */
            continue;
        }
        if (mode == 7 && plan[i].m7 < 2)
            plan[i].m7 = 0;
        /* Second stage: -m2/-m3 compress the record before its filter runs,
         * with a length base that comes from the mode it is about to get.
         * A result of 511 bytes or less makes the record a copy record (the
         * vendor then skips the filter: 0x412be8). */
        if (!failed && level >= 1 && g_enc_sub_armed) {
            int align = 0;
            uint32_t lbase = sbc_enc_sub_lbase(mode, len, &align);
            if (lbase) {
                uint8_t *sb = (uint8_t *)malloc((size_t)len + 64);
                size_t sn = 0;
                if (sb)
                    sn = sbc_enc_sub_compress(plan[i].src, len, sb,
                                              sbc_enc_sub_cap(len), lbase,
                                              align);
                if (sn) {
                    plan[i].sub = 1;
                    plan[i].subidx = lbase;
                    plan[i].subal = (uint32_t)align;
                    plan[i].src = sb;
                    plan[i].srclen = sn;
                    owned[i] = sb;
                    if (sn <= 0x1FF) {
                        /* the vendor skips the filter for a stream this small
                         * and writes a copy record (0x412be8) */
                        plan[i].mode = 5;
                    } else {
                        /* the filter is chosen on the *stream*, not on the raw
                         * record: a text record whose stream is binary ends up
                         * a copy record (a 2 MB repetitive text at -m3 comes
                         * out `mode=5 sub=1 idx=9`, because the length base
                         * was picked before the stage ran) */
                        uint32_t c2 = 0, m72 = 0;
                        int m2 = sbc_enc_policy_mode((int)level, sb, sn,
                                                     sn, &c2, &m72);
                        if (m2 < 0) {
                            failed = 1;
                        } else {
                            plan[i].mode = m2;
                            plan[i].ctrl = c2;
                            plan[i].m7 = m72;
                        }
                    }
                } else {
                    free(sb);
                }
            }
        }
    }
    if (!failed && sbc_enc_pipeline_plan(&b, data, plan, nrec, (int)level) != 0)
        failed = 1;
    for (i = 0; i < nrec; i++)
        free(owned[i]);
    free(owned);
    free(plan);
    if (failed)
        return sbc_enc_stored_block(out, data, n, segs, nsegs, csum, extra,
                                    nsyms, flush_bytes, hash, level);
    /* A copy-block payload has to win by more than SBC_ENC_MIN_GAIN bytes
     * (the coder's flush eats that much), but a *filtered* block is kept as
     * soon as its payload is smaller: the mode-6 cycle block stores 93 BWT
     * bytes and still writes a 89-byte payload.  The vendor then keeps the BWT
     * string when the filter and LZP already shrank it (mixed-m2 blk000:
     * 35003 -> 2983), and only falls back to the raw stored block when they
     * did not. */
    /* The eight-byte margin was measured on high-entropy blocks, where the
     * LZP pass found nothing (flag3 = 0).  When it did shrink the filtered
     * stream, any saving is enough: the t5 set's five mode-5 records
     * (4000/900/900/300/300 pat bytes) have vlq 435 and a 428-byte payload,
     * and the vendor writes that payload -- 428 + 8 would have failed. */
    /* The eight-byte margin only applies when the block came out of the
     * filter unchanged (bwtlen == n): there the coder's flush eats that much,
     * so a payload that only ties the BWT string is not worth writing.  As
     * soon as the filter chain shrank the block -- LZP, or the second stage
     * turning 300 bytes into a copy stream -- the cheaper filter margin
     * applies: the `-m2` 300-byte prose record writes 19 bytes against a
     * 24-byte BWT (saves 5), while at `-m3` the same file's 26 bytes against
     * 28 are stored instead (saves 2 < 3). */
    if (b.modes[0] == 5 ? (b.flag3 || b.bwtlen < n
                               ? b.payload.n + SBC_ENC_FILT_GAIN <= b.bwtlen
                               : b.payload.n + SBC_ENC_MIN_GAIN < b.bwtlen)
                        : b.payload.n + SBC_ENC_FILT_GAIN <= b.bwtlen) {
        rc = sbc_enc_comp_write(out, &b, data, n, csum, extra, nsyms,
                                flush_bytes, hash, level, 0);
    } else if (b.bwtlen < n) {
        rc = sbc_enc_comp_write(out, &b, data, n, csum, extra, nsyms,
                                flush_bytes, hash, level, 1);
    } else {
        sbc_enc_block_free(&b);
        rc = sbc_enc_stored_block(out, data, n, segs, nsegs, csum, extra,
                                  nsyms, flush_bytes, hash, level);
        if (rc == 0 && level >= 1)
            sbc_enc_feed_segs(data, segs, nsegs);
        return rc;
    }
    if (rc == 0 && level >= 1) {
        /* feed the *records* the block was written with (512 kB chunks at
         * -m3), which is what the decoder replays too */
        size_t pos = 0;
        for (i = 0; i < b.nsegs; i++) {
            if (!b.drefs[i])
                sbc_enc_sub_feed_record(data + pos, b.rawsegs[i]);
            pos += b.rawsegs[i];
        }
    }
    sbc_enc_block_free(&b);
    return rc;
}

static void sbc_enc_block_init(void)
{
    sbc_enc_block_fn = sbc_enc_block_dispatch;
}

#endif /* SBC_ENC_BLOCK_H */
