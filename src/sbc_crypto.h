/*
 * sbc_crypto.h -- the vendor's archive encryption (SBC Archiver 0.970).
 *
 * Container (measured on `sbc.exe c -ca ...`):
 *
 *   magic   "SBC\x1e" + ('H' + cipher id)     5 bytes
 *   salt    A                                  16 random bytes
 *   check   B                                  16 bytes
 *   body    AES-CBC(key, IV = B)               ceil((len - 5) / 16) blocks
 *
 * The whole archive body (header range-coder and payload, starting right
 * after the 5-byte magic) is encrypted; even the file table is unreadable
 * without the passphrase.  The check block is one CBC block under IV = A:
 * its plaintext P must satisfy P[15] == check_byte(passphrase, cipher), the
 * vendor's `FUN_00404b40` comparison (it only inspects the last byte,
 * `FUN_004014c0`); the cipher's CBC state then continues with IV = B, so the
 * body is decrypted in the same stream.
 *
 * key: `FUN_00402530`, a 8192-round iterated SHA-1/SHA-256 KDF
 * (SHA-1 when the key is 20 bytes or less, SHA-256 otherwise) seeded with the
 * 16-byte salt and a 767-byte repeated-passphrase buffer that every round
 * permutes with two swapped bytes.  check_byte: `FUN_00401f40`, SHA-1 over
 * the passphrase followed by 8192 raw block encryptions of a 16-byte buffer
 * that starts as the passphrase (zero padded).
 *
 * Cipher ids (the 5th magic byte is 'H' + id):
 *   1 AES/Rijndael (32-byte key)   2 Blowfish (32)   3 CAST-128 (16)
 *   4 triple-DES (24)              5 Serpent (32)    6 Twofish (32)
 *
 * All six block primitives are implemented (AES and Blowfish here, CAST-128
 * and 3DES below, Serpent and Twofish in sbc_cipher_extra.h).  The vendor's
 * Serpent is the byte-reversed variant (TNEPRES): key and block bytes go into
 * the cipher backwards; Twofish is the plain reference algorithm.
 */
#ifndef SBC_CRYPTO_H
#define SBC_CRYPTO_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "sbc_hash.h"
#include "sbc_cipher_tables.h"
#include "sbc_cipher_extra.h"

/* ---------------- AES (FIPS-197) ---------------- */

typedef struct {
    uint8_t rk[240]; /* round keys, 4*(nr+1) words */
    int nr;
    int bits;
} SbcAes;

static uint32_t sbc_aes_sbox[256];
static uint32_t sbc_aes_rsbox[256];
static int sbc_aes_tab_ready;

static uint8_t sbc_aes_xtime(uint8_t x)
{
    return (uint8_t)((uint8_t)(x << 1) ^ (uint8_t)((x >> 7) * 0x1b));
}

static uint8_t sbc_aes_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) {
        if (b & 1)
            r ^= a;
        a = sbc_aes_xtime(a);
        b >>= 1;
    }
    return r;
}

static void sbc_aes_tables(void)
{
    int x;
    if (sbc_aes_tab_ready)
        return;
    for (x = 0; x < 256; x++) {
        uint8_t y = 1, v;
        int i;
        if (x == 0)
            y = 0;
        else {
            for (i = 0; i < 254; i++)
                y = sbc_aes_mul(y, (uint8_t)x);
        }
        v = (uint8_t)(y ^ ((y << 1) | (y >> 7)) ^ ((y << 2) | (y >> 6)) ^
                      ((y << 3) | (y >> 5)) ^ ((y << 4) | (y >> 4)) ^ 0x63);
        sbc_aes_sbox[x] = v;
        sbc_aes_rsbox[v] = (uint8_t)x;
    }
    sbc_aes_tab_ready = 1;
}

static void sbc_aes_setkey(SbcAes *a, const uint8_t *key, int bits)
{
    int nk = bits / 32, nr = nk + 6, i, j;
    uint8_t rcon = 1;
    sbc_aes_tables();
    a->bits = bits;
    a->nr = nr;
    memcpy(a->rk, key, (size_t)bits / 8);
    for (i = nk; i < 4 * (nr + 1); i++) {
        uint8_t t[4];
        memcpy(t, a->rk + 4 * (i - 1), 4);
        if (i % nk == 0) {
            uint8_t u = t[0];
            t[0] = (uint8_t)(sbc_aes_sbox[t[1]] ^ rcon);
            t[1] = (uint8_t)sbc_aes_sbox[t[2]];
            t[2] = (uint8_t)sbc_aes_sbox[t[3]];
            t[3] = (uint8_t)sbc_aes_sbox[u];
            rcon = sbc_aes_xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            for (j = 0; j < 4; j++)
                t[j] = (uint8_t)sbc_aes_sbox[t[j]];
        }
        for (j = 0; j < 4; j++)
            a->rk[4 * i + j] = (uint8_t)(a->rk[4 * (i - nk) + j] ^ t[j]);
    }
}

static void sbc_aes_addkey(uint8_t *s, const uint8_t *rk)
{
    int i;
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

static void sbc_aes_encrypt(const SbcAes *a, const uint8_t *in, uint8_t *out)
{
    uint8_t s[16], t[16];
    int r, i, c;
    memcpy(s, in, 16);
    sbc_aes_addkey(s, a->rk);
    for (r = 1; r <= a->nr; r++) {
        for (i = 0; i < 16; i++)
            s[i] = (uint8_t)sbc_aes_sbox[s[i]];
        for (c = 0; c < 4; c++)
            for (i = 0; i < 4; i++)
                t[i + 4 * c] = s[i + 4 * ((c + i) & 3)];
        memcpy(s, t, 16);
        if (r != a->nr) {
            for (c = 0; c < 4; c++) {
                uint8_t *p = s + 4 * c;
                uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                p[0] = (uint8_t)(sbc_aes_mul(a0, 2) ^ sbc_aes_mul(a1, 3) ^ a2 ^ a3);
                p[1] = (uint8_t)(a0 ^ sbc_aes_mul(a1, 2) ^ sbc_aes_mul(a2, 3) ^ a3);
                p[2] = (uint8_t)(a0 ^ a1 ^ sbc_aes_mul(a2, 2) ^ sbc_aes_mul(a3, 3));
                p[3] = (uint8_t)(sbc_aes_mul(a0, 3) ^ a1 ^ a2 ^ sbc_aes_mul(a3, 2));
            }
        }
        sbc_aes_addkey(s, a->rk + 16 * r);
    }
    memcpy(out, s, 16);
}

static void sbc_aes_decrypt(const SbcAes *a, const uint8_t *in, uint8_t *out)
{
    uint8_t s[16], t[16];
    int r, i, c;
    memcpy(s, in, 16);
    sbc_aes_addkey(s, a->rk + 16 * a->nr);
    for (r = a->nr - 1; r >= 0; r--) {
        for (c = 0; c < 4; c++)
            for (i = 0; i < 4; i++)
                t[i + 4 * c] = s[i + 4 * ((c - i + 4) & 3)];
        memcpy(s, t, 16);
        for (i = 0; i < 16; i++)
            s[i] = (uint8_t)sbc_aes_rsbox[s[i]];
        sbc_aes_addkey(s, a->rk + 16 * r);
        if (r != 0) {
            for (c = 0; c < 4; c++) {
                uint8_t *p = s + 4 * c;
                uint8_t a0 = p[0], a1 = p[1], a2 = p[2], a3 = p[3];
                p[0] = (uint8_t)(sbc_aes_mul(a0, 14) ^ sbc_aes_mul(a1, 11) ^
                                 sbc_aes_mul(a2, 13) ^ sbc_aes_mul(a3, 9));
                p[1] = (uint8_t)(sbc_aes_mul(a0, 9) ^ sbc_aes_mul(a1, 14) ^
                                 sbc_aes_mul(a2, 11) ^ sbc_aes_mul(a3, 13));
                p[2] = (uint8_t)(sbc_aes_mul(a0, 13) ^ sbc_aes_mul(a1, 9) ^
                                 sbc_aes_mul(a2, 14) ^ sbc_aes_mul(a3, 11));
                p[3] = (uint8_t)(sbc_aes_mul(a0, 11) ^ sbc_aes_mul(a1, 13) ^
                                 sbc_aes_mul(a2, 9) ^ sbc_aes_mul(a3, 14));
            }
        }
    }
    memcpy(out, s, 16);
}

/* ---------------- Blowfish (32-byte key) ---------------- */

typedef struct {
    uint32_t p[18];
    uint32_t s[4][256];
} SbcBlowfish;

static uint32_t sbc_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | p[3];
}

static void sbc_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t sbc_bf_f(const SbcBlowfish *b, uint32_t x)
{
    return ((b->s[0][x >> 24] + b->s[1][(x >> 16) & 255]) ^
            b->s[2][(x >> 8) & 255]) + b->s[3][x & 255];
}

static void sbc_bf_encrypt(const SbcBlowfish *b, uint32_t *pl, uint32_t *pr)
{
    uint32_t l = *pl, r = *pr;
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t t;
        l ^= b->p[i];
        r ^= sbc_bf_f(b, l);
        t = l;
        l = r;
        r = t;
    }
    {
        uint32_t t = l;
        l = r;
        r = t;
    }
    r ^= b->p[16];
    l ^= b->p[17];
    *pl = l;
    *pr = r;
}

static void sbc_bf_decrypt(const SbcBlowfish *b, uint32_t *pl, uint32_t *pr)
{
    uint32_t l = *pl, r = *pr;
    int i;
    for (i = 17; i >= 2; i--) {
        uint32_t t;
        l ^= b->p[i];
        r ^= sbc_bf_f(b, l);
        t = l;
        l = r;
        r = t;
    }
    {
        uint32_t t = l;
        l = r;
        r = t;
    }
    r ^= b->p[1];
    l ^= b->p[0];
    *pl = l;
    *pr = r;
}

static void sbc_bf_setkey(SbcBlowfish *b, const uint8_t *key, int len)
{
    uint32_t l = 0, r = 0;
    int i, j = 0;
    memcpy(b->p, sbc_bf_p, sizeof(b->p));
    memcpy(b->s[0], sbc_bf_s0, 1024);
    memcpy(b->s[1], sbc_bf_s1, 1024);
    memcpy(b->s[2], sbc_bf_s2, 1024);
    memcpy(b->s[3], sbc_bf_s3, 1024);
    for (i = 0; i < 18; i++) {
        uint32_t w = 0;
        int k;
        for (k = 0; k < 4; k++) {
            w = (w << 8) | key[j];
            j = (j + 1) % len;
        }
        b->p[i] ^= w;
    }
    for (i = 0; i < 18; i += 2) {
        sbc_bf_encrypt(b, &l, &r);
        b->p[i] = l;
        b->p[i + 1] = r;
    }
    for (i = 0; i < 4; i++) {
        int k;
        for (k = 0; k < 256; k += 2) {
            sbc_bf_encrypt(b, &l, &r);
            b->s[i][k] = l;
            b->s[i][k + 1] = r;
        }
    }
}

static void sbc_bf_enc_block(const SbcBlowfish *b, const uint8_t *in,
                             uint8_t *out)
{
    uint32_t l = sbc_be32(in), r = sbc_be32(in + 4);
    sbc_bf_encrypt(b, &l, &r);
    sbc_put_be32(out, l);
    sbc_put_be32(out + 4, r);
}

static void sbc_bf_dec_block(const SbcBlowfish *b, const uint8_t *in,
                             uint8_t *out)
{
    uint32_t l = sbc_be32(in), r = sbc_be32(in + 4);
    sbc_bf_decrypt(b, &l, &r);
    sbc_put_be32(out, l);
    sbc_put_be32(out + 4, r);
}

/* ---------------- CAST-128 (16-byte key, RFC 2144) ---------------- */

typedef struct {
    uint32_t km[16];
    uint8_t kr[16];
} SbcCast;

static uint32_t sbc_cast_f1(uint32_t d)
{
    return ((sbc_cast_s1[d >> 24] ^ sbc_cast_s2[(d >> 16) & 255]) -
            sbc_cast_s3[(d >> 8) & 255]) + sbc_cast_s4[d & 255];
}

static uint32_t sbc_cast_f2(uint32_t d)
{
    return ((sbc_cast_s1[d >> 24] - sbc_cast_s2[(d >> 16) & 255]) +
            sbc_cast_s3[(d >> 8) & 255]) ^ sbc_cast_s4[d & 255];
}

static uint32_t sbc_cast_f3(uint32_t d)
{
    return ((sbc_cast_s1[d >> 24] + sbc_cast_s2[(d >> 16) & 255]) ^
            sbc_cast_s3[(d >> 8) & 255]) - sbc_cast_s4[d & 255];
}

static uint32_t sbc_rotl32(uint32_t v, int n)
{
    n &= 31;
    return n ? (v << n) | (v >> (32 - n)) : v;
}

static uint32_t sbc_be32_at(const uint8_t *p)
{
    return sbc_be32(p);
}

/* z from x (RFC 2144 section 2.4) */
static void sbc_cast_z(uint8_t *z, const uint8_t *x)
{
    uint32_t a;
    a = sbc_be32_at(x) ^ sbc_cast_s5[x[0xd]] ^ sbc_cast_s6[x[0xf]] ^
        sbc_cast_s7[x[0xc]] ^ sbc_cast_s8[x[0xe]] ^ sbc_cast_s7[x[8]];
    sbc_put_be32(z, a);
    a = sbc_be32_at(x + 8) ^ sbc_cast_s5[z[0]] ^ sbc_cast_s6[z[2]] ^
        sbc_cast_s7[z[1]] ^ sbc_cast_s8[z[3]] ^ sbc_cast_s8[x[0xa]];
    sbc_put_be32(z + 4, a);
    a = sbc_be32_at(x + 12) ^ sbc_cast_s5[z[7]] ^ sbc_cast_s6[z[6]] ^
        sbc_cast_s7[z[5]] ^ sbc_cast_s8[z[4]] ^ sbc_cast_s5[x[9]];
    sbc_put_be32(z + 8, a);
    a = sbc_be32_at(x + 4) ^ sbc_cast_s5[z[0xa]] ^ sbc_cast_s6[z[9]] ^
        sbc_cast_s7[z[0xb]] ^ sbc_cast_s8[z[8]] ^ sbc_cast_s6[x[0xb]];
    sbc_put_be32(z + 12, a);
}

/* x from z (same section) */
/*
 * x from z -- the four groups are assigned in order, exactly as the RFC's
 * prose reads: the x4..x7 group already uses the new x0..x3 bytes, the
 * x8..xB group the new x4..x7, and xC..xF the new x8..xB.  Computing all
 * four from the old bytes gives a different schedule (and wrong keys).
 */
static void sbc_cast_x(uint8_t *x, const uint8_t *z)
{
    uint32_t a, b, c, d;
    a = sbc_be32_at(z + 8) ^ sbc_cast_s5[z[5]] ^ sbc_cast_s6[z[7]] ^
        sbc_cast_s7[z[4]] ^ sbc_cast_s8[z[6]] ^ sbc_cast_s7[z[0]];
    sbc_put_be32(x, a);
    b = sbc_be32_at(z) ^ sbc_cast_s5[x[0]] ^ sbc_cast_s6[x[2]] ^
        sbc_cast_s7[x[1]] ^ sbc_cast_s8[x[3]] ^ sbc_cast_s8[z[2]];
    sbc_put_be32(x + 4, b);
    c = sbc_be32_at(z + 4) ^ sbc_cast_s5[x[7]] ^ sbc_cast_s6[x[6]] ^
        sbc_cast_s7[x[5]] ^ sbc_cast_s8[x[4]] ^ sbc_cast_s5[z[1]];
    sbc_put_be32(x + 8, c);
    d = sbc_be32_at(z + 12) ^ sbc_cast_s5[x[0xa]] ^ sbc_cast_s6[x[9]] ^
        sbc_cast_s7[x[0xb]] ^ sbc_cast_s8[x[8]] ^ sbc_cast_s6[z[3]];
    sbc_put_be32(x + 12, d);
}

static void sbc_cast_keys(SbcCast *c, const uint8_t *key)
{
    uint8_t x[16], z[16];
    uint32_t k[32];
    memcpy(x, key, 16);

    sbc_cast_z(z, x);
    k[0] = sbc_cast_s5[z[8]] ^ sbc_cast_s6[z[9]] ^ sbc_cast_s7[z[7]] ^
           sbc_cast_s8[z[6]] ^ sbc_cast_s5[z[2]];
    k[1] = sbc_cast_s5[z[0xa]] ^ sbc_cast_s6[z[0xb]] ^ sbc_cast_s7[z[5]] ^
           sbc_cast_s8[z[4]] ^ sbc_cast_s6[z[6]];
    k[2] = sbc_cast_s5[z[0xc]] ^ sbc_cast_s6[z[0xd]] ^ sbc_cast_s7[z[3]] ^
           sbc_cast_s8[z[2]] ^ sbc_cast_s7[z[9]];
    k[3] = sbc_cast_s5[z[0xe]] ^ sbc_cast_s6[z[0xf]] ^ sbc_cast_s7[z[1]] ^
           sbc_cast_s8[z[0]] ^ sbc_cast_s8[z[0xc]];

    sbc_cast_x(x, z);
    k[4] = sbc_cast_s5[x[3]] ^ sbc_cast_s6[x[2]] ^ sbc_cast_s7[x[0xc]] ^
           sbc_cast_s8[x[0xd]] ^ sbc_cast_s5[x[8]];
    k[5] = sbc_cast_s5[x[1]] ^ sbc_cast_s6[x[0]] ^ sbc_cast_s7[x[0xe]] ^
           sbc_cast_s8[x[0xf]] ^ sbc_cast_s6[x[0xd]];
    k[6] = sbc_cast_s5[x[7]] ^ sbc_cast_s6[x[6]] ^ sbc_cast_s7[x[8]] ^
           sbc_cast_s8[x[9]] ^ sbc_cast_s7[x[3]];
    k[7] = sbc_cast_s5[x[5]] ^ sbc_cast_s6[x[4]] ^ sbc_cast_s7[x[0xa]] ^
           sbc_cast_s8[x[0xb]] ^ sbc_cast_s8[x[7]];

    sbc_cast_z(z, x);
    k[8] = sbc_cast_s5[z[3]] ^ sbc_cast_s6[z[2]] ^ sbc_cast_s7[z[0xc]] ^
           sbc_cast_s8[z[0xd]] ^ sbc_cast_s5[z[9]];
    k[9] = sbc_cast_s5[z[1]] ^ sbc_cast_s6[z[0]] ^ sbc_cast_s7[z[0xe]] ^
           sbc_cast_s8[z[0xf]] ^ sbc_cast_s6[z[0xc]];
    k[10] = sbc_cast_s5[z[7]] ^ sbc_cast_s6[z[6]] ^ sbc_cast_s7[z[8]] ^
            sbc_cast_s8[z[9]] ^ sbc_cast_s7[z[2]];
    k[11] = sbc_cast_s5[z[5]] ^ sbc_cast_s6[z[4]] ^ sbc_cast_s7[z[0xa]] ^
            sbc_cast_s8[z[0xb]] ^ sbc_cast_s8[z[6]];

    sbc_cast_x(x, z);
    k[12] = sbc_cast_s5[x[8]] ^ sbc_cast_s6[x[9]] ^ sbc_cast_s7[x[7]] ^
            sbc_cast_s8[x[6]] ^ sbc_cast_s5[x[3]];
    k[13] = sbc_cast_s5[x[0xa]] ^ sbc_cast_s6[x[0xb]] ^ sbc_cast_s7[x[5]] ^
            sbc_cast_s8[x[4]] ^ sbc_cast_s6[x[7]];
    k[14] = sbc_cast_s5[x[0xc]] ^ sbc_cast_s6[x[0xd]] ^ sbc_cast_s7[x[3]] ^
            sbc_cast_s8[x[2]] ^ sbc_cast_s7[x[8]];
    k[15] = sbc_cast_s5[x[0xe]] ^ sbc_cast_s6[x[0xf]] ^ sbc_cast_s7[x[1]] ^
            sbc_cast_s8[x[0]] ^ sbc_cast_s8[x[0xd]];

    /* the second half repeats the pattern from the current x */
    sbc_cast_z(z, x);
    k[16] = sbc_cast_s5[z[8]] ^ sbc_cast_s6[z[9]] ^ sbc_cast_s7[z[7]] ^
            sbc_cast_s8[z[6]] ^ sbc_cast_s5[z[2]];
    k[17] = sbc_cast_s5[z[0xa]] ^ sbc_cast_s6[z[0xb]] ^ sbc_cast_s7[z[5]] ^
            sbc_cast_s8[z[4]] ^ sbc_cast_s6[z[6]];
    k[18] = sbc_cast_s5[z[0xc]] ^ sbc_cast_s6[z[0xd]] ^ sbc_cast_s7[z[3]] ^
            sbc_cast_s8[z[2]] ^ sbc_cast_s7[z[9]];
    k[19] = sbc_cast_s5[z[0xe]] ^ sbc_cast_s6[z[0xf]] ^ sbc_cast_s7[z[1]] ^
            sbc_cast_s8[z[0]] ^ sbc_cast_s8[z[0xc]];

    sbc_cast_x(x, z);
    k[20] = sbc_cast_s5[x[3]] ^ sbc_cast_s6[x[2]] ^ sbc_cast_s7[x[0xc]] ^
            sbc_cast_s8[x[0xd]] ^ sbc_cast_s5[x[8]];
    k[21] = sbc_cast_s5[x[1]] ^ sbc_cast_s6[x[0]] ^ sbc_cast_s7[x[0xe]] ^
            sbc_cast_s8[x[0xf]] ^ sbc_cast_s6[x[0xd]];
    k[22] = sbc_cast_s5[x[7]] ^ sbc_cast_s6[x[6]] ^ sbc_cast_s7[x[8]] ^
            sbc_cast_s8[x[9]] ^ sbc_cast_s7[x[3]];
    k[23] = sbc_cast_s5[x[5]] ^ sbc_cast_s6[x[4]] ^ sbc_cast_s7[x[0xa]] ^
            sbc_cast_s8[x[0xb]] ^ sbc_cast_s8[x[7]];

    sbc_cast_z(z, x);
    k[24] = sbc_cast_s5[z[3]] ^ sbc_cast_s6[z[2]] ^ sbc_cast_s7[z[0xc]] ^
            sbc_cast_s8[z[0xd]] ^ sbc_cast_s5[z[9]];
    k[25] = sbc_cast_s5[z[1]] ^ sbc_cast_s6[z[0]] ^ sbc_cast_s7[z[0xe]] ^
            sbc_cast_s8[z[0xf]] ^ sbc_cast_s6[z[0xc]];
    k[26] = sbc_cast_s5[z[7]] ^ sbc_cast_s6[z[6]] ^ sbc_cast_s7[z[8]] ^
            sbc_cast_s8[z[9]] ^ sbc_cast_s7[z[2]];
    k[27] = sbc_cast_s5[z[5]] ^ sbc_cast_s6[z[4]] ^ sbc_cast_s7[z[0xa]] ^
            sbc_cast_s8[z[0xb]] ^ sbc_cast_s8[z[6]];

    sbc_cast_x(x, z);
    k[28] = sbc_cast_s5[x[8]] ^ sbc_cast_s6[x[9]] ^ sbc_cast_s7[x[7]] ^
            sbc_cast_s8[x[6]] ^ sbc_cast_s5[x[3]];
    k[29] = sbc_cast_s5[x[0xa]] ^ sbc_cast_s6[x[0xb]] ^ sbc_cast_s7[x[5]] ^
            sbc_cast_s8[x[4]] ^ sbc_cast_s6[x[7]];
    k[30] = sbc_cast_s5[x[0xc]] ^ sbc_cast_s6[x[0xd]] ^ sbc_cast_s7[x[3]] ^
            sbc_cast_s8[x[2]] ^ sbc_cast_s7[x[8]];
    k[31] = sbc_cast_s5[x[0xe]] ^ sbc_cast_s6[x[0xf]] ^ sbc_cast_s7[x[1]] ^
            sbc_cast_s8[x[0]] ^ sbc_cast_s8[x[0xd]];

    for (int i = 0; i < 16; i++) {
        c->km[i] = k[i];
        c->kr[i] = (uint8_t)(k[16 + i] & 31);
    }
}

static void sbc_cast_crypt(const SbcCast *c, const uint8_t *in, uint8_t *out,
                           int decrypt)
{
    uint32_t l = sbc_be32(in), r = sbc_be32(in + 4);
    int i;
    for (i = 0; i < 16; i++) {
        int rnd = decrypt ? 15 - i : i;
        uint32_t t;
        if ((rnd % 3) == 0) {
            uint32_t d = sbc_rotl32(c->km[rnd] + r, c->kr[rnd]);
            t = l ^ sbc_cast_f1(d);
        } else if ((rnd % 3) == 1) {
            uint32_t d = sbc_rotl32(c->km[rnd] ^ r, c->kr[rnd]);
            t = l ^ sbc_cast_f2(d);
        } else {
            uint32_t d = sbc_rotl32(c->km[rnd] - r, c->kr[rnd]);
            t = l ^ sbc_cast_f3(d);
        }
        l = r;
        r = t;
    }
    /* c = R16 || L16 */
    sbc_put_be32(out, r);
    sbc_put_be32(out + 4, l);
}

/* ---------------- DES / triple-DES (FIPS 46-3) ---------------- */

static const uint8_t sbc_des_ip[64] = {
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};
static const uint8_t sbc_des_fp[64] = {
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};
static const uint8_t sbc_des_e[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1};
static const uint8_t sbc_des_p[32] = {
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25};
static const uint8_t sbc_des_pc1[56] = {
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4};
static const uint8_t sbc_des_pc2[48] = {
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32};
static const uint8_t sbc_des_shifts[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
static const uint8_t sbc_des_s[8][64] = {
    {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
    {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
    {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
    {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
    {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
    {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
    {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
    {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};

typedef struct {
    uint64_t k[16]; /* 48-bit round keys in the low bits */
} SbcDes;

static uint64_t sbc_des_perm(uint64_t in, const uint8_t *tab, int n, int inbits)
{
    uint64_t out = 0;
    int i;
    for (i = 0; i < n; i++)
        out = (out << 1) | ((in >> (inbits - tab[i])) & 1);
    return out;
}

static void sbc_des_setkey(SbcDes *d, const uint8_t *key)
{
    uint64_t k = 0, cd;
    uint32_t c, dd;
    int i;
    for (i = 0; i < 8; i++)
        k = (k << 8) | key[i];
    cd = sbc_des_perm(k, sbc_des_pc1, 56, 64);
    c = (uint32_t)(cd >> 28) & 0x0fffffffu;
    dd = (uint32_t)cd & 0x0fffffffu;
    for (i = 0; i < 16; i++) {
        int s = sbc_des_shifts[i];
        c = ((c << s) | (c >> (28 - s))) & 0x0fffffffu;
        dd = ((dd << s) | (dd >> (28 - s))) & 0x0fffffffu;
        d->k[i] = sbc_des_perm(((uint64_t)c << 28) | dd, sbc_des_pc2, 48, 56);
    }
}

static uint32_t sbc_des_f(uint32_t r, uint64_t k)
{
    uint64_t x = sbc_des_perm(r, sbc_des_e, 48, 32) ^ k;
    uint32_t out = 0;
    int i;
    for (i = 0; i < 8; i++) {
        int b = (int)((x >> (42 - 6 * i)) & 0x3f);
        int row = ((b & 0x20) >> 4) | (b & 1);
        int col = (b >> 1) & 0xf;
        out = (out << 4) | sbc_des_s[i][row * 16 + col];
    }
    return (uint32_t)sbc_des_perm(out, sbc_des_p, 32, 32);
}

static void sbc_des_crypt(const SbcDes *d, const uint8_t *in, uint8_t *out,
                          int decrypt)
{
    uint64_t blk = 0;
    uint32_t l, r;
    int i;
    for (i = 0; i < 8; i++)
        blk = (blk << 8) | in[i];
    blk = sbc_des_perm(blk, sbc_des_ip, 64, 64);
    l = (uint32_t)(blk >> 32);
    r = (uint32_t)blk;
    for (i = 0; i < 16; i++) {
        uint32_t t = l ^ sbc_des_f(r, d->k[decrypt ? 15 - i : i]);
        l = r;
        r = t;
    }
    blk = ((uint64_t)r << 32) | l;
    blk = sbc_des_perm(blk, sbc_des_fp, 64, 64);
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)blk;
        blk >>= 8;
    }
}

typedef struct {
    SbcDes k[3];
} SbcDes3;

static void sbc_des3_setkey(SbcDes3 *d, const uint8_t *key)
{
    sbc_des_setkey(&d->k[0], key);
    sbc_des_setkey(&d->k[1], key + 8);
    sbc_des_setkey(&d->k[2], key + 16);
}

static void sbc_des3_crypt(const SbcDes3 *d, const uint8_t *in, uint8_t *out,
                           int decrypt)
{
    uint8_t a[8], b[8];
    if (!decrypt) {
        sbc_des_crypt(&d->k[0], in, a, 0);
        sbc_des_crypt(&d->k[1], a, b, 1);
        sbc_des_crypt(&d->k[2], b, out, 0);
    } else {
        sbc_des_crypt(&d->k[2], in, a, 1);
        sbc_des_crypt(&d->k[1], a, b, 0);
        sbc_des_crypt(&d->k[0], b, out, 1);
    }
}

/* ---------------- cipher object ---------------- */

/*
 * The vendor's cipher objects all share one interface: a native block size
 * (8 for Blowfish/CAST/3DES, 16 for AES/Serpent/Twofish), a 16-byte IV field
 * and ECB `encrypt`/CBC `decrypt` entry points.  `sbc_cipher_*` presents the
 * same thing to the container code below.
 */
typedef struct {
    int id;
    int bs;   /* native block size */
    int klen; /* key length in bytes */
    uint8_t iv[16];
    union {
        SbcAes aes;
        SbcBlowfish bf;
        SbcCast cast;
        SbcDes3 des3;
        SbcSerpent serpent;
        SbcTwofish twofish;
    } u;
} SbcCipher;

static int sbc_cipher_keylen(int id)
{
    if (id == 3)
        return 16;
    if (id == 4)
        return 24;
    return 32;
}

static int sbc_cipher_setkey(SbcCipher *c, int id, const uint8_t *key)
{
    memset(c, 0, sizeof(*c));
    c->id = id;
    c->klen = sbc_cipher_keylen(id);
    switch (id) {
    case 1:
        c->bs = 16;
        sbc_aes_setkey(&c->u.aes, key, c->klen * 8);
        return 0;
    case 2:
        c->bs = 8;
        sbc_bf_setkey(&c->u.bf, key, c->klen);
        return 0;
    case 3:
        c->bs = 8;
        sbc_cast_keys(&c->u.cast, key);
        return 0;
    case 4:
        c->bs = 8;
        sbc_des3_setkey(&c->u.des3, key);
        return 0;
    case 5:
        c->bs = 16;
        return sbc_serpent_setkey(&c->u.serpent, key, c->klen);
    case 6:
        c->bs = 16;
        return sbc_twofish_setkey(&c->u.twofish, key, c->klen);
    default:
        return -1;
    }
}

static void sbc_cipher_enc_block(const SbcCipher *c, const uint8_t *in,
                                 uint8_t *out)
{
    if (c->id == 1)
        sbc_aes_encrypt(&c->u.aes, in, out);
    else if (c->id == 2)
        sbc_bf_enc_block(&c->u.bf, in, out);
    else if (c->id == 3)
        sbc_cast_crypt(&c->u.cast, in, out, 0);
    else if (c->id == 4)
        sbc_des3_crypt(&c->u.des3, in, out, 0);
    else if (c->id == 5)
        sbc_serpent_enc(&c->u.serpent, in, out);
    else
        sbc_twofish_enc(&c->u.twofish, in, out);
}

static void sbc_cipher_dec_block(const SbcCipher *c, const uint8_t *in,
                                 uint8_t *out)
{
    if (c->id == 1)
        sbc_aes_decrypt(&c->u.aes, in, out);
    else if (c->id == 2)
        sbc_bf_dec_block(&c->u.bf, in, out);
    else if (c->id == 3)
        sbc_cast_crypt(&c->u.cast, in, out, 1);
    else if (c->id == 4)
        sbc_des3_crypt(&c->u.des3, in, out, 1);
    else if (c->id == 5)
        sbc_serpent_dec(&c->u.serpent, in, out);
    else
        sbc_twofish_dec(&c->u.twofish, in, out);
}

/* raw ECB over n bytes (n a multiple of the block size), no IV: the vendor's
 * `encrypt` entry point, which check_byte uses */
static void sbc_cipher_ecb_encrypt(const SbcCipher *c, uint8_t *buf, size_t n)
{
    size_t i;
    for (i = 0; i + (size_t)c->bs <= n; i += (size_t)c->bs)
        sbc_cipher_enc_block(c, buf + i, buf + i);
}

/* ---------------- CBC over a whole buffer ---------------- */

static void sbc_cipher_cbc_encrypt(SbcCipher *c, const uint8_t *in,
                                   uint8_t *out, size_t n)
{
    uint8_t tmp[16];
    size_t i;
    int j;
    for (i = 0; i + (size_t)c->bs <= n; i += (size_t)c->bs) {
        for (j = 0; j < c->bs; j++)
            tmp[j] = (uint8_t)(in[i + j] ^ c->iv[j]);
        sbc_cipher_enc_block(c, tmp, out + i);
        memcpy(c->iv, out + i, (size_t)c->bs);
    }
}

static void sbc_cipher_cbc_decrypt(SbcCipher *c, const uint8_t *in,
                                   uint8_t *out, size_t n)
{
    uint8_t tmp[16], prev[16];
    size_t i;
    int j;
    for (i = 0; i + (size_t)c->bs <= n; i += (size_t)c->bs) {
        memcpy(prev, c->iv, (size_t)c->bs);
        sbc_cipher_dec_block(c, in + i, tmp);
        for (j = 0; j < c->bs; j++)
            out[i + j] = (uint8_t)(tmp[j] ^ prev[j]);
        memcpy(c->iv, in + i, (size_t)c->bs);
    }
}

/* ---------------- passphrase KDF (FUN_00402530) ---------------- */

static void sbc_kdf(const uint8_t *pw, size_t pwlen, const uint8_t *salt,
                    uint32_t keylen, uint8_t cid, uint8_t *out)
{
    int alg = keylen <= 20 ? SBC_SHA1 : SBC_SHA256;
    int hlen = keylen <= 20 ? 20 : 32;
    uint8_t buf[767], st[32], ctr[2], d[32];
    uint32_t x, y;
    int it, i;
    SbcHash h;

    if (pwlen == 0)
        return;
    memset(buf, 0, sizeof(buf));
    memset(st, 0, sizeof(st));
    buf[0] = pw[0];
    for (i = 1; i < 767; i++)
        buf[i] = pw[i % pwlen];
    st[0] = cid;
    x = (uint32_t)pwlen;
    y = 0;
    for (it = 0x2000; it > 0; it--) {
        uint32_t sl = (x + y) % 0x11; /* 32-bit sum, as the vendor's `add` */
        uint32_t off = y % 0x180;
        uint32_t len = x % 0x181;
        uint32_t i1, i2;
        uint8_t t;
        sbc_hash_init(&h, alg);
        sbc_hash_upd(&h, alg, salt, sl);
        sbc_hash_upd(&h, alg, st, (size_t)hlen);
        ctr[0] = (uint8_t)((uint32_t)it >> 8);
        ctr[1] = (uint8_t)it;
        sbc_hash_upd(&h, alg, ctr, 2);
        sbc_hash_upd(&h, alg, buf + off, len);
        sbc_hash_final(&h, alg, st);
        x = x * y + st[0];
        y = (y * 2) ^ st[1];
        i1 = y % 767;
        i2 = x % 767;
        t = buf[i1];
        buf[i1] = buf[i2];
        buf[i2] = t;
    }
    sbc_hash_init(&h, alg);
    sbc_hash_upd(&h, alg, salt, 16);
    sbc_hash_upd(&h, alg, st, (size_t)hlen);
    sbc_hash_upd(&h, alg, pw, pwlen);
    sbc_hash_final(&h, alg, d);
    memcpy(out, d, keylen);
}

/* ---------------- check byte (FUN_00401f40) ---------------- */

static uint8_t sbc_check_byte(const uint8_t *pw, size_t pwlen, SbcCipher *c)
{
    uint8_t blk[16], d[20];
    SbcHash h;
    int i;
    memset(blk, 0, sizeof(blk));
    memcpy(blk, pw, pwlen < 16 ? pwlen : 16);
    sbc_hash_init(&h, SBC_SHA1);
    sbc_hash_upd(&h, SBC_SHA1, pw, pwlen);
    for (i = 0; i < 0x2000; i++) {
        sbc_cipher_ecb_encrypt(c, blk, 16);
        sbc_hash_upd(&h, SBC_SHA1, blk, 16);
    }
    sbc_hash_final(&h, SBC_SHA1, d);
    return d[0];
}

/* ---------------- container ---------------- */

static int sbc_crypt_id(const uint8_t *d, size_t n)
{
    if (n < 5 || memcmp(d, "SBC\x1e", 4) != 0)
        return 0;
    if (d[4] <= 'H' || d[4] > 'N')
        return 0;
    return (int)d[4] - 'H';
}

static int sbc_crypt_keylen(int id)
{
    return sbc_cipher_keylen(id);
}

/*
 * Decrypt an encrypted archive.  Returns 0 and a malloc'ed plaintext archive
 * (magic `SBC\x1eH` included) on success, -2 for a cipher we do not
 * implement, -3 for a wrong passphrase and -1 for a malformed container.
 */
static int sbc_crypt_decrypt(const uint8_t *in, size_t n, const char *pw,
                             uint8_t **out, size_t *outn)
{
    int id, klen;
    uint8_t key[32], blk[16], chk;
    SbcCipher c;
    uint8_t *plain;

    *out = NULL;
    *outn = 0;
    id = sbc_crypt_id(in, n);
    if (id == 0)
        return -1;
    if (!pw || !*pw)
        return -3;
    if (n < 5 + 32 || (n - 5 - 32) % 16 != 0)
        return -1;
    klen = sbc_crypt_keylen(id);
    sbc_kdf((const uint8_t *)pw, strlen(pw), in + 5, (uint32_t)klen,
            (uint8_t)id, key);
    if (sbc_cipher_setkey(&c, id, key) != 0) {
        memset(key, 0, sizeof(key));
        return -2;
    }
    chk = sbc_check_byte((const uint8_t *)pw, strlen(pw), &c);
    memcpy(c.iv, in + 5, 16);
    sbc_cipher_cbc_decrypt(&c, in + 21, blk, 16);
    if (blk[15] != chk) {
        memset(key, 0, sizeof(key));
        memset(&c, 0, sizeof(c));
        return -3;
    }
    /* the IV now holds the check block: the body continues from there */
    plain = (uint8_t *)malloc(n - 5 - 32 + 5);
    if (!plain) {
        memset(key, 0, sizeof(key));
        return -1;
    }
    memcpy(plain, "SBC\x1eH", 5);
    sbc_cipher_cbc_decrypt(&c, in + 37, plain + 5, n - 37);
    memset(key, 0, sizeof(key));
    memset(&c, 0, sizeof(c));
    *out = plain;
    *outn = n - 32;
    return 0;
}

static void sbc_crypt_random(uint8_t *buf, size_t n)
{
    FILE *f = fopen("/dev/urandom", "rb");
    size_t got = 0;
    if (f) {
        got = fread(buf, 1, n, f);
        fclose(f);
    }
    while (got < n) {
        /* deterministic fallback, only for systems without /dev/urandom */
        static uint32_t s = 0x9e3779b9u;
        s ^= (uint32_t)time(NULL) + (uint32_t)(size_t)buf;
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        buf[got++] = (uint8_t)s;
    }
}

/*
 * Encrypt a plain archive (magic `SBC\x1eH`, header + payload + trailer) into
 * an encrypted one.  Returns 0 on success.
 */
static int sbc_crypt_encode(const uint8_t *plain, size_t n, int id,
                            const char *pw, uint8_t **out, size_t *outn)
{
    uint8_t key[32], salt[16], chk, blk[16];
    size_t body, padded;
    uint8_t *res;
    SbcCipher c;

    *out = NULL;
    *outn = 0;
    if (id < 1 || id > 6 || !pw || !*pw || n < 5)
        return -1;
    body = n - 5;
    padded = (body + 15) & ~(size_t)15;
    res = (uint8_t *)malloc(5 + 32 + padded);
    if (!res)
        return -1;
    sbc_crypt_random(salt, sizeof(salt));
    sbc_kdf((const uint8_t *)pw, strlen(pw), salt,
            (uint32_t)sbc_crypt_keylen(id), (uint8_t)id, key);
    if (sbc_cipher_setkey(&c, id, key) != 0) {
        free(res);
        memset(key, 0, sizeof(key));
        return -2;
    }
    chk = sbc_check_byte((const uint8_t *)pw, strlen(pw), &c);
    /* P: the check block's plaintext; only its last byte is verified */
    memset(blk, 0, sizeof(blk));
    blk[15] = chk;
    memcpy(res, "SBC\x1e", 4);
    res[4] = (uint8_t)('H' + id);
    memcpy(res + 5, salt, 16);
    memcpy(c.iv, salt, 16);
    sbc_cipher_cbc_encrypt(&c, blk, res + 21, 16); /* B = CBC(P) under IV A */
    {
        uint8_t *tmp = (uint8_t *)calloc(padded ? padded : 1, 1);
        if (!tmp) {
            free(res);
            memset(key, 0, sizeof(key));
            return -1;
        }
        memcpy(tmp, plain + 5, body);
        sbc_cipher_cbc_encrypt(&c, tmp, res + 37, padded);
        free(tmp);
    }
    memset(key, 0, sizeof(key));
    memset(&c, 0, sizeof(c));
    *out = res;
    *outn = 5 + 32 + padded;
    return 0;
}

/* ---------------- known-answer tests ---------------- */

/*
 * One published ECB vector per primitive, so a broken cipher fails without
 * Wine or a vendor archive.  Serpent is the vendor's byte-reversed variant:
 * the LTC vector (key 80 00.., pt 00.., ct A2 23 ..) is fed through the same
 * reversal the container uses, i.e. key and plaintext reversed and the
 * expected ciphertext reversed back.  The 3DES entry reuses the DES key three
 * times, which must reduce to single DES (the standard vector).
 */
static int sbc_crypto_selftest(void)
{
    static const uint8_t aes_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                        0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t aes_pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t aes_ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                       0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                       0x70, 0xb4, 0xc5, 0x5a};
    static const uint8_t des_key[8] = {0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc,
                                       0xdf, 0xf1};
    static const uint8_t des_pt[8] = {0x01, 0x23, 0x45, 0x67,
                                      0x89, 0xab, 0xcd, 0xef};
    static const uint8_t des_ct[8] = {0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a,
                                      0xb4, 0x05};
    static const uint8_t cast_key[16] = {0x01, 0x23, 0x45, 0x67, 0x12, 0x34,
                                         0x56, 0x78, 0x23, 0x45, 0x67, 0x89,
                                         0x34, 0x56, 0x78, 0x9a};
    static const uint8_t cast_pt[8] = {0x01, 0x23, 0x45, 0x67,
                                       0x89, 0xab, 0xcd, 0xef};
    static const uint8_t cast_ct[8] = {0x23, 0x8b, 0x4f, 0xe5, 0x84, 0x7e,
                                       0x44, 0xb2};
    static const uint8_t bf_key[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t bf_pt[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t bf_ct[8] = {0x4e, 0xf9, 0x97, 0x45,
                                     0x61, 0x98, 0xdd, 0x78};
    /* LTC Serpent vector, presented in the container's reversed byte order */
    static const uint8_t sp_key[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0x80};
    static const uint8_t sp_pt[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0};
    static const uint8_t sp_ct[16] = {0xc0, 0x16, 0x56, 0x82, 0xbd, 0x8e,
                                      0xe3, 0x2b, 0x0e, 0x3c, 0x46, 0x88,
                                      0x12, 0xaa, 0x23, 0xa2};
    static const uint8_t tf_key[32] = {0xd4, 0x3b, 0xb7, 0x55, 0x6e, 0xa3,
                                       0x2e, 0x46, 0xf2, 0xa2, 0x82, 0xb7,
                                       0xd4, 0x5b, 0x4e, 0x0d, 0x57, 0xff,
                                       0x73, 0x9d, 0x4d, 0xc9, 0x2c, 0x1b,
                                       0xd7, 0xfc, 0x01, 0x70, 0x0c, 0xc8,
                                       0x21, 0x6f};
    static const uint8_t tf_pt[16] = {0x90, 0xaf, 0xe9, 0x1b, 0xb2, 0x88,
                                      0x54, 0x4f, 0x2c, 0x32, 0xdc, 0x23,
                                      0x9b, 0x26, 0x35, 0xe6};
    static const uint8_t tf_ct[16] = {0x6c, 0xb4, 0x56, 0x1c, 0x40, 0xbf,
                                      0x0a, 0x97, 0x05, 0x93, 0x1c, 0xb6,
                                      0xd4, 0x08, 0xe7, 0xfa};
    uint8_t out[16], k24[24];
    int bad = 0;
    SbcAes aes;
    SbcBlowfish bf;
    SbcCast cast;
    SbcDes des;
    SbcDes3 des3;
    SbcSerpent sp;
    SbcTwofish tf;

    sbc_aes_setkey(&aes, aes_key, 128);
    sbc_aes_encrypt(&aes, aes_pt, out);
    if (memcmp(out, aes_ct, 16) != 0)
        bad |= 1;
    sbc_bf_setkey(&bf, bf_key, 8);
    sbc_bf_enc_block(&bf, bf_pt, out);
    if (memcmp(out, bf_ct, 8) != 0)
        bad |= 2;
    sbc_cast_keys(&cast, cast_key);
    sbc_cast_crypt(&cast, cast_pt, out, 0);
    if (memcmp(out, cast_ct, 8) != 0)
        bad |= 4;
    sbc_des_setkey(&des, des_key);
    sbc_des_crypt(&des, des_pt, out, 0);
    if (memcmp(out, des_ct, 8) != 0)
        bad |= 8;
    memcpy(k24, des_key, 8);
    memcpy(k24 + 8, des_key, 8);
    memcpy(k24 + 16, des_key, 8);
    sbc_des3_setkey(&des3, k24);
    sbc_des3_crypt(&des3, des_pt, out, 0);
    if (memcmp(out, des_ct, 8) != 0)
        bad |= 16;
    if (sbc_serpent_setkey(&sp, sp_key, 32) != 0) {
        bad |= 32;
    } else {
        sbc_serpent_enc(&sp, sp_pt, out);
        if (memcmp(out, sp_ct, 16) != 0)
            bad |= 32;
    }
    if (sbc_twofish_setkey(&tf, tf_key, 32) != 0) {
        bad |= 64;
    } else {
        sbc_twofish_enc(&tf, tf_pt, out);
        if (memcmp(out, tf_ct, 16) != 0)
            bad |= 64;
    }
    return bad;
}

#endif /* SBC_CRYPTO_H */
