/*
 * sbc_hash.h -- MD5, SHA-1 and SHA-256, used by the -hm/-h1/-h2 checksums.
 *
 * The vendor keeps one digest object per archive header and per block, so the
 * implementations are streaming (init/update/final).  All of them share the
 * same 64-byte block buffering; only the compression function and the
 * padding's length encoding differ (MD5 little-endian, SHA big-endian).
 */
#ifndef SBC_HASH_H
#define SBC_HASH_H

#include <stdint.h>
#include <string.h>

enum { SBC_MD5 = 0, SBC_SHA1 = 1, SBC_SHA256 = 2 };

typedef struct {
    uint32_t h[8];
    uint64_t len;   /* bytes fed so far */
    uint32_t nbuf;  /* bytes pending in buf */
    uint8_t buf[64];
} SbcHash;

static uint32_t sbc_hsh_ld32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint32_t sbc_hsh_ld32le(const uint8_t *p)
{
    return ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) | (uint32_t)p[0];
}

static void sbc_hsh_st32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sbc_hsh_st32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t sbc_hsh_rol(uint32_t v, int n)
{
    return (v << n) | (v >> (32 - n));
}

/* ---------------- MD5 ---------------- */

static const uint32_t sbc_md5_k[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u
};

static void sbc_md5_block(SbcHash *c, const uint8_t *p)
{
    static const int s[64] = {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    };
    uint32_t m[16], a, b, d, e;
    int i;

    for (i = 0; i < 16; i++)
        m[i] = sbc_hsh_ld32le(p + i * 4);
    a = c->h[0]; b = c->h[1]; d = c->h[2]; e = c->h[3];
    for (i = 0; i < 64; i++) {
        uint32_t f, g, t;
        if (i < 16) {
            f = (b & d) | (~b & e);
            g = (uint32_t)i;
        } else if (i < 32) {
            f = (e & b) | (~e & d);
            g = (uint32_t)(5 * i + 1) & 15u;
        } else if (i < 48) {
            f = b ^ d ^ e;
            g = (uint32_t)(3 * i + 5) & 15u;
        } else {
            f = d ^ (b | ~e);
            g = (uint32_t)(7 * i) & 15u;
        }
        t = e;
        e = d;
        d = b;
        b = b + sbc_hsh_rol(a + f + sbc_md5_k[i] + m[g], s[i]);
        a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += d; c->h[3] += e;
}

/* ---------------- SHA-1 ---------------- */

static void sbc_sha1_block(SbcHash *c, const uint8_t *p)
{
    uint32_t w[80], A, B, C, D, E, k, t;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = sbc_hsh_ld32(p + i * 4);
    for (i = 16; i < 80; i++)
        w[i] = sbc_hsh_rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    A = c->h[0]; B = c->h[1]; C = c->h[2]; D = c->h[3]; E = c->h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f;
        if (i < 20) {
            f = (B & C) | (~B & D);
            k = 0x5a827999u;
        } else if (i < 40) {
            f = B ^ C ^ D;
            k = 0x6ed9eba1u;
        } else if (i < 60) {
            f = (B & C) | (B & D) | (C & D);
            k = 0x8f1bbcdcu;
        } else {
            f = B ^ C ^ D;
            k = 0xca62c1d6u;
        }
        t = sbc_hsh_rol(A, 5) + f + E + k + w[i];
        E = D;
        D = C;
        C = sbc_hsh_rol(B, 30);
        B = A;
        A = t;
    }
    c->h[0] += A; c->h[1] += B; c->h[2] += C; c->h[3] += D; c->h[4] += E;
}

/* ---------------- SHA-256 ---------------- */

static const uint32_t sbc_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static void sbc_sha256_block(SbcHash *c, const uint8_t *p)
{
    uint32_t w[64], A, B, C, D, E, F, G, H;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = sbc_hsh_ld32(p + i * 4);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = sbc_hsh_rol(w[i - 15], 25) ^ sbc_hsh_rol(w[i - 15], 14) ^
                      (w[i - 15] >> 3);
        uint32_t s1 = sbc_hsh_rol(w[i - 2], 15) ^ sbc_hsh_rol(w[i - 2], 13) ^
                      (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    A = c->h[0]; B = c->h[1]; C = c->h[2]; D = c->h[3];
    E = c->h[4]; F = c->h[5]; G = c->h[6]; H = c->h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = sbc_hsh_rol(E, 26) ^ sbc_hsh_rol(E, 21) ^ sbc_hsh_rol(E, 7);
        uint32_t ch = (E & F) ^ (~E & G);
        uint32_t t1 = H + S1 + ch + sbc_sha256_k[i] + w[i];
        uint32_t S0 = sbc_hsh_rol(A, 30) ^ sbc_hsh_rol(A, 19) ^ sbc_hsh_rol(A, 10);
        uint32_t maj = (A & B) ^ (A & C) ^ (B & C);
        uint32_t t2 = S0 + maj;

        H = G; G = F; F = E; E = D + t1;
        D = C; C = B; B = A; A = t1 + t2;
    }
    c->h[0] += A; c->h[1] += B; c->h[2] += C; c->h[3] += D;
    c->h[4] += E; c->h[5] += F; c->h[6] += G; c->h[7] += H;
}

/* ---------------- generic streaming interface ---------------- */

static uint32_t sbc_hash_size(int alg)
{
    return alg == SBC_MD5 ? 16u : (alg == SBC_SHA1 ? 20u : 32u);
}

static void sbc_hash_init(SbcHash *c, int alg)
{
    memset(c, 0, sizeof(*c));
    if (alg == SBC_MD5) {
        c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u;
        c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u;
    } else if (alg == SBC_SHA1) {
        c->h[0] = 0x67452301u; c->h[1] = 0xefcdab89u;
        c->h[2] = 0x98badcfeu; c->h[3] = 0x10325476u;
        c->h[4] = 0xc3d2e1f0u;
    } else {
        c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u;
        c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
        c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu;
        c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    }
}

static void sbc_hash_block(SbcHash *c, int alg, const uint8_t *p)
{
    if (alg == SBC_MD5)
        sbc_md5_block(c, p);
    else if (alg == SBC_SHA1)
        sbc_sha1_block(c, p);
    else
        sbc_sha256_block(c, p);
}

static void sbc_hash_upd(SbcHash *c, int alg, const uint8_t *p, size_t n)
{
    c->len += (uint64_t)n;
    if (c->nbuf) {
        size_t k = 64 - c->nbuf;
        if (k > n)
            k = n;
        memcpy(c->buf + c->nbuf, p, k);
        c->nbuf += (uint32_t)k;
        p += k;
        n -= k;
        if (c->nbuf < 64)
            return;
        sbc_hash_block(c, alg, c->buf);
        c->nbuf = 0;
    }
    while (n >= 64) {
        sbc_hash_block(c, alg, p);
        p += 64;
        n -= 64;
    }
    if (n) {
        memcpy(c->buf, p, n);
        c->nbuf = (uint32_t)n;
    }
}

/* Writes sbc_hash_size(alg) raw big-endian bytes to out. */
static void sbc_hash_final(SbcHash *c, int alg, uint8_t *out)
{
    uint64_t bits = c->len * 8u;
    uint32_t i, size = sbc_hash_size(alg);

    c->buf[c->nbuf++] = 0x80;
    if (c->nbuf > 56) {
        while (c->nbuf < 64)
            c->buf[c->nbuf++] = 0;
        sbc_hash_block(c, alg, c->buf);
        c->nbuf = 0;
    }
    while (c->nbuf < 56)
        c->buf[c->nbuf++] = 0;
    for (i = 0; i < 8; i++) {
        uint8_t b = (uint8_t)(bits >> (56 - 8 * i));
        if (alg == SBC_MD5)
            c->buf[56 + (7 - i)] = b; /* little-endian length */
        else
            c->buf[56 + i] = b;
    }
    sbc_hash_block(c, alg, c->buf);
    if (alg == SBC_MD5) {
        for (i = 0; i < 4; i++)
            sbc_hsh_st32le(out + i * 4, c->h[i]);
    } else {
        for (i = 0; i < size / 4; i++)
            sbc_hsh_st32(out + i * 4, c->h[i]);
    }
    c->nbuf = 0;
}

#endif
