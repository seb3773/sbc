/*
 * sbc_cipher_extra.h -- Serpent (id 5) and Twofish (id 6).
 *
 * Both block ciphers are derived from LibTomCrypt (Unlicense, public
 * domain): `serpent.c` and `twofish.c`.  The two `*_impl.h` files next to
 * this one are those sources with only the `tomcrypt_private.h` include
 * removed; everything they need (types, ROLc, LOAD32L, the CRYPT_* codes and
 * the `symmetric_key` shape) is supplied here.  `sbc_cipher_*` keeps using
 * its own object layout; the wrappers below adapt the LTC entry points.
 */
#ifndef SBC_CIPHER_EXTRA_H
#define SBC_CIPHER_EXTRA_H

#include <stdint.h>
#include <string.h>

typedef unsigned int ulong32;
typedef unsigned long long ulong64;

#define ROLc(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define RORc(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define LOAD32L(x, y)                                                          \
    do {                                                                       \
        (x) = ((ulong32)((y)[0] & 255)) | ((ulong32)((y)[1] & 255) << 8) |     \
              ((ulong32)((y)[2] & 255) << 16) | ((ulong32)((y)[3] & 255) << 24);\
    } while (0)
#define STORE32L(x, y)                                                         \
    do {                                                                       \
        (y)[3] = (unsigned char)(((x) >> 24) & 255);                           \
        (y)[2] = (unsigned char)(((x) >> 16) & 255);                           \
        (y)[1] = (unsigned char)(((x) >> 8) & 255);                            \
        (y)[0] = (unsigned char)((x) & 255);                                   \
    } while (0)
#define LTC_ARGCHK(x)                                                          \
    do {                                                                       \
        if (!(x))                                                              \
            return CRYPT_INVALID_ARG;                                          \
    } while (0)
#define LTC_UNUSED_PARAM(x) (void)(x)
#define LTC_BYTE(x, n) (((x) >> (8 * (n))) & 255)
#define LTC_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define LTC_FALLTHROUGH ((void)0)

#define CRYPT_OK 0
#define CRYPT_INVALID_ARG -1
#define CRYPT_INVALID_ROUNDS -2
#define CRYPT_INVALID_KEYSIZE -3
#define CRYPT_FAIL_TESTVECTOR -9
#define CRYPT_NOP -11

struct ltc_cipher_descriptor {
    const char *name;
    int id, min_key_length, max_key_length, block_length, default_rounds;
    void *p[20];
};

typedef union {
    struct {
        ulong32 k[140];
    } serpent;
    struct {
        ulong32 K[40];
        ulong32 S[4][256];
        int start;
    } twofish;
} symmetric_key;

int serpent_setup(const unsigned char *, int, int, symmetric_key *);
int serpent_ecb_encrypt(const unsigned char *, unsigned char *,
                        const symmetric_key *);
int serpent_ecb_decrypt(const unsigned char *, unsigned char *,
                        const symmetric_key *);
int serpent_test(void);
void serpent_done(symmetric_key *);
int serpent_keysize(int *);
int twofish_setup(const unsigned char *, int, int, symmetric_key *);
int twofish_ecb_encrypt(const unsigned char *, unsigned char *,
                        const symmetric_key *);
int twofish_ecb_decrypt(const unsigned char *, unsigned char *,
                        const symmetric_key *);
int twofish_test(void);
void twofish_done(symmetric_key *);
int twofish_keysize(int *);

#define LTC_SERPENT
#define LTC_TWOFISH
#include "sbc_cipher_serpent_impl.h"
#include "sbc_cipher_twofish_impl.h"

typedef struct {
    symmetric_key k;
} SbcSerpent;

typedef struct {
    symmetric_key k;
} SbcTwofish;

/*
 * The vendor's Serpent is the byte-reversed variant (TNEPRES): the key and
 * every 16-byte block are fed to the cipher backwards.  Measured on a
 * `-cs` archive: reversing both makes the check byte and the body match.
 */
static int sbc_serpent_setkey(SbcSerpent *s, const uint8_t *key, int klen)
{
    uint8_t rk[32];
    int i;
    for (i = 0; i < klen; i++)
        rk[i] = key[klen - 1 - i];
    return serpent_setup(rk, klen, 32, &s->k);
}

static void sbc_serpent_enc(const SbcSerpent *s, const uint8_t *in,
                            uint8_t *out)
{
    uint8_t a[16], b[16];
    int i;
    for (i = 0; i < 16; i++)
        a[i] = in[15 - i];
    serpent_ecb_encrypt(a, b, &s->k);
    for (i = 0; i < 16; i++)
        out[i] = b[15 - i];
}

static void sbc_serpent_dec(const SbcSerpent *s, const uint8_t *in,
                            uint8_t *out)
{
    uint8_t a[16], b[16];
    int i;
    for (i = 0; i < 16; i++)
        a[i] = in[15 - i];
    serpent_ecb_decrypt(a, b, &s->k);
    for (i = 0; i < 16; i++)
        out[i] = b[15 - i];
}

static int sbc_twofish_setkey(SbcTwofish *s, const uint8_t *key, int klen)
{
    return twofish_setup(key, klen, 0, &s->k);
}

static void sbc_twofish_enc(const SbcTwofish *s, const uint8_t *in,
                            uint8_t *out)
{
    twofish_ecb_encrypt(in, out, &s->k);
}

static void sbc_twofish_dec(const SbcTwofish *s, const uint8_t *in,
                            uint8_t *out)
{
    twofish_ecb_decrypt(in, out, &s->k);
}

#endif /* SBC_CIPHER_EXTRA_H */
