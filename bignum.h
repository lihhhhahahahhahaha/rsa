#ifndef BIGNUM_H
#define BIGNUM_H

#include <stdint.h>

typedef uint8_t u8;

/*
 * MAX_WORDS must be >= 2*128+4 = 260 for RSA-4096:
 * Montgomery multiply computes a full 2n-word product internally,
 * where n = 128 words for 4096-bit keys.
 */
#define MAX_WORDS 260

typedef struct {
    uint32_t words[MAX_WORDS]; /* little-endian: words[0] is least significant */
    int len;                   /* number of significant words                  */
} bignum_t;

/* ---- basic operations ---- */
void bn_zero(bignum_t *a);
void bn_copy(bignum_t *dst, const bignum_t *src);
int  bn_is_zero(const bignum_t *a);
int  bn_cmp(const bignum_t *a, const bignum_t *b);

void bn_from_bytes(bignum_t *bn, const u8 *bytes, int byte_len);
void bn_to_bytes(u8 *bytes, const bignum_t *bn, int byte_len);

void bn_add(bignum_t *c, const bignum_t *a, const bignum_t *b);
void bn_sub(bignum_t *c, const bignum_t *a, const bignum_t *b);

/* ---- Montgomery operations ---- */
void bn_montgomery_setup(const bignum_t *mod, uint32_t *mp);
void bn_to_montgomery(bignum_t *x_mont, const bignum_t *x,
                      const bignum_t *mod, uint32_t mp);
void bn_from_montgomery(bignum_t *x, const bignum_t *x_mont,
                        const bignum_t *mod, uint32_t mp);
void bn_montgomery_mul(bignum_t *res, const bignum_t *a, const bignum_t *b,
                       const bignum_t *mod, uint32_t mp);
int  bn_mod_exp_mont(bignum_t *c, const bignum_t *a, const bignum_t *e,
                     const bignum_t *m);

#endif /* BIGNUM_H */
