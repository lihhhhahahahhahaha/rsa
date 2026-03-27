
#include "bignum.h"
#include <string.h>
#include <stdio.h>

#define EINVAL 22

/* ======================================================
 * Basic operations
 * ====================================================== */

void bn_zero(bignum_t *a) {
    memset(a->words, 0, sizeof(a->words));
    a->len = 1;
}

void bn_copy(bignum_t *dst, const bignum_t *src) {
    memcpy(dst->words, src->words, sizeof(src->words));
    dst->len = src->len;
}

int bn_is_zero(const bignum_t *a) {
    for (int i = 0; i < a->len; i++)
        if (a->words[i]) return 0;
    return 1;
}

int bn_cmp(const bignum_t *a, const bignum_t *b) {
    int len = a->len > b->len ? a->len : b->len;
    for (int i = len - 1; i >= 0; i--) {
        uint32_t wa = (i < a->len) ? a->words[i] : 0;
        uint32_t wb = (i < b->len) ? b->words[i] : 0;
        if (wa < wb) return -1;
        if (wa > wb) return  1;
    }
    return 0;
}

/* Import from big-endian byte array (e.g. DER INTEGER value) */
void bn_from_bytes(bignum_t *bn, const u8 *bytes, int byte_len) {
    bn_zero(bn);
    int word_idx = 0;
    uint32_t word = 0;
    int shift = 0;
    for (int i = byte_len - 1; i >= 0; i--) {
        word |= ((uint32_t)bytes[i]) << shift;
        shift += 8;
        if (shift == 32) {
            if (word_idx < MAX_WORDS) bn->words[word_idx] = word;
            word_idx++;
            word = 0;
            shift = 0;
        }
    }
    if (shift > 0 && word_idx < MAX_WORDS) {
        bn->words[word_idx++] = word;
    }
    bn->len = word_idx < MAX_WORDS ? word_idx : MAX_WORDS;
    while (bn->len > 1 && bn->words[bn->len - 1] == 0)
        bn->len--;
}

/* Export to big-endian byte array of exactly byte_len bytes */
void bn_to_bytes(u8 *bytes, const bignum_t *bn, int byte_len) {
    memset(bytes, 0, byte_len);
    int written = 0;
    for (int i = 0; i < bn->len && written < byte_len; i++) {
        uint32_t w = bn->words[i];
        for (int j = 0; j < 4 && written < byte_len; j++) {
            bytes[byte_len - 1 - written] = (u8)(w & 0xFF);
            w >>= 8;
            written++;
        }
    }
}

void bn_add(bignum_t *c, const bignum_t *a, const bignum_t *b) {
    uint64_t carry = 0;
    int max_len = a->len > b->len ? a->len : b->len;
    int i;
    for (i = 0; i < max_len || carry; i++) {
        if (i >= MAX_WORDS) break;
        uint64_t sum = carry;
        if (i < a->len) sum += a->words[i];
        if (i < b->len) sum += b->words[i];
        c->words[i] = (uint32_t)sum;
        carry = sum >> 32;
    }
    c->len = i > MAX_WORDS ? MAX_WORDS : i;
    if (c->len == 0) c->len = 1;
}

void bn_sub(bignum_t *c, const bignum_t *a, const bignum_t *b) {
    int64_t borrow = 0;
    for (int i = 0; i < a->len; i++) {
        int64_t diff = (int64_t)a->words[i] - borrow;
        if (i < b->len) diff -= b->words[i];
        if (diff < 0) {
            c->words[i] = (uint32_t)(diff + (1ULL << 32));
            borrow = 1;
        } else {
            c->words[i] = (uint32_t)diff;
            borrow = 0;
        }
    }
    c->len = a->len;
    while (c->len > 1 && c->words[c->len - 1] == 0)
        c->len--;
}

/* ======================================================
 * Montgomery operations
 * ====================================================== */

/*
 * Compute mp = -m[0]^{-1} mod 2^32.
 *
 * Uses Newton's method: starting from y=1 (which satisfies m[0]*1 ≡ 1 mod 2),
 * iterate y = y*(2 - m[0]*y) to double the precision each step.
 * 5 iterations give full 32-bit precision.
 */
void bn_montgomery_setup(const bignum_t *mod, uint32_t *mp) {
    uint32_t x = mod->words[0]; /* must be odd */
    uint32_t y = 1;             /* accurate mod 2 */
    y *= 2 - x * y;             /* accurate mod 4 */
    y *= 2 - x * y;             /* accurate mod 16 */
    y *= 2 - x * y;             /* accurate mod 256 */
    y *= 2 - x * y;             /* accurate mod 65536 */
    y *= 2 - x * y;             /* accurate mod 2^32 */
    /* now x * y ≡ 1 mod 2^32, so mp = -y = -(m^{-1}) mod 2^32 */
    *mp = (uint32_t)(0u - y);
}

/*
 * Montgomery reduction: given T (up to 2n words), compute T * R^{-1} mod m,
 * where R = 2^(32*n) and n = m->len.
 *
 * Algorithm (HAC 14.32):
 *   for i = 0 to n-1:
 *     u_i = T[i] * mp mod 2^32
 *     T += u_i * m * 2^{32*i}
 *   T = T / R   (right-shift n words)
 *   if T >= m: T -= m
 */
static void bn_montgomery_reduce(bignum_t *res, const bignum_t *T,
                                  const bignum_t *mod, uint32_t mp) {
    bignum_t tmp;
    bn_copy(&tmp, T);
    /* ensure the buffer covers at least 2n+1 words */
    int n = mod->len;
    if (tmp.len < 2 * n + 1) {
        for (int i = tmp.len; i < 2 * n + 1 && i < MAX_WORDS; i++)
            tmp.words[i] = 0;
        tmp.len = 2 * n + 1;
    }

    for (int i = 0; i < n; i++) {
        uint32_t u = tmp.words[i] * mp;
        uint32_t carry = 0;
        for (int j = 0; j < n; j++) {
            if (i + j >= MAX_WORDS) break;
            uint64_t sum = (uint64_t)tmp.words[i + j]
                         + (uint64_t)u * mod->words[j]
                         + carry;
            tmp.words[i + j] = (uint32_t)sum;
            carry = (uint32_t)(sum >> 32);
        }
        /* propagate remaining carry */
        for (int j = n; carry; j++) {
            if (i + j >= MAX_WORDS) break;
            uint64_t sum = (uint64_t)tmp.words[i + j] + carry;
            tmp.words[i + j] = (uint32_t)sum;
            carry = (uint32_t)(sum >> 32);
        }
    }

    /* right-shift n words (divide by R) */
    int rem = MAX_WORDS - n;
    memmove(tmp.words, &tmp.words[n], rem * sizeof(uint32_t));
    memset(&tmp.words[rem], 0, n * sizeof(uint32_t));

    /* set length: result fits in n+1 words */
    tmp.len = n + 1;
    while (tmp.len > 1 && tmp.words[tmp.len - 1] == 0)
        tmp.len--;

    /* conditional final subtraction */
    if (bn_cmp(&tmp, mod) >= 0) {
        bignum_t sub;
        bn_sub(&sub, &tmp, mod);
        bn_copy(&tmp, &sub);
    }

    bn_copy(res, &tmp);
}

/*
 * Convert x to Montgomery domain: x_mont = x * R mod m
 *
 * Computes x * R mod m by repeated doubling:
 *   after k doublings, T = 2^k * x mod m
 *   after 32*n doublings, T = 2^{32n} * x mod m = R * x mod m
 *
 * This is O(n^2) but correct and fast enough (called only ~2 times per
 * modular exponentiation).  The naive approach (lshift + reduce_slow)
 * would require up to 2^{4096} subtractions — completely infeasible.
 */
void bn_to_montgomery(bignum_t *x_mont, const bignum_t *x,
                      const bignum_t *mod, uint32_t mp) {
    (void)mp;
    bignum_t T;
    bn_copy(&T, x);

    int n = mod->len;
    for (int i = 0; i < 32 * n; i++) {
        /* T = 2 * T */
        bignum_t tmp;
        bn_add(&tmp, &T, &T);
        bn_copy(&T, &tmp);
        /* if T >= mod: T -= mod */
        if (bn_cmp(&T, mod) >= 0) {
            bignum_t sub;
            bn_sub(&sub, &T, mod);
            bn_copy(&T, &sub);
        }
    }
    bn_copy(x_mont, &T);
}

/*
 * Convert back from Montgomery domain: x = x_mont * R^{-1} mod m
 */
void bn_from_montgomery(bignum_t *x, const bignum_t *x_mont,
                        const bignum_t *mod, uint32_t mp) {
    bn_montgomery_reduce(x, x_mont, mod, mp);
}

/*
 * Montgomery multiplication: res = a * b * R^{-1} mod m
 *
 * Computes T = a * b (full 2n-word product), then applies Montgomery
 * reduction to obtain a * b * R^{-1} mod m.
 */
void bn_montgomery_mul(bignum_t *res, const bignum_t *a, const bignum_t *b,
                       const bignum_t *mod, uint32_t mp) {
    int n = mod->len;
    bignum_t T;
    bn_zero(&T);

    for (int i = 0; i < n; i++) {
        uint32_t ai = (i < a->len) ? a->words[i] : 0;
        uint32_t carry = 0;
        for (int j = 0; j < n; j++) {
            if (i + j >= MAX_WORDS) break;
            uint32_t bj = (j < b->len) ? b->words[j] : 0;
            uint64_t prod = (uint64_t)ai * bj + T.words[i + j] + carry;
            T.words[i + j] = (uint32_t)prod;
            carry = (uint32_t)(prod >> 32);
        }
        /* propagate carry */
        for (int j = n; carry; j++) {
            if (i + j >= MAX_WORDS) break;
            uint64_t sum = (uint64_t)T.words[i + j] + carry;
            T.words[i + j] = (uint32_t)sum;
            carry = (uint32_t)(sum >> 32);
        }
    }

    /* product occupies at most 2n words */
    T.len = 2 * n;
    if (T.len > MAX_WORDS) T.len = MAX_WORDS;
    while (T.len > 1 && T.words[T.len - 1] == 0)
        T.len--;

    bn_montgomery_reduce(res, &T, mod, mp);
}

/*
 * Modular exponentiation using Montgomery multiplication: c = a^e mod m
 *
 * Requirement: m must be odd (true for all RSA moduli).
 * a must be in [0, m).
 */
int bn_mod_exp_mont(bignum_t *c, const bignum_t *a, const bignum_t *e,
                    const bignum_t *m) {
    if (bn_is_zero(m) || (m->words[0] & 1) == 0)
        return -EINVAL;
    if (bn_cmp(a, m) >= 0)
        return -EINVAL;

    uint32_t mp;
    bn_montgomery_setup(m, &mp);

    /* Convert a to Montgomery domain: a_mont = a * R mod m */
    bignum_t a_mont;
    bn_to_montgomery(&a_mont, a, m, mp);

    /* result_mont = 1 * R mod m (Montgomery representation of 1) */
    bignum_t one, result_mont;
    bn_zero(&one);
    one.words[0] = 1;
    one.len = 1;
    bn_to_montgomery(&result_mont, &one, m, mp);

    /* base_mont starts as a_mont */
    bignum_t base_mont;
    bn_copy(&base_mont, &a_mont);

    /* Right-to-left binary exponentiation */
    for (int i = 0; i < e->len; i++) {
        uint32_t word = e->words[i];
        for (int j = 0; j < 32; j++) {
            if (word & (1U << j)) {
                bignum_t temp;
                bn_montgomery_mul(&temp, &result_mont, &base_mont, m, mp);
                bn_copy(&result_mont, &temp);
            }
            /* Always square base (skip the last unnecessary square) */
            if (i < e->len - 1 || j < 31) {
                bignum_t temp;
                bn_montgomery_mul(&temp, &base_mont, &base_mont, m, mp);
                bn_copy(&base_mont, &temp);
            }
        }
    }

    /* Convert result back from Montgomery domain */
    bn_from_montgomery(c, &result_mont, m, mp);
    return 0;
}
