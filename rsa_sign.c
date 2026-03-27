/*
 * rsa_sign.c — RSA-4096 / RSA-PSS / SHA-256 signing tool
 *
 * Padding scheme : EMSA-PSS  (RFC 8017 §9.1)
 * Hash           : SHA-256   (hLen = 32)
 * MGF            : MGF1-SHA-256
 * Salt length    : 32 bytes  (= hLen, recommended)
 *
 * Usage:
 *   rsa_sign <private_key.pem> <message_file> [signature_output.bin]
 *
 * To verify with OpenSSL:
 *   openssl dgst -sha256 \
 *       -sigopt rsa_padding_mode:pss \
 *       -sigopt rsa_pss_saltlen:32 \
 *       -verify pub.pem \
 *       -signature signature.bin \
 *       message_file
 *
 * Does NOT use OpenSSL library or any crypto library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>       /* fallback srand(time(NULL)) */
#include "bignum.h"
#include "sha256.h"

/* Windows CSPRNG */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <wincrypt.h>
#endif

/* ======================================================
 * Base64 decoder
 * ====================================================== */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1; /* whitespace, '=', etc. */
}

static size_t base64_decode(const char *in, size_t in_len,
                            uint8_t *out, size_t out_max) {
    size_t out_len = 0;
    uint32_t acc  = 0;
    int      bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        int v = b64_val(in[i]);
        if (v < 0) continue;
        acc   = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (out_len < out_max)
                out[out_len++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return out_len;
}

/* ======================================================
 * Minimal DER/ASN.1 reader
 * ====================================================== */

/* Read DER length field; advance *p; return 0 on error */
static int der_read_len(const uint8_t **p, const uint8_t *end, size_t *out) {
    if (*p >= end) return 0;
    uint8_t b = *(*p)++;
    if (b < 0x80) { *out = b; return 1; }
    int n = b & 0x7F;
    if (n == 0 || n > 4 || *p + n > end) return 0;
    *out = 0;
    for (int i = 0; i < n; i++) *out = (*out << 8) | *(*p)++;
    return 1;
}

/* Read one DER INTEGER; advance *p; return 0 on error */
static int der_read_integer(const uint8_t **p, const uint8_t *end,
                             const uint8_t **val, size_t *vlen) {
    if (*p >= end || **p != 0x02) return 0;
    (*p)++;
    if (!der_read_len(p, end, vlen)) return 0;
    if (*p + *vlen > end) return 0;
    *val = *p;
    *p  += *vlen;
    return 1;
}

/* Skip a DER TLV element entirely; advance *p */
static int der_skip_tlv(const uint8_t **p, const uint8_t *end) {
    if (*p >= end) return 0;
    (*p)++; /* tag */
    size_t len;
    if (!der_read_len(p, end, &len)) return 0;
    if (*p + len > end) return 0;
    *p += len;
    return 1;
}

/*
 * Parse PKCS#1 RSAPrivateKey inner structure and extract n and d.
 * Called after the outer SEQUENCE tag+len have been consumed.
 */
static int parse_pkcs1_inner(const uint8_t *p, const uint8_t *end,
                              bignum_t *n_out, bignum_t *d_out) {
    const uint8_t *val;
    size_t vlen;

    /* version INTEGER (must be 0) */
    if (!der_read_integer(&p, end, &val, &vlen)) return 0;
    if (vlen != 1 || val[0] != 0) return 0;

    /* n INTEGER */
    if (!der_read_integer(&p, end, &val, &vlen)) return 0;
    if (vlen > 0 && val[0] == 0x00) { val++; vlen--; }
    bn_from_bytes(n_out, val, (int)vlen);

    /* e INTEGER (skip) */
    if (!der_read_integer(&p, end, &val, &vlen)) return 0;

    /* d INTEGER */
    if (!der_read_integer(&p, end, &val, &vlen)) return 0;
    if (vlen > 0 && val[0] == 0x00) { val++; vlen--; }
    bn_from_bytes(d_out, val, (int)vlen);

    return 1;
}

/*
 * Parse a DER-encoded private key — handles both:
 *   PKCS#1  "BEGIN RSA PRIVATE KEY"  (tag 0x30, then directly RSAPrivateKey)
 *   PKCS#8  "BEGIN PRIVATE KEY"      (PrivateKeyInfo wrapper)
 *
 * PKCS#8 structure:
 *   SEQUENCE {
 *     INTEGER (version=0)
 *     SEQUENCE { OID rsaEncryption, NULL }   <- AlgorithmIdentifier
 *     OCTET STRING { <PKCS#1 RSAPrivateKey> }
 *   }
 */
static int parse_rsa_private_key(const uint8_t *der, size_t der_len,
                                  bignum_t *n_out, bignum_t *d_out) {
    const uint8_t *p   = der;
    const uint8_t *end = der + der_len;

    if (p >= end || *p != 0x30) return 0;
    p++;
    size_t seq_len;
    if (!der_read_len(&p, end, &seq_len)) return 0;
    const uint8_t *seq_end = p + seq_len;
    if (seq_end > end) return 0;

    /* Peek at the first element to distinguish PKCS#1 from PKCS#8 */
    const uint8_t *peek = p;
    const uint8_t *val;
    size_t vlen;
    if (!der_read_integer(&peek, seq_end, &val, &vlen)) return 0;

    if (vlen == 1 && val[0] == 0) {
        /* Could be PKCS#1 (version=0 then n) or PKCS#8 (version=0 then AlgId) */
        /* In PKCS#8 the next element after version is a SEQUENCE (AlgId), not INTEGER */
        if (peek < seq_end && *peek == 0x30) {
            /* PKCS#8: skip AlgorithmIdentifier SEQUENCE */
            if (!der_skip_tlv(&peek, seq_end)) return 0;
            /* Next must be OCTET STRING containing PKCS#1 DER */
            if (peek >= seq_end || *peek != 0x04) return 0;
            peek++;
            size_t inner_len;
            if (!der_read_len(&peek, seq_end, &inner_len)) return 0;
            /* Recurse into the PKCS#1 inner structure */
            return parse_rsa_private_key(peek, inner_len, n_out, d_out);
        }
        /* PKCS#1: p still points to the start of the sequence body */
        return parse_pkcs1_inner(p, seq_end, n_out, d_out);
    }
    return 0;
}

/* ======================================================
 * PEM reader — supports both PKCS#1 and PKCS#8 private key PEM
 * ====================================================== */

static int read_pem_private_key(const char *path,
                                 uint8_t *der, size_t der_max,
                                 size_t *der_len) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return 0; }

    static char pem_buf[32768];
    size_t pem_len = fread(pem_buf, 1, sizeof(pem_buf) - 1, f);
    fclose(f);
    pem_buf[pem_len] = '\0';

    /* Try PKCS#1 first, then PKCS#8 */
    static const char *hdrs[] = {
        "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",     "-----END PRIVATE KEY-----",
        NULL
    };
    const char *begin = NULL, *finish = NULL;
    for (int i = 0; hdrs[i]; i += 2) {
        begin  = strstr(pem_buf, hdrs[i]);
        finish = strstr(pem_buf, hdrs[i+1]);
        if (begin && finish) {
            begin += strlen(hdrs[i]);
            break;
        }
    }
    if (!begin || !finish) {
        fprintf(stderr, "PEM: no recognized private key header in %s\n", path);
        return 0;
    }
    while (*begin == '\r' || *begin == '\n') begin++;

    *der_len = base64_decode(begin, (size_t)(finish - begin), der, der_max);
    return (*der_len > 0) ? 1 : 0;
}

/* forward declarations (defined in the RSA signing section below) */
static void print_hex(const char *label, const uint8_t *data, int len);

/* ======================================================
 * CSPRNG — OS-provided cryptographically secure random bytes
 * ====================================================== */

static void get_random_bytes(uint8_t *buf, size_t len)
{
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    if (CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        CryptGenRandom(hProv, (DWORD)len, buf);
        CryptReleaseContext(hProv, 0);
    } else {
        /* insecure fallback — should never happen on Windows */
        fprintf(stderr, "WARNING: CryptAcquireContext failed; "
                        "using non-cryptographic fallback\n");
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rand();
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(buf, 1, len, f) != len)
            fprintf(stderr, "WARNING: short read from /dev/urandom\n");
        fclose(f);
    } else {
        fprintf(stderr, "WARNING: /dev/urandom unavailable; "
                        "using non-cryptographic fallback\n");
        srand((unsigned)time(NULL));
        for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)rand();
    }
#endif
}

/* ======================================================
 * MGF1 with SHA-256  (RFC 8017 §B.2.1)
 *
 * Generates mask_len bytes from `seed` of `seed_len` bytes:
 *   T = Hash(seed||0) || Hash(seed||1) || ...
 *   return T[0..mask_len-1]
 * ====================================================== */

static void mgf1_sha256(const uint8_t *seed, size_t seed_len,
                        uint8_t *mask, size_t mask_len)
{
    /* seed is always H (32 bytes) in PSS */
    uint8_t buf[SHA256_DIGEST_LEN + 4];   /* seed || 4-byte counter */
    uint8_t hash[SHA256_DIGEST_LEN];
    uint32_t counter  = 0;
    size_t   produced = 0;

    if (seed_len > SHA256_DIGEST_LEN) seed_len = SHA256_DIGEST_LEN;
    memcpy(buf, seed, seed_len);

    while (produced < mask_len) {
        buf[seed_len]     = (uint8_t)(counter >> 24);
        buf[seed_len + 1] = (uint8_t)(counter >> 16);
        buf[seed_len + 2] = (uint8_t)(counter >>  8);
        buf[seed_len + 3] = (uint8_t)(counter      );

        sha256_compute(buf, seed_len + 4, hash);

        size_t copy = mask_len - produced;
        if (copy > SHA256_DIGEST_LEN) copy = SHA256_DIGEST_LEN;
        memcpy(mask + produced, hash, copy);
        produced += copy;
        counter++;
    }
}

/* ======================================================
 * EMSA-PSS-ENCODE  (RFC 8017 §9.1.1)
 *
 * Hash  : SHA-256  (hLen = 32)
 * MGF   : MGF1-SHA-256
 * sLen  : PSS_SALT_LEN = 32
 *
 * For RSA-4096:
 *   emBits = 4095,  emLen = 512
 *   db_len = emLen - hLen - 1  = 479
 *   ps_len = emLen - sLen - hLen - 2 = 446
 *
 * EM layout (512 bytes):
 *   [ maskedDB (479 B) | H (32 B) | 0xBC (1 B) ]
 *          └── PS (446×0x00) | 0x01 | salt (32 B)  ← before masking
 *
 * Returns 1 on success, 0 on error.
 * ====================================================== */

#define PSS_SALT_LEN SHA256_DIGEST_LEN   /* 32 */

static int pss_encode(const uint8_t msg_hash[SHA256_DIGEST_LEN],
                      int key_bits, uint8_t *em)
{
    const int hLen   = SHA256_DIGEST_LEN;
    const int sLen   = PSS_SALT_LEN;
    const int emBits = key_bits - 1;
    const int emLen  = (emBits + 7) / 8;
    const int db_len = emLen - hLen - 1;
    const int ps_len = emLen - sLen - hLen - 2;

    if (emLen < hLen + sLen + 2) {
        fprintf(stderr, "PSS: key too small for chosen parameters\n");
        return 0;
    }

    /* ---- step 4: random salt ---- */
    uint8_t salt[PSS_SALT_LEN];
    get_random_bytes(salt, sLen);
    print_hex("PSS salt (random)", salt, sLen);

    /* ---- step 5: M' = 0x00^8 || mHash || salt ---- */
    uint8_t mprime[8 + SHA256_DIGEST_LEN + PSS_SALT_LEN];
    memset(mprime, 0, 8);
    memcpy(mprime + 8,        msg_hash, hLen);
    memcpy(mprime + 8 + hLen, salt,     sLen);

    /* ---- step 6: H = Hash(M') ---- */
    uint8_t H[SHA256_DIGEST_LEN];
    sha256_compute(mprime, sizeof(mprime), H);
    print_hex("PSS H = SHA-256(M')", H, hLen);

    /* ---- step 7-8: build DB = PS || 0x01 || salt in em[0..db_len-1] ---- */
    memset(em, 0x00, ps_len);
    em[ps_len] = 0x01;
    memcpy(em + ps_len + 1, salt, sLen);

    /* ---- step 9: dbMask = MGF1(H, db_len) ---- */
    uint8_t *dbMask = (uint8_t *)malloc(db_len);
    if (!dbMask) { fprintf(stderr, "PSS: malloc failed\n"); return 0; }
    mgf1_sha256(H, hLen, dbMask, db_len);

    /* ---- step 10: maskedDB = DB XOR dbMask  (in-place in em) ---- */
    for (int i = 0; i < db_len; i++)
        em[i] ^= dbMask[i];
    free(dbMask);

    /* ---- step 11: clear top (8*emLen - emBits) bits of maskedDB[0] ---- */
    em[0] &= (uint8_t)(0xFF >> (8 * emLen - emBits));

    /* ---- step 12: EM = maskedDB || H || 0xBC ---- */
    memcpy(em + db_len, H, hLen);
    em[emLen - 1] = 0xBC;

    return 1;
}

/* ======================================================
 * RSA signing
 * ====================================================== */

/*
 * Compute the byte length of the modulus (strips leading zero bytes).
 */
static int modulus_byte_len(const bignum_t *n) {
    int top = n->len - 1;
    while (top > 0 && n->words[top] == 0) top--;
    uint32_t w = n->words[top];
    int bits = (top + 1) * 32;
    /* subtract leading zero bits in top word */
    while (!(w & 0x80000000u)) { w <<= 1; bits--; }
    return (bits + 7) / 8;
}

/* Print a byte array as hex, with a label and line breaks every 32 bytes */
static void print_hex(const char *label, const uint8_t *data, int len) {
    printf("\n[%s] (%d bytes):\n", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 32 == 0) printf("\n");
        else if ((i + 1) % 4 == 0) printf(" ");
    }
    if (len % 32 != 0) printf("\n");
}

/* Print a bignum as big-endian hex with a label */
static void print_bn(const char *label, const bignum_t *bn, int byte_len) {
    uint8_t *buf = malloc(byte_len);
    if (!buf) return;
    bn_to_bytes(buf, bn, byte_len);
    print_hex(label, buf, byte_len);
    free(buf);
}

static int rsa_sign(const bignum_t *n, const bignum_t *d,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t *sig, int key_bytes) {
    /* 1. SHA-256(message) */
    uint8_t hash[SHA256_DIGEST_LEN];
    sha256_compute(msg, msg_len, hash);
    print_hex("SHA-256(message)", hash, SHA256_DIGEST_LEN);

    /* 2. EMSA-PSS-ENCODE → EM */
    uint8_t *em = (uint8_t *)malloc(key_bytes);
    if (!em) return 0;
    if (!pss_encode(hash, key_bytes * 8, em)) { free(em); return 0; }
    print_hex("PSS encoded message EM", em, key_bytes);

    /* 3. EM → bignum; must satisfy m < n */
    bignum_t m_bn;
    bn_from_bytes(&m_bn, em, key_bytes);
    free(em);

    if (bn_cmp(&m_bn, n) >= 0) {
        fprintf(stderr, "Encoded message >= modulus\n");
        return 0;
    }

    /* 4. RSA private operation: sig = EM^d mod n */
    bignum_t sig_bn;
    if (bn_mod_exp_mont(&sig_bn, &m_bn, d, n) != 0) {
        fprintf(stderr, "Modular exponentiation failed\n");
        return 0;
    }

    /* 5. Export big-endian fixed-width */
    bn_to_bytes(sig, &sig_bn, key_bytes);
    print_hex("RSA-PSS signature (sig = EM^d mod n)", sig, key_bytes);
    return 1;
}

/* ======================================================
 * main
 * ====================================================== */

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr,
            "Usage: %s <private_key.pem> <message_file> [signature.bin]\n"
            "\n"
            "Verify with OpenSSL:\n"
            "  openssl rsa -in key.pem -pubout -out pub.pem\n"
            "  openssl dgst -sha256 -verify pub.pem -signature signature.bin <message_file>\n",
            argv[0]);
        return 1;
    }

    const char *key_path = argv[1];
    const char *msg_path = argv[2];
    const char *sig_path = (argc >= 4) ? argv[3] : "signature.bin";

    /* --- load private key --- */
    static uint8_t der_buf[16384];
    size_t der_len;
    if (!read_pem_private_key(key_path, der_buf, sizeof(der_buf), &der_len)) {
        fprintf(stderr, "Failed to read PEM key from %s\n", key_path);
        return 1;
    }

    bignum_t n_bn, d_bn;
    if (!parse_rsa_private_key(der_buf, der_len, &n_bn, &d_bn)) {
        fprintf(stderr, "Failed to parse RSAPrivateKey DER\n");
        return 1;
    }

    int key_bytes = modulus_byte_len(&n_bn);
    fprintf(stderr, "Key modulus: %d bits (%d bytes)\n",
            key_bytes * 8, key_bytes);
    print_bn("n (modulus)", &n_bn, key_bytes);
    print_bn("d (private exponent)", &d_bn, key_bytes);

    /* --- load message --- */
    FILE *f = fopen(msg_path, "rb");
    if (!f) { perror(msg_path); return 1; }
    static uint8_t msg_buf[1048576]; /* 1 MB max */
    size_t msg_len = fread(msg_buf, 1, sizeof(msg_buf), f);
    fclose(f);
    printf("msg_buf = %s\n",  msg_buf);
    printf("msg_path = %s\n",  msg_path);
    printf("key_path = %s\n",  key_path);
    printf("sig_path = %s\n",  sig_path);

    /* --- sign --- */
    uint8_t *sig = malloc(key_bytes);
    if (!sig) { fprintf(stderr, "Out of memory\n"); return 1; }

    fprintf(stderr, "Signing %zu bytes with RSA-%d...\n",
            msg_len, key_bytes * 8);

    if (!rsa_sign(&n_bn, &d_bn, msg_buf, msg_len, sig, key_bytes)) {
        fprintf(stderr, "Signing failed\n");
        free(sig);
        return 1;
    }

    /* --- write signature --- */
    f = fopen(sig_path, "wb");
    if (!f) { perror(sig_path); free(sig); return 1; }
    fwrite(sig, 1, key_bytes, f);
    fclose(f);
    free(sig);

    fprintf(stderr, "Signature2 written to %s (%d bytes)\n",
            sig_path, key_bytes);
    return 0;
}
