#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_LEN 32

typedef struct {
    uint32_t state[8];
    uint64_t count;        /* total bytes processed */
    uint8_t  buf[64];
    uint32_t buf_len;
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t digest[SHA256_DIGEST_LEN]);

/* One-shot convenience */
void sha256_compute(const uint8_t *data, size_t len, uint8_t digest[SHA256_DIGEST_LEN]);

#endif /* SHA256_H */
