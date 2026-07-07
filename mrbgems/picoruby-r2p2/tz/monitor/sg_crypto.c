/* sg_crypto.c — see sg_crypto.h. */

#include <string.h>

#include "sg_crypto.h"

/* ---- SHA-256 shim -------------------------------------------------------- */

#ifdef SG_CRYPTO_HOST_TEST

int tz_sha256_start(tz_sha256_t *s) {
    mbedtls_sha256_init(s);
    return mbedtls_sha256_starts(s, 0 /* SHA-256, not 224 */);
}

void tz_sha256_update(tz_sha256_t *s, const uint8_t *data, size_t len) {
    mbedtls_sha256_update(s, data, len);
}

void tz_sha256_finish(tz_sha256_t *s, uint8_t out[32]) {
    mbedtls_sha256_finish(s, out);
    mbedtls_sha256_free(s);
}

#else /* hardware engine */

int tz_sha256_start(tz_sha256_t *s) {
    /* No DMA: a channel used here would need Secure SECCFG + claim
     * bookkeeping (same call as sg_sha256 makes). */
    return pico_sha256_try_start(s, SHA256_BIG_ENDIAN, false);
}

void tz_sha256_update(tz_sha256_t *s, const uint8_t *data, size_t len) {
    pico_sha256_update_blocking(s, data, len);
}

void tz_sha256_finish(tz_sha256_t *s, uint8_t out[32]) {
    sha256_result_t result;
    pico_sha256_finish(s, &result);
    memcpy(out, result.bytes, 32);
    tz_zeroize(&result, sizeof result);
}

#endif

/* ---- helpers ------------------------------------------------------------- */

void tz_zeroize(void *p, size_t len) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}

int tz_ct_neq(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t acc = 0;
    for (size_t i = 0; i < len; i++) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc != 0;
}

/* ---- HMAC-SHA256 --------------------------------------------------------- */

int tz_hmac_start(tz_hmac_t *h, const uint8_t *key, size_t key_len) {
    uint8_t kblock[64];
    memset(kblock, 0, sizeof kblock);

    if (key_len > sizeof kblock) {
        tz_sha256_t kh;
        int rc = tz_sha256_start(&kh);
        if (rc) return rc;
        tz_sha256_update(&kh, key, key_len);
        tz_sha256_finish(&kh, kblock);
    } else {
        memcpy(kblock, key, key_len);
    }

    uint8_t ikeypad[64];
    for (int i = 0; i < 64; i++) {
        ikeypad[i]    = kblock[i] ^ 0x36;
        h->okeypad[i] = kblock[i] ^ 0x5c;
    }
    tz_zeroize(kblock, sizeof kblock);

    int rc = tz_sha256_start(&h->hash);
    if (rc == 0) tz_sha256_update(&h->hash, ikeypad, sizeof ikeypad);
    tz_zeroize(ikeypad, sizeof ikeypad);
    return rc;
}

void tz_hmac_update(tz_hmac_t *h, const uint8_t *data, size_t len) {
    tz_sha256_update(&h->hash, data, len);
}

int tz_hmac_finish(tz_hmac_t *h, uint8_t mac[32]) {
    uint8_t inner[32];
    tz_sha256_finish(&h->hash, inner);

    /* Single hardware engine: the outer hash starts only after the inner
     * finished, so sequential sessions are safe. */
    int rc = tz_sha256_start(&h->hash);
    if (rc == 0) {
        tz_sha256_update(&h->hash, h->okeypad, sizeof h->okeypad);
        tz_sha256_update(&h->hash, inner, sizeof inner);
        tz_sha256_finish(&h->hash, mac);
    }
    tz_zeroize(inner, sizeof inner);
    tz_zeroize(h, sizeof *h);
    return rc;
}

/* ---- HKDF-SHA256 --------------------------------------------------------- */

int tz_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    tz_hmac_t h;
    int rc = tz_hmac_start(&h, salt, salt_len);
    if (rc) return rc;
    tz_hmac_update(&h, ikm, ikm_len);
    return tz_hmac_finish(&h, prk);
}

int tz_hkdf_expand(const uint8_t prk[32],
                   const uint8_t *label, size_t label_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len) {
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t counter = 1;

    while (okm_len > 0) {
        tz_hmac_t h;
        int rc = tz_hmac_start(&h, prk, 32);
        if (rc) { tz_zeroize(t, sizeof t); return rc; }
        tz_hmac_update(&h, t, t_len);
        tz_hmac_update(&h, label, label_len);
        if (info_len) tz_hmac_update(&h, info, info_len);
        tz_hmac_update(&h, &counter, 1);
        rc = tz_hmac_finish(&h, t);
        if (rc) { tz_zeroize(t, sizeof t); return rc; }

        size_t n = okm_len < sizeof t ? okm_len : sizeof t;
        memcpy(okm, t, n);
        okm += n;
        okm_len -= n;
        t_len = sizeof t;
        counter++;
    }
    tz_zeroize(t, sizeof t);
    return 0;
}

/* ---- ChaCha20-Poly1305 (RFC 8439 construction) --------------------------- */

int tz_aead_start(tz_aead_t *c, const uint8_t key[32], const uint8_t nonce[12]) {
    mbedtls_chacha20_init(&c->chacha);
    mbedtls_poly1305_init(&c->poly);
    memcpy(c->nonce, nonce, sizeof c->nonce);
    c->aad_len = 0;
    c->ct_len = 0;

    int rc = mbedtls_chacha20_setkey(&c->chacha, key);

    /* Poly1305 one-time key = first 32 bytes of ChaCha20 block 0. */
    uint8_t block0[64];
    memset(block0, 0, sizeof block0);
    if (rc == 0) rc = mbedtls_chacha20_starts(&c->chacha, nonce, 0);
    if (rc == 0) rc = mbedtls_chacha20_update(&c->chacha, sizeof block0,
                                              block0, block0);
    if (rc == 0) rc = mbedtls_poly1305_starts(&c->poly, block0);
    tz_zeroize(block0, sizeof block0);

    /* Payload keystream begins at block 1. */
    if (rc == 0) rc = mbedtls_chacha20_starts(&c->chacha, c->nonce, 1);
    if (rc) tz_aead_end(c);
    return rc;
}

static void poly_pad16(tz_aead_t *c, uint64_t len) {
    static const uint8_t zeros[16] = {0};
    size_t rem = (size_t)(len % 16);
    if (rem) mbedtls_poly1305_update(&c->poly, zeros, 16 - rem);
}

void tz_aead_aad(tz_aead_t *c, const uint8_t *aad, size_t len) {
    if (len == 0) return;
    mbedtls_poly1305_update(&c->poly, aad, len);
    c->aad_len += len;
}

void tz_aead_aad_done(tz_aead_t *c) {
    poly_pad16(c, c->aad_len);
}

void tz_aead_encrypt(tz_aead_t *c, const uint8_t *pt, uint8_t *ct, size_t len) {
    if (len == 0) return;
    mbedtls_chacha20_update(&c->chacha, len, pt, ct);
    mbedtls_poly1305_update(&c->poly, ct, len);
    c->ct_len += len;
}

void tz_aead_mac_ct(tz_aead_t *c, const uint8_t *ct, size_t len) {
    if (len == 0) return;
    mbedtls_poly1305_update(&c->poly, ct, len);
    c->ct_len += len;
}

void tz_aead_tag(tz_aead_t *c, uint8_t tag[16]) {
    poly_pad16(c, c->ct_len);
    uint8_t lens[16];
    for (int i = 0; i < 8; i++) {
        lens[i]     = (uint8_t)(c->aad_len >> (8 * i));
        lens[8 + i] = (uint8_t)(c->ct_len  >> (8 * i));
    }
    mbedtls_poly1305_update(&c->poly, lens, sizeof lens);
    mbedtls_poly1305_finish(&c->poly, tag);
}

int tz_aead_begin_decrypt(tz_aead_t *c) {
    return mbedtls_chacha20_starts(&c->chacha, c->nonce, 1);
}

void tz_aead_decrypt(tz_aead_t *c, const uint8_t *ct, uint8_t *pt, size_t len) {
    if (len == 0) return;
    mbedtls_chacha20_update(&c->chacha, len, ct, pt);
}

void tz_aead_end(tz_aead_t *c) {
    mbedtls_chacha20_free(&c->chacha);
    mbedtls_poly1305_free(&c->poly);
    tz_zeroize(c, sizeof *c);
}
