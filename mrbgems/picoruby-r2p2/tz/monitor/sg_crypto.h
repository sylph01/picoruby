/*
 * sg_crypto.h — monitor-side symmetric crypto: SHA-256 (hardware), HMAC,
 * HKDF, and the RFC 8439 ChaCha20-Poly1305 AEAD construction over the
 * mbedTLS chacha20/poly1305 primitives (no mbedtls md/chachapoly layers —
 * they'd drag in software SHA-256 and heap use we don't want).
 *
 * Host testability: build with SG_CRYPTO_HOST_TEST to swap the hardware
 * SHA-256 for mbedTLS's software one; everything else is identical, so the
 * RFC test vectors exercise the exact code the monitor runs.
 *
 * None of these functions touch Non-secure memory validation — callers
 * (sg_veneers.c) validate NS pointers first. Buffers may point into NS
 * space where the veneer layer decided that is safe (see the TOCTOU notes
 * there).
 */

#ifndef SG_CRYPTO_H
#define SG_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/chacha20.h"
#include "mbedtls/poly1305.h"

#ifdef SG_CRYPTO_HOST_TEST
#include "mbedtls/sha256.h"
typedef mbedtls_sha256_context tz_sha256_t;
#else
#include "pico/sha256.h"
typedef pico_sha256_state_t tz_sha256_t;
#endif

/* ---- SHA-256 (one engine, sequential sessions only) --------------------- */

/* Returns 0 or a negative error (hardware engine busy — cannot happen while
 * veneers are single-caller, but propagated anyway). */
int  tz_sha256_start(tz_sha256_t *s);
void tz_sha256_update(tz_sha256_t *s, const uint8_t *data, size_t len);
void tz_sha256_finish(tz_sha256_t *s, uint8_t out[32]);

/* ---- HMAC-SHA256 --------------------------------------------------------- */

typedef struct {
    tz_sha256_t hash;      /* inner hash while streaming */
    uint8_t     okeypad[64];
} tz_hmac_t;

int  tz_hmac_start(tz_hmac_t *h, const uint8_t *key, size_t key_len);
void tz_hmac_update(tz_hmac_t *h, const uint8_t *data, size_t len);
int  tz_hmac_finish(tz_hmac_t *h, uint8_t mac[32]); /* zeroizes *h */

/* ---- HKDF-SHA256 (RFC 5869) ---------------------------------------------- */

int tz_hkdf_extract(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]);

/* Expand with the info split in two segments (label || info); info may be
 * NULL/0. okm_len <= 255*32. NB: for okm_len > 32 the segments are re-read
 * every 32-byte block — callers passing NS-resident info accept that NS
 * mutating it mid-call only corrupts NS's own derived key. */
int tz_hkdf_expand(const uint8_t prk[32],
                   const uint8_t *label, size_t label_len,
                   const uint8_t *info, size_t info_len,
                   uint8_t *okm, size_t okm_len);

/* ---- ChaCha20-Poly1305 AEAD (RFC 8439) ----------------------------------- */

typedef struct {
    mbedtls_chacha20_context chacha;
    mbedtls_poly1305_context poly;
    uint8_t  nonce[12];
    uint64_t aad_len;
    uint64_t ct_len;
} tz_aead_t;

/* Derives the Poly1305 key (ChaCha20 block 0), starts ChaCha20 at block 1.
 * Call sequence, encrypt:  start, aad*, aad_done, encrypt*, tag, end.
 * Call sequence, decrypt:  start, aad*, aad_done, mac_ct*, tag (compare
 * with tz_ct_neq; on mismatch: end, write NOTHING), begin_decrypt,
 * decrypt*, end. */
int  tz_aead_start(tz_aead_t *c, const uint8_t key[32], const uint8_t nonce[12]);
void tz_aead_aad(tz_aead_t *c, const uint8_t *aad, size_t len);
void tz_aead_aad_done(tz_aead_t *c);
/* Encrypt pt -> ct (may alias) and MAC the ciphertext. */
void tz_aead_encrypt(tz_aead_t *c, const uint8_t *pt, uint8_t *ct, size_t len);
/* Decrypt pass 1: MAC ciphertext without producing plaintext. */
void tz_aead_mac_ct(tz_aead_t *c, const uint8_t *ct, size_t len);
/* Pad AAD/ct to 16, absorb the length block, emit the tag. */
void tz_aead_tag(tz_aead_t *c, uint8_t tag[16]);
/* Decrypt pass 2 (after tag verified): rewind ChaCha20 to block 1 (the key
 * is retained in the context until tz_aead_end)... */
int  tz_aead_begin_decrypt(tz_aead_t *c);
/* ...then stream ct -> pt (may alias). */
void tz_aead_decrypt(tz_aead_t *c, const uint8_t *ct, uint8_t *pt, size_t len);
/* Zeroize contexts. Always call, on every path. */
void tz_aead_end(tz_aead_t *c);

/* Constant-time compare: 0 iff equal. */
int tz_ct_neq(const uint8_t *a, const uint8_t *b, size_t len);

/* Best-effort secure wipe that the compiler may not elide. */
void tz_zeroize(void *p, size_t len);

#endif /* SG_CRYPTO_H */
