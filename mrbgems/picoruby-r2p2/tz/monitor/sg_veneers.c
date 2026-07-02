/*
 * sg_veneers.c — Secure-side implementations of the r2p2_sg_api.h veneer
 * functions. SKETCH. Compiled with R2P2_TZ_MONITOR defined, so SG_API
 * expands to __attribute__((cmse_nonsecure_entry)) and the linker
 * (-mcmse, --cmse-implib) emits the SG stubs into .gnu.sgstubs.
 *
 * Implemented now:
 *   sg_version, sg_random_bytes, sg_sha256
 * Stubbed (return SG_ERR_NOT_PERMITTED, see TODOs):
 *   keystore, HKDF, ChaCha20-Poly1305, HMAC — pending the mbedTLS
 *   symmetric-slice build (chacha20/poly1305/chachapoly/hkdf from
 *   ${PICO_SDK_PATH}/lib/mbedtls/library, minimal config)
 *   sg_verify_mrb — phase 2 by decision.
 *
 * Every NS pointer is validated with the bootrom's rom_validate_ns_buffer
 * before use (checks the full range against SAU + NS MPU; RCP-boolean
 * hardened). A buffer that fails validation returns SG_ERR_BAD_BUFFER
 * without being touched.
 *
 * Reentrancy: veneers assume a single NS caller (core 0, thread mode).
 * R2P2's cooperative scheduler satisfies this. TODO: once core 1 runs NS
 * (sg_launch_core1_ns), add a busy flag/spinlock at each entry.
 */

#include <string.h>

#include "pico.h"
#include "pico/bootrom.h"
#include "pico/rand.h"
#include "pico/sha256.h"
#include "hardware/rcp.h"

#include "../include/r2p2_sg_api.h"
#include "../include/r2p2_tz_config.h"

#if !defined(R2P2_TZ_MONITOR)
#error sg_veneers.c must be compiled with R2P2_TZ_MONITOR defined
#endif

static bool ns_buffer_ok(const void *addr, size_t len, bool write) {
    if (len == 0) return true;
    uint32_t ok = RCP_MASK_FALSE;
    rom_validate_ns_buffer(addr, (uint32_t)len,
                           write ? RCP_MASK_TRUE : RCP_MASK_FALSE, &ok);
    return ok == RCP_MASK_TRUE;
}

/* ---- lifecycle ---------------------------------------------------------- */

SG_API int sg_version(void) {
    return SG_API_VERSION;
}

/* ---- randomness / hashing ----------------------------------------------- */

/* Secure-side pico_rand: on RP2350 its xoroshiro128** state is continuously
 * reseeded from the TRNG, so per-call TRNG latency is amortized here rather
 * than paid by every NS request. The NS image never touches the TRNG. */
SG_API int sg_random_bytes(uint8_t *out, size_t len) {
    if (!out) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(out, len, true)) return SG_ERR_BAD_BUFFER;
    while (len > 0) {
        uint64_t r = get_rand_64();
        size_t n = MIN(len, sizeof r);
        memcpy(out, &r, n);
        out += n;
        len -= n;
    }
    return SG_OK;
}

/* One-shot hash on the SHA-256 accelerator, no DMA (a DMA channel used here
 * would need Secure SECCFG and claim bookkeeping; CPU feed is plenty for
 * veneer-sized inputs). Input is NS data hashing itself — NS mutating the
 * buffer mid-hash only changes NS's own result, so no TOCTOU copy needed. */
SG_API int sg_sha256(const uint8_t *in, size_t len,
                     uint8_t out[SG_SHA256_DIGEST_LEN]) {
    if (!in || !out) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(in, len, false)) return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(out, SG_SHA256_DIGEST_LEN, true)) return SG_ERR_BAD_BUFFER;

    pico_sha256_state_t state;
    if (pico_sha256_try_start(&state, SHA256_BIG_ENDIAN, false) != PICO_OK) {
        return SG_ERR_NO_RESOURCES;
    }
    pico_sha256_update_blocking(&state, in, len);
    sha256_result_t result;
    pico_sha256_finish(&state, &result);
    memcpy(out, result.bytes, SG_SHA256_DIGEST_LEN);
    return SG_OK;
}

/* ---- keystore / KDF / AEAD / MAC — TODO(keystore + mbedTLS slice) ------- */

SG_API int sg_key_open(uint32_t slot, sg_key_t *out_key) {
    (void)slot; (void)out_key;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_key_close(sg_key_t key) {
    (void)key;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_key_get_policy(sg_key_t key, uint32_t *out_policy) {
    (void)key; (void)out_policy;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_key_derive(sg_key_t parent, const uint8_t *info,
                         size_t info_len, sg_key_t *out_key) {
    (void)parent; (void)info; (void)info_len; (void)out_key;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_key_derive_export(sg_key_t parent, const uint8_t *info,
                                size_t info_len, uint8_t *out, size_t out_len) {
    (void)parent; (void)info; (void)info_len; (void)out; (void)out_len;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_aead_encrypt(sg_key_t key,
                           const uint8_t nonce[SG_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t pt_len,
                           uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)key; (void)nonce; (void)aad; (void)aad_len;
    (void)plaintext; (void)pt_len; (void)out; (void)out_cap; (void)out_len;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_aead_decrypt(sg_key_t key,
                           const uint8_t nonce[SG_AEAD_NONCE_LEN],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)key; (void)nonce; (void)aad; (void)aad_len;
    (void)in; (void)in_len; (void)out; (void)out_cap; (void)out_len;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_hmac_sha256(sg_key_t key, const uint8_t *msg, size_t msg_len,
                          uint8_t mac[SG_SHA256_DIGEST_LEN]) {
    (void)key; (void)msg; (void)msg_len; (void)mac;
    return SG_ERR_NOT_PERMITTED;
}

/* ---- signed bytecode — phase 2 by decision ------------------------------ */

SG_API int sg_verify_mrb(const uint8_t *pkg, size_t pkg_len) {
    (void)pkg; (void)pkg_len;
    return SG_ERR_NOT_PERMITTED;
}
