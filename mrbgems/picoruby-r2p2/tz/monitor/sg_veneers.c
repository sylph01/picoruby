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
#include "hardware/flash.h"
#include "hardware/sync.h"

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

/* TODO(real impl): memcpy *req into Secure stack FIRST, then validate the
 * copied pointers with ns_buffer_ok() — never re-read NS struct fields
 * after validation (TOCTOU, ABI rule 5 in the header). */
SG_API int sg_key_derive_export(sg_key_t parent, const sg_derive_export_t *req) {
    (void)parent; (void)req;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_aead_encrypt(sg_aead_op_t *op) {
    (void)op;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_aead_decrypt(sg_aead_op_t *op) {
    (void)op;
    return SG_ERR_NOT_PERMITTED;
}

SG_API int sg_hmac_sha256(sg_key_t key, const uint8_t *msg, size_t msg_len,
                          uint8_t mac[SG_SHA256_DIGEST_LEN]) {
    (void)key; (void)msg; (void)msg_len; (void)mac;
    return SG_ERR_NOT_PERMITTED;
}

/* ---- flash --------------------------------------------------------------- */

/* Mirrors flash.c's flash_flush_cache(): the ROM function ('F','C') is
 * Arm-S-only, hence this veneer. See the header for why NS can't do its
 * own cache maintenance. No parameters, no NS memory touched. */
SG_API int sg_flash_flush_cache(void) {
    rom_flash_flush_cache_fn func =
        (rom_flash_flush_cache_fn) rom_func_lookup_inline(ROM_FUNC_FLASH_FLUSH_CACHE);
    func();
    return SG_OK;
}

/* Is [offset, offset+count) entirely inside the NS filesystem partition?
 * count == 0 is accepted (callers treat it as a no-op, like the SDK). */
static bool fs_range_ok(uint32_t offset, uint32_t count) {
    uint64_t end = (uint64_t)offset + count;
    return offset >= TZ_FS_OFFSET
        && end <= (uint64_t)TZ_FS_OFFSET + TZ_FS_SIZE;
}

/* Erase/program run Secure-side: flash_range_erase/program are RAM-resident
 * (__no_inline_not_in_flash_func) and manage XIP exit/re-enter and the cache
 * flush themselves. We only add interrupt masking so no IRQ handler is
 * fetched from the (temporarily unreadable) flash mid-op. Range is clamped
 * to the NS fs partition; NS can't reach the monitor or NS-code regions. */
SG_API int sg_flash_erase(uint32_t offset, uint32_t count) {
    if (!fs_range_ok(offset, count)) return SG_ERR_BAD_PARAM;
    if ((offset & (FLASH_SECTOR_SIZE - 1)) || (count & (FLASH_SECTOR_SIZE - 1)))
        return SG_ERR_BAD_PARAM;
    if (count == 0) return SG_OK;
    uint32_t save = save_and_disable_interrupts();
    flash_range_erase(offset, count);
    restore_interrupts(save);
    return SG_OK;
}

SG_API int sg_flash_program(uint32_t offset, const uint8_t *data, uint32_t count) {
    if (!fs_range_ok(offset, count)) return SG_ERR_BAD_PARAM;
    if ((offset & (FLASH_PAGE_SIZE - 1)) || (count & (FLASH_PAGE_SIZE - 1)))
        return SG_ERR_BAD_PARAM;
    if (count == 0) return SG_OK;
    if (!ns_buffer_ok(data, count, false)) return SG_ERR_BAD_BUFFER;
    /* NB: data must not point into XIP flash — flash is unreadable during
     * the op (same constraint as the stock SDK; FatFS passes RAM buffers). */
    uint32_t save = save_and_disable_interrupts();
    flash_range_program(offset, data, count);
    restore_interrupts(save);
    return SG_OK;
}

/* ---- signed bytecode — phase 2 by decision ------------------------------ */

SG_API int sg_verify_mrb(const uint8_t *pkg, size_t pkg_len) {
    (void)pkg; (void)pkg_len;
    return SG_ERR_NOT_PERMITTED;
}
