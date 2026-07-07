/*
 * sg_veneers.c — Secure-side implementations of the r2p2_sg_api.h veneer
 * functions. SKETCH. Compiled with R2P2_TZ_MONITOR defined, so SG_API
 * expands to __attribute__((cmse_nonsecure_entry)) and the linker
 * (-mcmse, --cmse-implib) emits the SG stubs into .gnu.sgstubs.
 *
 * NS data buffers (AEAD in/out, hash/MAC input, HKDF info) are deliberately
 * read/written in place after validation: during a veneer call NS code is
 * suspended on this core, and the only way NS can race us is with its own
 * bus masters against its own buffers — which corrupts NS's own message,
 * never key material. Request STRUCTS, headers, nonces, and signatures are
 * different: fields participate in OUR control flow and checks, so they are
 * snapshotted into Secure stack before validation/use (TOCTOU rule, ABI
 * rule 5 in the header).
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
#include "../include/r2p2_mrb_envelope.h"
#include "keystore.h"
#include "sg_crypto.h"
#include "mrb_pubkey.h"
#include "vendor/micro-ecc/uECC.h"

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

/* ---- keystore / KDF ------------------------------------------------------ */

SG_API int sg_key_open(uint32_t slot, sg_key_t *out_key) {
    if (!out_key) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(out_key, sizeof *out_key, true)) return SG_ERR_BAD_BUFFER;
    sg_key_t k;
    int rc = ks_open(slot, &k);
    if (rc == SG_OK) *out_key = k;
    return rc;
}

SG_API int sg_key_close(sg_key_t key) {
    return ks_close(key);
}

SG_API int sg_key_get_policy(sg_key_t key, uint32_t *out_policy) {
    if (!out_policy) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(out_policy, sizeof *out_policy, true))
        return SG_ERR_BAD_BUFFER;
    uint32_t policy;
    int rc = ks_policy(key, &policy);
    if (rc == SG_OK) *out_policy = policy;
    return rc;
}

SG_API int sg_key_derive(sg_key_t parent, const uint8_t *info,
                         size_t info_len, sg_key_t *out_key) {
    if (!out_key || (info_len && !info)) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(info, info_len, false)) return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(out_key, sizeof *out_key, true)) return SG_ERR_BAD_BUFFER;
    sg_key_t k;
    int rc = ks_derive(parent, info, info_len, &k);
    if (rc == SG_OK) *out_key = k;
    return rc;
}

SG_API int sg_key_derive_export(sg_key_t parent, const sg_derive_export_t *req) {
    if (!req) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(req, sizeof *req, false)) return SG_ERR_BAD_BUFFER;
    /* TOCTOU rule: snapshot the request, then validate and use only the
     * copy — NS can rewrite its struct mid-call. */
    sg_derive_export_t r;
    memcpy(&r, req, sizeof r);
    if (!r.out || r.out_len == 0 || r.out_len > 64) return SG_ERR_BAD_PARAM;
    if (r.info_len && !r.info) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(r.info, r.info_len, false)) return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(r.out, r.out_len, true)) return SG_ERR_BAD_BUFFER;

    const uint8_t *parent_key;
    int rc = ks_key_acquire(parent, SG_KEY_POLICY_EXPORT_DERIVED, &parent_key);
    if (rc) return rc;

    /* The tier-2 knob: what leaves the boundary is HKDF output — NS
     * compromise reveals this session key, never the parent. */
    static const char label[] = "R2P2-TZ-export-v1";
    return tz_hkdf_expand(parent_key, (const uint8_t *)label, strlen(label),
                          r.info, r.info_len, r.out, r.out_len)
               ? SG_ERR_INTERNAL : SG_OK;
}

/* ---- AEAD / MAC ----------------------------------------------------------- */

/* Snapshot + validate everything except the out length (op-specific).
 * The struct itself is validated writable: out_len is written back. */
static int aead_snapshot(sg_aead_op_t *ns_op, sg_aead_op_t *op) {
    if (!ns_op) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(ns_op, sizeof *ns_op, true)) return SG_ERR_BAD_BUFFER;
    memcpy(op, ns_op, sizeof *op);
    if (!op->nonce || !op->out) return SG_ERR_BAD_PARAM;
    if (op->aad_len && !op->aad) return SG_ERR_BAD_PARAM;
    if (op->in_len && !op->in) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(op->nonce, SG_AEAD_NONCE_LEN, false))
        return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(op->aad, op->aad_len, false)) return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(op->in, op->in_len, false)) return SG_ERR_BAD_BUFFER;
    return SG_OK;
}

SG_API int sg_aead_encrypt(sg_aead_op_t *ns_op) {
    sg_aead_op_t op;
    int rc = aead_snapshot(ns_op, &op);
    if (rc) return rc;
    size_t need = op.in_len + SG_AEAD_TAG_LEN;
    if (need < op.in_len || op.out_cap < need) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(op.out, need, true)) return SG_ERR_BAD_BUFFER;

    const uint8_t *key;
    rc = ks_key_acquire(op.key, SG_KEY_POLICY_ENCRYPT, &key);
    if (rc) return rc;

    uint8_t nonce[SG_AEAD_NONCE_LEN];
    memcpy(nonce, op.nonce, sizeof nonce);

    tz_aead_t c;
    if (tz_aead_start(&c, key, nonce)) return SG_ERR_INTERNAL;
    tz_aead_aad(&c, op.aad, op.aad_len);
    tz_aead_aad_done(&c);
    tz_aead_encrypt(&c, op.in, op.out, op.in_len);
    uint8_t tag[SG_AEAD_TAG_LEN];
    tz_aead_tag(&c, tag);
    tz_aead_end(&c);
    memcpy(op.out + op.in_len, tag, sizeof tag);

    ns_op->out_len = need;
    return SG_OK;
}

SG_API int sg_aead_decrypt(sg_aead_op_t *ns_op) {
    sg_aead_op_t op;
    int rc = aead_snapshot(ns_op, &op);
    if (rc) return rc;
    if (op.in_len < SG_AEAD_TAG_LEN) return SG_ERR_BAD_PARAM;
    size_t ct_len = op.in_len - SG_AEAD_TAG_LEN;
    if (op.out_cap < ct_len) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(op.out, ct_len, true)) return SG_ERR_BAD_BUFFER;

    const uint8_t *key;
    rc = ks_key_acquire(op.key, SG_KEY_POLICY_DECRYPT, &key);
    if (rc) return rc;

    uint8_t nonce[SG_AEAD_NONCE_LEN];
    memcpy(nonce, op.nonce, sizeof nonce);

    /* Pass 1: MAC the ciphertext only — no plaintext exists anywhere until
     * the tag has been checked, so a mismatch writes NOTHING to NS. */
    tz_aead_t c;
    if (tz_aead_start(&c, key, nonce)) return SG_ERR_INTERNAL;
    tz_aead_aad(&c, op.aad, op.aad_len);
    tz_aead_aad_done(&c);
    tz_aead_mac_ct(&c, op.in, ct_len);
    uint8_t tag[SG_AEAD_TAG_LEN], ns_tag[SG_AEAD_TAG_LEN];
    tz_aead_tag(&c, tag);
    memcpy(ns_tag, op.in + ct_len, sizeof ns_tag);
    if (tz_ct_neq(tag, ns_tag, sizeof tag)) {
        tz_aead_end(&c);
        return SG_ERR_AUTH_FAILED;
    }

    /* Pass 2 re-reads the NS ciphertext. An NS bus master mutating it
     * between the passes gets garbage plaintext in its own buffer — the
     * no-write-on-mismatch guarantee is about the check above. */
    if (tz_aead_begin_decrypt(&c)) { tz_aead_end(&c); return SG_ERR_INTERNAL; }
    tz_aead_decrypt(&c, op.in, op.out, ct_len);
    tz_aead_end(&c);

    ns_op->out_len = ct_len;
    return SG_OK;
}

SG_API int sg_hmac_sha256(sg_key_t key, const uint8_t *msg, size_t msg_len,
                          uint8_t mac[SG_SHA256_DIGEST_LEN]) {
    if (!mac || (msg_len && !msg)) return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(msg, msg_len, false)) return SG_ERR_BAD_BUFFER;
    if (!ns_buffer_ok(mac, SG_SHA256_DIGEST_LEN, true)) return SG_ERR_BAD_BUFFER;

    const uint8_t *k;
    int rc = ks_key_acquire(key, SG_KEY_POLICY_HMAC, &k);
    if (rc) return rc;

    tz_hmac_t h;
    if (tz_hmac_start(&h, k, 32)) return SG_ERR_NO_RESOURCES;
    tz_hmac_update(&h, msg, msg_len);
    uint8_t out[SG_SHA256_DIGEST_LEN];
    if (tz_hmac_finish(&h, out)) return SG_ERR_INTERNAL;
    memcpy(mac, out, sizeof out);
    return SG_OK;
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

/* ---- signed bytecode ------------------------------------------------------ */

/* Verify an r2p2_mrb_envelope.h package: ECDSA P-256 (micro-ecc, verify
 * only — all inputs public, so the non-hardened path is fine) over
 * SHA-256(domain || header || payload), plus the OTP anti-rollback check.
 * Success latches ks_set_mrb_verified(), which is what opens
 * SG_SLOT_GATEWAY_PSK.
 *
 * Honest scope (an explicit phase-1 decision — keep this note): this
 * attests the buffer contents at call time. NS owns the buffer and the VM
 * that will execute it; it is a policy gate, not an NS-integrity
 * guarantee. The boundary protects keys, not NS control flow. */
SG_API int sg_verify_mrb(const uint8_t *pkg, size_t pkg_len) {
    if (!pkg) return SG_ERR_BAD_PARAM;
    if (pkg_len < sizeof(r2p2_mrb_env_hdr_t) + R2P2_MRB_SIG_LEN)
        return SG_ERR_BAD_PARAM;
    if (!ns_buffer_ok(pkg, pkg_len, false)) return SG_ERR_BAD_BUFFER;

    /* Header and signature participate in our checks: snapshot them
     * (TOCTOU). The payload is hashed straight from NS — mutation mid-hash
     * can only produce a digest no genuine signature covers. */
    r2p2_mrb_env_hdr_t hdr;
    memcpy(&hdr, pkg, sizeof hdr);
    if (hdr.magic != R2P2_MRB_ENV_MAGIC ||
        hdr.fmt != R2P2_MRB_ENV_FMT ||
        hdr.scheme != R2P2_MRB_SCHEME_ECDSA_P256_SHA256 ||
        hdr.header_len != sizeof hdr ||
        hdr.payload_len != pkg_len - sizeof hdr - R2P2_MRB_SIG_LEN) {
        return SG_ERR_BAD_PARAM;
    }
    /* Cap before checking: a package claiming a version above the counter's
     * capacity could otherwise exhaust it and brick all future updates. */
    if (hdr.rollback > ks_rollback_capacity()) return SG_ERR_BAD_PARAM;
    if (hdr.rollback < ks_rollback_read()) return SG_ERR_NOT_PERMITTED;

    uint8_t sig[R2P2_MRB_SIG_LEN];
    memcpy(sig, pkg + pkg_len - sizeof sig, sizeof sig);

    static const uint8_t domain[R2P2_MRB_SIG_DOMAIN_LEN] = R2P2_MRB_SIG_DOMAIN;
    tz_sha256_t s;
    if (tz_sha256_start(&s)) return SG_ERR_NO_RESOURCES;
    tz_sha256_update(&s, domain, sizeof domain);
    tz_sha256_update(&s, (const uint8_t *)&hdr, sizeof hdr);
    tz_sha256_update(&s, pkg + sizeof hdr, hdr.payload_len);
    uint8_t digest[SG_SHA256_DIGEST_LEN];
    tz_sha256_finish(&s, digest);

    if (!uECC_verify(r2p2_mrb_pubkey, digest, sizeof digest, sig,
                     uECC_secp256r1())) {
        return SG_ERR_AUTH_FAILED;
    }

    int rc = ks_rollback_advance(hdr.rollback);
    if (rc) return rc;
    ks_set_mrb_verified();
    return SG_OK;
}
