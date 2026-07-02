/*
 * r2p2_sg_api.h — Secure Gateway (veneer) API between the R2P2 Secure
 * monitor and the Non-secure R2P2 firmware. RP2350 TrustZone-M. SKETCH.
 *
 * This header is the shared contract, compiled into BOTH images:
 *
 *  - Secure monitor: define R2P2_TZ_MONITOR so SG_API expands to
 *    __attribute__((cmse_nonsecure_entry)). Build with -mcmse (the SDK
 *    Cortex-M33 toolchain default) and link with
 *        -Wl,--cmse-implib,--out-implib=r2p2_sg_implib.o
 *    so GCC emits SG veneers into .gnu.sgstubs (placed at a fixed address
 *    by memmap_monitor_s.ld). Pass the previous implib back via
 *    -Wl,--in-implib=... on rebuilds to keep veneer addresses stable.
 *
 *  - Non-secure R2P2: leave R2P2_TZ_MONITOR undefined and link
 *    r2p2_sg_implib.o; sg_* are then ordinary function calls that land on
 *    the veneers.
 *
 * Calling rules (every function below):
 *
 *  1. Every pointer argument must reference Non-secure memory for its full
 *     length. The monitor validates with rom_validate_ns_buffer(); a
 *     violation returns SG_ERR_BAD_BUFFER. The monitor never dereferences
 *     an NS pointer before validating it.
 *  2. Calls are synchronous, run in Secure state on the caller's thread,
 *     are NOT reentrant, and must not be made from IRQ context. R2P2's
 *     cooperative task scheduler satisfies this naturally: a veneer call
 *     blocks the VM exactly like any other blocking C function.
 *  3. Key material never crosses this boundary. The single deliberate
 *     exception is sg_key_derive_export(), which succeeds only for parent
 *     keys whose monitor-side policy carries SG_KEY_POLICY_EXPORT_DERIVED
 *     (the tier-2 "session key in NS RAM" model). Long-term keys are
 *     reachable only as handles.
 *  4. Return value: SG_OK (0) or a negative sg_status_t. Out-params are
 *     unspecified on error.
 *  5. ABI: cmse_nonsecure_entry functions cannot take stack-passed
 *     arguments (the NS stack is untrusted; GCC rejects >4 register
 *     args). Wide operations therefore take a request struct. The monitor
 *     must copy the struct into Secure memory BEFORE validating and using
 *     the embedded pointers — NS could rewrite fields mid-call (TOCTOU).
 */

#ifndef R2P2_SG_API_H
#define R2P2_SG_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bump on any ABI change. NS calls sg_version() at boot and refuses to run
 * against a mismatched monitor. */
#define SG_API_VERSION 0x0001

/* noipa: GCC's IPA passes otherwise clone entry functions into local
 * `*.constprop.N` symbols (e.g. when a stub ignores its arguments), and
 * CMSE veneer generation requires global function symbols — the clone is
 * a hard link error. used: veneers must exist even with no Secure-side
 * caller. */
#if defined(R2P2_TZ_MONITOR)
#define SG_API __attribute__((cmse_nonsecure_entry, noipa, used))
#else
#define SG_API
#endif

typedef enum {
  SG_OK                  = 0,
  SG_ERR_VERSION         = -1,  /* ABI mismatch */
  SG_ERR_BAD_BUFFER      = -2,  /* pointer not entirely in NS memory */
  SG_ERR_INVALID_HANDLE  = -3,
  SG_ERR_INVALID_SLOT    = -4,
  SG_ERR_NOT_PERMITTED   = -5,  /* key policy forbids this operation */
  SG_ERR_NO_RESOURCES    = -6,  /* handle table full, workspace too small */
  SG_ERR_AUTH_FAILED     = -7,  /* AEAD tag / signature verify failed */
  SG_ERR_BAD_PARAM       = -8,
  SG_ERR_INTERNAL        = -9,
} sg_status_t;

/* Opaque key handle. Values are monitor-generated and meaningless to NS;
 * 0 is never a valid handle. Handles do not survive reset. */
typedef uint32_t sg_key_t;

/* Well-known key slots. A slot names a monitor-side key definition (OTP
 * page/rows + derivation + policy); the mapping table lives in the monitor
 * image only, so an NS rebuild cannot repoint or repolicy a slot. */
enum sg_key_slot {
  SG_SLOT_DEVICE_ROOT = 0, /* OTP-derived device root, DERIVE only        */
  SG_SLOT_GATEWAY_PSK = 1, /* provisioned server<->device PSK             */
  SG_SLOT_MRB_VERIFY  = 2, /* public key for sg_verify_mrb (verify-only)  */
};

/* Key policy bits — readable by NS for introspection, settable only in the
 * monitor's slot table. */
#define SG_KEY_POLICY_ENCRYPT        (1u << 0)
#define SG_KEY_POLICY_DECRYPT        (1u << 1)
#define SG_KEY_POLICY_HMAC           (1u << 2)
#define SG_KEY_POLICY_DERIVE         (1u << 3)
#define SG_KEY_POLICY_EXPORT_DERIVED (1u << 4) /* sg_key_derive_export ok */

#define SG_SHA256_DIGEST_LEN 32
#define SG_AEAD_NONCE_LEN    12
#define SG_AEAD_TAG_LEN      16

/* ---- lifecycle ---------------------------------------------------------- */

/* Returns SG_API_VERSION (positive), or negative sg_status_t. Call first. */
SG_API int sg_version(void);

SG_API int sg_key_open(uint32_t slot, sg_key_t *out_key);
SG_API int sg_key_close(sg_key_t key);
SG_API int sg_key_get_policy(sg_key_t key, uint32_t *out_policy);

/* ---- randomness / hashing ---------------------------------------------- */

/* TRNG-backed (the TRNG is Secure-only at the bus level; this is the only
 * NS path to it). picoruby-rng's RP2350 port becomes a call to this. */
SG_API int sg_random_bytes(uint8_t *out, size_t len);

/* One-shot SHA-256 on the hardware accelerator. Deliberately not streaming:
 * the engine holds hash state internally under an exclusive bootrom lock,
 * so a streaming NS API would let NS pin a Secure resource across calls. */
SG_API int sg_sha256(const uint8_t *in, size_t len,
                     uint8_t out[SG_SHA256_DIGEST_LEN]);

/* ---- key derivation ----------------------------------------------------- */

/* HKDF-SHA256(parent, info) -> new handle. Requires SG_KEY_POLICY_DERIVE on
 * parent. The derived key's policy is inherited minus DERIVE (no chains of
 * unbounded depth in the sketch). */
SG_API int sg_key_derive(sg_key_t parent, const uint8_t *info,
                         size_t info_len, sg_key_t *out_key);

/* Same derivation, but the derived key material is written to NS memory.
 * Requires SG_KEY_POLICY_EXPORT_DERIVED on parent. This is the deliberate
 * tier-2 knob: compromise of NS reveals the session key, never the parent.
 * Feeds e.g. MbedTLS::Cipher#key= for NS-side TLS/AEAD sessions.
 * Request struct per ABI rule 5 (5 args would spill to the NS stack). */
typedef struct {
    const uint8_t *info;
    size_t info_len;
    uint8_t *out;
    size_t out_len;
} sg_derive_export_t;

SG_API int sg_key_derive_export(sg_key_t parent, const sg_derive_export_t *req);

/* ---- AEAD / MAC ---------------------------------------------------------- */

/* ChaCha20-Poly1305 (RFC 8439). Chosen over AES-GCM: RP2350 has no AES
 * hardware, and ChaCha20 is naturally constant-time in software — no
 * table-lookup side channels — and small enough that the monitor needs no
 * mbedTLS at all. Request struct per ABI rule 5. Nonce discipline is the
 * caller's job; the monitor does not track uniqueness in the sketch.
 *
 * encrypt: in/in_len = plaintext; out must have room for
 *          in_len + SG_AEAD_TAG_LEN (tag appended); out_len written.
 * decrypt: in/in_len = ciphertext||tag; returns SG_ERR_AUTH_FAILED (and
 *          writes nothing) on tag mismatch. */
typedef struct {
    sg_key_t key;
    const uint8_t *nonce;   /* SG_AEAD_NONCE_LEN bytes */
    const uint8_t *aad;
    size_t aad_len;
    const uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_cap;
    size_t out_len;         /* written by the monitor */
} sg_aead_op_t;

SG_API int sg_aead_encrypt(sg_aead_op_t *op);
SG_API int sg_aead_decrypt(sg_aead_op_t *op);

SG_API int sg_hmac_sha256(sg_key_t key, const uint8_t *msg, size_t msg_len,
                          uint8_t mac[SG_SHA256_DIGEST_LEN]);

/* ---- flash --------------------------------------------------------------- */

/* Invalidate the entire XIP cache after NS flash writes. NS flash
 * program/erase goes through the bootrom's checked_flash_op NS API (not a
 * veneer), but the bootrom does NOT do cache maintenance, the ROM's
 * flash_flush_cache is Arm-S-only, and NS maintenance-window writes are
 * disabled by design (XIP_CTRL.MAINT_NONSEC stays clear — enabling it is
 * unsafe while Secure code performs cached XIP accesses, which the XIP
 * monitor does). So NS calls this after program/erase to make writes
 * visible to subsequent cached reads. Whole-cache invalidate: costs the
 * monitor its warm cache lines too — performance only, no security
 * impact, and flash writes are rare (filesystem writes). */
SG_API int sg_flash_flush_cache(void);

/* ---- signed bytecode ----------------------------------------------------- */

/* PHASE 2 — returns SG_ERR_NOT_PERMITTED in phase 1. Reserved in the ABI
 * now so the veneer table stays stable.
 *
 * Will verify an authenticated .mrb package (envelope format TBD; ECDSA
 * signature vs HMAC seal undecided) against SG_SLOT_MRB_VERIFY, including
 * a monotonic rollback counter check (OTP thermometer rows, monitor-side).
 *
 * Honest scope note: this attests the buffer contents at call time. NS owns
 * the buffer and the VM that will execute it, so this is a policy gate
 * (e.g. "only verified packages may open SG_SLOT_GATEWAY_PSK"), not an NS
 * integrity guarantee — the boundary protects keys, not NS control flow. */
SG_API int sg_verify_mrb(const uint8_t *pkg, size_t pkg_len);

/* ---- privileged services (TODO, unimplemented even in sketch) ----------- */

/* Core 1 launch into NS state: the bootrom's core-1 launch protocol runs
 * Secure-side, so NS cannot start core 1 itself. The monitor pins core 1
 * Non-secure (ACCESSCTRL FORCE_CORE_NS) and releases it into the given NS
 * entry. Needed for picoruby-psg / pitchdetector.
 * SG_API int sg_launch_core1_ns(uintptr_t ns_vector_table,
 *                               uintptr_t ns_entry, uintptr_t ns_stack_top);
 */

/* Deep sleep / clock dialing: CLOCKS/PLL/POWMAN stay Secure-only, so
 * Machine.deep_sleep needs a veneer with a fixed menu of states rather than
 * raw register access.
 * SG_API int sg_deep_sleep(uint32_t mode, uint32_t wake_mask);
 */

#ifdef __cplusplus
}
#endif

#endif /* R2P2_SG_API_H */
