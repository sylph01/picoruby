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
 *     blocks the VM exactly like any other blocking C function. The
 *     monitor additionally serializes entry with a try-lock: a call that
 *     arrives while another is in flight (an IRQ handler calling sg_*
 *     over a preempted veneer, or a second core) returns SG_ERR_BUSY
 *     instead of interleaving. sg_version() alone is exempt (pure).
 *     Core 1 cannot call veneers at all — see sg_launch_core1_ns.
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
 * against a mismatched monitor.
 * 0x0002: sg_launch_core1_ns, SG_ERR_BUSY + entry serialization. */
#define SG_API_VERSION 0x0002

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
  SG_ERR_BUSY            = -10, /* another veneer call is in flight (rule 2) */
} sg_status_t;

/* Opaque key handle. Values are monitor-generated and meaningless to NS;
 * 0 is never a valid handle. Handles do not survive reset. */
typedef uint32_t sg_key_t;

/* Well-known key slots. A slot names a monitor-side key definition (OTP
 * page/rows + derivation + policy); the mapping table lives in the monitor
 * image only, so an NS rebuild cannot repoint or repolicy a slot. */
enum sg_key_slot {
  SG_SLOT_DEVICE_ROOT = 0, /* OTP-derived device root                      */
  SG_SLOT_GATEWAY_PSK = 1, /* provisioned server<->device PSK; sg_key_open
                            * requires a prior successful sg_verify_mrb
                            * this boot (the policy-gate latch)            */
  SG_SLOT_MRB_VERIFY  = 2, /* names the sg_verify_mrb public key in policy
                            * discussions; NOT keystore material (the key
                            * is compiled into the monitor's verify path) —
                            * sg_key_open returns SG_ERR_INVALID_SLOT      */
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

/* Erase / program flash. offset and count are 0-based flash offsets (from
 * the start of flash), matching the SDK's flash_range_* convention. The
 * monitor performs the op Secure-side (flash_range_erase/program run from
 * RAM with XIP handled and interrupts masked) — NS cannot do this safely
 * because the ROM flash op leaves flash unreadable across the call and
 * flash_safe_execute needs the Secure-only BOOTRAM lock.
 *
 * Both are clamped to the NS filesystem partition [TZ_FS_OFFSET,
 * TZ_FS_OFFSET+TZ_FS_SIZE); anything outside returns SG_ERR_BAD_PARAM, so
 * NS can never erase/program the monitor or the NS code image. erase needs
 * 4 KiB alignment, program 256 B alignment. program validates the source
 * buffer is NS memory. Each does its own cache flush. */
SG_API int sg_flash_erase(uint32_t offset, uint32_t count);
SG_API int sg_flash_program(uint32_t offset, const uint8_t *data, uint32_t count);

/* ---- signed bytecode ----------------------------------------------------- */

/* Verify a signed .mrb package (format: r2p2_mrb_envelope.h; sign with
 * tz/tools/mrb_sign.rb). ECDSA P-256 over SHA-256(domain||header||payload)
 * against the monitor-compiled public key, plus a monotonic anti-rollback
 * check (OTP thermometer rows, monitor-side; the counter advances on
 * success — only when the monitor is built with R2P2_TZ_OTP_WRITE=1).
 * Success unlocks SG_SLOT_GATEWAY_PSK for the rest of this boot.
 *
 * Returns: SG_OK; SG_ERR_AUTH_FAILED (bad signature); SG_ERR_NOT_PERMITTED
 * (rollback: package older than the counter); SG_ERR_BAD_PARAM (malformed
 * envelope, or version beyond counter capacity).
 *
 * Honest scope note: this attests the buffer contents at call time. NS owns
 * the buffer and the VM that will execute it, so this is a policy gate
 * (e.g. "only verified packages may open SG_SLOT_GATEWAY_PSK"), not an NS
 * integrity guarantee — the boundary protects keys, not NS control flow. */
SG_API int sg_verify_mrb(const uint8_t *pkg, size_t pkg_len);

/* ---- privileged services -------------------------------------------------- */

/* Launch core 1 into the Non-secure image. Core 1 is the designated NS
 * core: partition_configure pins ACCESSCTRL FORCE_CORE_NS.CORE1 (before
 * the ACCESSCTRL lock), so every bus access core 1 ever makes is
 * attributed Non-secure no matter its architectural state — nothing that
 * runs there can reach monitor flash/RAM, Secure peripherals, or key
 * material. That includes the veneers: core 1 jumping at an sg_* address
 * faults on its first Secure access. Core-1 code that needs a Secure
 * service must relay through core 0.
 *
 * The monitor hard-resets core 1 (PSM — Secure-only, which is why NS
 * cannot do any of this itself) and runs the bootrom mailbox launch
 * protocol with the given NS vector table / stack top / entry. The
 * bootrom's core-1 wait loop is security-aware and mailboxes via the
 * SIO_NONSEC alias on a forced-NS core. Thumb bit on ns_entry is set by
 * the monitor.
 *
 * ns_entry == 0: reset core 1 and leave it parked in the bootrom wait
 * loop (the "stop core 1" operation; other args ignored). Calling while
 * core 1 is already running is fine — the reset kills the old payload
 * first.
 *
 * Parameter rules (SG_ERR_BAD_PARAM): vector table and entry in NS flash
 * or NS RAM, vector table 128-byte aligned; stack top 8-byte aligned,
 * stack in NS RAM (grows down from ns_stack_top).
 *
 * Flash hazard while core 1 runs: sg_flash_erase/program make XIP
 * unreadable for their duration; NS must ensure core 1 neither executes
 * from nor reads flash during those calls (the same
 * PICO_FLASH_ASSUME_CORE1_SAFE contract stock R2P2 already builds with).
 *
 * Returns SG_OK once the bootrom handshake completes, SG_ERR_INTERNAL if
 * core 1 stops responding (bounded waits — no indefinite Secure spin). */
SG_API int sg_launch_core1_ns(uintptr_t ns_vector_table, uintptr_t ns_entry,
                              uintptr_t ns_stack_top);

/* Deep sleep / clock dialing: CLOCKS/PLL/POWMAN stay Secure-only, so
 * Machine.deep_sleep needs a veneer with a fixed menu of states rather than
 * raw register access.
 * SG_API int sg_deep_sleep(uint32_t mode, uint32_t wake_mask);
 */

#ifdef __cplusplus
}
#endif

#endif /* R2P2_SG_API_H */
