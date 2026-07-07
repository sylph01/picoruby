/*
 * r2p2_mrb_envelope.h — signed .mrb package format for sg_verify_mrb.
 * Shared contract between the monitor's verifier, the (future) NS Ruby
 * surface, and the host signer (tz/tools/mrb_sign.rb mirrors these
 * constants — keep them in sync).
 *
 * Package layout (little-endian, no alignment padding):
 *
 *     r2p2_mrb_env_hdr_t   header      (16 bytes)
 *     uint8_t              payload[payload_len]     (the .mrb bytes)
 *     uint8_t              signature[64]            (ECDSA P-256, raw r||s,
 *                                                    big-endian halves)
 *
 * The signature is over SHA-256(domain || header || payload) where domain
 * is the fixed 16-byte string below (domain separation: a signature over
 * an mrb package can never be confused with any other R2P2 signature use).
 *
 * Verification key: compiled into the monitor image (tz/monitor/
 * mrb_pubkey.h — regenerate with mrb_sign.rb). SG_SLOT_MRB_VERIFY names
 * this key in policy discussions but it is not keystore material; the
 * private half exists only on the signing host.
 *
 * rollback: monotonic package version checked against (and, on success,
 * advancing) the monitor's OTP thermometer counter. A package with
 * rollback below the counter is rejected; equal is accepted (same-version
 * re-verify after reboot must work). Capacity is 1536 — reject anything
 * above it at signing time.
 */

#ifndef R2P2_MRB_ENVELOPE_H
#define R2P2_MRB_ENVELOPE_H

#include <stdint.h>

#define R2P2_MRB_ENV_MAGIC   0x3142524du   /* "MRB1" read as LE uint32 */
#define R2P2_MRB_ENV_FMT     1u
#define R2P2_MRB_SCHEME_ECDSA_P256_SHA256 1u
#define R2P2_MRB_SIG_LEN     64u

/* Exactly 16 bytes, including the trailing NUL. */
#define R2P2_MRB_SIG_DOMAIN  "R2P2-mrb-sig-v1"
#define R2P2_MRB_SIG_DOMAIN_LEN 16u

typedef struct {
    uint32_t magic;        /* R2P2_MRB_ENV_MAGIC */
    uint8_t  fmt;          /* R2P2_MRB_ENV_FMT */
    uint8_t  scheme;       /* R2P2_MRB_SCHEME_ECDSA_P256_SHA256 */
    uint16_t header_len;   /* sizeof(r2p2_mrb_env_hdr_t) */
    uint32_t payload_len;
    uint32_t rollback;     /* monotonic package version */
} r2p2_mrb_env_hdr_t;

_Static_assert(sizeof(r2p2_mrb_env_hdr_t) == 16, "envelope header is 16 bytes");

#endif /* R2P2_MRB_ENVELOPE_H */
