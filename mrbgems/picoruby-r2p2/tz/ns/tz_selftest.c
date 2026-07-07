/*
 * tz_selftest.c — on-target exerciser for the phase-2 Secure veneers,
 * exposed to the shell as `TZ.selftest` (registered in ports/rp2040/main.c
 * under R2P2_TRUSTZONE). Run it from irb on a fresh boot for full
 * coverage; a re-run in the same boot skips the pre-latch gate check
 * (the sg_verify_mrb latch and the rollback shadow persist until reset)
 * and reports accordingly.
 *
 * Prints one line per check over the USB CDC console and returns
 * true/false, so it can double as a scripted assertion:
 *   irb> TZ.selftest   #=> true
 */

#include <stdbool.h>
#include <string.h>

#include <mruby.h>

#include "../include/r2p2_sg_api.h"
#include "../include/r2p2_mrb_envelope.h"
#include "tz_selftest_pkgs.h"

/* The machine hal's console write. hal.h #defines picorb_hal_write to this
 * for the mruby VM (the only VM the TZ build uses), so name the real
 * symbol directly rather than dragging that header's include paths here. */
int mrb_hal_write(int fd, const void *buf, int nbytes);

static int t_failures;

static void t_out(const char *s) {
    mrb_hal_write(1, s, (int)strlen(s));
}

static void t_check(const char *name, bool ok) {
    t_out(ok ? "  ok    " : "  FAIL  ");
    t_out(name);
    t_out("\r\n");
    if (!ok) t_failures++;
}

/* ---- randomness / hashing ------------------------------------------------ */

static void t_rand_sha(void) {
    uint8_t a[32], b[32];
    memset(a, 0, sizeof a); memset(b, 0, sizeof b);
    t_check("random_bytes rc", sg_random_bytes(a, sizeof a) == SG_OK &&
                               sg_random_bytes(b, sizeof b) == SG_OK);
    t_check("random_bytes differ", memcmp(a, b, sizeof a) != 0);

    /* SHA-256("abc") — known answer through the veneer + hw engine. */
    static const uint8_t abc_digest[SG_SHA256_DIGEST_LEN] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t d[SG_SHA256_DIGEST_LEN];
    t_check("sha256 rc", sg_sha256((const uint8_t *)"abc", 3, d) == SG_OK);
    t_check("sha256(\"abc\") KAT", memcmp(d, abc_digest, sizeof d) == 0);
}

/* ---- keystore ------------------------------------------------------------ */

static void t_keystore(sg_key_t *root_out) {
    sg_key_t root = 0;
    t_check("key_open(DEVICE_ROOT)",
            sg_key_open(SG_SLOT_DEVICE_ROOT, &root) == SG_OK && root != 0);

    uint32_t policy = 0;
    t_check("root policy readback",
            sg_key_get_policy(root, &policy) == SG_OK);
    t_check("root policy has DERIVE|EXPORT",
            (policy & (SG_KEY_POLICY_DERIVE | SG_KEY_POLICY_EXPORT_DERIVED))
                == (SG_KEY_POLICY_DERIVE | SG_KEY_POLICY_EXPORT_DERIVED));

    sg_key_t mrbk = 0;
    t_check("key_open(MRB_VERIFY) = INVALID_SLOT",
            sg_key_open(SG_SLOT_MRB_VERIFY, &mrbk) == SG_ERR_INVALID_SLOT);

    sg_key_t child = 0;
    t_check("key_derive",
            sg_key_derive(root, (const uint8_t *)"session-a", 9, &child)
                == SG_OK && child != 0);
    uint32_t child_policy = 0;
    t_check("child policy = parent minus DERIVE",
            sg_key_get_policy(child, &child_policy) == SG_OK &&
            child_policy == (policy & ~SG_KEY_POLICY_DERIVE));
    t_check("derived key cannot derive",
            sg_key_derive(child, (const uint8_t *)"x", 1, &child)
                == SG_ERR_NOT_PERMITTED);
    t_check("key_close(child)", sg_key_close(child) == SG_OK);
    t_check("stale handle rejected",
            sg_key_get_policy(child, &child_policy) == SG_ERR_INVALID_HANDLE);

    /* derive_export: deterministic per info, distinct across infos, and a
     * 64-byte (two-HKDF-block) export works; bad lengths rejected. */
    uint8_t ka[64], kb[32], kc[32];
    sg_derive_export_t req = {
        .info = (const uint8_t *)"exp-a", .info_len = 5,
        .out = ka, .out_len = 64,
    };
    t_check("derive_export 64B", sg_key_derive_export(root, &req) == SG_OK);
    req.out = kb; req.out_len = 32;
    t_check("derive_export 32B", sg_key_derive_export(root, &req) == SG_OK);
    t_check("export deterministic", memcmp(ka, kb, 32) == 0);
    req.info = (const uint8_t *)"exp-b";
    req.out = kc;
    t_check("export differs by info",
            sg_key_derive_export(root, &req) == SG_OK &&
            memcmp(kb, kc, 32) != 0);
    req.out_len = 0;
    t_check("export len 0 = BAD_PARAM",
            sg_key_derive_export(root, &req) == SG_ERR_BAD_PARAM);
    req.out_len = 65;
    t_check("export len 65 = BAD_PARAM",
            sg_key_derive_export(root, &req) == SG_ERR_BAD_PARAM);

    /* Handle table: exhaust, then verify close releases entries. */
    sg_key_t extra[9];
    int opened = 0, rc_last = SG_OK;
    for (int i = 0; i < 9; i++) {
        rc_last = sg_key_open(SG_SLOT_DEVICE_ROOT, &extra[i]);
        if (rc_last != SG_OK) break;
        opened++;
    }
    t_check("handle table exhausts = NO_RESOURCES",
            rc_last == SG_ERR_NO_RESOURCES);
    for (int i = 0; i < opened; i++) sg_key_close(extra[i]);
    sg_key_t again = 0;
    t_check("handles reusable after close",
            sg_key_open(SG_SLOT_DEVICE_ROOT, &again) == SG_OK);
    sg_key_close(again);

    *root_out = root;
}

/* ---- HMAC / AEAD ---------------------------------------------------------- */

static void t_hmac_aead(sg_key_t root) {
    static const uint8_t msg[] = "The quick brown fox jumps over the lazy dog";
    uint8_t m1[SG_SHA256_DIGEST_LEN], m2[SG_SHA256_DIGEST_LEN];
    t_check("hmac rc", sg_hmac_sha256(root, msg, sizeof msg - 1, m1) == SG_OK);
    t_check("hmac deterministic",
            sg_hmac_sha256(root, msg, sizeof msg - 1, m2) == SG_OK &&
            memcmp(m1, m2, sizeof m1) == 0);

    sg_key_t k = 0;
    if (sg_key_derive(root, (const uint8_t *)"aead-test", 9, &k) != SG_OK) {
        t_check("derive aead key", false);
        return;
    }

    uint8_t nonce[SG_AEAD_NONCE_LEN] = "tz-nonce-01"; /* 11 chars + NUL */
    uint8_t ct[sizeof msg - 1 + SG_AEAD_TAG_LEN];
    sg_aead_op_t op = {
        .key = k, .nonce = nonce,
        .aad = (const uint8_t *)"hdr", .aad_len = 3,
        .in = msg, .in_len = sizeof msg - 1,
        .out = ct, .out_cap = sizeof ct, .out_len = 0,
    };
    t_check("aead_encrypt rc", sg_aead_encrypt(&op) == SG_OK);
    t_check("aead_encrypt out_len", op.out_len == sizeof ct);
    t_check("ciphertext != plaintext",
            memcmp(ct, msg, sizeof msg - 1) != 0);

    uint8_t pt[sizeof msg - 1];
    memset(pt, 0xa5, sizeof pt);
    sg_aead_op_t dec = {
        .key = k, .nonce = nonce,
        .aad = (const uint8_t *)"hdr", .aad_len = 3,
        .in = ct, .in_len = sizeof ct,
        .out = pt, .out_cap = sizeof pt, .out_len = 0,
    };
    t_check("aead_decrypt rc", sg_aead_decrypt(&dec) == SG_OK);
    t_check("aead round-trip",
            dec.out_len == sizeof pt && memcmp(pt, msg, sizeof pt) == 0);

    /* Tamper: flip one ciphertext byte -> AUTH_FAILED and out untouched. */
    ct[5] ^= 1;
    memset(pt, 0xa5, sizeof pt);
    dec.out_len = 0;
    t_check("tampered ct = AUTH_FAILED",
            sg_aead_decrypt(&dec) == SG_ERR_AUTH_FAILED);
    bool untouched = true;
    for (size_t i = 0; i < sizeof pt; i++) {
        if (pt[i] != 0xa5) { untouched = false; break; }
    }
    t_check("no plaintext on tag mismatch", untouched);
    ct[5] ^= 1;

    /* Wrong AAD must also fail the tag. */
    dec.aad = (const uint8_t *)"HDR";
    t_check("wrong aad = AUTH_FAILED",
            sg_aead_decrypt(&dec) == SG_ERR_AUTH_FAILED);

    sg_key_close(k);
}

/* ---- sg_verify_mrb + policy latch + rollback ------------------------------ */

static void t_verify_mrb(void) {
    /* The latch state tells us whether this is a fresh-boot run. */
    sg_key_t psk = 0;
    int gate = sg_key_open(SG_SLOT_GATEWAY_PSK, &psk);
    if (gate == SG_OK) {
        t_out("  note  PSK latch already open (re-run this boot); gate check skipped\r\n");
        sg_key_close(psk);
    } else {
        t_check("PSK gated before verify = NOT_PERMITTED",
                gate == SG_ERR_NOT_PERMITTED);
    }

    t_check("verify(garbage) = BAD_PARAM",
            sg_verify_mrb((const uint8_t *)"nonsense-package-nonsense", 25)
                == SG_ERR_BAD_PARAM);

    t_check("verify(signed v3) = OK",
            sg_verify_mrb(tz_pkg_v3, sizeof tz_pkg_v3) == SG_OK);

    psk = 0;
    t_check("PSK opens after verify (latch)",
            sg_key_open(SG_SLOT_GATEWAY_PSK, &psk) == SG_OK && psk != 0);
    if (psk) sg_key_close(psk);

    t_check("verify(v1 after v3) = rollback NOT_PERMITTED",
            sg_verify_mrb(tz_pkg_v1, sizeof tz_pkg_v1) == SG_ERR_NOT_PERMITTED);

    uint8_t tampered[sizeof tz_pkg_v3];
    memcpy(tampered, tz_pkg_v3, sizeof tampered);
    tampered[sizeof(r2p2_mrb_env_hdr_t) + 2] ^= 1; /* payload bit */
    t_check("verify(tampered v3) = AUTH_FAILED",
            sg_verify_mrb(tampered, sizeof tampered) == SG_ERR_AUTH_FAILED);

    t_check("verify(signed v3 again, == counter) = OK",
            sg_verify_mrb(tz_pkg_v3, sizeof tz_pkg_v3) == SG_OK);
}

/* ---- entry ----------------------------------------------------------------- */

mrb_value mrb_tz_selftest(mrb_state *mrb, mrb_value self) {
    (void)mrb; (void)self;
    t_failures = 0;

    t_out("TZ veneer self-test (phase 2)\r\n");
    t_check("sg_version", sg_version() == SG_API_VERSION);
    t_rand_sha();

    sg_key_t root = 0;
    t_keystore(&root);
    if (root) {
        t_hmac_aead(root);
        sg_key_close(root);
    }
    t_verify_mrb();

    t_out(t_failures ? "RESULT: FAILED\r\n" : "RESULT: PASSED\r\n");
    return mrb_bool_value(t_failures == 0);
}
