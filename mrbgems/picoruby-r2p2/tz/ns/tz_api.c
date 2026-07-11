/*
 * tz_api.c — the NS Ruby surface over the Secure veneers. Registered from
 * ports/rp2040/main.c (single call: mrb_tz_api_init) under R2P2_TRUSTZONE.
 *
 *   Digest::SHA256.digest(str)    -> 32-byte String   (hardware SHA-256
 *   Digest::SHA256.hexdigest(str) -> hex String        via sg_sha256)
 *
 *   TZ.derive_key(info, len = 32, slot = 0) -> String
 *       sg_key_derive_export from the slot's key: the tier-2 session-key
 *       path (feed MbedTLS::Cipher#key=). slot 1 (GATEWAY_PSK) requires a
 *       prior successful TZ.verify_mrb this boot.
 *   TZ.verify_mrb(pkg) -> true | false
 *       true latches the GATEWAY_PSK policy gate. false covers bad
 *       signature and rollback; a malformed envelope raises ArgumentError.
 *   TZ.selftest -> true | false            (tz_selftest.c)
 *
 * CRuby-parity note: Digest::SHA256 is one-shot only by decision — the
 * hardware engine holds state under an exclusive bootrom lock, so the
 * veneer (and therefore this API) deliberately has no streaming form.
 */

#include <string.h>

#include <mruby.h>
#include <mruby/string.h>
#include <mruby/class.h>

#include "../include/r2p2_sg_api.h"

mrb_value mrb_tz_selftest(mrb_state *mrb, mrb_value self); /* tz_selftest.c */

static void tz_raise_sg(mrb_state *mrb, int rc) {
    const char *msg;
    switch (rc) {
    case SG_ERR_NOT_PERMITTED: msg = "not permitted by key policy"; break;
    case SG_ERR_NO_RESOURCES:  msg = "secure keystore/engine busy";  break;
    case SG_ERR_BAD_BUFFER:    msg = "buffer rejected by monitor";   break;
    case SG_ERR_BUSY:          msg = "secure gateway busy (reentry)"; break;
    default:                   msg = "secure gateway error";         break;
    }
    mrb_raise(mrb, E_RUNTIME_ERROR, msg);
}

/* ---- Digest::SHA256 ------------------------------------------------------- */

static void tz_sha256_str(mrb_state *mrb, mrb_value str,
                          uint8_t out[SG_SHA256_DIGEST_LEN]) {
    int rc = sg_sha256((const uint8_t *)RSTRING_PTR(str),
                       (size_t)RSTRING_LEN(str), out);
    if (rc != SG_OK) tz_raise_sg(mrb, rc);
}

static mrb_value mrb_digest_sha256_digest(mrb_state *mrb, mrb_value self) {
    (void)self;
    mrb_value str;
    mrb_get_args(mrb, "S", &str);
    uint8_t d[SG_SHA256_DIGEST_LEN];
    tz_sha256_str(mrb, str, d);
    return mrb_str_new(mrb, (const char *)d, sizeof d);
}

static mrb_value mrb_digest_sha256_hexdigest(mrb_state *mrb, mrb_value self) {
    (void)self;
    mrb_value str;
    mrb_get_args(mrb, "S", &str);
    uint8_t d[SG_SHA256_DIGEST_LEN];
    tz_sha256_str(mrb, str, d);
    char hex[SG_SHA256_DIGEST_LEN * 2];
    static const char x[] = "0123456789abcdef";
    for (int i = 0; i < SG_SHA256_DIGEST_LEN; i++) {
        hex[2 * i]     = x[d[i] >> 4];
        hex[2 * i + 1] = x[d[i] & 0xf];
    }
    return mrb_str_new(mrb, hex, sizeof hex);
}

/* ---- TZ.derive_key --------------------------------------------------------- */

static mrb_value mrb_tz_derive_key(mrb_state *mrb, mrb_value self) {
    (void)self;
    mrb_value info;
    mrb_int len = 32, slot = SG_SLOT_DEVICE_ROOT;
    mrb_get_args(mrb, "S|ii", &info, &len, &slot);
    if (len < 1 || len > 64) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "key length must be 1..64");
    }
    if (slot != SG_SLOT_DEVICE_ROOT && slot != SG_SLOT_GATEWAY_PSK) {
        mrb_raise(mrb, E_ARGUMENT_ERROR, "unknown key slot");
    }

    sg_key_t key = 0;
    int rc = sg_key_open((uint32_t)slot, &key);
    if (rc != SG_OK) tz_raise_sg(mrb, rc);

    uint8_t out[64];
    sg_derive_export_t req = {
        .info = (const uint8_t *)RSTRING_PTR(info),
        .info_len = (size_t)RSTRING_LEN(info),
        .out = out,
        .out_len = (size_t)len,
    };
    rc = sg_key_derive_export(key, &req);
    sg_key_close(key);
    if (rc != SG_OK) tz_raise_sg(mrb, rc);

    mrb_value s = mrb_str_new(mrb, (const char *)out, (size_t)len);
    memset(out, 0, sizeof out);
    return s;
}

/* ---- TZ.verify_mrb ---------------------------------------------------------- */

static mrb_value mrb_tz_verify_mrb(mrb_state *mrb, mrb_value self) {
    (void)self;
    mrb_value pkg;
    mrb_get_args(mrb, "S", &pkg);
    int rc = sg_verify_mrb((const uint8_t *)RSTRING_PTR(pkg),
                           (size_t)RSTRING_LEN(pkg));
    switch (rc) {
    case SG_OK:                return mrb_true_value();
    case SG_ERR_AUTH_FAILED:   return mrb_false_value();   /* bad signature */
    case SG_ERR_NOT_PERMITTED: return mrb_false_value();   /* rollback */
    case SG_ERR_BAD_PARAM:
        mrb_raise(mrb, E_ARGUMENT_ERROR, "malformed package envelope");
    default:
        tz_raise_sg(mrb, rc);
    }
    return mrb_nil_value(); /* unreached */
}

/* ---- registration ----------------------------------------------------------- */

void mrb_tz_api_init(mrb_state *mrb) {
    struct RClass *tz = mrb_define_module(mrb, "TZ");
    mrb_define_class_method(mrb, tz, "selftest", mrb_tz_selftest, MRB_ARGS_NONE());
    mrb_define_class_method(mrb, tz, "derive_key", mrb_tz_derive_key,
                            MRB_ARGS_ARG(1, 2));
    mrb_define_class_method(mrb, tz, "verify_mrb", mrb_tz_verify_mrb,
                            MRB_ARGS_REQ(1));

    struct RClass *digest = mrb_define_module(mrb, "Digest");
    struct RClass *sha256 = mrb_define_class_under(mrb, digest, "SHA256",
                                                   mrb->object_class);
    mrb_define_class_method(mrb, sha256, "digest",
                            mrb_digest_sha256_digest, MRB_ARGS_REQ(1));
    mrb_define_class_method(mrb, sha256, "hexdigest",
                            mrb_digest_sha256_hexdigest, MRB_ARGS_REQ(1));
}
