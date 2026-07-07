/*
 * sg_crypto_test.c — host-side test vectors for the monitor's crypto core.
 * Compiles the EXACT sources the monitor runs (sg_crypto.c, the mbedTLS
 * chacha20/poly1305 slice, vendored micro-ecc) with SG_CRYPTO_HOST_TEST
 * swapping the hardware SHA-256 for mbedTLS's software one.
 *
 * Build & run (from tz/):
 *
 *   gcc -o /tmp/sg_crypto_test -DSG_CRYPTO_HOST_TEST \
 *       -DMBEDTLS_CONFIG_FILE='"mbedtls_config_monitor.h"' \
 *       -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 \
 *       -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256r1=1 \
 *       -DuECC_SUPPORTS_secp256k1=0 -DuECC_SUPPORT_COMPRESSED_POINT=0 \
 *       -I monitor -I include \
 *       -I $PICO_SDK_PATH/lib/mbedtls/include -I $PICO_SDK_PATH/lib/mbedtls/library \
 *       tools/sg_crypto_test.c monitor/sg_crypto.c monitor/vendor/micro-ecc/uECC.c \
 *       $PICO_SDK_PATH/lib/mbedtls/library/chacha20.c \
 *       $PICO_SDK_PATH/lib/mbedtls/library/poly1305.c \
 *       $PICO_SDK_PATH/lib/mbedtls/library/sha256.c \
 *       $PICO_SDK_PATH/lib/mbedtls/library/platform_util.c \
 *       $PICO_SDK_PATH/lib/mbedtls/library/constant_time.c
 *   /tmp/sg_crypto_test [signed-package.mrbx]
 *
 * With a package argument (produced by mrb_sign.rb sign), additionally
 * runs the sg_verify_mrb digest+uECC path against monitor/mrb_pubkey.h —
 * an end-to-end check that host signer and monitor verifier agree.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_crypto.h"
#include "mrb_pubkey.h"
#include "r2p2_mrb_envelope.h"
#include "../monitor/vendor/micro-ecc/uECC.h"

static int failures;

static void check(const char *name, int ok) {
    printf("%-42s %s\n", name, ok ? "ok" : "FAIL");
    if (!ok) failures++;
}

static void hex2bin(const char *hex, uint8_t *out) {
    for (size_t i = 0; hex[2 * i]; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

/* RFC 8439 §2.8.2 AEAD test vector. */
static void test_aead(void) {
    uint8_t key[32], nonce[12], aad[12];
    hex2bin("808182838485868788898a8b8c8d8e8f"
            "909192939495969798999a9b9c9d9e9f", key);
    hex2bin("070000004041424344454647", nonce);
    hex2bin("50515253c0c1c2c3c4c5c6c7", aad);
    static const char pt[] =
        "Ladies and Gentlemen of the class of '99: If I could offer you "
        "only one tip for the future, sunscreen would be it.";
    const size_t pt_len = 114;
    uint8_t want_tag[16];
    hex2bin("1ae10b594f09e26a7e902ecbd0600691", want_tag);
    uint8_t want_ct_head[16];
    hex2bin("d31a8d34648e60db7b86afbc53ef7ec2", want_ct_head);

    uint8_t ct[114], tag[16];
    tz_aead_t c;
    check("aead start", tz_aead_start(&c, key, nonce) == 0);
    tz_aead_aad(&c, aad, sizeof aad);
    tz_aead_aad_done(&c);
    tz_aead_encrypt(&c, (const uint8_t *)pt, ct, pt_len);
    tz_aead_tag(&c, tag);
    tz_aead_end(&c);
    check("aead rfc8439 ciphertext", memcmp(ct, want_ct_head, 16) == 0);
    check("aead rfc8439 tag", memcmp(tag, want_tag, 16) == 0);

    /* Decrypt flow as sg_aead_decrypt runs it: MAC pass, tag check,
     * separate decrypt pass. */
    uint8_t out[114], tag2[16];
    check("aead start (decrypt)", tz_aead_start(&c, key, nonce) == 0);
    tz_aead_aad(&c, aad, sizeof aad);
    tz_aead_aad_done(&c);
    tz_aead_mac_ct(&c, ct, pt_len);
    tz_aead_tag(&c, tag2);
    check("decrypt tag matches", tz_ct_neq(tag2, tag, 16) == 0);
    check("begin_decrypt", tz_aead_begin_decrypt(&c) == 0);
    tz_aead_decrypt(&c, ct, out, pt_len);
    tz_aead_end(&c);
    check("decrypt round-trip", memcmp(out, pt, pt_len) == 0);

    /* Tampered ciphertext must fail the tag. */
    ct[7] ^= 1;
    check("aead start (tamper)", tz_aead_start(&c, key, nonce) == 0);
    tz_aead_aad(&c, aad, sizeof aad);
    tz_aead_aad_done(&c);
    tz_aead_mac_ct(&c, ct, pt_len);
    tz_aead_tag(&c, tag2);
    tz_aead_end(&c);
    check("tampered ct rejected", tz_ct_neq(tag2, tag, 16) != 0);
}

/* RFC 4231 test case 2 (short key). */
static void test_hmac(void) {
    uint8_t want[32];
    hex2bin("5bdcc146bf60754e6a042426089575c7"
            "5a003f089d2739839dec58b964ec3843", want);
    tz_hmac_t h;
    uint8_t mac[32];
    check("hmac start", tz_hmac_start(&h, (const uint8_t *)"Jefe", 4) == 0);
    tz_hmac_update(&h, (const uint8_t *)"what do ya want ", 16);
    tz_hmac_update(&h, (const uint8_t *)"for nothing?", 12);
    check("hmac finish", tz_hmac_finish(&h, mac) == 0);
    check("hmac rfc4231 case 2", memcmp(mac, want, 32) == 0);
}

/* RFC 5869 test case 1. */
static void test_hkdf(void) {
    uint8_t ikm[22], salt[13], info[10], prk[32], okm[42];
    memset(ikm, 0x0b, sizeof ikm);
    hex2bin("000102030405060708090a0b0c", salt);
    hex2bin("f0f1f2f3f4f5f6f7f8f9", info);
    uint8_t want_prk[32], want_okm[42];
    hex2bin("077709362c2e32df0ddc3f0dc47bba63"
            "90b6c73bb50f9c3122ec844ad7c2b3e5", want_prk);
    hex2bin("3cb25f25faacd57a90434f64d0362f2a"
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
            "34007208d5b887185865", want_okm);

    check("hkdf extract",
          tz_hkdf_extract(salt, sizeof salt, ikm, sizeof ikm, prk) == 0);
    check("hkdf prk rfc5869", memcmp(prk, want_prk, 32) == 0);
    /* Split info across the two segments to exercise the label path. */
    check("hkdf expand",
          tz_hkdf_expand(prk, info, 4, info + 4, 6, okm, sizeof okm) == 0);
    check("hkdf okm rfc5869", memcmp(okm, want_okm, sizeof want_okm) == 0);
}

/* The sg_verify_mrb crypto path, against a real mrb_sign.rb package. */
static void test_verify_pkg(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { check("open package", 0); return; }
    static uint8_t pkg[64 * 1024];
    size_t pkg_len = fread(pkg, 1, sizeof pkg, f);
    fclose(f);

    r2p2_mrb_env_hdr_t hdr;
    memcpy(&hdr, pkg, sizeof hdr);
    check("envelope magic", hdr.magic == R2P2_MRB_ENV_MAGIC);
    check("envelope lengths",
          hdr.header_len == sizeof hdr &&
          hdr.payload_len == pkg_len - sizeof hdr - R2P2_MRB_SIG_LEN);

    static const uint8_t domain[R2P2_MRB_SIG_DOMAIN_LEN] = R2P2_MRB_SIG_DOMAIN;
    tz_sha256_t s;
    uint8_t digest[32];
    check("sha start", tz_sha256_start(&s) == 0);
    tz_sha256_update(&s, domain, sizeof domain);
    tz_sha256_update(&s, (const uint8_t *)&hdr, sizeof hdr);
    tz_sha256_update(&s, pkg + sizeof hdr, hdr.payload_len);
    tz_sha256_finish(&s, digest);

    const uint8_t *sig = pkg + pkg_len - R2P2_MRB_SIG_LEN;
    check("uECC_verify(signed pkg)",
          uECC_verify(r2p2_mrb_pubkey, digest, sizeof digest, sig,
                      uECC_secp256r1()) == 1);

    pkg[sizeof hdr] ^= 1; /* flip one payload bit */
    check("sha start (tamper)", tz_sha256_start(&s) == 0);
    tz_sha256_update(&s, domain, sizeof domain);
    tz_sha256_update(&s, (const uint8_t *)&hdr, sizeof hdr);
    tz_sha256_update(&s, pkg + sizeof hdr, hdr.payload_len);
    tz_sha256_finish(&s, digest);
    check("tampered pkg rejected",
          uECC_verify(r2p2_mrb_pubkey, digest, sizeof digest, sig,
                      uECC_secp256r1()) == 0);
}

int main(int argc, char **argv) {
    test_aead();
    test_hmac();
    test_hkdf();
    if (argc > 1) test_verify_pkg(argv[1]);
    printf("%s (%d failure%s)\n", failures ? "FAILED" : "PASSED",
           failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
