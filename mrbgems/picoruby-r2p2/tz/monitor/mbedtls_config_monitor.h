/* mbedtls_config_monitor.h — minimal mbedTLS 3.x config for the Secure
 * monitor: ONLY the ChaCha20 and Poly1305 primitives (the RFC 8439 AEAD
 * construction, HKDF, and HMAC live in sg_crypto.c over the hardware
 * SHA-256). No md layer, no software SHA, no heap use, no self-tests.
 *
 * SG_CRYPTO_HOST_TEST builds (host-side test vectors) additionally need a
 * software SHA-256 to stand in for the hardware engine. */

#ifndef MBEDTLS_CONFIG_MONITOR_H
#define MBEDTLS_CONFIG_MONITOR_H

#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C

#ifdef SG_CRYPTO_HOST_TEST
#define MBEDTLS_SHA256_C
#endif

#endif /* MBEDTLS_CONFIG_MONITOR_H */
