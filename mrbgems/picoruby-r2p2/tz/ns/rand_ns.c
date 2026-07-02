/*
 * rand_ns.c — link-level replacement for pico_rand in the Non-secure R2P2
 * image, backed by the sg_random_bytes() veneer. SKETCH.
 *
 * Why replace pico_rand instead of patching its callers: on RP2350 the
 * stock get_rand_*() implementation reads the TRNG, which is Secure-only
 * under the partition — the first call from NS bus-faults. Everything
 * random in the firmware funnels through this one API:
 *
 *   - picoruby-rng: rng_random_byte_impl() -> get_rand_32()
 *   - pico_mbedtls: mbedtls_hardware_poll() -> get_rand_64()
 *   - pico_lwip (pico2_w): LWIP_RAND -> pico_rand
 *
 * so satisfying the pico/rand.h API here fixes every gem at once with zero
 * gem-source changes.
 *
 * Link mechanics: pico_rand is an SDK INTERFACE library, so its rand.c is
 * injected as a PEER OBJECT of the executable (not an archive member) — a
 * plain redefinition would collide ("multiple definition of get_rand_*").
 * So we use the linker --wrap mechanism (the same one the SDK itself uses
 * for the AEABI double routines): ns_build.cmake passes
 * -Wl,--wrap=get_rand_32/64/128, which redirects every caller to the
 * __wrap_* functions below. The real get_rand_* (still defined in rand.c)
 * become unreferenced and are dropped by --gc-sections, taking the
 * Secure-only TRNG path out of the NS image entirely.
 *
 * Cost: one boundary crossing per call (~10^2 cycles); the expensive TRNG
 * conditioning is amortized Secure-side by pico_rand's xoroshiro state.
 * If profiling ever shows this hot (e.g. TLS handshakes on pico2_w), the
 * upgrade path is an NS-local ChaCha20-based DRBG reseeded from
 * sg_random_bytes(), not more veneer calls.
 */

#include "pico.h"
#include "pico/rand.h"

#include "../include/r2p2_sg_api.h"

void __wrap_get_rand_128(rng_128_t *rand128) {
    int rc = sg_random_bytes((uint8_t *)rand128->r, sizeof rand128->r);
    hard_assert(rc == SG_OK);
}

uint64_t __wrap_get_rand_64(void) {
    uint64_t v;
    int rc = sg_random_bytes((uint8_t *)&v, sizeof v);
    hard_assert(rc == SG_OK);
    return v;
}

uint32_t __wrap_get_rand_32(void) {
    uint32_t v;
    int rc = sg_random_bytes((uint8_t *)&v, sizeof v);
    hard_assert(rc == SG_OK);
    return v;
}
