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
 * Link mechanics: this file is a direct source of the firmware target
 * (see ns_build.cmake), so its symbol definitions win — the linker only
 * pulls pico_rand's rand.o out of the archive for symbols still
 * undefined, and there are none. No weak-symbol tricks needed; the
 * `pico_rand` entry in target_link_libraries can even stay.
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

void get_rand_128(rng_128_t *rand128) {
    int rc = sg_random_bytes((uint8_t *)rand128->r, sizeof rand128->r);
    hard_assert(rc == SG_OK);
}

uint64_t get_rand_64(void) {
    uint64_t v;
    int rc = sg_random_bytes((uint8_t *)&v, sizeof v);
    hard_assert(rc == SG_OK);
    return v;
}

uint32_t get_rand_32(void) {
    uint32_t v;
    int rc = sg_random_bytes((uint8_t *)&v, sizeof v);
    hard_assert(rc == SG_OK);
    return v;
}
