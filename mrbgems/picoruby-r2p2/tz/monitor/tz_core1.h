/*
 * tz_core1.h — Non-secure core-1 launch, monitor-internal contract between
 * sg_veneers.c (the NS-facing veneer + argument validation) and main.c
 * (the Secure core-1 machinery: bootrom mailbox + the S->NS trampoline).
 */

#ifndef TZ_CORE1_H
#define TZ_CORE1_H

#include <stdint.h>

/*
 * Reset core 1 and either park it in the bootrom wait loop (ns_entry == 0)
 * or launch it into the Non-secure image at ns_entry. Arguments are
 * pre-validated by the veneer (NS-range, alignment). Runs on core 0 in
 * Secure state; drives the bootrom mailbox with bounded waits, so a
 * non-responding core 1 returns SG_ERR_INTERNAL rather than hanging.
 *
 * Core 1 is NOT forced Non-secure at the bus level: it is launched via the
 * ordinary Secure bootrom handshake into a Secure trampoline that sets up
 * core 1's banked SAU + coprocessor grants (identically to core 0) and then
 * does the architectural S->NS transition. Returns SG_OK / SG_ERR_INTERNAL.
 */
int tz_core1_launch_ns(uintptr_t ns_vtor, uintptr_t ns_entry,
                       uintptr_t ns_stack_top);

#endif /* TZ_CORE1_H */
