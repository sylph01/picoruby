/*
 * keystore.h — monitor-side key slots, handles, and the OTP rollback
 * counter. The slot -> OTP-page mapping and per-slot policy table live in
 * keystore.c ONLY (monitor image), so an NS rebuild can neither repoint
 * nor repolicy a slot.
 */

#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/r2p2_sg_api.h"

/* Boot-time init: load/derive slot keys from OTP (chip-ID dev fallback on
 * blank pages), then ratchet SW_LOCK on the key pages. Returns SG_OK or a
 * negative sg_status_t (fatal at boot). */
int ks_init(void);

/* True if the slot's OTP page was blank and the key was derived from the
 * (public) chip ID — dev-grade, no secrecy. */
bool ks_slot_is_dev(uint32_t slot);

/* Veneer backends. */
int ks_open(uint32_t slot, sg_key_t *out_key);
int ks_close(sg_key_t key);
int ks_policy(sg_key_t key, uint32_t *out_policy);

/* Handle -> key material, gated on ALL bits of need_policy. Returns SG_OK
 * and sets *out_key (32 bytes, Secure RAM, valid until ks_close), or
 * SG_ERR_INVALID_HANDLE / SG_ERR_NOT_PERMITTED. */
int ks_key_acquire(sg_key_t key, uint32_t need_policy, const uint8_t **out_key);

/* HKDF-derive a child key into a new handle (policy = parent minus DERIVE). */
int ks_derive(sg_key_t parent, const uint8_t *info, size_t info_len,
              sg_key_t *out_key);

/* ---- sg_verify_mrb support ---------------------------------------------- */

/* Monotonic anti-rollback counter (OTP thermometer rows). read() never
 * touches state; advance() is a no-op RAM shadow unless the monitor is
 * built with R2P2_TZ_OTP_WRITE=1. */
uint32_t ks_rollback_read(void);
uint32_t ks_rollback_capacity(void);
int      ks_rollback_advance(uint32_t target);

/* Verified-package latch: set by a successful sg_verify_mrb; required by
 * slots whose policy says so (SG_SLOT_GATEWAY_PSK). Cleared only by reset. */
void ks_set_mrb_verified(void);
bool ks_mrb_verified(void);

#endif /* KEYSTORE_H */
