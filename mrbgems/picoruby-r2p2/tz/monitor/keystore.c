/* keystore.c — see keystore.h. Slot -> OTP mapping and policy table are
 * deliberately HERE and nowhere else. */

#include <string.h>

#include "pico.h"
#include "pico/bootrom.h"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/otp.h"
#include "hardware/regs/otp_data.h"
#include "hardware/structs/otp.h"

#include "keystore.h"
#include "sg_crypto.h"

/* ---- OTP layout (user-content rows 0x0c0..0xf47 are all ours to assign) --
 *
 * Page 48 (rows 0xc00..0xc3f): DEVICE_ROOT master secret, 16 ECC rows
 *                              (32 bytes) at the page start.
 * Page 49 (rows 0xc40..0xc7f): GATEWAY_PSK, 16 ECC rows at the page start.
 * Page 50 (rows 0xc80..0xcbf): anti-rollback counter, all 64 rows, raw
 *                              thermometer code (capacity 64*24 = 1536).
 *
 * Provisioning (picotool otp / SWD, before secure boot is enabled) writes
 * the 32-byte secrets ECC-encoded at those offsets. A blank page (all raw
 * bits zero) selects the chip-ID dev fallback below.
 */
#define KS_PAGE_DEVICE_ROOT 48u
#define KS_PAGE_GATEWAY_PSK 49u
#define KS_PAGE_ROLLBACK    50u
#define KS_ROWS_PER_PAGE    64u
#define KS_KEY_ROWS         16u   /* 16 ECC rows * 16 bits = 32 bytes */

/* ECC-corrected reads: u16 per row. Raw reads: u32 per row (24 valid bits).
 * Both aliases are Secure-only at the bus level (OTP is not granted to NS
 * in ACCESSCTRL) and respect SW_LOCK — do all reads before ratcheting. */
static inline uint16_t otp_ecc_read(uint32_t row) {
    return *(volatile uint16_t *)(OTP_DATA_BASE + row * 2u);
}
static inline uint32_t otp_raw_read(uint32_t row) {
    return *(volatile uint32_t *)(OTP_DATA_RAW_BASE + row * 4u) & 0x00ffffffu;
}

static bool otp_page_blank(uint32_t page) {
    uint32_t row = page * KS_ROWS_PER_PAGE;
    uint32_t acc = 0;
    for (uint32_t i = 0; i < KS_KEY_ROWS; i++) acc |= otp_raw_read(row + i);
    return acc == 0;
}

static void otp_read_key(uint32_t page, uint8_t out[32]) {
    uint32_t row = page * KS_ROWS_PER_PAGE;
    for (uint32_t i = 0; i < KS_KEY_ROWS; i++) {
        uint16_t v = otp_ecc_read(row + i);
        out[2 * i]     = (uint8_t)v;
        out[2 * i + 1] = (uint8_t)(v >> 8);
    }
}

/* ---- slot table ----------------------------------------------------------
 *
 * SG_SLOT_MRB_VERIFY is NOT here: the package-verify public key is compiled
 * into the verify path (sg_veneers.c) and is not keystore material —
 * sg_key_open on it returns SG_ERR_INVALID_SLOT. */

typedef struct {
    uint32_t otp_page;
    uint32_t policy;
    bool     require_verified_mrb;  /* gate open() on the sg_verify_mrb latch */
    /* runtime: */
    uint8_t  key[32];               /* Secure SRAM8/9 .bss only */
    bool     dev_fallback;
} ks_slot_t;

static ks_slot_t slots[] = {
    [SG_SLOT_DEVICE_ROOT] = {
        .otp_page = KS_PAGE_DEVICE_ROOT,
        .policy = SG_KEY_POLICY_ENCRYPT | SG_KEY_POLICY_DECRYPT
                | SG_KEY_POLICY_HMAC | SG_KEY_POLICY_DERIVE
                | SG_KEY_POLICY_EXPORT_DERIVED,
        .require_verified_mrb = false,
    },
    [SG_SLOT_GATEWAY_PSK] = {
        .otp_page = KS_PAGE_GATEWAY_PSK,
        .policy = SG_KEY_POLICY_ENCRYPT | SG_KEY_POLICY_DECRYPT
                | SG_KEY_POLICY_HMAC | SG_KEY_POLICY_DERIVE
                | SG_KEY_POLICY_EXPORT_DERIVED,
        .require_verified_mrb = true,
    },
};
#define KS_SLOT_COUNT count_of(slots)

/* ---- handle table ---------------------------------------------------------
 *
 * Handle value: (generation << 8) | (index + 1) — never 0, and a stale
 * handle to a reused entry fails the generation check. */

#define KS_MAX_HANDLES 8

typedef struct {
    uint8_t  key[32];
    uint32_t policy;
    uint32_t gen;
    bool     used;
} ks_handle_t;

static ks_handle_t handles[KS_MAX_HANDLES];
static uint32_t next_gen = 1;

static ks_handle_t *handle_lookup(sg_key_t key) {
    uint32_t idx = (key & 0xffu);
    if (idx == 0 || idx > KS_MAX_HANDLES) return NULL;
    ks_handle_t *h = &handles[idx - 1];
    if (!h->used || h->gen != (key >> 8)) return NULL;
    return h;
}

static int handle_alloc(const uint8_t key_material[32], uint32_t policy,
                        sg_key_t *out_key) {
    for (uint32_t i = 0; i < KS_MAX_HANDLES; i++) {
        ks_handle_t *h = &handles[i];
        if (h->used) continue;
        memcpy(h->key, key_material, 32);
        h->policy = policy;
        h->gen = next_gen++ & 0xffffffu;
        if (h->gen == 0) h->gen = next_gen++;
        h->used = true;
        *out_key = (h->gen << 8) | (i + 1);
        return SG_OK;
    }
    return SG_ERR_NO_RESOURCES;
}

/* ---- init ----------------------------------------------------------------- */

static bool mrb_verified_latch = false;

int ks_init(void) {
    /* Chip-ID IKM for the dev fallback: 64-bit random per-die ID from the
     * CHIPID rows. PUBLIC (readable by anyone with the chip) — dev-fallback
     * keys give a working keystore with pristine OTP, not secrecy. */
    uint8_t chipid[8];
    for (uint32_t i = 0; i < 4; i++) {
        uint16_t v = otp_ecc_read(OTP_DATA_CHIPID0_ROW + i);
        chipid[2 * i]     = (uint8_t)v;
        chipid[2 * i + 1] = (uint8_t)(v >> 8);
    }

    static const char root_salt[]     = "R2P2-TZ-root-v1";
    static const char dev_root_salt[] = "R2P2-TZ-DEV-root-v1";
    static const char dev_psk_salt[]  = "R2P2-TZ-DEV-psk-v1";

    int rc = SG_OK;
    for (uint32_t s = 0; s < KS_SLOT_COUNT && rc == SG_OK; s++) {
        ks_slot_t *slot = &slots[s];
        slot->dev_fallback = otp_page_blank(slot->otp_page);
        if (slot->dev_fallback) {
            const char *salt = (s == SG_SLOT_DEVICE_ROOT) ? dev_root_salt
                                                          : dev_psk_salt;
            rc = tz_hkdf_extract((const uint8_t *)salt, strlen(salt),
                                 chipid, sizeof chipid, slot->key);
        } else if (s == SG_SLOT_DEVICE_ROOT) {
            /* Never use the OTP master directly; extract so the working
             * root differs from the (ratchet-protected) stored secret. */
            uint8_t ikm[32];
            otp_read_key(slot->otp_page, ikm);
            rc = tz_hkdf_extract((const uint8_t *)root_salt, strlen(root_salt),
                                 ikm, sizeof ikm, slot->key);
            tz_zeroize(ikm, sizeof ikm);
        } else {
            /* Provisioned PSK is used as stored. */
            otp_read_key(slot->otp_page, slot->key);
        }
    }
    tz_zeroize(chipid, sizeof chipid);

    /* Ratchet: SW_LOCK the key pages inaccessible (SEC and NSEC fields both
     * 0x3) until the next reset — even Secure code can no longer reread the
     * master pages. Registers, not fuses: this repeats every boot. */
    otp_hw->sw_lock[KS_PAGE_DEVICE_ROOT] =
        OTP_SW_LOCK0_SEC_BITS | OTP_SW_LOCK0_NSEC_BITS;
    otp_hw->sw_lock[KS_PAGE_GATEWAY_PSK] =
        OTP_SW_LOCK0_SEC_BITS | OTP_SW_LOCK0_NSEC_BITS;

    return rc;
}

bool ks_slot_is_dev(uint32_t slot) {
    return slot < KS_SLOT_COUNT && slots[slot].dev_fallback;
}

/* ---- veneer backends ------------------------------------------------------ */

int ks_open(uint32_t slot, sg_key_t *out_key) {
    if (slot >= KS_SLOT_COUNT) return SG_ERR_INVALID_SLOT;
    ks_slot_t *s = &slots[slot];
    if (s->require_verified_mrb && !mrb_verified_latch) {
        return SG_ERR_NOT_PERMITTED; /* policy gate: sg_verify_mrb first */
    }
    return handle_alloc(s->key, s->policy, out_key);
}

int ks_close(sg_key_t key) {
    ks_handle_t *h = handle_lookup(key);
    if (!h) return SG_ERR_INVALID_HANDLE;
    tz_zeroize(h, sizeof *h);
    return SG_OK;
}

int ks_policy(sg_key_t key, uint32_t *out_policy) {
    ks_handle_t *h = handle_lookup(key);
    if (!h) return SG_ERR_INVALID_HANDLE;
    *out_policy = h->policy;
    return SG_OK;
}

int ks_key_acquire(sg_key_t key, uint32_t need_policy, const uint8_t **out_key) {
    ks_handle_t *h = handle_lookup(key);
    if (!h) return SG_ERR_INVALID_HANDLE;
    if ((h->policy & need_policy) != need_policy) return SG_ERR_NOT_PERMITTED;
    *out_key = h->key;
    return SG_OK;
}

int ks_derive(sg_key_t parent, const uint8_t *info, size_t info_len,
              sg_key_t *out_key) {
    const uint8_t *pkey;
    int rc = ks_key_acquire(parent, SG_KEY_POLICY_DERIVE, &pkey);
    if (rc) return rc;

    static const char label[] = "R2P2-TZ-derive-v1";
    uint8_t child[32];
    rc = tz_hkdf_expand(pkey, (const uint8_t *)label, strlen(label),
                        info, info_len, child, sizeof child);
    if (rc == 0) {
        /* Child policy: inherited minus DERIVE (no unbounded chains). */
        uint32_t policy;
        ks_policy(parent, &policy);
        rc = handle_alloc(child, policy & ~SG_KEY_POLICY_DERIVE, out_key);
    }
    tz_zeroize(child, sizeof child);
    return rc;
}

/* ---- rollback counter ------------------------------------------------------
 *
 * Thermometer code over page 50's 64 raw rows: the counter value is the
 * number of set bits, bits are set LSB-first row by row. OTP writes can
 * only set bits, so the count is monotonic by construction.
 *
 * The write path is compiled out unless R2P2_TZ_OTP_WRITE=1 (dev boards
 * stay pristine); a RAM shadow keeps the semantics — including "counter
 * advanced" visible to later calls this boot — exercisable either way. */

static uint32_t rollback_shadow;

static uint32_t rollback_read_otp(void) {
    uint32_t row = KS_PAGE_ROLLBACK * KS_ROWS_PER_PAGE;
    uint32_t count = 0;
    for (uint32_t i = 0; i < KS_ROWS_PER_PAGE; i++) {
        count += (uint32_t)__builtin_popcount(otp_raw_read(row + i));
    }
    return count;
}

uint32_t ks_rollback_capacity(void) {
    return KS_ROWS_PER_PAGE * 24u;
}

uint32_t ks_rollback_read(void) {
    uint32_t v = rollback_read_otp();
    return v > rollback_shadow ? v : rollback_shadow;
}

int ks_rollback_advance(uint32_t target) {
    if (target > ks_rollback_capacity()) return SG_ERR_BAD_PARAM;
    if (target <= ks_rollback_read()) return SG_OK;

#if R2P2_TZ_OTP_WRITE
    /* Set bits until popcount == target: LSB-first within each row. Raw
     * (non-ECC) writes through the bootrom; OR-ing bits into a partly
     * written row is legal for raw rows. */
    uint32_t row = KS_PAGE_ROLLBACK * KS_ROWS_PER_PAGE;
    uint32_t remaining = target;
    for (uint32_t i = 0; i < KS_ROWS_PER_PAGE && remaining > 0; i++) {
        uint32_t have = (uint32_t)__builtin_popcount(otp_raw_read(row + i));
        uint32_t want = remaining < 24u ? remaining : 24u;
        remaining -= want;
        if (want <= have) continue;
        uint32_t value = (want >= 24u) ? 0x00ffffffu : ((1u << want) - 1u);
        otp_cmd_t cmd = { .flags = (row + i) | OTP_CMD_WRITE_BITS };
        uint8_t buf[4] = {
            (uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), 0
        };
        int brc = rom_func_otp_access(buf, sizeof buf, cmd);
        if (brc != BOOTROM_OK) return SG_ERR_INTERNAL;
    }
#endif
    rollback_shadow = target;
    return SG_OK;
}

/* ---- verified-package latch ------------------------------------------------ */

void ks_set_mrb_verified(void) { mrb_verified_latch = true; }
bool ks_mrb_verified(void)     { return mrb_verified_latch; }
