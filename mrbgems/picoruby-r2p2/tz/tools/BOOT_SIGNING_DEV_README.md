# boot_signing_dev.pem — DEV boot-signing key (secp256k1)

Used by `R2P2_TZ_SIGKEY=... rake r2p2:tz:package` -> `picotool seal --sig`
to exercise the sealed-monitor path. The private key is committed, so it
authenticates NOTHING. Before enabling secure boot (OTP BOOTKEY +
CRIT1.SECURE_BOOT_ENABLE — irreversible, board 1 only), generate a fresh
keypair OFF-repo and use that; the OTP fingerprint must match the real key.
