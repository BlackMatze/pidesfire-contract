# PiDesFire Contract

This document is the authoritative reference for the card/reader protocol.
Both the PiDesFire provisioner and the ESPHome door reader must implement exactly what is described here.

## Application

- **AID:** `D15F01`
- **Key type:** AES-128 only
- **Key count:** 3

## Application Keys

| Slot | Role | User |
|------|------|------|
| Key 0 | Application master key | Provisioner (admin operations, key rotation) |
| Key 1 | Reader authentication key | Door reader (proves card is genuine) |
| Key 2 | Provisioner service key | Pi-side provisioner (maintenance, file rewrite) |

All three keys are diversified per card using the formula below.

## Files

### File 01 — Identity Record

| Property | Value |
|----------|-------|
| File number | `0x01` |
| Type | Standard data file |
| Communication | Plain |
| Size | 32 bytes |
| Read | **FREE — no authentication required** |
| Write | DENY |
| Read-Write | Key 2 |
| Change settings | Key 0 |

#### Binary Layout

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | `format_version` | Layout version; current value `0x01` |
| 1 | 16 | `card_uuid` | Random 16-byte card identifier (binary) |
| 17 | 4 | `issue_counter` | Big-endian unsigned 32-bit credential generation counter |
| 21 | 1 | `flags` | Reserved for future operational markers; write `0x00` |
| 22 | 10 | `reserved` | Reserved; write `0x00` |

### File 02 — Metadata Record (optional)

| Property | Value |
|----------|-------|
| File number | `0x02` |
| Type | Standard data file |
| Communication | Enciphered |
| Size | 32 bytes |
| Read / Write / Read-Write | Key 2 |
| Change settings | Key 0 |

Contents are provisioner-defined. Suggested fields: issuer identifier, provisioning timestamp, diversification scheme version, reserved bytes.

## Key Diversification

All three AES keys are derived with a single formula. Only the `keySlot` integer changes between them.

```
input  = siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" + keySlot
output = SHA256(input)[0:16]
```

- All string parameters are **lowercase hex**.
- `keySlot` is the decimal integer written as an ASCII string (`"0"`, `"1"`, or `"2"`).
- `tagUidHex` is the raw NFC UID as returned by libfreefare / PN532 (typically 8–14 hex chars).
- `cardUuidHex` is the 32-char hex representation of the 16-byte UUID stored in File 01 bytes 1–16.
- `siteKeyHex` is a 32-char hex (16-byte) site master secret configured in both the provisioner and the reader.

The portable reference implementation is in `sha256_impl.h` and `contract.h` (`pidesfire::deriveAesKey`).

## Reader Protocol

File 01 is freely readable. Key 1 authentication is performed **after** reading File 01 because `card_uuid` (needed to derive Key 1) is stored in File 01. The authentication result proves the card is genuine; any reader that skips it must not trust the identity data.

### Step-by-step

1. Detect ISO 14443-A card; capture NFC UID (`tagUidHex`).
2. Select AID `D15F01`. If selection fails, the card is not a PiDesFire card — ignore it.
3. Read File 01 (32 bytes, no authentication needed).
4. Decode `card_uuid` from bytes 1–16. Decode `issue_counter` from bytes 17–20 (big-endian). Verify `format_version == 0x01`.
5. Derive Key 1: `SHA256(siteKeyHex + ":" + "D15F01" + ":" + tagUidHex + ":" + cardUuidHex + ":" + "1")[0:16]`.
6. Authenticate with derived Key 1 using DESFire AES mutual authentication.
7. **On success:** report `{ card_uuid, tag_uid, issue_counter, reader_id, timestamp }` to Home Assistant.
8. **On failure:** discard all data silently. Do not report any identity to Home Assistant.

## Provisioner Protocol

1. Connect to NFC tag; read NFC UID.
2. Authenticate to the PICC with the factory-default key.
3. Delete the existing `D15F01` application if present (reprovisioning path).
4. Create application `D15F01` with 3 AES keys.
5. Select the application; authenticate with the default (all-zeros) application master key.
6. Generate a random 16-byte `card_uuid`.
7. Derive Key 0, Key 1, and Key 2 using the diversification formula.
8. Rotate keys: Key 1, Key 2, then Key 0 (in that order; Key 0 last because it controls the others).
9. Create File 01 with the access rights above (read=FREE, write=DENY, rw=KEY2, change=KEY0).
10. Write the 32-byte identity record to File 01.
11. Read back File 01 and verify every byte.
12. Register the `card_uuid` and `tag_uid` in Home Assistant.

## Trust Model

- File 01 metadata is **not secret**. Knowing `card_uuid` alone gives no access.
- Security depends entirely on the card holding the correct diversified Key 1. Only the original provisioner (with the site master secret) can produce a card that passes Key 1 authentication.
- Cloning the NFC UID does not help; Key 1 derivation uses `card_uuid` as well, and the DESFire chip enforces the authentication cryptographically.
- The door reader is stateless. It reports authenticated identities to Home Assistant; Home Assistant alone decides grant/deny.

## Test Vectors

See `test_vectors.h` for hardcoded inputs and expected outputs.
Run with:

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
