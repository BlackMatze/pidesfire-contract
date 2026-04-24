#pragma once
// PiDesFire Card/Reader Contract
// Single-header, C++17, no external dependencies.
// Include sha256_impl.h before this header if you are not supplying your own SHA-256.
//
// This header is the single source of truth shared by:
//   - PiDesFire (Raspberry Pi provisioner)
//   - pidesfire-reader (ESPHome / custom door reader)
//
// See docs/contract.md for protocol description and trust model.

#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

#include "sha256_impl.h"

namespace pidesfire
{

// ---------------------------------------------------------------------------
// Application constants
// ---------------------------------------------------------------------------

/// DESFire AID as a 6-character lowercase hex string.
constexpr const char* kAid = "D15F01";

/// File number for the 32-byte identity record.
constexpr std::uint8_t kIdentityFileNumber = 0x01;

/// File number for the optional 32-byte metadata record (admin-only).
constexpr std::uint8_t kMetadataFileNumber = 0x02;

/// Size in bytes of the identity record and the metadata record.
constexpr std::uint32_t kIdentityRecordSize = 32;
constexpr std::uint32_t kMetadataRecordSize = 32;

/// Number of AES keys in the application.
constexpr std::uint8_t kApplicationKeyCount = 3;

/// Format version byte written at offset 0 of the identity record.
constexpr std::uint8_t kFormatVersion = 0x01;

// ---------------------------------------------------------------------------
// Key slot roles
// ---------------------------------------------------------------------------

/// Key 0: application master key (provisioning and rotation).
constexpr std::uint8_t kKeyMaster = 0;

/// Key 1: reader authentication key (door reader, diversified per card).
/// File 01 is readable without auth; Key 1 authentication PROVES the card is genuine.
constexpr std::uint8_t kKeyReader = 1;

/// Key 2: provisioner service key (maintenance, recovery, file rewrite).
constexpr std::uint8_t kKeyProvisioner = 2;

// ---------------------------------------------------------------------------
// File 01 access rights (informational — enforced on-card by DESFire settings)
//   read     = FREE  (no authentication required)
//   write    = DENY
//   read-write = KEY2 (provisioner key)
//   change settings = KEY0 (master key)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Identity record
// ---------------------------------------------------------------------------

struct IdentityRecord
{
    /// 32-character lowercase hex string representing a random 16-byte card UUID.
    std::string cardUuidHex;

    /// Big-endian credential generation counter. Increment on each reissue.
    std::uint32_t issueCounter = 0;

    /// Reserved flags byte for future operational markers.
    std::uint8_t flags = 0;
};

/// Encode an IdentityRecord into a 32-byte binary buffer.
/// Throws std::runtime_error if cardUuidHex does not encode exactly 16 bytes (32 hex chars).
inline std::vector<std::uint8_t> encodeIdentityRecord(const IdentityRecord& identity)
{
    if (identity.cardUuidHex.size() != 32)
    {
        throw std::runtime_error("card_uuid must be a 32-character hex string (16 bytes).");
    }

    // Decode hex to bytes for storage.
    std::vector<std::uint8_t> uuidBytes;
    uuidBytes.reserve(16);
    for (std::size_t i = 0; i < 32; i += 2)
    {
        const std::string byteStr = identity.cardUuidHex.substr(i, 2);
        uuidBytes.push_back(static_cast<std::uint8_t>(std::stoul(byteStr, nullptr, 16)));
    }

    std::vector<std::uint8_t> encoded(kIdentityRecordSize, 0x00);
    encoded[0] = kFormatVersion;
    std::copy(uuidBytes.begin(), uuidBytes.end(), encoded.begin() + 1);
    encoded[17] = static_cast<std::uint8_t>((identity.issueCounter >> 24) & 0xFF);
    encoded[18] = static_cast<std::uint8_t>((identity.issueCounter >> 16) & 0xFF);
    encoded[19] = static_cast<std::uint8_t>((identity.issueCounter >> 8) & 0xFF);
    encoded[20] = static_cast<std::uint8_t>(identity.issueCounter & 0xFF);
    encoded[21] = identity.flags;
    // bytes 22–31 remain zero (reserved)
    return encoded;
}

/// Decode a 32-byte binary buffer into an IdentityRecord.
/// Throws std::runtime_error on wrong size or unsupported format version.
inline IdentityRecord decodeIdentityRecord(const std::vector<std::uint8_t>& bytes)
{
    if (bytes.size() != kIdentityRecordSize)
    {
        throw std::runtime_error("Identity record must be exactly 32 bytes.");
    }
    if (bytes[0] != kFormatVersion)
    {
        throw std::runtime_error("Unsupported identity record format version.");
    }

    // Encode 16 UUID bytes back to hex string.
    std::string uuidHex;
    uuidHex.reserve(32);
    static constexpr char hexChars[] = "0123456789abcdef";
    for (std::size_t i = 1; i <= 16; ++i)
    {
        uuidHex += hexChars[(bytes[i] >> 4) & 0x0F];
        uuidHex += hexChars[bytes[i] & 0x0F];
    }

    IdentityRecord record;
    record.cardUuidHex = uuidHex;
    record.issueCounter = (static_cast<std::uint32_t>(bytes[17]) << 24) | (static_cast<std::uint32_t>(bytes[18]) << 16) | (static_cast<std::uint32_t>(bytes[19]) << 8) | static_cast<std::uint32_t>(bytes[20]);
    record.flags = bytes[21];
    return record;
}

// ---------------------------------------------------------------------------
// Key diversification
// ---------------------------------------------------------------------------

/// Derive a 16-byte AES key from site master material and card-specific inputs.
///
/// Formula:
///   input  = siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" + keySlot
///   output = SHA256(input)[0:16]
///
/// All hex string parameters are lowercase. keySlot is 0, 1, or 2.
/// The same formula is used for all three key slots.
inline std::array<std::uint8_t, 16> deriveAesKey(
    const std::string& siteKeyHex,
    const std::string& appAidHex,
    const std::string& tagUidHex,
    const std::string& cardUuidHex,
    std::uint8_t keySlot)
{
    const std::string material =
        siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" +
        std::to_string(static_cast<int>(keySlot));

    std::array<std::uint8_t, 32> digest{};
    pidesfire::sha256(
        reinterpret_cast<const std::uint8_t*>(material.data()),
        material.size(),
        digest.data());

    std::array<std::uint8_t, 16> key{};
    std::copy_n(digest.begin(), 16, key.begin());
    return key;
}

} // namespace pidesfire
