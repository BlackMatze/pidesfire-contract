#pragma once
// PiDesFire Contract — test vectors
// Generated from reference Python (hashlib SHA-256) with the inputs below.
// Any implementation of deriveAesKey() or encodeIdentityRecord() must produce
// these exact bytes or it diverges from the contract.

#include <array>
#include <cstdint>
#include <vector>

namespace pidesfire
{
namespace test_vectors
{

// ---------------------------------------------------------------------------
// Key derivation inputs
// ---------------------------------------------------------------------------

/// Site master key (32-char hex = 16 bytes).
constexpr const char* kSiteKeyHex = "2791aa5aa3bcd050a275c727730ac99a";

/// Application AID used during derivation.
constexpr const char* kAppAidHex = "D15F01";

/// Tag NFC UID (example 4-byte UID in hex).
constexpr const char* kTagUidHex = "04a12b3c";

/// Card UUID (32-char hex = 16 bytes).
constexpr const char* kCardUuidHex = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// Expected derived keys
// SHA256(siteKeyHex + ":" + appAidHex + ":" + tagUidHex + ":" + cardUuidHex + ":" + keySlot)[0:16]
// ---------------------------------------------------------------------------

/// Expected Key 0 (master key).
constexpr std::array<std::uint8_t, 16> kExpectedKey0 = {
    0xf6,
    0x83,
    0xf0,
    0x77,
    0x48,
    0x33,
    0xac,
    0x20,
    0xec,
    0x5b,
    0xcb,
    0xb2,
    0xee,
    0x04,
    0xa1,
    0xe1,
};

/// Expected Key 1 (reader key).
constexpr std::array<std::uint8_t, 16> kExpectedKey1 = {
    0x76,
    0x97,
    0x5b,
    0xab,
    0xf5,
    0x4f,
    0xa8,
    0x71,
    0x00,
    0x5f,
    0xc5,
    0xdc,
    0xfb,
    0xb1,
    0x0a,
    0x23,
};

/// Expected Key 2 (provisioner key).
constexpr std::array<std::uint8_t, 16> kExpectedKey2 = {
    0xa2,
    0x30,
    0xe0,
    0x0c,
    0xe8,
    0xb4,
    0x2b,
    0x25,
    0x20,
    0xb3,
    0x44,
    0x06,
    0xdc,
    0x08,
    0x1e,
    0x59,
};

// ---------------------------------------------------------------------------
// Identity record encoding inputs
// ---------------------------------------------------------------------------

constexpr std::uint32_t kIssueCounter = 0x11223344;
constexpr std::uint8_t kFlags = 0x5A;

/// Expected 32-byte encoding of an IdentityRecord with:
///   cardUuidHex   = kCardUuidHex
///   issueCounter  = kIssueCounter
///   flags         = kFlags
constexpr std::array<std::uint8_t, 32> kExpectedEncoded = {
    0x01,                                                      // format_version
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,            // card_uuid bytes 0-7
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,            // card_uuid bytes 8-15
    0x11, 0x22, 0x33, 0x44,                                    // issue_counter big-endian
    0x5a,                                                      // flags
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // reserved
};

} // namespace test_vectors
} // namespace pidesfire
