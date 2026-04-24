#include "contract.h"
#include "test_vectors.h"

#include <array>
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

void passMsg(const char* name)
{
    std::printf("  PASS: %s\n", name);
}

void failMsg(const char* name, const char* detail)
{
    std::fprintf(stderr, "  FAIL: %s — %s\n", name, detail);
    std::exit(1);
}

// ---------------------------------------------------------------------------
// SHA-256 sanity check (NIST FIPS 180-4 known-answer test: SHA-256("abc"))
// ---------------------------------------------------------------------------
void test_sha256_known_answer()
{
    const std::string input = "abc";
    const std::array<std::uint8_t, 32> expected = {
        0xba,
        0x78,
        0x16,
        0xbf,
        0x8f,
        0x01,
        0xcf,
        0xea,
        0x41,
        0x41,
        0x40,
        0xde,
        0x5d,
        0xae,
        0x22,
        0x23,
        0xb0,
        0x03,
        0x61,
        0xa3,
        0x96,
        0x17,
        0x7a,
        0x9c,
        0xb4,
        0x10,
        0xff,
        0x61,
        0xf2,
        0x00,
        0x15,
        0xad,
    };

    std::array<std::uint8_t, 32> digest{};
    pidesfire::sha256(
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size(),
        digest.data());

    if (digest != expected)
        failMsg("sha256 known-answer (abc)", "digest mismatch");

    passMsg("sha256 known-answer (abc)");
}

// ---------------------------------------------------------------------------
// Key derivation — all three slots match reference Python output
// ---------------------------------------------------------------------------
void test_key_derivation()
{
    namespace tv = pidesfire::test_vectors;

    const auto key0 = pidesfire::deriveAesKey(tv::kSiteKeyHex, tv::kAppAidHex, tv::kTagUidHex, tv::kCardUuidHex, 0);
    const auto key1 = pidesfire::deriveAesKey(tv::kSiteKeyHex, tv::kAppAidHex, tv::kTagUidHex, tv::kCardUuidHex, 1);
    const auto key2 = pidesfire::deriveAesKey(tv::kSiteKeyHex, tv::kAppAidHex, tv::kTagUidHex, tv::kCardUuidHex, 2);

    if (key0 != tv::kExpectedKey0)
        failMsg("key derivation slot 0", "key mismatch");
    if (key1 != tv::kExpectedKey1)
        failMsg("key derivation slot 1", "key mismatch");
    if (key2 != tv::kExpectedKey2)
        failMsg("key derivation slot 2", "key mismatch");

    passMsg("key derivation slot 0");
    passMsg("key derivation slot 1");
    passMsg("key derivation slot 2");
}

// ---------------------------------------------------------------------------
// Identity record — encode produces expected bytes
// ---------------------------------------------------------------------------
void test_encode()
{
    namespace tv = pidesfire::test_vectors;

    pidesfire::IdentityRecord rec;
    rec.cardUuidHex = tv::kCardUuidHex;
    rec.issueCounter = tv::kIssueCounter;
    rec.flags = tv::kFlags;

    const auto encoded = pidesfire::encodeIdentityRecord(rec);

    if (encoded.size() != 32)
        failMsg("encode size", "not 32 bytes");

    for (std::size_t i = 0; i < 32; ++i)
    {
        if (encoded[i] != tv::kExpectedEncoded[i])
        {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "byte %zu: got 0x%02x expected 0x%02x",
                          i, encoded[i], tv::kExpectedEncoded[i]);
            failMsg("encode bytes", buf);
        }
    }
    passMsg("encode bytes match reference vector");
}

// ---------------------------------------------------------------------------
// Identity record — decode round-trips correctly
// ---------------------------------------------------------------------------
void test_decode_roundtrip()
{
    namespace tv = pidesfire::test_vectors;

    const std::vector<std::uint8_t> raw(tv::kExpectedEncoded.begin(), tv::kExpectedEncoded.end());
    const auto rec = pidesfire::decodeIdentityRecord(raw);

    if (rec.cardUuidHex != std::string(tv::kCardUuidHex))
        failMsg("decode round-trip", "cardUuidHex mismatch");
    if (rec.issueCounter != tv::kIssueCounter)
        failMsg("decode round-trip", "issueCounter mismatch");
    if (rec.flags != tv::kFlags)
        failMsg("decode round-trip", "flags mismatch");

    passMsg("decode round-trip");
}

// ---------------------------------------------------------------------------
// Encode then decode preserves all fields
// ---------------------------------------------------------------------------
void test_encode_decode_roundtrip()
{
    pidesfire::IdentityRecord original;
    original.cardUuidHex = "cafebabecafebabecafebabecafebabe";
    original.issueCounter = 0xdeadbeef;
    original.flags = 0x42;

    const auto encoded = pidesfire::encodeIdentityRecord(original);
    const auto decoded = pidesfire::decodeIdentityRecord(encoded);

    if (decoded.cardUuidHex != original.cardUuidHex)
        failMsg("encode→decode", "cardUuidHex mismatch");
    if (decoded.issueCounter != original.issueCounter)
        failMsg("encode→decode", "issueCounter mismatch");
    if (decoded.flags != original.flags)
        failMsg("encode→decode", "flags mismatch");

    passMsg("encode→decode round-trip");
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------
void test_error_cases()
{
    // Wrong UUID length
    try
    {
        pidesfire::IdentityRecord bad;
        bad.cardUuidHex = "0011"; // too short
        pidesfire::encodeIdentityRecord(bad);
        failMsg("encode rejects short UUID", "no exception thrown");
    }
    catch (const std::runtime_error&)
    {
        passMsg("encode rejects short UUID");
    }

    // Wrong buffer size
    try
    {
        std::vector<std::uint8_t> buf(10, 0x00);
        pidesfire::decodeIdentityRecord(buf);
        failMsg("decode rejects wrong size", "no exception thrown");
    }
    catch (const std::runtime_error&)
    {
        passMsg("decode rejects wrong size");
    }

    // Wrong format version
    try
    {
        std::vector<std::uint8_t> buf(32, 0x00);
        buf[0] = 0xFF; // unsupported version
        pidesfire::decodeIdentityRecord(buf);
        failMsg("decode rejects bad version", "no exception thrown");
    }
    catch (const std::runtime_error&)
    {
        passMsg("decode rejects bad version");
    }
}

// ---------------------------------------------------------------------------
// Format version and field placement sanity
// ---------------------------------------------------------------------------
void test_binary_layout()
{
    namespace tv = pidesfire::test_vectors;

    // format_version at byte 0
    if (tv::kExpectedEncoded[0] != 0x01)
        failMsg("binary layout", "format_version not at offset 0");

    // issue_counter big-endian at bytes 17-20
    const std::uint32_t counterFromBytes =
        (static_cast<std::uint32_t>(tv::kExpectedEncoded[17]) << 24) |
        (static_cast<std::uint32_t>(tv::kExpectedEncoded[18]) << 16) |
        (static_cast<std::uint32_t>(tv::kExpectedEncoded[19]) << 8) |
        static_cast<std::uint32_t>(tv::kExpectedEncoded[20]);
    if (counterFromBytes != tv::kIssueCounter)
        failMsg("binary layout", "issue_counter offset/endianness wrong");

    // flags at byte 21
    if (tv::kExpectedEncoded[21] != tv::kFlags)
        failMsg("binary layout", "flags not at offset 21");

    // reserved bytes 22-31 are zero
    for (std::size_t i = 22; i < 32; ++i)
    {
        if (tv::kExpectedEncoded[i] != 0x00)
            failMsg("binary layout", "reserved bytes not zero");
    }

    passMsg("binary layout offsets and endianness");
}

} // anonymous namespace

int main()
{
    std::printf("pidesfire-contract tests\n");
    std::printf("========================\n");

    test_sha256_known_answer();
    test_key_derivation();
    test_encode();
    test_decode_roundtrip();
    test_encode_decode_roundtrip();
    test_error_cases();
    test_binary_layout();

    std::printf("========================\n");
    std::printf("ALL PASS\n");
    return 0;
}
