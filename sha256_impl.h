#pragma once
// Portable SHA-256 implementation.
// Derived from Brad Conte's public-domain crypto-algorithms:
//   https://github.com/B-Con/crypto-algorithms
// Adapted for use in the PiDesFire contract header without external dependencies.

#include <cstdint>
#include <cstring>

namespace pidesfire
{

namespace detail
{

static constexpr std::uint32_t sha256_k[64] = {
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
};

inline std::uint32_t rotr32(std::uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}

struct Sha256State
{
    std::uint8_t data[64];
    std::uint32_t datalen;
    std::uint64_t bitlen;
    std::uint32_t state[8];
};

inline void sha256_init(Sha256State& s)
{
    s.datalen = 0;
    s.bitlen = 0;
    s.state[0] = 0x6a09e667;
    s.state[1] = 0xbb67ae85;
    s.state[2] = 0x3c6ef372;
    s.state[3] = 0xa54ff53a;
    s.state[4] = 0x510e527f;
    s.state[5] = 0x9b05688c;
    s.state[6] = 0x1f83d9ab;
    s.state[7] = 0x5be0cd19;
}

inline void sha256_transform(Sha256State& s, const std::uint8_t* data)
{
    std::uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    for (unsigned i = 0, j = 0; i < 16; ++i, j += 4)
    {
        m[i] = (static_cast<std::uint32_t>(data[j]) << 24) |
               (static_cast<std::uint32_t>(data[j + 1]) << 16) |
               (static_cast<std::uint32_t>(data[j + 2]) << 8) |
               (static_cast<std::uint32_t>(data[j + 3]));
    }
    for (unsigned i = 16; i < 64; ++i)
    {
        const std::uint32_t s0 = rotr32(m[i - 15], 7) ^ rotr32(m[i - 15], 18) ^ (m[i - 15] >> 3);
        const std::uint32_t s1 = rotr32(m[i - 2], 17) ^ rotr32(m[i - 2], 19) ^ (m[i - 2] >> 10);
        m[i] = m[i - 16] + s0 + m[i - 7] + s1;
    }

    a = s.state[0];
    b = s.state[1];
    c = s.state[2];
    d = s.state[3];
    e = s.state[4];
    f = s.state[5];
    g = s.state[6];
    h = s.state[7];

    for (unsigned i = 0; i < 64; ++i)
    {
        const std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + sha256_k[i] + m[i];
        const std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s.state[0] += a;
    s.state[1] += b;
    s.state[2] += c;
    s.state[3] += d;
    s.state[4] += e;
    s.state[5] += f;
    s.state[6] += g;
    s.state[7] += h;
}

inline void sha256_update(Sha256State& s, const std::uint8_t* data, std::size_t len)
{
    for (std::size_t i = 0; i < len; ++i)
    {
        s.data[s.datalen++] = data[i];
        if (s.datalen == 64)
        {
            sha256_transform(s, s.data);
            s.bitlen += 512;
            s.datalen = 0;
        }
    }
}

inline void sha256_final(Sha256State& s, std::uint8_t* digest)
{
    std::uint32_t i = s.datalen;

    if (s.datalen < 56)
    {
        s.data[i++] = 0x80;
        while (i < 56)
            s.data[i++] = 0x00;
    }
    else
    {
        s.data[i++] = 0x80;
        while (i < 64)
            s.data[i++] = 0x00;
        sha256_transform(s, s.data);
        std::memset(s.data, 0, 56);
    }

    s.bitlen += static_cast<std::uint64_t>(s.datalen) * 8;
    s.data[63] = static_cast<std::uint8_t>(s.bitlen);
    s.data[62] = static_cast<std::uint8_t>(s.bitlen >> 8);
    s.data[61] = static_cast<std::uint8_t>(s.bitlen >> 16);
    s.data[60] = static_cast<std::uint8_t>(s.bitlen >> 24);
    s.data[59] = static_cast<std::uint8_t>(s.bitlen >> 32);
    s.data[58] = static_cast<std::uint8_t>(s.bitlen >> 40);
    s.data[57] = static_cast<std::uint8_t>(s.bitlen >> 48);
    s.data[56] = static_cast<std::uint8_t>(s.bitlen >> 56);
    sha256_transform(s, s.data);

    for (unsigned j = 0; j < 4; ++j)
    {
        digest[j] = static_cast<std::uint8_t>(s.state[0] >> (24 - j * 8));
        digest[4 + j] = static_cast<std::uint8_t>(s.state[1] >> (24 - j * 8));
        digest[8 + j] = static_cast<std::uint8_t>(s.state[2] >> (24 - j * 8));
        digest[12 + j] = static_cast<std::uint8_t>(s.state[3] >> (24 - j * 8));
        digest[16 + j] = static_cast<std::uint8_t>(s.state[4] >> (24 - j * 8));
        digest[20 + j] = static_cast<std::uint8_t>(s.state[5] >> (24 - j * 8));
        digest[24 + j] = static_cast<std::uint8_t>(s.state[6] >> (24 - j * 8));
        digest[28 + j] = static_cast<std::uint8_t>(s.state[7] >> (24 - j * 8));
    }
}

} // namespace detail

// Compute SHA-256 of `len` bytes at `data`, writing 32 bytes to `digest`.
inline void sha256(const std::uint8_t* data, std::size_t len, std::uint8_t* digest)
{
    detail::Sha256State s;
    detail::sha256_init(s);
    detail::sha256_update(s, data, len);
    detail::sha256_final(s, digest);
}

} // namespace pidesfire
