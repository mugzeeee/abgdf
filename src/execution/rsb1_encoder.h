#pragma once
// ============================================================================
// RSB1 Bytecode Encoder with BLAKE3 Signing
//
// Ported DIRECTLY from reference executor's bytecode.h (Bytecode class).
//
// The complete pipeline:
//   1. Raw Luau bytecode (from LuauCompiler::Compile with opcode*227 encoder)
//   2. BLAKE3 sign: compute hash, transform, append 40-byte footer
//   3. RSB1 compress: "RSB1" + uint32 size + ZSTD compressed + XOR encrypt
//
// Critical differences from our old implementation:
//   - Size is uint32 (4 bytes), NOT uint64 (8 bytes)
//   - BLAKE3 signing step was MISSING entirely
//   - Hash seed is 42, NOT 0
//   - Uses ZSTD_maxCLevel() for compression, NOT level 3
// ============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <iostream>
#include <cstring>
#include <zstd.h>

extern "C" {
#include "blake3.h"
}

// Inline xxHash32 — avoids external dependency while being ABI-identical to XXH32()
static inline uint32_t XXH32(const void* input, size_t length, uint32_t seed) {
    static constexpr uint32_t PRIME1 = 2654435761U;
    static constexpr uint32_t PRIME2 = 2246822519U;
    static constexpr uint32_t PRIME3 = 3266489917U;
    static constexpr uint32_t PRIME4 =  668265263U;
    static constexpr uint32_t PRIME5 =  374761393U;
    auto rotl32 = [](uint32_t v, int s) -> uint32_t {
        return (v << s) | (v >> (32 - s));
    };
    const uint8_t* p   = reinterpret_cast<const uint8_t*>(input);
    const uint8_t* end = p + length;
    uint32_t h32;
    if (length >= 16) {
        uint32_t v1 = seed + PRIME1 + PRIME2;
        uint32_t v2 = seed + PRIME2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - PRIME1;
        do {
            uint32_t t; std::memcpy(&t, p, 4); v1 = rotl32(v1 + t * PRIME2, 13) * PRIME1; p += 4;
            std::memcpy(&t, p, 4); v2 = rotl32(v2 + t * PRIME2, 13) * PRIME1; p += 4;
            std::memcpy(&t, p, 4); v3 = rotl32(v3 + t * PRIME2, 13) * PRIME1; p += 4;
            std::memcpy(&t, p, 4); v4 = rotl32(v4 + t * PRIME2, 13) * PRIME1; p += 4;
        } while (p <= end - 16);
        h32 = rotl32(v1, 1) + rotl32(v2, 7) + rotl32(v3, 12) + rotl32(v4, 18);
    } else {
        h32 = seed + PRIME5;
    }
    h32 += static_cast<uint32_t>(length);
    while (p + 4 <= end) {
        uint32_t t; std::memcpy(&t, p, 4);
        h32 = rotl32(h32 + t * PRIME3, 17) * PRIME4; p += 4;
    }
    while (p < end) { h32 = rotl32(h32 + (*p++) * PRIME5, 11) * PRIME1; }
    h32 ^= h32 >> 15; h32 *= PRIME2;
    h32 ^= h32 >> 13; h32 *= PRIME3;
    h32 ^= h32 >> 16;
    return h32;
}

class RSB1Encoder {
private:
    static constexpr uint8_t BYTECODE_SIGNATURE[4] = { 'R', 'S', 'B', '1' };
    static constexpr uint8_t BYTECODE_HASH_MULTIPLIER = 41;
    static constexpr uint32_t BYTECODE_HASH_SEED = 42u;

    static constexpr uint32_t MAGIC_A = 0x4C464F52;  // "ROFL"
    static constexpr uint32_t MAGIC_B = 0x946AC432;
    static constexpr uint8_t  KEY_BYTES[4] = { 0x52, 0x4F, 0x46, 0x4C };  // "ROFL"

    static inline uint8_t rotl8(uint8_t value, int shift) {
        shift &= 7;
        return (value << shift) | (value >> (8 - shift));
    }

public:
    // Compress bytecode into RSB1 format
    // Input: raw bytecode (already signed with BLAKE3 footer)
    // Output: RSB1 encrypted compressed blob
    static std::string Compress(const std::string& bytecode) {
        const auto MaxSize = ZSTD_compressBound(bytecode.size());
        auto Buffer = std::vector<char>(MaxSize + 8);

        memcpy(&Buffer[0], BYTECODE_SIGNATURE, 4);

        // Size is uint32 (4 bytes), NOT uint64!
        const auto Size = static_cast<uint32_t>(bytecode.size());
        memcpy(&Buffer[4], &Size, sizeof(Size));

        const auto compressed_size = ZSTD_compress(
            &Buffer[8], MaxSize, 
            bytecode.data(), bytecode.size(), 
            ZSTD_maxCLevel()
        );
        if (ZSTD_isError(compressed_size)) {
            std::cerr << "[RSB1] ZSTD compress failed: " << ZSTD_getErrorName(compressed_size) << "\n";
            return "";
        }

        const auto FinalSize = compressed_size + 8;
        Buffer.resize(FinalSize);

        // XOR encrypt: key = xxHash32 of buffer, offset = key[i%4] + 41*i
        const auto HashKey = XXH32(Buffer.data(), FinalSize, BYTECODE_HASH_SEED);
        const auto Bytes = reinterpret_cast<const uint8_t*>(&HashKey);

        for (auto i = 0u; i < FinalSize; ++i)
            Buffer[i] ^= (Bytes[i % 4] + i * BYTECODE_HASH_MULTIPLIER) & 0xFF;

        std::cout << "[RSB1] Compressed " << bytecode.size() << " bytes -> " 
                  << FinalSize << " bytes RSB1 (ZSTD: " << compressed_size << ")\n";

        return std::string(Buffer.data(), FinalSize);
    }

    // Sign bytecode with BLAKE3 hash (40-byte footer)
    // This is REQUIRED — Roblox verifies the bytecode signature
    static std::string SignBytecode(const std::string& bytecode) {
        if (bytecode.empty()) {
            return "";
        }

        constexpr uint32_t FOOTER_SIZE = 40u;

        // Step 1: BLAKE3 hash the bytecode
        std::vector<uint8_t> blake3_hash(32);
        {
            blake3_hasher hasher;
            blake3_hasher_init(&hasher);
            blake3_hasher_update(&hasher, bytecode.data(), bytecode.size());
            blake3_hasher_finalize(&hasher, blake3_hash.data(), blake3_hash.size());
        }

        // Step 2: Transform hash with key rotation
        std::vector<uint8_t> transformed_hash(32);
        for (int i = 0; i < 32; ++i) {
            uint8_t byte = KEY_BYTES[i & 3];
            uint8_t hash_byte = blake3_hash[i];
            uint8_t combined = byte + i;
            uint8_t result;

            switch (i & 3) {
            case 0: {
                int shift = ((combined & 3) + 1);
                result = rotl8(hash_byte ^ ~byte, shift);
                break;
            }
            case 1: {
                int shift = ((combined & 3) + 2);
                result = rotl8(byte ^ ~hash_byte, shift);
                break;
            }
            case 2: {
                int shift = ((combined & 3) + 3);
                result = rotl8(hash_byte ^ ~byte, shift);
                break;
            }
            case 3: {
                int shift = ((combined & 3) + 4);
                result = rotl8(byte ^ ~hash_byte, shift);
                break;
            }
            }
            transformed_hash[i] = result;
        }

        // Step 3: Build 40-byte footer
        std::vector<uint8_t> footer(FOOTER_SIZE, 0);

        uint32_t first_hash_dword = *reinterpret_cast<uint32_t*>(transformed_hash.data());
        uint32_t footer_prefix = first_hash_dword ^ MAGIC_B;
        memcpy(&footer[0], &footer_prefix, 4);

        uint32_t xor_ed = first_hash_dword ^ MAGIC_A;
        memcpy(&footer[4], &xor_ed, 4);

        memcpy(&footer[8], transformed_hash.data(), 32);

        // Step 4: Append footer to bytecode
        std::string signed_bytecode = bytecode;
        signed_bytecode.append(reinterpret_cast<const char*>(footer.data()), footer.size());

        std::cout << "[SIGN] BLAKE3 signed: " << bytecode.size() << " + " 
                  << FOOTER_SIZE << " footer = " << signed_bytecode.size() << " bytes\n";

        return signed_bytecode;
    }

    // Full encode pipeline: Sign + Compress
    // This is the main entry point
    static std::string Encode(const std::string& bytecode) {
        // Step 1: BLAKE3 sign (appends 40-byte footer)
        std::string signed_bc = SignBytecode(bytecode);
        if (signed_bc.empty()) return "";

        // Step 2: RSB1 compress + XOR encrypt
        return Compress(signed_bc);
    }

    // Legacy interface for existing code that uses vector<uint8_t>
    static std::vector<uint8_t> Encode(const std::vector<uint8_t>& bytecode) {
        std::string bc(bytecode.begin(), bytecode.end());
        std::string result = Encode(bc);
        return std::vector<uint8_t>(result.begin(), result.end());
    }
};
