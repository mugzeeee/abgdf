#pragma once
// ============================================================================
// Luau Bytecode Compiler Wrapper
//
// Based on reference executor's bytecode.h.
// Key: Uses BytecodeEncoder that multiplies opcodes by 227.
// This is REQUIRED — Roblox's VM expects encrypted opcodes.
// ============================================================================

#include <string>
#include <iostream>
#include <algorithm>
#include "Luau/Compiler.h"
#include "Luau/BytecodeBuilder.h"
#include "Luau/BytecodeUtils.h"

// Roblox requires opcodes to be encrypted with *227
// Without this, the VM can't decode the instructions
class BytecodeEncoder : public Luau::BytecodeEncoder {
    inline void encode(uint32_t* data, size_t count) override {
        for (auto i = 0u; i < count;) {
            auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
            i += Luau::getOpLength(LuauOpcode(opcode));
            opcode *= 227;
        }
    }
};

class LuauCompiler {
public:
    // Compile Luau source code to bytecode string
    // Returns: {success, bytecode_or_error}
    static std::pair<bool, std::string> Compile(const std::string& source) {
        BytecodeEncoder encoder{};
        const std::string bytecode = Luau::compile(source, {}, {}, &encoder);

        if (bytecode.empty()) {
            return { false, "Compilation returned empty bytecode" };
        }

        // First byte 0 means error
        if (bytecode[0] == '\0') {
            std::string error_message = bytecode;
            error_message.erase(
                std::remove(error_message.begin(), error_message.end(), '\0'), 
                error_message.end()
            );
            return { false, error_message };
        }

        std::cout << "[LUAU] Compiled " << source.size() << " bytes source -> " 
                  << bytecode.size() << " bytes bytecode (version " 
                  << (int)(uint8_t)bytecode[0] << ")\n";

        return { true, bytecode };
    }
};
