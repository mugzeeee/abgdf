#pragma once
// ============================================================================
// Pattern Scanner
//
// Scans Roblox's memory for byte patterns to dynamically find addresses.
// This makes the executor version-independent — no need to update offsets
// every time Roblox patches.
// ============================================================================

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include "process/scanner.h"

class PatternScanner {
public:
    PatternScanner(HANDLE hProcess, uintptr_t baseAddress)
        : m_process(hProcess), m_base(baseAddress) {
    }

    // Parse a pattern string like "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    // ?? = wildcard (matches any byte)
    struct PatternByte {
        uint8_t value;
        bool isWildcard;
    };

    static std::vector<PatternByte> ParsePattern(const std::string& pattern) {
        std::vector<PatternByte> result;
        std::istringstream stream(pattern);
        std::string token;

        while (stream >> token) {
            if (token == "??" || token == "?") {
                result.push_back({ 0, true });
            } else {
                result.push_back({ static_cast<uint8_t>(std::stoul(token, nullptr, 16)), false });
            }
        }
        return result;
    }

    // Scan a memory region for a pattern
    uintptr_t ScanRegion(uintptr_t start, size_t size, const std::vector<PatternByte>& pattern) {
        if (pattern.empty() || size < pattern.size()) return 0;

        // Read the region into local buffer
        std::vector<uint8_t> buffer(size);
        if (!ProcessScanner::ReadMemory(m_process, start, buffer.data(), size)) {
            return 0;
        }

        // Search for pattern
        for (size_t i = 0; i <= buffer.size() - pattern.size(); i++) {
            bool found = true;
            for (size_t j = 0; j < pattern.size(); j++) {
                if (!pattern[j].isWildcard && buffer[i + j] != pattern[j].value) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return start + i;
            }
        }
        return 0;
    }

    // Scan the .text section of the module for a pattern
    uintptr_t ScanModule(const std::string& patternStr) {
        auto pattern = ParsePattern(patternStr);
        if (pattern.empty()) return 0;

        // Read the PE headers to find the .text section
        IMAGE_DOS_HEADER dosHeader{};
        if (!ProcessScanner::ReadMemory(m_process, m_base, &dosHeader, sizeof(dosHeader))) return 0;
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return 0;

        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!ProcessScanner::ReadMemory(m_process, m_base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) return 0;
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return 0;

        // Scan each section
        WORD numSections = ntHeaders.FileHeader.NumberOfSections;
        uintptr_t sectionHeadersAddr = m_base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

        for (WORD i = 0; i < numSections; i++) {
            IMAGE_SECTION_HEADER section{};
            if (!ProcessScanner::ReadMemory(m_process, sectionHeadersAddr + i * sizeof(IMAGE_SECTION_HEADER),
                &section, sizeof(section))) continue;

            // Only scan executable sections (.text)
            if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            uintptr_t sectionStart = m_base + section.VirtualAddress;
            size_t sectionSize = section.Misc.VirtualSize;

            // Scan in chunks to avoid massive allocations
            const size_t chunkSize = 0x100000; // 1MB chunks
            for (size_t offset = 0; offset < sectionSize; offset += chunkSize - pattern.size()) {
                size_t currentSize = min(chunkSize, sectionSize - offset);
                uintptr_t result = ScanRegion(sectionStart + offset, currentSize, pattern);
                if (result) return result;
            }
        }

        return 0;
    }

    // Scan ALL sections (including .rdata for strings)
    uintptr_t ScanAllSections(const std::string& patternStr) {
        auto pattern = ParsePattern(patternStr);
        if (pattern.empty()) return 0;

        IMAGE_DOS_HEADER dosHeader{};
        if (!ProcessScanner::ReadMemory(m_process, m_base, &dosHeader, sizeof(dosHeader))) return 0;

        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!ProcessScanner::ReadMemory(m_process, m_base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) return 0;

        WORD numSections = ntHeaders.FileHeader.NumberOfSections;
        uintptr_t sectionHeadersAddr = m_base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

        for (WORD i = 0; i < numSections; i++) {
            IMAGE_SECTION_HEADER section{};
            if (!ProcessScanner::ReadMemory(m_process, sectionHeadersAddr + i * sizeof(IMAGE_SECTION_HEADER),
                &section, sizeof(section))) continue;

            uintptr_t sectionStart = m_base + section.VirtualAddress;
            size_t sectionSize = section.Misc.VirtualSize;
            if (sectionSize == 0) continue;

            const size_t chunkSize = 0x100000;
            for (size_t offset = 0; offset < sectionSize; offset += chunkSize - pattern.size()) {
                size_t currentSize = min(chunkSize, sectionSize - offset);
                uintptr_t result = ScanRegion(sectionStart + offset, currentSize, pattern);
                if (result) return result;
            }
        }
        return 0;
    }

    // Resolve a RIP-relative address (lea reg, [rip+offset] pattern)
    // Given the address of the instruction start and instruction length
    uintptr_t ResolveRIPRelative(uintptr_t instrAddr, int instrLength) {
        // The displacement is a 32-bit signed int at instrAddr + (instrLength - 4)
        int32_t displacement = ProcessScanner::Read<int32_t>(m_process, instrAddr + instrLength - 4);
        return instrAddr + instrLength + displacement;
    }

    // ---- High-level finders ----

    // Find TaskScheduler by scanning for its singleton accessor pattern
    // The accessor typically looks like: lea rax, [rip+xxxx] or mov rax, [rip+xxxx]
    // followed by a reference to the global pointer
    uintptr_t FindTaskScheduler() {
        // Common patterns for TaskScheduler::singleton()
        // Pattern: 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 (mov rax, [rip+xxx]; test rax, rax; jz)
        // This is the typical "load global, check if null" pattern

        // First, try to find the "TaskScheduler" string reference
        // Search for UTF-8 string "TaskScheduler" in .rdata
        std::string searchBytes;
        const char* ts = "TaskScheduler";
        for (int i = 0; ts[i]; i++) {
            char hex[4];
            snprintf(hex, sizeof(hex), "%02X ", (unsigned char)ts[i]);
            searchBytes += hex;
        }

        uintptr_t stringAddr = ScanAllSections(searchBytes);
        if (stringAddr) {
            std::cout << "[*] Found 'TaskScheduler' string at: 0x" << std::hex << stringAddr << std::dec << std::endl;

            // Now find code that references this string (lea reg, [rip+xxx] pointing to stringAddr)
            // We need to search for a LEA instruction where rip+disp = stringAddr
            // Search for: 48 8D 0D ?? ?? ?? ?? or 48 8D 15 ?? ?? ?? ??  (lea rcx/rdx, [rip+xxx])
            // The displacement = stringAddr - (instrAddr + 7)

            // Scan .text section for any lea that resolves to our string address
            IMAGE_DOS_HEADER dosHeader{};
            ProcessScanner::ReadMemory(m_process, m_base, &dosHeader, sizeof(dosHeader));
            IMAGE_NT_HEADERS64 ntHeaders{};
            ProcessScanner::ReadMemory(m_process, m_base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders));

            WORD numSections = ntHeaders.FileHeader.NumberOfSections;
            uintptr_t sectionHeadersAddr = m_base + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);

            for (WORD si = 0; si < numSections; si++) {
                IMAGE_SECTION_HEADER section{};
                ProcessScanner::ReadMemory(m_process, sectionHeadersAddr + si * sizeof(IMAGE_SECTION_HEADER),
                    &section, sizeof(section));

                if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

                uintptr_t sectionStart = m_base + section.VirtualAddress;
                size_t sectionSize = section.Misc.VirtualSize;

                // Read full text section in large chunks
                const size_t chunkSize = 0x200000; // 2MB
                for (size_t offset = 0; offset < sectionSize; offset += chunkSize - 64) {
                    size_t currentSize = min(chunkSize, sectionSize - offset);
                    std::vector<uint8_t> buffer(currentSize);
                    if (!ProcessScanner::ReadMemory(m_process, sectionStart + offset, buffer.data(), currentSize))
                        continue;

                    // Scan for LEA instructions referencing our string
                    for (size_t i = 0; i + 7 < currentSize; i++) {
                        // 48 8D 0D xx xx xx xx  (lea rcx, [rip+disp32])
                        // 48 8D 15 xx xx xx xx  (lea rdx, [rip+disp32])
                        // 4C 8D 05 xx xx xx xx  (lea r8, [rip+disp32])
                        if ((buffer[i] == 0x48 || buffer[i] == 0x4C) && buffer[i + 1] == 0x8D) {
                            uint8_t modrm = buffer[i + 2];
                            if ((modrm & 0xC7) == 0x05) { // [rip+disp32] addressing
                                int32_t disp = *reinterpret_cast<int32_t*>(&buffer[i + 3]);
                                uintptr_t instrAddr = sectionStart + offset + i;
                                uintptr_t targetAddr = instrAddr + 7 + disp;

                                if (targetAddr == stringAddr) {
                                    std::cout << "[*] Found LEA referencing 'TaskScheduler' at: 0x"
                                        << std::hex << instrAddr << std::dec << std::endl;

                                    // Now look nearby (before this instruction) for a mov rax, [rip+xxx]
                                    // which loads the TaskScheduler pointer
                                    // Search backwards up to 200 bytes
                                    size_t searchStart = (i > 200) ? i - 200 : 0;
                                    for (size_t j = searchStart; j < i; j++) {
                                        // 48 8B ?? ?? ?? ?? ??  (mov reg, [rip+disp32])
                                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x8B) {
                                            uint8_t mod = buffer[j + 2];
                                            if ((mod & 0xC7) == 0x05) { // [rip+disp32]
                                                int32_t d = *reinterpret_cast<int32_t*>(&buffer[j + 3]);
                                                uintptr_t globalAddr = (sectionStart + offset + j) + 7 + d;

                                                // Read the pointer at this global address
                                                uintptr_t tsPtr = ProcessScanner::Read<uintptr_t>(m_process, globalAddr);
                                                if (tsPtr > 0x10000 && tsPtr < 0x7FFFFFFFFFFF) {
                                                    std::cout << "[*] Candidate TaskScheduler global at: 0x"
                                                        << std::hex << globalAddr
                                                        << " -> 0x" << tsPtr << std::dec << std::endl;
                                                    return globalAddr;
                                                }
                                            }
                                        }
                                    }

                                    // Also search forward up to 100 bytes
                                    for (size_t j = i + 7; j < i + 100 && j + 7 < currentSize; j++) {
                                        if (buffer[j] == 0x48 && buffer[j + 1] == 0x8B) {
                                            uint8_t mod = buffer[j + 2];
                                            if ((mod & 0xC7) == 0x05) {
                                                int32_t d = *reinterpret_cast<int32_t*>(&buffer[j + 3]);
                                                uintptr_t globalAddr = (sectionStart + offset + j) + 7 + d;
                                                uintptr_t tsPtr = ProcessScanner::Read<uintptr_t>(m_process, globalAddr);
                                                if (tsPtr > 0x10000 && tsPtr < 0x7FFFFFFFFFFF) {
                                                    std::cout << "[*] Candidate TaskScheduler global at: 0x"
                                                        << std::hex << globalAddr
                                                        << " -> 0x" << tsPtr << std::dec << std::endl;
                                                    return globalAddr;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        return 0;
    }

    // Get the module's image size
    size_t GetModuleSize() {
        IMAGE_DOS_HEADER dosHeader{};
        if (!ProcessScanner::ReadMemory(m_process, m_base, &dosHeader, sizeof(dosHeader))) return 0;
        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!ProcessScanner::ReadMemory(m_process, m_base + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders))) return 0;
        return ntHeaders.OptionalHeader.SizeOfImage;
    }

private:
    HANDLE m_process;
    uintptr_t m_base;
};
