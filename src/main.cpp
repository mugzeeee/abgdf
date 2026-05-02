#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <iomanip>
#include <algorithm>

#include "syscalls/syscalls.h"
#include "process/scanner.h"
#include "offsets.h"

// Improved string reader that handles both SSO and Heap strings
std::string ReadRobloxString(HANDLE h, uintptr_t address) {
    if (address < 0x10000 || address > 0x7FFFFFFFFFFF) return "";

    struct RobloxString {
        union {
            char buffer[16];
            char* ptr;
        };
        size_t length;
        size_t capacity;
    } strData;

    if (!ProcessScanner::ReadMemory(h, address, &strData, sizeof(strData))) return "";
    if (strData.length == 0 || strData.length > 200) return "";

    std::string result;
    if (strData.length < 16) {
        result = std::string(strData.buffer, strData.length);
    } else {
        uintptr_t dataAddr = reinterpret_cast<uintptr_t>(strData.ptr);
        if (dataAddr < 0x10000 || dataAddr > 0x7FFFFFFFFFFF) return "";
        std::vector<char> buffer(strData.length + 1, 0);
        if (ProcessScanner::ReadMemory(h, dataAddr, buffer.data(), strData.length)) {
            result = std::string(buffer.data(), strData.length);
        }
    }

    for (char& c : result) {
        if (c < 32 || c > 126) return "";
    }
    return result;
}

int main() {
    std::cout << "===================================\n";
    std::cout << "   Roblox Executor - Final Discovery\n";
    std::cout << "===================================\n";

    if (!SyscallResolver::Initialize()) return 1;

    auto pids = ProcessScanner::FindRobloxProcesses();
    while (pids.empty()) { 
        std::this_thread::sleep_for(std::chrono::seconds(1)); 
        pids = ProcessScanner::FindRobloxProcesses(); 
    }

    for (auto pid : pids) {
        auto roblox = ProcessScanner::Connect(pid);
        if (!roblox) continue;
        
        HANDLE h = roblox->handle;
        uintptr_t base = roblox->baseAddress;
        uintptr_t ts = ProcessScanner::Read<uintptr_t>(h, base + offsets::Pointer::TaskScheduler);
        if (!ts) continue;

        uintptr_t jS = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobStart);
        uintptr_t jE = ProcessScanner::Read<uintptr_t>(h, ts + offsets::TaskScheduler::JobEnd);
        size_t count = (jE > jS) ? (jE - jS) / 8 : 0;
        if (count < 10) continue;

        std::cout << "\n[+] PID " << pid << " (" << count << " jobs)\n";

        uintptr_t foundDM = 0;
        for (size_t i = 0; i < count; i++) {
            uintptr_t job = ProcessScanner::Read<uintptr_t>(h, jS + i * 8);
            if (!job) continue;

            std::string jobName = ReadRobloxString(h, job + offsets::Jobs::JobName);
            if (jobName.empty()) continue;

            std::vector<uintptr_t> jobMem(0x80, 0); 
            ProcessScanner::ReadMemory(h, job, jobMem.data(), jobMem.size() * 8);

            for (size_t k = 0; k < jobMem.size(); k++) {
                uintptr_t ptr = jobMem[k];
                if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF || (ptr % 8 != 0)) continue;

                uintptr_t cd = ProcessScanner::Read<uintptr_t>(h, ptr + 0x18);
                if (cd < 0x7FF000000000 || cd > 0x7FFFFFF00000 || (cd % 8 != 0)) continue;

                std::string className = ReadRobloxString(h, cd + 0x8);
                if (className == "DataModel") {
                    std::cout << "  [!!!] FOUND DataModel in \"" << jobName << "\" at +0x" << std::hex << (k*8) << std::dec << "\n";
                    foundDM = ptr;
                    break;
                }
            }
            if (foundDM) break;
        }

        if (foundDM) {
            uintptr_t childOffsets[] = { 0xF8, 0x100, 0x108, 0x110, 0x70 };
            for (auto off : childOffsets) {
                uintptr_t s = ProcessScanner::Read<uintptr_t>(h, foundDM + off);
                uintptr_t e = ProcessScanner::Read<uintptr_t>(h, foundDM + off + 8);
                if (s && e > s && (e - s) % 8 == 0) {
                    size_t cCount = (e - s) / 8;
                    if (cCount >= 10 && cCount < 100) {
                        std::cout << "      Services at +0x" << std::hex << off << std::dec << " (count: " << cCount << ")\n";
                        std::vector<uintptr_t> children(cCount);
                        ProcessScanner::ReadMemory(h, s, children.data(), cCount * 8);
                        for (size_t j = 0; j < (cCount < 10 ? cCount : 10); j++) {
                            uintptr_t c = children[j];
                            if (!c) continue;
                            uintptr_t ccd = ProcessScanner::Read<uintptr_t>(h, c + 0x18);
                            std::string ccn = ReadRobloxString(h, ccd + 0x8);
                            std::cout << "        [" << j << "] " << ccn << "\n";
                        }
                        break;
                    }
                }
            }
        } else {
            std::cout << "  [-] DataModel not found.\n";
        }
    }

    std::cout << "\nDone. Press Enter...\n";
    std::string dummy;
    std::getline(std::cin, dummy);
    return 0;
}
