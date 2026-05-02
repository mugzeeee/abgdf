#pragma once
// ============================================================================
// Roblox Process Scanner
//
// Finds running Roblox instances, gets their base address, and provides
// handles for memory operations via direct syscalls.
// ============================================================================

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <iostream>
#include "syscalls/syscalls.h"

struct RobloxProcess {
    DWORD pid = 0;
    uintptr_t baseAddress = 0;
    HANDLE handle = nullptr;
    int state = 0; // 0=found, 1=attached, 2=runtime_injected, 3=ready

    RobloxProcess() = default;

    // Move constructor — transfers handle ownership
    RobloxProcess(RobloxProcess&& other) noexcept
        : pid(other.pid), baseAddress(other.baseAddress),
          handle(other.handle), state(other.state) {
        other.handle = nullptr; // prevent source from closing it
    }

    // Move assignment
    RobloxProcess& operator=(RobloxProcess&& other) noexcept {
        if (this != &other) {
            if (handle) syscall::NtClose(handle);
            pid = other.pid;
            baseAddress = other.baseAddress;
            handle = other.handle;
            state = other.state;
            other.handle = nullptr;
        }
        return *this;
    }

    // No copying — handle is exclusive
    RobloxProcess(const RobloxProcess&) = delete;
    RobloxProcess& operator=(const RobloxProcess&) = delete;

    ~RobloxProcess() {
        if (handle) {
            syscall::NtClose(handle);
            handle = nullptr;
        }
    }
};

class ProcessScanner {
public:
    // Find all running Roblox processes
    static std::vector<DWORD> FindRobloxProcesses() {
        std::vector<DWORD> pids;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return pids;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                std::wstring name(pe.szExeFile);
                if (name == L"RobloxPlayerBeta.exe" || name == L"Windows10Universal.exe") {
                    pids.push_back(pe.th32ProcessID);
                }
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
        return pids;
    }

    // Get the base address of the main module
    static uintptr_t GetBaseAddress(DWORD pid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        uintptr_t base = 0;
        if (Module32FirstW(snapshot, &me)) {
            base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        }

        CloseHandle(snapshot);
        return base;
    }

    // Open a process handle via direct syscall
    static HANDLE OpenProcess(DWORD pid) {
        HANDLE hProcess = nullptr;

        // Must match the REAL NT OBJECT_ATTRIBUTES layout exactly!
        // See: https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
        struct NT_OBJECT_ATTRIBUTES {
            ULONG Length;
            HANDLE RootDirectory;
            void* ObjectName;     // PUNICODE_STRING
            ULONG Attributes;
            void* SecurityDescriptor;
            void* SecurityQualityOfService;
        };

        struct NT_CLIENT_ID {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        };

        NT_OBJECT_ATTRIBUTES oa{};
        oa.Length = sizeof(NT_OBJECT_ATTRIBUTES);

        NT_CLIENT_ID cid{};
        cid.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid));
        cid.UniqueThread = nullptr;

        std::cout << "[DBG] NtOpenProcess: sizeof(OA)=" << sizeof(NT_OBJECT_ATTRIBUTES) 
                  << " sizeof(CID)=" << sizeof(NT_CLIENT_ID)
                  << " pid=" << pid << std::endl;

        NTSTATUS status = syscall::NtOpenProcess(
            &hProcess,
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
            &oa,
            &cid
        );

        std::cout << "[DBG] NtOpenProcess result: status=0x" << std::hex << (uint32_t)status 
                  << " handle=0x" << (uintptr_t)hProcess << std::dec << std::endl;

        if (status != 0) {
            std::cerr << "[-] NtOpenProcess failed: 0x" << std::hex << (uint32_t)status << std::dec << std::endl;
            return nullptr;
        }

        return hProcess;
    }

    // Read memory from target process
    static bool ReadMemory(HANDLE hProcess, uintptr_t address, void* buffer, size_t size) {
        SIZE_T bytesRead = 0;
        NTSTATUS status = syscall::NtReadVirtualMemory(
            hProcess,
            reinterpret_cast<PVOID>(address),
            buffer,
            size,
            &bytesRead
        );
        return status == 0 && bytesRead == size;
    }

    // Write memory to target process
    static bool WriteMemory(HANDLE hProcess, uintptr_t address, const void* buffer, size_t size) {
        SIZE_T bytesWritten = 0;
        NTSTATUS status = syscall::NtWriteVirtualMemory(
            hProcess,
            reinterpret_cast<PVOID>(address),
            const_cast<PVOID>(static_cast<const void*>(buffer)),
            size,
            &bytesWritten
        );
        return status == 0 && bytesWritten == size;
    }

    // Read a single value
    template<typename T>
    static T Read(HANDLE hProcess, uintptr_t address) {
        T value{};
        ReadMemory(hProcess, address, &value, sizeof(T));
        return value;
    }

    // Read a string (Roblox uses std::string with SSO)
    static std::string ReadString(HANDLE hProcess, uintptr_t address) {
        // Roblox std::string layout (MSVC x64):
        // +0x00: union { char buf[16]; char* ptr; }
        // +0x10: size_t length
        // +0x18: size_t capacity
        
        size_t length = Read<size_t>(hProcess, address + 0x10);
        size_t capacity = Read<size_t>(hProcess, address + 0x18);

        if (length == 0 || length > 4096) return "";

        std::string result(length, '\0');

        if (capacity > 15) {
            // Long string — data is on the heap, read pointer first
            uintptr_t ptr = Read<uintptr_t>(hProcess, address);
            if (ptr == 0) return "";
            ReadMemory(hProcess, ptr, result.data(), length);
        } else {
            // Short string — data is inline (SSO)
            ReadMemory(hProcess, address, result.data(), length);
        }

        return result;
    }

    // Initialize and connect to a Roblox instance
    static std::optional<RobloxProcess> Connect(DWORD pid) {
        RobloxProcess rblx;
        rblx.pid = pid;
        rblx.baseAddress = GetBaseAddress(pid);
        
        if (rblx.baseAddress == 0) {
            std::cerr << "[-] Failed to get base address for PID " << pid << std::endl;
            return std::nullopt;
        }

        rblx.handle = OpenProcess(pid);
        if (!rblx.handle) {
            return std::nullopt;
        }

        rblx.state = 0;
        return rblx;
    }
};
