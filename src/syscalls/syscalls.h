#pragma once
// ============================================================================
// Direct Syscall Layer
// 
// Resolves System Service Numbers (SSNs) from ntdll.dll on disk and provides
// wrappers for NT functions. This avoids calling ntdll exports directly,
// which could be hooked by anti-cheat.
//
// How it works:
//   1. Map ntdll.dll from disk (not the in-memory version which could be hooked)
//   2. Parse the export table to find Nt* functions
//   3. Read the SSN from the function prologue (mov eax, SSN pattern)
//   4. Use our own syscall stub with the resolved SSN
// ============================================================================

#include <WinSock2.h>
#include <Windows.h>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <stdexcept>
#include <filesystem>

// Define NTSTATUS before bcrypt.h can — bcrypt.h checks #ifndef _NTDEF_
#ifndef _NTDEF_
#define _NTDEF_
typedef LONG NTSTATUS;
typedef NTSTATUS *PNTSTATUS;
#endif

// NT types not always available in standard headers
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// CLIENT_ID for NtOpenProcess
typedef struct _MY_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} MY_CLIENT_ID, *PMY_CLIENT_ID;

// SSN storage — filled at runtime by the resolver
struct SyscallTable {
    uint32_t NtOpenProcess           = 0;
    uint32_t NtReadVirtualMemory     = 0;
    uint32_t NtWriteVirtualMemory    = 0;
    uint32_t NtAllocateVirtualMemory = 0;
    uint32_t NtFreeVirtualMemory     = 0;
    uint32_t NtProtectVirtualMemory  = 0;
    uint32_t NtSuspendProcess        = 0;
    uint32_t NtResumeProcess         = 0;
    uint32_t NtQueryInformationProcess = 0;
    uint32_t NtClose                 = 0;
};

inline SyscallTable g_syscalls{};

// ============================================================================
// SSN Resolver — reads ntdll.dll from disk to extract syscall numbers
// ============================================================================
class SyscallResolver {
public:
    static bool Initialize() {
        // Get ntdll path from system directory (read from disk, not hooked in-memory version)
        wchar_t sysDir[MAX_PATH];
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring ntdllPath = std::wstring(sysDir) + L"\\ntdll.dll";

        // Map the file into memory for parsing
        HANDLE hFile = CreateFileW(ntdllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                                    nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;

        HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping) { CloseHandle(hFile); return false; }

        LPVOID fileBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!fileBase) { CloseHandle(hMapping); CloseHandle(hFile); return false; }

        bool result = ParseExports(fileBase);

        UnmapViewOfFile(fileBase);
        CloseHandle(hMapping);
        CloseHandle(hFile);

        return result;
    }

private:
    static bool ParseExports(LPVOID fileBase) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBase);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(
            reinterpret_cast<uint8_t*>(fileBase) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        auto& exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0) return false;

        // Convert RVA to file offset
        auto rvaToOffset = [&](DWORD rva) -> uint8_t* {
            auto sections = IMAGE_FIRST_SECTION(ntHeaders);
            for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
                if (rva >= sections[i].VirtualAddress && 
                    rva < sections[i].VirtualAddress + sections[i].SizeOfRawData) {
                    return reinterpret_cast<uint8_t*>(fileBase) + 
                           sections[i].PointerToRawData + (rva - sections[i].VirtualAddress);
                }
            }
            return nullptr;
        };

        auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(rvaToOffset(exportDir.VirtualAddress));
        if (!exports) return false;

        auto names    = reinterpret_cast<DWORD*>(rvaToOffset(exports->AddressOfNames));
        auto funcs    = reinterpret_cast<DWORD*>(rvaToOffset(exports->AddressOfFunctions));
        auto ordinals = reinterpret_cast<WORD*>(rvaToOffset(exports->AddressOfNameOrdinals));

        // Map of function names we need → pointer to SSN storage
        std::unordered_map<std::string, uint32_t*> needed = {
            {"NtOpenProcess",              &g_syscalls.NtOpenProcess},
            {"NtReadVirtualMemory",        &g_syscalls.NtReadVirtualMemory},
            {"NtWriteVirtualMemory",       &g_syscalls.NtWriteVirtualMemory},
            {"NtAllocateVirtualMemory",    &g_syscalls.NtAllocateVirtualMemory},
            {"NtFreeVirtualMemory",        &g_syscalls.NtFreeVirtualMemory},
            {"NtProtectVirtualMemory",     &g_syscalls.NtProtectVirtualMemory},
            {"NtSuspendProcess",           &g_syscalls.NtSuspendProcess},
            {"NtResumeProcess",            &g_syscalls.NtResumeProcess},
            {"NtQueryInformationProcess",  &g_syscalls.NtQueryInformationProcess},
            {"NtClose",                    &g_syscalls.NtClose},
        };

        int found = 0;
        for (DWORD i = 0; i < exports->NumberOfNames; i++) {
            auto name = reinterpret_cast<const char*>(rvaToOffset(names[i]));
            if (!name) continue;

            auto it = needed.find(name);
            if (it == needed.end()) continue;

            // Get the function body
            auto funcBody = rvaToOffset(funcs[ordinals[i]]);
            if (!funcBody) continue;

            // Extract SSN from the syscall stub pattern:
            //   4C 8B D1          mov r10, rcx
            //   B8 XX XX 00 00    mov eax, SSN
            if (funcBody[0] == 0x4C && funcBody[1] == 0x8B && funcBody[2] == 0xD1 &&
                funcBody[3] == 0xB8) {
                uint32_t ssn = *reinterpret_cast<uint32_t*>(funcBody + 4);
                *(it->second) = ssn;
                found++;
            }

            if (found == static_cast<int>(needed.size())) break;
        }

        return found == static_cast<int>(needed.size());
    }
};

// ============================================================================
// Syscall interface (implemented in syscalls.asm)
//
// DoSyscall uses explicit void* parameters so the compiler generates correct
// x64 register assignments (RCX, RDX, R8, R9, stack). 
// No variadic (...) — that can cause MSVC to mishandle arg passing.
// ============================================================================
extern "C" {
    extern uint32_t currentSSN;
    // Max 6 args covers all NT functions we need
    NTSTATUS DoSyscall(void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
}

// ============================================================================
// Clean C++ wrappers — set SSN, cast args to void*, call DoSyscall
// ============================================================================
namespace syscall {

    inline NTSTATUS NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        void* ObjectAttributes,
        void* ClientId
    ) {
        currentSSN = g_syscalls.NtOpenProcess;
        return DoSyscall(
            (void*)ProcessHandle,
            (void*)(uintptr_t)DesiredAccess,
            (void*)ObjectAttributes,
            (void*)ClientId,
            nullptr, nullptr
        );
    }

    inline NTSTATUS NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    ) {
        currentSSN = g_syscalls.NtReadVirtualMemory;
        return DoSyscall(
            (void*)ProcessHandle,
            (void*)BaseAddress,
            (void*)Buffer,
            (void*)NumberOfBytesToRead,
            (void*)NumberOfBytesRead,
            nullptr
        );
    }

    inline NTSTATUS NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    ) {
        currentSSN = g_syscalls.NtWriteVirtualMemory;
        return DoSyscall(
            (void*)ProcessHandle,
            (void*)BaseAddress,
            (void*)Buffer,
            (void*)NumberOfBytesToWrite,
            (void*)NumberOfBytesWritten,
            nullptr
        );
    }

    inline NTSTATUS NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    ) {
        currentSSN = g_syscalls.NtAllocateVirtualMemory;
        return DoSyscall(
            (void*)ProcessHandle,
            (void*)BaseAddress,
            (void*)ZeroBits,
            (void*)RegionSize,
            (void*)(uintptr_t)AllocationType,
            (void*)(uintptr_t)Protect
        );
    }

    inline NTSTATUS NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    ) {
        currentSSN = g_syscalls.NtProtectVirtualMemory;
        return DoSyscall(
            (void*)ProcessHandle,
            (void*)BaseAddress,
            (void*)RegionSize,
            (void*)(uintptr_t)NewProtect,
            (void*)OldProtect,
            nullptr
        );
    }

    inline NTSTATUS NtSuspendProcess(HANDLE ProcessHandle) {
        currentSSN = g_syscalls.NtSuspendProcess;
        return DoSyscall((void*)ProcessHandle, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    inline NTSTATUS NtResumeProcess(HANDLE ProcessHandle) {
        currentSSN = g_syscalls.NtResumeProcess;
        return DoSyscall((void*)ProcessHandle, nullptr, nullptr, nullptr, nullptr, nullptr);
    }

    inline NTSTATUS NtClose(HANDLE Handle) {
        currentSSN = g_syscalls.NtClose;
        return DoSyscall((void*)Handle, nullptr, nullptr, nullptr, nullptr, nullptr);
    }
}

