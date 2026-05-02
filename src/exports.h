#pragma once
#include <windows.h>
#include <string>

#ifdef RBLX_EXPORT
#define RBLX_API __declspec(dllexport)
#else
#define RBLX_API __declspec(dllimport)
#endif

extern "C" {
    // Basic lifecycle
    RBLX_API bool __stdcall Initialize();
    RBLX_API DWORD __stdcall FindRobloxProcess();
    RBLX_API bool __stdcall Connect(DWORD pid);
    RBLX_API void __stdcall Disconnect();
    RBLX_API DWORD __stdcall GetRobloxPid();
    RBLX_API void __stdcall RedirConsole();

    // DataModel discovery
    RBLX_API uintptr_t __stdcall GetDataModel();
    RBLX_API int __stdcall GetJobCount();

    // Script execution
    RBLX_API int __stdcall ExecuteScript(const char* source, int sourceLen);
    RBLX_API int __stdcall GetLastExecError(char* buffer, int bufLen);

    // Memory operations (wrapped for C# ease)
    RBLX_API bool __stdcall ReadMemory(uintptr_t address, void* buffer, size_t size);
    RBLX_API bool __stdcall WriteMemory(uintptr_t address, const void* buffer, size_t size);

    // Dynamic data
    RBLX_API bool __stdcall GetClientInfo(char* buffer, int maxSize);
}
