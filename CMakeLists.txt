cmake_minimum_required(VERSION 3.10)
project(Syntax)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Force static linking of VC++ runtime (/MT)
if(MSVC)
    set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
    )
    foreach(CompilerFlag ${CompilerFlags})
        string(REPLACE "/MD" "/MT" ${CompilerFlag} "${${CompilerFlag}}")
    endforeach()
endif()

# ---- Zlib (kept for compatibility) ----
include(FetchContent)
FetchContent_Declare(
    zlib
    GIT_REPOSITORY https://github.com/madler/zlib.git
    GIT_TAG v1.3.1
)
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zlib)

# ---- ZSTD (for RSB1 bytecode encoding - confirmed from Xeno RE) ----
FetchContent_Declare(
    zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG v1.5.6
    SOURCE_SUBDIR build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZSTD_MULTITHREAD_SUPPORT OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)
set(ZSTD_LEGACY_SUPPORT OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# ---- BLAKE3 (for bytecode signing - required by Roblox) ----
FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG 1.8.2
    SOURCE_SUBDIR c
)
set(BLAKE3_FETCH_CONTENT ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(blake3)

# ---- cpp-httplib (header-only HTTP server for Lua<->C++ communication) ----
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.18.3
)
set(HTTPLIB_COMPILE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_REQUIRE_OPENSSL OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(httplib)

# ---- nlohmann/json (for HTTP message parsing) ----
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(json)

# ---- Luau Compiler (bytecode compilation) ----
# We only need Compiler + Ast + Common (not VM, CodeGen, etc.)
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/luau EXCLUDE_FROM_ALL)

# Identify core source files (everything except main)
file(GLOB_RECURSE CORE_SOURCES 
    "src/syscalls/*.cpp" 
    "src/syscalls/*.asm"
    "src/process/*.cpp" 
    "src/memory/*.cpp"
    "src/execution/*.cpp"
    "src/exports.cpp"
)

# Force MASM for the syscall file
set_source_files_properties("src/syscalls/syscalls.asm" PROPERTIES LANGUAGE ASM_MASM)

# Enable MASM
enable_language(ASM_MASM)

# Include directories
include_directories(src)
include_directories(include)

# Build the Core DLL
add_library(Syntax SHARED ${CORE_SOURCES})
target_compile_definitions(Syntax PRIVATE RBLX_EXPORT WIN32_LEAN_AND_MEAN NOMINMAX)
set_target_properties(Syntax PROPERTIES LINKER_LANGUAGE CXX)

# Link Luau Compiler + Ast libraries
target_link_libraries(Syntax PRIVATE 
    kernel32 user32 winhttp ws2_32
    Luau.Compiler Luau.Ast
    zlibstatic
    libzstd_static
    blake3
    httplib::httplib
    nlohmann_json::nlohmann_json
)

# Add Luau include paths
target_include_directories(Syntax PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Compiler/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Ast/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Common/include
    ${zlib_SOURCE_DIR}
    ${zlib_BINARY_DIR}
    ${zstd_SOURCE_DIR}/lib
    ${zstd_SOURCE_DIR}/lib/common
    ${blake3_SOURCE_DIR}/c
)
