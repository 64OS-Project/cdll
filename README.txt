╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██████╗██████╗ ██╗     ██╗     ██╗   ██╗   ████████╗██╗  ██╗               ║
║  ██╔════╝██╔══██╗██║     ██║     ██║   ██║   ╚══██╔══╝██║  ██║               ║
║  ██║     ██║  ██║██║     ██║     ██║   ██║█████╗██║   ███████║               ║
║  ██║     ██║  ██║██║     ██║     ██║   ██║╚════╝██║   ██╔══██║               ║
║  ╚██████╗██████╔╝███████╗███████╗╚██████╔╝     ██║   ██║  ██║               ║
║   ╚═════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝      ╚═╝   ╚═╝  ╚═╝               ║
║                                                                               ║
║     Complete Dynamic Link Library Management Library for C                   ║
║                      Version 3.0.0 - Professional Edition                    ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝


┌───────────────────────────────────────────────────────────────────────────────┐
│                           TABLE OF CONTENTS                                   │
├───────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│   1. DESCRIPTION                                                              │
│   2. FEATURES                                                                 │
│   3. SYSTEM REQUIREMENTS                                                      │
│   4. COMPILATION                                                              │
│   5. QUICK START                                                              │
│   6. API REFERENCE                                                            │
│   7. EXAMPLES                                                                 │
│   8. PLATFORM-SPECIFIC NOTES                                                  │
│   9. SECURITY CONSIDERATIONS                                                  │
│   10. LICENSE                                                                 │
│   11. CONTACT                                                                 │
│                                                                               │
└───────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
1. DESCRIPTION
═══════════════════════════════════════════════════════════════════════════════

CDLL (Complete Dynamic Link Library) is a powerful, cross-platform,
single-header library for C that provides comprehensive functionality for
loading, analyzing, manipulating, and executing dynamic libraries and
executables across Windows, Linux, and macOS.

Unlike traditional approaches that require multiple libraries and complex
setup, CDLL is distributed as a single header file. Just include it and
you're ready to go.

Whether you need to:
  • Load DLLs/SOs/DYLIBs dynamically
  • Inject code into running processes
  • Hook and intercept function calls
  • Parse and analyze PE/ELF/Mach-O executables
  • Enumerate exports, imports, and sections
  • Patch memory with pattern matching
  • Execute code asynchronously with thread pools
  • Sandbox untrusted libraries
  • Verify digital signatures

CDLL provides a unified, consistent API that works the same way across all
supported platforms.


═══════════════════════════════════════════════════════════════════════════════
2. FEATURES
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ CORE FUNCTIONALITY                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Cross-platform: Windows (PE32/PE32+), Linux (ELF32/ELF64),               │
│   macOS (Mach-O)                                                            │
│ ✓ Load/unload/reload dynamic libraries                                      │
│ ✓ Thread-safe reference counting with atomic operations                     │
│ ✓ Symbol caching with TTL (Time-To-Live)                                    │
│ ✓ Delay-load DLL (load on first call)                                       │
│ ✓ Get function pointers by name or ordinal (Windows)                        │
│ ✓ C++ symbol demangling (MSVC and Itanium ABI)                              │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ PROCESS & MEMORY MANIPULATION                                               │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Remote DLL injection into running processes                               │
│ ✓ DLL unloading from remote processes                                       │
│ ✓ Process enumeration by name or PID                                        │
│ ✓ Memory patching with pattern search and wildcard masks                    │
│ ✓ Hot patching without stopping execution                                   │
│ ✓ Memory region enumeration and analysis                                    │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXECUTABLE & DRIVER ANALYSIS                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Parse PE (.exe, .dll, .sys) files                                        │
│ ✓ Parse ELF (.elf, .so, .ko) files                                         │
│ ✓ Parse Mach-O (.dylib, .kext) files                                       │
│ ✓ Enumerate exports, imports, sections                                     │
│ ✓ Extract version information                                              │
│ ✓ Detect compiler and packer (UPX, MPRESS, etc.)                           │
│ ✓ Calculate section entropy (detect encryption/packing)                    │
│ ✓ Load executables to custom memory addresses                              │
│ ✓ Execute loaded executables with custom entry points                      │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ HOOKING & PATCHING                                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Function hooking (detouring) on Windows                                  │
│ ✓ Hot patching support                                                     │
│ ✓ Pattern-based memory search                                              │
│ ✓ Wildcard byte matching                                                   │
│ ✓ Backup and restore original bytes                                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ ASYNCHRONOUS & CONCURRENT EXECUTION                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Asynchronous function calls with future/promise pattern                  │
│ ✓ Thread pool with work stealing                                           │
│ ✓ Batch calls with parallel execution                                      │
│ ✓ Lock-free call queues                                                    │
│ ✓ Call graph analysis and profiling                                        │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ SECURITY FEATURES                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Sandboxing with seccomp-bpf (Linux), Landlock (Linux),                   │
│   sandbox_init (macOS)                                                     │
│ ✓ Digital signature validation (Authenticode on Windows,                    │
│   code signing on macOS)                                                   │
│ ✓ Anti-debugging protection detection                                      │
│ ✓ Anti-tamper integrity checks with SHA-256                                │
│ ✓ DEP/ASLR validation                                                      │
│ ✓ Stack overflow protection                                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ ADVANCED FEATURES                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✓ Encrypted DLL loading (XOR decryption)                                   │
│ ✓ Compressed DLL loading (zlib, lz4)                                       │
│ ✓ Library pooling with TTL                                                 │
│ ✓ Automatic garbage collection                                             │
│ ✓ Dependency cycle detection                                               │
│ ✓ DLL proxying with call logging                                           │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ STATISTICS                                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Lines of code: ~10,000                                                    │
│ • Functions: 150+                                                           │
│ • Supported platforms: Windows, Linux, macOS                                │
│ • Supported binary formats: PE32, PE32+, ELF32, ELF64, Mach-O               │
│ • Supported file types: .dll, .so, .dylib, .exe, .sys, .ko, .kext          │
│ • License: MIT                                                              │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
3. SYSTEM REQUIREMENTS
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ WINDOWS                                                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Windows 7 or later (x86/x64)                                              │
│ • Visual Studio 2015+ or MinGW-w64                                          │
│ • pthreads-w32 (for threading support)                                      │
│ • Windows SDK (for version info, signatures)                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ LINUX                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Linux kernel 3.0+ (x86/x86_64, ARM64)                                     │
│ • GCC 4.8+ or Clang 3.5+                                                    │
│ • glibc 2.15+                                                               │
│ • libelf-dev (for ELF parsing)                                              │
│ • libseccomp-dev (optional, for sandboxing)                                 │
│ • zlib1g-dev (for compressed library support)                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ macOS                                                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ • macOS 10.12+ (Sierra or later)                                            │
│ • Xcode Command Line Tools                                                  │
│ • Clang (default compiler)                                                  │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
4. COMPILATION
═══════════════════════════════════════════════════════════════════════════════

CDLL is a single-header library. To use it, simply include the header and
define CDLL_IMPLEMENTATION in exactly ONE source file:

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 1: Basic usage (one file)                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   #define CDLL_IMPLEMENTATION                                               │
│   #include "cdll.h"                                                         │
│                                                                             │
│   int main() {                                                              │
│       cdll_library_t* lib = cdll_load_library("kernel32.dll");              │
│       // ...                                                                │
│       return 0;                                                             │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 2: Separate implementation                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   // cdll_impl.c                                                            │
│   #define CDLL_IMPLEMENTATION                                               │
│   #include "cdll.h"                                                         │
│                                                                             │
│   // main.c                                                                 │
│   #include "cdll.h"                                                         │
│                                                                             │
│   int main() {                                                              │
│       // ...                                                                │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ COMPILATION COMMANDS                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   Windows (MinGW-w64):                                                      │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ gcc -o myapp myapp.c -lpthread -lversion -lwintrust -lcrypt32       │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Windows (MSVC):                                                           │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ cl myapp.c /I. /link psapi.lib kernel32.lib dbghelp.lib version.lib │   │
│   │    wintrust.lib crypt32.lib advapi32.lib                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   Linux:                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ gcc -o myapp myapp.c -lpthread -ldl -lz -lrt -lm                    │   │
│   │   (add -lseccomp if sandboxing is needed)                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   macOS:                                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ gcc -o myapp myapp.c -lpthread -ldl -lz                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
5. QUICK START
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 1: Load a library and call a function                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   #define CDLL_IMPLEMENTATION                                               │
│   #include "cdll.h"                                                         │
│   #include <stdio.h>                                                        │
│                                                                             │
│   int main() {                                                              │
│       // Load library                                                       │
│       cdll_library_t* lib = cdll_load_library("user32.dll");                │
│       if (!lib) {                                                           │
│           printf("Error: %s\n", cdll_get_error_message());                  │
│           return 1;                                                         │
│       }                                                                     │
│                                                                             │
│       // Get function                                                       │
│       cdll_function_t* msgbox = cdll_get_function(lib, "MessageBoxA");      │
│       if (!msgbox) {                                                        │
│           printf("Function not found\n");                                   │
│           return 1;                                                         │
│       }                                                                     │
│                                                                             │
│       // Call it                                                            │
│       CDLL_CALL(lib, "MessageBoxA", int, "HWND", NULL,                      │
│                 "LPCSTR", "Hello, CDLL!", "LPCSTR", "Title", "UINT", 0);    │
│                                                                             │
│       // Cleanup                                                            │
│       cdll_unload_library(lib);                                             │
│       return 0;                                                             │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 2: Enumerate exports from kernel32.dll                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   cdll_library_t* lib = cdll_load_library("kernel32.dll");                  │
│   cdll_export_entry_t exports[256];                                         │
│   size_t count = cdll_enumerate_exports(lib, exports, 256);                 │
│                                                                             │
│   for (size_t i = 0; i < count; i++) {                                      │
│       printf("%s @ %p\n", exports[i].name, exports[i].address);             │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 3: Find and patch a memory pattern                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   // Find pattern "48 89 5C 24 ?? 48 89 6C 24"                             │
│   uint8_t pattern[] = {0x48, 0x89, 0x5C, 0x24, 0x00,                       │
│                        0x48, 0x89, 0x6C, 0x24, 0x00};                       │
│   uint8_t mask[]    = {0xFF, 0xFF, 0xFF, 0xFF, 0x00,                       │
│                        0xFF, 0xFF, 0xFF, 0xFF, 0x00};                       │
│                                                                             │
│   void* addr = cdll_find_pattern(module_base, module_size,                  │
│                                   pattern, mask, sizeof(pattern));          │
│                                                                             │
│   if (addr) {                                                               │
│       uint8_t nops[] = {0x90, 0x90, 0x90, 0x90, 0x90,                       │
│                         0x90, 0x90, 0x90, 0x90, 0x90};                       │
│       cdll_memory_patch_t* patch = cdll_memory_patch_create(                │
│           addr, pattern, mask, sizeof(pattern), nops, sizeof(nops)          │
│       );                                                                     │
│       cdll_memory_patch_apply(patch);                                       │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 4: Inject DLL into a running process                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   uint32_t pids[256];                                                       │
│   size_t count;                                                             │
│   cdll_enumerate_processes(pids, &count, 256);                              │
│                                                                             │
│   for (size_t i = 0; i < count; i++) {                                      │
│       // Find target process                                                │
│       if (/* your condition */) {                                           │
│           cdll_injection_info_t info;                                       │
│           if (cdll_inject_dll(pids[i], "my_hook.dll", &info)) {             │
│               printf("Injected successfully!\n");                           │
│               cdll_unload_injected_dll(&info);                              │
│           }                                                                 │
│           break;                                                            │
│       }                                                                     │
│   }                                                                         │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXAMPLE 5: Asynchronous function call                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   cdll_function_t* func = cdll_get_function(lib, "process_data");           │
│   cdll_future_t* future = cdll_call_async(func, my_data);                   │
│                                                                             │
│   // Do other work...                                                       │
│                                                                             │
│   cdll_future_wait(future, 5000);  // Wait up to 5 seconds                  │
│   cdll_call_result_t result = cdll_future_get_result(future);               │
│   cdll_future_release(future);                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
6. API REFERENCE
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ CORE LIBRARY LOADING                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   cdll_library_t* cdll_load_library(const char* path);                      │
│       Load a dynamic library.                                               │
│                                                                             │
│   cdll_library_t* cdll_load_library_ex(const char* path, uint32_t flags);   │
│       Load with extended flags.                                             │
│                                                                             │
│   bool cdll_unload_library(cdll_library_t* lib);                            │
│       Unload a library (decrements refcount).                               │
│                                                                             │
│   bool cdll_reload_library(cdll_library_t* lib);                            │
│       Unload and reload a library.                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ FUNCTION MANAGEMENT                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   cdll_func_ptr cdll_get_function_raw(cdll_library_t* lib, const char* name);│
│       Get raw function pointer.                                             │
│                                                                             │
│   cdll_function_t* cdll_get_function(cdll_library_t* lib, const char* name);│
│       Get function with caching support.                                    │
│                                                                             │
│   bool cdll_has_function(cdll_library_t* lib, const char* name);            │
│       Check if function exists.                                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ CALLING MACROS                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CDLL_CALL(lib, name, ret_type, arg1_type, arg1, arg2_type, arg2, ...)    │
│       Call a function with up to 10 arguments.                              │
│                                                                             │
│   CDLL_CALL_VOID(lib, name, ...)                                            │
│       Call a void function.                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ EXECUTABLE & DRIVER ANALYSIS                                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   bool cdll_get_executable_info(const char* path,                           │
│                                  cdll_executable_info_t* info);             │
│       Get comprehensive executable information.                             │
│                                                                             │
│   size_t cdll_enumerate_executable_sections(const char* path,               │
│           cdll_executable_section_t* sections, size_t max);                 │
│       Enumerate all sections.                                               │
│                                                                             │
│   size_t cdll_enumerate_executable_imports(const char* path,                │
│           cdll_executable_import_t* imports, size_t max);                   │
│       Enumerate all imports.                                                │
│                                                                             │
│   size_t cdll_enumerate_executable_exports(const char* path,                │
│           cdll_executable_export_t* exports, size_t max);                   │
│       Enumerate all exports.                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ PROCESS INJECTION                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   bool cdll_inject_dll(uint32_t pid, const char* dll_path,                  │
│                        cdll_injection_info_t* info);                        │
│       Inject DLL into remote process.                                       │
│                                                                             │
│   bool cdll_unload_injected_dll(cdll_injection_info_t* info);               │
│       Unload injected DLL.                                                  │
│                                                                             │
│   bool cdll_enumerate_processes(uint32_t* pids, size_t* count,              │
│                                 size_t max_pids);                           │
│       Enumerate running processes.                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ MEMORY PATCHING                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   void* cdll_find_pattern(void* start, size_t size,                         │
│                           const uint8_t* pattern, const uint8_t* mask,      │
│                           size_t pattern_size);                             │
│       Find byte pattern with wildcard support.                              │
│                                                                             │
│   cdll_memory_patch_t* cdll_memory_patch_create(...);                       │
│       Create a memory patch.                                                │
│                                                                             │
│   bool cdll_memory_patch_apply(cdll_memory_patch_t* patch);                 │
│       Apply the patch.                                                      │
│                                                                             │
│   bool cdll_memory_patch_restore(cdll_memory_patch_t* patch);               │
│       Restore original bytes.                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ ASYNCHRONOUS EXECUTION                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   cdll_future_t* cdll_call_async(cdll_function_t* func, ...);               │
│       Execute function asynchronously.                                      │
│                                                                             │
│   bool cdll_future_wait(cdll_future_t* future, int timeout_ms);             │
│       Wait for completion.                                                  │
│                                                                             │
│   cdll_thread_pool_t* cdll_thread_pool_create(size_t thread_count);         │
│       Create a thread pool.                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ ERROR HANDLING                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   void cdll_clear_error(void);                                              │
│       Clear last error.                                                     │
│                                                                             │
│   const char* cdll_get_error_message(void);                                 │
│       Get last error message.                                               │
│                                                                             │
│   int cdll_get_error_code(void);                                            │
│       Get last error code.                                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ UTILITY FUNCTIONS                                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   const char* cdll_get_version(void);                                       │
│       Get library version.                                                  │
│                                                                             │
│   const char* cdll_get_os_name(void);                                       │
│       Get OS name.                                                          │
│                                                                             │
│   bool cdll_file_exists(const char* path);                                  │
│       Check if file exists.                                                 │
│                                                                             │
│   void cdll_add_search_path(const char* path);                              │
│       Add library search path.                                              │
│                                                                             │
│   void cdll_cleanup(void);                                                  │
│       Clean up all resources.                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
7. EXAMPLES
═══════════════════════════════════════════════════════════════════════════════

Complete examples are available in the examples/ directory:

  • basic_usage.c        - Loading libraries and calling functions
  • enumerate_exports.c  - Listing all exported functions
  • inject_notepad.c     - Injecting DLL into Notepad
  • pattern_search.c     - Finding and patching memory patterns
  • async_calls.c        - Asynchronous function execution
  • parse_executable.c   - Analyzing PE/ELF/Mach-O files
  • sandbox_example.c    - Isolating untrusted code
  • driver_analysis.c    - Parsing kernel drivers (.sys/.ko/.kext)


═══════════════════════════════════════════════════════════════════════════════
8. PLATFORM-SPECIFIC NOTES
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ WINDOWS SPECIFIC                                                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   • Hook functions are fully supported (x86/x64 detours)                    │
│   • Remote injection uses CreateRemoteThread                                │
│   • Digital signature verification via WinTrust                            │
│   • Version info extraction via VerQueryValue                               │
│   • Delay-load imports are supported                                        │
│   • TLS callbacks are executed on load                                      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ LINUX SPECIFIC                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   • Hooking is currently limited (stub implementation)                      │
│   • Remote injection uses ptrace                                           │
│   • Sandboxing via seccomp-bpf and Landlock                                 │
│   • ELF .ko (kernel module) parsing support                                 │
│   • TLS via arch_prctl                                                      │
│   • Init/fini array execution                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ macOS SPECIFIC                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   • Hooking is currently limited (stub implementation)                      │
│   • Sandboxing via sandbox_init                                            │
│   • Kext (kernel extension) parsing support                                 │
│   • FAT binary (universal) support                                          │
│   • Bundle (.app) detection and parsing                                     │
│   • Code signing verification                                               │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
9. SECURITY CONSIDERATIONS
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│ ⚠️  IMPORTANT DISCLAIMER                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   CDLL provides powerful low-level system access. This library is          │
│   intended for legitimate purposes only:                                    │
│                                                                             │
│   ✓ Security research and vulnerability analysis                           │
│   ✓ Reverse engineering for malware analysis                               │
│   ✓ Debugging and testing tools                                            │
│   ✓ Educational purposes                                                    │
│   ✓ Game modding (single-player)                                           │
│   ✓ Automation and RPA tools                                               │
│                                                                             │
│   ✗ Creating cheats for online games                                       │
│   ✗ Developing malware or ransomware                                       │
│   ✗ Bypassing license checks                                               │
│   ✗ Unauthorized access to systems                                         │
│                                                                             │
│   The author assumes no responsibility for misuse of this library.         │
│   By using CDLL, you agree to comply with all applicable laws and          │
│   regulations.                                                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ BEST PRACTICES                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   1. Always check return values and use error handling                      │
│   2. Use sandboxing when loading untrusted libraries                        │
│   3. Verify digital signatures when loading system libraries               │
│   4. Clean up resources with cdll_cleanup()                                 │
│   5. Use library pooling for frequently loaded libraries                    │
│   6. Enable anti-tamper for critical code                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════════
10. LICENSE
═══════════════════════════════════════════════════════════════════════════════

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


═══════════════════════════════════════════════════════════════════════════════
11. CONTACT & SUPPORT
═══════════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   • GitHub: https://github.com/64OS-Project/cdll                            │
│   • Issues: https://github.com/64OS-Project/cdll/issues                     │
│                                                                             │
│   For bug reports, please include:                                          │
│     - Operating system and version                                          │
│     - Compiler version                                                      │
│     - Minimal code to reproduce the issue                                   │
│     - Expected vs actual behavior                                           │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘


╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║                         CDLL - Professional Grade                            ║
║                   Complete Dynamic Link Library Management                   ║
║                                                                               ║
║                          Version 3.0.0 - MIT License                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
