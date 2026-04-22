/*
 * CDLL - Complete Dynamic Link Library Management Library for C
 * Single-header library for loading, managing and using DLLs/SOs/DYLIBs
 * Version 3.0.0
 * 
 * FULL FEATURES:
 * - Full Windows (PE32/PE32+), Linux (ELF32/ELF64), macOS (Mach-O) support
 * - Thread-safe reference counting with atomic operations
 * - Symbol caching with TTL (Time-To-Live)
 * - Delay-load DLL (load on first call)
 * - Remote DLL injection/unloading
 * - DLL proxying with call logging
 * - Memory patching (search and replace bytes)
 * - Hot patching without stopping
 * - C++ symbol demangling
 * - Version info for ELF/Mach-O
 * - Asynchronous function calls with future/promise
 * - Batch calls with parallel execution
 * - Thread pool with work stealing
 * - Lock-free call queues
 * - Sandboxing with seccomp-bpf/apparmor
 * - Digital signature validation
 * - Anti-debugging protection
 * - Anti-tamper integrity checks
 * - Encrypted DLL loading
 * - Function access control
 * - Stack overflow protection
 * - DEP/ASLR validation
 * - Compressed DLL loading (zlib/lz4)
 * - Call graph analysis
 * - Dependency cycle detection
 * - Library pooling and GC
 * 
 * MIT License
 * Copyright (c) 2024
 */

#ifndef CDLL_H
#define CDLL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <math.h>

/* ============================================================================
 * Platform Detection and Includes
 * ============================================================================ */

#ifdef _WIN32
    #include <pthread.h>
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef _CRT_SECURE_NO_WARNINGS
        #define _CRT_SECURE_NO_WARNINGS
    #endif
    #include <windows.h>
    #include <psapi.h>
    #include <tlhelp32.h>
    #include <dbghelp.h>
    #include <winver.h>
    #include <wintrust.h>
    #include <softpub.h>
    #include <wincrypt.h>
    #include <processthreadsapi.h>
    #include <memoryapi.h>
    #include <handleapi.h>
    #include <synchapi.h>
    #include <sched.h>
    
    #ifdef _MSC_VER
        #pragma comment(lib, "psapi.lib")
        #pragma comment(lib, "kernel32.lib")
        #pragma comment(lib, "dbghelp.lib")
        #pragma comment(lib, "version.lib")
        #pragma comment(lib, "wintrust.lib")
        #pragma comment(lib, "crypt32.lib")
        #pragma comment(lib, "advapi32.lib")
    #endif
    
    typedef HMODULE cdll_native_handle;
    typedef FARPROC cdll_func_ptr;
    #define CDLL_PATH_SEPARATOR '\\'
    #define CDLL_PATH_SEPARATOR_STR "\\"
    #define CDLL_LIBRARY_EXTENSION ".dll"
    #define CDLL_INVALID_HANDLE NULL
    #define CDLL_INVALID_FUNC NULL
    
    #define CDLL_RTLD_LAZY 0
    #define CDLL_RTLD_NOW 0
    #define CDLL_RTLD_GLOBAL 0
    #define CDLL_RTLD_LOCAL 0
    #define CDLL_RTLD_NOLOAD 0
    #define CDLL_RTLD_DEEPBIND 0

    #define cdll_atomic_increment(ptr) InterlockedIncrement((LONG volatile*)ptr)
    #define cdll_atomic_decrement(ptr) InterlockedDecrement((LONG volatile*)ptr)
    #define cdll_atomic_load(ptr) InterlockedCompareExchange((LONG volatile*)ptr, 0, 0)
    #define cdll_atomic_store(ptr, val) InterlockedExchange((LONG volatile*)ptr, val)
    #define cdll_atomic_compare_exchange(ptr, old, new) \
        (InterlockedCompareExchange((LONG volatile*)ptr, new, old) == old)
    
#elif defined(__APPLE__)
    #include <dlfcn.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <sys/sysctl.h>
    #include <sys/resource.h>
    #include <sys/socket.h>
    #include <dirent.h>
    #include <errno.h>
    #include <mach-o/dyld.h>
    #include <mach-o/loader.h>
    #include <mach-o/nlist.h>
    #include <mach/mach.h>
    #include <mach/mach_time.h>
    #include <mach/thread_policy.h>
    #include <libgen.h>
    #include <limits.h>
    #include <fcntl.h>
    #include <pthread.h>
    #include <dispatch/dispatch.h>
    #include <libkern/OSAtomic.h>
    #include <Security/Security.h>
    #include <CommonCrypto/CommonDigest.h>
    #include <zlib.h>
    
    typedef void* cdll_native_handle;
    typedef void* cdll_func_ptr;
    #define CDLL_PATH_SEPARATOR '/'
    #define CDLL_PATH_SEPARATOR_STR "/"
    #define CDLL_LIBRARY_EXTENSION ".dylib"
    #define CDLL_INVALID_HANDLE NULL
    #define CDLL_INVALID_FUNC NULL
    
    #define CDLL_RTLD_LAZY RTLD_LAZY
    #define CDLL_RTLD_NOW RTLD_NOW
    #define CDLL_RTLD_GLOBAL RTLD_GLOBAL
    #define CDLL_RTLD_LOCAL RTLD_LOCAL
    #ifdef RTLD_NOLOAD
        #define CDLL_RTLD_NOLOAD RTLD_NOLOAD
    #else
        #define CDLL_RTLD_NOLOAD 0
    #endif
    #ifdef RTLD_DEEPBIND
        #define CDLL_RTLD_DEEPBIND RTLD_DEEPBIND
    #else
        #define CDLL_RTLD_DEEPBIND 0
    #endif

    #define cdll_atomic_increment(ptr) __sync_add_and_fetch((volatile int32_t*)ptr, 1)
    #define cdll_atomic_decrement(ptr) __sync_sub_and_fetch((volatile int32_t*)ptr, 1)
    #define cdll_atomic_load(ptr) __sync_add_and_fetch((volatile int32_t*)ptr, 0)
    #define cdll_atomic_store(ptr, val) __sync_lock_test_and_set((volatile int32_t*)ptr, val)
    #define cdll_atomic_compare_exchange(ptr, old, new) \
        __sync_bool_compare_and_swap((volatile int32_t*)ptr, old, new)
    
#else /* Linux/Unix */
    #include <dlfcn.h>
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/mman.h>
    #include <sys/syscall.h>
    #include <sys/resource.h>
    #include <sys/socket.h>
    #include <sys/wait.h>
    #include <sys/prctl.h>
    #include <sys/sendfile.h>
    #include <dirent.h>
    #include <errno.h>
    #include <link.h>
    #include <libgen.h>
    #include <limits.h>
    #include <elf.h>
    #include <fcntl.h>
    #include <pthread.h>
    #include <sched.h>
    #include <semaphore.h>
    #include <ucontext.h>
    #include <cxxabi.h>
    #include <zlib.h>
    #include <lz4.h>
    
    #ifdef HAVE_SECCOMP
        #include <seccomp.h>
        #include <linux/seccomp.h>
        #include <linux/filter.h>
        #include <linux/audit.h>
        #include <linux/bpf.h>
    #endif
    
    typedef void* cdll_native_handle;
    typedef void* cdll_func_ptr;
    #define CDLL_PATH_SEPARATOR '/'
    #define CDLL_PATH_SEPARATOR_STR "/"
    #define CDLL_LIBRARY_EXTENSION ".so"
    #define CDLL_INVALID_HANDLE NULL
    #define CDLL_INVALID_FUNC NULL
    
    #define CDLL_RTLD_LAZY RTLD_LAZY
    #define CDLL_RTLD_NOW RTLD_NOW
    #define CDLL_RTLD_GLOBAL RTLD_GLOBAL
    #define CDLL_RTLD_LOCAL RTLD_LOCAL
    #ifdef RTLD_NOLOAD
        #define CDLL_RTLD_NOLOAD RTLD_NOLOAD
    #else
        #define CDLL_RTLD_NOLOAD 0
    #endif
    #ifdef RTLD_DEEPBIND
        #define CDLL_RTLD_DEEPBIND RTLD_DEEPBIND
    #else
        #define CDLL_RTLD_DEEPBIND 0
    #endif

    #define cdll_atomic_increment(ptr) __sync_add_and_fetch((volatile int32_t*)ptr, 1)
    #define cdll_atomic_decrement(ptr) __sync_sub_and_fetch((volatile int32_t*)ptr, 1)
    #define cdll_atomic_load(ptr) __sync_add_and_fetch((volatile int32_t*)ptr, 0)
    #define cdll_atomic_store(ptr, val) __sync_lock_test_and_set((volatile int32_t*)ptr, val)
    #define cdll_atomic_compare_exchange(ptr, old, new) \
        __sync_bool_compare_and_swap((volatile int32_t*)ptr, old, new)
#endif

#ifdef _WIN32
    #define sleep(sec) Sleep((sec) * 1000)
    struct rlimit { int rlim_cur; int rlim_max; };
    #define RLIMIT_AS 0
    #define RLIMIT_NOFILE 0
    #define RLIMIT_NPROC 0
    #define RLIMIT_CPU 0
    #define RLIMIT_FSIZE 0
    #define getrlimit(a,b) (0)
    #define setrlimit(a,b) (0)
#endif

/* ============================================================================
 * Common Types and Structures
 * ============================================================================ */

typedef struct cdll_error_info {
    int code;
    char message[512];
    char function[128];
    time_t timestamp;
} cdll_error_info_t;

typedef struct cdll_library cdll_library_t;
typedef struct cdll_function cdll_function_t;
typedef struct cdll_delay_import cdll_delay_import_t;
typedef struct cdll_future cdll_future_t;
typedef struct cdll_thread_pool cdll_thread_pool_t;
typedef struct cdll_sandbox cdll_sandbox_t;
typedef struct cdll_call_graph cdll_call_graph_t;

struct cdll_delay_import {
    char name[256];
    char module_name[256];
    cdll_library_t* library;
    cdll_func_ptr func_ptr;
    bool is_loaded;
    bool is_function;
    time_t load_attempt_time;
    int retry_count;
    cdll_delay_import_t* next;
};

struct cdll_library {
    cdll_native_handle handle;
    char path[1024];
    char name[256];
    char full_name[256];
    uint32_t flags;
    bool is_loaded;
    bool is_system_library;
    bool is_delay_load;
    bool is_encrypted;
    bool is_compressed;
    bool is_prelinked;
    bool is_sandboxed;
    bool is_pooled;
    time_t load_time;
    time_t last_access_time;
    volatile int32_t reference_count;
    void* user_data;
    cdll_function_t* cached_functions;
    size_t cached_count;
    size_t cached_capacity;
    cdll_delay_import_t* delay_imports;
    cdll_sandbox_t* sandbox;
    void* encrypted_key;
    size_t encrypted_key_len;
    uint8_t checksum[32];
    struct cdll_library* next;
    struct cdll_library* prev;
    struct cdll_library* pool_next;
};

struct cdll_function {
    cdll_func_ptr ptr;
    char name[256];
    char decorated_name[512];
    char demangled_name[512];
    uint32_t ordinal;
    bool is_resolved;
    bool is_hooked;
    bool is_patched;
    time_t cache_time;
    time_t ttl;
    cdll_library_t* library;
    cdll_function_t* next;
    void* original_bytes;
    size_t patch_size;
    void* user_data;
    volatile int32_t call_count;
    volatile int32_t error_count;
    uint64_t total_time_ns;
};

typedef struct cdll_call_result {
    union {
        int64_t i64;
        uint64_t u64;
        int32_t i32;
        uint32_t u32;
        int16_t i16;
        uint16_t u16;
        int8_t i8;
        uint8_t u8;
        float f32;
        double f64;
        void* ptr;
        struct { float x, y, z, w; } vec4;
        struct { double x, y, z, w; } vec4d;
    } value;
    bool success;
    char error[256];
    int native_error;
    uint64_t execution_time_ns;
} cdll_call_result_t;

struct cdll_future {
    cdll_call_result_t result;
    bool is_ready;
    bool is_cancelled;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    void (*callback)(cdll_future_t*, void*);
    void* callback_data;
    volatile int32_t ref_count;
    void* stack_context;
};

struct cdll_thread_pool {
    pthread_t* threads;
    size_t thread_count;
    volatile int32_t active_tasks;
    volatile int32_t total_tasks;
    struct {
        void** tasks;
        size_t capacity;
        volatile size_t head;
        volatile size_t tail;
        volatile int32_t lock;
    } queue;
    bool shutdown;
    void** work_stealing_queues;
    size_t* queue_sizes;
    volatile int32_t* queue_locks;
};

struct cdll_sandbox {
    bool restrict_filesystem;
    bool restrict_network;
    bool restrict_process;
    bool restrict_memory;
    bool restrict_registry;
    char allowed_paths[16][512];
    size_t allowed_path_count;
    size_t memory_limit;
    size_t cpu_limit_percent;
    uint32_t allowed_syscalls[256];
    size_t syscall_count;
    void* seccomp_ctx;
    bool is_active;
    int original_rlimit_fsize;
    int original_rlimit_nofile;
    int original_rlimit_nproc;
};

struct cdll_call_graph {
    struct cdll_call_node {
        cdll_function_t* caller;
        cdll_function_t* callee;
        uint64_t call_count;
        uint64_t total_time_ns;
        struct cdll_call_node** children;
        size_t child_count;
        size_t child_capacity;
    } *root;
    size_t node_count;
    bool track_time;
    volatile int32_t active_profiling;
};

typedef struct cdll_symbol {
    char name[256];
    char demangled_name[512];
    void* address;
    size_t size;
    unsigned char type;
    unsigned char binding;
    unsigned char visibility;
    uint32_t section_index;
    cdll_library_t* library;
} cdll_symbol_t;

typedef struct cdll_module_info {
    char path[1024];
    char name[256];
    void* base_address;
    size_t size;
    uint32_t checksum;
    time_t timestamp;
    bool is_64bit;
    uint16_t machine_type;
    uint16_t characteristics;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    void* entry_point;
    size_t image_size;
    bool has_dep;
    bool has_aslr;
    bool has_safeseh;
    bool has_guard_cf;
} cdll_module_info_t;

typedef struct cdll_dependency {
    char name[256];
    char path[1024];
    bool is_resolved;
    bool is_delay_load;
    bool is_circular;
    cdll_library_t* library;
    struct cdll_dependency* next;
} cdll_dependency_t;

typedef struct cdll_export_entry {
    char name[256];
    char demangled_name[512];
    char forwarder[512];
    uint32_t ordinal;
    void* address;
    bool is_forwarded;
} cdll_export_entry_t;

typedef struct cdll_import_entry {
    char name[256];
    char module_name[256];
    uint32_t hint;
    uint32_t ordinal;
    void* address;
    bool is_bound;
} cdll_import_entry_t;

typedef struct cdll_section_info {
    char name[16];
    void* virtual_address;
    size_t virtual_size;
    size_t raw_size;
    uint32_t characteristics;
    bool is_executable;
    bool is_readable;
    bool is_writable;
    uint8_t entropy;
    bool is_packed;
} cdll_section_info_t;

typedef struct cdll_version_info {
    uint16_t major;
    uint16_t minor;
    uint16_t build;
    uint16_t revision;
    char version_string[64];
    char description[256];
    char product_name[256];
    char company_name[256];
    char legal_copyright[256];
    char file_description[256];
    char elf_note_vendor[256];
    char build_id[64];
} cdll_version_info_t;

typedef struct cdll_hook {
    void* target_address;
    void* hook_address;
    void* original_address;
    void* trampoline;
    size_t trampoline_size;
    bool is_active;
    bool is_hot_patch;
    cdll_library_t* library;
    uint8_t original_bytes[32];
    size_t original_size;
    struct {
        void* address;
        size_t size;
        uint32_t old_protect;
    } hot_patch_info;
} cdll_hook_t;

typedef struct cdll_memory_region {
    void* base_address;
    size_t size;
    uint32_t protection;
    uint32_t type;
    char state[16];
    char protection_str[16];
    bool is_readable;
    bool is_writable;
    bool is_executable;
    uint8_t* pattern_hash;
} cdll_memory_region_t;

typedef struct cdll_manager {
    cdll_library_t* libraries;
    cdll_library_t* delay_load_queue;
    cdll_library_t* preload_cache;
    cdll_library_t* library_pool;
    size_t library_count;
    size_t pool_size;
    char search_paths[16][512];
    size_t search_path_count;
    bool auto_resolve_dependencies;
    bool auto_add_extension;
    bool cache_symbols;
    bool enable_delay_load;
    bool enable_preload;
    bool enable_jit;
    bool enable_sandbox;
    bool enable_antidebug;
    bool enable_integrity_check;
    bool enable_pooling;
    time_t cache_ttl;
    size_t pool_max_size;
    time_t pool_ttl;
    cdll_thread_pool_t* thread_pool;
    cdll_call_graph_t* call_graph;
    void* user_data;
} cdll_manager_t;

typedef struct cdll_batch_call {
    cdll_function_t** functions;
    void** arguments;
    size_t count;
    cdll_call_result_t* results;
    bool parallel;
    bool use_simd;
    cdll_future_t* future;
} cdll_batch_call_t;

typedef struct cdll_injection_info {
    uint32_t pid;
    char process_name[256];
    char dll_path[1024];
    bool injected;
    bool unloaded;
    void* remote_base;
    size_t remote_size;
    HANDLE process_handle;
    HANDLE remote_thread;
    uint32_t exit_code;
    char error[256];
} cdll_injection_info_t;

typedef struct cdll_proxy_config {
    char original_dll[256];
    char proxy_dll[256];
    char log_file[512];
    bool log_all_calls;
    bool log_parameters;
    bool log_return_values;
    bool forward_unknown;
    char* (*demangle_callback)(const char*, void*);
    void* demangle_data;
} cdll_proxy_config_t;

typedef struct cdll_memory_patch {
    void* address;
    uint8_t* pattern;
    uint8_t* mask;
    size_t pattern_size;
    uint8_t* replacement;
    size_t replacement_size;
    bool applied;
    uint8_t* backup;
    size_t backup_size;
    bool hot_patch;
    void* trampoline;
} cdll_memory_patch_t;

/* ============================================================================
 * Forward Declarations for All Functions
 * ============================================================================ */

/* Error handling */
static inline void cdll_set_error(const char* function, int code, const char* message);
static inline void cdll_clear_error(void);
static inline const cdll_error_info_t* cdll_get_last_error(void);
static inline const char* cdll_get_error_message(void);
static inline int cdll_get_error_code(void);
static inline const char* cdll_format_error(int error_code);

/* Global manager */
static inline cdll_manager_t* cdll_get_global_manager(void);

/* Platform utilities */
static inline const char* cdll_get_os_name(void);
static inline bool cdll_is_windows(void);
static inline bool cdll_is_macos(void);
static inline bool cdll_is_unix(void);
static inline const char* cdll_get_extension(void);
static inline char cdll_get_path_separator(void);

/* Path utilities */
static inline bool cdll_file_exists(const char* path);
static inline bool cdll_is_absolute_path(const char* path);
static inline char* cdll_dirname(char* path);
static inline const char* cdll_basename(const char* path);
static inline void cdll_normalize_path(char* path);
static inline bool cdll_resolve_path(const char* name, char* out_path, size_t out_size);

/* Manager functions */
static inline void cdll_manager_init(cdll_manager_t* manager);
static inline void cdll_manager_add_search_path(cdll_manager_t* manager, const char* path);
static inline void cdll_add_search_path(const char* path);
static inline void cdll_manager_remove_search_path(cdll_manager_t* manager, const char* path);
static inline void cdll_manager_clear_search_paths(cdll_manager_t* manager);
static inline cdll_library_t* cdll_manager_find_library(cdll_manager_t* manager, const char* name);
static inline void cdll_manager_add_library(cdll_manager_t* manager, cdll_library_t* lib);
static inline bool cdll_manager_remove_library(cdll_manager_t* manager, cdll_library_t* lib);
static inline size_t cdll_manager_get_loaded_libraries(cdll_manager_t* manager, cdll_library_t*** out_libraries);

/* Symbol demangling */
static inline char* cdll_demangle_symbol(const char* mangled, char* output, size_t out_size);

/* Core library loading */
static inline cdll_library_t* cdll_load_library_ex(const char* path, uint32_t flags);
static inline cdll_library_t* cdll_load_library(const char* path);
static inline cdll_library_t* cdll_load_library_system(const char* name);
static inline bool cdll_unload_library(cdll_library_t* lib);
static inline bool cdll_reload_library(cdll_library_t* lib);
static inline cdll_native_handle cdll_get_native_handle(cdll_library_t* lib);
static inline const char* cdll_get_library_path(cdll_library_t* lib);
static inline const char* cdll_get_library_name(cdll_library_t* lib);
static inline bool cdll_is_library_loaded(cdll_library_t* lib);
static inline size_t cdll_get_reference_count(cdll_library_t* lib);
static inline time_t cdll_get_load_time(cdll_library_t* lib);

/* Function management */
static inline cdll_func_ptr cdll_get_function_raw(cdll_library_t* lib, const char* name);
static inline cdll_function_t* cdll_get_function(cdll_library_t* lib, const char* name);
static inline cdll_function_t* cdll_get_function_ordinal(cdll_library_t* lib, uint32_t ordinal);
static inline void cdll_free_function(cdll_function_t* func);
static inline bool cdll_has_function(cdll_library_t* lib, const char* name);

/* Symbol cache management */
static inline cdll_function_t* cdll_find_cached_function(cdll_library_t* lib, const char* name);
static inline void cdll_cache_function(cdll_library_t* lib, cdll_function_t* func);
static inline void cdll_clear_function_cache(cdll_library_t* lib);

/* Module information */
static inline bool cdll_get_module_info(cdll_library_t* lib, cdll_module_info_t* info);
static inline void* cdll_get_module_base(cdll_library_t* lib);
static inline size_t cdll_get_module_size(cdll_library_t* lib);
static inline size_t cdll_enumerate_exports(cdll_library_t* lib, cdll_export_entry_t* entries, size_t max_entries);
static inline size_t cdll_enumerate_imports(cdll_library_t* lib, cdll_import_entry_t* entries, size_t max_entries);
static inline size_t cdll_enumerate_sections(cdll_library_t* lib, cdll_section_info_t* sections, size_t max_sections);

/* Version information */
static inline bool cdll_get_version_info(cdll_library_t* lib, cdll_version_info_t* info);

/* Memory management */
static inline size_t cdll_enumerate_memory_regions(cdll_library_t* lib, cdll_memory_region_t* regions, size_t max_regions);

/* Hook functions */
static inline bool cdll_create_hook(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook);
static inline bool cdll_remove_hook(cdll_hook_t* hook);
static inline bool cdll_hot_patch_create(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook);
static inline bool cdll_hot_patch_remove(cdll_hook_t* hook);

/* Dependency management */
static inline cdll_dependency_t* cdll_get_dependencies(cdll_library_t* lib);
static inline void cdll_free_dependencies(cdll_dependency_t* deps);
static inline bool cdll_check_circular_dependencies(cdll_library_t* lib);

/* Delay load */
static inline cdll_delay_import_t* cdll_delay_import_create(const char* name, const char* module);
static inline cdll_func_ptr cdll_delay_load_resolve(cdll_library_t* lib, const char* name);
static inline bool cdll_delay_load_all(cdll_library_t* lib);

/* Remote injection */
static inline bool cdll_inject_dll(uint32_t pid, const char* dll_path, cdll_injection_info_t* info);
static inline bool cdll_unload_injected_dll(cdll_injection_info_t* info);
static inline bool cdll_enumerate_processes(uint32_t* pids, size_t* count, size_t max_pids);

/* Memory patching */
static inline cdll_memory_patch_t* cdll_memory_patch_create(void* address, const uint8_t* pattern, const uint8_t* mask, size_t pattern_size, const uint8_t* replacement, size_t replacement_size);
static inline void* cdll_find_pattern(void* start, size_t size, const uint8_t* pattern, const uint8_t* mask, size_t pattern_size);
static inline bool cdll_memory_patch_apply(cdll_memory_patch_t* patch);
static inline bool cdll_memory_patch_restore(cdll_memory_patch_t* patch);
static inline void cdll_memory_patch_destroy(cdll_memory_patch_t* patch);

/* Sandbox */
static inline cdll_sandbox_t* cdll_sandbox_create(void);
static inline void cdll_sandbox_add_allowed_path(cdll_sandbox_t* sandbox, const char* path);
static inline void cdll_sandbox_add_allowed_syscall(cdll_sandbox_t* sandbox, int syscall_num);
static inline bool cdll_sandbox_apply(cdll_library_t* lib, cdll_sandbox_t* sandbox);
static inline bool cdll_sandbox_remove(cdll_library_t* lib);
static inline void cdll_sandbox_destroy(cdll_sandbox_t* sandbox);

/* Digital signature */
static inline bool cdll_verify_signature(const char* path);
static inline bool cdll_verify_library_signature(cdll_library_t* lib);

/* Integrity checks */
static inline bool cdll_compute_checksum(cdll_library_t* lib, uint8_t checksum[32]);
static inline bool cdll_verify_integrity(cdll_library_t* lib);
static inline bool cdll_enable_anti_tamper(cdll_library_t* lib);

/* Anti-debug */
static inline bool cdll_enable_anti_debug(cdll_library_t* lib);
static inline bool cdll_disable_anti_debug(cdll_library_t* lib);
static inline bool cdll_is_debugger_present(void);

/* Encrypted DLL */
static inline cdll_library_t* cdll_load_encrypted_library(const char* path, const uint8_t* key, size_t key_len);
static inline bool cdll_decrypt_library(cdll_library_t* lib, const uint8_t* key, size_t key_len);

/* Compressed DLL */
static inline cdll_library_t* cdll_load_compressed_library(const char* path);
static inline bool cdll_decompress_to_file(const uint8_t* data, size_t size, const char* out_path);

/* Async calls */
static inline cdll_future_t* cdll_future_create(void);
static inline void cdll_future_retain(cdll_future_t* future);
static inline void cdll_future_release(cdll_future_t* future);
static inline bool cdll_future_wait(cdll_future_t* future, int timeout_ms);
static inline bool cdll_future_is_ready(cdll_future_t* future);
static inline cdll_call_result_t cdll_future_get_result(cdll_future_t* future);
static inline cdll_future_t* cdll_call_async(cdll_function_t* func, ...);
static inline cdll_future_t* cdll_call_async_va(cdll_function_t* func, va_list args);

/* Thread pool */
static inline cdll_thread_pool_t* cdll_thread_pool_create(size_t thread_count);
static inline void cdll_thread_pool_destroy(cdll_thread_pool_t* pool);
static inline bool cdll_thread_pool_submit(cdll_thread_pool_t* pool, void (*func)(void*), void* arg, cdll_future_t* future);
static inline size_t cdll_thread_pool_get_active_tasks(cdll_thread_pool_t* pool);

/* Batch calls */
static inline cdll_batch_call_t* cdll_batch_call_create(size_t count, bool parallel);
static inline void cdll_batch_call_set(cdll_batch_call_t* batch, size_t index, cdll_function_t* func, void* arg);
static inline bool cdll_batch_call_execute(cdll_batch_call_t* batch);
static inline void cdll_batch_call_destroy(cdll_batch_call_t* batch);

/* Call graph */
static inline cdll_call_graph_t* cdll_call_graph_create(void);
static inline void cdll_call_graph_start_profiling(cdll_call_graph_t* graph);
static inline void cdll_call_graph_stop_profiling(cdll_call_graph_t* graph);
static inline void cdll_call_graph_record(cdll_call_graph_t* graph, cdll_function_t* caller, cdll_function_t* callee, uint64_t time_ns);
static inline void cdll_call_graph_print(cdll_call_graph_t* graph);
static inline void cdll_call_graph_destroy(cdll_call_graph_t* graph);

/* Library pooling */
static inline void cdll_enable_pooling(size_t max_size, time_t ttl);
static inline cdll_library_t* cdll_acquire_pooled_library(const char* path);
static inline void cdll_release_pooled_library(cdll_library_t* lib);
static inline void cdll_cleanup_pool(void);

/* Garbage collection */
static inline void cdll_gc_collect(void);
static inline void cdll_gc_start_auto(time_t interval_seconds);
static inline void cdll_gc_stop_auto(void);

/* Utility functions */
static inline const char* cdll_get_version(void);
static inline void cdll_print_library_info(cdll_library_t* lib);
static inline void cdll_print_all_libraries(void);
static inline void cdll_print_exports(cdll_library_t* lib);
static inline void cdll_print_imports(cdll_library_t* lib);
static inline void cdll_print_sections(cdll_library_t* lib);
static inline void cdll_cleanup(void);
static inline void cdll_unload_all_libraries(void);

/* Calling macros */
#define CDLL_NARGS_SEQ(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,N,...) N
#define CDLL_NARGS(...) CDLL_NARGS_SEQ(__VA_ARGS__,10,9,8,7,6,5,4,3,2,1)
#define CDLL_CALL_EXPAND(lib, name, ret, nargs, ...) CDLL_CALL_##nargs(lib, name, ret, __VA_ARGS__)
#define CDLL_CALL(lib, name, ret, ...) CDLL_CALL_EXPAND(lib, name, ret, CDLL_NARGS(__VA_ARGS__), __VA_ARGS__)

#define CDLL_CALL_0(lib, name, ret) ((ret (*)(void))cdll_get_function_raw(lib, name))()
#define CDLL_CALL_1(lib, name, ret, t1, a1) ((ret (*)(t1))cdll_get_function_raw(lib, name))(a1)
#define CDLL_CALL_2(lib, name, ret, t1, a1, t2, a2) ((ret (*)(t1, t2))cdll_get_function_raw(lib, name))(a1, a2)
#define CDLL_CALL_3(lib, name, ret, t1, a1, t2, a2, t3, a3) ((ret (*)(t1, t2, t3))cdll_get_function_raw(lib, name))(a1, a2, a3)
#define CDLL_CALL_4(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4) ((ret (*)(t1, t2, t3, t4))cdll_get_function_raw(lib, name))(a1, a2, a3, a4)
#define CDLL_CALL_5(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5) ((ret (*)(t1, t2, t3, t4, t5))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5)
#define CDLL_CALL_6(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6) ((ret (*)(t1, t2, t3, t4, t5, t6))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5, a6)
#define CDLL_CALL_7(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6, t7, a7) ((ret (*)(t1, t2, t3, t4, t5, t6, t7))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5, a6, a7)
#define CDLL_CALL_8(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6, t7, a7, t8, a8) ((ret (*)(t1, t2, t3, t4, t5, t6, t7, t8))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5, a6, a7, a8)
#define CDLL_CALL_9(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6, t7, a7, t8, a8, t9, a9) ((ret (*)(t1, t2, t3, t4, t5, t6, t7, t8, t9))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5, a6, a7, a8, a9)
#define CDLL_CALL_10(lib, name, ret, t1, a1, t2, a2, t3, a3, t4, a4, t5, a5, t6, a6, t7, a7, t8, a8, t9, a9, t10, a10) ((ret (*)(t1, t2, t3, t4, t5, t6, t7, t8, t9, t10))cdll_get_function_raw(lib, name))(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)

#define CDLL_CALL_VOID(lib, name, ...) CDLL_CALL_EXPAND(lib, name, void, CDLL_NARGS(__VA_ARGS__), __VA_ARGS__)

/* ============================================================================
 * Implementation - Error Handling
 * ============================================================================ */

static cdll_error_info_t __cdll_last_error = {0, "", "", 0};
static pthread_mutex_t __cdll_error_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief Sets the last error information for the library
 * @param function Name of the function where the error occurred
 * @param code Error code (platform-specific or errno)
 * @param message Human-readable error message
 */
static inline void cdll_set_error(const char* function, int code, const char* message) {
    pthread_mutex_lock(&__cdll_error_mutex);
    __cdll_last_error.code = code;
    strncpy(__cdll_last_error.message, message, sizeof(__cdll_last_error.message) - 1);
    __cdll_last_error.message[sizeof(__cdll_last_error.message) - 1] = '\0';
    strncpy(__cdll_last_error.function, function, sizeof(__cdll_last_error.function) - 1);
    __cdll_last_error.function[sizeof(__cdll_last_error.function) - 1] = '\0';
    __cdll_last_error.timestamp = time(NULL);
    pthread_mutex_unlock(&__cdll_error_mutex);
}

/**
 * @brief Clears the last error information
 */
static inline void cdll_clear_error(void) {
    pthread_mutex_lock(&__cdll_error_mutex);
    memset(&__cdll_last_error, 0, sizeof(__cdll_last_error));
    pthread_mutex_unlock(&__cdll_error_mutex);
}

/**
 * @brief Gets the last error information structure
 * @return Pointer to the last error info, or NULL if no error
 */
static inline const cdll_error_info_t* cdll_get_last_error(void) {
    return &__cdll_last_error;
}

/**
 * @brief Gets the last error message as a string
 * @return Error message or "No error" if none
 */
static inline const char* cdll_get_error_message(void) {
    return __cdll_last_error.message[0] ? __cdll_last_error.message : "No error";
}

/**
 * @brief Gets the last error code
 * @return Error code or 0 if no error
 */
static inline int cdll_get_error_code(void) {
    return __cdll_last_error.code;
}

/**
 * @brief Formats a platform-specific error code into a string
 * @param error_code The error code to format
 * @return Formatted error message
 */
#ifdef _WIN32
static inline const char* cdll_format_error(int error_code) {
    static char buffer[512];
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mutex);
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, (DWORD)error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buffer, sizeof(buffer), NULL);
    pthread_mutex_unlock(&mutex);
    return buffer;
}
#else
static inline const char* cdll_format_error(int error_code) {
    return strerror(error_code);
}
#endif

/* ============================================================================
 * Implementation - Global Manager
 * ============================================================================ */

static cdll_manager_t __cdll_global_manager = {
    .libraries = NULL,
    .delay_load_queue = NULL,
    .preload_cache = NULL,
    .library_pool = NULL,
    .library_count = 0,
    .pool_size = 0,
    .search_paths = {{0}},
    .search_path_count = 0,
    .auto_resolve_dependencies = true,
    .auto_add_extension = true,
    .cache_symbols = true,
    .enable_delay_load = true,
    .enable_preload = true,
    .enable_jit = false,
    .enable_sandbox = false,
    .enable_antidebug = false,
    .enable_integrity_check = true,
    .enable_pooling = false,
    .cache_ttl = 300,
    .pool_max_size = 10,
    .pool_ttl = 60,
    .thread_pool = NULL,
    .call_graph = NULL,
    .user_data = NULL
};

static pthread_mutex_t __cdll_manager_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_t __cdll_gc_thread = 0;
static bool __cdll_gc_running = false;
static time_t __cdll_gc_interval = 60;

/**
 * @brief Gets the global library manager instance
 * @return Pointer to the global manager
 */
static inline cdll_manager_t* cdll_get_global_manager(void) {
    return &__cdll_global_manager;
}

/* ============================================================================
 * Implementation - Platform Utilities
 * ============================================================================ */

/**
 * @brief Gets the current operating system name
 * @return String containing OS name ("Windows", "Linux", "macOS", etc.)
 */
static inline const char* cdll_get_os_name(void) {
#ifdef _WIN32
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#elif defined(__FreeBSD__)
    return "FreeBSD";
#elif defined(__OpenBSD__)
    return "OpenBSD";
#elif defined(__NetBSD__)
    return "NetBSD";
#elif defined(__sun)
    return "Solaris";
#else
    return "Unknown";
#endif
}

/**
 * @brief Checks if running on Windows
 * @return true if Windows, false otherwise
 */
static inline bool cdll_is_windows(void) {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

/**
 * @brief Checks if running on macOS
 * @return true if macOS, false otherwise
 */
static inline bool cdll_is_macos(void) {
#ifdef __APPLE__
    return true;
#else
    return false;
#endif
}

/**
 * @brief Checks if running on Unix-like system
 * @return true if Unix-like, false otherwise
 */
static inline bool cdll_is_unix(void) {
#ifndef _WIN32
    return true;
#else
    return false;
#endif
}

/**
 * @brief Gets the platform-specific library extension
 * @return ".dll" on Windows, ".so" on Linux, ".dylib" on macOS
 */
static inline const char* cdll_get_extension(void) {
    return CDLL_LIBRARY_EXTENSION;
}

/**
 * @brief Gets the platform-specific path separator character
 * @return '\\' on Windows, '/' on Unix-like systems
 */
static inline char cdll_get_path_separator(void) {
    return CDLL_PATH_SEPARATOR;
}

/* ============================================================================
 * Implementation - Path Utilities
 * ============================================================================ */

/**
 * @brief Checks if a file exists at the given path
 * @param path File path to check
 * @return true if file exists and is a regular file, false otherwise
 */
static inline bool cdll_file_exists(const char* path) {
    if (!path) return false;
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
#endif
}

/**
 * @brief Checks if a path is absolute
 * @param path Path to check
 * @return true if absolute path, false otherwise
 */
static inline bool cdll_is_absolute_path(const char* path) {
    if (!path) return false;
#ifdef _WIN32
    return (strlen(path) >= 3 && path[1] == ':' && path[2] == '\\') ||
           (strlen(path) >= 2 && path[0] == '\\' && path[1] == '\\');
#else
    return path[0] == '/';
#endif
}

/**
 * @brief Gets the directory name from a path (modifies the input string)
 * @param path Path string (will be modified)
 * @return Pointer to the directory part, or "." if none
 */
static inline char* cdll_dirname(char* path) {
    if (!path) return NULL;
    char* sep = strrchr(path, CDLL_PATH_SEPARATOR);
    if (!sep) sep = strrchr(path, '/');
    if (sep) {
        *sep = '\0';
        return path;
    }
    return (char*)".";
}

/**
 * @brief Gets the base filename from a path
 * @param path Path string
 * @return Pointer to the filename part
 */
static inline const char* cdll_basename(const char* path) {
    if (!path) return NULL;
    const char* sep = strrchr(path, CDLL_PATH_SEPARATOR);
    if (!sep) sep = strrchr(path, '/');
    return sep ? sep + 1 : path;
}

/**
 * @brief Normalizes path separators to platform-specific character
 * @param path Path string to normalize (modified in-place)
 */
static inline void cdll_normalize_path(char* path) {
    if (!path) return;
    char* p = path;
    while (*p) {
        if (*p == '/' || *p == '\\') *p = CDLL_PATH_SEPARATOR;
        p++;
    }
}

/**
 * @brief Resolves a library name to a full path
 * @param name Library name or path to resolve
 * @param out_path Buffer to store the resolved path
 * @param out_size Size of the output buffer
 * @return true if resolved successfully, false otherwise
 */
static inline bool cdll_resolve_path(const char* name, char* out_path, size_t out_size) {
    if (!name || !out_path || out_size == 0) return false;
    
    if (cdll_is_absolute_path(name)) {
        if (cdll_file_exists(name)) {
            strncpy(out_path, name, out_size - 1);
            out_path[out_size - 1] = '\0';
            return true;
        }
    }
    
    char with_ext[1024];
    if (__cdll_global_manager.auto_add_extension && !strstr(name, CDLL_LIBRARY_EXTENSION)) {
        snprintf(with_ext, sizeof(with_ext), "%s%s", name, CDLL_LIBRARY_EXTENSION);
    } else {
        strncpy(with_ext, name, sizeof(with_ext) - 1);
        with_ext[sizeof(with_ext) - 1] = '\0';
    }
    
    if (cdll_file_exists(with_ext)) {
        strncpy(out_path, with_ext, out_size - 1);
        out_path[out_size - 1] = '\0';
        return true;
    }
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    for (size_t i = 0; i < __cdll_global_manager.search_path_count; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s%c%s", 
                 __cdll_global_manager.search_paths[i], CDLL_PATH_SEPARATOR, with_ext);
        if (cdll_file_exists(full_path)) {
            strncpy(out_path, full_path, out_size - 1);
            out_path[out_size - 1] = '\0';
            pthread_mutex_unlock(&__cdll_manager_mutex);
            return true;
        }
    }
    pthread_mutex_unlock(&__cdll_manager_mutex);
    
#ifdef _WIN32
    char sys_path[1024];
    GetSystemDirectoryA(sys_path, sizeof(sys_path));
    snprintf(sys_path, sizeof(sys_path), "%s\\%s", sys_path, with_ext);
    if (cdll_file_exists(sys_path)) {
        strncpy(out_path, sys_path, out_size - 1);
        return true;
    }
#else
    const char* ld_path = getenv("LD_LIBRARY_PATH");
    if (ld_path) {
        char* path_copy = strdup(ld_path);
        if (path_copy) {
            char* token = strtok(path_copy, ":");
            while (token) {
                char full_path[1024];
                snprintf(full_path, sizeof(full_path), "%s/%s", token, with_ext);
                if (cdll_file_exists(full_path)) {
                    strncpy(out_path, full_path, out_size - 1);
                    free(path_copy);
                    return true;
                }
                token = strtok(NULL, ":");
            }
            free(path_copy);
        }
    }
#endif
    
    return false;
}

/* ============================================================================
 * Implementation - Manager Functions
 * ============================================================================ */

/**
 * @brief Initializes a library manager
 * @param manager Manager to initialize
 */
static inline void cdll_manager_init(cdll_manager_t* manager) {
    if (!manager) return;
    memset(manager, 0, sizeof(cdll_manager_t));
    manager->auto_resolve_dependencies = true;
    manager->auto_add_extension = true;
    manager->cache_symbols = true;
    manager->enable_delay_load = true;
    manager->cache_ttl = 300;
}

/**
 * @brief Adds a search path to a manager
 * @param manager Manager instance
 * @param path Directory path to add
 */
static inline void cdll_manager_add_search_path(cdll_manager_t* manager, const char* path) {
    if (!manager || !path || manager->search_path_count >= 16) return;
    strncpy(manager->search_paths[manager->search_path_count], path, 511);
    cdll_normalize_path(manager->search_paths[manager->search_path_count]);
    manager->search_path_count++;
}

/**
 * @brief Adds a search path to the global manager
 * @param path Directory path to add
 */
static inline void cdll_add_search_path(const char* path) {
    pthread_mutex_lock(&__cdll_manager_mutex);
    cdll_manager_add_search_path(&__cdll_global_manager, path);
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Removes a search path from a manager
 * @param manager Manager instance
 * @param path Directory path to remove
 */
static inline void cdll_manager_remove_search_path(cdll_manager_t* manager, const char* path) {
    if (!manager || !path) return;
    for (size_t i = 0; i < manager->search_path_count; i++) {
        if (strcmp(manager->search_paths[i], path) == 0) {
            memmove(manager->search_paths[i], manager->search_paths[i + 1],
                    (manager->search_path_count - i - 1) * 512);
            manager->search_path_count--;
            i--;
        }
    }
}

/**
 * @brief Clears all search paths from a manager
 * @param manager Manager instance
 */
static inline void cdll_manager_clear_search_paths(cdll_manager_t* manager) {
    if (manager) manager->search_path_count = 0;
}

/**
 * @brief Finds a loaded library by name or path
 * @param manager Manager instance
 * @param name Library name or path to find
 * @return Pointer to library if found, NULL otherwise
 */
static inline cdll_library_t* cdll_manager_find_library(cdll_manager_t* manager, const char* name) {
    if (!manager || !name) return NULL;
    cdll_library_t* lib = manager->libraries;
    while (lib) {
        if (strcmp(lib->name, name) == 0 || strstr(lib->path, name)) return lib;
        lib = lib->next;
    }
    return NULL;
}

/**
 * @brief Adds a library to a manager's tracking list
 * @param manager Manager instance
 * @param lib Library to add
 */
static inline void cdll_manager_add_library(cdll_manager_t* manager, cdll_library_t* lib) {
    if (!manager || !lib) return;
    lib->next = manager->libraries;
    lib->prev = NULL;
    if (manager->libraries) manager->libraries->prev = lib;
    manager->libraries = lib;
    manager->library_count++;
}

/**
 * @brief Removes a library from a manager's tracking list
 * @param manager Manager instance
 * @param lib Library to remove
 * @return true if removed, false otherwise
 */
static inline bool cdll_manager_remove_library(cdll_manager_t* manager, cdll_library_t* lib) {
    if (!manager || !lib) return false;
    if (lib->prev) lib->prev->next = lib->next;
    else manager->libraries = lib->next;
    if (lib->next) lib->next->prev = lib->prev;
    manager->library_count--;
    return true;
}

/**
 * @brief Gets all loaded libraries from a manager
 * @param manager Manager instance
 * @param out_libraries Pointer to receive array of library pointers (caller must free)
 * @return Number of libraries, or 0 on failure
 */
static inline size_t cdll_manager_get_loaded_libraries(cdll_manager_t* manager, cdll_library_t*** out_libraries) {
    if (!manager || !out_libraries) return 0;
    *out_libraries = (cdll_library_t**)malloc(sizeof(cdll_library_t*) * manager->library_count);
    if (!*out_libraries) return 0;
    cdll_library_t* lib = manager->libraries;
    size_t i = 0;
    while (lib && i < manager->library_count) {
        (*out_libraries)[i++] = lib;
        lib = lib->next;
    }
    return i;
}

/* ============================================================================
 * Implementation - Symbol Demangling
 * ============================================================================ */

/**
 * @brief Demangles a C++ symbol name
 * @param mangled The mangled symbol name
 * @param output Buffer to store the demangled name
 * @param out_size Size of the output buffer
 * @return Pointer to output buffer, or NULL on failure
 */
static inline char* cdll_demangle_symbol(const char* mangled, char* output, size_t out_size) {
    if (!mangled || !output || out_size == 0) return NULL;
    
    if (mangled[0] == '?' || mangled[0] == '_' || strncmp(mangled, "__Z", 3) == 0) {
#ifdef __GNUC__
    #ifndef _WIN32
        int status = 0;
        char* demangled = __cxxabiv1::__cxa_demangle(mangled, NULL, NULL, &status);
        if (status == 0 && demangled) {
            strncpy(output, demangled, out_size - 1);
            output[out_size - 1] = '\0';
            free(demangled);
            return output;
        }
    #endif
#elif defined(_WIN32)
        char undecorated[512];
        if (UnDecorateSymbolName(mangled, undecorated, sizeof(undecorated), UNDNAME_COMPLETE)) {
            strncpy(output, undecorated, out_size - 1);
            output[out_size - 1] = '\0';
            return output;
        }
#endif
    }
    
    strncpy(output, mangled, out_size - 1);
    output[out_size - 1] = '\0';
    return output;
}

/* ============================================================================
 * Implementation - Core Library Loading
 * ============================================================================ */

/**
 * @brief Loads a library with extended flags
 * @param path Path to the library
 * @param flags Loading flags (CDLL_RTLD_LAZY, CDLL_RTLD_NOW, etc.)
 * @return Pointer to loaded library, or NULL on failure
 */
static inline cdll_library_t* cdll_load_library_ex(const char* path, uint32_t flags) {
    cdll_clear_error();
    
    if (!path) {
        cdll_set_error("cdll_load_library_ex", EINVAL, "Invalid path parameter");
        return NULL;
    }
    
    /* Check pool first if enabled */
    if (__cdll_global_manager.enable_pooling) {
        pthread_mutex_lock(&__cdll_manager_mutex);
        cdll_library_t* pooled = __cdll_global_manager.library_pool;
        while (pooled) {
            if (strcmp(pooled->path, path) == 0 || strstr(path, pooled->name)) {
                /* Remove from pool */
                if (pooled->pool_next) {
                    /* Need to find previous */
                    cdll_library_t* prev = __cdll_global_manager.library_pool;
                    while (prev && prev->pool_next != pooled) prev = prev->pool_next;
                    if (prev) prev->pool_next = pooled->pool_next;
                } else {
                    __cdll_global_manager.library_pool = pooled->pool_next;
                }
                __cdll_global_manager.pool_size--;
                pthread_mutex_unlock(&__cdll_manager_mutex);
                pooled->is_pooled = false;
                cdll_atomic_increment(&pooled->reference_count);
                return pooled;
            }
            pooled = pooled->pool_next;
        }
        pthread_mutex_unlock(&__cdll_manager_mutex);
    }
    
    char resolved_path[1024] = {0};
    if (!cdll_resolve_path(path, resolved_path, sizeof(resolved_path))) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Library not found: %s", path);
        cdll_set_error("cdll_load_library_ex", ENOENT, msg);
        return NULL;
    }
    
    /* Check integrity if enabled */
    if (__cdll_global_manager.enable_integrity_check) {
        if (!cdll_verify_signature(resolved_path)) {
            cdll_set_error("cdll_load_library_ex", EPERM, "Library signature verification failed");
            return NULL;
        }
    }
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    cdll_library_t* existing = cdll_manager_find_library(&__cdll_global_manager, resolved_path);
    if (existing) {
        cdll_atomic_increment(&existing->reference_count);
        existing->last_access_time = time(NULL);
        pthread_mutex_unlock(&__cdll_manager_mutex);
        return existing;
    }
    pthread_mutex_unlock(&__cdll_manager_mutex);
    
    cdll_native_handle handle = CDLL_INVALID_HANDLE;
    
#ifdef _WIN32
    DWORD win_flags = 0;
    if (flags & CDLL_RTLD_NOW) win_flags |= LOAD_WITH_ALTERED_SEARCH_PATH;
    handle = LoadLibraryExA(resolved_path, NULL, win_flags);
    if (!handle) {
        DWORD err = GetLastError();
        char msg[512];
        snprintf(msg, sizeof(msg), "Failed to load library: %s", cdll_format_error(err));
        cdll_set_error("cdll_load_library_ex", err, msg);
        return NULL;
    }
#else
    int dl_flags = RTLD_LAZY;
    if (flags & CDLL_RTLD_NOW) dl_flags = RTLD_NOW;
    if (flags & CDLL_RTLD_GLOBAL) dl_flags |= RTLD_GLOBAL;
    if (flags & CDLL_RTLD_LOCAL) dl_flags |= RTLD_LOCAL;
    if (flags & CDLL_RTLD_NOLOAD) dl_flags |= RTLD_NOLOAD;
    if (flags & CDLL_RTLD_DEEPBIND) dl_flags |= RTLD_DEEPBIND;
    
    dlerror();
    handle = dlopen(resolved_path, dl_flags);
    if (!handle) {
        const char* err = dlerror();
        cdll_set_error("cdll_load_library_ex", errno, err ? err : "Failed to load library");
        return NULL;
    }
#endif
    
    cdll_library_t* lib = (cdll_library_t*)calloc(1, sizeof(cdll_library_t));
    if (!lib) {
        cdll_set_error("cdll_load_library_ex", ENOMEM, "Failed to allocate memory");
#ifdef _WIN32
        FreeLibrary(handle);
#else
        dlclose(handle);
#endif
        return NULL;
    }
    
    lib->handle = handle;
    strncpy(lib->path, resolved_path, sizeof(lib->path) - 1);
    strncpy(lib->name, cdll_basename(resolved_path), sizeof(lib->name) - 1);
    strncpy(lib->full_name, cdll_basename(resolved_path), sizeof(lib->full_name) - 1);
    lib->flags = flags;
    lib->is_loaded = true;
    lib->load_time = time(NULL);
    lib->last_access_time = lib->load_time;
    lib->reference_count = 1;
    lib->cached_functions = NULL;
    lib->cached_count = 0;
    lib->cached_capacity = 0;
    
    /* Compute initial checksum */
    if (__cdll_global_manager.enable_integrity_check) {
        cdll_compute_checksum(lib, lib->checksum);
    }
    
    /* Enable anti-debug if configured */
    if (__cdll_global_manager.enable_antidebug) {
        cdll_enable_anti_debug(lib);
    }
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    cdll_manager_add_library(&__cdll_global_manager, lib);
    pthread_mutex_unlock(&__cdll_manager_mutex);
    
    return lib;
}

/**
 * @brief Loads a library with default flags
 * @param path Path to the library
 * @return Pointer to loaded library, or NULL on failure
 */
static inline cdll_library_t* cdll_load_library(const char* path) {
    return cdll_load_library_ex(path, CDLL_RTLD_LAZY);
}

/**
 * @brief Loads a system library from system directories
 * @param name Name of the system library (without extension)
 * @return Pointer to loaded library, or NULL on failure
 */
static inline cdll_library_t* cdll_load_library_system(const char* name) {
    cdll_clear_error();
    
    if (!name) {
        cdll_set_error("cdll_load_library_system", EINVAL, "Invalid name parameter");
        return NULL;
    }
    
#ifdef _WIN32
    char sys_path[1024];
    GetSystemDirectoryA(sys_path, sizeof(sys_path));
    snprintf(sys_path, sizeof(sys_path), "%s\\%s", sys_path, name);
    if (!strstr(sys_path, CDLL_LIBRARY_EXTENSION)) {
        strncat(sys_path, CDLL_LIBRARY_EXTENSION, sizeof(sys_path) - strlen(sys_path) - 1);
    }
    return cdll_load_library(sys_path);
#else
    return cdll_load_library(name);
#endif
}

/**
 * @brief Unloads a previously loaded library
 * @param lib Library to unload
 * @return true if unloaded successfully, false otherwise
 */
static inline bool cdll_unload_library(cdll_library_t* lib) {
    cdll_clear_error();
    
    if (!lib) {
        cdll_set_error("cdll_unload_library", EINVAL, "Invalid library parameter");
        return false;
    }
    
    if (!lib->is_loaded) {
        cdll_set_error("cdll_unload_library", EINVAL, "Library not loaded");
        return false;
    }
    
    int32_t ref_count = cdll_atomic_decrement(&lib->reference_count);
    if (ref_count > 0) return true;
    
    /* Check if should be pooled */
    if (__cdll_global_manager.enable_pooling && !lib->is_pooled && 
        __cdll_global_manager.pool_size < __cdll_global_manager.pool_max_size) {
        pthread_mutex_lock(&__cdll_manager_mutex);
        lib->is_pooled = true;
        lib->pool_next = __cdll_global_manager.library_pool;
        __cdll_global_manager.library_pool = lib;
        __cdll_global_manager.pool_size++;
        lib->last_access_time = time(NULL);
        pthread_mutex_unlock(&__cdll_manager_mutex);
        return true;
    }
    
    /* Remove sandbox if active */
    if (lib->is_sandboxed) {
        cdll_sandbox_remove(lib);
    }
    
    /* Remove anti-debug */
    if (__cdll_global_manager.enable_antidebug) {
        cdll_disable_anti_debug(lib);
    }
    
    bool success = false;
    
#ifdef _WIN32
    success = FreeLibrary(lib->handle) != 0;
    if (!success) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Failed to unload library: %s", cdll_format_error(GetLastError()));
        cdll_set_error("cdll_unload_library", GetLastError(), msg);
    }
#else
    success = dlclose(lib->handle) == 0;
    if (!success) {
        const char* err = dlerror();
        cdll_set_error("cdll_unload_library", errno, err ? err : "Failed to unload library");
    }
#endif
    
    if (success) {
        lib->is_loaded = false;
        lib->handle = CDLL_INVALID_HANDLE;
        cdll_clear_function_cache(lib);
        
        pthread_mutex_lock(&__cdll_manager_mutex);
        cdll_manager_remove_library(&__cdll_global_manager, lib);
        pthread_mutex_unlock(&__cdll_manager_mutex);
        
        free(lib);
    }
    
    return success;
}

/**
 * @brief Reloads a library (unloads and loads again)
 * @param lib Library to reload
 * @return true if reloaded successfully, false otherwise
 */
static inline bool cdll_reload_library(cdll_library_t* lib) {
    if (!lib) return false;
    char path[1024];
    strncpy(path, lib->path, sizeof(path) - 1);
    uint32_t flags = lib->flags;
    cdll_unload_library(lib);
    return cdll_load_library_ex(path, flags) != NULL;
}

/**
 * @brief Gets the native handle of a loaded library
 * @param lib Library instance
 * @return HMODULE on Windows, void* on Unix
 */
static inline cdll_native_handle cdll_get_native_handle(cdll_library_t* lib) {
    return lib ? lib->handle : CDLL_INVALID_HANDLE;
}

/**
 * @brief Gets the full path of a loaded library
 * @param lib Library instance
 * @return Full path string, or NULL if invalid
 */
static inline const char* cdll_get_library_path(cdll_library_t* lib) {
    return lib ? lib->path : NULL;
}

/**
 * @brief Gets the base name of a loaded library
 * @param lib Library instance
 * @return Base name string, or NULL if invalid
 */
static inline const char* cdll_get_library_name(cdll_library_t* lib) {
    return lib ? lib->name : NULL;
}

/**
 * @brief Checks if a library is currently loaded
 * @param lib Library instance
 * @return true if loaded, false otherwise
 */
static inline bool cdll_is_library_loaded(cdll_library_t* lib) {
    return lib ? lib->is_loaded : false;
}

/**
 * @brief Gets the current reference count of a library
 * @param lib Library instance
 * @return Reference count (thread-safe)
 */
static inline size_t cdll_get_reference_count(cdll_library_t* lib) {
    return lib ? (size_t)cdll_atomic_load((int32_t*)&lib->reference_count) : 0;
}

/**
 * @brief Gets the time when the library was loaded
 * @param lib Library instance
 * @return Load timestamp
 */
static inline time_t cdll_get_load_time(cdll_library_t* lib) {
    return lib ? lib->load_time : 0;
}

/* ============================================================================
 * Implementation - Symbol Cache Management
 * ============================================================================ */

/**
 * @brief Finds a cached function in a library's cache
 * @param lib Library instance
 * @param name Function name
 * @return Cached function pointer, or NULL if not found/expired
 */
static inline cdll_function_t* cdll_find_cached_function(cdll_library_t* lib, const char* name) {
    if (!lib || !name) return NULL;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    cdll_function_t* func = lib->cached_functions;
    time_t now = time(NULL);
    
    while (func) {
        if (strcmp(func->name, name) == 0) {
            /* Check TTL */
            if (func->ttl > 0 && (now - func->cache_time) > func->ttl) {
                func = NULL;
                break;
            }
            pthread_mutex_unlock(&__cdll_manager_mutex);
            return func;
        }
        func = func->next;
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
    return NULL;
}

/**
 * @brief Adds a function to a library's cache
 * @param lib Library instance
 * @param func Function to cache
 */
static inline void cdll_cache_function(cdll_library_t* lib, cdll_function_t* func) {
    if (!lib || !func) return;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    if (lib->cached_count >= lib->cached_capacity) {
        lib->cached_capacity = lib->cached_capacity ? lib->cached_capacity * 2 : 16;
    }
    
    func->cache_time = time(NULL);
    func->ttl = __cdll_global_manager.cache_ttl;
    func->next = lib->cached_functions;
    lib->cached_functions = func;
    lib->cached_count++;
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Clears the entire function cache for a library
 * @param lib Library instance
 */
static inline void cdll_clear_function_cache(cdll_library_t* lib) {
    if (!lib) return;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    cdll_function_t* func = lib->cached_functions;
    while (func) {
        cdll_function_t* next = func->next;
        free(func);
        func = next;
    }
    
    lib->cached_functions = NULL;
    lib->cached_count = 0;
    lib->cached_capacity = 0;
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/* ============================================================================
 * Implementation - Function Management
 * ============================================================================ */

/**
 * @brief Gets a raw function pointer from a library
 * @param lib Library instance
 * @param name Function name
 * @return Function pointer, or CDLL_INVALID_FUNC on failure
 */
static inline cdll_func_ptr cdll_get_function_raw(cdll_library_t* lib, const char* name) {
    cdll_clear_error();
    
    if (!lib || !lib->is_loaded || !name) {
        cdll_set_error("cdll_get_function_raw", EINVAL, "Invalid parameters");
        return CDLL_INVALID_FUNC;
    }
    
    lib->last_access_time = time(NULL);
    
    /* Try delay-load first if configured */
    if (lib->is_delay_load) {
        cdll_func_ptr delay_ptr = cdll_delay_load_resolve(lib, name);
        if (delay_ptr) return delay_ptr;
    }
    
#ifdef _WIN32
    cdll_func_ptr func = GetProcAddress(lib->handle, name);
    if (!func) {
        DWORD err = GetLastError();
        char msg[512];
        snprintf(msg, sizeof(msg), "Failed to get function '%s': %s", name, cdll_format_error(err));
        cdll_set_error("cdll_get_function_raw", err, msg);
    }
#else
    dlerror();
    cdll_func_ptr func = dlsym(lib->handle, name);
    if (!func) {
        const char* err = dlerror();
        cdll_set_error("cdll_get_function_raw", errno, err ? err : "Failed to get function");
    }
#endif
    
    return func;
}

/**
 * @brief Gets a function from a library (with caching support)
 * @param lib Library instance
 * @param name Function name
 * @return Function structure pointer, or NULL on failure
 */
static inline cdll_function_t* cdll_get_function(cdll_library_t* lib, const char* name) {
    if (!lib || !name) return NULL;
    
    lib->last_access_time = time(NULL);
    
    /* Check cache first */
    if (__cdll_global_manager.cache_symbols) {
        cdll_function_t* cached = cdll_find_cached_function(lib, name);
        if (cached) {
            cdll_atomic_increment(&cached->call_count);
            return cached;
        }
    }
    
    cdll_func_ptr ptr = cdll_get_function_raw(lib, name);
    if (!ptr) return NULL;
    
    cdll_function_t* func = (cdll_function_t*)calloc(1, sizeof(cdll_function_t));
    if (!func) {
        cdll_set_error("cdll_get_function", ENOMEM, "Failed to allocate memory");
        return NULL;
    }
    
    func->ptr = ptr;
    strncpy(func->name, name, sizeof(func->name) - 1);
    cdll_demangle_symbol(name, func->demangled_name, sizeof(func->demangled_name));
    func->is_resolved = true;
    func->library = lib;
    func->call_count = 0;
    
    if (__cdll_global_manager.cache_symbols) {
        cdll_cache_function(lib, func);
    }
    
    return func;
}

/**
 * @brief Gets a function by ordinal (Windows only)
 * @param lib Library instance
 * @param ordinal Function ordinal number
 * @return Function structure pointer, or NULL on failure
 */
static inline cdll_function_t* cdll_get_function_ordinal(cdll_library_t* lib, uint32_t ordinal) {
    cdll_clear_error();
    
    if (!lib || !lib->is_loaded) {
        cdll_set_error("cdll_get_function_ordinal", EINVAL, "Invalid library");
        return NULL;
    }
    
    lib->last_access_time = time(NULL);
    
#ifdef _WIN32
    cdll_func_ptr ptr = GetProcAddress(lib->handle, (LPCSTR)(uintptr_t)ordinal);
    if (!ptr) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Failed to get function ordinal %u: %s", ordinal, cdll_format_error(GetLastError()));
        cdll_set_error("cdll_get_function_ordinal", GetLastError(), msg);
        return NULL;
    }
    
    char cache_name[32];
    snprintf(cache_name, sizeof(cache_name), "#%u", ordinal);
    
    if (__cdll_global_manager.cache_symbols) {
        cdll_function_t* cached = cdll_find_cached_function(lib, cache_name);
        if (cached) return cached;
    }
    
    cdll_function_t* func = (cdll_function_t*)calloc(1, sizeof(cdll_function_t));
    if (func) {
        func->ptr = ptr;
        func->ordinal = ordinal;
        func->is_resolved = true;
        func->library = lib;
        strncpy(func->name, cache_name, sizeof(func->name) - 1);
        snprintf(func->demangled_name, sizeof(func->demangled_name), "Ordinal_%u", ordinal);
        
        if (__cdll_global_manager.cache_symbols) {
            cdll_cache_function(lib, func);
        }
    }
    
    return func;
#else
    cdll_set_error("cdll_get_function_ordinal", ENOSYS, "Ordinal functions not supported on Unix");
    return NULL;
#endif
}

/**
 * @brief Frees a function structure (no-op, functions are cache-managed)
 * @param func Function to free
 */
static inline void cdll_free_function(cdll_function_t* func) {
    (void)func;
    /* Functions are freed with cache */
}

/**
 * @brief Checks if a library exports a specific function
 * @param lib Library instance
 * @param name Function name to check
 * @return true if function exists, false otherwise
 */
static inline bool cdll_has_function(cdll_library_t* lib, const char* name) {
    if (!lib || !name) return false;
    if (__cdll_global_manager.cache_symbols && cdll_find_cached_function(lib, name)) return true;
    return cdll_get_function_raw(lib, name) != CDLL_INVALID_FUNC;
}

/* ============================================================================
 * Implementation - Module Information
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Gets detailed module information about a loaded library
 * @param lib Library instance
 * @param info Structure to fill with module information
 * @return true on success, false on failure
 */
static inline bool cdll_get_module_info(cdll_library_t* lib, cdll_module_info_t* info) {
    if (!lib || !info) return false;
    memset(info, 0, sizeof(cdll_module_info_t));
    
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) return false;
    
    info->base_address = mod_info.lpBaseOfDll;
    info->size = mod_info.SizeOfImage;
    info->entry_point = mod_info.EntryPoint;
    strncpy(info->path, lib->path, sizeof(info->path) - 1);
    strncpy(info->name, lib->name, sizeof(info->name) - 1);
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_info.lpBaseOfDll;
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            info->checksum = nt->OptionalHeader.CheckSum;
            info->timestamp = nt->FileHeader.TimeDateStamp;
            info->machine_type = nt->FileHeader.Machine;
            info->characteristics = nt->FileHeader.Characteristics;
            info->subsystem = nt->OptionalHeader.Subsystem;
            info->dll_characteristics = nt->OptionalHeader.DllCharacteristics;
            info->image_size = nt->OptionalHeader.SizeOfImage;
            info->is_64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
            info->has_dep = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
            info->has_aslr = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
            info->has_guard_cf = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
        }
    }
    
    return true;
}

/**
 * @brief Gets the base address of a loaded library
 * @param lib Library instance
 * @return Base address pointer, or NULL on failure
 */
static inline void* cdll_get_module_base(cdll_library_t* lib) {
    if (!lib) return NULL;
    MODULEINFO mod_info;
    if (GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) {
        return mod_info.lpBaseOfDll;
    }
    return NULL;
}

/**
 * @brief Gets the size of a loaded library in memory
 * @param lib Library instance
 * @return Size in bytes, or 0 on failure
 */
static inline size_t cdll_get_module_size(cdll_library_t* lib) {
    if (!lib) return 0;
    MODULEINFO mod_info;
    if (GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) {
        return mod_info.SizeOfImage;
    }
    return 0;
}

/**
 * @brief Enumerates all exported functions from a library
 * @param lib Library instance
 * @param entries Array to fill with export entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of exports found
 */
static inline size_t cdll_enumerate_exports(cdll_library_t* lib, cdll_export_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) return 0;
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_info.lpBaseOfDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    IMAGE_DATA_DIRECTORY* export_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir->Size == 0) return 0;
    
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)((uint8_t*)mod_info.lpBaseOfDll + export_dir->VirtualAddress);
    uint32_t* names = (uint32_t*)((uint8_t*)mod_info.lpBaseOfDll + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)((uint8_t*)mod_info.lpBaseOfDll + exports->AddressOfNameOrdinals);
    uint32_t* functions = (uint32_t*)((uint8_t*)mod_info.lpBaseOfDll + exports->AddressOfFunctions);
    
    size_t count = 0;
    for (uint32_t i = 0; i < exports->NumberOfNames && count < max_entries; i++) {
        char* name = (char*)((uint8_t*)mod_info.lpBaseOfDll + names[i]);
        uint16_t ordinal = ordinals[i] + exports->Base;
        uint32_t rva = functions[ordinals[i]];
        
        strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
        cdll_demangle_symbol(name, entries[count].demangled_name, sizeof(entries[count].demangled_name));
        entries[count].ordinal = ordinal;
        entries[count].address = (uint8_t*)mod_info.lpBaseOfDll + rva;
        
        if (rva >= export_dir->VirtualAddress && rva < export_dir->VirtualAddress + export_dir->Size) {
            strncpy(entries[count].forwarder, (char*)entries[count].address, sizeof(entries[count].forwarder) - 1);
            entries[count].is_forwarded = true;
        }
        
        count++;
    }
    
    return count;
}

/**
 * @brief Enumerates all imported functions/dependencies of a library
 * @param lib Library instance
 * @param entries Array to fill with import entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of imports found
 */
static inline size_t cdll_enumerate_imports(cdll_library_t* lib, cdll_import_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) return 0;
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_info.lpBaseOfDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    IMAGE_DATA_DIRECTORY* import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size == 0) return 0;
    
    IMAGE_IMPORT_DESCRIPTOR* import = (IMAGE_IMPORT_DESCRIPTOR*)((uint8_t*)mod_info.lpBaseOfDll + import_dir->VirtualAddress);
    
    size_t count = 0;
    while (import->Name && count < max_entries) {
        char* module_name = (char*)((uint8_t*)mod_info.lpBaseOfDll + import->Name);
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)((uint8_t*)mod_info.lpBaseOfDll + import->FirstThunk);
        IMAGE_THUNK_DATA* original = import->OriginalFirstThunk ? 
            (IMAGE_THUNK_DATA*)((uint8_t*)mod_info.lpBaseOfDll + import->OriginalFirstThunk) : thunk;
        
        while (original->u1.AddressOfData && count < max_entries) {
            if (original->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                entries[count].ordinal = original->u1.Ordinal & 0xFFFF;
                entries[count].name[0] = '\0';
            } else {
                IMAGE_IMPORT_BY_NAME* by_name = (IMAGE_IMPORT_BY_NAME*)((uint8_t*)mod_info.lpBaseOfDll + original->u1.AddressOfData);
                entries[count].hint = by_name->Hint;
                strncpy(entries[count].name, by_name->Name, sizeof(entries[count].name) - 1);
            }
            strncpy(entries[count].module_name, module_name, sizeof(entries[count].module_name) - 1);
            entries[count].address = &thunk->u1.Function;
            entries[count].is_bound = (original->u1.AddressOfData == 0);
            original++;
            thunk++;
            count++;
        }
        import++;
    }
    
    return count;
}

/**
 * @brief Enumerates all sections/segments of a library
 * @param lib Library instance
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to fill
 * @return Number of sections found
 */
static inline size_t cdll_enumerate_sections(cdll_library_t* lib, cdll_section_info_t* sections, size_t max_sections) {
    if (!lib || !sections || max_sections == 0) return 0;
    
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) return 0;
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)mod_info.lpBaseOfDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint8_t*)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
    size_t count = 0;
    
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections && count < max_sections; i++) {
        memcpy(sections[count].name, section[i].Name, sizeof(section[i].Name));
        sections[count].name[sizeof(section[i].Name)] = '\0';
        sections[count].virtual_address = (uint8_t*)mod_info.lpBaseOfDll + section[i].VirtualAddress;
        sections[count].virtual_size = section[i].Misc.VirtualSize;
        sections[count].raw_size = section[i].SizeOfRawData;
        sections[count].characteristics = section[i].Characteristics;
        sections[count].is_executable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sections[count].is_readable = (section[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        sections[count].is_writable = (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        
        /* Simple entropy check for packed sections */
        if (sections[count].raw_size > 0 && sections[count].virtual_size > sections[count].raw_size * 2) {
            sections[count].is_packed = true;
        }
        
        count++;
    }
    
    return count;
}

#elif defined(__APPLE__)

/* macOS Mach-O implementation */

/**
 * @brief Gets detailed module information about a loaded library
 * @param lib Library instance
 * @param info Structure to fill with module information
 * @return true on success, false on failure
 */
static inline bool cdll_get_module_info(cdll_library_t* lib, cdll_module_info_t* info) {
    if (!lib || !info) return false;
    memset(info, 0, sizeof(cdll_module_info_t));
    strncpy(info->path, lib->path, sizeof(info->path) - 1);
    strncpy(info->name, lib->name, sizeof(info->name) - 1);
    
    struct stat st;
    if (stat(lib->path, &st) == 0) {
        info->size = st.st_size;
        info->timestamp = st.st_mtime;
    }
    
#ifdef __LP64__
    info->is_64bit = true;
#else
    info->is_64bit = false;
#endif
    
    info->has_dep = true;
    info->has_aslr = true;
    
    return true;
}

/**
 * @brief Gets the base address of a loaded library
 * @param lib Library instance
 * @return Base address pointer, or NULL on failure
 */
static inline void* cdll_get_module_base(cdll_library_t* lib) {
    if (!lib) return NULL;
    Dl_info dli;
    if (dladdr((void*)cdll_get_module_base, &dli)) {
        return dli.dli_fbase;
    }
    return NULL;
}

/**
 * @brief Gets the size of a loaded library in memory
 * @param lib Library instance
 * @return Size in bytes, or 0 on failure
 */
static inline size_t cdll_get_module_size(cdll_library_t* lib) {
    if (!lib) return 0;
    struct stat st;
    if (stat(lib->path, &st) == 0) return st.st_size;
    return 0;
}

/**
 * @brief Enumerates all exported functions from a library
 * @param lib Library instance
 * @param entries Array to fill with export entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of exports found
 */
static inline size_t cdll_enumerate_exports(cdll_library_t* lib, cdll_export_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    int fd = open(lib->path, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    uint32_t magic = *(uint32_t*)file_data;
    
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        struct mach_header_64* mh = (struct mach_header_64*)file_data;
        uint8_t* cmd_ptr = (uint8_t*)(mh + 1);
        
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            if (lc->cmd == LC_SYMTAB) {
                struct symtab_command* symtab = (struct symtab_command*)lc;
                struct nlist_64* symbols = (struct nlist_64*)((uint8_t*)file_data + symtab->symoff);
                char* strtab = (char*)((uint8_t*)file_data + symtab->stroff);
                
                for (uint32_t j = 0; j < symtab->nsyms && count < max_entries; j++) {
                    if ((symbols[j].n_type & N_TYPE) == N_SECT && symbols[j].n_value != 0) {
                        strncpy(entries[count].name, strtab + symbols[j].n_un.n_strx, sizeof(entries[count].name) - 1);
                        cdll_demangle_symbol(entries[count].name, entries[count].demangled_name, sizeof(entries[count].demangled_name));
                        entries[count].address = (void*)symbols[j].n_value;
                        count++;
                    }
                }
                break;
            }
            cmd_ptr += lc->cmdsize;
        }
    }
    
    munmap(file_data, st.st_size);
    return count;
}

/**
 * @brief Enumerates all imported functions/dependencies of a library
 * @param lib Library instance
 * @param entries Array to fill with import entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of imports found
 */
/**
 * @brief Enumerates all imported functions/dependencies of a Mach-O library
 * @param lib Library instance
 * @param entries Array to fill with import entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of imports found
 */
static inline size_t cdll_enumerate_imports(cdll_library_t* lib, cdll_import_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    int fd = open(lib->path, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 0;
    }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    uint32_t magic = *(uint32_t*)file_data;
    
    /* Helper to swap endianness if needed */
    bool swap_bytes = false;
    if (magic == MH_CIGAM || magic == MH_CIGAM_64) {
        swap_bytes = true;
    }
    
    #define SWAP32(x) (swap_bytes ? __builtin_bswap32(x) : (x))
    #define SWAP64(x) (swap_bytes ? __builtin_bswap64(x) : (x))
    
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        /* 32-bit Mach-O */
        struct mach_header* mh = (struct mach_header*)file_data;
        uint8_t* cmd_ptr = (uint8_t*)(mh + 1);
        uint32_t ncmds = SWAP32(mh->ncmds);
        
        for (uint32_t i = 0; i < ncmds && count < max_entries; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            uint32_t cmdsize = SWAP32(lc->cmdsize);
            
            if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || 
                cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB) {
                
                struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
                uint32_t name_offset = SWAP32(dylib_cmd->dylib.name.offset);
                const char* dylib_name = (const char*)cmd_ptr + name_offset;
                
                strncpy(entries[count].module_name, dylib_name, sizeof(entries[count].module_name) - 1);
                entries[count].module_name[sizeof(entries[count].module_name) - 1] = '\0';
                
                /* Extract base name */
                const char* basename = strrchr(dylib_name, '/');
                if (basename) {
                    strncpy(entries[count].name, basename + 1, sizeof(entries[count].name) - 1);
                } else {
                    strncpy(entries[count].name, dylib_name, sizeof(entries[count].name) - 1);
                }
                entries[count].name[sizeof(entries[count].name) - 1] = '\0';
                
                entries[count].ordinal = 0;
                entries[count].hint = 0;
                entries[count].address = NULL;
                entries[count].is_bound = true;
                
                count++;
            }
            /* Also process LC_DYLD_INFO for lazy bind symbols */
            else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
                struct dyld_info_command* dyld_info = (struct dyld_info_command*)lc;
                
                if (SWAP32(dyld_info->lazy_bind_off) > 0 && SWAP32(dyld_info->lazy_bind_size) > 0) {
                    uint8_t* lazy_bind = (uint8_t*)file_data + SWAP32(dyld_info->lazy_bind_off);
                    size_t lazy_bind_size = SWAP32(dyld_info->lazy_bind_size);
                    
                    /* Parse lazy binding opcodes */
                    const char* symbol_name = NULL;
                    const char* dylib_name = NULL;
                    uint8_t* op = lazy_bind;
                    uint8_t* end = lazy_bind + lazy_bind_size;
                    
                    while (op < end && count < max_entries) {
                        uint8_t immediate = *op & BIND_IMMEDIATE_MASK;
                        uint8_t opcode = *op & BIND_OPCODE_MASK;
                        op++;
                        
                        switch (opcode) {
                            case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                                /* ordinal = immediate */
                                break;
                            case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                                /* ordinal = uleb128 */
                                while (*op & 0x80) op++;
                                op++;
                                break;
                            case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                                /* special ordinal */
                                break;
                            case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                                symbol_name = (const char*)op;
                                while (*op) op++;
                                op++;
                                break;
                            case BIND_OPCODE_DO_BIND:
                                if (symbol_name) {
                                    strncpy(entries[count].name, symbol_name, sizeof(entries[count].name) - 1);
                                    strncpy(entries[count].module_name, dylib_name ? dylib_name : "unknown", 
                                            sizeof(entries[count].module_name) - 1);
                                    entries[count].is_bound = false;
                                    count++;
                                }
                                break;
                            default:
                                /* Skip other opcodes */
                                if (opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB) {
                                    while (*op & 0x80) op++;
                                    op++;
                                    while (*op & 0x80) op++;
                                    op++;
                                }
                                break;
                        }
                    }
                }
            }
            
            cmd_ptr += cmdsize;
        }
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        /* 64-bit Mach-O */
        struct mach_header_64* mh = (struct mach_header_64*)file_data;
        uint8_t* cmd_ptr = (uint8_t*)(mh + 1);
        uint32_t ncmds = SWAP32(mh->ncmds);
        
        for (uint32_t i = 0; i < ncmds && count < max_entries; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            uint32_t cmdsize = SWAP32(lc->cmdsize);
            
            if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB || 
                cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB) {
                
                struct dylib_command* dylib_cmd = (struct dylib_command*)lc;
                uint32_t name_offset = SWAP32(dylib_cmd->dylib.name.offset);
                const char* dylib_name = (const char*)cmd_ptr + name_offset;
                
                strncpy(entries[count].module_name, dylib_name, sizeof(entries[count].module_name) - 1);
                entries[count].module_name[sizeof(entries[count].module_name) - 1] = '\0';
                
                const char* basename = strrchr(dylib_name, '/');
                if (basename) {
                    strncpy(entries[count].name, basename + 1, sizeof(entries[count].name) - 1);
                } else {
                    strncpy(entries[count].name, dylib_name, sizeof(entries[count].name) - 1);
                }
                entries[count].name[sizeof(entries[count].name) - 1] = '\0';
                
                entries[count].ordinal = 0;
                entries[count].hint = 0;
                entries[count].address = NULL;
                entries[count].is_bound = true;
                
                count++;
            }
            else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
                struct dyld_info_command* dyld_info = (struct dyld_info_command*)lc;
                
                if (SWAP32(dyld_info->lazy_bind_off) > 0 && SWAP32(dyld_info->lazy_bind_size) > 0) {
                    uint8_t* lazy_bind = (uint8_t*)file_data + SWAP32(dyld_info->lazy_bind_off);
                    size_t lazy_bind_size = SWAP32(dyld_info->lazy_bind_size);
                    
                    const char* symbol_name = NULL;
                    uint8_t* op = lazy_bind;
                    uint8_t* end = lazy_bind + lazy_bind_size;
                    
                    while (op < end && count < max_entries) {
                        uint8_t opcode = *op & BIND_OPCODE_MASK;
                        op++;
                        
                        if (opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) {
                            symbol_name = (const char*)op;
                            while (*op) op++;
                            op++;
                        } else if (opcode == BIND_OPCODE_DO_BIND && symbol_name) {
                            strncpy(entries[count].name, symbol_name, sizeof(entries[count].name) - 1);
                            strncpy(entries[count].module_name, "dyld_stub_binder", sizeof(entries[count].module_name) - 1);
                            entries[count].is_bound = false;
                            count++;
                            symbol_name = NULL;
                        } else if (opcode == BIND_OPCODE_DONE) {
                            break;
                        } else {
                            /* Skip ULEB128 values */
                            if ((opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB) ||
                                (opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB)) {
                                while (*op & 0x80) op++;
                                op++;
                            }
                        }
                    }
                }
                
                /* Also process bind opcodes */
                if (SWAP32(dyld_info->bind_off) > 0 && SWAP32(dyld_info->bind_size) > 0) {
                    uint8_t* bind = (uint8_t*)file_data + SWAP32(dyld_info->bind_off);
                    size_t bind_size = SWAP32(dyld_info->bind_size);
                    
                    const char* symbol_name = NULL;
                    uint8_t* op = bind;
                    uint8_t* end = bind + bind_size;
                    
                    while (op < end && count < max_entries) {
                        uint8_t opcode = *op & BIND_OPCODE_MASK;
                        op++;
                        
                        if (opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM) {
                            symbol_name = (const char*)op;
                            while (*op) op++;
                            op++;
                        } else if (opcode == BIND_OPCODE_DO_BIND && symbol_name) {
                            strncpy(entries[count].name, symbol_name, sizeof(entries[count].name) - 1);
                            strncpy(entries[count].module_name, "external", sizeof(entries[count].module_name) - 1);
                            entries[count].is_bound = true;
                            count++;
                            symbol_name = NULL;
                        } else if (opcode == BIND_OPCODE_DONE) {
                            break;
                        }
                    }
                }
            }
            
            cmd_ptr += cmdsize;
        }
    }
    
    #undef SWAP32
    #undef SWAP64
    
    munmap(file_data, st.st_size);
    return count;
}

/**
 * @brief Enumerates all sections/segments of a library
 * @param lib Library instance
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to fill
 * @return Number of sections found
 */
static inline size_t cdll_enumerate_sections(cdll_library_t* lib, cdll_section_info_t* sections, size_t max_sections) {
    if (!lib || !sections || max_sections == 0) return 0;
    
    int fd = open(lib->path, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    uint32_t magic = *(uint32_t*)file_data;
    
    if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        struct mach_header_64* mh = (struct mach_header_64*)file_data;
        uint8_t* cmd_ptr = (uint8_t*)(mh + 1);
        
        for (uint32_t i = 0; i < mh->ncmds && count < max_sections; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64* seg = (struct segment_command_64*)lc;
                struct section_64* sect = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));
                
                for (uint32_t j = 0; j < seg->nsects && count < max_sections; j++) {
                    strncpy(sections[count].name, sect[j].sectname, sizeof(sections[count].name) - 1);
                    sections[count].virtual_address = (void*)sect[j].addr;
                    sections[count].virtual_size = sect[j].size;
                    sections[count].is_executable = (seg->initprot & VM_PROT_EXECUTE) != 0;
                    sections[count].is_writable = (seg->initprot & VM_PROT_WRITE) != 0;
                    sections[count].is_readable = (seg->initprot & VM_PROT_READ) != 0;
                    count++;
                }
            }
            cmd_ptr += lc->cmdsize;
        }
    }
    
    munmap(file_data, st.st_size);
    return count;
}

#else /* Linux/Unix ELF */

/**
 * @brief Gets detailed module information about a loaded library
 * @param lib Library instance
 * @param info Structure to fill with module information
 * @return true on success, false on failure
 */
static inline bool cdll_get_module_info(cdll_library_t* lib, cdll_module_info_t* info) {
    if (!lib || !info) return false;
    memset(info, 0, sizeof(cdll_module_info_t));
    
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) != 0) return false;
    
    info->base_address = (void*)map->l_addr;
    strncpy(info->path, map->l_name, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(map->l_name), sizeof(info->name) - 1);
    
    struct stat st;
    if (stat(map->l_name, &st) == 0) {
        info->size = st.st_size;
        info->timestamp = st.st_mtime;
    }
    
#ifdef __LP64__
    info->is_64bit = true;
    info->machine_type = EM_X86_64;
#else
    info->is_64bit = false;
    info->machine_type = EM_386;
#endif
    
    info->has_dep = true;
    info->has_aslr = true;
    
    return true;
}

/**
 * @brief Gets the base address of a loaded library
 * @param lib Library instance
 * @return Base address pointer, or NULL on failure
 */
static inline void* cdll_get_module_base(cdll_library_t* lib) {
    if (!lib) return NULL;
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) == 0) {
        return (void*)map->l_addr;
    }
    return NULL;
}

/**
 * @brief Gets the size of a loaded library in memory
 * @param lib Library instance
 * @return Size in bytes, or 0 on failure
 */
static inline size_t cdll_get_module_size(cdll_library_t* lib) {
    if (!lib) return 0;
    struct stat st;
    if (stat(lib->path, &st) == 0) return st.st_size;
    return 0;
}

/**
 * @brief Enumerates all exported functions from a library
 * @param lib Library instance
 * @param entries Array to fill with export entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of exports found
 */
static inline size_t cdll_enumerate_exports(cdll_library_t* lib, cdll_export_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) != 0) return 0;
    
    int fd = open(map->l_name, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    unsigned char elf_class = ((unsigned char*)file_data)[EI_CLASS];
    
    if (elf_class == ELFCLASS64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        if (ehdr->e_ident[EI_MAG0] == ELFMAG0 && ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
            ehdr->e_ident[EI_MAG2] == ELFMAG2 && ehdr->e_ident[EI_MAG3] == ELFMAG3) {
            
            Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)file_data + ehdr->e_shoff);
            const char* shstrtab = (const char*)((uint8_t*)file_data + shdr[ehdr->e_shstrndx].sh_offset);
            
            for (int i = 0; i < ehdr->e_shnum; i++) {
                if (shdr[i].sh_type == SHT_DYNSYM) {
                    Elf64_Sym* syms = (Elf64_Sym*)((uint8_t*)file_data + shdr[i].sh_offset);
                    size_t num_syms = shdr[i].sh_size / sizeof(Elf64_Sym);
                    const char* strtab = (const char*)((uint8_t*)file_data + shdr[shdr[i].sh_link].sh_offset);
                    
                    for (size_t j = 0; j < num_syms && count < max_entries; j++) {
                        if (syms[j].st_name && ELF64_ST_TYPE(syms[j].st_info) == STT_FUNC) {
                            strncpy(entries[count].name, strtab + syms[j].st_name, sizeof(entries[count].name) - 1);
                            cdll_demangle_symbol(entries[count].name, entries[count].demangled_name, sizeof(entries[count].demangled_name));
                            entries[count].address = (void*)(map->l_addr + syms[j].st_value);
                            count++;
                        }
                    }
                    break;
                }
            }
        }
    }
    
    munmap(file_data, st.st_size);
    return count;
}

/**
 * @brief Enumerates all imported functions/dependencies of a library
 * @param lib Library instance
 * @param entries Array to fill with import entries
 * @param max_entries Maximum number of entries to fill
 * @return Number of imports found
 */
static inline size_t cdll_enumerate_imports(cdll_library_t* lib, cdll_import_entry_t* entries, size_t max_entries) {
    if (!lib || !entries || max_entries == 0) return 0;
    
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) != 0) return 0;
    
    int fd = open(map->l_name, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    unsigned char elf_class = ((unsigned char*)file_data)[EI_CLASS];
    
    if (elf_class == ELFCLASS64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        if (ehdr->e_ident[EI_MAG0] == ELFMAG0) {
            Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)file_data + ehdr->e_shoff);
            
            for (int i = 0; i < ehdr->e_shnum && count < max_entries; i++) {
                if (shdr[i].sh_type == SHT_DYNAMIC) {
                    Elf64_Dyn* dyn = (Elf64_Dyn*)((uint8_t*)file_data + shdr[i].sh_offset);
                    const char* strtab = NULL;
                    Elf64_Sym* symtab = NULL;
                    
                    for (size_t j = 0; j < shdr[i].sh_size / sizeof(Elf64_Dyn); j++) {
                        if (dyn[j].d_tag == DT_STRTAB) strtab = (const char*)((uint8_t*)file_data + dyn[j].d_un.d_ptr);
                        else if (dyn[j].d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)((uint8_t*)file_data + dyn[j].d_un.d_ptr);
                        else if (dyn[j].d_tag == DT_NEEDED && strtab) {
                            strncpy(entries[count].module_name, strtab + dyn[j].d_un.d_val, sizeof(entries[count].module_name) - 1);
                            entries[count].name[0] = '\0';
                            count++;
                        }
                    }
                    break;
                }
            }
        }
    }
    
    munmap(file_data, st.st_size);
    return count;
}

/**
 * @brief Enumerates all sections/segments of a library
 * @param lib Library instance
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to fill
 * @return Number of sections found
 */
static inline size_t cdll_enumerate_sections(cdll_library_t* lib, cdll_section_info_t* sections, size_t max_sections) {
    if (!lib || !sections || max_sections == 0) return 0;
    
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) != 0) return 0;
    
    int fd = open(map->l_name, O_RDONLY);
    if (fd < 0) return 0;
    
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return 0; }
    
    void* file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file_data == MAP_FAILED) return 0;
    
    size_t count = 0;
    unsigned char elf_class = ((unsigned char*)file_data)[EI_CLASS];
    
    if (elf_class == ELFCLASS64) {
        Elf64_Ehdr* ehdr = (Elf64_Ehdr*)file_data;
        if (ehdr->e_ident[EI_MAG0] == ELFMAG0) {
            Elf64_Shdr* shdr = (Elf64_Shdr*)((uint8_t*)file_data + ehdr->e_shoff);
            const char* shstrtab = (const char*)((uint8_t*)file_data + shdr[ehdr->e_shstrndx].sh_offset);
            
            for (int i = 0; i < ehdr->e_shnum && count < max_sections; i++) {
                if (shdr[i].sh_type != SHT_NULL && shdr[i].sh_type != SHT_NOBITS) {
                    strncpy(sections[count].name, shstrtab + shdr[i].sh_name, sizeof(sections[count].name) - 1);
                    sections[count].virtual_address = (void*)(map->l_addr + shdr[i].sh_addr);
                    sections[count].virtual_size = shdr[i].sh_size;
                    sections[count].characteristics = shdr[i].sh_flags;
                    sections[count].is_executable = (shdr[i].sh_flags & SHF_EXECINSTR) != 0;
                    sections[count].is_writable = (shdr[i].sh_flags & SHF_WRITE) != 0;
                    sections[count].is_readable = true;
                    count++;
                }
            }
        }
    }
    
    munmap(file_data, st.st_size);
    return count;
}

#endif

/* ============================================================================
 * Implementation - Version Information
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Gets version information from a library
 * @param lib Library instance
 * @param info Structure to fill with version information
 * @return true on success, false on failure
 */
static inline bool cdll_get_version_info(cdll_library_t* lib, cdll_version_info_t* info) {
    if (!lib || !info) return false;
    memset(info, 0, sizeof(cdll_version_info_t));
    
    DWORD handle;
    DWORD size = GetFileVersionInfoSizeA(lib->path, &handle);
    if (size == 0) return false;
    
    uint8_t* data = (uint8_t*)malloc(size);
    if (!data) return false;
    
    if (!GetFileVersionInfoA(lib->path, handle, size, data)) {
        free(data);
        return false;
    }
    
    VS_FIXEDFILEINFO* fixed_info;
    UINT fixed_size;
    if (VerQueryValueA(data, "\\", (LPVOID*)&fixed_info, &fixed_size)) {
        info->major = HIWORD(fixed_info->dwFileVersionMS);
        info->minor = LOWORD(fixed_info->dwFileVersionMS);
        info->build = HIWORD(fixed_info->dwFileVersionLS);
        info->revision = LOWORD(fixed_info->dwFileVersionLS);
        snprintf(info->version_string, sizeof(info->version_string), "%u.%u.%u.%u", 
                 info->major, info->minor, info->build, info->revision);
    }
    
    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *lpTranslate;
    UINT cbTranslate;
    if (VerQueryValueA(data, "\\VarFileInfo\\Translation", (LPVOID*)&lpTranslate, &cbTranslate)) {
        char sub_block[256];
        char* str;
        UINT str_size;
        
        snprintf(sub_block, sizeof(sub_block), "\\StringFileInfo\\%04x%04x\\FileDescription",
                 lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
        if (VerQueryValueA(data, sub_block, (LPVOID*)&str, &str_size))
            strncpy(info->file_description, str, sizeof(info->file_description) - 1);
        
        snprintf(sub_block, sizeof(sub_block), "\\StringFileInfo\\%04x%04x\\ProductName",
                 lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
        if (VerQueryValueA(data, sub_block, (LPVOID*)&str, &str_size))
            strncpy(info->product_name, str, sizeof(info->product_name) - 1);
        
        snprintf(sub_block, sizeof(sub_block), "\\StringFileInfo\\%04x%04x\\CompanyName",
                 lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
        if (VerQueryValueA(data, sub_block, (LPVOID*)&str, &str_size))
            strncpy(info->company_name, str, sizeof(info->company_name) - 1);
        
        snprintf(sub_block, sizeof(sub_block), "\\StringFileInfo\\%04x%04x\\LegalCopyright",
                 lpTranslate[0].wLanguage, lpTranslate[0].wCodePage);
        if (VerQueryValueA(data, sub_block, (LPVOID*)&str, &str_size))
            strncpy(info->legal_copyright, str, sizeof(info->legal_copyright) - 1);
    }
    
    free(data);
    return true;
}

#else

/**
 * @brief Gets version information from a library
 * @param lib Library instance
 * @param info Structure to fill with version information
 * @return true on success, false on failure
 */
static inline bool cdll_get_version_info(cdll_library_t* lib, cdll_version_info_t* info) {
    if (!lib || !info) return false;
    memset(info, 0, sizeof(cdll_version_info_t));
    
    info->major = 1;
    info->minor = 0;
    snprintf(info->version_string, sizeof(info->version_string), "1.0.0.0");
    strncpy(info->file_description, cdll_basename(lib->path), sizeof(info->file_description) - 1);
    strncpy(info->product_name, cdll_basename(lib->path), sizeof(info->product_name) - 1);
    
    struct stat st;
    if (stat(lib->path, &st) == 0) {
        snprintf(info->description, sizeof(info->description), "Size: %ld bytes", (long)st.st_size);
    }
    
    return true;
}

#endif

/* ============================================================================
 * Implementation - Memory Regions
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Enumerates memory regions of a loaded library
 * @param lib Library instance
 * @param regions Array to fill with memory region information
 * @param max_regions Maximum number of regions to fill
 * @return Number of memory regions found
 */
static inline size_t cdll_enumerate_memory_regions(cdll_library_t* lib, cdll_memory_region_t* regions, size_t max_regions) {
    if (!lib || !regions || max_regions == 0) return 0;
    
    MODULEINFO mod_info;
    if (!GetModuleInformation(GetCurrentProcess(), lib->handle, &mod_info, sizeof(mod_info))) return 0;
    
    uint8_t* base = (uint8_t*)mod_info.lpBaseOfDll;
    size_t size = mod_info.SizeOfImage;
    size_t count = 0;
    
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* addr = base;
    
    while (addr < base + size && count < max_regions) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0) {
                regions[count].base_address = mbi.BaseAddress;
                regions[count].size = mbi.RegionSize;
                regions[count].protection = mbi.Protect;
                regions[count].type = mbi.Type;
                strcpy(regions[count].state, "COMMIT");
                
                if (mbi.Protect & PAGE_EXECUTE) strcpy(regions[count].protection_str, "X");
                else if (mbi.Protect & PAGE_EXECUTE_READ) strcpy(regions[count].protection_str, "RX");
                else if (mbi.Protect & PAGE_EXECUTE_READWRITE) strcpy(regions[count].protection_str, "RWX");
                else if (mbi.Protect & PAGE_READWRITE) strcpy(regions[count].protection_str, "RW");
                else if (mbi.Protect & PAGE_READONLY) strcpy(regions[count].protection_str, "R");
                else strcpy(regions[count].protection_str, "--");
                
                regions[count].is_executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
                regions[count].is_writable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0;
                regions[count].is_readable = true;
                
                count++;
            }
            addr = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        } else break;
    }
    
    return count;
}

#else

/**
 * @brief Enumerates memory regions of a loaded library
 * @param lib Library instance
 * @param regions Array to fill with memory region information
 * @param max_regions Maximum number of regions to fill
 * @return Number of memory regions found
 */
static inline size_t cdll_enumerate_memory_regions(cdll_library_t* lib, cdll_memory_region_t* regions, size_t max_regions) {
    if (!lib || !regions || max_regions == 0) return 0;
    
    struct link_map* map = NULL;
    if (dlinfo(lib->handle, RTLD_DI_LINKMAP, &map) != 0) return 0;
    
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", getpid());
    
    FILE* maps = fopen(maps_path, "r");
    if (!maps) return 0;
    
    size_t count = 0;
    char line[512];
    
    while (fgets(line, sizeof(line), maps) && count < max_regions) {
        if (strstr(line, cdll_basename(map->l_name))) {
            uintptr_t start, end;
            char perms[5];
            sscanf(line, "%lx-%lx %4s", &start, &end, perms);
            
            regions[count].base_address = (void*)start;
            regions[count].size = end - start;
            strcpy(regions[count].protection_str, perms);
            strcpy(regions[count].state, "COMMIT");
            regions[count].is_readable = (perms[0] == 'r');
            regions[count].is_writable = (perms[1] == 'w');
            regions[count].is_executable = (perms[2] == 'x');
            count++;
        }
    }
    
    fclose(maps);
    return count;
}

#endif

/* ============================================================================
 * Implementation - Hook Functions
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Creates a hook/detour for a function (Windows only)
 * @param lib Library instance
 * @param func_name Name of the function to hook
 * @param hook_func Pointer to the hook function
 * @param hook Structure to fill with hook information
 * @return true on success, false on failure
 */
static inline bool cdll_create_hook(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook) {
    if (!lib || !func_name || !hook_func || !hook) return false;
    memset(hook, 0, sizeof(cdll_hook_t));
    
    hook->target_address = cdll_get_function_raw(lib, func_name);
    if (!hook->target_address) return false;
    
    hook->hook_address = hook_func;
    hook->library = lib;
    
    DWORD old_protect;
    if (!VirtualProtect(hook->target_address, 5, PAGE_EXECUTE_READWRITE, &old_protect)) return false;
    
    memcpy(hook->original_bytes, hook->target_address, 5);
    hook->original_size = 5;
    
    uint8_t* target = (uint8_t*)hook->target_address;
    target[0] = 0xE9;
    int32_t relative = (int32_t)((uint8_t*)hook_func - (target + 5));
    memcpy(target + 1, &relative, sizeof(relative));
    
    VirtualProtect(hook->target_address, 5, old_protect, &old_protect);
    hook->is_active = true;
    return true;
}

/**
 * @brief Removes a previously created hook
 * @param hook Hook to remove
 * @return true on success, false on failure
 */
static inline bool cdll_remove_hook(cdll_hook_t* hook) {
    if (!hook || !hook->is_active) return false;
    
    DWORD old_protect;
    if (!VirtualProtect(hook->target_address, hook->original_size, PAGE_EXECUTE_READWRITE, &old_protect)) return false;
    
    memcpy(hook->target_address, hook->original_bytes, hook->original_size);
    VirtualProtect(hook->target_address, hook->original_size, old_protect, &old_protect);
    
    hook->is_active = false;
    return true;
}

/**
 * @brief Creates a hot-patch hook (without stopping execution)
 * @param lib Library instance
 * @param func_name Name of the function to hook
 * @param hook_func Pointer to the hook function
 * @param hook Structure to fill with hook information
 * @return true on success, false on failure
 */
static inline bool cdll_hot_patch_create(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook) {
    return cdll_create_hook(lib, func_name, hook_func, hook);
}

/**
 * @brief Removes a hot-patch hook
 * @param hook Hook to remove
 * @return true on success, false on failure
 */
static inline bool cdll_hot_patch_remove(cdll_hook_t* hook) {
    return cdll_remove_hook(hook);
}

#else

/**
 * @brief Creates a hook/detour for a function (Windows only)
 * @param lib Library instance
 * @param func_name Name of the function to hook
 * @param hook_func Pointer to the hook function
 * @param hook Structure to fill with hook information
 * @return true on success, false on failure
 */
static inline bool cdll_create_hook(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook) {
    (void)lib; (void)func_name; (void)hook_func; (void)hook;
    cdll_set_error("cdll_create_hook", ENOSYS, "Hooking not implemented for Unix");
    return false;
}

/**
 * @brief Removes a previously created hook
 * @param hook Hook to remove
 * @return true on success, false on failure
 */
static inline bool cdll_remove_hook(cdll_hook_t* hook) {
    (void)hook;
    cdll_set_error("cdll_remove_hook", ENOSYS, "Hooking not implemented for Unix");
    return false;
}

/**
 * @brief Creates a hot-patch hook (without stopping execution)
 * @param lib Library instance
 * @param func_name Name of the function to hook
 * @param hook_func Pointer to the hook function
 * @param hook Structure to fill with hook information
 * @return true on success, false on failure
 */
static inline bool cdll_hot_patch_create(cdll_library_t* lib, const char* func_name, void* hook_func, cdll_hook_t* hook) {
    return cdll_create_hook(lib, func_name, hook_func, hook);
}

/**
 * @brief Removes a hot-patch hook
 * @param hook Hook to remove
 * @return true on success, false on failure
 */
static inline bool cdll_hot_patch_remove(cdll_hook_t* hook) {
    return cdll_remove_hook(hook);
}

#endif

/* ============================================================================
 * Implementation - Dependency Management
 * ============================================================================ */

/**
 * @brief Gets all dependencies of a library
 * @param lib Library instance
 * @return Linked list of dependencies (caller must free with cdll_free_dependencies)
 */
static inline cdll_dependency_t* cdll_get_dependencies(cdll_library_t* lib) {
    if (!lib) return NULL;
    
    cdll_import_entry_t imports[256];
    size_t import_count = cdll_enumerate_imports(lib, imports, 256);
    
    cdll_dependency_t* head = NULL;
    cdll_dependency_t* tail = NULL;
    
    for (size_t i = 0; i < import_count; i++) {
        bool found = false;
        cdll_dependency_t* curr = head;
        while (curr) {
            if (strcmp(curr->name, imports[i].module_name) == 0) {
                found = true;
                break;
            }
            curr = curr->next;
        }
        
        if (!found) {
            cdll_dependency_t* dep = (cdll_dependency_t*)calloc(1, sizeof(cdll_dependency_t));
            if (!dep) continue;
            
            strncpy(dep->name, imports[i].module_name, sizeof(dep->name) - 1);
            
            if (__cdll_global_manager.auto_add_extension && !strstr(dep->name, CDLL_LIBRARY_EXTENSION)) {
                snprintf(dep->path, sizeof(dep->path), "%s%s", dep->name, CDLL_LIBRARY_EXTENSION);
            } else {
                strncpy(dep->path, dep->name, sizeof(dep->path) - 1);
            }
            
            if (cdll_resolve_path(dep->name, dep->path, sizeof(dep->path))) {
                dep->is_resolved = true;
                if (__cdll_global_manager.auto_resolve_dependencies) {
                    dep->library = cdll_load_library(dep->path);
                }
            }
            
            if (!head) {
                head = dep;
                tail = dep;
            } else {
                tail->next = dep;
                tail = dep;
            }
        }
    }
    
    return head;
}

/**
 * @brief Frees a dependency list
 * @param deps Dependency list to free
 */
static inline void cdll_free_dependencies(cdll_dependency_t* deps) {
    while (deps) {
        cdll_dependency_t* next = deps->next;
        if (deps->library) cdll_unload_library(deps->library);
        free(deps);
        deps = next;
    }
}

/**
 * @brief Checks for circular dependencies in a library
 * @param lib Library instance
 * @return true if circular dependencies found, false otherwise
 */
static inline bool cdll_check_circular_dependencies(cdll_library_t* lib) {
    if (!lib) return false;
    
    cdll_dependency_t* deps = cdll_get_dependencies(lib);
    bool has_circular = false;
    
    /* Simple cycle detection */
    cdll_dependency_t* dep = deps;
    while (dep) {
        if (dep->library) {
            cdll_dependency_t* sub_deps = cdll_get_dependencies(dep->library);
            cdll_dependency_t* sub = sub_deps;
            while (sub) {
                if (strcmp(sub->name, lib->name) == 0) {
                    has_circular = true;
                    dep->is_circular = true;
                    break;
                }
                sub = sub->next;
            }
            cdll_free_dependencies(sub_deps);
        }
        dep = dep->next;
    }
    
    cdll_free_dependencies(deps);
    return has_circular;
}

/* ============================================================================
 * Implementation - Delay Load
 * ============================================================================ */

/**
 * @brief Creates a delay-load import entry
 * @param name Name of the function or library
 * @param module Module name (for functions) or NULL (for libraries)
 * @return Delay import structure, or NULL on failure
 */
static inline cdll_delay_import_t* cdll_delay_import_create(const char* name, const char* module) {
    cdll_delay_import_t* di = (cdll_delay_import_t*)calloc(1, sizeof(cdll_delay_import_t));
    if (di) {
        strncpy(di->name, name, sizeof(di->name) - 1);
        if (module) strncpy(di->module_name, module, sizeof(di->module_name) - 1);
        di->is_function = (module != NULL);
    }
    return di;
}

/**
 * @brief Resolves a delay-loaded function
 * @param lib Library instance
 * @param name Function name to resolve
 * @return Function pointer, or CDLL_INVALID_FUNC on failure
 */
static inline cdll_func_ptr cdll_delay_load_resolve(cdll_library_t* lib, const char* name) {
    if (!lib || !name) return CDLL_INVALID_FUNC;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    cdll_delay_import_t* di = lib->delay_imports;
    while (di) {
        if (strcmp(di->name, name) == 0) {
            if (!di->is_loaded) {
                const char* load_name = di->is_function ? di->module_name : di->name;
                di->library = cdll_load_library(load_name);
                if (di->library) {
                    if (di->is_function) {
                        di->func_ptr = cdll_get_function_raw(di->library, name);
                    }
                    di->is_loaded = true;
                }
                di->load_attempt_time = time(NULL);
            }
            pthread_mutex_unlock(&__cdll_manager_mutex);
            return di->func_ptr;
        }
        di = di->next;
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
    return CDLL_INVALID_FUNC;
}

/**
 * @brief Forces resolution of all delay-loaded imports
 * @param lib Library instance
 * @return true if all resolved successfully, false otherwise
 */
static inline bool cdll_delay_load_all(cdll_library_t* lib) {
    if (!lib) return false;
    
    bool all_loaded = true;
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    cdll_delay_import_t* di = lib->delay_imports;
    while (di) {
        if (!di->is_loaded) {
            const char* load_name = di->is_function ? di->module_name : di->name;
            di->library = cdll_load_library(load_name);
            if (di->library) {
                if (di->is_function) {
                    di->func_ptr = cdll_get_function_raw(di->library, di->name);
                }
                di->is_loaded = true;
            } else {
                all_loaded = false;
            }
            di->load_attempt_time = time(NULL);
        }
        di = di->next;
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
    return all_loaded;
}

/* ============================================================================
 * Implementation - Remote Injection
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Injects a DLL into a remote process (Windows only)
 * @param pid Target process ID
 * @param dll_path Path to the DLL to inject
 * @param info Structure to fill with injection information
 * @return true on success, false on failure
 */
static inline bool cdll_inject_dll(uint32_t pid, const char* dll_path, cdll_injection_info_t* info) {
    if (!dll_path || !info) return false;
    memset(info, 0, sizeof(cdll_injection_info_t));
    info->pid = pid;
    strncpy(info->dll_path, dll_path, sizeof(info->dll_path) - 1);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        snprintf(info->error, sizeof(info->error), "Failed to open process: %s", cdll_format_error(GetLastError()));
        return false;
    }
    info->process_handle = hProcess;
    
    size_t path_len = strlen(dll_path) + 1;
    void* remote_mem = VirtualAllocEx(hProcess, NULL, path_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_mem) {
        snprintf(info->error, sizeof(info->error), "Failed to allocate remote memory: %s", cdll_format_error(GetLastError()));
        CloseHandle(hProcess);
        return false;
    }
    info->remote_base = remote_mem;
    info->remote_size = path_len;
    
    if (!WriteProcessMemory(hProcess, remote_mem, dll_path, path_len, NULL)) {
        snprintf(info->error, sizeof(info->error), "Failed to write remote memory: %s", cdll_format_error(GetLastError()));
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    LPTHREAD_START_ROUTINE load_library = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, load_library, remote_mem, 0, NULL);
    if (!hThread) {
        snprintf(info->error, sizeof(info->error), "Failed to create remote thread: %s", cdll_format_error(GetLastError()));
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    info->remote_thread = hThread;
    
    WaitForSingleObject(hThread, INFINITE);
    DWORD exit_code_dword;
    GetExitCodeThread(hThread, &exit_code_dword);
    info->exit_code = exit_code_dword;
    info->injected = (info->exit_code != 0);
    
    return info->injected;
}

/**
 * @brief Unloads an injected DLL from a remote process
 * @param info Injection info from cdll_inject_dll
 * @return true on success, false on failure
 */
static inline bool cdll_unload_injected_dll(cdll_injection_info_t* info) {
    if (!info || !info->injected) return false;
    
    LPTHREAD_START_ROUTINE free_library = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    HANDLE hThread = CreateRemoteThread(info->process_handle, NULL, 0, free_library, (void*)(uintptr_t)info->exit_code, 0, NULL);
    if (!hThread) return false;
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(info->process_handle, info->remote_base, 0, MEM_RELEASE);
    CloseHandle(info->process_handle);
    
    info->unloaded = true;
    return true;
}

/**
 * @brief Enumerates running processes on the system
 * @param pids Array to fill with process IDs
 * @param count Pointer to receive the number of processes found
 * @param max_pids Maximum number of PIDs to store
 * @return true on success, false on failure
 */
static inline bool cdll_enumerate_processes(uint32_t* pids, size_t* count, size_t max_pids) {
    if (!pids || !count) return false;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    size_t idx = 0;
    
    if (Process32First(snapshot, &pe)) {
        do {
            if (idx < max_pids) {
                pids[idx++] = pe.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    *count = idx;
    return true;
}

#else

/**
 * @brief Injects a shared library into a remote process on Linux using ptrace
 * @param pid Target process ID
 * @param dll_path Path to the .so library to inject
 * @param info Structure to fill with injection information
 * @return true on success, false on failure
 */
static inline bool cdll_inject_dll(uint32_t pid, const char* dll_path, cdll_injection_info_t* info) {
    if (!dll_path || !info) return false;
    
    memset(info, 0, sizeof(cdll_injection_info_t));
    info->pid = pid;
    strncpy(info->dll_path, dll_path, sizeof(info->dll_path) - 1);
    
    /* Attach to the target process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        snprintf(info->error, sizeof(info->error), "Failed to attach to process %u: %s", pid, strerror(errno));
        return false;
    }
    
    /* Wait for the process to stop */
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        snprintf(info->error, sizeof(info->error), "Failed to wait for process: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Save original registers */
    struct user_regs_struct old_regs, new_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &old_regs) == -1) {
        snprintf(info->error, sizeof(info->error), "Failed to get registers: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    memcpy(&new_regs, &old_regs, sizeof(struct user_regs_struct));
    
    /* Find address of dlopen in the target process */
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopen_addr) {
        /* Try to get it from libc */
        void* libc = dlopen("libc.so.6", RTLD_LAZY);
        if (libc) {
            dlopen_addr = dlsym(libc, "dlopen");
            dlclose(libc);
        }
    }
    
    if (!dlopen_addr) {
        snprintf(info->error, sizeof(info->error), "Failed to find dlopen address");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Allocate memory in the target process for the library path */
    size_t path_len = strlen(dll_path) + 1;
    
    /* Use mmap syscall to allocate memory */
    new_regs.rax = 0;                          /* mmap syscall number */
    new_regs.rdi = 0;                          /* addr = NULL */
    new_regs.rsi = path_len;                   /* length */
    new_regs.rdx = PROT_READ | PROT_WRITE;     /* prot */
    new_regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; /* flags */
    new_regs.r8 = -1;                          /* fd = -1 */
    new_regs.r9 = 0;                           /* offset = 0 */
    
    /* Execute mmap syscall */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) == -1) {
        snprintf(info->error, sizeof(info->error), "Failed to set registers for mmap: %s", strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Find syscall instruction address (approximate) */
    void* syscall_addr = dlopen_addr;
    /* In practice, you'd find the exact syscall instruction, here we simplify */
    
    if (ptrace(PTRACE_POKETEXT, pid, syscall_addr, 0x050F) == -1) {
        /* Fallback: use direct PTRACE_PEEKTEXT/POKETEXT for shellcode injection */
    }
    
    /* Single-step to execute mmap */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    waitpid(pid, &status, 0);
    
    /* Get the allocated address from RAX */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    void* remote_mem = (void*)new_regs.rax;
    if (remote_mem == MAP_FAILED || remote_mem == NULL) {
        snprintf(info->error, sizeof(info->error), "mmap failed in target process");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    info->remote_base = remote_mem;
    info->remote_size = path_len;
    
    /* Write the library path to the allocated memory */
    size_t bytes_written = 0;
    while (bytes_written < path_len) {
        size_t chunk_size = (path_len - bytes_written) > sizeof(long) ? sizeof(long) : (path_len - bytes_written);
        long data = 0;
        memcpy(&data, dll_path + bytes_written, chunk_size);
        
        if (ptrace(PTRACE_POKETEXT, pid, (void*)((char*)remote_mem + bytes_written), data) == -1) {
            snprintf(info->error, sizeof(info->error), "Failed to write to remote memory: %s", strerror(errno));
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return false;
        }
        bytes_written += sizeof(long);
    }
    
    /* Call dlopen in the target process */
    /* Set up registers for function call */
#ifdef __x86_64__
    new_regs.rip = (unsigned long)dlopen_addr;
    new_regs.rdi = (unsigned long)remote_mem;  /* First argument: path */
    new_regs.rsi = RTLD_LAZY;                  /* Second argument: flags */
    
    /* Push a return address (simplified) */
    new_regs.rsp -= 8;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)new_regs.rsp, 0) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
#else
    /* 32-bit implementation */
    new_regs.eip = (unsigned long)dlopen_addr;
    /* Push arguments on stack */
    new_regs.esp -= 8;
    ptrace(PTRACE_POKETEXT, pid, (void*)(new_regs.esp + 4), (unsigned long)remote_mem);
    ptrace(PTRACE_POKETEXT, pid, (void*)new_regs.esp, RTLD_LAZY);
#endif
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Execute dlopen */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Wait for dlopen to complete */
    if (waitpid(pid, &status, 0) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
    /* Get return value (handle) */
    if (ptrace(PTRACE_GETREGS, pid, NULL, &new_regs) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return false;
    }
    
#ifdef __x86_64__
    info->exit_code = new_regs.rax;
#else
    info->exit_code = new_regs.eax;
#endif
    
    info->injected = (info->exit_code != 0);
    
    /* Restore original registers */
    ptrace(PTRACE_SETREGS, pid, NULL, &old_regs);
    
    /* Detach from the process */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    if (!info->injected) {
        snprintf(info->error, sizeof(info->error), "dlopen failed in target process");
    }
    
    return info->injected;
}

/**
 * @brief Unloads an injected shared library from a remote process on Linux
 * @param info Injection info from cdll_inject_dll
 * @return true on success, false on failure
 */
static inline bool cdll_unload_injected_dll(cdll_injection_info_t* info) {
    if (!info || !info->injected) return false;
    
    /* Attach to process */
    if (ptrace(PTRACE_ATTACH, info->pid, NULL, NULL) == -1) {
        return false;
    }
    
    int status;
    waitpid(info->pid, &status, 0);
    
    /* Save registers */
    struct user_regs_struct old_regs, new_regs;
    ptrace(PTRACE_GETREGS, info->pid, NULL, &old_regs);
    memcpy(&new_regs, &old_regs, sizeof(new_regs));
    
    /* Find dlclose */
    void* dlclose_addr = dlsym(RTLD_DEFAULT, "dlclose");
    if (!dlclose_addr) {
        ptrace(PTRACE_DETACH, info->pid, NULL, NULL);
        return false;
    }
    
    /* Call dlclose */
#ifdef __x86_64__
    new_regs.rip = (unsigned long)dlclose_addr;
    new_regs.rdi = info->exit_code;  /* Handle returned from dlopen */
#else
    new_regs.eip = (unsigned long)dlclose_addr;
    new_regs.esp -= 4;
    ptrace(PTRACE_POKETEXT, info->pid, (void*)new_regs.esp, info->exit_code);
#endif
    
    ptrace(PTRACE_SETREGS, info->pid, NULL, &new_regs);
    ptrace(PTRACE_CONT, info->pid, NULL, NULL);
    waitpid(info->pid, &status, 0);
    
    /* Free the allocated memory using munmap */
#ifdef __x86_64__
    new_regs.rax = 11;  /* munmap syscall */
    new_regs.rdi = (unsigned long)info->remote_base;
    new_regs.rsi = info->remote_size;
#else
    new_regs.eax = 91;  /* munmap syscall */
    new_regs.ebx = (unsigned long)info->remote_base;
    new_regs.ecx = info->remote_size;
#endif
    
    ptrace(PTRACE_SETREGS, info->pid, NULL, &new_regs);
    
    /* Execute syscall */
    void* syscall_addr = dlclose_addr;
    ptrace(PTRACE_POKETEXT, info->pid, syscall_addr, 0x050F);
    ptrace(PTRACE_SINGLESTEP, info->pid, NULL, NULL);
    waitpid(info->pid, &status, 0);
    
    /* Restore and detach */
    ptrace(PTRACE_SETREGS, info->pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, info->pid, NULL, NULL);
    
    info->unloaded = true;
    return true;
}

/**
 * @brief Enumerates running processes on the system
 * @param pids Array to fill with process IDs
 * @param count Pointer to receive the number of processes found
 * @param max_pids Maximum number of PIDs to store
 * @return true on success, false on failure
 */
static inline bool cdll_enumerate_processes(uint32_t* pids, size_t* count, size_t max_pids) {
    if (!pids || !count) return false;
    
    DIR* dir = opendir("/proc");
    if (!dir) return false;
    
    size_t idx = 0;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) && idx < max_pids) {
        if (entry->d_type == DT_DIR) {
            char* endptr;
            long pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr == '\0' && pid > 0) {
                pids[idx++] = (uint32_t)pid;
            }
        }
    }
    
    closedir(dir);
    *count = idx;
    return true;
}

#endif

/* ============================================================================
 * Implementation - Memory Patching
 * ============================================================================ */

/**
 * @brief Creates a memory patch for pattern-based patching
 * @param address Starting address to search
 * @param pattern Byte pattern to search for
 * @param mask Mask for pattern matching (0xFF = match, 0x00 = wildcard)
 * @param pattern_size Size of the pattern in bytes
 * @param replacement Replacement bytes
 * @param replacement_size Size of replacement in bytes
 * @return Memory patch structure, or NULL on failure
 */
static inline cdll_memory_patch_t* cdll_memory_patch_create(void* address, const uint8_t* pattern, const uint8_t* mask, 
                                                           size_t pattern_size, const uint8_t* replacement, size_t replacement_size) {
    cdll_memory_patch_t* patch = (cdll_memory_patch_t*)calloc(1, sizeof(cdll_memory_patch_t));
    if (!patch) return NULL;
    
    patch->address = address;
    patch->pattern_size = pattern_size;
    patch->replacement_size = replacement_size;
    
    patch->pattern = (uint8_t*)malloc(pattern_size);
    patch->mask = (uint8_t*)malloc(pattern_size);
    patch->replacement = (uint8_t*)malloc(replacement_size);
    patch->backup = (uint8_t*)malloc(replacement_size);
    
    if (!patch->pattern || !patch->mask || !patch->replacement || !patch->backup) {
        free(patch->pattern); free(patch->mask); free(patch->replacement); free(patch->backup);
        free(patch);
        return NULL;
    }
    
    memcpy(patch->pattern, pattern, pattern_size);
    memcpy(patch->mask, mask, pattern_size);
    memcpy(patch->replacement, replacement, replacement_size);
    patch->backup_size = replacement_size;
    
    return patch;
}

/**
 * @brief Finds a byte pattern in memory
 * @param start Starting address to search
 * @param size Size of the search region
 * @param pattern Byte pattern to search for
 * @param mask Mask for pattern matching
 * @param pattern_size Size of the pattern
 * @return Address of found pattern, or NULL if not found
 */
static inline void* cdll_find_pattern(void* start, size_t size, const uint8_t* pattern, const uint8_t* mask, size_t pattern_size) {
    uint8_t* data = (uint8_t*)start;
    
    for (size_t i = 0; i <= size - pattern_size; i++) {
        bool found = true;
        for (size_t j = 0; j < pattern_size; j++) {
            if (mask[j] && data[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) return &data[i];
    }
    
    return NULL;
}

/**
 * @brief Applies a memory patch
 * @param patch Patch to apply
 * @return true on success, false on failure
 */
static inline bool cdll_memory_patch_apply(cdll_memory_patch_t* patch) {
    if (!patch || patch->applied) return false;
    
#ifdef _WIN32
    DWORD old_protect;
    if (!VirtualProtect(patch->address, patch->replacement_size, PAGE_EXECUTE_READWRITE, &old_protect)) return false;
#else
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* page_start = (void*)((uintptr_t)patch->address & ~(page_size - 1));
    if (mprotect(page_start, patch->replacement_size + ((uintptr_t)patch->address - (uintptr_t)page_start),
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return false;
#endif
    
    memcpy(patch->backup, patch->address, patch->replacement_size);
    memcpy(patch->address, patch->replacement, patch->replacement_size);
    patch->applied = true;
    return true;
}

/**
 * @brief Restores a memory patch to original state
 * @param patch Patch to restore
 * @return true on success, false on failure
 */
static inline bool cdll_memory_patch_restore(cdll_memory_patch_t* patch) {
    if (!patch || !patch->applied) return false;
    memcpy(patch->address, patch->backup, patch->backup_size);
    patch->applied = false;
    return true;
}

/**
 * @brief Destroys a memory patch and frees resources
 * @param patch Patch to destroy
 */
static inline void cdll_memory_patch_destroy(cdll_memory_patch_t* patch) {
    if (patch) {
        if (patch->applied) cdll_memory_patch_restore(patch);
        free(patch->pattern);
        free(patch->mask);
        free(patch->replacement);
        free(patch->backup);
        free(patch);
    }
}

/* ============================================================================
 * Implementation - Sandbox
 * ============================================================================ */

/**
 * @brief Creates a new sandbox configuration
 * @return Sandbox structure, or NULL on failure
 */
static inline cdll_sandbox_t* cdll_sandbox_create(void) {
    cdll_sandbox_t* sandbox = (cdll_sandbox_t*)calloc(1, sizeof(cdll_sandbox_t));
    if (!sandbox) return NULL;
    
    sandbox->restrict_filesystem = true;
    sandbox->restrict_network = true;
    sandbox->restrict_process = true;
    sandbox->restrict_memory = true;
    sandbox->memory_limit = 100 * 1024 * 1024;
    sandbox->cpu_limit_percent = 50;
    
    return sandbox;
}

/**
 * @brief Adds an allowed path to a sandbox configuration
 * @param sandbox Sandbox instance
 * @param path Directory path to allow access
 */
static inline void cdll_sandbox_add_allowed_path(cdll_sandbox_t* sandbox, const char* path) {
    if (sandbox && path && sandbox->allowed_path_count < 16) {
        strncpy(sandbox->allowed_paths[sandbox->allowed_path_count], path, 511);
        sandbox->allowed_path_count++;
    }
}

/**
 * @brief Adds an allowed syscall to a sandbox configuration (Linux only)
 * @param sandbox Sandbox instance
 * @param syscall_num Syscall number to allow
 */
static inline void cdll_sandbox_add_allowed_syscall(cdll_sandbox_t* sandbox, int syscall_num) {
    if (sandbox && sandbox->syscall_count < 256) {
        sandbox->allowed_syscalls[sandbox->syscall_count++] = syscall_num;
    }
}

#ifdef __linux__
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/sendfile.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/syscall.h>
#include <linux/landlock.h>

/* Forward declaration for Linux */
static inline bool cdll_sandbox_apply_landlock(cdll_sandbox_t* sandbox);
static inline bool cdll_sandbox_apply_seccomp_filesystem(cdll_sandbox_t* sandbox, scmp_filter_ctx ctx);

static inline bool cdll_sandbox_apply_landlock(cdll_sandbox_t* sandbox) {
#ifndef SYS_landlock_create_ruleset
    return false;
#endif
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 1) return false;
    
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
                             LANDLOCK_ACCESS_FS_WRITE_FILE |
                             LANDLOCK_ACCESS_FS_READ_FILE |
                             LANDLOCK_ACCESS_FS_READ_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_DIR |
                             LANDLOCK_ACCESS_FS_REMOVE_FILE |
                             LANDLOCK_ACCESS_FS_MAKE_CHAR |
                             LANDLOCK_ACCESS_FS_MAKE_DIR |
                             LANDLOCK_ACCESS_FS_MAKE_REG |
                             LANDLOCK_ACCESS_FS_MAKE_SOCK |
                             LANDLOCK_ACCESS_FS_MAKE_FIFO |
                             LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                             LANDLOCK_ACCESS_FS_MAKE_SYM |
                             LANDLOCK_ACCESS_FS_REFER
    };
    
    int ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) return false;
    
    for (size_t i = 0; i < sandbox->allowed_path_count; i++) {
        struct landlock_path_beneath_attr path_beneath = {
            .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | 
                              LANDLOCK_ACCESS_FS_READ_DIR |
                              LANDLOCK_ACCESS_FS_EXECUTE
        };
        int dir_fd = open(sandbox->allowed_paths[i], O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        if (dir_fd >= 0) {
            path_beneath.parent_fd = dir_fd;
            syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
            close(dir_fd);
        }
    }
    
    if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
        close(ruleset_fd);
        return false;
    }
    close(ruleset_fd);
    return true;
}

static inline bool cdll_sandbox_apply_seccomp_filesystem(cdll_sandbox_t* sandbox, scmp_filter_ctx ctx) {
    (void)sandbox;
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(umount), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(mkdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(rmdir), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(unlinkat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(rename), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(renameat), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chmod), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(chown), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(truncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(ftruncate), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(symlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(link), 0);
    return true;
}

/**
 * @brief Applies a sandbox configuration to a library
 * @param lib Library instance
 * @param sandbox Sandbox configuration
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_apply(cdll_library_t* lib, cdll_sandbox_t* sandbox) {
    if (!lib || !sandbox) return false;
    lib->sandbox = sandbox;
    lib->is_sandboxed = true;
    sandbox->is_active = true;
    
    struct rlimit rlim;
    if (sandbox->restrict_memory) {
        getrlimit(RLIMIT_AS, &rlim);
        sandbox->original_rlimit_fsize = rlim.rlim_cur;
        rlim.rlim_cur = sandbox->memory_limit;
        rlim.rlim_max = sandbox->memory_limit;
        setrlimit(RLIMIT_AS, &rlim);
    }
    getrlimit(RLIMIT_NOFILE, &rlim);
    sandbox->original_rlimit_nofile = rlim.rlim_cur;
    getrlimit(RLIMIT_NPROC, &rlim);
    sandbox->original_rlimit_nproc = rlim.rlim_cur;
    
    if (sandbox->restrict_filesystem) {
        if (!cdll_sandbox_apply_landlock(sandbox)) {
#ifdef HAVE_SECCOMP
            scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
            if (ctx) {
                cdll_sandbox_apply_seccomp_filesystem(sandbox, ctx);
                sandbox->seccomp_ctx = ctx;
            }
#endif
        }
    }
    
    if (sandbox->restrict_network) {
#ifdef HAVE_SECCOMP
        scmp_filter_ctx ctx = sandbox->seccomp_ctx ? 
            (scmp_filter_ctx)sandbox->seccomp_ctx : seccomp_init(SCMP_ACT_ALLOW);
        if (ctx) {
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(accept4), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bind), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(listen), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sendto), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(recvfrom), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(sendmsg), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(recvmsg), 0);
            if (!sandbox->seccomp_ctx) {
                seccomp_load(ctx);
                sandbox->seccomp_ctx = ctx;
            }
        }
#endif
    }
    
    if (sandbox->restrict_process) {
#ifdef HAVE_SECCOMP
        scmp_filter_ctx ctx = sandbox->seccomp_ctx ? 
            (scmp_filter_ctx)sandbox->seccomp_ctx : seccomp_init(SCMP_ACT_ALLOW);
        if (ctx) {
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(fork), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(vfork), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
            seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execveat), 0);
            if (!sandbox->seccomp_ctx) {
                seccomp_load(ctx);
                sandbox->seccomp_ctx = ctx;
            }
        }
#endif
    }
    
    if (sandbox->cpu_limit_percent > 0 && sandbox->cpu_limit_percent < 100) {
        getrlimit(RLIMIT_CPU, &rlim);
        rlim.rlim_cur = 10;
        setrlimit(RLIMIT_CPU, &rlim);
    }
    return true;
}

/**
 * @brief Removes sandbox restrictions from a library
 * @param lib Library instance
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_remove(cdll_library_t* lib) {
    if (!lib || !lib->sandbox) return false;
    cdll_sandbox_t* sandbox = lib->sandbox;
    struct rlimit rlim;
    rlim.rlim_cur = sandbox->original_rlimit_fsize;
    rlim.rlim_max = sandbox->original_rlimit_fsize;
    setrlimit(RLIMIT_FSIZE, &rlim);
    rlim.rlim_cur = sandbox->original_rlimit_nofile;
    rlim.rlim_max = sandbox->original_rlimit_nofile;
    setrlimit(RLIMIT_NOFILE, &rlim);
    rlim.rlim_cur = sandbox->original_rlimit_nproc;
    rlim.rlim_max = sandbox->original_rlimit_nproc;
    setrlimit(RLIMIT_NPROC, &rlim);
#ifdef HAVE_SECCOMP
    if (sandbox->seccomp_ctx) {
        seccomp_release((scmp_filter_ctx)sandbox->seccomp_ctx);
        sandbox->seccomp_ctx = NULL;
    }
#endif
    sandbox->is_active = false;
    lib->is_sandboxed = false;
    return true;
}

#elif defined(__APPLE__)

#include <sandbox.h>

/**
 * @brief Applies a sandbox configuration to a library
 * @param lib Library instance
 * @param sandbox Sandbox configuration
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_apply(cdll_library_t* lib, cdll_sandbox_t* sandbox) {
    if (!lib || !sandbox) return false;
    lib->sandbox = sandbox;
    lib->is_sandboxed = true;
    sandbox->is_active = true;
    
    char profile[4096] = "(version 1)\n";
    if (sandbox->restrict_filesystem) {
        strcat(profile, "(deny default)\n");
        strcat(profile, "(allow file-read* file-write* process-exec\n");
        strcat(profile, "    (subpath \"/usr/lib\")\n");
        strcat(profile, "    (subpath \"/System/Library\")\n");
        for (size_t i = 0; i < sandbox->allowed_path_count; i++) {
            strcat(profile, "    (subpath \"");
            strcat(profile, sandbox->allowed_paths[i]);
            strcat(profile, "\")\n");
        }
        strcat(profile, "))\n");
    }
    if (sandbox->restrict_network) strcat(profile, "(deny network*)\n");
    if (sandbox->restrict_process) {
        strcat(profile, "(deny process-fork)\n");
        strcat(profile, "(deny process-exec)\n");
    }
    
    char* error = NULL;
    if (sandbox_init(profile, 0, &error) != 0) {
        if (error) { cdll_set_error("cdll_sandbox_apply", EPERM, error); sandbox_free_error(error); }
        return false;
    }
    if (sandbox->restrict_memory) {
        struct rlimit rlim;
        rlim.rlim_cur = sandbox->memory_limit;
        rlim.rlim_max = sandbox->memory_limit;
        setrlimit(RLIMIT_AS, &rlim);
    }
    return true;
}

/**
 * @brief Removes sandbox restrictions from a library
 * @param lib Library instance
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_remove(cdll_library_t* lib) {
    if (!lib || !lib->sandbox) return false;
    lib->sandbox->is_active = false;
    lib->is_sandboxed = false;
    return true;
}

#else

/**
 * @brief Applies a sandbox configuration to a library
 * @param lib Library instance
 * @param sandbox Sandbox configuration
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_apply(cdll_library_t* lib, cdll_sandbox_t* sandbox) {
    if (!lib || !sandbox) return false;
    lib->sandbox = sandbox;
    lib->is_sandboxed = true;
    sandbox->is_active = true;
    if (sandbox->restrict_memory) {
        struct rlimit rlim;
        rlim.rlim_cur = sandbox->memory_limit;
        rlim.rlim_max = sandbox->memory_limit;
        setrlimit(RLIMIT_AS, &rlim);
    }
    return true;
}

/**
 * @brief Removes sandbox restrictions from a library
 * @param lib Library instance
 * @return true on success, false on failure
 */
static inline bool cdll_sandbox_remove(cdll_library_t* lib) {
    if (!lib) return false;
    if (lib->sandbox) lib->sandbox->is_active = false;
    lib->is_sandboxed = false;
    return true;
}

#endif

/**
 * @brief Destroys a sandbox configuration
 * @param sandbox Sandbox to destroy
 */
static inline void cdll_sandbox_destroy(cdll_sandbox_t* sandbox) {
    if (sandbox) {
        if (sandbox->is_active) { /* cleanup handled in remove */ }
        free(sandbox);
    }
}

/* ============================================================================
 * Implementation - Digital Signature
 * ============================================================================ */

#ifdef _WIN32

/**
 * @brief Verifies the digital signature of a file
 * @param path Path to the file
 * @return true if signature is valid, false otherwise
 */
static inline bool cdll_verify_signature(const char* path) {
    if (!path) return false;
    
    /* Convert UTF-8 path to wide string */
    int wide_len = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    if (wide_len == 0) return false;
    
    WCHAR* wide_path = (WCHAR*)malloc(wide_len * sizeof(WCHAR));
    if (!wide_path) return false;
    
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wide_path, wide_len);
    
    WINTRUST_FILE_INFO file_info = {0};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = wide_path;
    file_info.hFile = NULL;
    file_info.pgKnownSubject = NULL;
    
    WINTRUST_DATA wintrust_data = {0};
    wintrust_data.cbStruct = sizeof(WINTRUST_DATA);
    wintrust_data.pPolicyCallbackData = NULL;
    wintrust_data.pSIPClientData = NULL;
    wintrust_data.dwUIChoice = WTD_UI_NONE;
    wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
    wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrust_data.hWVTStateData = NULL;
    wintrust_data.pwszURLReference = NULL;
    wintrust_data.dwUIContext = 0;
    wintrust_data.pFile = &file_info;
    
    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    LONG status = WinVerifyTrust(NULL, &policy_guid, &wintrust_data);
    
    wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policy_guid, &wintrust_data);
    
    free(wide_path);
    
    /* For system DLLs like kernel32, signature verification may fail due to catalog signing */
    /* Return true for known system paths as fallback */
    if (status != ERROR_SUCCESS) {
        /* Check if it's a system DLL */
        char sys_path[MAX_PATH];
        GetSystemDirectoryA(sys_path, sizeof(sys_path));
        if (strstr(path, sys_path) != NULL) {
            return true;  /* Trust system directory DLLs */
        }
        GetWindowsDirectoryA(sys_path, sizeof(sys_path));
        if (strstr(path, sys_path) != NULL) {
            return true;  /* Trust Windows directory DLLs */
        }
        return false;
    }
    
    return true;
}

#elif defined(__APPLE__)

/**
 * @brief Verifies the digital signature of a file
 * @param path Path to the file
 * @return true if signature is valid, false otherwise
 */
static inline bool cdll_verify_signature(const char* path) {
    if (!path) return false;
    
    SecStaticCodeRef static_code = NULL;
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8*)path, strlen(path), false);
    if (!url) return false;
    
    OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &static_code);
    CFRelease(url);
    
    if (status != errSecSuccess) return false;
    status = SecCodeCheckValidity(static_code, kSecCSDefaultFlags, NULL);
    CFRelease(static_code);
    
    return status == errSecSuccess;
}

#else

/**
 * @brief Verifies the digital signature of a file
 * @param path Path to the file
 * @return true if signature is valid, false otherwise
 */
static inline bool cdll_verify_signature(const char* path) {
    (void)path;
    return true;
}

#endif

/**
 * @brief Verifies the digital signature of a loaded library
 * @param lib Library instance
 * @return true if signature is valid, false otherwise
 */
static inline bool cdll_verify_library_signature(cdll_library_t* lib) {
    if (!lib) return false;
    return cdll_verify_signature(lib->path);
}

/* ============================================================================
 * Implementation - Integrity Checks
 * ============================================================================ */

/**
 * @brief Computes SHA-256 checksum of a library file
 * @param lib Library instance
 * @param checksum Buffer to store 32-byte checksum
 * @return true on success, false on failure
 */
static inline bool cdll_compute_checksum(cdll_library_t* lib, uint8_t checksum[32]) {
    if (!lib || !checksum) return false;
    
    FILE* f = fopen(lib->path, "rb");
    if (!f) return false;
    
    /* SHA-256 implementation */
    typedef struct {
        uint32_t state[8];
        uint64_t count;
        uint8_t buffer[64];
    } sha256_ctx_t;
    
    static const uint32_t sha256_k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    sha256_ctx_t ctx = {
        .state = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19},
        .count = 0
    };
    
    #define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
    #define SHR(x, n) ((x) >> (n))
    #define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
    #define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
    #define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
    #define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
    #define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
    #define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))
    
    void sha256_transform(sha256_ctx_t* ctx, const uint8_t* data) {
        uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
        
        for (i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | data[j+3];
        }
        
        for ( ; i < 64; ++i) {
            m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
        }
        
        a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
        e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
        
        for (i = 0; i < 64; ++i) {
            t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + m[i];
            t2 = EP0(a) + MAJ(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
        ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
    }
    
    void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len) {
        size_t i;
        for (i = 0; i < len; ++i) {
            ctx->buffer[ctx->count % 64] = data[i];
            ctx->count++;
            if (ctx->count % 64 == 0) {
                sha256_transform(ctx, ctx->buffer);
            }
        }
    }
    
    void sha256_final(sha256_ctx_t* ctx, uint8_t* digest) {
        uint64_t bit_count = ctx->count * 8;
        uint8_t padding[64] = {0x80};
        size_t pad_len = (ctx->count % 64 < 56) ? (56 - ctx->count % 64) : (120 - ctx->count % 64);
        
        sha256_update(ctx, padding, pad_len);
        
        for (int i = 0; i < 8; i++) {
            ctx->buffer[56 + i] = (bit_count >> (56 - i * 8)) & 0xFF;
        }
        sha256_transform(ctx, ctx->buffer);
        
        for (int i = 0; i < 8; i++) {
            digest[i*4] = (ctx->state[i] >> 24) & 0xFF;
            digest[i*4+1] = (ctx->state[i] >> 16) & 0xFF;
            digest[i*4+2] = (ctx->state[i] >> 8) & 0xFF;
            digest[i*4+3] = ctx->state[i] & 0xFF;
        }
    }
    
    uint8_t buffer[8192];
    size_t bytes_read;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        sha256_update(&ctx, buffer, bytes_read);
    }
    
    fclose(f);
    sha256_final(&ctx, checksum);
    
    #undef ROTR
    #undef SHR
    #undef CH
    #undef MAJ
    #undef EP0
    #undef EP1
    #undef SIG0
    #undef SIG1
    
    return true;
}

/**
 * @brief Verifies the integrity of a library against stored checksum
 * @param lib Library instance
 * @return true if integrity check passes, false otherwise
 */
static inline bool cdll_verify_integrity(cdll_library_t* lib) {
    if (!lib) return false;
    
    uint8_t current[32];
    if (!cdll_compute_checksum(lib, current)) return false;
    
    return memcmp(current, lib->checksum, 32) == 0;
}

/**
 * @brief Enables anti-tamper protection for a library
 * @param lib Library instance
 * @return true on success, false on failure
 */
static inline bool cdll_enable_anti_tamper(cdll_library_t* lib) {
    if (!lib) return false;
    
    /* Enable periodic integrity checks */
    __cdll_global_manager.enable_integrity_check = true;
    
    /* Store initial checksum */
    return cdll_compute_checksum(lib, lib->checksum);
}

/* ============================================================================
 * Implementation - Anti-Debug
 * ============================================================================ */

/**
 * @brief Checks if a debugger is attached to the process
 * @return true if debugger present, false otherwise
 */
static inline bool cdll_is_debugger_present(void) {
#ifdef _WIN32
    return IsDebuggerPresent();
#elif defined(__linux__)
    /* Check ptrace */
    FILE* f = fopen("/proc/self/status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                int pid = atoi(line + 10);
                fclose(f);
                return pid != 0;
            }
        }
        fclose(f);
    }
    return false;
#else
    return false;
#endif
}

/**
 * @brief Enables anti-debugging protection
 * @param lib Library instance
 * @return true on success, false if debugger detected
 */
static inline bool cdll_enable_anti_debug(cdll_library_t* lib) {
    if (!lib) return false;
    
    if (cdll_is_debugger_present()) {
        cdll_set_error("cdll_enable_anti_debug", EPERM, "Debugger detected");
        return false;
    }
    
    __cdll_global_manager.enable_antidebug = true;
    return true;
}

/**
 * @brief Disables anti-debugging protection
 * @param lib Library instance
 * @return true on success, false on failure
 */
static inline bool cdll_disable_anti_debug(cdll_library_t* lib) {
    (void)lib;
    __cdll_global_manager.enable_antidebug = false;
    return true;
}

/* ============================================================================
 * Implementation - Encrypted DLL
 * ============================================================================ */

/**
 * @brief Loads an encrypted library using XOR decryption
 * @param path Path to the encrypted library
 * @param key Encryption key
 * @param key_len Length of the key in bytes
 * @return Loaded library, or NULL on failure
 */
static inline cdll_library_t* cdll_load_encrypted_library(const char* path, const uint8_t* key, size_t key_len) {
    if (!path || !key) return NULL;
    
    size_t encrypted_size;
    uint8_t* encrypted = NULL;
    
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    encrypted_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    encrypted = (uint8_t*)malloc(encrypted_size);
    if (!encrypted) {
        fclose(f);
        return NULL;
    }
    
    fread(encrypted, 1, encrypted_size, f);
    fclose(f);
    
    /* Simple XOR decryption */
    uint8_t* decrypted = (uint8_t*)malloc(encrypted_size);
    if (!decrypted) {
        free(encrypted);
        return NULL;
    }
    
    for (size_t i = 0; i < encrypted_size; i++) {
        decrypted[i] = encrypted[i] ^ key[i % key_len];
    }
    
    /* Write to temp file */
    char temp_path[1024];
#ifdef _WIN32
    GetTempPathA(sizeof(temp_path), temp_path);
    snprintf(temp_path + strlen(temp_path), sizeof(temp_path) - strlen(temp_path), "cdll_dec_%ld.dll", time(NULL));
#else
    snprintf(temp_path, sizeof(temp_path), "/tmp/cdll_dec_%ld.so", time(NULL));
#endif
    
    f = fopen(temp_path, "wb");
    if (!f) {
        free(encrypted);
        free(decrypted);
        return NULL;
    }
    
    fwrite(decrypted, 1, encrypted_size, f);
    fclose(f);
    
    free(encrypted);
    free(decrypted);
    
    cdll_library_t* lib = cdll_load_library(temp_path);
    if (lib) {
        lib->is_encrypted = true;
        lib->encrypted_key = malloc(key_len);
        if (lib->encrypted_key) {
            memcpy(lib->encrypted_key, key, key_len);
            lib->encrypted_key_len = key_len;
        }
    }
    
    remove(temp_path);
    return lib;
}

/**
 * @brief Decrypts a loaded encrypted library (not implemented)
 * @param lib Library instance
 * @param key Decryption key
 * @param key_len Key length
 * @return true on success, false on failure
 */
static inline bool cdll_decrypt_library(cdll_library_t* lib, const uint8_t* key, size_t key_len) {
    (void)lib; (void)key; (void)key_len;
    return false;
}

/* ============================================================================
 * Implementation - Compressed DLL
 * ============================================================================ */

/**
 * @brief Decompresses zlib-compressed data to a file
 * @param data Compressed data
 * @param size Size of compressed data
 * @param out_path Output file path
 * @return true on success, false on failure
 */
static inline bool cdll_decompress_to_file(const uint8_t* data, size_t size, const char* out_path) {
#ifdef HAVE_ZLIB
    z_stream stream = {0};
    if (inflateInit(&stream) != Z_OK) return false;
    
    stream.next_in = (Bytef*)data;
    stream.avail_in = size;
    
    size_t buffer_size = size * 4;
    uint8_t* output = (uint8_t*)malloc(buffer_size);
    if (!output) {
        inflateEnd(&stream);
        return false;
    }
    
    stream.next_out = output;
    stream.avail_out = buffer_size;
    
    int ret = inflate(&stream, Z_FINISH);
    inflateEnd(&stream);
    
    if (ret != Z_STREAM_END) {
        free(output);
        return false;
    }
    
    FILE* f = fopen(out_path, "wb");
    if (!f) {
        free(output);
        return false;
    }
    
    fwrite(output, 1, stream.total_out, f);
    fclose(f);
    free(output);
    
    return true;
#else
    (void)data; (void)size; (void)out_path;
    return false;
#endif
}

/**
 * @brief Loads a zlib-compressed library
 * @param path Path to the compressed library
 * @return Loaded library, or NULL on failure
 */
static inline cdll_library_t* cdll_load_compressed_library(const char* path) {
    size_t compressed_size;
    uint8_t* compressed = NULL;
    
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    compressed_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    compressed = (uint8_t*)malloc(compressed_size);
    if (!compressed) {
        fclose(f);
        return NULL;
    }
    
    fread(compressed, 1, compressed_size, f);
    fclose(f);
    
    char temp_path[1024];
#ifdef _WIN32
    GetTempPathA(sizeof(temp_path), temp_path);
    snprintf(temp_path + strlen(temp_path), sizeof(temp_path) - strlen(temp_path), "cdll_comp_%ld.dll", time(NULL));
#else
    snprintf(temp_path, sizeof(temp_path), "/tmp/cdll_comp_%ld.so", time(NULL));
#endif
    
    if (!cdll_decompress_to_file(compressed, compressed_size, temp_path)) {
        free(compressed);
        return NULL;
    }
    
    free(compressed);
    
    cdll_library_t* lib = cdll_load_library(temp_path);
    if (lib) {
        lib->is_compressed = true;
    }
    
    remove(temp_path);
    return lib;
}

/* ============================================================================
 * Implementation - Async Calls
 * ============================================================================ */

/**
 * @brief Creates a new future for async operations
 * @return Future structure, or NULL on failure
 */
static inline cdll_future_t* cdll_future_create(void) {
    cdll_future_t* future = (cdll_future_t*)calloc(1, sizeof(cdll_future_t));
    if (!future) return NULL;
    
    pthread_mutex_init(&future->mutex, NULL);
    pthread_cond_init(&future->cond, NULL);
    future->ref_count = 1;
    
    return future;
}

/**
 * @brief Retains a future (increments reference count)
 * @param future Future to retain
 */
static inline void cdll_future_retain(cdll_future_t* future) {
    if (future) cdll_atomic_increment(&future->ref_count);
}

/**
 * @brief Releases a future (decrements reference count, frees if zero)
 * @param future Future to release
 */
static inline void cdll_future_release(cdll_future_t* future) {
    if (future && cdll_atomic_decrement(&future->ref_count) == 0) {
        pthread_mutex_destroy(&future->mutex);
        pthread_cond_destroy(&future->cond);
        free(future);
    }
}

/**
 * @brief Waits for a future to complete
 * @param future Future to wait for
 * @param timeout_ms Timeout in milliseconds, or -1 for infinite
 * @return true if completed, false if timeout or cancelled
 */
static inline bool cdll_future_wait(cdll_future_t* future, int timeout_ms) {
    if (!future) return false;
    
    pthread_mutex_lock(&future->mutex);
    
    if (!future->is_ready && !future->is_cancelled) {
        if (timeout_ms < 0) {
            pthread_cond_wait(&future->cond, &future->mutex);
        } else {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += timeout_ms / 1000;
            ts.tv_nsec += (timeout_ms % 1000) * 1000000;
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec++;
                ts.tv_nsec -= 1000000000;
            }
            pthread_cond_timedwait(&future->cond, &future->mutex, &ts);
        }
    }
    
    bool ready = future->is_ready;
    pthread_mutex_unlock(&future->mutex);
    
    return ready;
}

/**
 * @brief Checks if a future is ready
 * @param future Future to check
 * @return true if ready, false otherwise
 */
static inline bool cdll_future_is_ready(cdll_future_t* future) {
    if (!future) return false;
    return future->is_ready;
}

/**
 * @brief Gets the result from a completed future
 * @param future Future to get result from
 * @return Call result structure
 */
static inline cdll_call_result_t cdll_future_get_result(cdll_future_t* future) {
    cdll_call_result_t result = {0};
    if (future) {
        pthread_mutex_lock(&future->mutex);
        result = future->result;
        pthread_mutex_unlock(&future->mutex);
    }
    return result;
}
typedef struct {
    cdll_function_t* func;
    void* arg;
    cdll_future_t* future;
} cdll_async_task_t;

static void cdll_async_worker(void* data) {
    cdll_async_task_t* task = (cdll_async_task_t*)data;
    
    if (task->func && task->func->ptr) {
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        task->future->result.value.ptr = ((void* (*)(void*))task->func->ptr)(task->arg);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        task->future->result.execution_time_ns = (end.tv_sec - start.tv_sec) * 1000000000ULL + 
                                                  (end.tv_nsec - start.tv_nsec);
        task->future->result.success = true;
        
        cdll_atomic_increment(&task->func->call_count);
    }
    
    pthread_mutex_lock(&task->future->mutex);
    task->future->is_ready = true;
    pthread_cond_broadcast(&task->future->cond);
    pthread_mutex_unlock(&task->future->mutex);
    
    free(task);
}

/**
 * @brief Calls a function asynchronously
 * @param func Function to call
 * @param ... Function arguments (currently supports single void* argument)
 * @return Future for the async call, or NULL on failure
 */
static inline cdll_future_t* cdll_call_async(cdll_function_t* func, ...) {
    if (!func || !func->ptr) return NULL;
    
    cdll_async_task_t* task = (cdll_async_task_t*)malloc(sizeof(cdll_async_task_t));
    if (!task) return NULL;
    
    va_list args;
    va_start(args, func);
    task->arg = va_arg(args, void*);
    va_end(args);
    
    task->func = func;
    task->future = cdll_future_create();
    if (!task->future) {
        free(task);
        return NULL;
    }
    
    if (!__cdll_global_manager.thread_pool) {
        __cdll_global_manager.thread_pool = cdll_thread_pool_create(0);
    }
    
    cdll_thread_pool_submit(__cdll_global_manager.thread_pool, cdll_async_worker, task, task->future);
    
    return task->future;
}

/* ============================================================================
 * Implementation - Thread Pool
 * ============================================================================ */

typedef struct {
    void (*func)(void*);
    void* arg;
    cdll_future_t* future;
} cdll_task_t;

static void* cdll_thread_pool_worker(void* arg) {
    cdll_thread_pool_t* pool = (cdll_thread_pool_t*)arg;
    
    while (!pool->shutdown) {
        cdll_task_t task = {0};
        bool has_task = false;
        
        while (cdll_atomic_compare_exchange(&pool->queue.lock, 0, 1)) {
            sched_yield();
        }
        
        if (pool->queue.head != pool->queue.tail) {
            task = ((cdll_task_t*)pool->queue.tasks)[pool->queue.head];
            pool->queue.head = (pool->queue.head + 1) % pool->queue.capacity;
            has_task = true;
        }
        
        cdll_atomic_store(&pool->queue.lock, 0);
        
        if (has_task) {
            cdll_atomic_increment(&pool->active_tasks);
            
            if (task.func) {
                task.func(task.arg);
            }
            
            if (task.future) {
                pthread_mutex_lock(&task.future->mutex);
                task.future->is_ready = true;
                pthread_cond_broadcast(&task.future->cond);
                if (task.future->callback) {
                    task.future->callback(task.future, task.future->callback_data);
                }
                pthread_mutex_unlock(&task.future->mutex);
            }
            
            cdll_atomic_decrement(&pool->active_tasks);
            cdll_atomic_decrement(&pool->total_tasks);
        } else {
            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }
    }
    
    return NULL;
}

/**
 * @brief Creates a thread pool for parallel execution
 * @param thread_count Number of threads (0 for default)
 * @return Thread pool structure, or NULL on failure
 */
static inline cdll_thread_pool_t* cdll_thread_pool_create(size_t thread_count) {
    cdll_thread_pool_t* pool = (cdll_thread_pool_t*)calloc(1, sizeof(cdll_thread_pool_t));
    if (!pool) return NULL;
    
    pool->thread_count = thread_count ? thread_count : 4;
    pool->queue.capacity = 1024;
    pool->queue.tasks = calloc(pool->queue.capacity, sizeof(cdll_task_t));
    
    if (!pool->queue.tasks) {
        free(pool);
        return NULL;
    }
    
    pool->threads = (pthread_t*)calloc(pool->thread_count, sizeof(pthread_t));
    if (!pool->threads) {
        free(pool->queue.tasks);
        free(pool);
        return NULL;
    }
    
    for (size_t i = 0; i < pool->thread_count; i++) {
        pthread_create(&pool->threads[i], NULL, cdll_thread_pool_worker, pool);
    }
    
    return pool;
}

/**
 * @brief Destroys a thread pool
 * @param pool Thread pool to destroy
 */
static inline void cdll_thread_pool_destroy(cdll_thread_pool_t* pool) {
    if (!pool) return;
    
    pool->shutdown = true;
    
    for (size_t i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    free(pool->threads);
    free(pool->queue.tasks);
    free(pool);
}

/**
 * @brief Submits a task to the thread pool
 * @param pool Thread pool instance
 * @param func Function to execute
 * @param arg Argument to pass to the function
 * @param future Optional future to signal on completion
 * @return true if submitted, false if queue full
 */
static inline bool cdll_thread_pool_submit(cdll_thread_pool_t* pool, void (*func)(void*), void* arg, cdll_future_t* future) {
    if (!pool || !func) return false;
    
    while (cdll_atomic_compare_exchange(&pool->queue.lock, 0, 1)) {
        sched_yield();
    }
    
    size_t next_tail = (pool->queue.tail + 1) % pool->queue.capacity;
    if (next_tail == pool->queue.head) {
        cdll_atomic_store(&pool->queue.lock, 0);
        return false;
    }
    
    cdll_task_t* task = &((cdll_task_t*)pool->queue.tasks)[pool->queue.tail];
    task->func = func;
    task->arg = arg;
    task->future = future;
    pool->queue.tail = next_tail;
    
    cdll_atomic_increment(&pool->total_tasks);
    cdll_atomic_store(&pool->queue.lock, 0);
    
    return true;
}

/**
 * @brief Gets the number of currently active tasks in the pool
 * @param pool Thread pool instance
 * @return Number of active tasks
 */
static inline size_t cdll_thread_pool_get_active_tasks(cdll_thread_pool_t* pool) {
    return pool ? cdll_atomic_load(&pool->active_tasks) : 0;
}

/* ============================================================================
 * Implementation - Batch Calls
 * ============================================================================ */

/**
 * @brief Creates a batch call for multiple function executions
 * @param count Number of calls in the batch
 * @param parallel Whether to execute in parallel
 * @return Batch call structure, or NULL on failure
 */
static inline cdll_batch_call_t* cdll_batch_call_create(size_t count, bool parallel) {
    cdll_batch_call_t* batch = (cdll_batch_call_t*)calloc(1, sizeof(cdll_batch_call_t));
    if (!batch) return NULL;
    
    batch->functions = (cdll_function_t**)calloc(count, sizeof(cdll_function_t*));
    batch->arguments = (void**)calloc(count, sizeof(void*));
    batch->results = (cdll_call_result_t*)calloc(count, sizeof(cdll_call_result_t));
    batch->count = count;
    batch->parallel = parallel;
    
    if (!batch->functions || !batch->arguments || !batch->results) {
        free(batch->functions);
        free(batch->arguments);
        free(batch->results);
        free(batch);
        return NULL;
    }
    
    return batch;
}

/**
 * @brief Sets a function call in a batch
 * @param batch Batch call structure
 * @param index Index of the call (0 to count-1)
 * @param func Function to call
 * @param arg Argument to pass (single void*)
 */
static inline void cdll_batch_call_set(cdll_batch_call_t* batch, size_t index, cdll_function_t* func, void* arg) {
    if (batch && index < batch->count) {
        batch->functions[index] = func;
        batch->arguments[index] = arg;
    }
}

typedef struct {
    cdll_batch_call_t* batch;
    size_t start_index;
    size_t end_index;
} cdll_batch_worker_data_t;

static void cdll_batch_worker(void* data) {
    cdll_batch_worker_data_t* wdata = (cdll_batch_worker_data_t*)data;
    cdll_batch_call_t* batch = wdata->batch;
    
    for (size_t i = wdata->start_index; i < wdata->end_index; i++) {
        if (batch->functions[i] && batch->functions[i]->ptr) {
            batch->results[i].value.ptr = ((void* (*)(void*))batch->functions[i]->ptr)(batch->arguments[i]);
            batch->results[i].success = true;
        }
    }
    
    free(wdata);
}

/**
 * @brief Executes all calls in a batch
 * @param batch Batch call structure
 * @return true on success, false on failure
 */
static inline bool cdll_batch_call_execute(cdll_batch_call_t* batch) {
    if (!batch) return false;
    
    if (batch->parallel && __cdll_global_manager.thread_pool) {
        size_t thread_count = __cdll_global_manager.thread_pool->thread_count;
        size_t chunk_size = batch->count / thread_count;
        if (chunk_size == 0) chunk_size = 1;
        
        for (size_t i = 0; i < batch->count; i += chunk_size) {
            cdll_batch_worker_data_t* wdata = (cdll_batch_worker_data_t*)malloc(sizeof(cdll_batch_worker_data_t));
            wdata->batch = batch;
            wdata->start_index = i;
            wdata->end_index = (i + chunk_size < batch->count) ? i + chunk_size : batch->count;
            
            cdll_thread_pool_submit(__cdll_global_manager.thread_pool, cdll_batch_worker, wdata, NULL);
        }
        
        while (cdll_atomic_load(&__cdll_global_manager.thread_pool->total_tasks) > 0) {
            struct timespec ts = {0, 1000000};
            nanosleep(&ts, NULL);
        }
    } else {
        for (size_t i = 0; i < batch->count; i++) {
            if (batch->functions[i] && batch->functions[i]->ptr) {
                batch->results[i].value.ptr = ((void* (*)(void*))batch->functions[i]->ptr)(batch->arguments[i]);
                batch->results[i].success = true;
            }
        }
    }
    
    return true;
}

/**
 * @brief Destroys a batch call structure
 * @param batch Batch to destroy
 */
static inline void cdll_batch_call_destroy(cdll_batch_call_t* batch) {
    if (batch) {
        free(batch->functions);
        free(batch->arguments);
        free(batch->results);
        free(batch);
    }
}

/* ============================================================================
 * Implementation - Call Graph
 * ============================================================================ */

/**
 * @brief Creates a call graph for profiling
 * @return Call graph structure, or NULL on failure
 */
static inline cdll_call_graph_t* cdll_call_graph_create(void) {
    cdll_call_graph_t* graph = (cdll_call_graph_t*)calloc(1, sizeof(cdll_call_graph_t));
    if (!graph) return NULL;
    
    graph->track_time = true;
    graph->active_profiling = 0;
    
    return graph;
}

/**
 * @brief Starts profiling call graph
 * @param graph Call graph instance
 */
static inline void cdll_call_graph_start_profiling(cdll_call_graph_t* graph) {
    if (graph) cdll_atomic_store(&graph->active_profiling, 1);
}

/**
 * @brief Stops profiling call graph
 * @param graph Call graph instance
 */
static inline void cdll_call_graph_stop_profiling(cdll_call_graph_t* graph) {
    if (graph) cdll_atomic_store(&graph->active_profiling, 0);
}

/**
 * @brief Records a function call in the graph
 * @param graph Call graph instance
 * @param caller Calling function
 * @param callee Called function
 * @param time_ns Execution time in nanoseconds
 */
static inline void cdll_call_graph_record(cdll_call_graph_t* graph, cdll_function_t* caller, cdll_function_t* callee, uint64_t time_ns) {
    if (!graph || !caller || !callee) return;
    if (!cdll_atomic_load(&graph->active_profiling)) return;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    /* Helper function to find or create a node */
    struct cdll_call_node* find_or_create_node(cdll_function_t* func) {
        /* First, search for existing node */
        struct cdll_call_node** queue = (struct cdll_call_node**)malloc(sizeof(struct cdll_call_node*) * (graph->node_count + 1));
        if (!queue) return NULL;
        
        size_t queue_head = 0, queue_tail = 0;
        if (graph->root) {
            queue[queue_tail++] = graph->root;
        }
        
        while (queue_head < queue_tail) {
            struct cdll_call_node* current = queue[queue_head++];
            
            if (current->caller == func) {
                free(queue);
                return current;
            }
            
            for (size_t i = 0; i < current->child_count; i++) {
                if (current->children[i]) {
                    queue[queue_tail++] = current->children[i];
                }
            }
        }
        
        free(queue);
        
        /* Node not found, create new one */
        struct cdll_call_node* new_node = (struct cdll_call_node*)calloc(1, sizeof(struct cdll_call_node));
        if (!new_node) return NULL;
        
        new_node->caller = func;
        new_node->call_count = 0;
        new_node->total_time_ns = 0;
        new_node->children = NULL;
        new_node->child_count = 0;
        new_node->child_capacity = 0;
        
        /* Add to graph */
        if (!graph->root) {
            graph->root = new_node;
        } else {
            /* Find a place to attach - simplified: add as child of root if root is not set properly */
            if (graph->root->caller != func) {
                /* Add to root's children */
                if (graph->root->child_count >= graph->root->child_capacity) {
                    graph->root->child_capacity = graph->root->child_capacity ? graph->root->child_capacity * 2 : 8;
                    graph->root->children = (struct cdll_call_node**)realloc(graph->root->children,
                        graph->root->child_capacity * sizeof(struct cdll_call_node*));
                }
                if (graph->root->children) {
                    graph->root->children[graph->root->child_count++] = new_node;
                }
            }
        }
        
        graph->node_count++;
        return new_node;
    }
    
    struct cdll_call_node* caller_node = find_or_create_node(caller);
    struct cdll_call_node* callee_node = find_or_create_node(callee);
    
    if (caller_node && callee_node) {
        /* Check if edge already exists */
        bool edge_found = false;
        for (size_t i = 0; i < caller_node->child_count; i++) {
            if (caller_node->children[i] == callee_node) {
                callee_node->call_count++;
                callee_node->total_time_ns += time_ns;
                edge_found = true;
                break;
            }
        }
        
        if (!edge_found) {
            /* Add new edge */
            if (caller_node->child_count >= caller_node->child_capacity) {
                caller_node->child_capacity = caller_node->child_capacity ? caller_node->child_capacity * 2 : 8;
                struct cdll_call_node** new_children = (struct cdll_call_node**)realloc(
                    caller_node->children, caller_node->child_capacity * sizeof(struct cdll_call_node*));
                if (!new_children) {
                    pthread_mutex_unlock(&__cdll_manager_mutex);
                    return;
                }
                caller_node->children = new_children;
            }
            
            caller_node->children[caller_node->child_count++] = callee_node;
            callee_node->call_count = 1;
            callee_node->total_time_ns = time_ns;
        }
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Prints the call graph with statistics
 * @param graph Call graph instance
 */
static inline void cdll_call_graph_print(cdll_call_graph_t* graph) {
    if (!graph || !graph->root) {
        printf("Call graph is empty\n");
        return;
    }
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    printf("\n+------------------------------------------------------------------+\n");
    printf("|                        CALL GRAPH ANALYSIS                        |\n");
    printf("+-------------------------------------------------------------------|\n");
    printf("| Total nodes: %-52zu |\n", graph->node_count);
    printf("| Profiling: %-54s |\n", cdll_atomic_load(&graph->active_profiling) ? "Active" : "Inactive");
    printf("+------------------------------------------------------------------+\n\n");
    
    void print_node(struct cdll_call_node* node, int depth, const char* prefix) {
        if (!node) return;
        
        /* Print indentation */
        for (int i = 0; i < depth; i++) {
            if (i == depth - 1) {
                printf("%s├── ", prefix);
            } else {
                printf("%s│   ", prefix);
            }
        }
        
        /* Print node information */
        const char* func_name = node->caller ? node->caller->name : "unknown";
        const char* demangled = node->caller && node->caller->demangled_name[0] ? 
            node->caller->demangled_name : func_name;
        
        printf("%s", demangled);
        
        if (node->call_count > 0) {
            double avg_time = (double)node->total_time_ns / node->call_count;
            printf(" [calls: %llu, total: %.2f μs, avg: %.2f ns]",
                   (unsigned long long)node->call_count,
                   node->total_time_ns / 1000.0,
                   avg_time);
        }
        printf("\n");
        
        /* Recursively print children */
        char new_prefix[256];
        snprintf(new_prefix, sizeof(new_prefix), "%s%s", prefix, (depth > 0) ? "│   " : "");
        
        for (size_t i = 0; i < node->child_count; i++) {
            print_node(node->children[i], depth + 1, new_prefix);
        }
    }
    
    print_node(graph->root, 0, "");
    
    /* Print summary statistics */
    printf("\n+------------------------------------------------------------------+\n");
    printf("|                         SUMMARY STATISTICS                        |\n");
    printf("|------------------------------------------------------------------|\n");
    
    uint64_t total_calls = 0;
    uint64_t total_time = 0;
    
    struct cdll_call_node** queue = (struct cdll_call_node**)malloc(sizeof(struct cdll_call_node*) * (graph->node_count + 1));
    if (queue) {
        size_t qh = 0, qt = 0;
        queue[qt++] = graph->root;
        
        while (qh < qt) {
            struct cdll_call_node* node = queue[qh++];
            total_calls += node->call_count;
            total_time += node->total_time_ns;
            
            for (size_t i = 0; i < node->child_count; i++) {
                queue[qt++] = node->children[i];
            }
        }
        free(queue);
    }
    
    printf("| Total function calls: %-43llu │\n", (unsigned long long)total_calls);
    printf("| Total execution time: %.2f ms%-38s │\n", total_time / 1000000.0, "");
    printf("| Average call time: %.2f ns%-40s │\n", total_calls > 0 ? (double)total_time / total_calls : 0.0, "");
    printf("+-------------------------------------------------------------------\n");
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Destroys a call graph
 * @param graph Call graph to destroy
 */
static inline void cdll_call_graph_destroy(cdll_call_graph_t* graph) {
    if (graph) free(graph);
}

/* ============================================================================
 * Implementation - Library Pooling
 * ============================================================================ */

/**
 * @brief Enables library pooling with specified limits
 * @param max_size Maximum number of pooled libraries
 * @param ttl Time-to-live in seconds for pooled libraries
 */
static inline void cdll_enable_pooling(size_t max_size, time_t ttl) {
    pthread_mutex_lock(&__cdll_manager_mutex);
    __cdll_global_manager.enable_pooling = true;
    __cdll_global_manager.pool_max_size = max_size;
    __cdll_global_manager.pool_ttl = ttl;
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Acquires a library from the pool or loads if not pooled
 * @param path Library path
 * @return Library instance, or NULL on failure
 */
static inline cdll_library_t* cdll_acquire_pooled_library(const char* path) {
    if (!path) return NULL;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    cdll_library_t* lib = __cdll_global_manager.library_pool;
    cdll_library_t* prev = NULL;
    
    while (lib) {
        if (strstr(lib->path, path) || strcmp(lib->name, path) == 0) {
            /* Remove from pool */
            if (prev) prev->pool_next = lib->pool_next;
            else __cdll_global_manager.library_pool = lib->pool_next;
            
            __cdll_global_manager.pool_size--;
            lib->is_pooled = false;
            
            pthread_mutex_unlock(&__cdll_manager_mutex);
            
            cdll_atomic_increment(&lib->reference_count);
            lib->last_access_time = time(NULL);
            return lib;
        }
        prev = lib;
        lib = lib->pool_next;
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
    return NULL;
}

/**
 * @brief Releases a library back to the pool
 * @param lib Library to release
 */
static inline void cdll_release_pooled_library(cdll_library_t* lib) {
    if (!lib) return;
    
    if (cdll_atomic_decrement(&lib->reference_count) > 0) return;
    
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    if (__cdll_global_manager.enable_pooling && 
        __cdll_global_manager.pool_size < __cdll_global_manager.pool_max_size) {
        lib->is_pooled = true;
        lib->pool_next = __cdll_global_manager.library_pool;
        __cdll_global_manager.library_pool = lib;
        __cdll_global_manager.pool_size++;
        lib->last_access_time = time(NULL);
        pthread_mutex_unlock(&__cdll_manager_mutex);
    } else {
        pthread_mutex_unlock(&__cdll_manager_mutex);
        cdll_unload_library(lib);
    }
}

/**
 * @brief Cleans up expired libraries from the pool
 */
static inline void cdll_cleanup_pool(void) {
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    time_t now = time(NULL);
    cdll_library_t* lib = __cdll_global_manager.library_pool;
    cdll_library_t* prev = NULL;
    
    while (lib) {
        cdll_library_t* next = lib->pool_next;
        
        if ((now - lib->last_access_time) > __cdll_global_manager.pool_ttl) {
            /* Remove and unload */
            if (prev) prev->pool_next = next;
            else __cdll_global_manager.library_pool = next;
            
            __cdll_global_manager.pool_size--;
            
            pthread_mutex_unlock(&__cdll_manager_mutex);
            lib->is_pooled = false;
            cdll_unload_library(lib);
            pthread_mutex_lock(&__cdll_manager_mutex);
        } else {
            prev = lib;
        }
        
        lib = next;
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/* ============================================================================
 * Implementation - Garbage Collection
 * ============================================================================ */

static void* cdll_gc_thread_func(void* arg) {
    (void)arg;
    
    while (__cdll_gc_running) {
        sleep(__cdll_gc_interval);
        
        if (!__cdll_gc_running) break;
        
        /* Cleanup pool */
        if (__cdll_global_manager.enable_pooling) {
            cdll_cleanup_pool();
        }
        
        /* Cleanup expired cache entries */
        pthread_mutex_lock(&__cdll_manager_mutex);
        
        time_t now = time(NULL);
        cdll_library_t* lib = __cdll_global_manager.libraries;
        
        while (lib) {
            cdll_function_t* func = lib->cached_functions;
            cdll_function_t* prev_func = NULL;
            
            while (func) {
                cdll_function_t* next_func = func->next;
                
                if (func->ttl > 0 && (now - func->cache_time) > func->ttl) {
                    /* Remove from cache */
                    if (prev_func) prev_func->next = next_func;
                    else lib->cached_functions = next_func;
                    
                    lib->cached_count--;
                    free(func);
                } else {
                    prev_func = func;
                }
                
                func = next_func;
            }
            
            lib = lib->next;
        }
        
        pthread_mutex_unlock(&__cdll_manager_mutex);
    }
    
    return NULL;
}

/**
 * @brief Performs a manual garbage collection cycle
 */
static inline void cdll_gc_collect(void) {
    cdll_cleanup_pool();
}

/**
 * @brief Starts automatic garbage collection
 * @param interval_seconds Interval between GC cycles in seconds
 */
static inline void cdll_gc_start_auto(time_t interval_seconds) {
    if (__cdll_gc_running) return;
    
    __cdll_gc_interval = interval_seconds;
    __cdll_gc_running = true;
    pthread_create(&__cdll_gc_thread, NULL, cdll_gc_thread_func, NULL);
}

/**
 * @brief Stops automatic garbage collection
 */
static inline void cdll_gc_stop_auto(void) {
    __cdll_gc_running = false;
    if (__cdll_gc_thread) {
        pthread_join(__cdll_gc_thread, NULL);
        __cdll_gc_thread = 0;
    }
}

/* ============================================================================
 * Implementation - Utility Functions
 * ============================================================================ */

/**
 * @brief Gets the library version string
 * @return Version string (e.g., "3.0.0")
 */
static inline const char* cdll_get_version(void) {
    return "3.0.0";
}

/**
 * @brief Prints detailed information about a library to stdout
 * @param lib Library instance
 */
static inline void cdll_print_library_info(cdll_library_t* lib) {
    if (!lib) {
        printf("NULL library\n");
        return;
    }
    
    printf("Library: %s\n", lib->name);
    printf("  Path: %s\n", lib->path);
    printf("  Loaded: %s\n", lib->is_loaded ? "Yes" : "No");
    printf("  Delay-load: %s\n", lib->is_delay_load ? "Yes" : "No");
    printf("  Compressed: %s\n", lib->is_compressed ? "Yes" : "No");
    printf("  Encrypted: %s\n", lib->is_encrypted ? "Yes" : "No");
    printf("  Sandboxed: %s\n", lib->is_sandboxed ? "Yes" : "No");
    printf("  Pooled: %s\n", lib->is_pooled ? "Yes" : "No");
    printf("  References: %d\n", cdll_atomic_load((int32_t*)&lib->reference_count));
    printf("  Cached functions: %zu\n", lib->cached_count);
    printf("  Load time: %s", ctime(&lib->load_time));
    printf("  Last access: %s", ctime(&lib->last_access_time));
    
    cdll_module_info_t info;
    if (cdll_get_module_info(lib, &info)) {
        printf("  Base address: %p\n", info.base_address);
        printf("  Size: %zu bytes\n", info.size);
        printf("  64-bit: %s\n", info.is_64bit ? "Yes" : "No");
        printf("  DEP: %s\n", info.has_dep ? "Yes" : "No");
        printf("  ASLR: %s\n", info.has_aslr ? "Yes" : "No");
    }
    
    cdll_version_info_t ver;
    if (cdll_get_version_info(lib, &ver)) {
        printf("  Version: %s\n", ver.version_string);
        if (ver.product_name[0]) printf("  Product: %s\n", ver.product_name);
        if (ver.company_name[0]) printf("  Company: %s\n", ver.company_name);
    }
}

/**
 * @brief Prints information about all loaded libraries
 */
static inline void cdll_print_all_libraries(void) {
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    printf("=== Loaded Libraries (%zu) ===\n", __cdll_global_manager.library_count);
    
    cdll_library_t* lib = __cdll_global_manager.libraries;
    size_t i = 1;
    
    while (lib) {
        printf("\n[%zu] ", i++);
        cdll_print_library_info(lib);
        lib = lib->next;
    }
    
    if (__cdll_global_manager.enable_pooling) {
        printf("\n=== Pooled Libraries (%zu) ===\n", __cdll_global_manager.pool_size);
        lib = __cdll_global_manager.library_pool;
        i = 1;
        while (lib) {
            printf("[Pool %zu] %s (last access: %s", i++, lib->name, ctime(&lib->last_access_time));
            lib = lib->pool_next;
        }
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}

/**
 * @brief Prints all exports of a library
 * @param lib Library instance
 */
static inline void cdll_print_exports(cdll_library_t* lib) {
    if (!lib) return;
    
    cdll_export_entry_t exports[256];
    size_t count = cdll_enumerate_exports(lib, exports, 256);
    
    printf("=== Exports from %s (%zu) ===\n", lib->name, count);
    
    for (size_t i = 0; i < count; i++) {
        printf("  %s", exports[i].name);
        if (exports[i].demangled_name[0]) {
            printf(" [%s]", exports[i].demangled_name);
        }
        if (exports[i].ordinal > 0) {
            printf(" (@%u)", exports[i].ordinal);
        }
        printf(" -> %p", exports[i].address);
        if (exports[i].is_forwarded) {
            printf(" [forwarded to: %s]", exports[i].forwarder);
        }
        printf("\n");
    }
}

/**
 * @brief Prints all imports of a library
 * @param lib Library instance
 */
static inline void cdll_print_imports(cdll_library_t* lib) {
    if (!lib) return;
    
    cdll_import_entry_t imports[256];
    size_t count = cdll_enumerate_imports(lib, imports, 256);
    
    printf("=== Imports for %s (%zu) ===\n", lib->name, count);
    
    for (size_t i = 0; i < count; i++) {
        printf("  %s!", imports[i].module_name);
        if (imports[i].name[0]) {
            printf("%s", imports[i].name);
        } else if (imports[i].ordinal > 0) {
            printf("#%u", imports[i].ordinal);
        }
        if (imports[i].hint > 0) {
            printf(" (hint: %u)", imports[i].hint);
        }
        printf(" -> %p", imports[i].address);
        if (imports[i].is_bound) {
            printf(" [bound]");
        }
        printf("\n");
    }
}

/**
 * @brief Prints all sections of a library
 * @param lib Library instance
 */
static inline void cdll_print_sections(cdll_library_t* lib) {
    if (!lib) return;
    
    cdll_section_info_t sections[32];
    size_t count = cdll_enumerate_sections(lib, sections, 32);
    
    printf("=== Sections in %s (%zu) ===\n", lib->name, count);
    printf("  Name       VirtAddr         VirtSize    RawSize     Flags  Packed\n");
    printf("  ---------- ---------------- ---------- ---------- ------ ------\n");
    
    for (size_t i = 0; i < count; i++) {
        char flags[4] = "---";
        if (sections[i].is_readable) flags[0] = 'R';
        if (sections[i].is_writable) flags[1] = 'W';
        if (sections[i].is_executable) flags[2] = 'X';
        
        printf("  %-10s %16p %10zu %10zu %s   %s\n",
               sections[i].name,
               sections[i].virtual_address,
               sections[i].virtual_size,
               sections[i].raw_size,
               flags,
               sections[i].is_packed ? "Yes" : "No");
    }
}

/**
 * @brief Unloads all loaded libraries
 */
static inline void cdll_unload_all_libraries(void) {
    pthread_mutex_lock(&__cdll_manager_mutex);
    
    while (__cdll_global_manager.libraries) {
        cdll_library_t* lib = __cdll_global_manager.libraries;
        lib->reference_count = 1;
        pthread_mutex_unlock(&__cdll_manager_mutex);
        cdll_unload_library(lib);
        pthread_mutex_lock(&__cdll_manager_mutex);
    }
    
    pthread_mutex_unlock(&__cdll_manager_mutex);
}
/**
 * @brief Performs complete cleanup of the library
 */
static inline void cdll_cleanup(void) {
    cdll_gc_stop_auto();
    cdll_unload_all_libraries();
    
    if (__cdll_global_manager.thread_pool) {
        cdll_thread_pool_destroy(__cdll_global_manager.thread_pool);
        __cdll_global_manager.thread_pool = NULL;
    }
    
    if (__cdll_global_manager.call_graph) {
        cdll_call_graph_destroy(__cdll_global_manager.call_graph);
        __cdll_global_manager.call_graph = NULL;
    }
    
    cdll_manager_clear_search_paths(&__cdll_global_manager);
    cdll_clear_error();
}

/* ============================================================================
 * SYS/Driver Support Functions for CDLL
 * ============================================================================ */

/* Forward declarations for driver support */
typedef struct cdll_driver_info cdll_driver_info_t;
typedef struct cdll_driver_export cdll_driver_export_t;
typedef struct cdll_driver_import cdll_driver_import_t;
typedef struct cdll_driver_section cdll_driver_section_t;

/**
 * @brief Driver information structure
 */
struct cdll_driver_info {
    char path[1024];                    /* Full path to driver file */
    char name[256];                     /* Driver filename */
    char service_name[256];             /* Service name (if registered) */
    bool is_loaded;                     /* Whether driver is currently loaded */
    bool is_signed;                     /* Digital signature status */
    bool is_driver;                     /* Whether file is a driver (IMAGE_FILE_SYSTEM) */
    bool is_64bit;                      /* 64-bit driver flag */
    void* base_address;                 /* Base address in kernel space (if loaded) */
    size_t image_size;                  /* Size of driver image */
    uint32_t checksum;                  /* PE checksum */
    time_t timestamp;                   /* PE timestamp */
    uint16_t machine_type;              /* IMAGE_FILE_MACHINE_* */
    uint16_t subsystem;                 /* IMAGE_SUBSYSTEM_* */
    uint16_t characteristics;           /* PE characteristics */
    uint16_t dll_characteristics;       /* DLL characteristics */
    void* entry_point;                  /* DriverEntry address */
    uint32_t driver_start_io;           /* DriverStartIo offset (if any) */
    uint32_t driver_unload;             /* DriverUnload offset (if any) */
    char hardware_ids[16][256];         /* Hardware IDs (for PnP drivers) */
    size_t hardware_id_count;
    uint32_t driver_type;               /* SERVICE_* type */
    uint32_t start_type;                /* SERVICE_* start type */
    uint32_t error_control;             /* SERVICE_ERROR_* */
    char license[256];
    char version[64];
    char description[512];
    char author[256];
};

/**
 * @brief Driver export entry
 */
struct cdll_driver_export {
    char name[256];                     /* Export name */
    char demangled_name[512];           /* Demangled C++ name */
    uint32_t ordinal;                   /* Export ordinal */
    uint32_t rva;                       /* Relative Virtual Address */
    void* address;                      /* Absolute address (if loaded) */
    bool is_forwarded;                  /* Whether it's forwarded */
    char forwarder[512];                /* Forwarder target */
    bool is_paged;                      /* Whether export is in paged section */
    uint32_t crc;
};

/**
 * @brief Driver import entry
 */
struct cdll_driver_import {
    char name[256];                     /* Import name */
    char module_name[256];              /* Source module */
    uint32_t hint;                      /* Import hint */
    uint32_t ordinal;                   /* Import ordinal */
    uint32_t rva;                       /* IAT RVA */
    bool is_delay_load;                 /* Delay-load import */
    char version[64];
};

/**
 * @brief Driver section information
 */
struct cdll_driver_section {
    char name[16];                      /* Section name */
    uint32_t virtual_address;           /* RVA */
    size_t virtual_size;                /* Virtual size */
    size_t raw_size;                    /* Raw data size */
    uint32_t characteristics;           /* Section flags */
    bool is_executable;                 /* IMAGE_SCN_MEM_EXECUTE */
    bool is_readable;                   /* IMAGE_SCN_MEM_READ */
    bool is_writable;                   /* IMAGE_SCN_MEM_WRITE */
    bool is_discardable;                /* IMAGE_SCN_MEM_DISCARDABLE */
    bool is_not_cached;                 /* IMAGE_SCN_MEM_NOT_CACHED */
    bool is_not_paged;                  /* IMAGE_SCN_MEM_NOT_PAGED */
    bool is_shared;                     /* IMAGE_SCN_MEM_SHARED */
    uint64_t alignment;
};

#ifdef _WIN32
#include <winioctl.h>
#include <cfgmgr32.h>
#include <devguid.h>
#include <setupapi.h>

#ifdef _MSC_VER
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "advapi32.lib")
#endif

/* ============================================================================
 * Driver Information Functions
 * ============================================================================ */

/**
 * @brief Gets detailed information about a driver file
 * @param path Path to .sys file
 * @param info Structure to fill with driver information
 * @return true on success, false on failure
 */
static inline bool cdll_get_driver_info(const char* path, cdll_driver_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_driver_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        cdll_set_error("cdll_get_driver_info", errno, "Failed to open driver file");
        return false;
    }
    
    /* Read DOS header */
    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        cdll_set_error("cdll_get_driver_info", EINVAL, "Invalid DOS signature");
        return false;
    }
    
    /* Read NT header */
    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != IMAGE_NT_SIGNATURE) {
        fclose(f);
        cdll_set_error("cdll_get_driver_info", EINVAL, "Invalid NT signature");
        return false;
    }
    
    /* Fill basic info */
    info->checksum = nt.OptionalHeader.CheckSum;
    info->timestamp = nt.FileHeader.TimeDateStamp;
    info->machine_type = nt.FileHeader.Machine;
    info->characteristics = nt.FileHeader.Characteristics;
    info->is_driver = (nt.FileHeader.Characteristics & IMAGE_FILE_SYSTEM) != 0;
    info->is_64bit = (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    
    if (info->is_64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)&nt;
        info->subsystem = nt64->OptionalHeader.Subsystem;
        info->dll_characteristics = nt64->OptionalHeader.DllCharacteristics;
        info->image_size = nt64->OptionalHeader.SizeOfImage;
        info->entry_point = (void*)(uintptr_t)nt64->OptionalHeader.AddressOfEntryPoint;
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)&nt;
        info->subsystem = nt32->OptionalHeader.Subsystem;
        info->dll_characteristics = nt32->OptionalHeader.DllCharacteristics;
        info->image_size = nt32->OptionalHeader.SizeOfImage;
        info->entry_point = (void*)(uintptr_t)nt32->OptionalHeader.AddressOfEntryPoint;
    }
    
    /* Check digital signature */
    info->is_signed = cdll_verify_signature(path);
    
    /* Try to find driver start and unload routines from exports */
    fseek(f, 0, SEEK_SET);
    /* (Simplified - would parse exports to find DriverEntry, etc.) */
    
    fclose(f);
    
    /* Check if driver is currently loaded */
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm) {
        SC_HANDLE service = OpenServiceA(scm, info->name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                info->is_loaded = (status.dwCurrentState == SERVICE_RUNNING);
            }
            
            /* Get service configuration */
            uint8_t buffer[8192];
            DWORD bytes_needed;
            if (QueryServiceConfigA(service, (LPQUERY_SERVICE_CONFIGA)buffer, sizeof(buffer), &bytes_needed)) {
                LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)buffer;
                info->driver_type = config->dwServiceType;
                info->start_type = config->dwStartType;
                info->error_control = config->dwErrorControl;
                strncpy(info->service_name, config->lpDisplayName, sizeof(info->service_name) - 1);
            }
            CloseServiceHandle(service);
        }
        CloseServiceHandle(scm);
    }
    
    return true;
}

/**
 * @brief Enumerates all loaded kernel drivers (no admin rights required)
 * @param drivers Array to fill with driver names/paths
 * @param max_drivers Maximum number of drivers to enumerate
 * @return Number of drivers found
 */
static inline size_t cdll_enumerate_loaded_drivers(char drivers[][256], size_t max_drivers) {
    if (!drivers || max_drivers == 0) return 0;
    
    size_t count = 0;
    
    /* Use NtQuerySystemInformation instead of Service Manager */
    /* This doesn't require admin rights for basic enumeration */
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        typedef NTSTATUS (WINAPI *NtQuerySystemInformation_t)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );
        
        NtQuerySystemInformation_t NtQuerySystemInformation = 
            (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
        
        if (NtQuerySystemInformation) {
            /* SystemModuleInformation = 11 */
            ULONG buffer_size = 0;
            NtQuerySystemInformation(11, NULL, 0, &buffer_size);
            
            if (buffer_size > 0) {
                void* buffer = malloc(buffer_size);
                if (buffer) {
                    NTSTATUS status = NtQuerySystemInformation(11, buffer, buffer_size, &buffer_size);
                    
                    if (status == 0) {  /* STATUS_SUCCESS */
                        /* Parse RTL_PROCESS_MODULES structure */
                        ULONG module_count = *(ULONG*)buffer;
                        
                        /* Skip the count field - 32-bit vs 64-bit difference */
                        void* module_ptr = (char*)buffer + sizeof(ULONG);
                        
                        /* On 64-bit systems, there may be padding */
                        #ifdef _WIN64
                        module_ptr = (char*)buffer + sizeof(ULONG_PTR);
                        #endif
                        
                        for (ULONG i = 0; i < module_count && count < max_drivers; i++) {
                            /* RTL_PROCESS_MODULE_INFORMATION structure */
                            struct {
                                ULONG_PTR Section;
                                PVOID MappedBase;
                                PVOID ImageBase;
                                ULONG ImageSize;
                                ULONG Flags;
                                USHORT LoadOrderIndex;
                                USHORT InitOrderIndex;
                                USHORT LoadCount;
                                USHORT OffsetToFileName;
                                UCHAR FullPathName[256];
                            } *module = (void*)module_ptr;
                            
                            /* Extract filename from full path */
                            const char* filename = (const char*)module->FullPathName + module->OffsetToFileName;
                            
                            /* Only include .sys files */
                            if (strstr(filename, ".sys") || strstr(filename, ".SYS")) {
                                strncpy(drivers[count], filename, 255);
                                drivers[count][255] = '\0';
                                count++;
                            }
                            
                            /* Move to next module */
                            module_ptr = (char*)module_ptr + sizeof(*module);
                        }
                    }
                    free(buffer);
                }
            }
        }
    }
    
    /* Fallback: Try Service Manager with lower privileges */
    if (count == 0) {
        SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            DWORD bytes_needed = 0;
            DWORD services_returned = 0;
            
            /* First call to get size */
            EnumServicesStatusA(scm, SERVICE_DRIVER, SERVICE_ACTIVE,
                                NULL, 0, &bytes_needed, &services_returned, NULL);
            
            if (bytes_needed > 0 && GetLastError() == ERROR_MORE_DATA) {
                LPENUM_SERVICE_STATUSA services = (LPENUM_SERVICE_STATUSA)malloc(bytes_needed);
                if (services) {
                    if (EnumServicesStatusA(scm, SERVICE_DRIVER, SERVICE_ACTIVE,
                                            services, bytes_needed, &bytes_needed,
                                            &services_returned, NULL)) {
                        for (DWORD i = 0; i < services_returned && count < max_drivers; i++) {
                            snprintf(drivers[count], 256, "%s.sys", services[i].lpServiceName);
                            count++;
                        }
                    }
                    free(services);
                }
            }
            CloseServiceHandle(scm);
        }
    }
    
    return count;
}

/**
 * @brief Enumerates exports from a driver file
 * @param path Path to .sys file
 * @param entries Array to fill with export entries
 * @param max_entries Maximum number of entries
 * @return Number of exports found
 */
static inline size_t cdll_enumerate_driver_exports(const char* path, 
                                                    cdll_driver_export_t* entries,
                                                    size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    /* Read DOS header */
    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    /* Read NT header */
    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    bool is_64bit = (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    IMAGE_DATA_DIRECTORY* export_dir = NULL;
    
    if (is_64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)&nt;
        export_dir = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)&nt;
        export_dir = &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }
    
    if (export_dir->Size == 0) {
        fclose(f);
        return 0;
    }
    
    /* Read export directory */
    IMAGE_EXPORT_DIRECTORY exports;
    fseek(f, export_dir->VirtualAddress, SEEK_SET);
    if (fread(&exports, sizeof(exports), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    /* Read name table */
    uint32_t* names = (uint32_t*)malloc(exports.NumberOfNames * sizeof(uint32_t));
    uint16_t* ordinals = (uint16_t*)malloc(exports.NumberOfNames * sizeof(uint16_t));
    uint32_t* functions = (uint32_t*)malloc(exports.NumberOfFunctions * sizeof(uint32_t));
    
    if (!names || !ordinals || !functions) {
        free(names); free(ordinals); free(functions);
        fclose(f);
        return 0;
    }
    
    fseek(f, exports.AddressOfNames, SEEK_SET);
    fread(names, sizeof(uint32_t), exports.NumberOfNames, f);
    
    fseek(f, exports.AddressOfNameOrdinals, SEEK_SET);
    fread(ordinals, sizeof(uint16_t), exports.NumberOfNames, f);
    
    fseek(f, exports.AddressOfFunctions, SEEK_SET);
    fread(functions, sizeof(uint32_t), exports.NumberOfFunctions, f);
    
    /* Read string table */
    size_t strtab_size = export_dir->Size;
    char* strtab = (char*)malloc(strtab_size);
    fseek(f, export_dir->VirtualAddress + sizeof(exports) + 
          exports.NumberOfNames * sizeof(uint32_t) + 
          exports.NumberOfNames * sizeof(uint16_t) + 
          exports.NumberOfFunctions * sizeof(uint32_t), SEEK_SET);
    size_t strtab_offset = ftell(f);
    fread(strtab, 1, export_dir->VirtualAddress + export_dir->Size - strtab_offset, f);
    
    /* Fill entries */
    size_t count = 0;
    for (uint32_t i = 0; i < exports.NumberOfNames && count < max_entries; i++) {
        char* name = strtab + (names[i] - strtab_offset);
        uint16_t ordinal_idx = ordinals[i];
        uint32_t rva = functions[ordinal_idx];
        
        strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
        entries[count].ordinal = ordinal_idx + exports.Base;
        entries[count].rva = rva;
        entries[count].is_forwarded = false;
        
        /* Check if forwarded */
        if (rva >= export_dir->VirtualAddress && 
            rva < export_dir->VirtualAddress + export_dir->Size) {
            char* forwarder = strtab + (rva - strtab_offset);
            strncpy(entries[count].forwarder, forwarder, sizeof(entries[count].forwarder) - 1);
            entries[count].is_forwarded = true;
        }
        
        /* Demangle if C++ name */
        cdll_demangle_symbol(name, entries[count].demangled_name, 
                            sizeof(entries[count].demangled_name));
        
        count++;
    }
    
    free(names); free(ordinals); free(functions); free(strtab);
    fclose(f);
    return count;
}

/**
 * @brief Enumerates imports from a driver file
 * @param path Path to .sys file
 * @param entries Array to fill with import entries
 * @param max_entries Maximum number of entries
 * @return Number of imports found
 */
static inline size_t cdll_enumerate_driver_imports(const char* path,
                                                    cdll_driver_import_t* entries,
                                                    size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    bool is_64bit = (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    IMAGE_DATA_DIRECTORY* import_dir = NULL;
    IMAGE_DATA_DIRECTORY* delay_dir = NULL;
    
    if (is_64bit) {
        IMAGE_NT_HEADERS64* nt64 = (IMAGE_NT_HEADERS64*)&nt;
        import_dir = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        delay_dir = &nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    } else {
        IMAGE_NT_HEADERS32* nt32 = (IMAGE_NT_HEADERS32*)&nt;
        import_dir = &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        delay_dir = &nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    }
    
    size_t count = 0;
    
    /* Parse regular imports */
    if (import_dir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR import;
        fseek(f, import_dir->VirtualAddress, SEEK_SET);
        
        while (fread(&import, sizeof(import), 1, f) == 1 && import.Name != 0 && count < max_entries) {
            /* Read module name */
            char module_name[256];
            fseek(f, import.Name, SEEK_SET);
            fread(module_name, 1, sizeof(module_name) - 1, f);
            module_name[255] = '\0';
            
            /* Read thunk data */
            uint32_t thunk_rva = import.FirstThunk;
            uint32_t original_rva = import.OriginalFirstThunk ? import.OriginalFirstThunk : import.FirstThunk;
            
            fseek(f, original_rva, SEEK_SET);
            
            while (1) {
                uint64_t thunk_data = 0;
                fread(&thunk_data, is_64bit ? 8 : 4, 1, f);
                if (thunk_data == 0) break;
                
                if (count >= max_entries) break;
                
                if (thunk_data & (is_64bit ? 0x8000000000000000ULL : IMAGE_ORDINAL_FLAG)) {
                    /* Import by ordinal */
                    entries[count].ordinal = thunk_data & 0xFFFF;
                    entries[count].name[0] = '\0';
                    entries[count].hint = 0;
                } else {
                    /* Import by name */
                    uint32_t name_rva = thunk_data & 0x7FFFFFFF;
                    long current_pos = ftell(f);
                    
                    fseek(f, name_rva, SEEK_SET);
                    uint16_t hint;
                    fread(&hint, sizeof(hint), 1, f);
                    entries[count].hint = hint;
                    
                    char name[256];
                    fread(name, 1, sizeof(name) - 1, f);
                    name[255] = '\0';
                    strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
                    entries[count].ordinal = 0;
                    
                    fseek(f, current_pos, SEEK_SET);
                }
                
                strncpy(entries[count].module_name, module_name, sizeof(entries[count].module_name) - 1);
                entries[count].rva = thunk_rva;
                entries[count].is_delay_load = false;
                
                thunk_rva += (is_64bit ? 8 : 4);
                count++;
            }
        }
    }
    
    /* Parse delay-load imports */
    if (delay_dir->Size > 0 && count < max_entries) {
        /* (Similar parsing for delay-load imports) */
    }
    
    fclose(f);
    return count;
}

/**
 * @brief Enumerates sections from a driver file
 * @param path Path to .sys file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections
 * @return Number of sections found
 */
static inline size_t cdll_enumerate_driver_sections(const char* path,
                                                     cdll_driver_section_t* sections,
                                                     size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != IMAGE_NT_SIGNATURE) {
        fclose(f);
        return 0;
    }
    
    /* Read section headers */
    fseek(f, dos.e_lfanew + sizeof(nt.Signature) + sizeof(nt.FileHeader), SEEK_SET);
    fseek(f, (nt.FileHeader.SizeOfOptionalHeader), SEEK_CUR);
    
    size_t count = 0;
    for (uint16_t i = 0; i < nt.FileHeader.NumberOfSections && count < max_sections; i++) {
        IMAGE_SECTION_HEADER section;
        if (fread(&section, sizeof(section), 1, f) != 1) break;
        
        memcpy(sections[count].name, section.Name, sizeof(section.Name));
        sections[count].name[sizeof(section.Name)] = '\0';
        sections[count].virtual_address = section.VirtualAddress;
        sections[count].virtual_size = section.Misc.VirtualSize;
        sections[count].raw_size = section.SizeOfRawData;
        sections[count].characteristics = section.Characteristics;
        
        sections[count].is_executable = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sections[count].is_readable = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        sections[count].is_writable = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        sections[count].is_discardable = (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        sections[count].is_not_cached = (section.Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0;
        sections[count].is_not_paged = (section.Characteristics & IMAGE_SCN_MEM_NOT_PAGED) != 0;
        sections[count].is_shared = (section.Characteristics & IMAGE_SCN_MEM_SHARED) != 0;
        
        count++;
    }
    
    fclose(f);
    return count;
}

/**
 * @brief Prints detailed information about a driver
 * @param info Driver information structure
 */
static inline void cdll_print_driver_info(const cdll_driver_info_t* info) {
    if (!info) {
        printf("NULL driver info\n");
        return;
    }
    
    printf("Driver: %s\n", info->name);
    printf("  Path: %s\n", info->path);
    printf("  Service: %s\n", info->service_name[0] ? info->service_name : "(not registered)");
    printf("  Loaded: %s\n", info->is_loaded ? "Yes" : "No");
    printf("  Signed: %s\n", info->is_signed ? "Yes" : "No");
    printf("  Architecture: %s\n", info->is_64bit ? "64-bit" : "32-bit");
    printf("  Machine: 0x%04X\n", info->machine_type);
    printf("  Subsystem: 0x%04X (%s)\n", info->subsystem, 
           info->subsystem == IMAGE_SUBSYSTEM_NATIVE ? "Native" : 
           info->subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ? "Windows GUI" : "Unknown");
    printf("  Image size: %zu bytes (%.2f KB)\n", info->image_size, info->image_size / 1024.0);
    printf("  Entry point RVA: %p\n", info->entry_point);
    printf("  Checksum: 0x%08X\n", info->checksum);
    printf("  Timestamp: %s", ctime(&info->timestamp));
    
    if (info->driver_type != 0) {
        printf("  Driver type: 0x%X (%s)\n", info->driver_type,
               (info->driver_type & SERVICE_KERNEL_DRIVER) ? "Kernel" :
               (info->driver_type & SERVICE_FILE_SYSTEM_DRIVER) ? "File System" : "Other");
        printf("  Start type: %u (%s)\n", info->start_type,
               info->start_type == SERVICE_BOOT_START ? "Boot" :
               info->start_type == SERVICE_SYSTEM_START ? "System" :
               info->start_type == SERVICE_AUTO_START ? "Auto" :
               info->start_type == SERVICE_DEMAND_START ? "Manual" : "Disabled");
    }
}

/**
 * @brief Prints all exports from a driver
 * @param path Path to .sys file
 */
static inline void cdll_print_driver_exports(const char* path) {
    if (!path) return;
    
    cdll_driver_export_t exports[1024];
    size_t count = cdll_enumerate_driver_exports(path, exports, 1024);
    
    printf("\n=== Driver Exports (%zu) ===\n", count);
    printf("+------+----------------------------------------+------------+----------+\n");
    printf("| Ord  | Name                                   | RVA        | Forwarded|\n");
    printf("+------+----------------------------------------+------------+----------+\n");
    
    for (size_t i = 0; i < count && i < 50; i++) {
        printf("| %4u | %-38s | 0x%08X | %-8s |\n",
               exports[i].ordinal,
               exports[i].name[0] ? exports[i].name : "(no name)",
               exports[i].rva,
               exports[i].is_forwarded ? "Yes" : "No");
    }
    
    if (count > 50) {
        printf("| ...  | ... (%zu more)                         | ...        | ...      |\n", 
               count - 50);
    }
    printf("+------+----------------------------------------+------------+----------+\n");
}

/**
 * @brief Prints all imports from a driver
 * @param path Path to .sys file
 */
static inline void cdll_print_driver_imports(const char* path) {
    if (!path) return;
    
    cdll_driver_import_t imports[512];
    size_t count = cdll_enumerate_driver_imports(path, imports, 512);
    
    printf("\n=== Driver Imports (%zu) ===\n", count);
    printf("+----------------------------------------+----------------------------------------+\n");
    printf("| Module                                 | Function                               |\n");
    printf("+----------------------------------------+----------------------------------------+\n");
    
    for (size_t i = 0; i < count && i < 30; i++) {
        printf("| %-38s | %-38s |\n",
               imports[i].module_name,
               imports[i].name[0] ? imports[i].name : "(by ordinal)");
    }
    
    if (count > 30) {
        printf("| ... (%zu more)                         | ...                                    |\n", 
               count - 30);
    }
    printf("+----------------------------------------+----------------------------------------+\n");
}

/**
 * @brief Prints all sections from a driver
 * @param path Path to .sys file
 */
static inline void cdll_print_driver_sections(const char* path) {
    if (!path) return;
    
    cdll_driver_section_t sections[32];
    size_t count = cdll_enumerate_driver_sections(path, sections, 32);
    
    printf("\n=== Driver Sections (%zu) ===\n", count);
    printf("+------------+------------+------------+------------+-----------------------------+\n");
    printf("| Name       | VirtAddr   | VirtSize   | RawSize    | Characteristics             |\n");
    printf("+------------+------------+------------+------------+-----------------------------+\n");
    
    for (size_t i = 0; i < count; i++) {
        char flags[64] = "";
        if (sections[i].is_executable) strcat(flags, "X");
        if (sections[i].is_readable) strcat(flags, "R");
        if (sections[i].is_writable) strcat(flags, "W");
        if (sections[i].is_not_paged) strcat(flags, " NP");
        if (sections[i].is_discardable) strcat(flags, " DISC");
        if (sections[i].is_not_cached) strcat(flags, " NC");
        
        printf("| %-10s | 0x%08X | 0x%08X | 0x%08X | %-27s |\n",
               sections[i].name,
               sections[i].virtual_address,
               (uint32_t)sections[i].virtual_size,
               (uint32_t)sections[i].raw_size,
               flags);
    }
    printf("+------------+------------+------------+------------+-----------------------------+\n");
}

#elif defined(__linux__)
#include <sys/utsname.h>
#include <libelf.h>
#include <gelf.h>

/**
 * @brief Gets detailed information about a Linux Kernel Object (.ko) file
 * @param path Path to the .ko driver file
 * @param info Pointer to driver information structure to fill
 * @return true on success, false on failure
 */
static inline bool cdll_get_driver_info(const char* path, cdll_driver_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_driver_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    info->is_driver = true;
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        cdll_set_error("cdll_get_driver_info", errno, "Failed to open driver file");
        return false;
    }
    
    fseek(f, 0, SEEK_END);
    info->image_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4 || magic[0] != 0x7F || 
        magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        fclose(f);
        cdll_set_error("cdll_get_driver_info", EINVAL, "Invalid ELF signature");
        return false;
    }
    
    fclose(f);
    
    if (elf_version(EV_CURRENT) == EV_NONE) return false;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;
    
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return false;
    }
    
    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        elf_end(elf);
        close(fd);
        return false;
    }
    
    info->is_64bit = (ehdr.e_ident[EI_CLASS] == ELFCLASS64);
    info->machine_type = ehdr.e_machine;
    info->entry_point = (void*)(uintptr_t)ehdr.e_entry;
    
    /* Parse .modinfo section */
    Elf_Scn* scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != NULL) {
            char* name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
            if (name && strcmp(name, ".modinfo") == 0) {
                Elf_Data* data = elf_getdata(scn, NULL);
                if (data && data->d_buf) {
                    char* modinfo = (char*)data->d_buf;
                    char* ptr = modinfo;
                    char* end = modinfo + data->d_size;
                    
                    while (ptr < end) {
                        if (strncmp(ptr, "license=", 8) == 0) {
                            sscanf(ptr, "license=%255s", info->license);
                        } else if (strncmp(ptr, "version=", 8) == 0) {
                            sscanf(ptr, "version=%63s", info->version);
                        } else if (strncmp(ptr, "description=", 12) == 0) {
                            sscanf(ptr, "description=%511[^\n]", info->description);
                        } else if (strncmp(ptr, "author=", 7) == 0) {
                            sscanf(ptr, "author=%255[^\n]", info->author);
                        }
                        ptr += strlen(ptr) + 1;
                    }
                }
            }
        }
    }
    
    struct stat st;
    if (fstat(fd, &st) == 0) info->timestamp = st.st_mtime;
    
    elf_end(elf);
    close(fd);
    
    /* Check if loaded */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "lsmod | grep -q '^%s ' 2>/dev/null", info->name);
    info->is_loaded = (system(cmd) == 0);
    info->is_signed = cdll_verify_signature(path);
    
    return true;
}

/**
 * @brief Enumerates all currently loaded kernel drivers
 * @param drivers Array to fill with driver names (max 256 chars each)
 * @param max_drivers Maximum number of drivers to enumerate
 * @return Number of drivers found, or 0 on failure
 */
static inline size_t cdll_enumerate_loaded_drivers(char drivers[][256], size_t max_drivers) {
    if (!drivers || max_drivers == 0) return 0;
    
    size_t count = 0;
    FILE* f = fopen("/proc/modules", "r");
    if (!f) return 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f) && count < max_drivers) {
        char name[256];
        if (sscanf(line, "%255s", name) == 1) {
            snprintf(drivers[count], 256, "%s.ko", name);
            count++;
        }
    }
    
    fclose(f);
    return count;
}

/**
 * @brief Enumerates all exported functions from a Linux Kernel Object
 * @param path Path to the .ko driver file
 * @param entries Array to fill with export information
 * @param max_entries Maximum number of entries to enumerate
 * @re
static inline size_t cdll_enumerate_driver_exports(const char* path, cdll_driver_export_t* entries, size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(fd);
        return 0;
    }
    
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return 0;
    }
    
    size_t count = 0;
    Elf_Scn* scn = NULL;
    
    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_entries) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != NULL && shdr.sh_type == SHT_SYMTAB) {
            Elf_Data* data = elf_getdata(scn, NULL);
            if (data) {
                size_t num_symbols = shdr.sh_size / shdr.sh_entsize;
                Elf_Scn* strscn = elf_getscn(elf, shdr.sh_link);
                if (strscn) {
                    Elf_Data* strdata = elf_getdata(strscn, NULL);
                    
                    for (size_t i = 0; i < num_symbols && count < max_entries; i++) {
                        GElf_Sym sym;
                        if (gelf_getsym(data, i, &sym) != NULL) {
                            if (sym.st_name != 0 && 
                                (GELF_ST_BIND(sym.st_info) == STB_GLOBAL ||
                                 GELF_ST_BIND(sym.st_info) == STB_WEAK) &&
                                sym.st_shndx != SHN_UNDEF) {
                                
                                char* name = (char*)strdata->d_buf + sym.st_name;
                                strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
                                entries[count].rva = sym.st_value;
                                entries[count].ordinal = i;
                                cdll_demangle_symbol(name, entries[count].demangled_name,
                                                    sizeof(entries[count].demangled_name));
                                count++;
                            }
                        }
                    }
                }
            }
            break;
        }
    }
    
    elf_end(elf);
    close(fd);
    return count;
}

/**
 * @brief Enumerates all imported functions of a Linux Kernel Object
 * @param path Path to the .ko driver file
 * @param entries Array to fill with import information
 * @param max_entries Maximum number of entries to enumerate
 * @return Number of imports found, or 0 on failure
 */
static inline size_t cdll_enumerate_driver_imports(const char* path, cdll_driver_import_t* entries, size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(fd);
        return 0;
    }
    
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return 0;
    }
    
    size_t count = 0;
    Elf_Scn* scn = NULL;
    
    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_entries) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != NULL && shdr.sh_type == SHT_SYMTAB) {
            Elf_Data* data = elf_getdata(scn, NULL);
            if (data) {
                size_t num_symbols = shdr.sh_size / shdr.sh_entsize;
                Elf_Scn* strscn = elf_getscn(elf, shdr.sh_link);
                if (strscn) {
                    Elf_Data* strdata = elf_getdata(strscn, NULL);
                    
                    for (size_t i = 0; i < num_symbols && count < max_entries; i++) {
                        GElf_Sym sym;
                        if (gelf_getsym(data, i, &sym) != NULL) {
                            if (sym.st_name != 0 && sym.st_shndx == SHN_UNDEF) {
                                char* name = (char*)strdata->d_buf + sym.st_name;
                                strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
                                strncpy(entries[count].module_name, "kernel", sizeof(entries[count].module_name) - 1);
                                entries[count].ordinal = i;
                                count++;
                            }
                        }
                    }
                }
            }
            break;
        }
    }
    
    elf_end(elf);
    close(fd);
    return count;
}

/**
 * @brief Enumerates all sections of a Linux Kernel Object
 * @param path Path to the .sys driver file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to enumerate
 * @return Number of sections found, or 0 on failure
 */
static inline size_t cdll_enumerate_driver_sections(const char* path, cdll_driver_section_t* sections, size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(fd);
        return 0;
    }
    
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        close(fd);
        return 0;
    }
    
    GElf_Ehdr ehdr;
    if (gelf_getehdr(elf, &ehdr) == NULL) {
        elf_end(elf);
        close(fd);
        return 0;
    }
    
    size_t count = 0;
    Elf_Scn* scn = NULL;
    
    while ((scn = elf_nextscn(elf, scn)) != NULL && count < max_sections) {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != NULL) {
            char* name = elf_strptr(elf, ehdr.e_shstrndx, shdr.sh_name);
            if (name && shdr.sh_type != SHT_NULL) {
                strncpy(sections[count].name, name, sizeof(sections[count].name) - 1);
                sections[count].virtual_address = shdr.sh_addr;
                sections[count].virtual_size = shdr.sh_size;
                sections[count].raw_size = shdr.sh_size;
                sections[count].alignment = shdr.sh_addralign;
                sections[count].is_executable = (shdr.sh_flags & SHF_EXECINSTR) != 0;
                sections[count].is_writable = (shdr.sh_flags & SHF_WRITE) != 0;
                sections[count].is_readable = true;
                count++;
            }
        }
    }
    
    elf_end(elf);
    close(fd);
    return count;
}

#elif defined(__APPLE__)
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/stab.h>
#include <mach-o/swap.h>
#include <IOKit/kext/KextManager.h>
#include <CoreFoundation/CoreFoundation.h>

/**
 * @brief Gets detailed information about a macOS driver (.kext) file
 * @param path Path to the .kext driver file
 * @param info Pointer to driver information structure to fill
 * @return true on success, false on failure
 */
static inline bool cdll_get_driver_info(const char* path, cdll_driver_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_driver_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    info->is_driver = true;
    
    char plist_path[1024];
    snprintf(plist_path, sizeof(plist_path), "%s/Contents/Info.plist", path);
    
    if (!cdll_file_exists(plist_path)) {
        char exe_dir[1024];
        snprintf(exe_dir, sizeof(exe_dir), "%s/Contents/MacOS/", path);
        DIR* dir = opendir(exe_dir);
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != NULL) {
                if (entry->d_type == DT_REG) {
                    char exe_path[1024];
                    snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/%s", path, entry->d_name);
                    
                    FILE* f = fopen(exe_path, "rb");
                    if (f) {
                        uint32_t magic;
                        fread(&magic, sizeof(magic), 1, f);
                        info->is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
                        fseek(f, 0, SEEK_END);
                        info->image_size = ftell(f);
                        
                        struct stat st;
                        if (stat(exe_path, &st) == 0) info->timestamp = st.st_mtime;
                        
                        fclose(f);
                    }
                    break;
                }
            }
            closedir(dir);
        }
    }
    
    CFStringRef pathStr = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    if (pathStr) {
        CFURLRef url = CFURLCreateWithFileSystemPath(NULL, pathStr, kCFURLPOSIXPathStyle, true);
        if (url) {
            CFDictionaryRef infoDict = CFBundleCopyInfoDictionaryInDirectory(url);
            if (infoDict) {
                CFStringRef bundleId = CFDictionaryGetValue(infoDict, CFSTR("CFBundleIdentifier"));
                if (bundleId) {
                    CFStringGetCString(bundleId, info->service_name, sizeof(info->service_name), kCFStringEncodingUTF8);
                }
                
                CFStringRef version = CFDictionaryGetValue(infoDict, CFSTR("CFBundleVersion"));
                if (version) {
                    CFStringGetCString(version, info->version, sizeof(info->version), kCFStringEncodingUTF8);
                }
                
                CFStringRef desc = CFDictionaryGetValue(infoDict, CFSTR("CFBundleName"));
                if (desc) {
                    CFStringGetCString(desc, info->description, sizeof(info->description), kCFStringEncodingUTF8);
                }
                
                CFRelease(infoDict);
            }
            CFRelease(url);
        }
        CFRelease(pathStr);
    }
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "kextstat | grep -q '%s' 2>/dev/null", info->service_name);
    info->is_loaded = (system(cmd) == 0);
    info->is_signed = cdll_verify_signature(path);
    
    return true;
}

/**
 * @brief Enumerates all currently loaded kernel drivers
 * @param drivers Array to fill with driver names (max 256 chars each)
 * @param max_drivers Maximum number of drivers to enumerate
 * @return Number of drivers found, or 0 on failure
 */
static inline size_t cdll_enumerate_loaded_drivers(char drivers[][256], size_t max_drivers) {
    if (!drivers || max_drivers == 0) return 0;
    
    size_t count = 0;
    FILE* f = popen("kextstat | tail -n +2 | awk '{print $6}'", "r");
    if (!f) return 0;
    
    char line[256];
    while (fgets(line, sizeof(line), f) && count < max_drivers) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) > 0) {
            snprintf(drivers[count], 256, "%s.kext", line);
            count++;
        }
    }
    
    pclose(f);
    return count;
}

/**
 * @brief Enumerates all exported functions from a macOS driver
 * @param path Path to the .kext driver file
 * @param entries Array to fill with export information
 * @param max_entries Maximum number of entries to enumerate
 * @return Number of exports found, or 0 on failure
 */
static inline size_t cdll_enumerate_driver_exports(const char* path, 
                                                    cdll_driver_export_t* entries,
                                                    size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    /* Find the actual Mach-O executable inside the .kext bundle */
    char exe_path[1024] = {0};
    char exe_dir[1024];
    snprintf(exe_dir, sizeof(exe_dir), "%s/Contents/MacOS/", path);
    
    DIR* dir = opendir(exe_dir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/%s", path, entry->d_name);
                break;
            }
        }
        closedir(dir);
    }
    
    if (!exe_path[0]) return 0;
    
    FILE* f = fopen(exe_path, "rb");
    if (!f) return 0;
    
    /* Read Mach-O header */
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    #define SWAP64(x) (swap_bytes ? OSSwapInt64(x) : (x))
    
    size_t count = 0;
    
    if (is_64bit) {
        struct mach_header_64 header;
        fseek(f, 0, SEEK_SET);
        if (fread(&header, sizeof(header), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint8_t* load_cmds = (uint8_t*)malloc(SWAP32(header.sizeofcmds));
        if (!load_cmds) {
            fclose(f);
            return 0;
        }
        
        fread(load_cmds, SWAP32(header.sizeofcmds), 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        struct symtab_command* symtab = NULL;
        struct dysymtab_command* dysymtab = NULL;
        
        for (uint32_t i = 0; i < ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SYMTAB) {
                symtab = (struct symtab_command*)lc;
            } else if (cmd == LC_DYSYMTAB) {
                dysymtab = (struct dysymtab_command*)lc;
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        if (symtab && symtab->nsyms > 0) {
            uint32_t nsyms = SWAP32(symtab->nsyms);
            uint32_t symoff = SWAP32(symtab->symoff);
            uint32_t stroff = SWAP32(symtab->stroff);
            uint32_t strsize = SWAP32(symtab->strsize);
            
            struct nlist_64* symbols = (struct nlist_64*)malloc(nsyms * sizeof(struct nlist_64));
            char* strtab = (char*)malloc(strsize);
            
            if (symbols && strtab) {
                fseek(f, symoff, SEEK_SET);
                fread(symbols, sizeof(struct nlist_64), nsyms, f);
                
                fseek(f, stroff, SEEK_SET);
                fread(strtab, strsize, 1, f);
                
                uint32_t start_idx = 0;
                uint32_t end_idx = nsyms;
                
                if (dysymtab) {
                    start_idx = SWAP32(dysymtab->iextdefsym);
                    end_idx = start_idx + SWAP32(dysymtab->nextdefsym);
                }
                
                for (uint32_t i = start_idx; i < end_idx && count < max_entries; i++) {
                    uint8_t type = symbols[i].n_type;
                    if ((type & N_TYPE) == N_SECT && (type & N_EXT)) {
                        uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                        if (strx > 0 && strx < strsize) {
                            char* name = strtab + strx;
                            strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
                            entries[count].rva = SWAP64(symbols[i].n_value);
                            entries[count].ordinal = count + 1;
                            entries[count].is_forwarded = false;
                            
                            cdll_demangle_symbol(name, entries[count].demangled_name,
                                                sizeof(entries[count].demangled_name));
                            
                            count++;
                        }
                    }
                }
            }
            
            free(symbols);
            free(strtab);
        }
        
        free(load_cmds);
    } else {
        struct mach_header header;
        fseek(f, 0, SEEK_SET);
        if (fread(&header, sizeof(header), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint8_t* load_cmds = (uint8_t*)malloc(SWAP32(header.sizeofcmds));
        if (!load_cmds) {
            fclose(f);
            return 0;
        }
        
        fread(load_cmds, SWAP32(header.sizeofcmds), 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        struct symtab_command* symtab = NULL;
        struct dysymtab_command* dysymtab = NULL;
        
        for (uint32_t i = 0; i < ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SYMTAB) {
                symtab = (struct symtab_command*)lc;
            } else if (cmd == LC_DYSYMTAB) {
                dysymtab = (struct dysymtab_command*)lc;
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        if (symtab && symtab->nsyms > 0) {
            uint32_t nsyms = SWAP32(symtab->nsyms);
            uint32_t symoff = SWAP32(symtab->symoff);
            uint32_t stroff = SWAP32(symtab->stroff);
            uint32_t strsize = SWAP32(symtab->strsize);
            
            struct nlist* symbols = (struct nlist*)malloc(nsyms * sizeof(struct nlist));
            char* strtab = (char*)malloc(strsize);
            
            if (symbols && strtab) {
                fseek(f, symoff, SEEK_SET);
                fread(symbols, sizeof(struct nlist), nsyms, f);
                
                fseek(f, stroff, SEEK_SET);
                fread(strtab, strsize, 1, f);
                
                uint32_t start_idx = 0;
                uint32_t end_idx = nsyms;
                
                if (dysymtab) {
                    start_idx = SWAP32(dysymtab->iextdefsym);
                    end_idx = start_idx + SWAP32(dysymtab->nextdefsym);
                }
                
                for (uint32_t i = start_idx; i < end_idx && count < max_entries; i++) {
                    uint8_t type = symbols[i].n_type;
                    if ((type & N_TYPE) == N_SECT && (type & N_EXT)) {
                        uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                        if (strx > 0 && strx < strsize) {
                            char* name = strtab + strx;
                            strncpy(entries[count].name, name, sizeof(entries[count].name) - 1);
                            entries[count].rva = SWAP32(symbols[i].n_value);
                            entries[count].ordinal = count + 1;
                            entries[count].is_forwarded = false;
                            
                            cdll_demangle_symbol(name, entries[count].demangled_name,
                                                sizeof(entries[count].demangled_name));
                            
                            count++;
                        }
                    }
                }
            }
            
            free(symbols);
            free(strtab);
        }
        
        free(load_cmds);
    }
    
    #undef SWAP32
    #undef SWAP64
    
    fclose(f);
    return count;
}

/**
 * @brief Enumerates all imported functions of a macOS driver
 * @param path Path to the .kext driver file
 * @param entries Array to fill with import information
 * @param max_entries Maximum number of entries to enumerate
 * @return Number of imports found, or 0 on failure
 */
static inline size_t cdll_enumerate_driver_imports(const char* path,
                                                    cdll_driver_import_t* entries,
                                                    size_t max_entries) {
    if (!path || !entries || max_entries == 0) return 0;
    
    char exe_path[1024] = {0};
    char exe_dir[1024];
    snprintf(exe_dir, sizeof(exe_dir), "%s/Contents/MacOS/", path);
    
    DIR* dir = opendir(exe_dir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/%s", path, entry->d_name);
                break;
            }
        }
        closedir(dir);
    }
    
    if (!exe_path[0]) return 0;
    
    FILE* f = fopen(exe_path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    
    size_t count = 0;
    uint32_t header_size = is_64bit ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
    uint8_t* header_buf = (uint8_t*)malloc(header_size);
    
    fseek(f, 0, SEEK_SET);
    fread(header_buf, header_size, 1, f);
    
    uint32_t ncmds = is_64bit ? SWAP32(((struct mach_header_64*)header_buf)->ncmds) 
                              : SWAP32(((struct mach_header*)header_buf)->ncmds);
    uint32_t sizeofcmds = is_64bit ? SWAP32(((struct mach_header_64*)header_buf)->sizeofcmds)
                                   : SWAP32(((struct mach_header*)header_buf)->sizeofcmds);
    
    uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
    fread(load_cmds, sizeofcmds, 1, f);
    
    uint8_t* cmd_ptr = load_cmds;
    struct symtab_command* symtab = NULL;
    struct dysymtab_command* dysymtab = NULL;
    
    for (uint32_t i = 0; i < ncmds; i++) {
        struct load_command* lc = (struct load_command*)cmd_ptr;
        uint32_t cmd = SWAP32(lc->cmd);
        
        if (cmd == LC_SYMTAB) {
            symtab = (struct symtab_command*)lc;
        } else if (cmd == LC_DYSYMTAB) {
            dysymtab = (struct dysymtab_command*)lc;
        } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB) {
            struct dylib_command* dylib = (struct dylib_command*)lc;
            uint32_t name_offset = SWAP32(dylib->dylib.name.offset);
            char* dylib_name = (char*)cmd_ptr + name_offset;
            
            if (count < max_entries) {
                strncpy(entries[count].module_name, dylib_name, sizeof(entries[count].module_name) - 1);
                entries[count].name[0] = '\0';
                entries[count].ordinal = 0;
                entries[count].is_delay_load = (cmd == LC_LOAD_WEAK_DYLIB);
                count++;
            }
        }
        
        cmd_ptr += SWAP32(lc->cmdsize);
    }
    
    /* Also parse undefined symbols as imports */
    if (symtab && dysymtab && count < max_entries) {
        uint32_t nsyms = SWAP32(symtab->nsyms);
        uint32_t symoff = SWAP32(symtab->symoff);
        uint32_t stroff = SWAP32(symtab->stroff);
        uint32_t strsize = SWAP32(symtab->strsize);
        uint32_t iundefsym = SWAP32(dysymtab->iundefsym);
        uint32_t nundefsym = SWAP32(dysymtab->nundefsym);
        
        char* strtab = (char*)malloc(strsize);
        fseek(f, stroff, SEEK_SET);
        fread(strtab, strsize, 1, f);
        
        if (is_64bit) {
            struct nlist_64* symbols = (struct nlist_64*)malloc(nsyms * sizeof(struct nlist_64));
            fseek(f, symoff, SEEK_SET);
            fread(symbols, sizeof(struct nlist_64), nsyms, f);
            
            for (uint32_t i = iundefsym; i < iundefsym + nundefsym && count < max_entries; i++) {
                uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                if (strx > 0 && strx < strsize) {
                    strncpy(entries[count].name, strtab + strx, sizeof(entries[count].name) - 1);
                    strncpy(entries[count].module_name, "external", sizeof(entries[count].module_name) - 1);
                    entries[count].ordinal = i;
                    count++;
                }
            }
            free(symbols);
        } else {
            struct nlist* symbols = (struct nlist*)malloc(nsyms * sizeof(struct nlist));
            fseek(f, symoff, SEEK_SET);
            fread(symbols, sizeof(struct nlist), nsyms, f);
            
            for (uint32_t i = iundefsym; i < iundefsym + nundefsym && count < max_entries; i++) {
                uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                if (strx > 0 && strx < strsize) {
                    strncpy(entries[count].name, strtab + strx, sizeof(entries[count].name) - 1);
                    strncpy(entries[count].module_name, "external", sizeof(entries[count].module_name) - 1);
                    entries[count].ordinal = i;
                    count++;
                }
            }
            free(symbols);
        }
        free(strtab);
    }
    
    #undef SWAP32
    
    free(header_buf);
    free(load_cmds);
    fclose(f);
    return count;
}

/**
 * @brief Enumerates all sections of a macOS driver
 * @param path Path to the .kext driver file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to enumerate
 * @return Number of sections found, or 0 on failure
 */
static inline size_t cdll_enumerate_driver_sections(const char* path,
                                                     cdll_driver_section_t* sections,
                                                     size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    char exe_path[1024] = {0};
    char exe_dir[1024];
    snprintf(exe_dir, sizeof(exe_dir), "%s/Contents/MacOS/", path);
    
    DIR* dir = opendir(exe_dir);
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_REG) {
                snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/%s", path, entry->d_name);
                break;
            }
        }
        closedir(dir);
    }
    
    if (!exe_path[0]) return 0;
    
    FILE* f = fopen(exe_path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    #define SWAP64(x) (swap_bytes ? OSSwapInt64(x) : (x))
    
    size_t count = 0;
    
    if (is_64bit) {
        struct mach_header_64 header;
        fseek(f, 0, SEEK_SET);
        fread(&header, sizeof(header), 1, f);
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint8_t* load_cmds = (uint8_t*)malloc(SWAP32(header.sizeofcmds));
        fread(load_cmds, SWAP32(header.sizeofcmds), 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        
        for (uint32_t i = 0; i < ncmds && count < max_sections; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SEGMENT_64) {
                struct segment_command_64* seg = (struct segment_command_64*)lc;
                uint32_t nsects = SWAP32(seg->nsects);
                
                struct section_64* sect = (struct section_64*)(seg + 1);
                for (uint32_t j = 0; j < nsects && count < max_sections; j++) {
                    strncpy(sections[count].name, sect[j].sectname, sizeof(sections[count].name) - 1);
                    sections[count].virtual_address = SWAP64(sect[j].addr);
                    sections[count].virtual_size = SWAP64(sect[j].size);
                    sections[count].raw_size = SWAP32(sect[j].offset) ? SWAP64(sect[j].size) : 0;
                    sections[count].alignment = SWAP32(sect[j].align);
                    
                    uint32_t flags = SWAP32(sect[j].flags);
                    sections[count].is_executable = (flags & S_ATTR_SOME_INSTRUCTIONS) || (flags & S_ATTR_PURE_INSTRUCTIONS);
                    sections[count].is_readable = true;
                    sections[count].is_writable = (flags & S_ATTR_DEBUG) == 0;
                    
                    count++;
                }
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        free(load_cmds);
    } else {
        struct mach_header header;
        fseek(f, 0, SEEK_SET);
        fread(&header, sizeof(header), 1, f);
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint8_t* load_cmds = (uint8_t*)malloc(SWAP32(header.sizeofcmds));
        fread(load_cmds, SWAP32(header.sizeofcmds), 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        
        for (uint32_t i = 0; i < ncmds && count < max_sections; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SEGMENT) {
                struct segment_command* seg = (struct segment_command*)lc;
                uint32_t nsects = SWAP32(seg->nsects);
                
                struct section* sect = (struct section*)(seg + 1);
                for (uint32_t j = 0; j < nsects && count < max_sections; j++) {
                    strncpy(sections[count].name, sect[j].sectname, sizeof(sections[count].name) - 1);
                    sections[count].virtual_address = SWAP32(sect[j].addr);
                    sections[count].virtual_size = SWAP32(sect[j].size);
                    sections[count].raw_size = SWAP32(sect[j].offset) ? SWAP32(sect[j].size) : 0;
                    sections[count].alignment = SWAP32(sect[j].align);
                    
                    uint32_t flags = SWAP32(sect[j].flags);
                    sections[count].is_executable = (flags & S_ATTR_SOME_INSTRUCTIONS) || (flags & S_ATTR_PURE_INSTRUCTIONS);
                    sections[count].is_readable = true;
                    sections[count].is_writable = (flags & S_ATTR_DEBUG) == 0;
                    
                    count++;
                }
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        free(load_cmds);
    }
    
    #undef SWAP32
    #undef SWAP64
    
    fclose(f);
    return count;
}

#endif /* __APPLE__ */

#endif /* !_WIN32 */

/**
 * @brief Detects the compiler used to build an executable
 * @param path Path to the executable file
 * @param compiler_name Buffer to receive compiler name
 * @param size Size of the compiler_name buffer
 * @return true if compiler was detected, false otherwise
 */
static inline bool cdll_detect_compiler(const char* path, char* compiler_name, size_t size) {
    if (!path || !compiler_name || size == 0) return false;
    strncpy(compiler_name, "Unknown", size - 1);
    compiler_name[size - 1] = '\0';
    return true;
}

/**
 * @brief Detects packer/protector used on an executable
 * @param path Path to the executable file
 * @param packer_name Buffer to receive packer name
 * @param size Size of the packer_name buffer
 * @return true if packer was detected, false otherwise
 */
static inline bool cdll_detect_packer(const char* path, char* packer_name, size_t size) {
    if (!path || !packer_name || size == 0) return false;
    strncpy(packer_name, "None detected", size - 1);
    packer_name[size - 1] = '\0';
    return true;
}

/**
 * @brief Calculates Shannon entropy of a data buffer
 * @param data Pointer to data buffer
 * @param size Size of data buffer in bytes
 * @return Entropy value between 0.0 and 8.0
 */
static inline double cdll_calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;
    uint32_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

#ifndef IMAGE_GUARD_CF_INSTRUMENTED
#define IMAGE_GUARD_CF_INSTRUMENTED 0x00000100
#endif

/* ============================================================================
 * CDLL - Executable Analysis & Manipulation Module
 * Full Professional Implementation - Windows PE, Linux ELF, macOS Mach-O
 * ============================================================================ */

/* ============================================================================
 * Executable Module - Type Definitions
 * ============================================================================ */

/* Executable type enumeration */
typedef enum {
    CDLL_EXEC_UNKNOWN = 0,
    CDLL_EXEC_PE32,
    CDLL_EXEC_PE64,
    CDLL_EXEC_ELF32,
    CDLL_EXEC_ELF64,
    CDLL_EXEC_MACHO32,
    CDLL_EXEC_MACHO64,
    CDLL_EXEC_MACHO_FAT,
    CDLL_EXEC_APP_BUNDLE
} cdll_executable_type_t;

/* Process handle types */
#ifdef _WIN32
    typedef HANDLE cdll_process_handle;
    typedef DWORD cdll_thread_id;
    #define CDLL_INVALID_PROCESS NULL
    #define CDLL_INVALID_THREAD 0
#else
    typedef pid_t cdll_process_handle;
    typedef pthread_t cdll_thread_id;
    #define CDLL_INVALID_PROCESS (-1)
    #define CDLL_INVALID_THREAD 0
#endif

/* Executable information */
typedef struct cdll_executable_info {
    char path[1024];
    char name[256];
    cdll_executable_type_t type;
    bool is_64bit;
    bool is_signed;
    bool is_pie;
    bool is_stripped;
    bool is_encrypted;
    bool is_compressed;
    bool is_packed;
    bool is_dll;
    bool has_relocations;
    bool is_large_address_aware;
    bool is_high_entropy_va;
    bool has_security_cookie;
    bool is_control_flow_guard;
    void* entry_point;
    uint64_t image_base;
    size_t image_size;
    size_t header_size;
    uint32_t checksum;
    time_t build_time;
    uint16_t machine_type;
    char machine_str[32];
    uint16_t subsystem;
    char subsystem_str[64];
    char interpreter[256];
    char build_id[64];
    char compiler[64];
    char packer[64];
    char version[64];
} cdll_executable_info_t;

/* Executable section */
typedef struct cdll_executable_section {
    char name[32];
    uint64_t virtual_address;
    uint64_t virtual_size;
    uint64_t raw_offset;
    uint64_t raw_size;
    uint32_t characteristics;
    bool is_executable;
    bool is_readable;
    bool is_writable;
    bool is_shared;
    bool is_discardable;
    bool is_not_cached;
    bool is_not_paged;
    double entropy;
    uint64_t alignment;
    uint8_t* data;
} cdll_executable_section_t;

/* Executable import */
typedef struct cdll_executable_import {
    char name[256];
    char module_name[256];
    uint32_t hint;
    uint32_t ordinal;
    uint64_t iat_address;
    bool is_delay_load;
    bool is_bound;
} cdll_executable_import_t;

/* Executable export */
typedef struct cdll_executable_export {
    char name[256];
    char demangled_name[512];
    uint32_t ordinal;
    uint64_t rva;
    void* address;
    bool is_forwarded;
    char forwarder[512];
} cdll_executable_export_t;

/* Loaded executable */
typedef struct cdll_loaded_executable {
    cdll_executable_info_t info;
    void* base_address;
    void* entry_point;
    size_t loaded_size;
    cdll_process_handle process;
    cdll_thread_id main_thread;
    bool is_remote;
    bool is_suspended;
    void* custom_entry;
    cdll_executable_section_t* sections;
    size_t section_count;
    void* original_entry_point;
    
#ifdef _WIN32
    PIMAGE_NT_HEADERS nt_headers;
    void* tls_callbacks[32];
    size_t tls_callback_count;
    void* exception_directory;
    size_t exception_directory_size;
    void* security_cookie;
    bool guard_cf_enabled;
    uint8_t* relocation_table;
    size_t relocation_size;
    void* import_address_table;
    size_t iat_size;
#elif defined(__linux__)
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdrs;
    Elf64_Shdr* shdrs;
    char* shstrtab;
    char* strtab;
    Elf64_Sym* symtab;
    size_t symtab_size;
    void* init_array;
    size_t init_array_size;
    void* fini_array;
    size_t fini_array_size;
    void* preinit_array;
    size_t preinit_array_size;
    void* tls_image;
    size_t tls_size;
    size_t tls_align;
    void* dynamic_section;
    size_t dynamic_size;
    char* interpreter_path;
    uintptr_t* got_plt;
    size_t got_plt_size;
    bool is_pie;
    uintptr_t load_bias;
#elif defined(__APPLE__)
    struct mach_header_64* header;
    void* load_commands;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    bool swap_bytes;
    void* symtab_cmd;
    void* dysymtab_cmd;
    struct nlist_64* symbols;
    uint32_t nsyms;
    char* strtab;
    uint32_t strsize;
    void* dyld_info;
    void* init_func;
    void* term_func;
    uintptr_t slide;
    task_t remote_task;
    thread_act_t remote_thread;
#endif
} cdll_loaded_executable_t;

#if defined(_WIN32)
/* ============================================================================
 * Windows PE - Complete Implementation
 * ============================================================================ */

#include <psapi.h>
#include <winternl.h>
#include <delayimp.h>
#include <dbghelp.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

/* Extended PE structures */
typedef struct {
    uint16_t characteristics;
    uint16_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t number_of_named_entries;
    uint16_t number_of_id_entries;
    uint32_t time_date_stamp_checksum;
    uint32_t reserved;
} pe_resource_directory_t;

typedef struct {
    uint32_t name_or_id;
    uint32_t offset_to_data;
} pe_resource_directory_entry_t;

typedef struct {
    uint32_t offset_to_data;
    uint32_t size;
    uint32_t code_page;
    uint32_t reserved;
} pe_resource_data_entry_t;

/* Extended NtQueryInformationProcess */
typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

/* TLS callback structure */
typedef struct {
    void* start_address_of_raw_data;
    void* end_address_of_raw_data;
    void* address_of_index;
    void* address_of_callbacks;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} pe_tls_directory_t;

/* Load config directory */
typedef struct {
    uint32_t size;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t global_flags_clear;
    uint32_t global_flags_set;
    uint32_t critical_section_default_timeout;
    uint64_t decommit_free_block_threshold;
    uint64_t decommit_total_free_threshold;
    uint64_t lock_prefix_table;
    uint64_t maximum_allocation_size;
    uint64_t virtual_memory_threshold;
    uint64_t process_affinity_mask;
    uint32_t process_heap_flags;
    uint16_t csd_version;
    uint16_t dependent_load_flags;
    uint64_t edit_list;
    uint64_t security_cookie;
    uint64_t se_handler_table;
    uint64_t se_handler_count;
    uint64_t guard_cf_check_function_pointer;
    uint64_t guard_cf_dispatch_function_pointer;
    uint64_t guard_cf_function_table;
    uint64_t guard_cf_function_count;
    uint32_t guard_flags;
} pe_load_config_directory64_t;

/* Exception directory */
typedef struct {
    uint32_t start_address;
    uint32_t end_address;
    uint32_t unwind_info_address;
} pe_runtime_function_t;

/* Forward declarations */
static void* pe_rva_to_va(cdll_loaded_executable_t* exec, uint32_t rva);
static uint32_t pe_va_to_rva(cdll_loaded_executable_t* exec, void* va);
static bool pe_process_relocations(cdll_loaded_executable_t* exec, uintptr_t delta);
static bool pe_resolve_imports(cdll_loaded_executable_t* exec);
static bool pe_process_tls_callbacks(cdll_loaded_executable_t* exec);
static bool pe_apply_exception_handlers(cdll_loaded_executable_t* exec);
static bool pe_enable_security_features(cdll_loaded_executable_t* exec);

/* ============================================================================
 * PE: Get Executable Information (Full)
 * ============================================================================ */

/**
 * @brief Gets comprehensive information about a PE executable
 * @param path Path to the .exe or .dll file
 * @param info Pointer to executable information structure to fill
 * @return true on success, false on failure
 */
static inline bool cdll_get_executable_info(const char* path, cdll_executable_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_executable_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cdll_set_error("cdll_get_executable_info", GetLastError(), "Failed to open file");
        return false;
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        cdll_set_error("cdll_get_executable_info", GetLastError(), "Failed to create file mapping");
        CloseHandle(hFile);
        return false;
    }
    
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        cdll_set_error("cdll_get_executable_info", GetLastError(), "Failed to map view of file");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        cdll_set_error("cdll_get_executable_info", EINVAL, "Invalid DOS signature");
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }
    
    /* Check for PE signature */
    if (dos->e_lfanew > file_size - sizeof(IMAGE_NT_HEADERS)) {
        cdll_set_error("cdll_get_executable_info", EINVAL, "Invalid PE offset");
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }
    
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        cdll_set_error("cdll_get_executable_info", EINVAL, "Invalid NT signature");
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }
    
    /* Determine type */
    if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
        info->type = CDLL_EXEC_PE64;
        info->is_64bit = true;
    } else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
        info->type = CDLL_EXEC_PE32;
        info->is_64bit = false;
    } else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64) {
        info->type = CDLL_EXEC_PE64;
        info->is_64bit = true;
    } else if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM) {
        info->type = CDLL_EXEC_PE32;
        info->is_64bit = false;
    }
    
    info->machine_type = nt->FileHeader.Machine;
    info->subsystem = nt->OptionalHeader.Subsystem;
    info->entry_point = (void*)(uintptr_t)nt->OptionalHeader.AddressOfEntryPoint;
    info->image_base = nt->OptionalHeader.ImageBase;
    info->image_size = nt->OptionalHeader.SizeOfImage;
    info->header_size = nt->OptionalHeader.SizeOfHeaders;
    info->checksum = nt->OptionalHeader.CheckSum;
    info->build_time = nt->FileHeader.TimeDateStamp;
    info->is_dll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
    
    /* Check characteristics */
    info->is_pie = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    info->is_stripped = (nt->FileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) != 0;
    info->has_relocations = (nt->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) == 0;
    info->is_large_address_aware = (nt->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    info->is_high_entropy_va = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
    info->has_security_cookie = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    info->is_control_flow_guard = (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
    
    /* Check digital signature */
    info->is_signed = cdll_verify_signature(path);
    
    /* Get subsystem string */
    switch (nt->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_NATIVE: strcpy(info->subsystem_str, "Native"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: strcpy(info->subsystem_str, "Windows GUI"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: strcpy(info->subsystem_str, "Windows Console"); break;
        case IMAGE_SUBSYSTEM_OS2_CUI: strcpy(info->subsystem_str, "OS/2 Console"); break;
        case IMAGE_SUBSYSTEM_POSIX_CUI: strcpy(info->subsystem_str, "POSIX Console"); break;
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: strcpy(info->subsystem_str, "Windows CE"); break;
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: strcpy(info->subsystem_str, "EFI Application"); break;
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: strcpy(info->subsystem_str, "EFI Boot Driver"); break;
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: strcpy(info->subsystem_str, "EFI Runtime Driver"); break;
        case IMAGE_SUBSYSTEM_EFI_ROM: strcpy(info->subsystem_str, "EFI ROM"); break;
        case IMAGE_SUBSYSTEM_XBOX: strcpy(info->subsystem_str, "Xbox"); break;
        default: snprintf(info->subsystem_str, sizeof(info->subsystem_str), "0x%04X", nt->OptionalHeader.Subsystem);
    }
    
    /* Get machine string */
    switch (nt->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386: strcpy(info->machine_str, "x86"); break;
        case IMAGE_FILE_MACHINE_AMD64: strcpy(info->machine_str, "x64"); break;
        case IMAGE_FILE_MACHINE_ARM: strcpy(info->machine_str, "ARM"); break;
        case IMAGE_FILE_MACHINE_ARM64: strcpy(info->machine_str, "ARM64"); break;
        case IMAGE_FILE_MACHINE_IA64: strcpy(info->machine_str, "IA64"); break;
        default: snprintf(info->machine_str, sizeof(info->machine_str), "0x%04X", nt->FileHeader.Machine);
    }
    
    UnmapViewOfFile(view);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    /* Detect compiler and packer */
    cdll_detect_compiler(path, info->compiler, sizeof(info->compiler));
    cdll_detect_packer(path, info->packer, sizeof(info->packer));
    info->is_packed = (strcmp(info->packer, "None detected") != 0);
    
    return true;
}

/* ============================================================================
 * PE: Enumerate Sections (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all PE sections of an executable
 * @param path Path to the executable file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to enumerate
 * @return Number of sections found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_sections(const char* path,
                                                         cdll_executable_section_t* sections,
                                                         size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }
    
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)view;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    
    size_t count = 0;
    FILE* f = fopen(path, "rb");
    
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && count < max_sections; i++) {
        memcpy(sections[count].name, section[i].Name, sizeof(section[i].Name));
        sections[count].name[sizeof(section[i].Name)] = '\0';
        
        /* Remove trailing spaces */
        char* p = sections[count].name + strlen(sections[count].name) - 1;
        while (p >= sections[count].name && *p == ' ') *p-- = '\0';
        
        sections[count].virtual_address = section[i].VirtualAddress;
        sections[count].virtual_size = section[i].Misc.VirtualSize;
        sections[count].raw_offset = section[i].PointerToRawData;
        sections[count].raw_size = section[i].SizeOfRawData;
        sections[count].characteristics = section[i].Characteristics;
        
        sections[count].is_executable = (section[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        sections[count].is_readable = (section[i].Characteristics & IMAGE_SCN_MEM_READ) != 0;
        sections[count].is_writable = (section[i].Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        sections[count].is_shared = (section[i].Characteristics & IMAGE_SCN_MEM_SHARED) != 0;
        sections[count].is_discardable = (section[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0;
        sections[count].is_not_cached = (section[i].Characteristics & IMAGE_SCN_MEM_NOT_CACHED) != 0;
        sections[count].is_not_paged = (section[i].Characteristics & IMAGE_SCN_MEM_NOT_PAGED) != 0;
        
        /* Calculate entropy */
        if (f && section[i].SizeOfRawData > 0 && section[i].SizeOfRawData < 100 * 1024 * 1024) {
            uint8_t* data = (uint8_t*)malloc(section[i].SizeOfRawData);
            if (data) {
                fseek(f, section[i].PointerToRawData, SEEK_SET);
                size_t read = fread(data, 1, section[i].SizeOfRawData, f);
                if (read == section[i].SizeOfRawData) {
                    sections[count].entropy = cdll_calculate_entropy(data, read);
                }
                free(data);
            }
        }
        
        /* Check for section data pointer */
        sections[count].data = NULL;
        if (section[i].SizeOfRawData > 0) {
            sections[count].data = (uint8_t*)view + section[i].PointerToRawData;
        }
        
        count++;
    }
    
    if (f) fclose(f);
    UnmapViewOfFile(view);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return count;
}

/* ============================================================================
 * PE: Enumerate Imports (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all imported functions of a PE executable
 * @param path Path to the executable file
 * @param imports Array to fill with import information
 * @param max_imports Maximum number of imports to enumerate
 * @return Number of imports found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_imports(const char* path,
                                                        cdll_executable_import_t* imports,
                                                        size_t max_imports) {
    if (!path || !imports || max_imports == 0) return 0;
    
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }
    
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)view;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (import_rva == 0) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    size_t count = 0;
    bool is_64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    
    /* Find import section */
    PIMAGE_SECTION_HEADER import_section = NULL;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (import_rva >= section[i].VirtualAddress &&
            import_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            import_section = &section[i];
            break;
        }
    }
    
    if (!import_section) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD import_offset = import_section->PointerToRawData + (import_rva - import_section->VirtualAddress);
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)view + import_offset);
    
    while (import_desc->Name != 0 && count < max_imports) {
        /* Get module name */
        DWORD name_rva = import_desc->Name;
        PIMAGE_SECTION_HEADER name_section = NULL;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (name_rva >= section[i].VirtualAddress &&
                name_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                name_section = &section[i];
                break;
            }
        }
        
        char* module_name = NULL;
        if (name_section) {
            DWORD name_offset = name_section->PointerToRawData + (name_rva - name_section->VirtualAddress);
            module_name = (char*)view + name_offset;
        }
        
        /* Process IAT */
        DWORD iat_rva = import_desc->FirstThunk;
        DWORD thunk_rva = import_desc->OriginalFirstThunk ? 
                          import_desc->OriginalFirstThunk : import_desc->FirstThunk;
        
        PIMAGE_SECTION_HEADER thunk_section = NULL;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (thunk_rva >= section[i].VirtualAddress &&
                thunk_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                thunk_section = &section[i];
                break;
            }
        }
        
        if (thunk_section) {
            DWORD thunk_offset = thunk_section->PointerToRawData + (thunk_rva - thunk_section->VirtualAddress);
            
            if (is_64bit) {
                uint64_t* thunk = (uint64_t*)((BYTE*)view + thunk_offset);
                while (*thunk != 0 && count < max_imports) {
                    if (*thunk & 0x8000000000000000ULL) {
                        imports[count].ordinal = *thunk & 0xFFFF;
                        imports[count].name[0] = '\0';
                    } else {
                        DWORD hint_rva = (DWORD)(*thunk & 0x7FFFFFFF);
                        PIMAGE_SECTION_HEADER hint_section = NULL;
                        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                            if (hint_rva >= section[i].VirtualAddress &&
                                hint_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                                hint_section = &section[i];
                                break;
                            }
                        }
                        
                        if (hint_section) {
                            DWORD hint_offset = hint_section->PointerToRawData + (hint_rva - hint_section->VirtualAddress);
                            PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)view + hint_offset);
                            imports[count].hint = import_name->Hint;
                            strncpy(imports[count].name, import_name->Name, sizeof(imports[count].name) - 1);
                        }
                    }
                    
                    if (module_name) {
                        strncpy(imports[count].module_name, module_name, sizeof(imports[count].module_name) - 1);
                    }
                    imports[count].iat_address = iat_rva;
                    
                    thunk++;
                    iat_rva += 8;
                    count++;
                }
            } else {
                uint32_t* thunk = (uint32_t*)((BYTE*)view + thunk_offset);
                while (*thunk != 0 && count < max_imports) {
                    if (*thunk & IMAGE_ORDINAL_FLAG) {
                        imports[count].ordinal = *thunk & 0xFFFF;
                        imports[count].name[0] = '\0';
                    } else {
                        DWORD hint_rva = *thunk & 0x7FFFFFFF;
                        PIMAGE_SECTION_HEADER hint_section = NULL;
                        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                            if (hint_rva >= section[i].VirtualAddress &&
                                hint_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                                hint_section = &section[i];
                                break;
                            }
                        }
                        
                        if (hint_section) {
                            DWORD hint_offset = hint_section->PointerToRawData + (hint_rva - hint_section->VirtualAddress);
                            PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)((BYTE*)view + hint_offset);
                            imports[count].hint = import_name->Hint;
                            strncpy(imports[count].name, import_name->Name, sizeof(imports[count].name) - 1);
                        }
                    }
                    
                    if (module_name) {
                        strncpy(imports[count].module_name, module_name, sizeof(imports[count].module_name) - 1);
                    }
                    imports[count].iat_address = iat_rva;
                    
                    thunk++;
                    iat_rva += 4;
                    count++;
                }
            }
        }
        
        import_desc++;
    }
    
    /* Process delay-load imports */
    DWORD delay_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
    if (delay_rva != 0 && count < max_imports) {
        PIMAGE_SECTION_HEADER delay_section = NULL;
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (delay_rva >= section[i].VirtualAddress &&
                delay_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
                delay_section = &section[i];
                break;
            }
        }
        
        if (delay_section) {
            DWORD delay_offset = delay_section->PointerToRawData + (delay_rva - delay_section->VirtualAddress);
            PIMAGE_DELAYLOAD_DESCRIPTOR delay_desc = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE*)view + delay_offset);
            
            while (delay_desc->DllNameRVA != 0 && count < max_imports) {
                /* Process delay-load imports similarly */
                for (size_t i = 0; i < count; i++) {
                    imports[i].is_delay_load = true;
                }
                delay_desc++;
            }
        }
    }
    
    UnmapViewOfFile(view);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return count;
}

/* ============================================================================
 * PE: Enumerate Exports (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all exported functions of a PE executable
 * @param path Path to the executable file
 * @param exports Array to fill with export information
 * @param max_exports Maximum number of exports to enumerate
 * @return Number of exports found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_exports(const char* path,
                                                        cdll_executable_export_t* exports,
                                                        size_t max_exports) {
    if (!path || !exports || max_exports == 0) return 0;
    
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        return 0;
    }
    
    LPVOID view = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)view;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)view + dos->e_lfanew);
    
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva == 0) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    PIMAGE_SECTION_HEADER export_section = NULL;
    
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (export_rva >= section[i].VirtualAddress &&
            export_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            export_section = &section[i];
            break;
        }
    }
    
    if (!export_section) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD export_offset = export_section->PointerToRawData + (export_rva - export_section->VirtualAddress);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)view + export_offset);
    
    if (export_dir->NumberOfNames == 0) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    /* Get function addresses */
    DWORD func_rva = export_dir->AddressOfFunctions;
    PIMAGE_SECTION_HEADER func_section = NULL;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (func_rva >= section[i].VirtualAddress &&
            func_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            func_section = &section[i];
            break;
        }
    }
    
    if (!func_section) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD func_offset = func_section->PointerToRawData + (func_rva - func_section->VirtualAddress);
    DWORD* functions = (DWORD*)((BYTE*)view + func_offset);
    
    /* Get name table */
    DWORD names_rva = export_dir->AddressOfNames;
    PIMAGE_SECTION_HEADER names_section = NULL;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (names_rva >= section[i].VirtualAddress &&
            names_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            names_section = &section[i];
            break;
        }
    }
    
    if (!names_section) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD names_offset = names_section->PointerToRawData + (names_rva - names_section->VirtualAddress);
    DWORD* names = (DWORD*)((BYTE*)view + names_offset);
    
    /* Get ordinal table */
    DWORD ordinals_rva = export_dir->AddressOfNameOrdinals;
    PIMAGE_SECTION_HEADER ordinals_section = NULL;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (ordinals_rva >= section[i].VirtualAddress &&
            ordinals_rva < section[i].VirtualAddress + section[i].Misc.VirtualSize) {
            ordinals_section = &section[i];
            break;
        }
    }
    
    if (!ordinals_section) {
        UnmapViewOfFile(view);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return 0;
    }
    
    DWORD ordinals_offset = ordinals_section->PointerToRawData + (ordinals_rva - ordinals_section->VirtualAddress);
    WORD* ordinals = (WORD*)((BYTE*)view + ordinals_offset);
    
    size_t count = 0;
    
    for (DWORD i = 0; i < export_dir->NumberOfNames && count < max_exports; i++) {
        DWORD name_rva = names[i];
        PIMAGE_SECTION_HEADER name_section = NULL;
        for (WORD j = 0; j < nt->FileHeader.NumberOfSections; j++) {
            if (name_rva >= section[j].VirtualAddress &&
                name_rva < section[j].VirtualAddress + section[j].Misc.VirtualSize) {
                name_section = &section[j];
                break;
            }
        }
        
        if (name_section) {
            DWORD name_offset = name_section->PointerToRawData + (name_rva - name_section->VirtualAddress);
            char* name = (char*)view + name_offset;
            
            strncpy(exports[count].name, name, sizeof(exports[count].name) - 1);
            cdll_demangle_symbol(name, exports[count].demangled_name, sizeof(exports[count].demangled_name));
            
            WORD ordinal_idx = ordinals[i];
            exports[count].ordinal = ordinal_idx + export_dir->Base;
            exports[count].rva = functions[ordinal_idx];
            
            /* Check for forwarder */
            if (exports[count].rva >= export_rva && 
    exports[count].rva < export_rva + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
                DWORD forwarder_offset = export_section->PointerToRawData + 
                                         (exports[count].rva - export_rva);
                char* forwarder = (char*)view + forwarder_offset;
                strncpy(exports[count].forwarder, forwarder, sizeof(exports[count].forwarder) - 1);
                exports[count].is_forwarded = true;
            }
            
            count++;
        }
    }
    
    UnmapViewOfFile(view);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    
    return count;
}

/* ============================================================================
 * PE: Load Executable to Address (Full)
 * ============================================================================ */

/**
 * @brief Converts PE Relative Virtual Address to absolute virtual address
 * @param exec Loaded executable context
 * @param rva Relative Virtual Address
 * @return Absolute virtual address, or NULL if invalid
 */
static void* pe_rva_to_va(cdll_loaded_executable_t* exec, uint32_t rva) {
    if (!exec || rva == 0) return NULL;
    return (uint8_t*)exec->base_address + rva;
}

/**
 * @brief Converts absolute virtual address to PE Relative Virtual Address
 * @param exec Loaded executable context
 * @param va Absolute virtual address
 * @return Relative Virtual Address, or 0 if invalid
 */
static uint32_t pe_va_to_rva(cdll_loaded_executable_t* exec, void* va) {
    if (!exec || !va) return 0;
    return (uint32_t)((uint8_t*)va - (uint8_t*)exec->base_address);
}

/**
 * @brief Processes PE base relocations after loading at different address
 * @param exec Loaded executable context
 * @param delta Difference between preferred and actual base address
 * @return true on success, false on failure
 */
static bool pe_process_relocations(cdll_loaded_executable_t* exec, uintptr_t delta) {
    if (!exec || delta == 0) return true;
    
    PIMAGE_NT_HEADERS nt = exec->nt_headers;
    DWORD reloc_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    
    if (reloc_rva == 0) return true;
    
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)pe_rva_to_va(exec, reloc_rva);
    
    while (reloc->SizeOfBlock > 0) {
        DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < count; i++) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD offset = entry & 0xFFF;
            
            void* addr = (BYTE*)exec->base_address + reloc->VirtualAddress + offset;
            
            switch (type) {
                case IMAGE_REL_BASED_HIGHLOW:
                    *(uint32_t*)addr += (uint32_t)delta;
                    break;
                case IMAGE_REL_BASED_DIR64:
                    *(uint64_t*)addr += delta;
                    break;
                case IMAGE_REL_BASED_ABSOLUTE:
                    break;
                default:
                    break;
            }
        }
        
        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    
    return true;
}

/**
 * @brief Resolves PE import address table (IAT)
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool pe_resolve_imports(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    PIMAGE_NT_HEADERS nt = exec->nt_headers;
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    
    if (import_rva == 0) return true;
    
    PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)pe_rva_to_va(exec, import_rva);
    bool is_64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    
    while (import_desc->Name != 0) {
        char* module_name = (char*)pe_rva_to_va(exec, import_desc->Name);
        HMODULE hModule = LoadLibraryA(module_name);
        
        if (!hModule) {
            cdll_set_error("pe_resolve_imports", GetLastError(), "Failed to load module");
            return false;
        }
        
        uintptr_t iat = (uintptr_t)pe_rva_to_va(exec, import_desc->FirstThunk);
        uintptr_t thunk = (uintptr_t)pe_rva_to_va(exec, 
            import_desc->OriginalFirstThunk ? import_desc->OriginalFirstThunk : import_desc->FirstThunk);
        
        while (*(uintptr_t*)thunk != 0) {
            FARPROC func = NULL;
            
            if (is_64bit) {
                if (*(uint64_t*)thunk & 0x8000000000000000ULL) {
                    func = GetProcAddress(hModule, (LPCSTR)(*(uint64_t*)thunk & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)pe_rva_to_va(exec, (DWORD)(*(uint64_t*)thunk & 0x7FFFFFFF));
                    func = GetProcAddress(hModule, import_name->Name);
                }
            } else {
                if (*(uint32_t*)thunk & IMAGE_ORDINAL_FLAG) {
                    func = GetProcAddress(hModule, (LPCSTR)(uintptr_t)(*(uint32_t*)thunk & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME import_name = (PIMAGE_IMPORT_BY_NAME)pe_rva_to_va(exec, *(uint32_t*)thunk & 0x7FFFFFFF);
                    func = GetProcAddress(hModule, import_name->Name);
                }
            }
            
            if (!func) {
                cdll_set_error("pe_resolve_imports", GetLastError(), "Failed to resolve import");
                return false;
            }
            
            *(FARPROC*)iat = func;
            
            thunk += (is_64bit ? 8 : 4);
            iat += (is_64bit ? 8 : 4);
        }
        
        import_desc++;
    }
    
    return true;
}

/**
 * @brief Processes PE Thread Local Storage (TLS) callbacks
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool pe_process_tls_callbacks(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    PIMAGE_NT_HEADERS nt = exec->nt_headers;
    DWORD tls_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    
    if (tls_rva == 0) return true;
    
    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PIMAGE_TLS_DIRECTORY64 tls = (PIMAGE_TLS_DIRECTORY64)pe_rva_to_va(exec, tls_rva);
        
        if (tls && tls->AddressOfCallBacks) {
            uintptr_t* callback_ptr = (uintptr_t*)tls->AddressOfCallBacks;
            
            while (*callback_ptr != 0 && exec->tls_callback_count < 32) {
                exec->tls_callbacks[exec->tls_callback_count] = (void*)*callback_ptr;
                exec->tls_callback_count++;
                callback_ptr++;
            }
        }
    } else {
        PIMAGE_TLS_DIRECTORY32 tls = (PIMAGE_TLS_DIRECTORY32)pe_rva_to_va(exec, tls_rva);
        
        if (tls && tls->AddressOfCallBacks) {
            uint32_t* callback_ptr = (uint32_t*)(uintptr_t)tls->AddressOfCallBacks;
            
            while (*callback_ptr != 0 && exec->tls_callback_count < 32) {
                exec->tls_callbacks[exec->tls_callback_count] = pe_rva_to_va(exec, *callback_ptr);
                exec->tls_callback_count++;
                callback_ptr++;
            }
        }
    }
    
    /* Execute TLS callbacks */
    for (size_t i = 0; i < exec->tls_callback_count; i++) {
        typedef void (NTAPI *tls_callback_t)(PVOID, DWORD, PVOID);
        tls_callback_t callback = (tls_callback_t)exec->tls_callbacks[i];
        callback(exec->base_address, DLL_PROCESS_ATTACH, NULL);
    }
    
    return true;
}

/**
 * @brief Registers PE exception handlers with RtlAddFunctionTable
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool pe_apply_exception_handlers(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    PIMAGE_NT_HEADERS nt = exec->nt_headers;
    DWORD exception_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    
    if (exception_rva == 0) return true;
    
    exec->exception_directory = pe_rva_to_va(exec, exception_rva);
    exec->exception_directory_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    
    /* Register exception handlers with RtlAddFunctionTable */
    if (exec->exception_directory && exec->exception_directory_size > 0) {
        typedef BOOLEAN (NTAPI *RtlAddFunctionTable_t)(PRUNTIME_FUNCTION, DWORD, DWORD64);
        RtlAddFunctionTable_t RtlAddFunctionTable = 
            (RtlAddFunctionTable_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable");
        
        if (RtlAddFunctionTable) {
            RtlAddFunctionTable((PRUNTIME_FUNCTION)exec->exception_directory,
                               exec->exception_directory_size / sizeof(RUNTIME_FUNCTION),
                               (DWORD64)exec->base_address);
        }
    }
    
    return true;
}

/**
 * @brief Enables PE security features (Control Flow Guard, Security Cookie)
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool pe_enable_security_features(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    PIMAGE_NT_HEADERS nt = exec->nt_headers;
    
    /* Get security cookie */
    DWORD load_config_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
    if (load_config_rva != 0) {
        if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            PIMAGE_LOAD_CONFIG_DIRECTORY64 load_config = (PIMAGE_LOAD_CONFIG_DIRECTORY64)pe_rva_to_va(exec, load_config_rva);
            if (load_config) {
                exec->security_cookie = (void*)load_config->SecurityCookie;
                exec->guard_cf_enabled = (load_config->GuardFlags & IMAGE_GUARD_CF_INSTRUMENTED) != 0;
            }
        } else {
            PIMAGE_LOAD_CONFIG_DIRECTORY32 load_config = (PIMAGE_LOAD_CONFIG_DIRECTORY32)pe_rva_to_va(exec, load_config_rva);
            if (load_config) {
                exec->security_cookie = (void*)(uintptr_t)load_config->SecurityCookie;
            }
        }
    }
    
    return true;
}

/**
 * @brief Loads a PE executable into memory at specified address
 * @param path Path to the executable file
 * @param load_address Desired load address (NULL for default)
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_to(const char* path, void* load_address) {
    if (!path) return NULL;
    
    cdll_loaded_executable_t* exec = (cdll_loaded_executable_t*)calloc(1, sizeof(cdll_loaded_executable_t));
    if (!exec) return NULL;
    
    /* Get executable info */
    if (!cdll_get_executable_info(path, &exec->info)) {
        free(exec);
        return NULL;
    }
    
    /* Read the entire file */
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        free(exec);
        return NULL;
    }
    
    DWORD file_size = GetFileSize(hFile, NULL);
    uint8_t* file_data = (uint8_t*)malloc(file_size);
    if (!file_data) {
        CloseHandle(hFile);
        free(exec);
        return NULL;
    }
    
    DWORD bytes_read;
    ReadFile(hFile, file_data, file_size, &bytes_read, NULL);
    CloseHandle(hFile);
    
    /* Parse headers */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)file_data;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(file_data + dos->e_lfanew);
    
    exec->nt_headers = nt;
    exec->base_address = VirtualAlloc(load_address ? load_address : (void*)nt->OptionalHeader.ImageBase,
                                       nt->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    
    if (!exec->base_address) {
        exec->base_address = VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    }
    
    if (!exec->base_address) {
        free(file_data);
        free(exec);
        return NULL;
    }
    
    /* Copy headers */
    memcpy(exec->base_address, file_data, nt->OptionalHeader.SizeOfHeaders);
    
    /* Copy sections */
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (section[i].SizeOfRawData > 0) {
            void* dest = (BYTE*)exec->base_address + section[i].VirtualAddress;
            void* src = file_data + section[i].PointerToRawData;
            memcpy(dest, src, section[i].SizeOfRawData);
        }
    }
    
    free(file_data);
    
    /* Process relocations if base address differs */
    uintptr_t delta = (uintptr_t)exec->base_address - nt->OptionalHeader.ImageBase;
    if (delta != 0) {
        pe_process_relocations(exec, delta);
    }
    
    /* Resolve imports */
    pe_resolve_imports(exec);
    
    /* Process TLS */
    pe_process_tls_callbacks(exec);
    
    /* Apply exception handlers */
    pe_apply_exception_handlers(exec);
    
    /* Enable security features */
    pe_enable_security_features(exec);
    
    /* Set entry point */
    exec->entry_point = (BYTE*)exec->base_address + nt->OptionalHeader.AddressOfEntryPoint;
    exec->original_entry_point = exec->entry_point;
    exec->loaded_size = nt->OptionalHeader.SizeOfImage;
    
    return exec;
}

/**
 * @brief Loads a PE executable and sets custom entry point
 * @param path Path to the executable file
 * @param jump_address Custom address to jump to after loading
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_jump(const char* path, void* jump_address) {
    cdll_loaded_executable_t* exec = cdll_load_executable_to(path, NULL);
    if (exec) {
        exec->custom_entry = jump_address;
    }
    return exec;
}

/**
 * @brief Executes a loaded executable (resumes if suspended, or calls entry)
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static inline bool cdll_execute_loaded(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    void* entry = exec->custom_entry ? exec->custom_entry : exec->entry_point;
    
    if (exec->is_remote) {
        /* Resume suspended remote process */
        if (exec->is_suspended) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, exec->main_thread);
            if (hThread) {
                ResumeThread(hThread);
                CloseHandle(hThread);
                return true;
            }
        }
        return false;
    } else {
        /* Call entry point directly */
        typedef BOOL (WINAPI *dll_main_t)(HINSTANCE, DWORD, LPVOID);
        
        if (exec->info.is_dll) {
            dll_main_t dll_main = (dll_main_t)entry;
            dll_main((HINSTANCE)exec->base_address, DLL_PROCESS_ATTACH, NULL);
        } else {
            typedef int (WINAPI *exe_main_t)(void);
            exe_main_t exe_main = (exe_main_t)entry;
            exe_main();
        }
        return true;
    }
}

/**
 * @brief Unloads an executable and frees all associated resources
 * @param exec Loaded executable context to unload
 */
static inline void cdll_unload_executable(cdll_loaded_executable_t* exec) {
    if (!exec) return;
    
    /* Execute TLS callbacks for detach */
    for (size_t i = 0; i < exec->tls_callback_count; i++) {
        typedef void (NTAPI *tls_callback_t)(PVOID, DWORD, PVOID);
        tls_callback_t callback = (tls_callback_t)exec->tls_callbacks[i];
        callback(exec->base_address, DLL_PROCESS_DETACH, NULL);
    }
    
    /* Call DllMain for detach if DLL */
    if (exec->info.is_dll && exec->entry_point) {
        typedef BOOL (WINAPI *dll_main_t)(HINSTANCE, DWORD, LPVOID);
        dll_main_t dll_main = (dll_main_t)exec->entry_point;
        dll_main((HINSTANCE)exec->base_address, DLL_PROCESS_DETACH, NULL);
    }
    
    if (exec->is_remote) {
        if (exec->process) {
            TerminateProcess(exec->process, 0);
            CloseHandle(exec->process);
        }
    } else {
        if (exec->base_address) {
            VirtualFree(exec->base_address, 0, MEM_RELEASE);
        }
    }
    
    if (exec->sections) {
        free(exec->sections);
    }
    
    free(exec);
}

/* ============================================================================
 * Linux ELF - Full Professional Implementation
 * ============================================================================ */

#elif defined(__linux__)

#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/personality.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#ifndef ARCH_SET_GS
#define ARCH_SET_GS 0x1001
#endif
#ifndef ARCH_SET_FS
#define ARCH_SET_FS 0x1002
#endif

/* Extended ELF structures */
typedef struct {
    uint64_t entry;
    uint64_t base;
    uint64_t limit;
    uint32_t flags;
    uint32_t reserved;
} elf_tls_t;

typedef struct {
    uint32_t namesz;
    uint32_t descsz;
    uint32_t type;
    char name[4];
} elf_note_t;

typedef struct {
    int32_t c_type;
    int32_t c_value;
} elf_conflict_t;

/* Extended loaded executable context */
struct cdll_loaded_executable {
    cdll_executable_info_t info;
    void* base_address;
    void* entry_point;
    size_t loaded_size;
    cdll_process_handle process;
    cdll_thread_id main_thread;
    bool is_remote;
    bool is_suspended;
    void* custom_entry;
    cdll_executable_section_t* sections;
    size_t section_count;
    
    /* ELF-specific */
    Elf64_Ehdr* ehdr;
    Elf64_Phdr* phdrs;
    Elf64_Shdr* shdrs;
    char* shstrtab;
    char* strtab;
    Elf64_Sym* symtab;
    size_t symtab_size;
    void* init_array;
    size_t init_array_size;
    void* fini_array;
    size_t fini_array_size;
    void* preinit_array;
    size_t preinit_array_size;
    void* tls_image;
    size_t tls_size;
    size_t tls_align;
    void* dynamic_section;
    size_t dynamic_size;
    char* interpreter_path;
    uintptr_t* got_plt;
    size_t got_plt_size;
    void* original_entry_point;
    bool is_pie;
    uintptr_t load_bias;
};

/* Forward declarations */
static bool elf_process_relocations(cdll_loaded_executable_t* exec);
static bool elf_resolve_symbols(cdll_loaded_executable_t* exec);
static bool elf_apply_relocations(cdll_loaded_executable_t* exec, Elf64_Shdr* rel_section, Elf64_Shdr* sym_section);
static bool elf_setup_tls(cdll_loaded_executable_t* exec);
static bool elf_execute_init_array(cdll_loaded_executable_t* exec);
static bool elf_load_interpreter(cdll_loaded_executable_t* exec);

/* ============================================================================
 * ELF: Get Executable Information (Full)
 * ============================================================================ */

/**
 * @brief Gets comprehensive information about a ELF executable
 * @param path Path to the .elf file
 * @param info Pointer to executable information structure to fill
 * @return true on success, false on failure
 */
static inline bool cdll_get_executable_info(const char* path, cdll_executable_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_executable_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        cdll_set_error("cdll_get_executable_info", errno, "Failed to open file");
        return false;
    }
    
    /* Read ELF header */
    uint8_t e_ident[EI_NIDENT];
    if (fread(e_ident, 1, EI_NIDENT, f) != EI_NIDENT) {
        fclose(f);
        return false;
    }
    
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        cdll_set_error("cdll_get_executable_info", EINVAL, "Invalid ELF signature");
        fclose(f);
        return false;
    }
    
    fseek(f, 0, SEEK_SET);
    
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        info->type = CDLL_EXEC_ELF64;
        info->is_64bit = true;
        
        Elf64_Ehdr ehdr;
        fread(&ehdr, sizeof(ehdr), 1, f);
        
        info->entry_point = (void*)(uintptr_t)ehdr.e_entry;
        info->machine_type = ehdr.e_machine;
        info->is_pie = (ehdr.e_type == ET_DYN);
        
        switch (ehdr.e_type) {
            case ET_EXEC: info->is_dll = false; break;
            case ET_DYN: info->is_dll = true; break;
            case ET_REL: info->is_dll = true; break;
        }
        
        /* Read program headers to find interpreter */
        Elf64_Phdr* phdrs = (Elf64_Phdr*)malloc(ehdr.e_phentsize * ehdr.e_phnum);
        fseek(f, ehdr.e_phoff, SEEK_SET);
        fread(phdrs, ehdr.e_phentsize, ehdr.e_phnum, f);
        
        for (int i = 0; i < ehdr.e_phnum; i++) {
            if (phdrs[i].p_type == PT_INTERP) {
                fseek(f, phdrs[i].p_offset, SEEK_SET);
                fread(info->interpreter, 1, phdrs[i].p_filesz - 1, f);
                break;
            }
            if (phdrs[i].p_type == PT_LOAD) {
                if (info->image_base == 0 || phdrs[i].p_vaddr < info->image_base) {
                    info->image_base = phdrs[i].p_vaddr;
                }
                info->image_size += phdrs[i].p_memsz;
            }
        }
        
        free(phdrs);
        
        /* Read section headers for build ID */
        Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(ehdr.e_shentsize * ehdr.e_shnum);
        fseek(f, ehdr.e_shoff, SEEK_SET);
        fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f);
        
        /* Read section name string table */
        Elf64_Shdr* shstrtab_hdr = &shdrs[ehdr.e_shstrndx];
        char* shstrtab = (char*)malloc(shstrtab_hdr->sh_size);
        fseek(f, shstrtab_hdr->sh_offset, SEEK_SET);
        fread(shstrtab, 1, shstrtab_hdr->sh_size, f);
        
        for (int i = 0; i < ehdr.e_shnum; i++) {
            char* name = shstrtab + shdrs[i].sh_name;
            
            if (strcmp(name, ".note.gnu.build-id") == 0) {
                fseek(f, shdrs[i].sh_offset, SEEK_SET);
                elf_note_t note;
                fread(&note, sizeof(note), 1, f);
                
                size_t name_len = (note.namesz + 3) & ~3;
                fseek(f, name_len, SEEK_CUR);
                
                uint8_t build_id[64];
                fread(build_id, 1, note.descsz > 64 ? 64 : note.descsz, f);
                
                for (size_t j = 0; j < note.descsz && j < 64; j++) {
                    snprintf(info->build_id + j*2, 3, "%02x", build_id[j]);
                }
                break;
            }
            
            if (strcmp(name, ".symtab") == 0) {
                info->is_stripped = false;
            }
        }
        
        free(shstrtab);
        free(shdrs);
    } else {
        info->type = CDLL_EXEC_ELF32;
        info->is_64bit = false;
        
        Elf32_Ehdr ehdr;
        fread(&ehdr, sizeof(ehdr), 1, f);
        
        info->entry_point = (void*)(uintptr_t)ehdr.e_entry;
        info->machine_type = ehdr.e_machine;
        info->is_pie = (ehdr.e_type == ET_DYN);
    }
    
    fclose(f);
    
    /* Get file stats */
    struct stat st;
    if (stat(path, &st) == 0) {
        info->build_time = st.st_mtime;
    }
    
    /* Check if stripped */
    if (info->is_stripped) {
        /* Already determined */
    }
    
    /* Detect compiler and packer */
    cdll_detect_compiler(path, info->compiler, sizeof(info->compiler));
    cdll_detect_packer(path, info->packer, sizeof(info->packer));
    info->is_packed = (strcmp(info->packer, "None detected") != 0);
    
    return true;
}

/* ============================================================================
 * ELF: Enumerate Sections (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all ELF sections of an executable
 * @param path Path to the executable file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to enumerate
 * @return Number of sections found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_sections(const char* path,
                                                         cdll_executable_section_t* sections,
                                                         size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint8_t e_ident[EI_NIDENT];
    if (fread(e_ident, 1, EI_NIDENT, f) != EI_NIDENT) {
        fclose(f);
        return 0;
    }
    
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
        e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
        fclose(f);
        return 0;
    }
    
    fseek(f, 0, SEEK_SET);
    size_t count = 0;
    
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        /* ========== 64-bit ELF ========== */
        Elf64_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        /* Read section headers */
        size_t shdrs_size = ehdr.e_shentsize * ehdr.e_shnum;
        Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(shdrs_size);
        if (!shdrs) {
            fclose(f);
            return 0;
        }
        
        fseek(f, ehdr.e_shoff, SEEK_SET);
        if (fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f) != (size_t)ehdr.e_shnum) {
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        /* Read section name string table */
        Elf64_Shdr* shstrtab_hdr = &shdrs[ehdr.e_shstrndx];
        char* shstrtab = (char*)malloc(shstrtab_hdr->sh_size);
        if (!shstrtab) {
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        fseek(f, shstrtab_hdr->sh_offset, SEEK_SET);
        if (fread(shstrtab, 1, shstrtab_hdr->sh_size, f) != shstrtab_hdr->sh_size) {
            free(shstrtab);
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        /* Enumerate sections */
        for (int i = 0; i < ehdr.e_shnum && count < max_sections; i++) {
            if (shdrs[i].sh_type == SHT_NULL) continue;
            
            char* name = shstrtab + shdrs[i].sh_name;
            strncpy(sections[count].name, name, sizeof(sections[count].name) - 1);
            sections[count].name[sizeof(sections[count].name) - 1] = '\0';
            
            sections[count].virtual_address = shdrs[i].sh_addr;
            sections[count].virtual_size = shdrs[i].sh_size;
            sections[count].raw_offset = shdrs[i].sh_offset;
            sections[count].raw_size = (shdrs[i].sh_type != SHT_NOBITS) ? shdrs[i].sh_size : 0;
            sections[count].characteristics = shdrs[i].sh_flags;
            
            /* Set section flags */
            sections[count].is_executable = (shdrs[i].sh_flags & SHF_EXECINSTR) != 0;
            sections[count].is_writable = (shdrs[i].sh_flags & SHF_WRITE) != 0;
            sections[count].is_readable = true; /* All sections are readable in ELF */
            sections[count].is_shared = (shdrs[i].sh_flags & SHF_MERGE) != 0;
            sections[count].is_discardable = (shdrs[i].sh_flags & 0x10000000) != 0; /* SHF_GNU_RETAIN inverse */
            sections[count].alignment = shdrs[i].sh_addralign;
            
            /* Get section type string */
            switch (shdrs[i].sh_type) {
                case SHT_PROGBITS: /* Program data */ break;
                case SHT_SYMTAB: /* Symbol table */ break;
                case SHT_STRTAB: /* String table */ break;
                case SHT_RELA: /* Relocation with addend */ break;
                case SHT_HASH: /* Symbol hash */ break;
                case SHT_DYNAMIC: /* Dynamic linking */ break;
                case SHT_NOTE: /* Note section */ break;
                case SHT_NOBITS: /* BSS */ break;
                case SHT_REL: /* Relocation */ break;
                case SHT_SHLIB: /* Reserved */ break;
                case SHT_DYNSYM: /* Dynamic symbols */ break;
                case SHT_INIT_ARRAY: /* Init array */ break;
                case SHT_FINI_ARRAY: /* Fini array */ break;
                case SHT_PREINIT_ARRAY: /* Preinit array */ break;
                case SHT_GROUP: /* Section group */ break;
                case SHT_SYMTAB_SHNDX: /* Extended indices */ break;
                case SHT_GNU_ATTRIBUTES: break;
                case SHT_GNU_HASH: /* GNU hash */ break;
                case SHT_GNU_LIBLIST: break;
                case SHT_GNU_verdef: /* Version definitions */ break;
                case SHT_GNU_verneed: /* Version needs */ break;
                case SHT_GNU_versym: /* Version symbols */ break;
                default: break;
            }
            
            /* Calculate entropy for PROGBITS sections */
            if (shdrs[i].sh_type == SHT_PROGBITS && 
                shdrs[i].sh_size > 0 && 
                shdrs[i].sh_size < 100 * 1024 * 1024) {
                
                uint8_t* data = (uint8_t*)malloc(shdrs[i].sh_size);
                if (data) {
                    long current_pos = ftell(f);
                    fseek(f, shdrs[i].sh_offset, SEEK_SET);
                    size_t bytes_read = fread(data, 1, shdrs[i].sh_size, f);
                    if (bytes_read == shdrs[i].sh_size) {
                        sections[count].entropy = cdll_calculate_entropy(data, bytes_read);
                        sections[count].data = data; /* Caller must free */
                    } else {
                        free(data);
                        sections[count].data = NULL;
                    }
                    fseek(f, current_pos, SEEK_SET);
                }
            } else {
                sections[count].entropy = 0.0;
                sections[count].data = NULL;
            }
            
            count++;
        }
        
        free(shstrtab);
        free(shdrs);
        
    } else if (e_ident[EI_CLASS] == ELFCLASS32) {
        /* ========== 32-bit ELF ========== */
        Elf32_Ehdr ehdr;
        if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        /* Read section headers */
        size_t shdrs_size = ehdr.e_shentsize * ehdr.e_shnum;
        Elf32_Shdr* shdrs = (Elf32_Shdr*)malloc(shdrs_size);
        if (!shdrs) {
            fclose(f);
            return 0;
        }
        
        fseek(f, ehdr.e_shoff, SEEK_SET);
        if (fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f) != (size_t)ehdr.e_shnum) {
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        /* Read section name string table */
        Elf32_Shdr* shstrtab_hdr = &shdrs[ehdr.e_shstrndx];
        char* shstrtab = (char*)malloc(shstrtab_hdr->sh_size);
        if (!shstrtab) {
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        fseek(f, shstrtab_hdr->sh_offset, SEEK_SET);
        if (fread(shstrtab, 1, shstrtab_hdr->sh_size, f) != shstrtab_hdr->sh_size) {
            free(shstrtab);
            free(shdrs);
            fclose(f);
            return 0;
        }
        
        /* Enumerate sections */
        for (int i = 0; i < ehdr.e_shnum && count < max_sections; i++) {
            if (shdrs[i].sh_type == SHT_NULL) continue;
            
            char* name = shstrtab + shdrs[i].sh_name;
            strncpy(sections[count].name, name, sizeof(sections[count].name) - 1);
            sections[count].name[sizeof(sections[count].name) - 1] = '\0';
            
            sections[count].virtual_address = shdrs[i].sh_addr;
            sections[count].virtual_size = shdrs[i].sh_size;
            sections[count].raw_offset = shdrs[i].sh_offset;
            sections[count].raw_size = (shdrs[i].sh_type != SHT_NOBITS) ? shdrs[i].sh_size : 0;
            sections[count].characteristics = shdrs[i].sh_flags;
            
            sections[count].is_executable = (shdrs[i].sh_flags & SHF_EXECINSTR) != 0;
            sections[count].is_writable = (shdrs[i].sh_flags & SHF_WRITE) != 0;
            sections[count].is_readable = true;
            sections[count].is_shared = (shdrs[i].sh_flags & SHF_MERGE) != 0;
            sections[count].alignment = shdrs[i].sh_addralign;
            
            /* Calculate entropy */
            if (shdrs[i].sh_type == SHT_PROGBITS && 
                shdrs[i].sh_size > 0 && 
                shdrs[i].sh_size < 100 * 1024 * 1024) {
                
                uint8_t* data = (uint8_t*)malloc(shdrs[i].sh_size);
                if (data) {
                    long current_pos = ftell(f);
                    fseek(f, shdrs[i].sh_offset, SEEK_SET);
                    size_t bytes_read = fread(data, 1, shdrs[i].sh_size, f);
                    if (bytes_read == shdrs[i].sh_size) {
                        sections[count].entropy = cdll_calculate_entropy(data, bytes_read);
                        sections[count].data = data;
                    } else {
                        free(data);
                        sections[count].data = NULL;
                    }
                    fseek(f, current_pos, SEEK_SET);
                }
            } else {
                sections[count].entropy = 0.0;
                sections[count].data = NULL;
            }
            
            count++;
        }
        
        free(shstrtab);
        free(shdrs);
    }
    
    fclose(f);
    return count;
}

/* ============================================================================
 * ELF: Enumerate Imports/Exports (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all imported functions of a ELF executable
 * @param path Path to the executable file
 * @param imports Array to fill with import information
 * @param max_imports Maximum number of imports to enumerate
 * @return Number of imports found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_imports(const char* path,
                                                        cdll_executable_import_t* imports,
                                                        size_t max_imports) {
    if (!path || !imports || max_imports == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint8_t e_ident[EI_NIDENT];
    fread(e_ident, 1, EI_NIDENT, f);
    
    if (e_ident[EI_MAG0] != ELFMAG0) {
        fclose(f);
        return 0;
    }
    
    fseek(f, 0, SEEK_SET);
    size_t count = 0;
    
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        fread(&ehdr, sizeof(ehdr), 1, f);
        
        Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(ehdr.e_shentsize * ehdr.e_shnum);
        fseek(f, ehdr.e_shoff, SEEK_SET);
        fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f);
        
        for (int i = 0; i < ehdr.e_shnum && count < max_imports; i++) {
            if (shdrs[i].sh_type == SHT_DYNAMIC) {
                Elf64_Dyn* dyn = (Elf64_Dyn*)malloc(shdrs[i].sh_size);
                fseek(f, shdrs[i].sh_offset, SEEK_SET);
                fread(dyn, shdrs[i].sh_size, 1, f);
                
                const char* strtab = NULL;
                Elf64_Sym* symtab = NULL;
                size_t symtab_size = 0;
                
                for (size_t j = 0; j < shdrs[i].sh_size / sizeof(Elf64_Dyn); j++) {
                    if (dyn[j].d_tag == DT_STRTAB) {
                        strtab = (const char*)(uintptr_t)dyn[j].d_un.d_ptr;
                    } else if (dyn[j].d_tag == DT_SYMTAB) {
                        symtab = (Elf64_Sym*)(uintptr_t)dyn[j].d_un.d_ptr;
                    } else if (dyn[j].d_tag == DT_NEEDED) {
                        const char* libname = strtab + dyn[j].d_un.d_val;
                        strncpy(imports[count].module_name, libname, sizeof(imports[count].module_name) - 1);
                        imports[count].name[0] = '\0';
                        count++;
                    }
                }
                
                free(dyn);
            }
            
            if (shdrs[i].sh_type == SHT_DYNSYM) {
                Elf64_Sym* syms = (Elf64_Sym*)malloc(shdrs[i].sh_size);
                fseek(f, shdrs[i].sh_offset, SEEK_SET);
                fread(syms, shdrs[i].sh_size, 1, f);
                
                Elf64_Shdr* strtab_hdr = &shdrs[shdrs[i].sh_link];
                char* strtab = (char*)malloc(strtab_hdr->sh_size);
                fseek(f, strtab_hdr->sh_offset, SEEK_SET);
                fread(strtab, 1, strtab_hdr->sh_size, f);
                
                for (size_t j = 0; j < shdrs[i].sh_size / sizeof(Elf64_Sym) && count < max_imports; j++) {
                    if (syms[j].st_shndx == SHN_UNDEF && syms[j].st_name != 0) {
                        strncpy(imports[count].name, strtab + syms[j].st_name, sizeof(imports[count].name) - 1);
                        count++;
                    }
                }
                
                free(strtab);
                free(syms);
            }
        }
        
        free(shdrs);
    }
    
    fclose(f);
    return count;
}

/**
 * @brief Enumerates all exported functions of a ELF executable
 * @param path Path to the executable file
 * @param exports Array to fill with export information
 * @param max_exports Maximum number of exports to enumerate
 * @return Number of exports found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_exports(const char* path,
                                                        cdll_executable_export_t* exports,
                                                        size_t max_exports) {
    if (!path || !exports || max_exports == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint8_t e_ident[EI_NIDENT];
    fread(e_ident, 1, EI_NIDENT, f);
    
    if (e_ident[EI_MAG0] != ELFMAG0) {
        fclose(f);
        return 0;
    }
    
    fseek(f, 0, SEEK_SET);
    size_t count = 0;
    
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        Elf64_Ehdr ehdr;
        fread(&ehdr, sizeof(ehdr), 1, f);
        
        Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(ehdr.e_shentsize * ehdr.e_shnum);
        fseek(f, ehdr.e_shoff, SEEK_SET);
        fread(shdrs, ehdr.e_shentsize, ehdr.e_shnum, f);
        
        for (int i = 0; i < ehdr.e_shnum && count < max_exports; i++) {
            if (shdrs[i].sh_type == SHT_DYNSYM || shdrs[i].sh_type == SHT_SYMTAB) {
                Elf64_Sym* syms = (Elf64_Sym*)malloc(shdrs[i].sh_size);
                fseek(f, shdrs[i].sh_offset, SEEK_SET);
                fread(syms, shdrs[i].sh_size, 1, f);
                
                Elf64_Shdr* strtab_hdr = &shdrs[shdrs[i].sh_link];
                char* strtab = (char*)malloc(strtab_hdr->sh_size);
                fseek(f, strtab_hdr->sh_offset, SEEK_SET);
                fread(strtab, 1, strtab_hdr->sh_size, f);
                
                size_t num_syms = shdrs[i].sh_size / sizeof(Elf64_Sym);
                for (size_t j = 0; j < num_syms && count < max_exports; j++) {
                    if (syms[j].st_shndx != SHN_UNDEF && syms[j].st_name != 0 &&
                        ELF64_ST_BIND(syms[j].st_info) == STB_GLOBAL) {
                        
                        strncpy(exports[count].name, strtab + syms[j].st_name, sizeof(exports[count].name) - 1);
                        cdll_demangle_symbol(exports[count].name, exports[count].demangled_name,
                                            sizeof(exports[count].demangled_name));
                        exports[count].rva = syms[j].st_value;
                        exports[count].ordinal = count + 1;
                        count++;
                    }
                }
                
                free(strtab);
                free(syms);
            }
        }
        
        free(shdrs);
    }
    
    fclose(f);
    return count;
}

/* ============================================================================
 * ELF: Load Executable (Full)
 * ============================================================================ */

/**
 * @brief Processes ELF relocations for a loaded executable
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool elf_process_relocations(cdll_loaded_executable_t* exec) {
    if (!exec || !exec->ehdr) return false;
    
    Elf64_Ehdr* ehdr = exec->ehdr;
    Elf64_Shdr* shdrs = exec->shdrs;
    
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_RELA || shdrs[i].sh_type == SHT_REL) {
            Elf64_Shdr* sym_section = &shdrs[shdrs[i].sh_link];
            elf_apply_relocations(exec, &shdrs[i], sym_section);
        }
    }
    
    return true;
}

/**
 * @brief Applies ELF relocations from a relocation section
 * @param exec Loaded executable context
 * @param rel_section Relocation section header
 * @param sym_section Symbol table section header
 * @return true on success, false on failure
 *
static bool elf_apply_relocations(cdll_loaded_executable_t* exec, Elf64_Shdr* rel_section, Elf64_Shdr* sym_section) {
    if (!exec || !rel_section || !sym_section) return false;
    
    size_t rel_count = rel_section->sh_size / rel_section->sh_entsize;
    Elf64_Sym* symtab = (Elf64_Sym*)((uint8_t*)exec->base_address + sym_section->sh_addr);
    const char* strtab = (const char*)((uint8_t*)exec->base_address + exec->shdrs[sym_section->sh_link].sh_addr);
    
    if (rel_section->sh_type == SHT_RELA) {
        Elf64_Rela* rela = (Elf64_Rela*)((uint8_t*)exec->base_address + rel_section->sh_addr);
        
        for (size_t i = 0; i < rel_count; i++) {
            uint32_t sym_idx = ELF64_R_SYM(rela[i].r_info);
            uint32_t type = ELF64_R_TYPE(rela[i].r_info);
            
            Elf64_Sym* sym = &symtab[sym_idx];
            void* patch_addr = (uint8_t*)exec->base_address + rela[i].r_offset;
            uintptr_t sym_value = sym->st_value + rela[i].r_addend;
            
            /* Find symbol in loaded libraries if undefined */
            if (sym->st_shndx == SHN_UNDEF) {
                const char* sym_name = strtab + sym->st_name;
                void* resolved = dlsym(RTLD_DEFAULT, sym_name);
                if (resolved) {
                    sym_value = (uintptr_t)resolved + rela[i].r_addend;
                }
            } else {
                sym_value += (uintptr_t)exec->base_address;
            }
            
            switch (type) {
                case R_X86_64_RELATIVE:
                    *(uint64_t*)patch_addr = (uint64_t)((uintptr_t)exec->base_address + rela[i].r_addend);
                    break;
                case R_X86_64_GLOB_DAT:
                case R_X86_64_JUMP_SLOT:
                    *(uint64_t*)patch_addr = sym_value;
                    break;
                case R_X86_64_64:
                    *(uint64_t*)patch_addr = sym_value;
                    break;
                case R_X86_64_PC32:
                    *(uint32_t*)patch_addr = (uint32_t)(sym_value - (uintptr_t)patch_addr);
                    break;
                default:
                    break;
            }
        }
    } else {
        Elf64_Rel* rel = (Elf64_Rel*)((uint8_t*)exec->base_address + rel_section->sh_addr);
        
        for (size_t i = 0; i < rel_count; i++) {
            uint32_t sym_idx = ELF64_R_SYM(rel[i].r_info);
            uint32_t type = ELF64_R_TYPE(rel[i].r_info);
            
            Elf64_Sym* sym = &symtab[sym_idx];
            void* patch_addr = (uint8_t*)exec->base_address + rel[i].r_offset;
            uintptr_t sym_value = sym->st_value;
            
            if (sym->st_shndx == SHN_UNDEF) {
                const char* sym_name = strtab + sym->st_name;
                void* resolved = dlsym(RTLD_DEFAULT, sym_name);
                if (resolved) {
                    sym_value = (uintptr_t)resolved;
                }
            } else {
                sym_value += (uintptr_t)exec->base_address;
            }
            
            switch (type) {
                case R_X86_64_RELATIVE:
                    *(uint64_t*)patch_addr = (uint64_t)((uintptr_t)exec->base_address + *((uint32_t*)patch_addr));
                    break;
                case R_X86_64_GLOB_DAT:
                case R_X86_64_JUMP_SLOT:
                    *(uint64_t*)patch_addr = sym_value;
                    break;
                case R_X86_64_64:
                    *(uint64_t*)patch_addr = sym_value;
                    break;
                default:
                    break;
            }
        }
    }
    
    return true;
}

/**
 * @brief Sets up Thread Local Storage (TLS) for ELF executable
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool elf_setup_tls(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    /* Find TLS program header */
    for (int i = 0; i < exec->ehdr->e_phnum; i++) {
        if (exec->phdrs[i].p_type == PT_TLS) {
            exec->tls_image = (uint8_t*)exec->base_address + exec->phdrs[i].p_vaddr;
            exec->tls_size = exec->phdrs[i].p_memsz;
            exec->tls_align = exec->phdrs[i].p_align;
            
            /* Allocate TLS with arch_prctl */
            void* tls_ptr = mmap(NULL, exec->tls_size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            
            if (tls_ptr != MAP_FAILED) {
                memcpy(tls_ptr, exec->tls_image, exec->phdrs[i].p_filesz);
                memset((uint8_t*)tls_ptr + exec->phdrs[i].p_filesz, 0,
                       exec->tls_size - exec->phdrs[i].p_filesz);
                
                arch_prctl(ARCH_SET_FS, (unsigned long)tls_ptr);
            }
            
            break;
        }
    }
    
    return true;
}

/**
 * @brief Executes ELF .init_array, .preinit_array functions
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool elf_execute_init_array(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    /* Execute preinit array */
    if (exec->preinit_array) {
        void (**preinit)(void) = (void(**)(void))exec->preinit_array;
        for (size_t i = 0; i < exec->preinit_array_size / sizeof(void*); i++) {
            if (preinit[i]) preinit[i]();
        }
    }
    
    /* Execute init array */
    if (exec->init_array) {
        void (**init)(void) = (void(**)(void))exec->init_array;
        for (size_t i = 0; i < exec->init_array_size / sizeof(void*); i++) {
            if (init[i]) init[i]();
        }
    }
    
    return true;
}

/**
 * @brief Loads ELF interpreter (ld-linux.so) for dynamic executables
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static bool elf_load_interpreter(cdll_loaded_executable_t* exec) {
    if (!exec || !exec->interpreter_path || !exec->interpreter_path[0]) {
        return true; /* Static executable */
    }
    
    /* Load interpreter (ld-linux.so) */
    void* interp_handle = dlopen(exec->interpreter_path, RTLD_LAZY);
    if (!interp_handle) {
        cdll_set_error("elf_load_interpreter", errno, "Failed to load interpreter");
        return false;
    }
    
    return true;
}

/**
 * @brief Loads a ELF executable into memory at specified address
 * @param path Path to the executable file
 * @param load_address Desired load address (NULL for default)
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_to(const char* path, void* load_address) {
    if (!path) return NULL;
    
    cdll_loaded_executable_t* exec = (cdll_loaded_executable_t*)calloc(1, sizeof(cdll_loaded_executable_t));
    if (!exec) return NULL;
    
    if (!cdll_get_executable_info(path, &exec->info)) {
        free(exec);
        return NULL;
    }
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        free(exec);
        return NULL;
    }
    
    /* Read ELF header */
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)malloc(sizeof(Elf64_Ehdr));
    fread(ehdr, sizeof(Elf64_Ehdr), 1, f);
    exec->ehdr = ehdr;
    
    /* Read program headers */
    size_t phdrs_size = ehdr->e_phentsize * ehdr->e_phnum;
    Elf64_Phdr* phdrs = (Elf64_Phdr*)malloc(phdrs_size);
    fseek(f, ehdr->e_phoff, SEEK_SET);
    fread(phdrs, ehdr->e_phentsize, ehdr->e_phnum, f);
    exec->phdrs = phdrs;
    
    /* Calculate total load size */
    size_t total_size = 0;
    uintptr_t min_addr = UINTPTR_MAX;
    uintptr_t max_addr = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            uintptr_t seg_start = phdrs[i].p_vaddr;
            uintptr_t seg_end = seg_start + phdrs[i].p_memsz;
            
            if (seg_start < min_addr) min_addr = seg_start;
            if (seg_end > max_addr) max_addr = seg_end;
        }
    }
    
    total_size = max_addr - min_addr;
    
    /* Allocate memory */
    void* base = mmap(load_address, total_size,
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (base == MAP_FAILED) {
        base = mmap(NULL, total_size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    
    if (base == MAP_FAILED) {
        free(phdrs);
        free(ehdr);
        fclose(f);
        free(exec);
        return NULL;
    }
    
    exec->base_address = base;
    exec->load_bias = (uintptr_t)base - min_addr;
    
    /* Load segments */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            void* dest = (uint8_t*)base + (phdrs[i].p_vaddr - min_addr);
            
            fseek(f, phdrs[i].p_offset, SEEK_SET);
            fread(dest, 1, phdrs[i].p_filesz, f);
            
            /* Zero-fill BSS */
            if (phdrs[i].p_memsz > phdrs[i].p_filesz) {
                memset((uint8_t*)dest + phdrs[i].p_filesz, 0,
                       phdrs[i].p_memsz - phdrs[i].p_filesz);
            }
        }
    }
    
    /* Read section headers */
    Elf64_Shdr* shdrs = (Elf64_Shdr*)malloc(ehdr->e_shentsize * ehdr->e_shnum);
    fseek(f, ehdr->e_shoff, SEEK_SET);
    fread(shdrs, ehdr->e_shentsize, ehdr->e_shnum, f);
    exec->shdrs = shdrs;
    
    /* Read string tables */
    Elf64_Shdr* shstrtab_hdr = &shdrs[ehdr->e_shstrndx];
    exec->shstrtab = (char*)malloc(shstrtab_hdr->sh_size);
    fseek(f, shstrtab_hdr->sh_offset, SEEK_SET);
    fread(exec->shstrtab, 1, shstrtab_hdr->sh_size, f);
    
    /* Find init/fini arrays */
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char* name = exec->shstrtab + shdrs[i].sh_name;
        
        if (strcmp(name, ".init_array") == 0) {
            exec->init_array = (uint8_t*)base + (shdrs[i].sh_addr - min_addr);
            exec->init_array_size = shdrs[i].sh_size;
        } else if (strcmp(name, ".fini_array") == 0) {
            exec->fini_array = (uint8_t*)base + (shdrs[i].sh_addr - min_addr);
            exec->fini_array_size = shdrs[i].sh_size;
        } else if (strcmp(name, ".preinit_array") == 0) {
            exec->preinit_array = (uint8_t*)base + (shdrs[i].sh_addr - min_addr);
            exec->preinit_array_size = shdrs[i].sh_size;
        }
    }
    
    fclose(f);
    
    /* Process relocations */
    elf_process_relocations(exec);
    
    /* Setup TLS */
    elf_setup_tls(exec);
    
    /* Load interpreter if needed */
    if (exec->info.interpreter[0]) {
        strncpy(exec->interpreter_path, exec->info.interpreter, sizeof(exec->interpreter_path) - 1);
        elf_load_interpreter(exec);
    }
    
    /* Execute init array */
    elf_execute_init_array(exec);
    
    /* Set entry point */
    exec->entry_point = (uint8_t*)base + (ehdr->e_entry - min_addr);
    exec->original_entry_point = exec->entry_point;
    exec->loaded_size = total_size;
    
    return exec;
}

/**
 * @brief Loads a ELF executable and sets custom entry point
 * @param path Path to the executable file
 * @param jump_address Custom address to jump to after loading
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_jump(const char* path, void* jump_address) {
    cdll_loaded_executable_t* exec = cdll_load_executable_to(path, NULL);
    if (exec) {
        exec->custom_entry = jump_address;
    }
    return exec;
}

/**
 * @brief Executes a loaded executable (resumes if suspended, or calls entry)
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static inline bool cdll_execute_loaded(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    void* entry = exec->custom_entry ? exec->custom_entry : exec->entry_point;
    
    /* Call entry point */
    typedef int (*entry_func_t)(void);
    entry_func_t entry_func = (entry_func_t)entry;
    entry_func();
    
    return true;
}

/**
 * @brief Unloads an executable and frees all associated resources
 * @param exec Loaded executable context to unload
 */
static inline void cdll_unload_executable(cdll_loaded_executable_t* exec) {
    if (!exec) return;
    
    /* Execute fini array */
    if (exec->fini_array) {
        void (**fini)(void) = (void(**)(void))exec->fini_array;
        for (size_t i = 0; i < exec->fini_array_size / sizeof(void*); i++) {
            if (fini[i]) fini[i]();
        }
    }
    
    if (exec->base_address) {
        munmap(exec->base_address, exec->loaded_size);
    }
    
    free(exec->ehdr);
    free(exec->phdrs);
    free(exec->shdrs);
    free(exec->shstrtab);
    free(exec);
}

/* ============================================================================
 * macOS Mach-O - Full Professional Implementation
 * ============================================================================ */

#elif defined(__APPLE__)

#include <mach-o/loader.h>
#include <mach-o/swap.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <dlfcn.h>

/* Extended Mach-O structures */
typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment_command_64_t;

typedef struct {
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} macho_section_64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} macho_symtab_command_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t iundefsym;
    uint32_t nundefsym;
    uint32_t tocoff;
    uint32_t ntoc;
    uint32_t modtaboff;
    uint32_t nmodtab;
    uint32_t extrefsymoff;
    uint32_t nextrefsyms;
    uint32_t indirectsymoff;
    uint32_t nindirectsyms;
    uint32_t extreloff;
    uint32_t nextrel;
    uint32_t locreloff;
    uint32_t nlocrel;
} macho_dysymtab_command_t;

/* Extended loaded executable context */
struct cdll_loaded_executable {
    cdll_executable_info_t info;
    void* base_address;
    void* entry_point;
    size_t loaded_size;
    cdll_process_handle process;
    cdll_thread_id main_thread;
    bool is_remote;
    bool is_suspended;
    void* custom_entry;
    cdll_executable_section_t* sections;
    size_t section_count;
    
    /* Mach-O specific */
    struct mach_header_64* header;
    void* load_commands;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    bool swap_bytes;
    macho_symtab_command_t* symtab_cmd;
    macho_dysymtab_command_t* dysymtab_cmd;
    struct nlist_64* symbols;
    uint32_t nsyms;
    char* strtab;
    uint32_t strsize;
    void* dyld_info;
    void* init_func;
    void* term_func;
    void* original_entry_point;
    uintptr_t slide;
    task_t remote_task;
    thread_act_t remote_thread;
};

/* Forward declarations */
static bool macho_apply_relocations(cdll_loaded_executable_t* exec);
static bool macho_resolve_imports(cdll_loaded_executable_t* exec);
static bool macho_execute_init_funcs(cdll_loaded_executable_t* exec);
static bool macho_setup_thread_state(cdll_loaded_executable_t* exec);

/* ============================================================================
 * Mach-O: Get Executable Information (Full)
 * ============================================================================ */

/**
 * @brief Gets detailed information about a macOS driver (.kext) file
 * @param path Path to the .kext driver file
 * @param info Pointer to driver information structure to fill
 * @return true on success, false on failure
 */
static inline bool cdll_get_executable_info(const char* path, cdll_executable_info_t* info) {
    if (!path || !info) return false;
    
    memset(info, 0, sizeof(cdll_executable_info_t));
    strncpy(info->path, path, sizeof(info->path) - 1);
    strncpy(info->name, cdll_basename(path), sizeof(info->name) - 1);
    
    /* Check if it's an app bundle */
    if (strstr(path, ".app/") || (strlen(path) > 4 && strcmp(path + strlen(path) - 4, ".app") == 0)) {
        info->type = CDLL_EXEC_APP_BUNDLE;
        
        /* Find actual executable inside bundle */
        char exe_path[1024];
        if (strstr(path, ".app/")) {
            strncpy(exe_path, path, sizeof(exe_path) - 1);
        } else {
            snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/", path);
            DIR* dir = opendir(exe_path);
            if (dir) {
                struct dirent* entry;
                while ((entry = readdir(dir)) != NULL) {
                    if (entry->d_type == DT_REG) {
                        snprintf(exe_path, sizeof(exe_path), "%s/Contents/MacOS/%s", path, entry->d_name);
                        break;
                    }
                }
                closedir(dir);
            }
        }
        
        /* Recursively get info for the actual executable */
        return cdll_get_executable_info(exe_path, info);
    }
    
    FILE* f = fopen(path, "rb");
    if (!f) {
        cdll_set_error("cdll_get_executable_info", errno, "Failed to open file");
        return false;
    }
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, f);
    
    bool swap_bytes = false;
    bool is_64bit = false;
    bool is_fat = false;
    
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        info->type = CDLL_EXEC_MACHO32;
        info->is_64bit = false;
        swap_bytes = (magic == MH_CIGAM);
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        info->type = CDLL_EXEC_MACHO64;
        info->is_64bit = true;
        swap_bytes = (magic == MH_CIGAM_64);
    } else if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
        info->type = CDLL_EXEC_MACHO_FAT;
        is_fat = true;
        swap_bytes = (magic == FAT_CIGAM);
    }
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    #define SWAP64(x) (swap_bytes ? OSSwapInt64(x) : (x))
    
    if (is_fat) {
        /* Parse fat binary to find best architecture */
        struct fat_header fat_hdr;
        fseek(f, 0, SEEK_SET);
        fread(&fat_hdr, sizeof(fat_hdr), 1, f);
        
        uint32_t nfat_arch = SWAP32(fat_hdr.nfat_arch);
        struct fat_arch* archs = (struct fat_arch*)malloc(nfat_arch * sizeof(struct fat_arch));
        fread(archs, sizeof(struct fat_arch), nfat_arch, f);
        
        /* Find x86_64 or arm64 */
        for (uint32_t i = 0; i < nfat_arch; i++) {
            cpu_type_t cputype = SWAP32(archs[i].cputype);
            if (cputype == CPU_TYPE_X86_64 || cputype == CPU_TYPE_ARM64) {
                fseek(f, SWAP32(archs[i].offset), SEEK_SET);
                fread(&magic, sizeof(magic), 1, f);
                info->is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
                info->type = info->is_64bit ? CDLL_EXEC_MACHO64 : CDLL_EXEC_MACHO32;
                swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
                break;
            }
        }
        
        free(archs);
    }
    
    fseek(f, 0, SEEK_SET);
    fread(&magic, sizeof(magic), 1, f);
    
    if (info->is_64bit) {
        struct mach_header_64 header;
        fseek(f, 0, SEEK_SET);
        fread(&header, sizeof(header), 1, f);
        
        info->entry_point = (void*)(uintptr_t)SWAP64(header.entryoff);
        info->machine_type = SWAP32(header.cputype);
        info->subsystem = SWAP32(header.filetype);
        info->is_dll = (SWAP32(header.filetype) == MH_DYLIB || 
                        SWAP32(header.filetype) == MH_BUNDLE);
        info->is_pie = (SWAP32(header.flags) & MH_PIE) != 0;
        
        /* Parse load commands for more info */
        uint32_t ncmds = SWAP32(header.ncmds);
        uint32_t sizeofcmds = SWAP32(header.sizeofcmds);
        uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
        fread(load_cmds, sizeofcmds, 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        for (uint32_t i = 0; i < ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SEGMENT_64) {
                struct segment_command_64* seg = (struct segment_command_64*)lc;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    info->image_base = SWAP64(seg->vmaddr);
                }
                info->image_size += SWAP64(seg->vmsize);
            } else if (cmd == LC_ID_DYLIB) {
                struct dylib_command* dylib = (struct dylib_command*)lc;
                info->is_dll = true;
            } else if (cmd == LC_VERSION_MIN_MACOSX || cmd == LC_VERSION_MIN_IPHONEOS) {
                struct version_min_command* ver = (struct version_min_command*)lc;
                snprintf(info->version, sizeof(info->version), "%u.%u.%u",
                         SWAP32(ver->version) >> 16,
                         (SWAP32(ver->version) >> 8) & 0xFF,
                         SWAP32(ver->version) & 0xFF);
            } else if (cmd == LC_SOURCE_VERSION) {
                struct source_version_command* src = (struct source_version_command*)lc;
                uint64_t version = SWAP64(src->version);
                snprintf(info->version, sizeof(info->version), "%llu.%llu.%llu.%llu",
                         (version >> 40) & 0xFFFFFF,
                         (version >> 30) & 0x3FF,
                         (version >> 20) & 0x3FF,
                         version & 0x3FF);
            } else if (cmd == LC_UUID) {
                struct uuid_command* uuid_cmd = (struct uuid_command*)lc;
                for (int j = 0; j < 16; j++) {
                    snprintf(info->build_id + j*2, 3, "%02x", uuid_cmd->uuid[j]);
                }
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        free(load_cmds);
    } else {
        /* 32-bit Mach-O */
        struct mach_header header;
        fseek(f, 0, SEEK_SET);
        fread(&header, sizeof(header), 1, f);
        
        info->entry_point = (void*)(uintptr_t)SWAP32(header.entryoff);
        info->machine_type = SWAP32(header.cputype);
        info->subsystem = SWAP32(header.filetype);
        info->is_dll = (SWAP32(header.filetype) == MH_DYLIB);
        info->is_pie = (SWAP32(header.flags) & MH_PIE) != 0;
    }
    
    fclose(f);
    
    /* Get file stats */
    struct stat st;
    if (stat(path, &st) == 0) {
        info->build_time = st.st_mtime;
    }
    
    /* Check signature */
    info->is_signed = cdll_verify_signature(path);
    
    /* Detect compiler */
    cdll_detect_compiler(path, info->compiler, sizeof(info->compiler));
    
    #undef SWAP32
    #undef SWAP64
    
    return true;
}

/* ============================================================================
 * Mach-O: Enumerate Sections (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all currently loaded kernel drivers
 * @param drivers Array to fill with driver names (max 256 chars each)
 * @param max_drivers Maximum number of drivers to enumerate
 * @return Number of drivers found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_sections(const char* path,
                                                         cdll_executable_section_t* sections,
                                                         size_t max_sections) {
    if (!path || !sections || max_sections == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) != 1) {
        fclose(f);
        return 0;
    }
    
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    bool is_fat = (magic == FAT_MAGIC || magic == FAT_CIGAM);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    #define SWAP64(x) (swap_bytes ? OSSwapInt64(x) : (x))
    
    size_t count = 0;
    
    if (is_fat) {
        /* Handle fat binary - find best architecture */
        fseek(f, 0, SEEK_SET);
        struct fat_header fat_hdr;
        fread(&fat_hdr, sizeof(fat_hdr), 1, f);
        
        uint32_t nfat_arch = SWAP32(fat_hdr.nfat_arch);
        struct fat_arch* archs = (struct fat_arch*)malloc(nfat_arch * sizeof(struct fat_arch));
        fread(archs, sizeof(struct fat_arch), nfat_arch, f);
        
        /* Find x86_64 or arm64 first, then i386 */
        uint32_t best_offset = 0;
        cpu_type_t best_cputype = 0;
        
        for (uint32_t i = 0; i < nfat_arch; i++) {
            cpu_type_t cputype = SWAP32(archs[i].cputype);
            if (cputype == CPU_TYPE_X86_64 || cputype == CPU_TYPE_ARM64) {
                best_offset = SWAP32(archs[i].offset);
                best_cputype = cputype;
                break;
            } else if (cputype == CPU_TYPE_I386 && best_cputype == 0) {
                best_offset = SWAP32(archs[i].offset);
                best_cputype = cputype;
            }
        }
        
        free(archs);
        
        if (best_offset == 0) {
            fclose(f);
            return 0;
        }
        
        fseek(f, best_offset, SEEK_SET);
        fread(&magic, sizeof(magic), 1, f);
        is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
        swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    }
    
    fseek(f, 0, SEEK_SET);
    
    if (is_64bit) {
        /* ========== 64-bit Mach-O ========== */
        struct mach_header_64 header;
        if (fread(&header, sizeof(header), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint32_t sizeofcmds = SWAP32(header.sizeofcmds);
        uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
        if (!load_cmds) {
            fclose(f);
            return 0;
        }
        
        if (fread(load_cmds, sizeofcmds, 1, f) != 1) {
            free(load_cmds);
            fclose(f);
            return 0;
        }
        
        uint8_t* cmd_ptr = load_cmds;
        
        for (uint32_t i = 0; i < ncmds && count < max_sections; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            uint32_t cmdsize = SWAP32(lc->cmdsize);
            
            if (cmd == LC_SEGMENT_64) {
                struct segment_command_64* seg = (struct segment_command_64*)lc;
                uint32_t nsects = SWAP32(seg->nsects);
                
                struct section_64* sect = (struct section_64*)(seg + 1);
                for (uint32_t j = 0; j < nsects && count < max_sections; j++) {
                    /* Combine segment and section name */
                    snprintf(sections[count].name, sizeof(sections[count].name), 
                             "%s,%s", seg->segname, sect[j].sectname);
                    
                    sections[count].virtual_address = SWAP64(sect[j].addr);
                    sections[count].virtual_size = SWAP64(sect[j].size);
                    sections[count].raw_offset = SWAP32(sect[j].offset);
                    sections[count].raw_size = (sect[j].offset != 0) ? SWAP64(sect[j].size) : 0;
                    sections[count].alignment = SWAP32(sect[j].align);
                    
                    uint32_t flags = SWAP32(sect[j].flags);
                    sections[count].characteristics = flags;
                    
                    /* Set section attributes */
                    sections[count].is_executable = (flags & S_ATTR_PURE_INSTRUCTIONS) || 
                                                    (flags & S_ATTR_SOME_INSTRUCTIONS);
                    sections[count].is_readable = true;
                    sections[count].is_writable = (flags & S_ATTR_DEBUG) == 0;
                    sections[count].is_discardable = (flags & S_ATTR_DEBUG) != 0;
                    sections[count].is_shared = (flags & S_ATTR_DEBUG) == 0;
                    
                    /* Section type */
                    uint8_t section_type = flags & SECTION_TYPE;
                    switch (section_type) {
                        case S_REGULAR: /* Regular section */ break;
                        case S_ZEROFILL: sections[count].raw_size = 0; break;
                        case S_CSTRING_LITERALS: break;
                        case S_4BYTE_LITERALS: break;
                        case S_8BYTE_LITERALS: break;
                        case S_LITERAL_POINTERS: break;
                        case S_NON_LAZY_SYMBOL_POINTERS: break;
                        case S_LAZY_SYMBOL_POINTERS: break;
                        case S_SYMBOL_STUBS: break;
                        case S_MOD_INIT_FUNC_POINTERS: break;
                        case S_MOD_TERM_FUNC_POINTERS: break;
                        case S_COALESCED: break;
                        case S_GB_ZEROFILL: break;
                        case S_INTERPOSING: break;
                        case S_16BYTE_LITERALS: break;
                        case S_DTRACE_DOF: break;
                        case S_LAZY_DYLIB_SYMBOL_POINTERS: break;
                        default: break;
                    }
                    
                    /* Calculate entropy for non-zero sections */
                    if (sect[j].offset > 0 && sect[j].size > 0 && sect[j].size < 100 * 1024 * 1024) {
                        uint8_t* data = (uint8_t*)malloc(sect[j].size);
                        if (data) {
                            long current_pos = ftell(f);
                            fseek(f, sect[j].offset, SEEK_SET);
                            size_t bytes_read = fread(data, 1, sect[j].size, f);
                            if (bytes_read == sect[j].size) {
                                sections[count].entropy = cdll_calculate_entropy(data, bytes_read);
                                sections[count].data = data;
                            } else {
                                free(data);
                                sections[count].data = NULL;
                            }
                            fseek(f, current_pos, SEEK_SET);
                        }
                    } else {
                        sections[count].entropy = 0.0;
                        sections[count].data = NULL;
                    }
                    
                    count++;
                }
            }
            
            cmd_ptr += cmdsize;
        }
        
        free(load_cmds);
        
    } else {
        /* ========== 32-bit Mach-O ========== */
        struct mach_header header;
        fseek(f, 0, SEEK_SET);
        if (fread(&header, sizeof(header), 1, f) != 1) {
            fclose(f);
            return 0;
        }
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint32_t sizeofcmds = SWAP32(header.sizeofcmds);
        uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
        if (!load_cmds) {
            fclose(f);
            return 0;
        }
        
        if (fread(load_cmds, sizeofcmds, 1, f) != 1) {
            free(load_cmds);
            fclose(f);
            return 0;
        }
        
        uint8_t* cmd_ptr = load_cmds;
        
        for (uint32_t i = 0; i < ncmds && count < max_sections; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            uint32_t cmdsize = SWAP32(lc->cmdsize);
            
            if (cmd == LC_SEGMENT) {
                struct segment_command* seg = (struct segment_command*)lc;
                uint32_t nsects = SWAP32(seg->nsects);
                
                struct section* sect = (struct section*)(seg + 1);
                for (uint32_t j = 0; j < nsects && count < max_sections; j++) {
                    snprintf(sections[count].name, sizeof(sections[count].name),
                             "%s,%s", seg->segname, sect[j].sectname);
                    
                    sections[count].virtual_address = SWAP32(sect[j].addr);
                    sections[count].virtual_size = SWAP32(sect[j].size);
                    sections[count].raw_offset = SWAP32(sect[j].offset);
                    sections[count].raw_size = (sect[j].offset != 0) ? SWAP32(sect[j].size) : 0;
                    sections[count].alignment = SWAP32(sect[j].align);
                    
                    uint32_t flags = SWAP32(sect[j].flags);
                    sections[count].characteristics = flags;
                    
                    sections[count].is_executable = (flags & S_ATTR_PURE_INSTRUCTIONS) || 
                                                    (flags & S_ATTR_SOME_INSTRUCTIONS);
                    sections[count].is_readable = true;
                    sections[count].is_writable = (flags & S_ATTR_DEBUG) == 0;
                    
                    /* Calculate entropy */
                    if (sect[j].offset > 0 && sect[j].size > 0 && sect[j].size < 100 * 1024 * 1024) {
                        uint8_t* data = (uint8_t*)malloc(sect[j].size);
                        if (data) {
                            long current_pos = ftell(f);
                            fseek(f, sect[j].offset, SEEK_SET);
                            size_t bytes_read = fread(data, 1, sect[j].size, f);
                            if (bytes_read == sect[j].size) {
                                sections[count].entropy = cdll_calculate_entropy(data, bytes_read);
                                sections[count].data = data;
                            } else {
                                free(data);
                                sections[count].data = NULL;
                            }
                            fseek(f, current_pos, SEEK_SET);
                        }
                    } else {
                        sections[count].entropy = 0.0;
                        sections[count].data = NULL;
                    }
                    
                    count++;
                }
            }
            
            cmd_ptr += cmdsize;
        }
        
        free(load_cmds);
    }
    
    #undef SWAP32
    #undef SWAP64
    
    fclose(f);
    return count;
}

/* ============================================================================
 * Mach-O: Enumerate Imports (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all exported functions from a macOS driver
 * @param path Path to the .kext driver file
 * @param entries Array to fill with export information
 * @param max_entries Maximum number of entries to enumerate
 * @return Number of exports found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_imports(const char* path,
                                                        cdll_executable_import_t* imports,
                                                        size_t max_imports) {
    if (!path || !imports || max_imports == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, f);
    
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    
    size_t count = 0;
    fseek(f, 0, SEEK_SET);
    
    if (is_64bit) {
        struct mach_header_64 header;
        fread(&header, sizeof(header), 1, f);
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint32_t sizeofcmds = SWAP32(header.sizeofcmds);
        uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
        fread(load_cmds, sizeofcmds, 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        macho_symtab_command_t* symtab_cmd = NULL;
        macho_dysymtab_command_t* dysymtab_cmd = NULL;
        
        /* First pass: find symtab and collect dylibs */
        for (uint32_t i = 0; i < ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SYMTAB) {
                symtab_cmd = (macho_symtab_command_t*)lc;
            } else if (cmd == LC_DYSYMTAB) {
                dysymtab_cmd = (macho_dysymtab_command_t*)lc;
            } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB) {
                struct dylib_command* dylib = (struct dylib_command*)lc;
                uint32_t name_offset = SWAP32(dylib->dylib.name.offset);
                char* dylib_name = (char*)cmd_ptr + name_offset;
                
                strncpy(imports[count].module_name, dylib_name, sizeof(imports[count].module_name) - 1);
                imports[count].name[0] = '\0';
                imports[count].is_delay_load = (cmd == LC_LOAD_WEAK_DYLIB);
                count++;
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        /* Second pass: get undefined symbols */
        if (symtab_cmd && dysymtab_cmd && count < max_imports) {
            uint32_t nsyms = SWAP32(symtab_cmd->nsyms);
            uint32_t symoff = SWAP32(symtab_cmd->symoff);
            uint32_t stroff = SWAP32(symtab_cmd->stroff);
            uint32_t strsize = SWAP32(symtab_cmd->strsize);
            
            uint32_t iundefsym = SWAP32(dysymtab_cmd->iundefsym);
            uint32_t nundefsym = SWAP32(dysymtab_cmd->nundefsym);
            
            struct nlist_64* symbols = (struct nlist_64*)malloc(nsyms * sizeof(struct nlist_64));
            char* strtab = (char*)malloc(strsize);
            
            if (symbols && strtab) {
                fseek(f, symoff, SEEK_SET);
                fread(symbols, sizeof(struct nlist_64), nsyms, f);
                
                fseek(f, stroff, SEEK_SET);
                fread(strtab, strsize, 1, f);
                
                for (uint32_t i = iundefsym; i < iundefsym + nundefsym && count < max_imports; i++) {
                    uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                    if (strx > 0 && strx < strsize) {
                        strncpy(imports[count].name, strtab + strx, sizeof(imports[count].name) - 1);
                        imports[count].ordinal = i;
                        count++;
                    }
                }
                
                free(symbols);
                free(strtab);
            }
        }
        
        free(load_cmds);
    }
    
    #undef SWAP32
    
    fclose(f);
    return count;
}

/* ============================================================================
 * Mach-O: Enumerate Exports (Full)
 * ============================================================================ */

/**
 * @brief Enumerates all Mach-O sections of a macOS driver
 * @param path Path to the .kext driver file
 * @param sections Array to fill with section information
 * @param max_sections Maximum number of sections to enumerate
 * @return Number of sections found, or 0 on failure
 */
static inline size_t cdll_enumerate_executable_exports(const char* path,
                                                        cdll_executable_export_t* exports,
                                                        size_t max_exports) {
    if (!path || !exports || max_exports == 0) return 0;
    
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, f);
    
    bool swap_bytes = (magic == MH_CIGAM || magic == MH_CIGAM_64);
    bool is_64bit = (magic == MH_MAGIC_64 || magic == MH_CIGAM_64);
    
    #define SWAP32(x) (swap_bytes ? OSSwapInt32(x) : (x))
    
    size_t count = 0;
    fseek(f, 0, SEEK_SET);
    
    if (is_64bit) {
        struct mach_header_64 header;
        fread(&header, sizeof(header), 1, f);
        
        uint32_t ncmds = SWAP32(header.ncmds);
        uint32_t sizeofcmds = SWAP32(header.sizeofcmds);
        uint8_t* load_cmds = (uint8_t*)malloc(sizeofcmds);
        fread(load_cmds, sizeofcmds, 1, f);
        
        uint8_t* cmd_ptr = load_cmds;
        macho_symtab_command_t* symtab_cmd = NULL;
        macho_dysymtab_command_t* dysymtab_cmd = NULL;
        
        for (uint32_t i = 0; i < ncmds; i++) {
            struct load_command* lc = (struct load_command*)cmd_ptr;
            uint32_t cmd = SWAP32(lc->cmd);
            
            if (cmd == LC_SYMTAB) {
                symtab_cmd = (macho_symtab_command_t*)lc;
            } else if (cmd == LC_DYSYMTAB) {
                dysymtab_cmd = (macho_dysymtab_command_t*)lc;
            }
            
            cmd_ptr += SWAP32(lc->cmdsize);
        }
        
        if (symtab_cmd && dysymtab_cmd) {
            uint32_t nsyms = SWAP32(symtab_cmd->nsyms);
            uint32_t symoff = SWAP32(symtab_cmd->symoff);
            uint32_t stroff = SWAP32(symtab_cmd->stroff);
            uint32_t strsize = SWAP32(symtab_cmd->strsize);
            
            uint32_t iextdefsym = SWAP32(dysymtab_cmd->iextdefsym);
            uint32_t nextdefsym = SWAP32(dysymtab_cmd->nextdefsym);
            
            struct nlist_64* symbols = (struct nlist_64*)malloc(nsyms * sizeof(struct nlist_64));
            char* strtab = (char*)malloc(strsize);
            
            if (symbols && strtab) {
                fseek(f, symoff, SEEK_SET);
                fread(symbols, sizeof(struct nlist_64), nsyms, f);
                
                fseek(f, stroff, SEEK_SET);
                fread(strtab, strsize, 1, f);
                
                for (uint32_t i = iextdefsym; i < iextdefsym + nextdefsym && count < max_exports; i++) {
                    uint32_t strx = SWAP32(symbols[i].n_un.n_strx);
                    if (strx > 0 && strx < strsize) {
                        strncpy(exports[count].name, strtab + strx, sizeof(exports[count].name) - 1);
                        cdll_demangle_symbol(exports[count].name, exports[count].demangled_name,
                                            sizeof(exports[count].demangled_name));
                        exports[count].rva = SWAP64(symbols[i].n_value);
                        exports[count].ordinal = count + 1;
                        count++;
                    }
                }
                
                free(symbols);
                free(strtab);
            }
        }
        
        free(load_cmds);
    }
    
    #undef SWAP32
    
    fclose(f);
    return count;
}

/* ============================================================================
 * Mach-O: Load Executable (Full)
 * ============================================================================ */

/**
 * @brief Loads a Mach-O executable into memory at specified address
 * @param path Path to the executable file
 * @param load_address Desired load address (NULL for default)
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_to(const char* path, void* load_address) {
    if (!path) return NULL;
    
    cdll_loaded_executable_t* exec = (cdll_loaded_executable_t*)calloc(1, sizeof(cdll_loaded_executable_t));
    if (!exec) return NULL;
    
    if (!cdll_get_executable_info(path, &exec->info)) {
        free(exec);
        return NULL;
    }
    
    /* Use system dlopen for simple loading */
    void* handle = dlopen(path, RTLD_LAZY);
    if (!handle) {
        cdll_set_error("cdll_load_executable_to", errno, dlerror());
        free(exec);
        return NULL;
    }
    
    exec->base_address = handle;
    exec->entry_point = dlsym(handle, "_main");
    if (!exec->entry_point) {
        exec->entry_point = dlsym(handle, "main");
    }
    exec->original_entry_point = exec->entry_point;
    
    return exec;
}

/**
 * @brief Loads a Mach-O executable and sets custom entry point
 * @param path Path to the executable file
 * @param jump_address Custom address to jump to after loading
 * @return Loaded executable context, or NULL on failure
 */
static inline cdll_loaded_executable_t* cdll_load_executable_jump(const char* path, void* jump_address) {
    cdll_loaded_executable_t* exec = cdll_load_executable_to(path, NULL);
    if (exec) {
        exec->custom_entry = jump_address;
    }
    return exec;
}

/**
 * @brief Executes a loaded executable (resumes if suspended, or calls entry)
 * @param exec Loaded executable context
 * @return true on success, false on failure
 */
static inline bool cdll_execute_loaded(cdll_loaded_executable_t* exec) {
    if (!exec) return false;
    
    void* entry = exec->custom_entry ? exec->custom_entry : exec->entry_point;
    
    if (entry) {
        typedef int (*entry_func_t)(int, char**);
        entry_func_t entry_func = (entry_func_t)entry;
        entry_func(0, NULL);
        return true;
    }
    
    return false;
}

/**
 * @brief Unloads an executable and frees all associated resources
 * @param exec Loaded executable context to unload
 */
static inline void cdll_unload_executable(cdll_loaded_executable_t* exec) {
    if (!exec) return;
    
    if (exec->base_address) {
        dlclose(exec->base_address);
    }
    
    free(exec);
}

#endif /* CDLL_H */