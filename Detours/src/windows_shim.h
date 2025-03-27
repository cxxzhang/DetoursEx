// Define DETOUR_TRACE macro
// #define DETOUR_DEBUG 1
#ifndef DETOUR_TRACE
#if DETOUR_DEBUG
#define DETOUR_TRACE(x) printf x
#include <stdio.h>
#else
#define DETOUR_TRACE(x)
#endif
#endif

// Definition for Windows related things
#ifndef _WIN32

#include <stdint.h>
#include <stdlib.h>

#define CALLBACK
#define WINAPI

typedef uint32_t DWORD, *PDWORD;
typedef int16_t SHORT, *PSHORT;
typedef uint16_t USHORT, *PUSHORT;

typedef uint16_t UINT16;
typedef unsigned char UCHAR;
typedef char CHAR;
typedef uint8_t BYTE;
typedef uint8_t *PBYTE;
typedef int16_t SHORT;
typedef uint16_t USHORT, WORD;
typedef int32_t BOOL;
typedef int32_t INT, INT32;
typedef uint32_t UINT, UINT32;
typedef int64_t INT64, LONG64;
typedef int64_t __int64;
typedef uint64_t UINT64, ULONG64;
typedef long long LONGLONG;
typedef void VOID, *HMODULE, *PVOID, *LPVOID;
#define TRUE ((BOOL)1)
#define FALSE ((BOOL)0)
// long is 8bytes in Clang/GCC, but 4bytes on Windows
typedef int LONG;
typedef unsigned int ULONG, *PULONG;
typedef unsigned int ULONG32, * PULONG32;
typedef uintptr_t ULONG_PTR;
typedef intptr_t LONG_PTR;
typedef size_t SIZE_T;

typedef char *LPSTR;
typedef const char *LPCSTR;
typedef const void *LPCVOID;
typedef void *HANDLE;

#define ERROR_INVALID_DATA 0x10001
#define ERROR_INVALID_OPERATION 0x10002
#define ERROR_NOT_ENOUGH_MEMORY 0x10003
#define ERROR_INVALID_PARAMETER 0x10004
#define ERROR_INVALID_HANDLE 0x10005
#define ERROR_INVALID_BLOCK 0x10006
#define ERROR_DYNAMIC_CODE_BLOCKED 1655L
#define ERROR_NOT_SAME_THREAD 0x10020

#define ERROR_MACH_FAIL_BASE 0x20100
#define ERROR_ERRNO_FAIL_BASE 0x20200
#define NO_ERROR 0

extern "C" {
extern void SetLastError(int err);
extern int GetLastError();
}

static int GetCurrentThreadId() {
    return 0;
}

static HANDLE GetCurrentThread() {
    return (HANDLE)-2;
}

static HANDLE GetCurrentProcess() {
    return (HANDLE)-1;
}

#else

#include <windows.h>

#endif // _WIN32


#ifdef DETOURS_INTERNAL

extern "C" {
static unsigned long DetourGetModuleSize(void *) {
    return 0x1337;
}
}

#include <limits.h>
#undef LONG_MAX
#undef LONG_MIN
#define LONG_MAX INT_MAX
#define LONG_MIN INT_MIN

// Definition for windows shim functions
#ifdef _WIN32

static int getpagesize() {
    return 0x1000;
}

#else

#include <stdio.h>
#include <stddef.h>
#include <memory.h>

#include <unistd.h>
#include <errno.h>

#ifdef _LINUX
#include <fcntl.h>
#include <sys/mman.h>
#endif

#ifdef _DARWIN
#include <unistd.h>
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#endif

#define C_ASSERT(e) typedef char __C_ASSERT__[(e)?1:-1]
#define ARRAYSIZE(A) (sizeof(A)/sizeof(A[0]))

#define UNALIGNED

#define UNREFERENCED_PARAMETER(P) (P)

static inline
LONG InterlockedCompareExchange(LONG *ptr, LONG nval, LONG oval)
{
    return __sync_val_compare_and_swap (ptr, nval, oval);
}

static inline ULONG PtrToUlong(PVOID ptr) {
    return (ULONG)(ULONG_PTR)(ptr);
}

static void CopyMemory(
        PVOID  Destination,
  const VOID   *Source,
        SIZE_T Length
) {
    memcpy(Destination, Source, Length);
}

#define PAGE_NOACCESS 1
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_EXECUTE 0x10
#define PAGE_WRITECOPY 0x8
#define PAGE_EXECUTE_READ (PAGE_READONLY * PAGE_EXECUTE)
#define PAGE_EXECUTE_READWRITE (PAGE_READWRITE * PAGE_EXECUTE)
#define PAGE_EXECUTE_WRITECOPY (PAGE_WRITECOPY * PAGE_EXECUTE)

#define MEM_COMMIT 0x00001000
#define MEM_FREE   0x00010000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0

typedef struct _MEMORY_BASIC_INFORMATION {
  PVOID  BaseAddress;
  PVOID  AllocationBase;
  DWORD  AllocationProtect;
  WORD   PartitionId;
  SIZE_T RegionSize;
  DWORD  State;
  DWORD  Protect;
  DWORD  Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

static void WinProtToRWX(DWORD flProtect, int *r, int *w, int *x) {
    if (flProtect && (flProtect & 0xF) == 0) {
        *x = 1;
        flProtect >>= 4;
    }
    switch (flProtect) {
    case PAGE_READONLY:
        *r = 1;
        *w = 0;
        break;
    case PAGE_READWRITE:
        *r = 1;
        *w = 1;
        break;
    default:
        *r = 1;
        *w = 1;
        break;
    }
}

static DWORD RWXToWinProt(int r, int w, int x) {
    DWORD ret = PAGE_NOACCESS;
    if (r && w) {
        ret = PAGE_READWRITE;
    } else if (r) {
        ret = PAGE_READONLY;
    }
    if (x) {
        ret *= PAGE_EXECUTE;
    }
    return ret;
}

static SIZE_T VirtualQuery(
  LPCVOID                   lpAddress,
  PMEMORY_BASIC_INFORMATION lpBuffer,
  SIZE_T                    dwLength
) {
    if (!lpBuffer) return 0;
#if defined(_LINUX)
    int a = 0;
    unsigned int prot = 0;
    int f = open("/proc/self/maps", O_RDONLY);
    char b[1024] = { 0 };
    int b_pos = 0;
    unsigned long last_addr0 = 0, last_addr1 = 0;
    while ((read(f, &a, 1)) >= 0) {
        b[b_pos++] = a;
        if (b_pos >= sizeof(b) || a == '\n') {
            char*end0 = NULL;
            unsigned long addr0 = strtoul(b, &end0, 16);
            char*end1 = NULL;
            unsigned long addr1 = strtoul(end0+1, &end1, 16);
            if ((void*)addr0 <= lpAddress && lpAddress < (void*)addr1) {
                lpBuffer->BaseAddress = (PVOID)addr0;
                lpBuffer->AllocationBase = (PVOID)addr0;
                lpBuffer->RegionSize = addr1 - addr0;
                int r = (end1+1)[0] == 'r';
                int w = (end1+1)[1] == 'w';
                int x = (end1+1)[2] == 'x';
                int prot = RWXToWinProt(r,w,x);
                lpBuffer->AllocationProtect = prot;
                lpBuffer->PartitionId = 0;
                lpBuffer->State = MEM_COMMIT;
                break;
            } else if (lpAddress < (void*)addr0) {
                lpBuffer->BaseAddress = (PVOID)last_addr1;
                lpBuffer->AllocationBase = (PVOID)addr0;
                lpBuffer->RegionSize = addr0 - last_addr1;
                lpBuffer->AllocationProtect = 0;
                lpBuffer->PartitionId = 0;
                lpBuffer->State = MEM_FREE;
                break;
            }
            memset(b, 0, sizeof(b));
            b_pos = 0;
            last_addr0 = addr0;
            last_addr1 = addr1;
        }
    }
    
    close(f);
    return sizeof(MEMORY_BASIC_INFORMATION);
#elif defined(_DARWIN)
    kern_return_t kr = KERN_SUCCESS;
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = (mach_vm_address_t)lpAddress;
    mach_msg_type_number_t info_cnt = sizeof (vm_region_basic_info_data_64_t);
    vm_region_basic_info_data_64_t info;
    kr = mach_vm_region(mach_task_self(), &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &info_cnt, &object_name);
    if (kr) {
        SetLastError(kr + ERROR_MACH_FAIL_BASE);
    }
    if ((ULONG_PTR)address_info <= (ULONG_PTR)lpAddress) {
        lpBuffer->BaseAddress = (PVOID)address_info;
        lpBuffer->AllocationBase = (PVOID)address_info;
        lpBuffer->RegionSize = size_info;
        lpBuffer->State = MEM_COMMIT;
    } else {
        lpBuffer->BaseAddress = (PVOID)lpAddress;
        lpBuffer->AllocationBase = (PVOID)lpAddress;
        lpBuffer->RegionSize = (ULONG_PTR)address_info - (ULONG_PTR)lpAddress;
        lpBuffer->State = MEM_FREE;
    }
    int r = info.protection & VM_PROT_READ;
    int w = info.protection & VM_PROT_WRITE;
    int x = info.protection & VM_PROT_EXECUTE;
    int prot = RWXToWinProt(r,w,x);
    lpBuffer->AllocationProtect = prot;
    lpBuffer->PartitionId = 0;
    return sizeof(MEMORY_BASIC_INFORMATION);
#endif
    return 0;
}

static BOOL VirtualProtect(PVOID addr, SIZE_T dwSize, DWORD flNewProtect, DWORD *flOld) {
    DETOUR_TRACE(("VirtualProtect(%p, %lx, 0x%x)\n", addr, dwSize, flNewProtect));
    int newR = 0, newW = 0, newX = 0;
    WinProtToRWX(flNewProtect, &newR, &newW, &newX);

#if defined(_LINUX) || defined(_DARWIN)
    ULONG_PTR aligned_addr = (ULONG_PTR)addr & ~(getpagesize() - 1);
    SIZE_T aligned_size = (ULONG_PTR)addr - aligned_addr + dwSize;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((void *)aligned_addr, &mbi, sizeof(mbi))) {
        return FALSE;
    }
    int oldProt = mbi.AllocationProtect;
    *flOld = oldProt;
    BOOL ignoreRet = FALSE;
#ifdef _DARWIN
    if (newW && newX) {
        DETOUR_TRACE(("W^X detected, removing executing bit & ignoring error!\n"));
        newX = 0;
        ignoreRet = TRUE;
        // DETOUR_TRACE(("VirtualProtect: W^X detected, ignoring and directly return!\n"));
        // return TRUE;
    }
#endif
    int newProt = 0;
    newProt |= newR ? PROT_READ : 0;
    newProt |= newW ? PROT_WRITE : 0;
    newProt |= newX ? PROT_EXEC : 0;
    int ret = mprotect((void *)aligned_addr, aligned_size, newProt);
    if (!ignoreRet && ret == -1){
        DETOUR_TRACE(("VirtualProtect mprotect fail... errno=%d\n", errno));
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return FALSE;
    }
    return TRUE;
#else
#error Unknown OS (Please define _LINUX or _DARWIN)
#endif
    return FALSE;
}

static SIZE_T VirtualQueryEx(
  HANDLE                    hProcess,
  LPCVOID                   lpAddress,
  PMEMORY_BASIC_INFORMATION lpBuffer,
  SIZE_T                    dwLength
) {
    if (hProcess != GetCurrentProcess()) {
        return 0;
    }
    return VirtualQuery(lpAddress, lpBuffer, dwLength);
}

static BOOL VirtualProtectEx(HANDLE hProcess, PVOID addr, SIZE_T dwSize, DWORD flNewProtect, DWORD *flOld) {
    if (hProcess != GetCurrentProcess()) {
        return FALSE;
    }
    return VirtualProtect(addr, dwSize, flNewProtect, flOld);
}

static LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
) {
    DETOUR_TRACE(("VirtualAlloc(%p, 0x%lx, %d, 0x%x)\n", lpAddress, dwSize, flAllocationType, flProtect));
    int newR = 0, newW = 0, newX = 0;
    WinProtToRWX(flProtect, &newR, &newW, &newX);
    DETOUR_TRACE(("RWX parsed: %d %d %d\n", newR, newW, newX));
#ifdef _DARWIN
    if (newW && newX) {
        DETOUR_TRACE(("W^X detected, removing executing bit!\n"));
        newX = 0;
    }
#endif
    int newProt = 0;
    newProt |= newR ? PROT_READ : 0;
    newProt |= newW ? PROT_WRITE : 0;
    newProt |= newX ? PROT_EXEC : 0;

    LPVOID retAddr = mmap(lpAddress, dwSize, newProt, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    DETOUR_TRACE(("mmap(%p, 0x%lx, %d) = %p, errno = %d\n", lpAddress, dwSize, newProt, retAddr, errno));
    
    if (retAddr == (LPVOID)-1) {
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return NULL;
    }
    return retAddr;
}

#define FlushInstructionCache _FlushInstructionCache

#ifdef _DARWIN
#include <libkern/OSCacheControl.h>
#endif
static BOOL FlushInstructionCache(
  HANDLE  hProcess,
  LPCVOID lpBaseAddress,
  SIZE_T  dwSize
) {
#ifdef _DARWIN
    sys_icache_invalidate(( void *)lpBaseAddress,dwSize);
#endif
    return TRUE;
}

static BOOL VirtualFree(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  dwFreeType
) {
    if(munmap(lpAddress, dwSize)) {
        SetLastError(ERROR_ERRNO_FAIL_BASE + errno);
        return FALSE;
    };
    return TRUE;
}

static DWORD ResumeThread(
  HANDLE hThread
) {
    return 1;
}

static DWORD SuspendThread(
  HANDLE hThread
) {
    return 0;
}

#define ZeroMemory(a,s) memset((a), 0, (s))
#define __debugbreak() (void)0
#define DebugBreak() (void)0

#endif // _WIN32

#endif // DETOURS_INTERNAL

#undef DETOUR_TRACE
