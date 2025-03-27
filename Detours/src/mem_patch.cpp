#include <stdlib.h>
#include <memory.h>
#define DETOURS_INTERNAL
#include "detours.h"


#define patch_min(a,b) ((a) < (b) ? (a) : (b))

#if defined(_DARWIN)
#include <sys/mman.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_statistics.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>

void ClearCache(void *start, void *end) {
   return sys_icache_invalidate(start, (uint64_t)end - (uint64_t)start);
}



#define KERN_RETURN_ERROR(kr, failure)                                                                                 \
  do {                                                                                                                 \
    if (kr != KERN_SUCCESS) {                                                                                          \
      return failure;                                                                                                  \
    }                                                                                                                  \
  } while (0);

#include <sys/mman.h>
typedef uintptr_t addr_t;
#if defined(TARGET_ARCH_ARM64)
#define SYS_mprotect 74
int mprotect_impl(void *addr, size_t len, int prot) {
  int ret = 0;
  __asm__ __volatile__("mov x16, %[_SYS_mprotect]\n"
                       "svc 0x80\n"
                       "mov %w[_ret], w0\n"
                       "add %w[_ret], %w[_ret], #0x0\n"
                       : [_ret] "=r"(ret)
                       : [_SYS_mprotect] "n"(SYS_mprotect)
                       :);
  return ret;
}
#endif

#define ALIGN_FLOOR(address, range) ((uintptr_t)address & ~((uintptr_t)range - 1))
#define ALIGN_CEIL(address, range) (((uintptr_t)address + (uintptr_t)range - 1) & ~((uintptr_t)range - 1))
int _CodePatchPage(void *address, uint8_t *buffer, uint32_t buffer_size) {
  if (address == nullptr || buffer == nullptr || buffer_size == 0) {
    return -1;
  }

  size_t page_size = PAGE_SIZE;
  addr_t patch_page = ALIGN_FLOOR(address, page_size);

  // cross over page
  if ((addr_t)address + buffer_size > patch_page + page_size) {
    void *address_a = address;
    uint8_t *buffer_a = buffer;
    uint32_t buffer_size_a = (patch_page + page_size - (addr_t)address);
    auto ret = _CodePatchPage(address_a, buffer_a, buffer_size_a);
    if (ret == -1) {
      return ret;
    }

    void *address_b = (void *)((addr_t)address + buffer_size_a);
    uint8_t *buffer_b = buffer + buffer_size_a;
    uint32_t buffer_size_b = buffer_size - buffer_size_a;
    ret = _CodePatchPage(address_b, buffer_b, buffer_size_b);
    return ret;
  }

  addr_t remap_dest_page = patch_page;
  mach_vm_address_t remap_dummy_page = 0;

  auto self_task = mach_task_self();
  kern_return_t kr;

  int orig_prot = 0;
  int orig_max_prot = 0;
  int share_mode = 0;
  int is_enable_remap = -1;
  if (is_enable_remap == -1) {
    auto get_region_info = [&](addr_t region_start) -> void {
      vm_region_submap_info_64 region_submap_info;
      mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
      mach_vm_address_t addr = region_start;
      mach_vm_size_t size = 0;
      natural_t depth = 0;
      while (1) {
        kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t *)&addr, (mach_vm_size_t *)&size, &depth,
                                    (vm_region_recurse_info_t)&region_submap_info, &count);
        if (region_submap_info.is_submap) {
          depth++;
        } else {
          orig_prot = region_submap_info.protection;
          orig_max_prot = region_submap_info.max_protection;
          share_mode = region_submap_info.share_mode;
          return;
        }
      }
    };
    get_region_info(remap_dest_page);
    if (orig_max_prot != 5 && share_mode != 2) {
      is_enable_remap = 1;
    } else {
      is_enable_remap = 0;
    }
  }
  if (is_enable_remap == 1) {
    addr_t remap_dummy_page = 0;
    {
      kr = mach_vm_allocate(self_task, (mach_vm_address_t *)&remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
      KERN_RETURN_ERROR(kr, -1);

      memcpy((void *)remap_dummy_page, (void *)patch_page, page_size);

      int offset = (int)((addr_t)address - patch_page);
      memcpy((void *)(remap_dummy_page + offset), buffer, buffer_size);

      kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
      KERN_RETURN_ERROR(kr, -1);
    }

    vm_prot_t prot, max_prot;
    kr = mach_vm_remap(self_task, (mach_vm_address_t *)&remap_dest_page, page_size, 0,
                       VM_FLAGS_OVERWRITE | VM_FLAGS_FIXED, self_task, remap_dummy_page, true, &prot, &max_prot,
                       VM_INHERIT_COPY);
    KERN_RETURN_ERROR(kr, -1);

    kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
    KERN_RETURN_ERROR(kr, -1);
  } else {

    if (0) {
      {
        auto kr = mach_vm_allocate(self_task, &remap_dummy_page, page_size, VM_FLAGS_ANYWHERE);
        KERN_RETURN_ERROR(kr, -1);

        kr = mach_vm_deallocate(self_task, remap_dummy_page, page_size);
        KERN_RETURN_ERROR(kr, -1);
      }

      vm_prot_t prot, max_prot;
      kr = mach_vm_remap(self_task, &remap_dummy_page, page_size, 0, VM_FLAGS_ANYWHERE, self_task, remap_dest_page,
                         false, &prot, &max_prot, VM_INHERIT_SHARE);
      KERN_RETURN_ERROR(kr, -1);

      kr = mach_vm_protect(self_task, remap_dummy_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE);
      // the kr always return KERN_PROTECTION_FAILURE
      kr = KERN_PROTECTION_FAILURE;

      memcpy((void *)(remap_dummy_page + ((uint64_t)address - remap_dest_page)), buffer, buffer_size);
    }

    static __typeof(vm_protect) *vm_protect_impl = vm_protect;

    {
      kr = vm_protect_impl(self_task, remap_dest_page, page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
      KERN_RETURN_ERROR(kr, -1);

      memcpy((void *)(patch_page + ((uint64_t)address - remap_dest_page)), buffer, buffer_size);

      kr = vm_protect_impl(self_task, remap_dest_page, page_size, false, 5);
      KERN_RETURN_ERROR(kr, -1);
        
     ClearCache((void *)remap_dest_page, (void *)((addr_t)remap_dest_page + page_size));
    }
  }
  ClearCache(address, (void*)((addr_t)address + buffer_size));
  

  return 0;
}

#elif defined(_LINUX)

BOOL _CodePatchPage(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_EXECUTE_READWRITE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}

#elif defined(_WIN32)

#include <windows.h>

BOOL _CodePatchPage(void *target, void *buffer, size_t count) {
    DWORD flOld = 0;
    if (!VirtualProtect(target, count, PAGE_EXECUTE_READWRITE, &flOld)) {
        return FALSE;
    }
    memcpy(target, buffer, count);  
    if (!VirtualProtect(target, count, flOld, &flOld)) {
        return FALSE;
    }
    return TRUE;
}

#endif


#if !defined(_WIN32)
extern "C" {

    static int g_lastError = 0;

    void SetLastError(int err) {
        g_lastError = err;
    }

    int GetLastError() {
        return g_lastError;
    }

}
#endif


#include <vector>

extern "C" {

BOOL CodePatch(void *address, void *buffer, size_t buffer_size) {
    std::vector<char> _buffer;
    if (!buffer) {
        _buffer.resize(buffer_size);
        buffer = _buffer.data();
        memcpy(buffer, address, buffer_size);
    }
    char * start_addr = (char *)address;
    char * startPage = (char *)((uintptr_t)(start_addr + getpagesize()) & ~(getpagesize() - 1));
    BOOL ret = TRUE;
    if (!(ret = _CodePatchPage(start_addr, (uint8_t *)buffer, patch_min(startPage - start_addr, (int)buffer_size)))) {
        return ret;
    }
    uint32_t bufloc = (uint32_t)patch_min(startPage - start_addr, (int)buffer_size);
    while (bufloc < buffer_size) {
        uint32_t nextbufloc = (uint32_t)patch_min(bufloc + 0x1000, buffer_size);
        if (!(ret = _CodePatchPage(start_addr + bufloc,(uint8_t *)( (char *)buffer + bufloc), nextbufloc - bufloc))) {
            return ret;
        }
        bufloc = nextbufloc;
    }
    return ret;
}

}
