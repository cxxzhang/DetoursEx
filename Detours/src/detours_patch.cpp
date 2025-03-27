#define DETOURS_INTERNAL
#include "detours.h"
#undef DETOURS_INTERNAL

#include <stdlib.h>
#include <stdint.h>
#include <memory.h>

typedef unsigned char BYTE_,*PBYTE_;
typedef PBYTE_ ULONG_PTR_;
typedef uint64_t ULONG64_;
PBYTE_ detour_gen_jmp_immediate(PBYTE_ pbCode, PBYTE_ pbJmpVal);
PBYTE_ detour_gen_jmp_indirect(PBYTE_ pbCode, PBYTE_ *ppbJmpVal);
PBYTE_ detour_gen_brk(PBYTE_ pbCode, PBYTE_ pbLimit);
PBYTE_ detour_gen_jmp_immediate(PBYTE_ pbCode, PBYTE_ *ppPool, PBYTE_ pbJmpVal);
PBYTE_ detour_gen_jmp_indirect(BYTE_ *pbCode, ULONG64_ *pbJmpVal);

struct DetourMemoryOpWrapper {
    DetourMemoryOpWrapper *pNext;
    DetourMemoryOpWrapper *pPrev;
    void *pbCode;
    char rbCode[0x100];
    int iCodeSize;
};

static DetourMemoryOpWrapper *s_detoursMemoryOp = nullptr;


static BOOL is_trampoline(ULONG_PTR_ addr);

inline static void push_op(DetourMemoryOpWrapper *o) {
    o->pPrev = s_detoursMemoryOp;
    if (s_detoursMemoryOp) {
        s_detoursMemoryOp->pNext = o;
    }
    o->pNext = nullptr;
    s_detoursMemoryOp = o;
}

#define MAX_PAGE_SIZE 0x1000
#define MAX_PATCH_SIZE 0x100

// do 's|detour_gen_(.*?)\((.*?)\);|detour_gen_$1_($2);|' on detours.cpp
template<typename T1, typename T2>
PBYTE_ detour_gen_jmp_indirect_(T1 pbCode, T2 value) {
    DETOUR_TRACE(("detour_gen_jmp_indirect_(%p, %p)\n", pbCode, value));
#if !defined(_DARWIN)
	return detour_gen_jmp_indirect((T1)pbCode, (T2)value);
#endif
    if (is_trampoline((ULONG_PTR_)(pbCode))) return detour_gen_jmp_indirect((T1)pbCode, (T2)value);

    char _pbCodeBuf[2 * MAX_PAGE_SIZE + 0x100] = { 0 };
    char *pbCodeBuf = _pbCodeBuf + MAX_PAGE_SIZE - ((ULONG64_)(ULONG_PTR_)_pbCodeBuf & 0xfff) + ((ULONG64_)(ULONG_PTR_)pbCode & 0xfff);
    memcpy(pbCodeBuf, pbCode, MAX_PATCH_SIZE);
    ULONG_PTR_ newvalue = 0;
    if (value != nullptr) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_jmp_indirect((T1)pbCodeBuf, (T2)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    o->iCodeSize = (int)(ret - (PBYTE_)pbCodeBuf);
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2>
PBYTE_ detour_gen_jmp_immediate_(T1 pbCode, T2 value) {
    DETOUR_TRACE(("detour_gen_jmp_immediate_(%p, %p)\n", pbCode, value));
#if !defined(_DARWIN)
	return  detour_gen_jmp_immediate((T1)pbCode, (T2)value);
#endif
    if (is_trampoline((ULONG_PTR_)(pbCode))) return detour_gen_jmp_immediate((T1)pbCode, (T2)value);

    
    char _pbCodeBuf[2 * MAX_PAGE_SIZE + 0x100] = { 0 };
    char *pbCodeBuf = _pbCodeBuf + MAX_PAGE_SIZE - ((ULONG64_)(ULONG_PTR_)_pbCodeBuf & 0xfff) + ((ULONG64_)(ULONG_PTR_)pbCode & 0xfff);
    memcpy(pbCodeBuf, pbCode, MAX_PATCH_SIZE);
    ULONG_PTR_ newvalue = 0;
    if (value != nullptr) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_jmp_immediate((T1)pbCodeBuf, (T2)(ULONG_PTR_)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    o->iCodeSize = (int)(ret - (PBYTE_)pbCodeBuf);
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2, typename T3>
PBYTE_ detour_gen_jmp_immediate_(T1 pbCode, T2 ppPool, T3 pbJmpVal) {
    DETOUR_TRACE(("detour_gen_jmp_immediate_(%p, %p, %p)\n", pbCode, ppPool, pbJmpVal));
#if !defined(_DARWIN)
	return  detour_gen_jmp_immediate((T1)pbCode, (T2)ppPool, (T3)pbJmpVal);
#endif
    if (is_trampoline((ULONG_PTR_)(pbCode))) return detour_gen_jmp_immediate((T1)pbCode, (T2)ppPool, (T3)pbJmpVal);

    
    if (ppPool) {
        DETOUR_TRACE(("detour_gen_jmp_immediate_: Warning, cannot handle ppPool cases!\n"));
        return detour_gen_jmp_immediate(pbCode, ppPool, pbJmpVal);
    }

    char _pbCodeBuf[2 * MAX_PAGE_SIZE + 0x100] = { 0 };
    char *pbCodeBuf = _pbCodeBuf + MAX_PAGE_SIZE - ((ULONG64_)(ULONG_PTR_)_pbCodeBuf & 0xfff) + ((ULONG64_)(ULONG_PTR_)pbCode & 0xfff);
    memcpy(pbCodeBuf, pbCode, MAX_PATCH_SIZE);
    ULONG_PTR_ newvalue = pbJmpVal;
    //if (pbJmpVal != nullptr) {
    //    newvalue = (ULONG_PTR_)pbJmpVal - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    //}
    PBYTE_ ret = detour_gen_jmp_immediate((T1)pbCodeBuf, nullptr, (T3)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    o->iCodeSize = (int)(ret - (PBYTE_)pbCodeBuf);
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);

    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}

template<typename T1, typename T2>
PBYTE_ detour_gen_brk_(T1 pbCode, T2 value) {
    DETOUR_TRACE(("detour_gen_brk_(%p, %p)\n", pbCode, value));
#if !defined(_DARWIN)
	return  detour_gen_brk((T1)pbCode, (T2)value);
#endif
    if (is_trampoline((ULONG_PTR_)(pbCode))) return detour_gen_brk((T1)pbCode, (T2)value);

    char _pbCodeBuf[2 * MAX_PAGE_SIZE + 0x100] = { 0 };
    char *pbCodeBuf = _pbCodeBuf + MAX_PAGE_SIZE - ((ULONG64_)(ULONG_PTR_)_pbCodeBuf & 0xfff) + ((ULONG64_)(ULONG_PTR_)pbCode & 0xfff);
    memcpy(pbCodeBuf, pbCode, MAX_PATCH_SIZE);
    ULONG_PTR_ newvalue = 0;
    if (value != nullptr) {
        newvalue = (ULONG_PTR_)value - (ULONG_PTR_)pbCode + (ULONG_PTR_)pbCodeBuf;
    }
    PBYTE_ ret = detour_gen_brk((T1)pbCodeBuf, (T2)newvalue);
    
    DetourMemoryOpWrapper *o = new DetourMemoryOpWrapper;
    o->pbCode = pbCode;
    o->iCodeSize = (int)(ret - (PBYTE_)pbCodeBuf);
    memcpy(o->rbCode, pbCodeBuf, sizeof(o->rbCode));
    push_op(o);
    ret = (PBYTE_)((ULONG_PTR_)ret - (ULONG_PTR_)pbCodeBuf + (ULONG_PTR_)pbCode);
    return ret;
}


#define DetourTransactionCommit _DetourTransactionCommit
#include "detours.cpp"
#undef DetourTransactionCommit

static BOOL is_trampoline(ULONG_PTR_ addr) {
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        ULONG_PTR_ addrRegion = (ULONG_PTR_)pRegion;
        if ( addrRegion <= addr  && addr < addrRegion + DETOUR_REGION_SIZE ) {
            return TRUE;
        }
    }
    return FALSE;
}


#include <vector>

extern "C" {

// struct DetourOperationWrapper {
//     DetourOperationWrapper *pNext;
//     PBYTE oldPbTarget;
//     PBYTE newPbTarget;
//     DWORD cbTarget;
//     DWORD flOld;
// };
LONG WINAPI DetourTransactionCommit() {
//     DetourOperationWrapper *ori_s_pPendingOperations = nullptr;
//     LONG ret = 0;
//     for (DetourOperation *o = s_pPendingOperations; o != nullptr;) {
//         DetourOperationWrapper *o_ = new DetourOperationWrapper;
//         o_->oldPbTarget = o->pbTarget;
//         o_->cbTarget = o->pTrampoline->pbRemain - o->pbTarget;
//         o_->newPbTarget = new BYTE[o_->cbTarget + 0x100];
//         memcpy(o_->newPbTarget, o_->oldPbTarget, o_->cbTarget);
//         o_->flOld = o->dwPerm;
//         if (!VirtualProtect(o_->oldPbTarget, o_->cbTarget, PAGE_READWRITE, &o_->flOld)) {
//             // wait for ret
//             ret = GetLastError();
//             delete o_;
//             break;
//         }
        
//         o_->pNext = ori_s_pPendingOperations;
//         ori_s_pPendingOperations = o_;
//         DETOUR_TRACE(("Before transaction commit: %p (%x)\n", o_->oldPbTarget, o_->cbTarget));
//         // o->pbTarget = o_->newPbTarget;
//         // o->pTrampoline->pbRemain = o_->newPbTarget + o_->cbTarget;
//         // o->pTrampoline->rbCodeIn
//         o = o->pNext;
//     }
//     if (!ret) {
//         ret = _DetourTransactionCommit();
//         DETOUR_TRACE(("Transaction Result: %d\n", ret));
//     } else {
//         DETOUR_TRACE(("Error During VirtualProtect prepare: %d\n", ret));
//     }
    
//     for (DetourOperationWrapper *o_ = ori_s_pPendingOperations; o_ != nullptr;) {
//         //if (!!memcmp(o_->oldPbTarget, o_->newPbTarget, o_->cbTarget)) {
//         //    DETOUR_TRACE(("Applying After transaction commit: %p (%x) <- %p\n", o_->oldPbTarget, o_->cbTarget, o_->newPbTarget));
//         //    CodePatch(o_->oldPbTarget, o_->newPbTarget, o_->cbTarget);
//         //}
//         DWORD flOld = 0;
//         if (!VirtualProtect(o_->oldPbTarget, o_->cbTarget, o_->flOld, &flOld)) {
//             // wait for ret
//             ret = GetLastError();
//             DETOUR_TRACE(("Failed to restore page permission for %p: error %d\n", o_->oldPbTarget, ret));
//         }

//         delete[] o_->newPbTarget;
//         DetourOperationWrapper *n_ = o_->pNext;
//         delete o_;
//         o_ = n_;
//     }
//     return ret;
    LONG ret = _DetourTransactionCommit();
    DetourMemoryOpWrapper *begin = nullptr;
    for (DetourMemoryOpWrapper *o = s_detoursMemoryOp; o != nullptr; ) {
        begin = o;
        o = o->pPrev;
    }
    for (DetourMemoryOpWrapper *o = begin; o != nullptr; ) {
        BYTE *rbCode = (BYTE *)o->rbCode;
        DETOUR_TRACE(("Applying Code Changes: %p\n", o->pbCode));
        DETOUR_TRACE(("detours: pbCode=%p: "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x "
                          "%02x %02x %02x %02x [after]\n",
                          o->pbCode,
                          rbCode[0], rbCode[1], rbCode[2], rbCode[3],
                          rbCode[4], rbCode[5], rbCode[6], rbCode[7],
                          rbCode[8], rbCode[9], rbCode[10], rbCode[11]));
        if (!CodePatch(o->pbCode, o->rbCode, o->iCodeSize/* sizeof(o->rbCode)*/))
            ret = GetLastError();
        DetourMemoryOpWrapper *n = o->pNext;
        delete o;
        o = n;
    }
    s_detoursMemoryOp = NULL;
    // Mark all of the regions as executable.
    // for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
    //     DETOUR_TRACE(("Marking Trampolines as RX: %p\n", pRegion));
    //     CodePatch(pRegion, NULL, DETOUR_REGION_SIZE);
    // }
    return ret;
}



}
