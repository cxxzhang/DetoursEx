#define DETOURS_INTERNAL
#include "detours.h"
#include "DetoursNotify.h"
#include <vector>
#include <mutex>

class AutoMutexLock
{
public:
	AutoMutexLock(std::mutex& mutex) : m_mutex(mutex)
	{
		m_mutex.lock();
	}

	~AutoMutexLock()
	{
		m_mutex.unlock();
	}

private:
	std::mutex& m_mutex;
};

#define DETOURS_PFUNC_TO_PBYTE(p)  ((PBYTE)(((ULONG_PTR)(p)) & ~(ULONG_PTR)1))
#define DETOURS_PBYTE_TO_PFUNC(p)  ((PBYTE)(((ULONG_PTR)(p)) | (ULONG_PTR)1))

typedef struct _DETROUS_NOFITY_FUN_INFO
{
	BYTE pHookFun[2048];//代码里面asm部分生成的代码，因为要直接操作寄存器，所以用asm编写
	ULONG ulHookFunSize; //pHookFun里面的内容大小
	PVOID pPointer;//需要hook的内存位置
	PVOID pPointerHookRet;//detours生成的Trampoline的内存位置
	PVOID pNotifyFn;//注册的回调函数，当pPointer运行时，调用这个函数执行通知
	PVOID pPointerJmpNeedUpdate;//x86和x64的asm代码里面，内部使用的一个临时变量。用来将0xFF25跳转的绝对地址填充成上面的Trampoline。
	PVOID pContext;//注册回调时填入的pContext参数
}DETROUS_NOFITY_FUN_INFO, *PDETROUS_NOFITY_FUN_INFO;

static std::vector<PDETROUS_NOFITY_FUN_INFO>  g_notify_fun_list;
static  std::mutex g_mutex;

PDETROUS_NOFITY_FUN_INFO AllocNotifyInfo()
{
	//内存属性先申请成可读写，待函数地址填充完以后，修改成可执行只读
	PDETROUS_NOFITY_FUN_INFO pInfo = (PDETROUS_NOFITY_FUN_INFO)VirtualAlloc(nullptr, 4096,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	return pInfo;
}


VOID DestoryNotifyInfo(_In_ PDETROUS_NOFITY_FUN_INFO pDetour)
{
	if(pDetour)
		VirtualFree(pDetour, 0, MEM_RELEASE);

}


static inline ULONG fetch_thumb_opcode(PBYTE pbCode)
{
	ULONG Opcode = *(UINT16*)&pbCode[0];
	if (Opcode >= 0xe800) {
		Opcode = (Opcode << 16) | *(UINT16*)&pbCode[2];
	}
	return Opcode;
}



UCHAR* WINAPI SkipJump(UCHAR* Ptr)
{
#if defined(_M_IX86) || defined(_M_AMD64)
	if (*Ptr == 0xE9)
		Ptr += *((int*)(Ptr + 1)) + 5;

#elif defined(_M_ARM)	

	PBYTE pbCode = (PBYTE)Ptr;
	// Skip over the import jump if there is one.
	pbCode = (PBYTE)DETOURS_PFUNC_TO_PBYTE(pbCode);
	ULONG Opcode = fetch_thumb_opcode(pbCode);

	if ((Opcode & 0xfbf08f00) == 0xf2400c00) {          // movw r12,#xxxx
		ULONG Opcode2 = fetch_thumb_opcode(pbCode + 4);

		if ((Opcode2 & 0xfbf08f00) == 0xf2c00c00) {      // movt r12,#xxxx
			ULONG Opcode3 = fetch_thumb_opcode(pbCode + 8);
			if (Opcode3 == 0x00004760) {                 // ldr  pc,[r12]
				PBYTE pbTarget = (PBYTE)(((Opcode2 << 12) & 0xf7000000) |
					((Opcode2 << 1) & 0x08000000) |
					((Opcode2 << 16) & 0x00ff0000) |
					((Opcode >> 4) & 0x0000f700) |
					((Opcode >> 15) & 0x00000800) |
					((Opcode >> 0) & 0x000000ff));

				Ptr = (UCHAR*)DETOURS_PFUNC_TO_PBYTE(pbTarget);
			}
		}
	}
#endif
	return Ptr;
}




BOOL MakeNotifyInfoFun(_Inout_ PDETROUS_NOFITY_FUN_INFO pInfo, _In_ PF_DETOUR_HOOK_NOTIFY pNotify);

PDETROUS_NOFITY_FUN_INFO MakeHookFunForNotify(_In_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify)
{
	PVOID pPointer = *ppPointer;
	{
		AutoMutexLock lock(g_mutex);
		for (size_t i = 0; i < g_notify_fun_list.size(); i++)
		{
			if (g_notify_fun_list[i]->pPointer == pPointer)
			{
				return nullptr;//已经hook过了
			}
		}
	}
	

	PDETROUS_NOFITY_FUN_INFO pInfo = AllocNotifyInfo();
	pInfo->pPointer = pPointer;
	pInfo->pNotifyFn = pNotify;

	if (!MakeNotifyInfoFun(pInfo,pNotify))
	{
		DestoryNotifyInfo(pInfo);
		pInfo = nullptr;
	}
	else
	{
		AutoMutexLock lock(g_mutex);
		g_notify_fun_list.push_back(pInfo);
	}	

	return pInfo;
}

VOID RemoveHookFunForNotify(_In_ PVOID* ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify)
{
	PVOID pPointer = *ppPointer;

	AutoMutexLock lock(g_mutex);
	for (std::vector<PDETROUS_NOFITY_FUN_INFO>::const_iterator iter = g_notify_fun_list.begin();
		iter != g_notify_fun_list.end(); iter++)
	{
		if ((*iter)->pPointer == pPointer)
		{
			g_notify_fun_list.erase(iter);

			return ;
		}
	}

}


PDETROUS_NOFITY_FUN_INFO GetHookFunInfoForHookedNotify(_In_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify,BOOL bRemove)
{
	PVOID pPointer = *ppPointer;
	for (std::vector<PDETROUS_NOFITY_FUN_INFO>::const_iterator iter = g_notify_fun_list.begin();
		iter != g_notify_fun_list.end(); iter ++)
	{
		if ((*iter)->pPointerHookRet == pPointer)
		{
			PDETROUS_NOFITY_FUN_INFO pRet = *iter;
			if(bRemove)
				g_notify_fun_list.erase(iter);

			return pRet;
		}
	}

	return nullptr;
}

LONG WINAPI DetourInstallNotify(_Inout_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify, PVOID pContext)
{
	PDETROUS_NOFITY_FUN_INFO pDetour = MakeHookFunForNotify(ppPointer, pNotify);
	if (pDetour == nullptr) return -1;

	PDETOUR_TRAMPOLINE pRealTrampoline = nullptr;
	LONG l_ret = DetourAttachEx(ppPointer, pDetour->pHookFun,&pRealTrampoline, nullptr, nullptr);
	if (l_ret != 0)
	{		
		RemoveHookFunForNotify(ppPointer, pNotify);
		DestoryNotifyInfo(pDetour);
		return l_ret;
	}

	pDetour->pContext = pContext;	
	pDetour->pPointerHookRet = pRealTrampoline;
#ifdef _M_ARM
	pDetour->pPointerHookRet = DETOURS_PBYTE_TO_PFUNC(pDetour->pPointerHookRet);
#endif

	if (pDetour->pPointerJmpNeedUpdate)
	{
		size_t size = sizeof(char*);
		VOID* pTmp= &pDetour->pPointerHookRet;
		VOID* pTmp2 = &pTmp;
#if defined(_M_IX86)//x86是FF 25填存储绝对地址的地址
		memcpy_s(pDetour->pPointerJmpNeedUpdate, size, pTmp2, size);
#elif defined(_M_AMD64)//x64是FF 25 00 00 00 00后填地址
		memcpy_s(pDetour->pPointerJmpNeedUpdate, size, pTmp, size);
#endif
	}

	DWORD dwOldProtect = 0;
	//修改内存属性为可执行只读
	VirtualProtect(pDetour, 2048, PAGE_EXECUTE_READ, &dwOldProtect);
	
	return l_ret;
}

LONG WINAPI DetourUnInstallNotify(_Inout_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify)
{
	PDETROUS_NOFITY_FUN_INFO pDetour = GetHookFunInfoForHookedNotify(ppPointer, pNotify,TRUE);
	if (pDetour == nullptr) return -1;

	LONG l_ret = DetourDetach(ppPointer, pDetour->pHookFun);

	DestoryNotifyInfo(pDetour);
	return l_ret;
}

UCHAR* DetourGetTrampolinePtr()
{
#if defined(_M_IX86)
	return hookFunX86;
#elif defined(_M_AMD64)
	return hookFunX64;
#elif defined(_M_ARM)
	return hookFunARM;
#elif defined(_M_ARM64)
	return hookFunARM64;
#endif

	return nullptr;
}

ULONG GetTrampolineSize()
{
#ifdef _M_IX86
	return sizeof(hookFunX86);
#elif defined(_M_AMD64)
	return sizeof(hookFunX64);
#elif defined(_M_ARM)
	return sizeof(hookFunARM);
#elif defined(_M_ARM64)
	return sizeof(hookFunARM64);
#endif

	return 0;
}



#if defined(_M_IX86)
extern "C" VOID* notify_caller_ms_x86(VOID* _esp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.ESP = _esp;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;
		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}

	return nullptr;
}

#elif defined(_M_AMD64)
extern "C" VOID* notify_caller_ms_x64(VOID* rcx, VOID* rdx,VOID* r8, VOID* r9, VOID* rsp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.RSP = rsp;
		info.RCX = rcx;
		info.RDX = rdx;
		info.R8 = r8;
		info.R9 = r9;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;
		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}
	
	return nullptr;
}

#elif  defined(_M_ARM64)
extern "C" VOID* notify_caller_ms_arm64(VOID* r0, VOID* r1, VOID* r2, VOID* r3, 
	VOID* r4, VOID* r5, VOID* r6, VOID* r7, 
	VOID* sp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.SP = sp;
		info.R0 = r0;
		info.R1 = r1;
		info.R2 = r2;
		info.R3 = r3;
		info.R4 = r4;
		info.R5 = r5;
		info.R6 = r6;
		info.R7 = r7;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;
		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}

	return nullptr;
}

#elif  defined(_M_ARM)
extern "C" VOID* notify_caller_ms_arm(VOID* r0, VOID* r1, VOID* r2, VOID* r3,
		VOID* sp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.SP = sp;
		info.R0 = r0;
		info.R1 = r1;
		info.R2 = r2;
		info.R3 = r3;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;
		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}

	return nullptr;
}
#endif





BOOL MakeNotifyInfoFun(_Inout_ PDETROUS_NOFITY_FUN_INFO pInfo, _In_ PF_DETOUR_HOOK_NOTIFY pNotify)
{

	UCHAR* pHookFun = pInfo->pHookFun;
	UCHAR* fun_addr = DetourGetTrampolinePtr();
	ULONG fun_size = GetTrampolineSize();
	if (fun_addr == nullptr || fun_size == 0)
	{
		return FALSE;		 
	}	
	if (fun_size > 2048)
	{
		fun_size = 2048;
	}

	pInfo->ulHookFunSize = fun_size;

	UCHAR* Ptr = nullptr;

#if defined(_M_IX86)
	Ptr = (UCHAR*)(&notify_caller_ms_x86);
#elif defined(_M_AMD64)
	Ptr =(UCHAR*)(&notify_caller_ms_x64);
#elif defined(_M_ARM64)
	Ptr = (UCHAR*)(&notify_caller_ms_arm64);
#elif defined(_M_ARM)
	Ptr = (UCHAR*)(&notify_caller_ms_arm);
#endif

	if (Ptr == nullptr)
		return FALSE;

	__int64 pAddrDst = (__int64)(ULONG_PTR)Ptr;
	memcpy_s(pHookFun, 2048, fun_addr, fun_size);

	BOOL bUpdatedFunAddr = FALSE;
	BOOL bUpdatedJmpAddr = FALSE;
	for (ULONG i = 0; i < fun_size ; i++)
	{
		ULONG* ulFunAddr = (ULONG*)(pHookFun + i);
		size_t size_ptr = sizeof(UCHAR*);
		if (!bUpdatedFunAddr && *ulFunAddr == 0xAAAAAAAA )
		{
			bUpdatedFunAddr = TRUE;
			memcpy_s(ulFunAddr, size_ptr, &pAddrDst, size_ptr);

#if defined(_M_ARM64) || defined(_M_ARM) //ARM和ARM64平台不需要构造返回地址，存储在LR寄存器里面
			return TRUE;
#endif
		}

		
		if (!bUpdatedJmpAddr && (*ulFunAddr == 0xDDDDDDDD) )
		{
			bUpdatedJmpAddr = TRUE;
			pInfo->pPointerJmpNeedUpdate = ulFunAddr;
			break;
		}
	}

	return bUpdatedJmpAddr && bUpdatedJmpAddr;
}
