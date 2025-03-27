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
#if defined(DETOURS_X86) || defined(DETOURS_X64)
	if (*Ptr == 0xE9)
		Ptr += *((int*)(Ptr + 1)) + 5;

#elif defined(DETOURS_ARM)	

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
	pInfo->pNotifyFn = (PVOID)pNotify;

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
LONG WINAPI DetourInstallNotify(_Inout_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify, PVOID pContext )
{
	return DetourInstallNotifyEx(ppPointer, pNotify, pContext,0);
}



#define ADD_SP_IMM_ARM_THUMB(imm) (0xB000 + (((imm) / 4) & 0x7F) + ((((imm) / 4) & 0x80) << 3))

LONG WINAPI DetourInstallNotifyEx(_Inout_ PVOID *ppPointer, _In_ PF_DETOUR_HOOK_NOTIFY pNotify, PVOID pContext,USHORT ulEspAddWhenBlock)
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
#ifdef DETOURS_ARM
	pDetour->pPointerHookRet = DETOURS_PBYTE_TO_PFUNC(pDetour->pPointerHookRet);
#endif

	if (pDetour->pPointerJmpNeedUpdate)
	{
		size_t size = sizeof(char*);
		VOID* pTmp= &pDetour->pPointerHookRet;
		VOID* pTmp2 = &pTmp;
#if defined(DETOURS_X86)//x86是FF 25到绝对地址
		memcpy(pDetour->pPointerJmpNeedUpdate, pTmp2, size);
#elif defined(DETOURS_X64)//x64是FF 25 00 00 00 00后填地址
		memcpy(pDetour->pPointerJmpNeedUpdate, pTmp, size);
#endif
	}

	if (ulEspAddWhenBlock != 0)
	{

#if defined(DETOURS_X86) || defined(DETOURS_X64)
		USHORT* pOffset = (USHORT*)(pDetour->pHookFun + pDetour->ulHookFunSize - 2);
		UCHAR* pOpear = (UCHAR*)(pDetour->pHookFun + pDetour->ulHookFunSize - 3);
		if (*pOpear == 0xC2 && *pOffset == 0)//这里故意留一个退SP用的返回值，可以在阻止的时候平衡SP信息
		{
			*pOffset = ulEspAddWhenBlock;
		}
#elif defined(DETOURS_ARM)
		USHORT* pOffset = (USHORT*)(pDetour->pHookFun + pDetour->ulHookFunSize - 0x10);
		//找到add sp,sp,#4指令
		if (*pOffset == 0xB001 && ulEspAddWhenBlock < 0x1FC - 0x4)//最大支持1FC的回退,因为这里是2字节指令，所以最大支持1FC
		{
			///*00000068:*/ 0x01, 0xB0,    //add         sp,sp,#4
			///*0000006A:*/ 0xF7, 0x46,    //mov         pc,lr
			///*0000006C:*/ 0x00, 0xBF,    //nop
			///*0000006E:*/ 0x00, 0xBF,    //nop
			///*00000070:*/ 0x00, 0xBF,    //nop
			///*00000072:*/ 0x00, 0xBF,    //nop
			UCHAR dw_offset = 4 + ulEspAddWhenBlock;
			USHORT short_new = ADD_SP_IMM_ARM_THUMB(dw_offset);
			*pOffset = short_new;
			
		}
#elif defined(DETOURS_ARM64)
		ULONG* pOpear = (ULONG*)(pDetour->pHookFun + pDetour->ulHookFunSize - 24);
		if (*pOpear == 0x910043FF && ulEspAddWhenBlock < 0xFFF - 0x10)
		{//将add sp, sp, #0x10转换成 add sp, sp, #0x10 + ulEspAddWhenBlock
			UCHAR* ch1 = (UCHAR*)pOpear;
			UCHAR* ch2 = (UCHAR*)(ch1 + 3);
			if (*ch1 == 0xFF && *ch2 == 0x91)
			{
				//FF 43 00 91   add sp, sp, #0x10
				ULONG dw_offset = *(PULONG)ch1;
				dw_offset = dw_offset >> 0xA;
				dw_offset &= 0xFFF;
				dw_offset += ulEspAddWhenBlock;

				dw_offset = dw_offset << 0xA;
				dw_offset |= 0x3FF;
				dw_offset |= 0x244 << 22;

				*pOpear = dw_offset;
		}

}
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

//#define USE_ASM_TO_BUILD
#ifndef USE_ASM_TO_BUILD

UCHAR* DetourGetTrampolinePtr()
{
#if defined(DETOURS_X86)
	return hookFunX86;
#elif defined(DETOURS_X64)
	return hookFunX64;
#elif defined(DETOURS_ARM)
	return hookFunARM;
#elif defined(DETOURS_ARM64)
	return hookFunARM64;
#endif

	return nullptr;
}

ULONG GetTrampolineSize()
{
#ifdef DETOURS_X86
	return sizeof(hookFunX86);
#elif defined(DETOURS_X64)
	return sizeof(hookFunX64);
#elif defined(DETOURS_ARM)
	return sizeof(hookFunARM);
#elif defined(DETOURS_ARM64)
	return sizeof(hookFunARM64);
#endif

	return 0;
}

#else

#if defined(DETOURS_X86) || defined(DETOURS_X64) || defined(DETOURS_ARM64) || defined(DETOURS_ARM) 
extern "C" {	
	extern void(*notify_caller_ms_asm)();
	extern void(*get_notify_caller_ms_asm_size)();
}
#else//还没适配的平台，先填个空函数吧
void notify_caller_ms_asm()
{
}
void get_notify_caller_ms_asm_size()
{
}
#endif


UCHAR* DetourGetTrampolinePtr()
{

	UCHAR* Ptr = (UCHAR*)(&notify_caller_ms_asm);
	
	Ptr = SkipJump(Ptr);

#if defined(DETOURS_ARM)	
	Ptr = (UCHAR*)DETOURS_PFUNC_TO_PBYTE(Ptr);
#endif
	return Ptr;
}

ULONG GetTrampolineSize()
{	
	UCHAR* ch1 = DetourGetTrampolinePtr();	
	UCHAR* Ptr = (UCHAR*)(&get_notify_caller_ms_asm_size);

	//获取的位置天生带了一个jmp指令
	Ptr = SkipJump(Ptr);

	ULONG code_size = (ULONG)(Ptr - ch1);

#if defined(DETOURS_ARM)
	code_size += 0x3;
#elif defined(DETOURS_ARM64)
	code_size += 0x10;
#endif

	return code_size;
}

#endif

#if defined(DETOURS_X86)
extern "C" VOID* notify_caller_ms_x86(VOID* _esp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.ESP = _esp;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;

		ULONG32* pTmp = (ULONG32*)_esp;
		--pTmp; //push ebp

		info.pEAX = --pTmp;
		info.pECX = --pTmp;
		info.pEDX = --pTmp;
		info.pEBX = --pTmp;
		info.pESP = --pTmp;
		info.pEBP = --pTmp;
		info.pESI = --pTmp;
		info.pEDI = --pTmp;

		pTmp = (ULONG32*)_esp;
		info.pParam1 = ++pTmp;//thiscall,fastcall这种用ecx传参先不考虑了
		info.pParam2 = ++pTmp;
		info.pParam3 = ++pTmp;
		info.pParam4 = ++pTmp;
		info.pParam5 = ++pTmp;
		info.pParam6 = ++pTmp;
		info.pParam7 = ++pTmp;
		info.pParam8 = ++pTmp;
		info.pParam9 = ++pTmp;
		info.pParam10 = ++pTmp;
		info.pParam11 = ++pTmp;
		info.pParam12 = ++pTmp;
		info.pParam13 = ++pTmp;
		info.pParam14 = ++pTmp;
		info.pParam15 = ++pTmp;
		info.pParam16 = ++pTmp;


		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}

	return nullptr;
}

#elif defined(DETOURS_X64)
#ifdef _WIN32
extern "C" VOID* notify_caller_ms_x64(VOID* rcx, VOID* rdx,VOID* r8, VOID* r9, VOID* rsp, PDETROUS_NOFITY_FUN_INFO pInfo)
#else
extern "C" VOID* notify_caller_ms_x64(VOID* rdi, VOID* rsi, VOID* rdx, VOID* rcx, VOID* r8, VOID* r9, VOID* rsp, PDETROUS_NOFITY_FUN_INFO pInfo)
#endif
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		ULONG64* pTmp = (ULONG64*)rsp;

		--pTmp; //push rbp

		info.RSP = rsp;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;
        info.pRSP = --pTmp;
        info.pRAX = --pTmp;
        info.pRCX = --pTmp;
        info.pRDX = --pTmp;
        info.pRBX = --pTmp;
        info.pRBP = --pTmp;
        info.pRSI = --pTmp;
        info.pRDI = --pTmp;
        info.pR8  = --pTmp;
        info.pR9  = --pTmp;
        info.pR10 = --pTmp;
        info.pR11 = --pTmp;
        info.pR12 = --pTmp;
        info.pR13 = --pTmp;
        info.pR14 = --pTmp;
        info.pR15 = --pTmp;

		//x64下，windows和linux的传参有点差异
#ifdef _WIN32
		info.pParam1 = info.pRCX;
		info.pParam2 = info.pRDX;
		info.pParam3 = info.pR8;
		info.pParam4 = info.pR9;
		pTmp = (ULONG64*)((UCHAR*)rsp + 0x20);//第5个参数应该是RSP + 0x20	
		info.pParam5 = ++pTmp;
		info.pParam6 = ++pTmp;
#else
		info.pParam1 = info.pRDI;
		info.pParam2 = info.pRSI;
		info.pParam3 = info.pRDX;
		info.pParam4 = info.pRCX;
		info.pParam5 = info.pR8;
		info.pParam6 = info.pR9;
		pTmp = (ULONG64*)((UCHAR*)rsp);	
#endif
		info.pParam7 = ++pTmp;
		info.pParam8 = ++pTmp;
		info.pParam9 = ++pTmp;
		info.pParam10 = ++pTmp;
		info.pParam11 = ++pTmp;
		info.pParam12 = ++pTmp;
		info.pParam13 = ++pTmp;
		info.pParam14 = ++pTmp;
		info.pParam15 = ++pTmp;
		info.pParam16 = ++pTmp;

		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}
	
	return nullptr;
}

#elif  defined(DETOURS_ARM64)
extern "C" VOID* notify_caller_ms_arm64(VOID* r0, VOID* r1, VOID* r2, VOID* r3, 
	VOID* r4, VOID* r5, VOID* r6, VOID* r7, 
	VOID* sp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;
		info.SP = sp;		
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;

		ULONG64* pTmp  = (ULONG64*)((UCHAR*)sp - 0x10);
		info.pX0 = pTmp;

		pTmp = (ULONG64*)((UCHAR*)sp - 0x210);
		pTmp++;//X0

		info.pX1 = ++pTmp;
		info.pX2 = ++pTmp;
		info.pX3 = ++pTmp;
		info.pX4 = ++pTmp;
		info.pX5 = ++pTmp;
		info.pX6 = ++pTmp;
		info.pX7 = ++pTmp;
		info.pX8 = ++pTmp;
		info.pX9 = ++pTmp;
		info.pX10 = ++pTmp;
		info.pX11 = ++pTmp;
		info.pX12 = ++pTmp;
		info.pX13 = ++pTmp;
		info.pX14 = ++pTmp;
		info.pX15 = ++pTmp;
		info.pX16 = ++pTmp;
		info.pX17 = ++pTmp;
		info.pX18 = ++pTmp;
		info.pX19 = ++pTmp;
		info.pX20 = ++pTmp;
		info.pX21 = ++pTmp;
		info.pX22 = ++pTmp;
		info.pX23 = ++pTmp;
		info.pX24 = ++pTmp;
		info.pX25 = ++pTmp;
		info.pX26 = ++pTmp;
		info.pX27 = ++pTmp;
		info.pX28 = ++pTmp;
		info.pX29 = ++pTmp;
		info.pX30 = ++pTmp;


		info.pParam1 = info.pX0;
		info.pParam2 = info.pX1;
		info.pParam3 = info.pX2;
		info.pParam4 = info.pX3;
		info.pParam5 = info.pX4;
		info.pParam6 = info.pX5;
		info.pParam7 = info.pX6;
		info.pParam8 = info.pX7;

		pTmp = (ULONG64*)((UCHAR*)sp);
		info.pParam9 = pTmp++;
		info.pParam10 = pTmp++;
		info.pParam11 = pTmp++;
		info.pParam12 = pTmp++;
		info.pParam13 = pTmp++;
		info.pParam14 = pTmp++;
		info.pParam15 = pTmp++;
		info.pParam16 = pTmp++;
		
		if (pNotify(&info))
		{
			return pInfo->pPointerHookRet;
		}
	}

	return nullptr;
}

#elif  defined(DETOURS_ARM)
extern "C" VOID* notify_caller_ms_arm(VOID* r0, VOID* r1, VOID* r2, VOID* r3,
		VOID* sp, PDETROUS_NOFITY_FUN_INFO pInfo)
{
	if (pInfo && pInfo->pNotifyFn)
	{
		PF_DETOUR_HOOK_NOTIFY pNotify = (PF_DETOUR_HOOK_NOTIFY)pInfo->pNotifyFn;
		DETROUS_HOOK_NOTIFY_INFO_STRCUT info;	
		info.SP = sp;
		info.pContext = pInfo->pContext;
		info.pFunInfo = pInfo;

		ULONG32* pTmp = (ULONG32*)((UCHAR*)sp - 0x40); //

		pTmp++;//R0

		info.pR0 = pTmp++;
		info.pR1 = pTmp++;
		info.pR2 = pTmp++;
		info.pR3 = pTmp++;
		info.pR4 = pTmp++;
		info.pR5 = pTmp++;
		info.pR6 = pTmp++;
		info.pR7 = pTmp++;
		info.pR8 = pTmp++;
		info.pR9 = pTmp++;
		info.pR10 = pTmp++;
		info.pR12 = pTmp++;


		pTmp = (ULONG32*)sp;
		info.pParam1 = info.pR0;
		info.pParam2 = info.pR1;
		info.pParam3 = info.pR2;
		info.pParam4 = info.pR3;
		
		info.pParam5 = pTmp++;
		info.pParam6 = pTmp++;
		info.pParam7 = pTmp++;
		info.pParam8 = pTmp++;
		info.pParam9 = pTmp++;
		info.pParam10 = pTmp++;
		info.pParam11 = pTmp++;
		info.pParam12 = pTmp++;
		info.pParam13 = pTmp++;
		info.pParam14 = pTmp++;
		info.pParam15 = pTmp++;
		info.pParam16 = pTmp++;

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

#if defined(DETOURS_X86)
	Ptr = (UCHAR*)(&notify_caller_ms_x86);
#elif defined(DETOURS_X64)
	Ptr =(UCHAR*)(&notify_caller_ms_x64);
#elif defined(DETOURS_ARM64)
	Ptr = (UCHAR*)(&notify_caller_ms_arm64);
#elif defined(DETOURS_ARM)
	Ptr = (UCHAR*)(&notify_caller_ms_arm);
#endif

	if (Ptr == nullptr)
		return FALSE;

	__int64 pAddrDst = (__int64)(ULONG_PTR)Ptr;
	memcpy(pHookFun,  fun_addr, fun_size);

	BOOL bUpdatedFunAddr = FALSE;
	BOOL bUpdatedJmpAddr = FALSE;
	for (ULONG i = 0; i < fun_size ; i++)
	{
		ULONG* ulFunAddr = (ULONG*)(pHookFun + i);
		size_t size_ptr = sizeof(UCHAR*);
		if (!bUpdatedFunAddr && (*ulFunAddr == 0xAAAAAAAA|| *ulFunAddr == 0xAABBCCDD) )
		{
			bUpdatedFunAddr = TRUE;
			memcpy(ulFunAddr, &pAddrDst, size_ptr);

#if defined(DETOURS_ARM64) || defined(DETOURS_ARM) //ARM和ARM64平台不需要构造返回地址，存储在LR寄存器里面
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
