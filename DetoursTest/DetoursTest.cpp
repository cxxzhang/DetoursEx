// DetoursTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <detours.h>


__declspec(noinline) int __stdcall test2(int i)
{
	std::cout << "test2 start\n";

	std::cout << "test2 end\n";
	return 0;
}

__declspec(noinline) int __stdcall test1(int i1, int i2, int i3, int i4, int i5)
{
	std::cout << "test1 start\n";

	test2(i1);
	int i_ret = i1 + i2 + i3 + i4 + i5;

	std::cout << "test1 end\n";
	return  i_ret;
}


typedef int(__stdcall*pfn_test1)(int i1, int i2, int i3, int i4, int i5);
typedef int(__stdcall*pfn_test2)(int i);
pfn_test1 true_test1_notify = nullptr;
pfn_test2 true_test2_notify = nullptr;


BOOL CALLBACK DetoursHookNoitfy(_In_ PDETROUS_HOOK_NOTIFY_INFO_STRCUT  pInfo)
{
	std::cout << "DetoursHookNoitfy called,context=" << (char*)(ULONG_PTR)pInfo->pContext << std::endl;

	return TRUE;
}


int main()
{
	
#if defined(_M_IX86)
	std::cout << "x86 start!\n\n";
#elif defined(_M_AMD64)
	std::cout << "x64 start!\n\n";
#elif defined(_M_ARM)
	std::cout << "arm start!\n\n";
#elif defined(_M_ARM64)
	std::cout << "arm64 start!\n\n";
#endif

	true_test1_notify = test1;
	
#if defined(_M_IX86) &&  defined(_DEBUG)
	UCHAR* Ptr = (UCHAR*)test1;
	Ptr = SkipJump(Ptr);
	true_test1_notify = (pfn_test1) (Ptr + 0xC);//测试一下任意内存位置的hook,这个0xC可能不同的编译器不同，只要是指令的开始位置即可。
#endif

	true_test2_notify = test2;	

	//hook
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy, (PVOID)"test1_notify");
	DetourInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy, (PVOID)"test2_notify");
	DetourTransactionCommit();
	
	test1(1, 2, 3, 4, 5);

	//unhook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourUnInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy);
	DetourUnInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy);
	DetourTransactionCommit();

	test1(1, 2, 3, 4, 5);

    std::cout << "\nend!\n";
	return 0;
}
