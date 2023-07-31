// DetoursTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
#include <Windows.h>
#include <detours.h>


__declspec(noinline) int __stdcall test2(int i)
{
	std::cout << "test2 start,i=" << i  << std::endl;

	std::cout << "test2 end\n";
	return 0;
}

__declspec(noinline) int __stdcall test1(int i1, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11, int i12, int i13, int i14, int i15,int i16)
{
	std::cout << "test1 start\n";	

   int i_ret = i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9 + i10 + i11 + i12 + i13 + i14 + i15 + i16;

   test2(i_ret);

	std::cout << "test1 end\n";
	return  i_ret;
}


BOOL CALLBACK DetoursHookNoitfy(_In_ PDETROUS_HOOK_NOTIFY_INFO_STRCUT  pInfo)
{
	std::string str_context = (char*)(ULONG_PTR)pInfo->pContext;

	if (str_context.find("test1_notify") != -1)
	{
		std::cout << "DetoursHookNoitfy called,context=" << str_context
			<< ",i1=" << *(int*)pInfo->pParam1
			<< ",i16=" << *(int*)pInfo->pParam16
			<< std::endl;
	}
	else if (str_context.find("test2_notify") != -1)
	{

		std::cout << "DetoursHookNoitfy called,context=" << str_context
			<< ",i1=" << *(int*)pInfo->pParam1
			<< std::endl;

		*(int*)pInfo->pParam1 = 10086;

		std::cout << "modify pParam to " << *(int*)pInfo->pParam1	<< std::endl;

	}


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

	UCHAR *true_test1_notify = (UCHAR *)test1;
    UCHAR *true_test2_notify = (UCHAR *)test2;	
	
	//hook
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy, (PVOID)"test1_notify");
	DetourInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy, (PVOID)"test2_notify");
	DetourTransactionCommit();
	
	test1(1, 2, 3, 4, 5,6,7,8,9,10,11,12,13,14,15,16);

	std::cout << "\nunhook\n\n";
	//unhook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourUnInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy);
	DetourUnInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy);
	DetourTransactionCommit();

	test1(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);

    std::cout << "\nend!\n";
	return 0;
}
