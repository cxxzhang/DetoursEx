// DetoursTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <string>
#include <memory>

#ifdef _WIN32
#include <Windows.h>
#define TEST_CALL_TYPE __stdcall
#else
#define TEST_CALL_TYPE
#endif

#include <detours.h>


#ifdef _WIN32
__declspec(noinline) 
#endif
int TEST_CALL_TYPE  test2(int i)
{
	std::cout << "test2 start,i=" << i << std::endl;

	std::cout << "test2 end\n";
	return 0;
}

typedef int (TEST_CALL_TYPE*  Api_test2)(int i);
Api_test2 true_test2 = NULL;

int TEST_CALL_TYPE hook_test2(int i)
{
	std::cout << "hook_test2 start\n";

	int i_ret = true_test2(i+100);

	std::cout << "hook_test2 end\n";
	return i_ret;
}



#ifdef _WIN32
__declspec(noinline)
#endif
int TEST_CALL_TYPE test1(int i1, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, int i10, int i11, int i12, int i13, int i14, int i15, int i16)
{
	std::cout << "test1 start\n";

	int i_ret = i1 + i2 + i3 + i4 + i5 + i6 + i7 + i8 + i9 + i10 + i11 + i12 + i13 + i14 + i15 + i16;

	test2(i_ret);

	std::cout << "test1 end\n";
	return  i_ret;
}


class TestClass {
public:
	TestClass() {};
	long TEST_CALL_TYPE call(long a, long b)
	{
		std::cout << "TestClass::call start\n";
		long l_ret =  m_i + a + b;

		std::cout << "TestClass::call end ,ret "<< l_ret <<"\n";

		return  l_ret;
	}

private:
	long m_i = 100;
};





class HookTestClass {
public:
	long TEST_CALL_TYPE call(long a, long b)
	{
		std::cout << "HookTestClass::call start\n";
		long l_ret = (this->*m_true_call)(a+10,b+10);

		std::cout << "HookTestClass::call end\n";

		return  l_ret;
	}
public:
	typedef long (TEST_CALL_TYPE  HookTestClass::*Api_hook_testclass_call)(long, long);
	static Api_hook_testclass_call m_true_call;
};

typedef long (TEST_CALL_TYPE  HookTestClass::*Api_hook_testclass_call)(long, long);
typedef long (TEST_CALL_TYPE  TestClass::*Api_true_testclass_call)(long, long);

Api_hook_testclass_call HookTestClass::m_true_call = NULL;


BOOL WINAPI DetoursHookNoitfy(_In_ PDETROUS_HOOK_NOTIFY_INFO_STRCUT  pInfo)
{
	std::string str_context = (char*)(ULONG_PTR)pInfo->pContext;

	if (str_context.find("test1_notify") != -1)
	{
		std::cout << "DetoursHookNoitfy called,context=" << str_context
			<< ",i1=" << *(int*)pInfo->pParam1
			<< ",i16=" << *(int*)pInfo->pParam16
			<< std::endl;

		*(int*)pInfo->pParam1 = 10086;//如果不在函数的起始位置hook的话，一般不能返回阻止(平衡栈，一些析构函数的执行等)，但是修改参数的方式让它失败。
		
	}
	else if (str_context.find("test2_notify") != -1)
	{
		std::cout << "DetoursHookNoitfy called,context=" << str_context
			<< ",i1=" << *(int*)pInfo->pParam1			
			<< std::endl;
	}
	else if (str_context.find("test3_notify") != -1)
	{

		std::cout << "DetoursHookNoitfy called,context=" << str_context
			<< ",i1=" << *(int*)pInfo->pParam2
			<< std::endl;
	}


	return TRUE;
}


//s_rceCopyTable
int main()
{

#if defined(DETOURS_X86)
	std::cout << "x86 start!\n\n";
#elif defined(DETOURS_X64)
	std::cout << "x64 start!\n\n";
#elif defined(DETOURS_ARM)
	std::cout << "arm start!\n\n";
#elif defined(DETOURS_ARM64)
	std::cout << "arm64 start!\n\n";
#endif	

	true_test2 = test2;

	auto true_tmp = &TestClass::call;
	HookTestClass::m_true_call = (Api_hook_testclass_call)true_tmp;

	auto hook_tmp = &HookTestClass::call;	
	UCHAR *hook_call = (UCHAR *)*(&(PVOID&)hook_tmp);

	UCHAR *true_test1_notify = (UCHAR *)test1;
	UCHAR *true_test2_notify = (UCHAR *)true_test2;
	UCHAR *true_test3_notify = (UCHAR *)*(&(PVOID&)true_tmp);

	

	std::unique_ptr<TestClass> test_class = std::make_unique<TestClass>();

//#define TEST_ORG_HOOK

	//hook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
#ifdef TEST_ORG_HOOK
	DetourAttach(&(PVOID&)true_test2, (PVOID)hook_test2);
	DetourAttach(&(PVOID&)HookTestClass::m_true_call, (PVOID)hook_call);
#else
	DetourInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy, (PVOID)"test1_notify");
	DetourInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy, (PVOID)"test2_notify");
	DetourInstallNotify(&(PVOID&)true_test3_notify, DetoursHookNoitfy, (PVOID)"test3_notify");
#endif
	DetourTransactionCommit();

	test1(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
	test_class->call(10, 20);

	std::cout << "\nunhook\n\n";
	//unhook
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
#ifdef TEST_ORG_HOOK
	DetourDetach(&(PVOID&)true_test2, (PVOID)hook_test2);
	DetourDetach(&(PVOID&)HookTestClass::m_true_call, (PVOID)hook_call);
#else
	DetourUnInstallNotify(&(PVOID&)true_test1_notify, DetoursHookNoitfy);
	DetourUnInstallNotify(&(PVOID&)true_test2_notify, DetoursHookNoitfy);
	DetourUnInstallNotify(&(PVOID&)true_test3_notify, DetoursHookNoitfy);
#endif
	DetourTransactionCommit();

	test1(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
	test_class->call(10, 20);

	

	std::cout << "\nend!\n";
	return 0;
}
