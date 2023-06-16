# DetoursEx
Modified by Mircosoft detours.Support Window/Linux/Macos. Support X86/x64/ARM64/ARM/MIPS/LongArch. 
Can Hook in any address but not only the function beginning address.

## Usage

```c++
__declspec(noinline) int test1(int i1, int i2, int i3, int i4, int i5)
{
	std::cout << "test1 start\n";

	test2(i1);
	int i_ret = i1 + i2 + i3 + i4 + i5;

	std::cout << "test1 end\n";
	return  i_ret;
}

int hook_test1(int i1, int i2, int i3, int i4, int i5)
{
	std::cout << "hook_test1 start\n";

	int i_ret = true_test1(i1, i2, i3, i4, i5);

	std::cout << "hook_test1 end\n";
	return i_ret;
}

BOOL CALLBACK DetoursHookNoitfy(_In_ PDETROUS_HOOK_NOTIFY_INFO_STRCUT  pInfo)
{
	std::cout << "DetoursHookNoitfy called,context=" << (int)(ULONG_PTR)pInfo->pContext << std::endl;

	return TRUE;//return FALSE means block
}

typedef int(*pfn_test1)(int i1, int i2, int i3, int i4, int i5);
pfn_test1 true_test1 = nullptr;

int test_hook()
{
	DetourRestoreAfterWith();
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
 #if 0
	DetourAttach(&(PVOID&)true_test1, hook_test1);
 #else
	DetourInstallNotify(&(PVOID&)true_test1, DetoursHookNoitfy, (PVOID)1);
 #endif
	DetourTransactionCommit();
}
```
