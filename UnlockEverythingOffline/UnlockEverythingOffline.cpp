#include "pch.h"

using handle = std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&CloseHandle)>;

struct module
{
	uintptr_t dwBase, dwSize;
} kernelbase_dll, rainbowsix_exe;

module GetModule(const char* moduleName, uintptr_t process_id) {
	module TargetModule;
	HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	MODULEENTRY32 mEntry;
	mEntry.dwSize = sizeof(mEntry);

	do {
		if (!strcmp(mEntry.szModule, (LPSTR)moduleName)) {
			CloseHandle(hmodule);

			TargetModule = { (uintptr_t)mEntry.hModule, mEntry.modBaseSize };
			return TargetModule;
		}
	} while (Module32Next(hmodule, &mEntry));

	module mod = { (uintptr_t)false, (uintptr_t)false };
	return mod;
}

uintptr_t ProcessId()
{
	handle snap_shot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

	if (snap_shot.get() == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32 process_entry{ sizeof(PROCESSENTRY32) };

	for (Process32First(snap_shot.get(), &process_entry); Process32Next(snap_shot.get(), &process_entry); )
		if (!_strcmpi(process_entry.szExeFile, "RainbowSix.exe"))
			return static_cast<std::uintptr_t>(process_entry.th32ProcessID);

	return 0;
}

void UnlockEverything(HANDLE hndl, uintptr_t r6s_base)
{

	BYTE tmp = 0;
	const BYTE zero = 0x0;

	ReadProcessMemory(hndl, (LPCVOID)(r6s_base + 0x133FB18), &tmp, sizeof(tmp), nullptr);

	if (tmp == 0x0)
	{
		std::cout << colorwin::color(colorwin::green) << "[+] Unlock everything is already activated.\n";
	}
	else if (tmp == 0x1)
	{
		std::cout << colorwin::color(colorwin::green) << "[+] Activating 'unlock everything'...\n";
		WriteProcessMemory(hndl, (LPVOID)(r6s_base + 0x133FB18), &zero, sizeof(zero), nullptr);
		ReadProcessMemory(hndl, (LPCVOID)(r6s_base + 0x133FB18), &tmp, sizeof(tmp), nullptr);
		if (tmp == 0x0)
		{
			std::cout << colorwin::color(colorwin::green) << "[+] 'Unlock everything' is successfully activated.\n";
		}
		else if (tmp == 0x1)
		{
			printf("'Unlock everything' could not be activated.\n");
			std::cout << colorwin::color(colorwin::red) << "[-] 'Unlock everything' could not be activated.\n";
		}
		else
		{
			std::cout << colorwin::color(colorwin::red) << "[-] Unknown result #1 in function " << __FUNCTION__ << ", contact the developer.\n";
		}
	}
	else
	{
		std::cout << colorwin::color(colorwin::red) << "[-] Unknown result #2 in function " << __FUNCTION__ << ", contact the developer.\n";
	}
}

bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++bData, ++bMask) {
		if (*szMask == 'x' && *bData != *bMask) {
			return false;
		}
	}
	return (*szMask == NULL);
}

uintptr_t FindSignature(HANDLE hndl, uintptr_t kernelbase_dll_base, DWORD size, const char* sig, const char* mask)
{
	BYTE* data = new BYTE[size];
	SIZE_T bytesRead;

	ReadProcessMemory(hndl, (LPCVOID)kernelbase_dll_base, data, size, &bytesRead);

	for (DWORD i = 0; i < size; i++)
	{
		if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
			return kernelbase_dll_base + i;
		}
	}
	delete[] data;
	return NULL;
}

int main()
{

	std::cout << colorwin::color(colorwin::red) << R"(
                _                 _           _           
               | |               | |         | |          
   ___ ___   __| | _____  ___ __ | | ___   __| | ___ _ __ 
  / __/ _ \ / _` |/ _ \ \/ / '_ \| |/ _ \ / _` |/ _ \ '__|
 | (_| (_) | (_| |  __/>  <| |_) | | (_) | (_| |  __/ |   
  \___\___/ \__,_|\___/_/\_\ .__/|_|\___/ \__,_|\___|_|   
                           | |                            
                           |_|                            
	)" << "\n";


	uintptr_t _process_id = ProcessId();

	if (ProcessId() == 0)
	{
		std::cout << colorwin::color(colorwin::red) << "[-] RainbowSix.exe not launched: " << std::endl;
		std::cout << colorwin::color(colorwin::red) << "[-] Exiting... " << std::endl;
		return 1;
	}

	HANDLE hndl = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _process_id);
	
	kernelbase_dll = GetModule("KERNELBASE.dll", _process_id);
	rainbowsix_exe = GetModule("RainbowSix.exe", _process_id);
	
	std::cout << colorwin::color(colorwin::green) << "[+] KERNELBASE.dll module base: " << std::hex << kernelbase_dll.dwBase << std::endl;
	//std::cout << "[+]kernelbase_dll.dwSize " << std::hex << kernelbase_dll.dwSize << std::endl;
	std::cout << colorwin::color(colorwin::green) << "[+] RainbowSix_exe module base: " << std::hex << rainbowsix_exe.dwBase << std::endl;
	//std::cout << "[+]rainbowsix_exe.dwSize " << std::hex << rainbowsix_exe.dwSize << std::endl;
	//std::cout << "kernelbase_dll_dwSize " << kernelbase_dll_dwSize << std::endl;
	const char * sig_original = "\x48\x89\x5C\x24\x08\x57\x48\x83\xEC\x20\x8B\xFA\x48\x8B\xD9\x48";
	const char * sig_tampered = "\x48\xC3\x5C\x24\x08\x57\x48\x83\xEC\x20\x8B\xFA\x48\x8B\xD9\x48";
	const char * mask = "xxxxxxxxxxxxxxxx";

	std::cout << colorwin::color(colorwin::green) << "[+] TerminateProcess address: " << FindSignature(hndl, kernelbase_dll.dwBase, kernelbase_dll.dwSize, sig_tampered, mask) << std::endl;

	uintptr_t original_address = FindSignature(hndl, kernelbase_dll.dwBase, kernelbase_dll.dwSize, sig_original, mask);
	uintptr_t tampered_address = FindSignature(hndl, kernelbase_dll.dwBase, kernelbase_dll.dwSize, sig_tampered, mask);

	/*if(original_address == NULL)
	{
		std::cout << "original_address is NULL" << std::endl;
	}
	if(tampered_address == NULL)
	{
		std::cout << "tampered_address is NULL" << std::endl;
	}*/

	BYTE tmp = 0;
	const BYTE mov = 0x89; // mov opcode
	const BYTE ret = 0xC3; // ret opcode

	if (tampered_address == NULL && original_address != NULL)
	{
		std::cout << colorwin::color(colorwin::green) << "[+] Original instruction found in kernelbase.dll\n";
		std::cout << colorwin::color(colorwin::green) << "[+] Disabling integrity checks\n";
		WriteProcessMemory(hndl, (LPVOID)(original_address + 0x1), &ret, sizeof(ret), nullptr);
		ReadProcessMemory(hndl, (LPCVOID)(original_address + 0x1), &tmp, sizeof(tmp), nullptr);
		if (tmp == mov)
		{
			std::cout << colorwin::color(colorwin::red) << "[-] Integrity checks could not be disabled...\n";
			std::cout << colorwin::color(colorwin::red) << "[-] Exiting\n";
			return 1;
		}
		else if (tmp == ret)
		{
			std::cout << colorwin::color(colorwin::green) << "[+] Integrity checks successfully disabled...\n";
			UnlockEverything(hndl, rainbowsix_exe.dwBase);

		} else
		{
			std::cout << colorwin::color(colorwin::red) << "[-] Unknown result #1, contact the developer.\n";
			return 1;
		}
	} else if (tampered_address != NULL && original_address == NULL)
	{
		std::cout << colorwin::color(colorwin::green) << "[+] Integrity checks already disabled. No need to disable it.\n";
		UnlockEverything(hndl, rainbowsix_exe.dwBase);

	}
	else
	{
		std::cout << colorwin::color(colorwin::red) << "[-] Unknown result #2 in function " << __FUNCTION__ << ", contact the developer.\n";
	}

	CloseHandle(hndl);

	std::this_thread::sleep_for(std::chrono::seconds(10));

	return 0;

}


