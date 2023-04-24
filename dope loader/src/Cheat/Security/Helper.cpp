#include "pch.h"
#include "Helper.h"

#include "../../../vendors/nt.h"

#include <winternl.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <vector>
#include <dope loader/pch.h>
#include <vector>
#include <string>
#include <iostream>
#include <Windows.h>
#include <WinInet.h>
#include <iostream>
#include <fstream>

#pragma optimize("", off)

#pragma region AntiDebug
__forceinline int RemoteDebuggerPresentAPI()
{
	auto dbg_present = 0;

	CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg_present);

	return dbg_present;
}

__forceinline int NtQueryInformationProcessDebugFlags()
{
	const auto debug_flags = 0x1f;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

	auto debug_inherit = 0;

	const auto status = query_info_process(GetCurrentProcess(), debug_flags, &debug_inherit,
		sizeof(DWORD),
		nullptr);

	if (status == 0x00000000 && debug_inherit == 0)
	{
		return 1;
	}

	return 0;
}

__forceinline int NtQueryInformationProcessDebugObject()
{
	const auto debug_object_handle = 0x1e;

	const auto query_info_process = reinterpret_cast<NtQueryInformationProcessTypedef>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));

	HANDLE debug_object = nullptr;

	const auto information_length = sizeof(ULONG) * 2;

	const auto status = query_info_process(GetCurrentProcess(), debug_object_handle, &debug_object,
		information_length,
		nullptr);

	if (status == 0x00000000 && debug_object)
	{
		return 1;
	}

	return 0;
}

__forceinline bool heapDebuggerFlags() // https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PVOID pHeapBase = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + 0x30));
	DWORD dwHeapFlagsOffset = 0x70;
	DWORD dwHeapForceFlagsOffset = 0x74;

	PDWORD pdwHeapFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapFlagsOffset);
	PDWORD pdwHeapForceFlags = (PDWORD)((PBYTE)pHeapBase + dwHeapForceFlagsOffset);
	return (*pdwHeapFlags & ~HEAP_GROWABLE) || (*pdwHeapForceFlags != 0);
}

__forceinline bool HeapProtectionFlag()
{
	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}

__forceinline bool PEBBeingDebugged()
{
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	return pPeb->BeingDebugged;
}

__forceinline bool IsDebuggerPresentPatched() // https://github.com/grossekette/artemis/blob/main/Artemis.cpp
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return false;

	FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
	if (!pIsDebuggerPresent)
		return false;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
		return false;

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hSnapshot, &ProcessEntry))
		return false;

	bool bDebuggerPresent = false;
	HANDLE hProcess = NULL;
	DWORD dwFuncBytes = 0;
	const DWORD dwCurrentPID = GetCurrentProcessId();
	do
	{
		__try
		{
			if (dwCurrentPID == ProcessEntry.th32ProcessID)
				__leave;

			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessEntry.th32ProcessID);
			if (NULL == hProcess)
				__leave;

			if (!ReadProcessMemory(hProcess, pIsDebuggerPresent, &dwFuncBytes, sizeof(DWORD), NULL))
				__leave;

			if (dwFuncBytes != *(PDWORD)pIsDebuggerPresent)
			{
				bDebuggerPresent = true;
				__leave;
			}
		}
		__finally
		{
			if (hProcess)
				CloseHandle(hProcess);
			else
			{

			}
		}
	} while (Process32NextW(hSnapshot, &ProcessEntry));

	if (hSnapshot)
		CloseHandle(hSnapshot);

	return bDebuggerPresent;
}

__forceinline void PatchRemoteBreakin() // https://github.com/grossekette/artemis/blob/main/Artemis.cpp
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgUiRemoteBreakin = GetProcAddress(hNtdll, "DbgUiRemoteBreakin");
	if (!pDbgUiRemoteBreakin)
		return;

	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
		return;

	FARPROC pTerminateProcess = GetProcAddress(hKernel32, "TerminateProcess");
	if (!pTerminateProcess)
		return;

	DbgUiRemoteBreakinPatch patch = { 0 };
	patch.push_0 = '\x6A\x00';
	patch.push = '\x68';
	patch.CurrentPorcessHandle = 0xFFFFFFFF;
	patch.mov_eax = '\xB8';
	patch.TerminateProcess = (DWORD)pTerminateProcess;
	patch.call_eax = '\xFF\xD0';

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), PAGE_READWRITE, &dwOldProtect))
		return;

	::memcpy_s(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch),
		&patch, sizeof(DbgUiRemoteBreakinPatch));
	VirtualProtect(pDbgUiRemoteBreakin, sizeof(DbgUiRemoteBreakinPatch), dwOldProtect, &dwOldProtect);
}

__forceinline bool CheckHardwareBP()
{
	CONTEXT ctx;
	ZeroMemory(&ctx, sizeof(CONTEXT));
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(GetCurrentThread(), &ctx))
		return false;

	return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
}
#pragma endregion

bool Security::HasHooks()
{



	std::vector<void*> addys{
		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetModuleHandleA"),		//
		(void*)GetProcAddress(GetModuleHandleW(L"user32.dll"), "FindWindowA"),				//
		(void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegOpenKeyA"),			//
		(void*)GetProcAddress(GetModuleHandleW(L"Advapi32.dll"), "RegQueryValueExA"),		//  THEMIDIE
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread"),	//
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryVirtualMemory"),		//
		(void*)GetProcAddress(GetModuleHandleW(L"ws2_32.dll"), "recv"),
		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetVolumeInformationA"),
		(void*)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "TerminateProcess"),
		(void*)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"),

	};

	for (auto address : addys) {
		if (address) {
			while (*(BYTE*)(address) == 0x90) { // while instruction == NOP 
				address = (void*)((uintptr_t)address + 0x1);
				Sleep(1);
			}

			if (*(BYTE*)address == 0xE9 || *(BYTE*)address == 0xC3) { // JMP / RET
				return true;
			}
		}
	}

 
		return false;
}

bool Security::IsBeingDebugged()
{
	return RemoteDebuggerPresentAPI() || NtQueryInformationProcessDebugFlags() || NtQueryInformationProcessDebugObject() || heapDebuggerFlags() || HeapProtectionFlag() || PEBBeingDebugged() || IsDebuggerPresentPatched();
}

void Security::AntiAttach()
{
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll)
		return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
	if (!pDbgBreakPoint)
		return;

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return;

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // 0xC3 == RET
}

/**/
bool IsUsingVMWARE() {

		DWORD error = ERROR_SUCCESS;
	DWORD acpiDataSize = 0;
	BYTE* acpiData = NULL;
	DWORD bytesWritten = 0;

	acpiDataSize = GetSystemFirmwareTable('ACPI', 'TEPH', NULL, 0);

	acpiData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, acpiDataSize);
	if (!acpiData) {
		error = ERROR_OUTOFMEMORY;
		HeapFree(GetProcessHeap(), 0, acpiData);
		return -1;
	}

	bytesWritten = GetSystemFirmwareTable('ACPI', 'TEPH', acpiData, acpiDataSize);

	if (bytesWritten != acpiDataSize) {
		error = ERROR_INVALID_DATA;
		HeapFree(GetProcessHeap(), 0, acpiData);
		return -1;
	}

	std::string haystack(acpiData, acpiData + bytesWritten);
	return haystack.find("VMWARE") != std::string::npos;

}

bool HasVm3dgl() {

		WIN32_FIND_DATAW findFileData;
	HANDLE file = FindFirstFileW(
		L"C:\\Windows\\System32\\vm3dgl.dll",
		&findFileData
	);

	return file != INVALID_HANDLE_VALUE;

}

bool HasSuspiciousRegistery() {

		HKEY hkResult;
	LONG key = RegOpenKeyExW(
		HKEY_LOCAL_MACHINE,
		L"System\\ControlSet001\\Services\\VMTools",
		0,
		KEY_QUERY_VALUE,
		&hkResult
	);

	return key == ERROR_SUCCESS;

}

bool HasSuspiciousSpecs() {

		SYSTEM_INFO lpSystemInfo;
	GetSystemInfo(&lpSystemInfo);
	DWORD numberOfProcessors = lpSystemInfo.dwNumberOfProcessors;
	if (numberOfProcessors < 2)
		return true;

	// Check RAM
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAMMB < 2048)
		return true;

	return false;
 
}

bool Security::IsOnVM()
{
	return HasSuspiciousSpecs() || HasSuspiciousRegistery() || HasVm3dgl() || IsUsingVMWARE();
}

#pragma region txtSectionIntegrity

int GetAllModule(std::vector<LPVOID>& modules) {
	MODULEENTRY32W mEntry;
	memset(&mEntry, 0, sizeof(mEntry));
	mEntry.dwSize = sizeof(MODULEENTRY32);

	DWORD curPid = GetCurrentProcessId();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	if (Module32FirstW(hSnapshot, &mEntry)) {
		do {
			modules.emplace_back(mEntry.modBaseAddr);
		} while (Module32NextW(hSnapshot, &mEntry));
	}

	CloseHandle(hSnapshot);

	if (modules.empty()) {
		return -1;
	}

	return 0;
}

int GetTextSectionInfo(LPVOID lpModBaseAddr, PSECTIONINFO info) {
	PIMAGE_NT_HEADERS pNtHdr = ImageNtHeader(lpModBaseAddr);
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHdr + 1);

	LPVOID lpTextAddr = NULL;
	DWORD dwSizeOfRawData = NULL;

	for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; ++i) {
		char* name = (char*)pSectionHeader->Name;

		if (!strcmp(name, ".text")) {
			info->lpVirtualAddress = (LPVOID)((DWORD64)lpModBaseAddr + pSectionHeader->VirtualAddress);
			info->dwSizeOfRawData = pSectionHeader->SizeOfRawData;
			break;
		}

		++pSectionHeader;
	}

	if (info->dwSizeOfRawData == NULL) {
		return -1;
	}

	return 0;
}

DWORD64 Security::HashSection(LPVOID lpSectionAddress, DWORD dwSizeOfRawData) {
	DWORD64 hash = 0;
	BYTE* str = (BYTE*)lpSectionAddress;
	for (int i = 0; i < dwSizeOfRawData; ++i, ++str) {
		if (*str) {
			hash = *str + (hash << 6) + (hash << 16) - hash;
		}
	}

	return hash;
}
#pragma endregion

std::vector<HASHSET> Security::GetModulesSectionHash()
{
	std::vector<LPVOID> modules; GetAllModule(modules);
	std::vector<HASHSET> hashes; hashes.reserve(modules.size());

	for (auto& module : modules) {
		SECTIONINFO info;
		GetTextSectionInfo(module, &info);

		DWORD64 dwRealHash = HashSection(info.lpVirtualAddress, info.dwSizeOfRawData);
		hashes.emplace_back(HASHSET{ dwRealHash, info });
	}

	return hashes;
}

