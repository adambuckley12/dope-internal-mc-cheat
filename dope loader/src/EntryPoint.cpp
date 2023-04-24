#include "pch.h"
#include "Helper/Communication.h"

#include "Cheat/Settings.h"
#include "Cheat/InjectionHelper.h"
#include "Cheat/Security/Helper.h"

#include "Interface/UserInterface.h"

#include <fstream>
#include <filesystem>

bool EnableTokenPriviliges(HANDLE processhandle, const char* permchar)
{
	HANDLE tokenhandle;
	LUID permissionidentifier;
	TOKEN_PRIVILEGES tokenpriv;
	if (OpenProcessToken(processhandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenhandle))
	{
		if (LookupPrivilegeValue(NULL, permchar, &permissionidentifier))
		{
			tokenpriv.PrivilegeCount = 1;
			tokenpriv.Privileges[0].Luid = permissionidentifier;
			tokenpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (AdjustTokenPrivileges(tokenhandle, false, &tokenpriv, sizeof(tokenpriv), NULL, NULL)) { return true; }
			else { return false; }
		}
		else { return false; }
	}
	else { return false; }
	CloseHandle(tokenhandle);
}

int main()
{
	srand((unsigned int)time_t(NULL));
	ShowWindow(GetConsoleWindow(), SW_HIDE);

	EnableTokenPriviliges(GetCurrentProcess(), SE_SECURITY_NAME);
	EnableTokenPriviliges(GetCurrentProcess(), SE_DEBUG_NAME);

	if (Instance<Security>::Get()->IsOnVM()) {
		MessageBoxA(NULL, "The usage of virtual environment is not allowed.", "", MB_OK | MB_ICONERROR);
		exit(-1);
	}

	if (std::filesystem::exists(std::filesystem::temp_directory_path().wstring() + L"\\c2a7a660-ca80-41d9-bb09-c133f11ee957-af23d.tmp"))
	{
		abort();
	}

	auto comm = new Communication();
	if (!comm->IsLoaded()) {
		FatalAppExitW(-1, L"An error occured while initializing communication.");
	}

#pragma region Security
	std::thread([&] {
		while (true)
		{
			Instance<Security>::Get()->AntiAttach();
			if (Instance<Security>::Get()->IsBeingDebugged())
			{
#ifndef _DEBUG
				std::ofstream{ std::string(std::filesystem::temp_directory_path().string() + "\\_CL_45644114475.tmp").data() };
				abort();
#endif
			}

			Instance<Globals>::Get()->Flags.m_Heartbeats.at(0) = GetTickCount64();
			Sleep(500);
		}
	}).detach();

	std::thread([&] {
		while (true)
		{
			if (Instance<Security>::Get()->HasHooks()) {
#ifndef _DEBUG
				std::ofstream{ std::string(std::filesystem::temp_directory_path().string() + "\\_CL_45644114475.tmp").data() };
				abort();
#endif
			}

			Instance<Globals>::Get()->Flags.m_Heartbeats.at(1) = GetTickCount64();
			Sleep(500);
		}
	}).detach();

	std::thread([&] {
		auto orgSections = Instance<Security>::Get()->GetModulesSectionHash();
		while (true)
		{
#ifndef _DEBUG
			for (const auto& section : orgSections) {

				auto curHash = Instance<Security>::Get()->HashSection(section.SectionInfo.lpVirtualAddress, section.SectionInfo.dwSizeOfRawData);
				if (curHash != section.dwRealHash) {
					std::ofstream{ std::string(std::filesystem::temp_directory_path().string() + "\\_CL_45644114475.tmp").data() };
					abort();
				}
			}

			Instance<Globals>::Get()->Flags.m_Heartbeats.at(2) = GetTickCount64();
#endif
			Sleep(1000);
		}
	}).detach();
#pragma endregion

	std::thread([&comm] {
		while (!Instance<Settings>::Get()->m_Destruct) {
			Sleep(1);
			if(comm->GetBuffer())
				memcpy(comm->GetBuffer(), Instance<Settings>::Get(), sizeof(Settings));
		}
	}).detach();


	std::thread([&comm] {
		const auto userInterface = new UserInterface(850.f, 595.f);
		userInterface->Display();
		delete userInterface;
	}).detach();

#ifdef _DEBUG
	Instance<Globals>::Get()->User.m_Token = "1e4b2ad3fe2bb590";
#else
	WCHAR filePath[MAX_PATH] = { 0 };
	GetModuleFileNameW(NULL, filePath, MAX_PATH);

	std::ifstream fileStream(filePath, std::ios::ate | std::ios::binary);
	size_t size = fileStream.tellg();
	fileStream.seekg(0, std::ios::beg);
	char* buffer = new char[size];
	fileStream.read(buffer, size);

	std::string token(buffer + size - 16, 16);

	for (int i = 0; i < token.size(); i++)
		token[i] = token[i] ^ 0xd3adc0de;

	delete[] buffer;
	Instance<Globals>::Get()->User.m_Token = token.data();
#endif

	while (!Instance<Settings>::Get()->m_Destruct) {
		Sleep(1);
	}

	Sleep(3500);
	Instance<InjectionHelper>::Get()->Unload();
	delete comm;
	return 0;
}