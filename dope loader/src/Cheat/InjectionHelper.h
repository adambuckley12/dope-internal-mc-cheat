#pragma once
#include <string>
#include "../../vendors/Singleton.h"

#include <Process/Process.h>

class InjectionHelper
{
private:
	blackbone::Process thisProc;
public:
	bool Inject(DWORD pid, void* buf, int size);
	void Unload();
};