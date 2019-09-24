// DLLMain.cpp : Defines the entry point for the GINA DLL.
//
#include <Windows.h>

#include "..\EIDCardLibrary\XPCompatibility.h"
#pragma comment(lib,"Winscard")
#pragma comment(lib,"Crypt32")

// this is the one and only global variable we use, and it's implemented to be read-only
static HANDLE _hModule;

HMODULE   GetMyModuleHandle() { return (HMODULE)_hModule; }
HINSTANCE GetMyInstance()     { return (HINSTANCE)_hModule; }

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  reason, 
                       LPVOID lpReserved
					 )
{
    if (DLL_PROCESS_ATTACH == reason) {
        _hModule = hModule;
        // memory leak when linked statically
		//DisableThreadLibraryCalls(GetMyModuleHandle());
    }
    return TRUE;
}

