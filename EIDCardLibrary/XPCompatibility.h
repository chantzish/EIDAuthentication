
#pragma comment(lib, "Delayimp.lib")
#include <delayimp.h>
// include this file only once in a project to give the xp compatibity
// note : using delayload hook doesn't work on a library

extern "C"
{
	FARPROC WINAPI delayHookFailureFunc (unsigned dliNotify, PDelayLoadInfo pdli);
	PfnDliHook __pfnDliFailureHook2 = delayHookFailureFunc;
}

