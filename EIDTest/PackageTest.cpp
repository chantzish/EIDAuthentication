
#include <windows.h>
#include <Ntsecapi.h>
#include <credentialprovider.h>
#include <lm.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "EIDTestUIUtil.h"

extern HWND hMainWnd;

void menu_CRED_CallAuthPackage()
{
	/*LPWSTR swImagePath = NULL;
	ULONG swImagePathLen = 0;
	WCHAR UserNameBuffer[UNLEN+1];
	WCHAR ComputerNameBuffer[UNLEN+1];
	HRESULT Status;
	if (AskUsername(UserNameBuffer,ComputerNameBuffer))
	{
		Status = CallAuthPackage(UserNameBuffer,&swImagePath,&swImagePathLen);
		if (SUCCEEDED(Status))
		{
			MessageBoxW(hMainWnd,swImagePath,L"ImagePath",0);
			LsaFreeMemory((PVOID)*swImagePath);
		}
		else
		{
			MessageBoxW(hMainWnd,L"Failure",L"ImagePath",0);
		}
	}*/
}