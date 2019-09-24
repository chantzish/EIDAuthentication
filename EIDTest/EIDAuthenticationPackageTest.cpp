// EDIAuthenticationPackageTest.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <windows.h>

#include <ntsecapi.h>
#include <intsafe.h>

#include <wincred.h>
#include <tchar.h>

#include <credentialprovider.h>
#include <lm.h>

#include <CodeAnalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable : ALL_CODE_ANALYSIS_WARNINGS)
#include <strsafe.h>
#pragma warning(pop)

#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)

#pragma comment(lib,"Secur32")


#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/Package.h"

extern HWND hMainWnd;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//

void MessageBoxStatus(NTSTATUS status) {
	MessageBoxWin32(LsaNtStatusToWinError(status));
}


void Menu_TestPackageRegistration() {
	HKEY phkResult;
	DWORD Status;
	Status=RegOpenKeyEx(HKEY_LOCAL_MACHINE,TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"),0,KEY_READ|KEY_QUERY_VALUE,&phkResult);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	DWORD RegType;
	DWORD RegSize;
	WCHAR Buffer[256];
	WCHAR* Pointer;
	RegSize = sizeof(Buffer);
	Status = RegQueryValueEx( phkResult,TEXT("Security Packages"),NULL,&RegType,(LPBYTE)&Buffer,&RegSize);
	if (Status != ERROR_SUCCESS) {
		MessageBoxWin32(Status);
		return;
	}
	RegCloseKey(phkResult);

	char bFound = FALSE;
	Pointer = Buffer;
	while (*Pointer) 
	{
		if (wcscmp(Pointer,AUTHENTICATIONPACKAGENAMEW)==0) {
			bFound = TRUE;
			break;
		}
		Pointer = Pointer + _tcslen(Pointer) + 1;
	}
	if (bFound == FALSE) {
		MessageBox(NULL,TEXT("Registery Key not found"),TEXT(""),MB_ICONASTERISK);
		return;
	}
	MessageBox(NULL,TEXT("Registery Key found"),TEXT("Success !"),MB_ICONINFORMATION);
	return;
}



void Menu_TestPackageLoad() {
	HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            hr = S_OK;
			MessageBox(NULL,TEXT("Package load successfull !"),TEXT("Success !"),MB_ICONINFORMATION);
        } else {
			MessageBoxStatus(status);
			hr = HRESULT_FROM_NT(status);
        }
    }
    else
    {
        MessageBoxStatus(status);
		hr= HRESULT_FROM_NT(status);
    }
	
	return;
}


void menu_AP_Protect()
{
	//-------------------------------------------------------------------
	// Declare and initialize variables.
    DATA_BLOB DataIn;
    DATA_BLOB DataOut;
	DATA_BLOB DataVerify;
    BYTE *pbDataInput =(BYTE *)"Hello world of data protection.";
    DWORD cbDataInput = (DWORD) (strlen((char *)pbDataInput)+1);
    DataIn.pbData = pbDataInput;
    DataIn.cbData = cbDataInput; 
	//-------------------------------------------------------------------
	//   Begin unprotect phase.
	if(CryptProtectData( &DataIn,L"This is the description string.",NULL, NULL, NULL, 0, &DataOut))
	{
		 MessageBox(0,_T("Works"), _T("Encryption"),0);
	}
	else
	{
		MessageBoxWin32(GetLastError());
		return;
	} 
	if (CryptUnprotectData(
			&DataOut,
			NULL,
			NULL,                 // Optional entropy
			NULL,                 // Reserved
			NULL, 
			//&PromptStruct,        // Optional PromptStruct
			0,
			&DataVerify))
	{
		 printf("The decrypted data is: %s\n", DataVerify.pbData);
		 MessageBox(hMainWnd,_T("The description phase worked."),_T("Info"),0);
	}
	else
	{
		MessageBoxWin32(GetLastError());
	}
	//-------------------------------------------------------------------
	// At this point, memcmp could be used to compare DataIn.pbData and 
	// DataVerify.pbDate for equality. If the two functions worked
	// correctly, the two byte strings are identical. 

	//-------------------------------------------------------------------
	//  Clean up.

	LocalFree(DataVerify.pbData);

}


void Menu_AP_Exception()
{
	int tab[10] = {1,2,3,4,5,6,7,8,9,0};
	__try
	{
		int x = 113250;
		for (int i = 0; i<10; i++)
		{
			x = x/tab[i];
		}
	}
	__except(EIDExceptionHandlerDebug(GetExceptionInformation(),FALSE))
	{
		DWORD dwException =0;// GetExceptionCode();
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NT exception 0x%08x",dwException);
		MessageBox(NULL,TEXT("Exception trapped"),TEXT(""),0);
	}
}