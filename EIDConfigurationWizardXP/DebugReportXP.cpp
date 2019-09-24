#include <windows.h>
#include <tchar.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <wmistr.h>
#include <Evntrace.h>

#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "../EIDCardLibrary/EIDAuthenticateVersion.h"

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"

#include "../EIDCardLibrary/StoredCredentialManagement.h"

#include "CContainerHolderXP.h"
#pragma comment(lib,"Credui")

TCHAR szPin[256];
// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
// selected credential
extern DWORD dwCurrentCredential;

INT_PTR CALLBACK WndProc_AskForPinDialog(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
		case WM_INITDIALOG:
			CenterWindow(hWnd);
			SetFocus(GetDlgItem(hWnd,IDC_PIN));
			break;
		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
			case IDOK:
				GetWindowText(GetDlgItem(hWnd,IDC_PIN),szPin,ARRAYSIZE(szPin));
				EndDialog(hWnd, 1);
				return TRUE;
			case IDCANCEL:
				EndDialog(hWnd, 0); 
				return TRUE;
			}
			break;
	}
	return FALSE;
}

BOOL TestLogon(HWND hMainWnd)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	CStoredCredentialManager* manager = NULL;
	TCHAR szTestPassword[] = TEXT("My_Super~Password !");
	PTSTR szRetrivedPassword = NULL;
	TCHAR szUserName[256];
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fCrypt = FALSE;
	__try
	{
		DWORD dwSize = ARRAYSIZE(szUserName);
		if (!GetUserName(szUserName, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetUserName 0X%08X",GetLastError());
			__leave;
		}
		// register the package again
		CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
		CContainer* container = MyTest->GetContainer();
		pCertContext = container->GetCertificate();
		fCrypt = (container->GetKeySpec() == AT_KEYEXCHANGE);
		if (!DialogBox(g_hinst, MAKEINTRESOURCE(IDD_ASKFORPIN), NULL, WndProc_AskForPinDialog))
		{
			dwError = ERROR_CANCELLED;
			__leave;
		}
		manager = CStoredCredentialManager::Instance();
		if (!manager->CreateCredential(GetRidFromUsername(szUserName), pCertContext,szTestPassword,0, fCrypt, FALSE))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCredential 0X%08X",GetLastError());
			__leave;
		}
		if (!manager->GetPassword(GetRidFromUsername(szUserName), pCertContext, szPin, &szRetrivedPassword))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetPassword 0X%08X",GetLastError());
			__leave;
		}
		if (_tcscmp(szRetrivedPassword, szTestPassword) != 0)
		{
			dwError = ERROR_INTERNAL_ERROR;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Password don't match %s %s",szRetrivedPassword, szTestPassword);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		SecureZeroMemory(szPin, ARRAYSIZE(szPin)*sizeof(TCHAR));
		if (szRetrivedPassword)
			EIDFree(szRetrivedPassword);
		if (manager)
		{
			if (!manager->RemoveStoredCredential(GetRidFromUsername(szUserName)))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RemoveStoredCredential 0X%08X",GetLastError());
			}
		}
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL DoTheActionToBeTraced()
{
	DWORD dwError;
	BOOL fSuccess = FALSE;
	PCCERT_CONTEXT pCertContext = NULL;
	__try
	{
		
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Starting report");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Version : %S", EIDAuthenticateVersionText);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Register the certificate");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		// register the package again
		CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
		CContainer* container = MyTest->GetContainer();
		pCertContext = container->GetCertificate();
		fSuccess = LsaEIDCreateStoredCredential(szUserName, szPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
		if (!fSuccess)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test failed with 0x%08X", dwError);
			__leave;
		}
		
		// call for a test
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test Logon");
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
		if (!TestLogon(NULL))
		{
			dwError = GetLastError();
			if (dwError == ERROR_CANCELLED)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"TestLogonCancelled");
				__leave;
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test failed with 0x%08X", dwError);
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success !!!");
		fSuccess = TRUE;
	}
	__finally
	{
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Ending tests");
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"===============");
	SetLastError(dwError);
	return fSuccess;
}

BOOL SendReport(DWORD dwErrorCode, PTSTR szEmail, PCCERT_CONTEXT pCertContext)
{
	DWORD dwRetVal;
	UINT uRetVal;
	TCHAR lpTempPathBuffer[MAX_PATH];
	TCHAR szTempFileName[MAX_PATH] = TEXT("");
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	LONG lStatus;
	BOOL fHasLogFile = FALSE;
	WCHAR szLogFileSaved[255];
	BOOL fHasLogLevel = FALSE;
	DWORD dwLogLevelSaved;
	DWORD dwLogLevel = 10;
	HKEY hKey = NULL;
	__try
	{
		// create a unique temp file
		// we need to use a temp file to communicate between the elevated process and this one
		// we can also use a pipe.
		dwRetVal = GetTempPath(MAX_PATH, lpTempPathBuffer);
		if (dwRetVal > MAX_PATH || (dwRetVal == 0))
		{
			dwError = GetLastError();
			__leave;
		}
		uRetVal = GetTempFileName(lpTempPathBuffer, TEXT("EIDAUTHENTICATE"), 0, szTempFileName);
		if (uRetVal == 0)
		{
			dwError = GetLastError();
			__leave;
		}
		// get the old tracing configuration
		lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hKey);
		if (lStatus != ERROR_SUCCESS)
		{
			dwError = lStatus;
			__leave;
		}
		DWORD dwSize = ARRAYSIZE(szLogFileSaved) *sizeof(WCHAR);
		lStatus = RegQueryValueEx(hKey,TEXT("EIDLogFile"), NULL, NULL,(PBYTE)szLogFileSaved,&dwSize);
		if (lStatus == ERROR_SUCCESS)
		{
			fHasLogFile = TRUE;
		}
		dwSize = sizeof(dwLogLevelSaved);
		lStatus = RegQueryValueEx(hKey,TEXT("EIDLogLevel"), NULL, NULL,(PBYTE)&dwLogLevelSaved,&dwSize);
		if (lStatus == ERROR_SUCCESS)
		{
			fHasLogLevel = TRUE;
		}
		// set the new log parameter
		lStatus = RegSetValueEx (hKey, TEXT("EIDLogFile"), 0, REG_SZ, (PBYTE) szTempFileName, (_tcslen(szTempFileName) + 1)*sizeof(TCHAR));
		if (lStatus  !=ERROR_SUCCESS)
		{
			dwError = lStatus;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x (not enough privilege ?)",lStatus );
			__leave;
		}
		lStatus = RegSetValueEx (hKey, TEXT("EIDLogLevel"), 0, REG_DWORD, (PBYTE) &dwLogLevel, sizeof(DWORD));
		if (lStatus  !=ERROR_SUCCESS)
		{
			dwError = lStatus;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x",lStatus );
			__leave;
		}
		// wait for the configuration to be taken care of
		Sleep(1000);
		DoTheActionToBeTraced();
		// activate the tracing
		if (!CommunicateTestNotOK(dwErrorCode, szEmail, szTempFileName,pCertContext))
		{
			dwError = GetLastError();
			__leave;
		}
		
		fReturn = TRUE;
	}
	__finally
	{
		if (_tcslen(szTempFileName) > 0)
		{
			DeleteFile(szTempFileName);
		}
		if (hKey) 
		{
			// revert back the tracing configuration
			if (fHasLogFile)
			{
				lStatus = RegSetValueEx (hKey, TEXT("EIDLogFile"), 0, REG_SZ, (PBYTE) szLogFileSaved, (_tcslen(szLogFileSaved) + 1)*sizeof(TCHAR));
				if (lStatus  !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x",lStatus );
				}
			}
			else
			{
				lStatus = RegDeleteValue(hKey, TEXT("EIDLogFile"));
				if (lStatus  !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegDeleteValue 0x%08x",lStatus );
				}
			}
			if (fHasLogLevel)
			{
				lStatus = RegSetValueEx (hKey, TEXT("EIDLogLevel"), 0, REG_DWORD, (PBYTE) &dwLogLevelSaved, sizeof(DWORD));
				if (lStatus  !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x",lStatus );
				}
			}
			else
			{
				lStatus = RegDeleteValue(hKey, TEXT("EIDLogLevel"));
				if (lStatus  !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegDeleteValue 0x%08x",lStatus );
				}
			}
			RegCloseKey(hKey);
		}
	}
	SetLastError(dwError);
	return fReturn;
}