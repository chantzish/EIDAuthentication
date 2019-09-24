
#include <windows.h>
#include <tchar.h>
#include <delayimp.h>
#include <evntprov.h>
#include <Wmistr.h>
#include <evntrace.h>
#include <wincred.h>

// to compil with windows XP

DWORD  RegistryCheckLastTime = {0};
WCHAR szLogFile[255] = L"c:\\EIDGinalog.txt";
DWORD dwLogLevel = 0;

extern "C"
{

	LONG WINAPI RegSetKeyValueXP(
	  __in      HKEY hKey,
	  __in_opt  LPCTSTR lpSubKey,
	  __in_opt  LPCTSTR lpValueName,
	  __in      DWORD dwType,
	  __in_opt  LPCVOID lpData,
	  __in      DWORD cbData
	)
	{
		HKEY hTempKey;
		LONG lResult;
		lResult = RegCreateKeyEx(hKey, lpSubKey, 0,NULL,0,KEY_WRITE, NULL,&hTempKey,NULL);
		if (lResult != ERROR_SUCCESS) return lResult;
		lResult = RegSetValueEx( hTempKey,lpValueName,0, dwType,  (PBYTE) lpData,cbData);
		RegCloseKey(hKey);
		return lResult;
	}

	ULONG WINAPI EventRegisterXP(
		__in LPCGUID ProviderId,
		__in_opt PENABLECALLBACK EnableCallback,
		__in_opt PVOID CallbackContext,
		__out PREGHANDLE RegHandle
		)
	{
		UNREFERENCED_PARAMETER(ProviderId);
		UNREFERENCED_PARAMETER(EnableCallback);
		UNREFERENCED_PARAMETER(CallbackContext);
		UNREFERENCED_PARAMETER(RegHandle);
		return 0;
	}

	ULONG WINAPI EventUnregisterXP(
		__in REGHANDLE RegHandle
		)
	{
		UNREFERENCED_PARAMETER(RegHandle);
		return 0;
	}

	VOID UpdateParameter()
	{
		// check registry
		HKEY hKey = NULL;
		__try
		{
			LONG lStatus;
			lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ|KEY_QUERY_VALUE, &hKey);
			if (lStatus != ERROR_SUCCESS)
			{
				__leave;
			}
			DWORD dwSize = ARRAYSIZE(szLogFile) *sizeof(WCHAR);
			lStatus = RegQueryValueEx(hKey,TEXT("EIDLogFile"), NULL, NULL,(PBYTE)szLogFile,&dwSize);
			if (lStatus != ERROR_SUCCESS)
			{

			}
			dwSize = sizeof(dwLogLevel);
			lStatus = RegQueryValueEx(hKey,TEXT("EIDLogLevel"), NULL, NULL,(PBYTE)&dwLogLevel,&dwSize);
			if (lStatus != ERROR_SUCCESS)
			{
				dwLogLevel = 0;
			}
		}
		__finally
		{
			if (hKey) RegCloseKey(hKey);
		}
	}

	ULONG WINAPI EventWriteStringXP(
		__in REGHANDLE RegHandle,
		__in UCHAR Level,
		__in ULONGLONG Keyword,
		__in PCWSTR String
		)
	{
		UNREFERENCED_PARAMETER(RegHandle);
		UNREFERENCED_PARAMETER(Keyword);
		DWORD Now = GetTickCount(); // number of milisecond since last restart
		if ((Now - RegistryCheckLastTime) > 1000 || RegistryCheckLastTime > Now) // 1 second
		{
			UpdateParameter();
			RegistryCheckLastTime = Now;
		}
		if (Level <= dwLogLevel)
		{
			HANDLE h = CreateFile(szLogFile, GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_ALWAYS, 0, 0);
			if (INVALID_HANDLE_VALUE != h) {
				if (INVALID_SET_FILE_POINTER != SetFilePointer(h, 0, 0, FILE_END)) {
					DWORD cb;
					SYSTEMTIME st;
					GetSystemTime(&st);
					TCHAR szLocalDate[255], szLocalTime[255];
					_stprintf_s(szLocalDate, ARRAYSIZE(szLocalDate),TEXT("%04d-%02d-%02d"),st.wYear,st.wMonth,st.wDay);
					_stprintf_s(szLocalTime, ARRAYSIZE(szLocalTime),TEXT("%02d:%02d:%02d"),st.wHour,st.wMinute,st.wSecond);
					WriteFile ( h, szLocalDate, (DWORD)_tcslen(szLocalDate) * (DWORD)sizeof(TCHAR), &cb, NULL);
					WriteFile ( h, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &cb, NULL);
					WriteFile ( h, szLocalTime, (DWORD)_tcslen(szLocalTime) * (DWORD)sizeof(TCHAR), &cb, NULL);
					WriteFile ( h, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &cb, NULL);
					cb = (DWORD) (wcslen(String) * sizeof(WCHAR));
					WriteFile(h, String, cb, &cb, 0);
					WCHAR szEndLine[] = L"\r\n";
					cb = 2 * sizeof(WCHAR);
					WriteFile(h, szEndLine, cb, &cb, 0);
				}
				FlushFileBuffers(h);
				CloseHandle(h);
			}
		}
		return 0;
	}

	ULONG WINAPI EnableTraceExXP(
		__in LPCGUID ProviderId,
		__in_opt LPCGUID SourceId,
		__in TRACEHANDLE TraceHandle,
		__in ULONG IsEnabled,
		__in UCHAR Level,
		__in ULONGLONG MatchAnyKeyword,
		__in ULONGLONG MatchAllKeyword,
		__in ULONG EnableProperty,
		__in_opt PEVENT_FILTER_DESCRIPTOR EnableFilterDesc
		)
	{
		UNREFERENCED_PARAMETER(ProviderId);
		UNREFERENCED_PARAMETER(SourceId);
		UNREFERENCED_PARAMETER(TraceHandle);
		UNREFERENCED_PARAMETER(IsEnabled);
		UNREFERENCED_PARAMETER(Level);
		UNREFERENCED_PARAMETER(MatchAnyKeyword);
		UNREFERENCED_PARAMETER(MatchAllKeyword);
		UNREFERENCED_PARAMETER(EnableProperty);
		UNREFERENCED_PARAMETER(EnableFilterDesc);
		return 0;
	}

	//*************************************************************
	//
	//  RegDelnodeRecurse()
	//
	//  Purpose:    Deletes a registry key and all its subkeys / values.
	//
	//  Parameters: hKeyRoot    -   Root key
	//              lpSubKey    -   SubKey to delete
	//
	//  Return:     LSTATUS
	//
	//*************************************************************

	LSTATUS RegDelnodeRecurse (HKEY hKeyRoot, LPTSTR lpSubKey)
	{
		LPTSTR lpEnd;
		LONG lResult;
		DWORD dwSize;
		TCHAR szName[MAX_PATH*2];
		HKEY hKey;
		FILETIME ftWrite;

		// First, see if we can delete the key without having
		// to recurse.

		lResult = RegDeleteKey(hKeyRoot, lpSubKey);

		if (lResult == ERROR_SUCCESS) 
			return lResult;

		lResult = RegOpenKeyEx (hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

		if (lResult != ERROR_SUCCESS) 
		{
			if (lResult == ERROR_FILE_NOT_FOUND) {
				return ERROR_SUCCESS;
			} 
			else {
				return lResult;
			}
		}

		// Check for an ending slash and add one if it is missing.

		lpEnd = lpSubKey + _tcsclen(lpSubKey);

		if (*(lpEnd - 1) != TEXT('\\')) 
		{
			*lpEnd =  TEXT('\\');
			lpEnd++;
			*lpEnd =  TEXT('\0');
		}

		// Enumerate the keys

		dwSize = MAX_PATH;
		lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
							   NULL, NULL, &ftWrite);

		if (lResult == ERROR_SUCCESS) 
		{
			do {

				_tcscpy_s (lpEnd, MAX_PATH*2 - _tcsclen(lpSubKey), szName);
				if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
					break;
				}
				dwSize = MAX_PATH;
				lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
									   NULL, NULL, &ftWrite);

			} while (lResult == ERROR_SUCCESS);
		}

		lpEnd--;
		*lpEnd = TEXT('\0');

		RegCloseKey (hKey);

		// Try again to delete the key.

		lResult = RegDeleteKey(hKeyRoot, lpSubKey);

    
		return lResult;
	}

	//*************************************************************
	//
	//  RegDelnode()
	//
	//  Purpose:    Deletes a registry key and all its subkeys / values.
	//
	//  Parameters: hKeyRoot    -   Root key
	//              lpSubKey    -   SubKey to delete
	//
	//  Return:     TRUE if successful.
	//              FALSE if an error occurs.
	//
	//*************************************************************
	LSTATUS NTAPI RegDeleteTreeXP (
		__in        HKEY     hKey,
		__in_opt    LPCTSTR  lpSubKey
		)
	{
		TCHAR szDelKey[MAX_PATH*2];

		_tcscpy_s(szDelKey, MAX_PATH*2, lpSubKey);
		return RegDelnodeRecurse(hKey, szDelKey);

	}

	HRESULT WINAPI SHGetStockIconInfoXP(SHSTOCKICONID siid, UINT uFlags, __inout SHSTOCKICONINFO *psii)
	{
		UNREFERENCED_PARAMETER(siid);
		UNREFERENCED_PARAMETER(uFlags);
		UNREFERENCED_PARAMETER(psii);
		return S_OK;
	}

	DWORD WINAPI CredUIPromptForCredentialsWXP(
		__in_opt PCREDUI_INFOW pUiInfo,
		__in_opt PCWSTR pszTargetName,
		__reserved PCtxtHandle pContext,
		__in DWORD dwAuthError,
		__inout_ecount(ulUserNameBufferSize) PWSTR pszUserName,
		__in ULONG ulUserNameBufferSize,
		__inout_ecount(ulPasswordBufferSize) PWSTR pszPassword,
		__in ULONG ulPasswordBufferSize,
		__inout_opt BOOL *save,
		__in DWORD dwFlags
		)
	{
		UNREFERENCED_PARAMETER(pUiInfo);
		UNREFERENCED_PARAMETER(pszTargetName);
		UNREFERENCED_PARAMETER(pContext);
		UNREFERENCED_PARAMETER(dwAuthError);
		UNREFERENCED_PARAMETER(pszUserName);
		UNREFERENCED_PARAMETER(ulUserNameBufferSize);
		UNREFERENCED_PARAMETER(pszPassword);
		UNREFERENCED_PARAMETER(ulPasswordBufferSize);
		UNREFERENCED_PARAMETER(save);
		UNREFERENCED_PARAMETER(dwFlags);
		return 0;
	}

	BOOL
	WINAPI
	CredUnPackAuthenticationBufferWXP(
		__in DWORD                                      dwFlags,
		__in_bcount(cbAuthBuffer) PVOID                 pAuthBuffer,
		__in DWORD                                      cbAuthBuffer,
		__out_ecount_opt(*pcchMaxUserName) LPWSTR       pszUserName,
		__inout DWORD*                                  pcchMaxUserName,
		__out_ecount_opt(*pcchMaxDomainName) LPWSTR     pszDomainName,
		__inout_opt DWORD*                              pcchMaxDomainName,
		__out_ecount_opt(*pcchMaxPassword) LPWSTR       pszPassword,
		__inout DWORD*                                  pcchMaxPassword
		)
	{
		UNREFERENCED_PARAMETER(dwFlags);
		UNREFERENCED_PARAMETER(pAuthBuffer);
		UNREFERENCED_PARAMETER(cbAuthBuffer);
		UNREFERENCED_PARAMETER(pszUserName);
		UNREFERENCED_PARAMETER(pcchMaxUserName);
		UNREFERENCED_PARAMETER(pcchMaxDomainName);
		UNREFERENCED_PARAMETER(pszDomainName);
		UNREFERENCED_PARAMETER(pszPassword);
		UNREFERENCED_PARAMETER(pcchMaxPassword);
		return TRUE;
	}

	// delayHookFunc - Delay load hooking function
	FARPROC WINAPI delayHookFailureFunc (unsigned dliNotify, PDelayLoadInfo pdli)
	{
	   FARPROC fp = NULL;   // Default return value

	   // NOTE: The members of the DelayLoadInfo structure pointed
	   // to by pdli shows the results of progress made so far. 
#ifdef _DEBUG
	OutputDebugString(TEXT("delayHookFailureFunc : "));
#endif
	   switch (dliNotify) {

	   case dliFailLoadLib:
		  // LoadLibrary failed.
		  // In here a second attempt could be made to load the dll somehow.
		  // If fp is still NULL, the ERROR_MOD_NOT_FOUND exception will be raised.
		  fp = NULL;
		  break;

	   case dliFailGetProc:
		  // GetProcAddress failed.
		  // A second attempt could be made to get the function pointer somehow.
		  // We can override and give our own function pointer in fp.
		  // Ofcourse, fp is still going to be NULL,
		  // the ERROR_PROC_NOT_FOUND exception will be raised.
		   fp = (FARPROC) NULL;
#ifdef _DEBUG
		  OutputDebugStringA(pdli->szDll);
		  OutputDebugStringA(" ");
		  if (pdli->dlp.fImportByName)
		  {
			  OutputDebugStringA(pdli->dlp.szProcName);
			  OutputDebugStringA(" ");
		  }
#endif
		  // recover for ADVAPI32.DLL
		  if (_strcmpi(pdli->szDll,"ADVAPI32.DLL") == 0)
		  {
			  if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"RegSetKeyValueW") == 0)
			  {
				  fp = (FARPROC) RegSetKeyValueXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"EnableTraceEx") == 0)
			  {
				  fp = (FARPROC) EnableTraceExXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"EventRegister") == 0)
			  {
				  fp = (FARPROC) EventRegisterXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"EventUnregister") == 0)
			  {
				  fp = (FARPROC) EventUnregisterXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"EventWriteString") == 0)
			  {
				  fp = (FARPROC) EventWriteStringXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"RegDeleteTreeW") == 0)
			  {
				  fp = (FARPROC) RegDeleteTreeXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"SHGetStockIconInfo") == 0)
			  {
				  fp = (FARPROC) SHGetStockIconInfoXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"CredUIPromptForCredentialsW") == 0)
			  {
				  fp = (FARPROC) CredUIPromptForCredentialsWXP;
			  }
			  else if (pdli->dlp.fImportByName && _strcmpi(pdli->dlp.szProcName,"CredUnPackAuthenticationBufferW") == 0)
			  {
				  fp = (FARPROC) CredUnPackAuthenticationBufferWXP;
			  }
		  }
      
		  break;
	   }
#ifdef _DEBUG
		  if (fp)
		  {
			  OutputDebugString(TEXT("SUCCESS\r\n"));
		  }
		  else
		  {
			  OutputDebugString(TEXT("FAILURE\r\n"));
		  }
#endif
	   return(fp);
	}


}
