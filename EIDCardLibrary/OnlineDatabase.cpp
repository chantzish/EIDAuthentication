#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Winhttp.h>
#include <Imagehlp.h>

#include "CertificateUtilities.h"
#include "Tracing.h"
#include "EIDCardLibrary.h"
#include "EIDAuthenticateVersion.h"

#pragma comment(lib,"Version.lib")
#pragma comment(lib,"Winhttp.lib")
#pragma comment(lib,"Wininet.lib")
#pragma comment(lib,"Imagehlp.lib")

#define DATABASE_SITE           TEXT("database.mysmartlogon.com")
#define TEST_DATABASE_SITE      TEXT("database-test.mysmartlogon.com")
#define SUBMIT_REPORT_PAGE      TEXT("/submitReport.aspx")
#define FIND_REPORT_BY_ATR_PAGE TEXT("/FindReportByAtr.aspx")

extern "C"
{
	// wininet and winhttp conflicts
	BOOLAPI
	InternetCanonicalizeUrlA(
		__in LPCSTR lpszUrl,
		__out_ecount(*lpdwBufferLength) LPSTR lpszBuffer,
		__inout LPDWORD lpdwBufferLength,
		__in DWORD dwFlags
		);
	BOOLAPI
	InternetCanonicalizeUrlW(
		__in LPCWSTR lpszUrl,
		__out_ecount(*lpdwBufferLength) LPWSTR lpszBuffer,
		__inout LPDWORD lpdwBufferLength,
		__in DWORD dwFlags
		);
	#ifdef UNICODE
	#define InternetCanonicalizeUrl  InternetCanonicalizeUrlW
	#else
	#define InternetCanonicalizeUrl  InternetCanonicalizeUrlA
	#endif // !UNICODE
}

// see http://www.codeproject.com/Articles/16598/Get-Your-DLL-s-Path-Name for the "__ImageBase"
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
PTSTR GetWebSite()
{
	// we must have 2 sites :
	// one for production use and one for test
	// but if someone compile this code, it will reach the production site.
	// We don't want that the production site is polluted with false report !
	// So, we are getting the digital signature of the binary in use.
	// if there are one, we contact the production site, else, the test site
	TCHAR szExeName[MAX_PATH];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL fIsTest = FALSE;
	DWORD dwIndices[128];
	DWORD dwCertsCount = 0;
    __try
    {
        // Retrieve the digital signature of the package if available
		if (!GetModuleFileName((HINSTANCE)&__ImageBase, szExeName, ARRAYSIZE(szExeName)))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to get the module name 0x%08X",GetLastError());
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Using %s as module name", szExeName);
        hFile = CreateFile(szExeName, FILE_READ_DATA , FILE_SHARE_READ, NULL, OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL , NULL);
        if (INVALID_HANDLE_VALUE == hFile)
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to open the file 0x%08X",GetLastError());
            __leave;
        }
        // Note : here "Certificate" doesn't mean X509 certificate but authenticode signature instead
        if (!ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &dwCertsCount, dwIndices, ARRAYSIZE(dwIndices)))
        {
            EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to find a digital signature 0x%08X",GetLastError());
            __leave;
        }
        if (dwCertsCount == 0)
        {
			fIsTest = TRUE;
		}
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}
	if (fIsTest)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Test configuration");
		return TEST_DATABASE_SITE;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Release configuration");
	return DATABASE_SITE;
}

TCHAR szAdvancedErrorMessage[2000] = TEXT("Unknow");

PTSTR GetAdvancedErrorMessage()
{
	return szAdvancedErrorMessage;
}

BOOL PostDataToTheSupportSite(PSTR szPostData)
{
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	HINTERNET hRequest = NULL;
	DWORD dwError = 0;
	DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(DWORD);
	BOOL fReturn = FALSE;
	PTSTR szWebSite = NULL;
	TCHAR szUrl[256];
	WINHTTP_AUTOPROXY_OPTIONS  AutoProxyOptions;
	WINHTTP_PROXY_INFO         ProxyInfo;
	WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ProxyConfig;
	DWORD cbProxyInfoSize = sizeof(ProxyInfo);
	ZeroMemory( &AutoProxyOptions, sizeof(AutoProxyOptions) );
	ZeroMemory( &ProxyInfo, sizeof(ProxyInfo) );
	ZeroMemory( &ProxyConfig, sizeof(ProxyConfig) );
	__try
	{ 
		if (!WinHttpGetIEProxyConfigForCurrentUser(&ProxyConfig))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpGetIEProxyConfigForCurrentUser 0x%08X",dwError);
			__leave;
		}

		hSession = WinHttpOpen(TEXT("EIDAuthenticate"), 
				(ProxyConfig.lpszProxy?WINHTTP_ACCESS_TYPE_NAMED_PROXY:WINHTTP_ACCESS_TYPE_DEFAULT_PROXY), 
				ProxyConfig.lpszProxy, ProxyConfig.lpszProxyBypass, 0);
		if (!hSession)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpOpen 0x%08X",dwError);
			__leave;
		}
		szWebSite = GetWebSite();
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"website : %s", szWebSite);
		hConnect = WinHttpConnect(hSession, szWebSite, INTERNET_DEFAULT_PORT, 0);
		if (!hConnect)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpConnect 0x%08X",dwError);
			__leave;
		}
		// WINHTTP_FLAG_SECURE
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"url : %s", SUBMIT_REPORT_PAGE);
		hRequest = WinHttpOpenRequest(hConnect,TEXT("POST"),SUBMIT_REPORT_PAGE,NULL,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0);
		if (!hRequest)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpOpenRequest 0x%08X",dwError);
			__leave;
		}
		// wpad autoconfiguration or autodect
		if (ProxyConfig.fAutoDetect || ProxyConfig.lpszAutoConfigUrl)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"autoproxy");
			AutoProxyOptions.fAutoLogonIfChallenged = TRUE;
			if (ProxyConfig.fAutoDetect)
			{
				AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
				AutoProxyOptions.dwAutoDetectFlags = 
									 WINHTTP_AUTO_DETECT_TYPE_DHCP |
									 WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			}
			if (ProxyConfig.lpszAutoConfigUrl)
			{
				AutoProxyOptions.lpszAutoConfigUrl = ProxyConfig.lpszAutoConfigUrl;
				AutoProxyOptions.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
			}

			_stprintf_s(szUrl, ARRAYSIZE(szUrl),TEXT("http://%s%s"),szWebSite,SUBMIT_REPORT_PAGE);
			if( WinHttpGetProxyForUrl( hRequest, szUrl, &AutoProxyOptions, &ProxyInfo))
			{
			  // A proxy configuration was found, set it on the
			  // request handle.
				if( !WinHttpSetOption( hRequest, 
								WINHTTP_OPTION_PROXY,
								&ProxyInfo,
								cbProxyInfoSize ) )
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpSetOption 0x%08X",dwError);
					__leave;
				}
			}
		}
		//min timeout : 30s WINHTTP_OPTION_RECEIVE_TIMEOUT, WINHTTP_OPTION_SEND_TIMEOUT
		LPCTSTR additionalHeaders = TEXT("Content-Type: application/x-www-form-urlencoded\r\n");
		if (!WinHttpSendRequest(hRequest, additionalHeaders, (DWORD) -1, (LPVOID)szPostData, (DWORD) strlen(szPostData), (DWORD) strlen(szPostData), 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpSendRequest 0x%08X",dwError);
			__leave;
		}
		if (!WinHttpReceiveResponse(hRequest, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpReceiveResponse 0x%08X",dwError);
			__leave;
		}
		if (!WinHttpQueryHeaders(hRequest,  WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
							   WINHTTP_HEADER_NAME_BY_INDEX,
							   &statusCode,
							   &statusCodeSize,
							   WINHTTP_NO_HEADER_INDEX))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpQueryHeaders 0x%08X",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"statusCode %d",statusCode);
		if ( statusCode >= 400 )
		{
			dwError = (DWORD) SPAPI_E_MACHINE_UNAVAILABLE;
			// system error message
			LPVOID Error = NULL;
			FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,dwError,0,(LPTSTR)&Error,0,NULL);
			_stprintf_s(szAdvancedErrorMessage,ARRAYSIZE(szAdvancedErrorMessage),
				TEXT("0x%08X - %s\r\nHTTP STATUS CODE: %d"),dwError,Error, statusCode);
			LocalFree(Error);
			__leave;
		}
        // Check for available data.
        CHAR szResult[2000];
		DWORD dwDownloaded = 0;
		if (!WinHttpReadData( hRequest, (LPVOID)szResult, 
                                ARRAYSIZE(szResult), &dwDownloaded))
        {  
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed WinHttpReadData 0x%08X",dwError);
			__leave;
		}
		szResult[dwDownloaded] = '\0';
		if (_strnicmp(szResult, "SUCCESS", 7) != 0)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"http:%S",szResult);
			dwError = ERROR_INTERNAL_ERROR;
			// system error message
			LPVOID Error = NULL;
			FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
					NULL,dwError,0,(LPTSTR)&Error,0,NULL);
			_stprintf_s(szAdvancedErrorMessage,ARRAYSIZE(szAdvancedErrorMessage),
				TEXT("0x%08X - %s\r\nDetail: %S"),dwError,Error, szResult);
			LocalFree(Error);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSession)
			WinHttpCloseHandle(hSession);
		if( ProxyInfo.lpszProxy != NULL )
			GlobalFree(ProxyInfo.lpszProxy);
		if( ProxyInfo.lpszProxyBypass != NULL )
			GlobalFree( ProxyInfo.lpszProxyBypass );
		if (ProxyConfig.lpszAutoConfigUrl)
			GlobalFree(ProxyConfig.lpszAutoConfigUrl);
		if (ProxyConfig.lpszProxy)
			GlobalFree(ProxyConfig.lpszProxy);
		if (ProxyConfig.lpszProxyBypass)
			GlobalFree(ProxyConfig.lpszProxyBypass);
	}
	SetLastError(dwError);
	return fReturn;
}


void UrlEncoder(__inout PCHAR *ppPointer, __inout PDWORD pdwRemainingSize, __in PTSTR szInput, _In_opt_ BOOL DoNotEscape = FALSE)
{
	if (!szInput) return;
	while(*szInput != L'\0')
	{
		if (
			(
				((*szInput >= L'A' && *szInput <= L'Z') 
					|| (*szInput >= L'a' && *szInput <= L'z')
					|| (*szInput >= L'0' && *szInput <= L'9')
					|| (*szInput == L'-') || (*szInput == L'_') || (*szInput == L'.') || (*szInput == L'~'))
				|| DoNotEscape) 
			&& *pdwRemainingSize > 1)
		{
			**ppPointer = (CHAR)*szInput;
			(*ppPointer)++;
			(*pdwRemainingSize)--;
		}
		else if (*szInput < 256 && *pdwRemainingSize > 3)
		{
			sprintf_s(*ppPointer, *pdwRemainingSize, "%%%02X",*szInput);
			(*ppPointer)+=3;
			(*pdwRemainingSize)-=3;
		}
		else if (*pdwRemainingSize > 6)
		{
			sprintf_s(*ppPointer, *pdwRemainingSize, "%%u%04X",*szInput);
			(*ppPointer)+=6;
			(*pdwRemainingSize)-=6;
		}
		szInput++;
	}
	**ppPointer = '\0';
}

void UrlLogFileEncoder(__inout PCHAR *ppPointer, __inout PDWORD pdwRemainingSize, __in PTSTR szTracingFile)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BYTE pbBuffer[256];
	BOOL bResult;
	DWORD dwByteRead;
	__try
	{
		hFile = CreateFile(szTracingFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			__leave;
		}
		bResult = ReadFile(hFile, pbBuffer, ARRAYSIZE(pbBuffer), &dwByteRead, NULL);
		while (! (bResult &&  dwByteRead == 0) )
		{
			for(DWORD i = 0; i< dwByteRead; i++)
			{
				if (pbBuffer[i] == '\0')
				{
					// ignore null character (conversion from WCHAR to CHAR)
				}
				else if (((pbBuffer[i] >= L'A' && pbBuffer[i] <= L'Z') 
							|| (pbBuffer[i] >= L'a' && pbBuffer[i] <= L'z')
							|| (pbBuffer[i] >= L'0' && pbBuffer[i] <= L'9')
							|| (pbBuffer[i] == L'-') || (pbBuffer[i] == L'_') || (pbBuffer[i] == L'.') || (pbBuffer[i] == L'~')
							|| (pbBuffer[i] == L'$') || (pbBuffer[i] == L'+') || (pbBuffer[i] == L'!') || (pbBuffer[i] == L'*'))
					&& *pdwRemainingSize > 1)
				{
					**ppPointer = (CHAR)pbBuffer[i];
					(*ppPointer)++;
					(*pdwRemainingSize)--;
				}
				else if (*pdwRemainingSize > 3)
				{
					sprintf_s(*ppPointer, *pdwRemainingSize, "%%%02X",pbBuffer[i]);
					(*ppPointer)+=3;
					(*pdwRemainingSize)-=3;
				}
			}
			bResult = ReadFile(hFile, pbBuffer, ARRAYSIZE(pbBuffer), &dwByteRead, NULL);
		}
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
	}
	**ppPointer = '\0';
}

void UrlLogCertificateEncoder(__inout PCHAR *ppPointer, __inout PDWORD pdwRemainingSize, __in PCCERT_CONTEXT pCertContext)
{
	DWORD dwSize = 0;
	PSTR pbBuffer = NULL;
	__try
	{
		if (!CryptBinaryToStringA( pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &dwSize))
		{
			__leave;
		}
		pbBuffer = (PSTR) EIDAlloc(dwSize);
		if (!pbBuffer)
		{
			__leave;
		}
		if (!CryptBinaryToStringA( pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, pbBuffer, &dwSize))
		{
			__leave;
		}
		for(DWORD i = 0; i< dwSize; i++)
		{
			if (((pbBuffer[i] >= L'A' && pbBuffer[i] <= L'Z') 
						|| (pbBuffer[i] >= L'a' && pbBuffer[i] <= L'z')
						|| (pbBuffer[i] >= L'0' && pbBuffer[i] <= L'9')
						|| (pbBuffer[i] == L'-') || (pbBuffer[i] == L'_') || (pbBuffer[i] == L'.') || (pbBuffer[i] == L'~'))
				&& *pdwRemainingSize > 1)
			{
				**ppPointer = (CHAR)pbBuffer[i];
				(*ppPointer)++;
				(*pdwRemainingSize)--;
			}
			else if (*pdwRemainingSize > 3)
			{
				sprintf_s(*ppPointer, *pdwRemainingSize, "%%%02X",pbBuffer[i]);
				(*ppPointer)+=3;
				(*pdwRemainingSize)-=3;
			}
		}
	}
	__finally
	{
		if (pbBuffer) EIDFree(pbBuffer);
	}
	**ppPointer = '\0';
}

#define UNKNOWN TEXT("Unknown")
BOOL CommunicateTestNotOK(DWORD dwErrorCode, PTSTR szEmail, PTSTR szTracingFile, PCCERT_CONTEXT pCertContext)
{
	if (dwErrorCode) EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"enter");
	BOOL fReturn = FALSE;
	TCHAR szReaderName[256] = UNKNOWN;
	TCHAR szCardName[256] = UNKNOWN;
	TCHAR szProviderName[256] = UNKNOWN;
	TCHAR szATR[256] = UNKNOWN;
	TCHAR szATRMask[256] = UNKNOWN;
	TCHAR szCspDll[256] = UNKNOWN;
	TCHAR szOsInfo[256] = UNKNOWN;
	TCHAR szHardwareInfo[256] = UNKNOWN;
	TCHAR szFileVersion[256] = UNKNOWN;
	TCHAR szCompany[256] = UNKNOWN;
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	DWORD dwSize;
	CHAR szPostData[1000000]= "";
	DWORD dwRemainingSize = ARRAYSIZE(szPostData);
	PCHAR ppPointer = szPostData;
	if (AskForCard(szReaderName,256,szCardName,256))
	{
		SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen);
		HKEY hRegKeyCalais, hRegKeyCSP, hRegKey;
		// smart card info (atr & mask)
		if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards"), 0, KEY_READ, &hRegKeyCalais))
		{
			BYTE bATR[100];
			DWORD dwSize = sizeof(bATR);
			if (!RegOpenKeyEx(hRegKeyCalais, szCardName, 0, KEY_READ, &hRegKey))
			{
				if (!RegQueryValueEx(hRegKey,TEXT("ATR"), NULL, NULL,(PBYTE)&bATR,&dwSize))
				{
					for(DWORD i=0; i< dwSize; i++)
					{
						_stprintf_s(szATR + 2*i, ARRAYSIZE(szATR) - 2*i,TEXT("%02X"),bATR[i]);
					}
					dwSize = sizeof(bATR);
					RegQueryValueEx(hRegKey,TEXT("ATRMask"), NULL, NULL,(PBYTE)&bATR,&dwSize);
					for(DWORD i=0; i< dwSize; i++)
					{
						_stprintf_s(szATRMask + 2*i, ARRAYSIZE(szATRMask) - 2*i,TEXT("%02X"),bATR[i]);
					}
				}
				if (_tcscmp(MS_SCARD_PROV, szProviderName) == 0)
				{
					dwSize = sizeof(szCspDll);
					RegQueryValueEx(hRegKey,TEXT("80000001"), NULL, NULL,(PBYTE)&szCspDll,&dwSize);
				}
				RegCloseKey(hRegKey);
			}
			RegCloseKey(hRegKeyCalais);
		}
		if (_tcscmp(szCspDll,UNKNOWN) == 0)
		{
			// csp info
			if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"), 0, KEY_READ, &hRegKeyCSP))
			{
				dwSize = sizeof(szCspDll);
				if (!RegOpenKeyEx(hRegKeyCalais, szProviderName, 0, KEY_READ, &hRegKey))
				{
					RegQueryValueEx(hRegKey, TEXT("Image Path"), NULL,NULL,(PBYTE)&szCspDll,&dwSize);
					RegCloseKey(hRegKey);
				}
				RegCloseKey(hRegKeyCalais);
			}
		}
		if (_tcscmp(szCspDll,UNKNOWN) != 0)
		{
			DWORD dwHandle;
			dwSize = GetFileVersionInfoSize(szCspDll, &dwHandle);
			if (dwSize)
			{
				UINT uSize;
				PVOID versionInfo = EIDAlloc(dwSize);
				PWSTR pszFileVersion = NULL;
				PWSTR pszCompany = NULL;
				if (GetFileVersionInfo(szCspDll, dwHandle, dwSize, versionInfo))
				{
					BOOL retVal; 
					LPVOID version=NULL;
					DWORD vLen,langD;
					TCHAR szfileVersionPath[256];
					retVal = VerQueryValue(versionInfo,TEXT("\\VarFileInfo\\Translation"),&version,(UINT *)&vLen);
					if (retVal && vLen==4) 
					{
						memcpy(&langD,version,4);            
						_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
									TEXT("\\StringFileInfo\\%02X%02X%02X%02X\\FileVersion"),
								(langD & 0xff00)>>8,langD & 0xff,(langD & 0xff000000)>>24, 
								(langD & 0xff0000)>>16);            
					}
					else 
						_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
									TEXT("\\StringFileInfo\\%04X04B0\\FileVersion"),
								GetUserDefaultLangID());
					retVal = VerQueryValue(versionInfo,szfileVersionPath,(PVOID*)&pszFileVersion,(UINT *)&uSize);

					if (pszFileVersion != NULL) 
						_stprintf_s(szFileVersion, ARRAYSIZE(szFileVersion),TEXT("%ls"),pszFileVersion);

					if (retVal && vLen==4) 
					{
						memcpy(&langD,version,4);            
						_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
									TEXT("\\StringFileInfo\\%02X%02X%02X%02X\\CompanyName"),
								(langD & 0xff00)>>8,langD & 0xff,(langD & 0xff000000)>>24, 
								(langD & 0xff0000)>>16);            
					}
					else 
						_stprintf_s(szfileVersionPath, ARRAYSIZE(szfileVersionPath),
									TEXT("\\StringFileInfo\\%04X04B0\\CompanyName"),
								GetUserDefaultLangID());
					retVal = VerQueryValue(versionInfo,szfileVersionPath,(PVOID*)&pszCompany,(UINT *)&uSize);

					if (pszFileVersion != NULL) 
						_stprintf_s(szCompany, ARRAYSIZE(szCompany),TEXT("%ls"),pszCompany);
				}
				EIDFree(versionInfo);
			}
		}
		if (wcscmp(szATR, UNKNOWN) == 0)
		{
			// ATR can be unknown, as for PIV card
		}
	}
	// os version
	OSVERSIONINFOEX version;
	version.dwOSVersionInfoSize = sizeof(version);
	GetVersionEx((LPOSVERSIONINFO )&version);
	_stprintf_s(szOsInfo, ARRAYSIZE(szOsInfo),TEXT("%d.%d.%d;%d;%d.%d;%s"), 
								version.dwMajorVersion, version.dwMinorVersion, 
								version.dwBuildNumber, version.dwPlatformId,
								version.wSuiteMask, version.wProductType, 
								version.szCSDVersion);
	
	// hardware info
	SYSTEM_INFO SystemInfo;
	GetNativeSystemInfo(&SystemInfo);
	_stprintf_s(szHardwareInfo, ARRAYSIZE(szHardwareInfo), TEXT("%u;%u;%u"), 
      SystemInfo.dwNumberOfProcessors, SystemInfo.dwProcessorType, SystemInfo.wProcessorRevision);

	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("hardwareInfo="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szHardwareInfo);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&osInfo="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szOsInfo);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ReaderName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szReaderName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&CardName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCardName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ProviderName="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szProviderName);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ATR="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szATR);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ATRMask="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szATRMask);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&CspDll="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCspDll);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&FileVersion="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szFileVersion);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Company="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, szCompany);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Software="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("EIDAuthenticate"));
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Version="), TRUE);
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT(EIDAuthenticateVersionText));
	UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&ErrorCode="), TRUE);

	TCHAR szErrorCode[16];
	_stprintf_s(szErrorCode, ARRAYSIZE(szErrorCode),TEXT("0x%08X"),dwErrorCode);
	UrlEncoder(&ppPointer, &dwRemainingSize, szErrorCode);
	if (szEmail != NULL)
	{
		UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Email="), TRUE);
		UrlEncoder(&ppPointer, &dwRemainingSize, szEmail);
	}
	if (szTracingFile != NULL)
	{
		UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&LogFile="), TRUE);
		UrlLogFileEncoder(&ppPointer, &dwRemainingSize, szTracingFile);
	}
	if (pCertContext != NULL)
	{
		UrlEncoder(&ppPointer, &dwRemainingSize, TEXT("&Certificate="), TRUE);
		UrlLogCertificateEncoder(&ppPointer, &dwRemainingSize, pCertContext);
	}
	fReturn = PostDataToTheSupportSite(szPostData);
	return fReturn;
}

BOOL CommunicateTestOK()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"enter");
	return CommunicateTestNotOK(0, NULL, NULL, NULL);
}


BOOL OpenBrowserOnDatabase(__in PBYTE pbAtr, __in DWORD dwAtrSize, __in_opt PTSTR szCardName)
{
	TCHAR szUrl[256];
	TCHAR szATR[100];
	for(DWORD i=0; i< dwAtrSize; i++)
	{
		_stprintf_s(szATR + 2*i, ARRAYSIZE(szATR) - 2*i,TEXT("%02X"),pbAtr[i]);
	}
	_stprintf_s(szUrl, ARRAYSIZE(szUrl),TEXT("http://%s%s?Atr=%s"),GetWebSite(),FIND_REPORT_BY_ATR_PAGE, szATR);
	if (szCardName)
	{
		_tcscat_s(szUrl, ARRAYSIZE(szUrl), TEXT("&Name="));
		_tcscat_s(szUrl, ARRAYSIZE(szUrl), szCardName);
	}
	ShellExecute(NULL, L"open", szUrl, NULL, NULL, SW_SHOW);
	SetLastError(0);
	return TRUE;
}


BOOL OpenBrowserOnDatabase()
{
	LONG lReturn = 0;
	BOOL fReturn = FALSE;
	SCARDCONTEXT     hSC = NULL;
	SCARDHANDLE hCard = NULL;
	DWORD dwProtocol;
	PBYTE pbAtr = NULL;
	DWORD dwAtrSize = SCARD_AUTOALLOCATE;
	TCHAR szReader[256];
	DWORD dwReaderSize = ARRAYSIZE(szReader);
	TCHAR szCard[256];
	DWORD dwCardSize = ARRAYSIZE(szCard);
	__try
	{
		if (!AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
		{
			lReturn = GetLastError();
			__leave;
		}
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardReleaseContext 0x%08X",lReturn);
			__leave;
		}
		lReturn = SCardConnect(hSC, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProtocol);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardConnect 0x%08X",lReturn);
			__leave;
		}
		// get the ATR
		lReturn = SCardStatus(hCard, (PTSTR) &szReader, &dwReaderSize, NULL, NULL, (PBYTE)&pbAtr, &dwAtrSize);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardStatus 0x%08X",lReturn);
			__leave;
		}
		if (!OpenBrowserOnDatabase(pbAtr, dwAtrSize, szCard))
		{
			lReturn = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hCard != NULL)
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		if (pbAtr)
			SCardFreeMemory(hSC, pbAtr);
		if (hSC)
			SCardReleaseContext(hSC);
	}
	SetLastError(lReturn);
	return fReturn;
}