/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "CContainer.h"
#include "CertificateValidation.h"
#include "GPO.h"
#include "package.h"

#pragma comment(lib, "Cryptui.lib")

#define REMOVALPOLICYKEY TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy")

CContainer::CContainer(LPCTSTR szReaderName, LPCTSTR szCardName, LPCTSTR szProviderName, LPCTSTR szContainerName, DWORD KeySpec,__in USHORT ActivityCount,PCCERT_CONTEXT pCertContext)
{
	_dwRid = 0;
	_szReaderName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szReaderName)+1)));
	if (_szReaderName)
	{
		_tcscpy_s(_szReaderName,_tcslen(szReaderName)+1,szReaderName);
	}
	_szProviderName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szProviderName)+1)));
	if (_szProviderName)
	{
		_tcscpy_s(_szProviderName,_tcslen(szProviderName)+1,szProviderName);
	}
	_szContainerName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szContainerName)+1)));
	if (_szContainerName)
	{
		_tcscpy_s(_szContainerName,_tcslen(szContainerName)+1,szContainerName);
	}
	_szCardName = (LPTSTR) EIDAlloc ((DWORD)(sizeof(TCHAR)*(_tcslen(szCardName)+1)));
	if (_szCardName)
	{
		_tcscpy_s(_szCardName,_tcslen(szCardName)+1,szCardName);
	}
	_szUserName = NULL;
	_KeySpec = KeySpec;
	_ActivityCount = ActivityCount;
	_pCertContext = pCertContext;
}

CContainer::~CContainer()
{
	if (_szReaderName)
		EIDFree(_szReaderName);
	if (_szCardName)
		EIDFree(_szCardName);
	if (_szProviderName)
		EIDFree(_szProviderName);
	if (_szContainerName)
		EIDFree(_szContainerName);
	if (_szUserName) 
		EIDFree(_szUserName);
	if (_pCertContext) {
		CertFreeCertificateContext(_pCertContext);
	}
}

PTSTR CContainer::GetUserName()
{
	if (_szUserName)
	{
		return _szUserName;
	}
	DWORD dwSize;
	BOOL fReturn = FALSE;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	__try
	{
		// get the subject details for the cert
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,NULL,0);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		_szUserName = (LPTSTR) EIDAlloc(dwSize*sizeof(TCHAR));
		if (!_szUserName) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc error = %d",GetLastError());
			__leave;
		}
		dwSize = CertGetNameString(_pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,_szUserName,dwSize);
		if (!dwSize)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertGetNameString error = %d",GetLastError());
			__leave;
		}
		fReturn = TRUE;

	}
	__finally
	{
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (!fReturn)
		{
			if (_szUserName)
			{
				EIDFree(_szUserName);
				_szUserName = NULL;
			}
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetUserNameFromCertificate = %s",_szUserName);
	return _szUserName;
}

DWORD CContainer::GetRid()
{
	DWORD dwError = 0;
	if (_dwRid == 0)
	{
		_dwRid = LsaEIDGetRIDFromStoredCredential(_pCertContext);
		dwError = GetLastError();
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"_dwRid set to 0x%x",_dwRid);
	}
	SetLastError(dwError);
	return _dwRid;
}

PTSTR CContainer::GetProviderName()
{
	return _szProviderName;
}
PTSTR CContainer::GetContainerName()
{
	return _szContainerName;
}
DWORD CContainer::GetKeySpec()
{
	return _KeySpec;
}

PCCERT_CONTEXT CContainer::GetCertificate()
{
	PCCERT_CONTEXT pCertContext = CertDuplicateCertificateContext(_pCertContext);
	return pCertContext;
}

BOOL CContainer::Erase()
{
	HCRYPTPROV hProv;
	return CryptAcquireContext(&hProv,
					_szContainerName,
					_szProviderName,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET);
}

BOOL CContainer::IsOnReader(LPCTSTR szReaderName)
{
	return _tcscmp(_szReaderName,szReaderName) == 0;
}

PEID_SMARTCARD_CSP_INFO CContainer::GetCSPInfo()
{
	_ASSERTE( _CrtCheckMemory( ) );
	DWORD dwReaderLen = (DWORD) _tcslen(_szReaderName)+1;
	DWORD dwCardLen = (DWORD) _tcslen(_szCardName)+1;
	DWORD dwProviderLen = (DWORD) _tcslen(_szProviderName)+1;
	DWORD dwContainerLen = (DWORD) _tcslen(_szContainerName)+1;
	DWORD dwBufferSize = dwReaderLen + dwCardLen + dwProviderLen + dwContainerLen;
	
	PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) EIDAlloc(sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR));
	if (!pCspInfo) return NULL;
	//ZeroMemory(pCspInfo);
	memset(pCspInfo,0,sizeof(EID_SMARTCARD_CSP_INFO));
	pCspInfo->dwCspInfoLen = sizeof(EID_SMARTCARD_CSP_INFO)+dwBufferSize*sizeof(TCHAR);
	pCspInfo->MessageType = 1;
	pCspInfo->KeySpec = _KeySpec;
	pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
	pCspInfo->nReaderNameOffset = pCspInfo->nCardNameOffset + dwCardLen;
	pCspInfo->nContainerNameOffset = pCspInfo->nReaderNameOffset + dwReaderLen;
	pCspInfo->nCSPNameOffset = pCspInfo->nContainerNameOffset + dwContainerLen;
	memset(pCspInfo->bBuffer,0,sizeof(pCspInfo->bBuffer));
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] ,dwBufferSize + 4 - pCspInfo->nCardNameOffset, _szCardName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwBufferSize + 4 - pCspInfo->nReaderNameOffset, _szReaderName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwBufferSize + 4 - pCspInfo->nContainerNameOffset, _szContainerName);
	_tcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] ,dwBufferSize + 4 - pCspInfo->nCSPNameOffset, _szProviderName);
	_ASSERTE( _CrtCheckMemory( ) );
	return pCspInfo;
}

void CContainer::FreeCSPInfo(PEID_SMARTCARD_CSP_INFO pCspInfo)
{
	EIDFree(pCspInfo);
}

BOOL CContainer::ViewCertificate(HWND hWnd)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	LPCSTR					szOid;
	certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
	certViewInfo.hwndParent = hWnd;
	certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK;
	certViewInfo.szTitle = TEXT("Info");
	certViewInfo.pCertContext = _pCertContext;
	certViewInfo.cPurposes = 0;
	certViewInfo.rgszPurposes = 0;
	if (!GetPolicyValue(AllowCertificatesWithNoEKU))
	{
		certViewInfo.cPurposes = 1;
		szOid = szOID_KP_SMARTCARD_LOGON;
		certViewInfo.rgszPurposes = & szOid;
	}
	certViewInfo.pCryptProviderData = NULL;
	certViewInfo.hWVTStateData = NULL;
	certViewInfo.fpCryptProviderDataTrustedUsage = FALSE;
	certViewInfo.idxSigner = 0;
	certViewInfo.idxCert = 0;
	certViewInfo.fCounterSigner = FALSE;
	certViewInfo.idxCounterSigner = 0;
	certViewInfo.cStores = 0;
	certViewInfo.rghStores = NULL;
	certViewInfo.cPropSheetPages = 0;
	certViewInfo.rgPropSheetPages = NULL;
	certViewInfo.nStartPage = 0;
	
	return CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
}

BOOL CContainer::TriggerRemovePolicy()
{
	LONG lResult;
	BOOL fReturn = FALSE;
	HKEY hRemovePolicyKey = NULL;
	PBYTE pbBuffer = NULL;
	DWORD dwSize;
	DWORD dwProcessId, dwSessionId;
	TCHAR szValueKey[sizeof(DWORD)+1];

	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Enter");
	if (!_ActivityCount)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activity Count = 0");
		return FALSE;
	}
	__try
	{
		dwProcessId = GetCurrentProcessId();
		if (!ProcessIdToSessionId(dwProcessId, &dwSessionId))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ProcessIdToSessionId 0x%08x",GetLastError());
			__leave;
		}
		lResult = RegOpenKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY ,&hRemovePolicyKey);
		if (lResult !=ERROR_SUCCESS)
		{
			if (lResult == ERROR_FILE_NOT_FOUND)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"REMOVALPOLICYKEY not found. Creating ...");
				lResult = RegCreateKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY ,&hRemovePolicyKey);
				if (lResult !=ERROR_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegCreateKey 0x%08x",lResult);
					__leave;
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegOpenKey 0x%08x (service not running ?)",lResult);
				__leave;
			}
		}
		dwSize = (DWORD) (sizeof(USHORT) + sizeof(USHORT) + (_tcslen(_szReaderName) + 1) *sizeof(WCHAR));
		pbBuffer = (PBYTE) EIDAlloc(dwSize);
		if (!pbBuffer)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
#ifdef UNICODE
		wcscpy_s((PWSTR)pbBuffer, wcslen(_szReaderName) + 1, _szReaderName);
#else
		MultiByteToWideChar(CP_ACP, 0, _szReaderName, _tcslen(_szReaderName) + 1, pbBuffer, _tcslen(_szReaderName) + 1);
#endif
		*(PUSHORT)(pbBuffer + dwSize - sizeof(USHORT)) = _ActivityCount;
		*(PUSHORT)(pbBuffer + dwSize - 2*sizeof(USHORT)) = 0;

		_stprintf_s(szValueKey, sizeof(DWORD)+1, TEXT("%d"),dwSessionId);

		lResult = RegSetValueEx (hRemovePolicyKey, szValueKey, 0, REG_BINARY, pbBuffer, dwSize);
		if (lResult !=ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RegSetValue 0x%08x (not enough privilege ?)",lResult);
			__leave;
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RegSetValue %s %d %d",_szReaderName, _ActivityCount, dwSessionId);
		}


		fReturn = TRUE;
	}
	__finally
	{
		if (pbBuffer)
			EIDFree(pbBuffer);
		if (hRemovePolicyKey)
			RegCloseKey(hRemovePolicyKey);
	}
	return fReturn;
}

PEID_INTERACTIVE_LOGON CContainer::AllocateLogonStruct(PWSTR szPin, PDWORD pdwSize)
{
	PEID_INTERACTIVE_LOGON pReturn = NULL;
	PEID_INTERACTIVE_LOGON pRequest = NULL;
	DWORD dwRid = 0;
	PWSTR szUserName = NULL;
	WCHAR szDomainName[MAX_COMPUTERNAME_LENGTH+1];
	DWORD dwSize, dwTotalSize;
	__try
	{
	
		// sanity check string lengths
		if (wcslen(szPin) * sizeof(WCHAR) > USHRT_MAX) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Input string is too long");
			__leave;
		}
		dwRid = this->GetRid();
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"dwRid = 0");
			__leave;
		}
		szUserName = GetUsernameFromRid(dwRid);
		if (!szUserName)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"szUserName not found");
			__leave;
		}
		dwSize = ARRAYSIZE(szDomainName);
		GetComputerName(szDomainName,&dwSize);

		DWORD dwCspBufferLength = (DWORD) (wcslen(_szCardName)+1
						+ wcslen(_szContainerName)+1
						+ wcslen(_szProviderName)+1
						+ wcslen(_szReaderName)+1);
		DWORD dwCspDataLength = sizeof(EID_SMARTCARD_CSP_INFO)
						+ (dwCspBufferLength) * sizeof(WCHAR);
		dwTotalSize = (DWORD) (sizeof(EID_INTERACTIVE_LOGON) 
						+ wcslen(szUserName) * sizeof(WCHAR)
						+ wcslen(szDomainName) * sizeof(WCHAR)
						+ wcslen(szPin) * sizeof(WCHAR)
						+ dwCspDataLength);
    
		pRequest = (PEID_INTERACTIVE_LOGON) EIDAlloc(dwTotalSize);
		if (!pRequest)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memset(pRequest, 0, dwTotalSize);
		pRequest->MessageType = EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLIA;
		pRequest->Flags = 0;
		_ASSERTE( _CrtCheckMemory( ) );
		PVOID pPointer = (PUCHAR) pRequest + sizeof(EID_INTERACTIVE_LOGON);
		// PIN
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->Pin.Length = pRequest->Pin.MaximumLength = (USHORT) (wcslen(szPin) * sizeof(WCHAR));
		pRequest->Pin.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->Pin.Buffer, szPin, pRequest->Pin.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->Pin.Length);
		// Username
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->UserName.Length = pRequest->UserName.MaximumLength = (USHORT) (wcslen(szUserName) * sizeof(WCHAR));
		pRequest->UserName.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->UserName.Buffer, szUserName, pRequest->UserName.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->UserName.Length);
		// Domain
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->LogonDomainName.Length = pRequest->LogonDomainName.MaximumLength = (USHORT) (wcslen(szDomainName) * sizeof(WCHAR));
		pRequest->LogonDomainName.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->LogonDomainName.Buffer, szDomainName, pRequest->LogonDomainName.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->LogonDomainName.Length);
		// CSPInfo
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->CspDataLength = dwCspDataLength;
		pRequest->CspData = (PUCHAR) pPointer;
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pPointer;
		pCspInfo->dwCspInfoLen = pRequest->CspDataLength;
		// CSPInfo + content
		_ASSERTE( _CrtCheckMemory( ) );
		pCspInfo->MessageType = 1;
		pCspInfo->KeySpec = _KeySpec;
		pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
		pCspInfo->nReaderNameOffset = (DWORD) (pCspInfo->nCardNameOffset + wcslen(_szCardName) + 1 );
		pCspInfo->nContainerNameOffset = (DWORD) (pCspInfo->nReaderNameOffset + wcslen(_szReaderName) + 1 );
		pCspInfo->nCSPNameOffset = (DWORD) (pCspInfo->nContainerNameOffset + wcslen(_szContainerName) + 1 );
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] , dwCspBufferLength +  ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCardNameOffset, _szCardName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nReaderNameOffset, _szReaderName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nContainerNameOffset, _szContainerName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] , dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCSPNameOffset, _szProviderName);	
		_ASSERTE( _CrtCheckMemory( ) );
		// Put pointer in relative format
		pRequest->Pin.Buffer = (PWSTR) ((PUCHAR) pRequest->Pin.Buffer - (ULONG_PTR) pRequest);
		pRequest->UserName.Buffer = (PWSTR) ((PUCHAR) pRequest->UserName.Buffer - (ULONG_PTR) pRequest);
		pRequest->LogonDomainName.Buffer = (PWSTR) ((PUCHAR) pRequest->LogonDomainName.Buffer - (ULONG_PTR) pRequest);
		pRequest->CspData = (pRequest->CspData - (ULONG_PTR) pRequest);
		// sucess !
		_ASSERTE( _CrtCheckMemory( ) );
		pReturn = pRequest;
		if (pdwSize) *pdwSize = dwTotalSize;
	}
	__finally
	{
		if (!pReturn && pRequest)
			EIDFree(pRequest);
		if (szUserName)
			EIDFree(szUserName);
	}
	return pReturn;
}
/*
PEID_MSGINA_AUTHENTICATION CContainer::AllocateGinaStruct(PWSTR szPin, PDWORD pdwSize)
{
	PEID_MSGINA_AUTHENTICATION pReturn = NULL;
	PEID_MSGINA_AUTHENTICATION pRequest = NULL;
	DWORD dwRid = 0;
	DWORD dwTotalSize;
	__try
	{
	
		// sanity check string lengths
		if (wcslen(szPin) * sizeof(WCHAR) > USHRT_MAX) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Input string is too long");
			__leave;
		}
		dwRid = this->GetRid();
		if (!dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"dwRid = 0");
			__leave;
		}
		DWORD dwCspBufferLength = wcslen(_szCardName)+1
						+ wcslen(_szContainerName)+1
						+ wcslen(_szProviderName)+1
						+ wcslen(_szReaderName)+1;
		DWORD dwCspDataLength = sizeof(EID_SMARTCARD_CSP_INFO)
						+ (dwCspBufferLength) * sizeof(WCHAR);
		dwTotalSize = sizeof(EID_INTERACTIVE_LOGON) 
						+ wcslen(szPin) * sizeof(WCHAR)
						+ dwCspDataLength;
    
		pRequest = (PEID_MSGINA_AUTHENTICATION) EIDAlloc(dwTotalSize);
		if (!pRequest)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memset(pRequest, 0, dwTotalSize);
		pRequest->MessageType = EIDCMEIDGinaAuthentication;
		pRequest->CspDataLength = dwCspBufferLength;
		pRequest->dwRid = dwRid;
		_ASSERTE( _CrtCheckMemory( ) );
		PVOID pPointer = (PUCHAR) pRequest + sizeof(EID_INTERACTIVE_LOGON);
		// PIN
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->Pin.Length = pRequest->Pin.MaximumLength = (USHORT) (wcslen(szPin) * sizeof(WCHAR));
		pRequest->Pin.Buffer = (PWSTR) pPointer;
		memcpy(pRequest->Pin.Buffer, szPin, pRequest->Pin.Length);
		pPointer = (PVOID) ((PCHAR) pPointer + pRequest->Pin.Length);
		// CSPInfo
		_ASSERTE( _CrtCheckMemory( ) );
		pRequest->CspData = (PEID_SMARTCARD_CSP_INFO) pPointer;
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pPointer;
		pCspInfo->dwCspInfoLen = dwCspBufferLength;
		// CSPInfo + content
		_ASSERTE( _CrtCheckMemory( ) );
		pCspInfo->MessageType = 1;
		pCspInfo->KeySpec = _KeySpec;
		pCspInfo->nCardNameOffset = ARRAYSIZE(pCspInfo->bBuffer);
		pCspInfo->nReaderNameOffset = pCspInfo->nCardNameOffset + wcslen(_szCardName) + 1 ;
		pCspInfo->nContainerNameOffset = pCspInfo->nReaderNameOffset + wcslen(_szReaderName) + 1 ;
		pCspInfo->nCSPNameOffset = pCspInfo->nContainerNameOffset + wcslen(_szContainerName) + 1 ;
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCardNameOffset] , dwCspBufferLength +  ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCardNameOffset, _szCardName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nReaderNameOffset, _szReaderName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset] ,dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nContainerNameOffset, _szContainerName);
		_ASSERTE( _CrtCheckMemory( ) );
		wcscpy_s(&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset] , dwCspBufferLength + ARRAYSIZE(pCspInfo->bBuffer) - pCspInfo->nCSPNameOffset, _szProviderName);	
		_ASSERTE( _CrtCheckMemory( ) );
		// Put pointer in relative format
		pRequest->Pin.Buffer = (PWSTR) ((PUCHAR) pRequest->Pin.Buffer - (ULONG_PTR) pRequest);
		pRequest->CspData = (PEID_SMARTCARD_CSP_INFO) ((PUCHAR)pRequest->CspData - (ULONG_PTR) pRequest);
		// sucess !
		_ASSERTE( _CrtCheckMemory( ) );
		pReturn = pRequest;
		if (pdwSize) *pdwSize = dwTotalSize;
	}
	__finally
	{
		if (!pReturn && pRequest)
			EIDFree(pRequest);
	}
	return pReturn;
}*/