/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is EIDFree software; you can redistribute it and/or
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
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tchar.h>
#include <intsafe.h>
#include <wincred.h>
#include <Lm.h>

#include <Ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <ntsecpkg.h>
#include <Wtsapi32.h>
#include <security.h>

#include <CodeAnalysis/warnings.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable : 4995)
#include <strsafe.h>
#pragma warning(pop)

#include <credentialprovider.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "StoredCredentialManagement.h"

#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

#define DEBUG_MARKUP "MySmartLogonHeapCheck"

PLSA_ALLOCATE_LSA_HEAP MyAllocateHeap = NULL;  
PLSA_FREE_LSA_HEAP MyFreeHeap = NULL;  
PLSA_IMPERSONATE_CLIENT MyImpersonate = NULL;
BOOL TraceAllocation = TRUE;

void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap)
{
	MyAllocateHeap = AllocateLsaHeap;
}

void SetFree(PLSA_FREE_LSA_HEAP FreeHeap)
{
	MyFreeHeap = FreeHeap;
}

PVOID EIDAllocEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,DWORD dwSize)
{
	UNREFERENCED_PARAMETER(szFile);
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFunction);
	PVOID memory = NULL;
	if (MyAllocateHeap)
	{
#ifdef _DEBUG	
		memory = MyAllocateHeap(dwSize + sizeof(DEBUG_MARKUP) + sizeof(PVOID));
		if (memory)
		{
			memcpy((PBYTE) memory + dwSize,DEBUG_MARKUP, sizeof(DEBUG_MARKUP));
			memcpy((PBYTE) memory + dwSize + sizeof(DEBUG_MARKUP),&memory, sizeof(PVOID));
		}
#else
		memory = MyAllocateHeap(dwSize);
#endif		
	}
	else
	{
#ifdef _DEBUG	
		memory = _malloc_dbg(dwSize,_CLIENT_BLOCK, szFile, dwLine);
#else
		memory = malloc(dwSize);
#endif		
	}
	//if (TraceAllocation)
	//{
	//	EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_VERBOSE, L"Allocation of %p",memory);
	//}
	return memory;
}
VOID EIDFreeEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,PVOID buffer)
{
	UNREFERENCED_PARAMETER(szFile);
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFunction);
	//if (TraceAllocation)
	//{
	//	EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_VERBOSE, L"Freeing of %p",buffer);
	//}
	if (MyFreeHeap)
	{
#ifdef _DEBUG
		// look for markup
		BOOL bFound = FALSE;
		for (int i = 0; i < 10000; i++)
		{
			if (memcmp((PBYTE)buffer + i,DEBUG_MARKUP, sizeof(DEBUG_MARKUP)) == 0)
			{
				if (memcmp((PBYTE)buffer + i + sizeof(DEBUG_MARKUP),&buffer,sizeof(PVOID)) != 0)
				{
					EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_ERROR, L"Markup not ok %p",buffer);
				}
				else
				{
					bFound = TRUE;
				}
				break;
			}
		}
		if (!bFound)
		{
			EIDCardLibraryTraceEx(szFile, dwLine, szFunction, WINEVENT_LEVEL_ERROR, L"Markup not found when freeing %p",buffer);
		}
		MyFreeHeap(buffer);
#else
		MyFreeHeap(buffer);
#endif
	}
	else
	{
#ifndef _DEBUG	
		free(buffer);
#else
		_free_dbg(buffer, _CLIENT_BLOCK);
#endif
	}
}

void SetImpersonate(PLSA_IMPERSONATE_CLIENT Impersonate)
{
	MyImpersonate = Impersonate;
}

VOID EIDImpersonate()
{
	if (MyImpersonate)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Impersonating");
		MyImpersonate();
	}
}

VOID EIDRevertToSelf()
{
	if (MyImpersonate)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"RevertToSelf");
		RevertToSelf();
	}
}

BOOL EIDIsComponentInLSAContext()
{
	return (MyImpersonate != NULL);
}
//
// This function copies the length of pwz and the pointer pwz into the UNICODE_STRING structure
// This function is intended for serializing a credential in GetSerialization only.
// Note that this function just makes a copy of the string pointer. It DOES NOT ALLOCATE storage!
// Be very, very sure that this is what you want, because it probably isn't outside of the
// exact GetSerialization call where the sample uses it.
//
HRESULT UnicodeStringInitWithString(
                                       PWSTR pwz,
                                       UNICODE_STRING* pus
                                       )
{
    HRESULT hr;
    if (pwz)
    {
        size_t lenString;
        hr = StringCchLengthW(pwz, USHORT_MAX, &(lenString));

        if (SUCCEEDED(hr))
        {
            USHORT usCharCount;
            hr = SizeTToUShort(lenString, &usCharCount);
            if (SUCCEEDED(hr))
            {
                USHORT usSize;
                hr = SizeTToUShort(sizeof(WCHAR), &usSize);
                if (SUCCEEDED(hr))
                {
                    hr = UShortMult(usCharCount, usSize, &(pus->Length)); // Explicitly NOT including NULL terminator
                    if (SUCCEEDED(hr))
                    {
                        pus->MaximumLength = pus->Length;
                        pus->Buffer = pwz;
                        hr = S_OK;
                    }
                    else
                    {
                        hr = HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
                    }
                }
            }
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}



//
// The following function is intended to be used ONLY with the Kerb*Pack functions.  It does
// no bounds-checking because its callers have precise requirements and are written to respect 
// its limitations.
// You can read more about the UNICODE_STRING type at:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/secauthn/security/unicode_string.asp
//
static void _UnicodeStringPackedUnicodeStringCopy(
    const UNICODE_STRING& rus,
    PWSTR pwzBuffer,
    UNICODE_STRING* pus
    )
{
    pus->Length = rus.Length;
    pus->MaximumLength = rus.Length;
    pus->Buffer = pwzBuffer;

    CopyMemory(pus->Buffer, rus.Buffer, pus->Length);
}

//
// WinLogon and LSA consume "packed" KERB_INTERACTIVE_UNLOCK_LOGONs.  In these, the PWSTR members of each
// UNICODE_STRING are not actually pointers but byte offsets into the overall buffer represented
// by the packed KERB_INTERACTIVE_UNLOCK_LOGON.  For example:
// 
// rkiulIn.Logon.LogonDomainName.Length = 14                                    -> Length is in bytes, not characters
// rkiulIn.Logon.LogonDomainName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) -> LogonDomainName begins immediately
//                                                                              after the KERB_... struct in the buffer
// rkiulIn.Logon.UserName.Length = 10
// rkiulIn.Logon.UserName.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14   -> UNICODE_STRINGS are NOT null-terminated
//
// rkiulIn.Logon.Password.Length = 16
// rkiulIn.Logon.Password.Buffer = sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 14 + 10
// 
// THere's more information on this at:
// http://msdn.microsoft.com/msdnmag/issues/05/06/SecurityBriefs/#void
//

HRESULT EIDUnlockLogonPack(
									   const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
									   const PEID_SMARTCARD_CSP_INFO pCspInfo,
                                       BYTE** prgb,
                                       DWORD* pcb
                                       )
{
    HRESULT hr;

    const EID_INTERACTIVE_LOGON* pkilIn = &rkiulIn.Logon;

    // alloc space for struct plus extra for the three strings
    DWORD cb = sizeof(rkiulIn) +
		pkilIn->LogonDomainName.Length +
        pkilIn->UserName.Length +
        pkilIn->Pin.Length +
		pCspInfo->dwCspInfoLen;


    EID_INTERACTIVE_UNLOCK_LOGON* pkiulOut = (EID_INTERACTIVE_UNLOCK_LOGON*)CoTaskMemAlloc(cb);

    if (pkiulOut)
    {
        ZeroMemory(&pkiulOut->LogonId, sizeof(LUID));

        //
        // point pbBuffer at the beginning of the extra space
        //
        BYTE* pbBuffer = (BYTE*)pkiulOut + sizeof(*pkiulOut);

        //
        // set up the Logon structure within the EID_INTERACTIVE_UNLOCK_LOGON
        //
        EID_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;
		//KERB_INTERACTIVE_LOGON* pkilOut = &pkiulOut->Logon;

        pkilOut->MessageType = pkilIn->MessageType;
		pkilOut->Flags = pkilIn->Flags;

        //
        // copy each string,
        // fix up appropriate buffer pointer to be offset,
        // advance buffer pointer over copied characters in extra space
        //
        _UnicodeStringPackedUnicodeStringCopy(pkilIn->LogonDomainName, (PWSTR)pbBuffer, &pkilOut->LogonDomainName);
        pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->LogonDomainName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->UserName, (PWSTR)pbBuffer, &pkilOut->UserName);
        pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
        pbBuffer += pkilOut->UserName.Length;

        _UnicodeStringPackedUnicodeStringCopy(pkilIn->Pin, (PWSTR)pbBuffer, &pkilOut->Pin);
        pkilOut->Pin.Buffer = (PWSTR)(pbBuffer - (BYTE*)pkiulOut);
		pbBuffer += pkilOut->Pin.Length;

		pkilOut->CspData = (PUCHAR) (pbBuffer - (BYTE*)pkiulOut);
		pkilOut->CspDataLength = pCspInfo->dwCspInfoLen;

		memcpy(pbBuffer,pCspInfo,pCspInfo->dwCspInfoLen);

        *prgb = (BYTE*)pkiulOut;
        *pcb = cb;

        hr = S_OK;
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}


// 
// This function packs the string pszSourceString in pszDestinationString
// for use with LSA functions including LsaLookupAuthenticationPackage.
//
HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString)
{
    size_t cchLength;
    HRESULT hr = StringCchLengthA(pszSourceString, USHORT_MAX, &cchLength);
    if (SUCCEEDED(hr))
    {
        USHORT usLength;
        hr = SizeTToUShort(cchLength, &usLength);

        if (SUCCEEDED(hr))
        {
            pszDestinationString->Buffer = (PCHAR)pszSourceString;
            pszDestinationString->Length = usLength;
            pszDestinationString->MaximumLength = pszDestinationString->Length+1;
            hr = S_OK;
        }
    }
    return hr;
}

//
// Retrieves the 'eid' AuthPackage from the LSA.
//
HRESULT RetrieveNegotiateAuthPackage(ULONG * pulAuthPackage)
{
    HRESULT hr;
    HANDLE hLsa;

    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		
		TCHAR szExeName[256];
		DWORD dwNumChar = GetModuleFileName(NULL, szExeName, ARRAYSIZE(szExeName));
		// mstsc.exe
		if (dwNumChar >= 9 && _tcsicmp(szExeName + dwNumChar - 9, TEXT("mstsc.exe")) == 0)
		{
			LsaInitString(&lsaszPackageName, NEGOSSP_NAME_A);
		}
		else
		{
			LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);
		}

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            *pulAuthPackage = ulAuthPackage;
            hr = S_OK;
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }

    return hr;
}

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen)
{
    NET_API_STATUS netStatus;
	HRESULT hr;
    HANDLE hLsa;
	DWORD dwRid,dwSubAuthorityCount;
	USER_INFO_23* pUserInfo;
	PSID pSid;
	
	// transform the username to usernameinfo
	netStatus = NetUserGetInfo(NULL,username,23,(LPBYTE*) &pUserInfo);
	if (NERR_Success != netStatus)
	{
		return MAKE_HRESULT(1,FACILITY_INTERNET,netStatus);
	}
	// get the sid
	pSid = pUserInfo->usri23_user_sid;
	// get the last identifier of the sid : it's the rid
	dwSubAuthorityCount = *GetSidSubAuthorityCount(pSid);
	dwRid = *GetSidSubAuthority(pSid, dwSubAuthorityCount-1);
	//
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (SUCCEEDED(HRESULT_FROM_NT(status)))
    {

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (SUCCEEDED(HRESULT_FROM_NT(status)))
        {
            status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, &dwRid, sizeof(DWORD),
				(PVOID *)szAuthPackageValue,szAuthPackageLen,NULL);
			hr = HRESULT_FROM_NT(status);
            
        }
        else
        {
            hr = HRESULT_FROM_NT(status);
        }
        LsaDeregisterLogonProcess(hLsa);
    }
    else
    {
        hr= HRESULT_FROM_NT(status);
    }
	NetApiBufferFree(pUserInfo);
    return hr;
}

// change pointer according ClientAuthenticationBase : the struct is a copy
// so pointer are invalid
NTSTATUS RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Diff %d %d",(PUCHAR) pUnlockLogon, (PUCHAR) ClientAuthenticationBase);
	if (!pUnlockLogon)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pUnlockLogon NULL");
		return STATUS_INVALID_PARAMETER;
	}
	if ((pUnlockLogon->Logon.UserName.Buffer) != NULL)
	{
		if ((ULONG_PTR)(pUnlockLogon->Logon.UserName.Buffer) + pUnlockLogon->Logon.UserName.MaximumLength > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserName Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if ((ULONG_PTR)(pUnlockLogon->Logon.UserName.Buffer) + pUnlockLogon->Logon.UserName.Length > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserName Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon from %d",pUnlockLogon->Logon.UserName.Buffer);
		pUnlockLogon->Logon.UserName.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.UserName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Logon to %d",pUnlockLogon->Logon.UserName.Buffer);
	}
	if ((pUnlockLogon->Logon.LogonDomainName.Buffer) != NULL)
	{
		if ((ULONG_PTR)(pUnlockLogon->Logon.LogonDomainName.Buffer) + pUnlockLogon->Logon.LogonDomainName.MaximumLength > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonDomainName Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if ((ULONG_PTR)(pUnlockLogon->Logon.LogonDomainName.Buffer) + pUnlockLogon->Logon.LogonDomainName.Length > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LogonDomainName Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName from %d",pUnlockLogon->Logon.LogonDomainName.Buffer);
		pUnlockLogon->Logon.LogonDomainName.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.LogonDomainName.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap LogonDomainName to %d",pUnlockLogon->Logon.LogonDomainName.Buffer);
	}
	if ((pUnlockLogon->Logon.Pin.Buffer) != NULL)
	{
		if ((ULONG_PTR)(pUnlockLogon->Logon.Pin.Buffer) + pUnlockLogon->Logon.Pin.MaximumLength > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Pin Overflow1");
			return STATUS_INVALID_PARAMETER_3;
		}
		if ((ULONG_PTR)(pUnlockLogon->Logon.Pin.Buffer) + pUnlockLogon->Logon.Pin.Length > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Pin Overflow2");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin from %d",pUnlockLogon->Logon.Pin.Buffer);
		pUnlockLogon->Logon.Pin.Buffer = PWSTR((ULONG_PTR)( pUnlockLogon) + (PUCHAR) pUnlockLogon->Logon.Pin.Buffer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap Pin to %d",pUnlockLogon->Logon.Pin.Buffer);
	}
	if ((pUnlockLogon->Logon.CspData) != NULL)
	{
		if ((ULONG_PTR)(pUnlockLogon->Logon.CspData) + pUnlockLogon->Logon.CspDataLength > AuthenticationInformationLength)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CspData Overflow");
			return STATUS_INVALID_PARAMETER_3;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData from %d",pUnlockLogon->Logon.CspData);
		pUnlockLogon->Logon.CspData = PUCHAR( (PBYTE)pUnlockLogon + (DWORD) pUnlockLogon->Logon.CspData);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remap CSPData to %d",pUnlockLogon->Logon.CspData);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;
}

VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon) {
	WCHAR Buffer[1000];
	EIDCardLibraryTrace(dwLevel,L"LogonId %d %d",pUnlockLogon->LogonId.LowPart,pUnlockLogon->LogonId.HighPart);
	EIDCardLibraryTrace(dwLevel,L"Username %d",pUnlockLogon->Logon.UserName.Length);
	if ((pUnlockLogon->Logon.UserName.Buffer) != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.UserName.Buffer,pUnlockLogon->Logon.UserName.Length/2);
		Buffer[pUnlockLogon->Logon.UserName.Length/2]=0;
		EIDCardLibraryTrace(dwLevel,L"Username '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No Username");
	}
	EIDCardLibraryTrace(dwLevel,L"LogonDomainName %d",pUnlockLogon->Logon.LogonDomainName.Length);
	if (pUnlockLogon->Logon.LogonDomainName.Buffer != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.LogonDomainName.Buffer,pUnlockLogon->Logon.LogonDomainName.Length/2);
		Buffer[pUnlockLogon->Logon.LogonDomainName.Length/2]=0;
		EIDCardLibraryTrace(dwLevel,L"LogonDomainName '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No DomainName");
	}
	EIDCardLibraryTrace(dwLevel,L"Pin %d",pUnlockLogon->Logon.Pin.Length);
	if (pUnlockLogon->Logon.Pin.Buffer != NULL)
	{
		wcsncpy_s(Buffer,1000,pUnlockLogon->Logon.Pin.Buffer,pUnlockLogon->Logon.Pin.Length/2);
		Buffer[pUnlockLogon->Logon.Pin.Length/2]=0;
		//EIDCardLibraryTrace(dwLevel,L"Pin '%s'",Buffer);
	}
	else
	{
		EIDCardLibraryTrace(dwLevel,L"No Pin");
	}
	EIDCardLibraryTrace(dwLevel,L"Flags %d",pUnlockLogon->Logon.Flags);
	EIDCardLibraryTrace(dwLevel,L"MessageType %d",pUnlockLogon->Logon.MessageType);
	EIDCardLibraryTrace(dwLevel,L"CspDataLength %d",pUnlockLogon->Logon.CspDataLength);
	if (pUnlockLogon->Logon.CspData)
	{
		PEID_SMARTCARD_CSP_INFO pCspInfo = (PEID_SMARTCARD_CSP_INFO) pUnlockLogon->Logon.CspData;
		EIDCardLibraryTrace(dwLevel,L"MessageType %d",pCspInfo->MessageType);
		EIDCardLibraryTrace(dwLevel,L"KeySpec %d",pCspInfo->KeySpec);
		if (pCspInfo->nCardNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"CardName '%s'",&pCspInfo->bBuffer[pCspInfo->nCardNameOffset]);
		}
		if (pCspInfo->nReaderNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"ReaderName '%s'",&pCspInfo->bBuffer[pCspInfo->nReaderNameOffset]);
		}
		if (pCspInfo->nContainerNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"ContainerName '%s'",&pCspInfo->bBuffer[pCspInfo->nContainerNameOffset]);
		}
		if (pCspInfo->nCSPNameOffset)
		{
			EIDCardLibraryTrace(dwLevel,L"CSPName '%s'",&pCspInfo->bBuffer[pCspInfo->nCSPNameOffset]);
		}
	}	
}

PTSTR GetUsernameFromRid(__in DWORD dwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = NULL;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	BOOL fFound = FALSE;
	DWORD dwI, dwSize;
	PTSTR szUsername = NULL;
	__try
	{
		Status = NetUserEnum(NULL, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			if (dwRid == pUserInfo[dwI].usri3_user_id)
			{
				fFound = TRUE;
				break;
			}
		}
		if (!fFound)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Rid not found %x",dwRid);
			__leave;
		}
		dwSize = (DWORD)(_tcslen(pUserInfo[dwI].usri3_name) +1);
		szUsername = (PTSTR) EIDAlloc(dwSize *sizeof(TCHAR));
		if (!szUsername)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}
		_tcscpy_s(szUsername, dwSize, pUserInfo[dwI].usri3_name);
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return szUsername;
}

BOOL IsCurrentUser(PTSTR szUserName)
{
	BOOL fReturn;
	PWSTR szCurrentUserName;
	DWORD dwSize;
	// GetUserName return SYSTEM
	//DWORD dwSessionId = WTSGetActiveConsoleSessionId();
	fReturn = WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &szCurrentUserName, &dwSize);
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WTSQuerySessionInformationW 0x%08X",GetLastError());
		return FALSE;
	}

	fReturn = wcscmp(szCurrentUserName,szUserName) == 0;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s' match with '%s'",szCurrentUserName,szUserName);
	WTSFreeMemory(szCurrentUserName);
	return fReturn;
}

BOOL IsAdmin(PTSTR szUserName)
{
	BOOL fReturn = FALSE;
	WCHAR szAdministratorGroupName[256];
	WCHAR szDomainName[256];
	PLOCALGROUP_USERS_INFO_0 pGroupInfo;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	SID_NAME_USE SidType;
	PSID AdministratorsGroup; 
	DWORD dwEntriesRead, dwTotalEntries, dwSize;
	if (NERR_Success != NetUserGetLocalGroups(NULL, szUserName, 0, LG_INCLUDE_INDIRECT, (PBYTE*)&pGroupInfo,
		MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries))
		return FALSE;
	fReturn = AllocateAndInitializeSid(&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup); 
	if(!fReturn) 
	{
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}
	dwSize = ARRAYSIZE(szAdministratorGroupName);
	if( !LookupAccountSid( NULL, AdministratorsGroup,
								  szAdministratorGroupName, &dwSize, szDomainName, 
								  &dwSize, &SidType ) ) 
	{
		FreeSid(AdministratorsGroup); 
		NetApiBufferFree(pGroupInfo);
		return FALSE;
	}

	for (DWORD dwI = 0; dwI < dwTotalEntries ; dwI++)
	{
		fReturn = wcscmp(szAdministratorGroupName, pGroupInfo[dwI].lgrui0_name) == 0;
		if (fReturn) break;
	}
	
	FreeSid(AdministratorsGroup); 
	NetApiBufferFree(pGroupInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CurrentUsername = '%s'",szUserName);
	return fReturn;
}

// extract RID from current process
DWORD GetCurrentRid()
{
	DWORD dwSize = 0, dwRid = 0;
	PSID pSid;
	PTOKEN_USER pInfo = NULL;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{
	
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
		pInfo = (PTOKEN_USER) EIDAlloc(dwSize);
		if (pInfo)
		{
			if (GetTokenInformation(hToken, TokenUser, pInfo, dwSize, &dwSize))
			{
				pSid = pInfo->User.Sid;
				dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by GetTokenInformation", GetLastError());
			}
			EIDFree(pInfo);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by OpenProcessToken", GetLastError());
	}
	return dwRid;
}

DWORD GetRidFromUsername(LPTSTR szUsername)
{
	BOOL bResult;
	SID_NAME_USE Use;
	PSID pSid = NULL;
	TCHAR checkDomainName[UNCLEN+1];
	DWORD cchReferencedDomainName=0, dwRid = 0;

	DWORD dLengthSid = 0;
	bResult = LookupAccountName(NULL,  szUsername, NULL,&dLengthSid,NULL, &cchReferencedDomainName, &Use);
	
	pSid = EIDAlloc(dLengthSid);
	cchReferencedDomainName=UNCLEN;
	bResult = LookupAccountName(NULL,  szUsername, pSid,&dLengthSid,checkDomainName, &cchReferencedDomainName, &Use);
	if (!bResult) 
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LookupAccountName", GetLastError());
		return 0;
	}
	dwRid = *GetSidSubAuthority(pSid, *GetSidSubAuthorityCount(pSid) -1);
	EIDFree(pSid);
	return dwRid;
}


BOOL LsaEIDCreateStoredCredential(__in_opt PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pContext, __in BOOL fEncryptPassword)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = NULL;
    HANDLE hLsa = NULL;
	DWORD dwSize;
	NTSTATUS status;
	PBYTE pPointer;
	DWORD dwPasswordSize, dwBufferSize = 0;
	DWORD dwError = 0;
	PCRYPT_KEY_PROV_INFO pProvInfo = NULL;
	__try
	{
		if (!szPassword) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szPassword null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		// add the CRYPT_KEY_PROV_INFO to the log if it exists
		dwSize = 0;
		if (CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			pProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
			if (!pProvInfo)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
				dwError = ERROR_OUTOFMEMORY;
				__leave;
			}
			if (CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwSize))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pProvInfo->pwszContainerName, pProvInfo->pwszProvName);
			}
		}
	
		dwPasswordSize = (DWORD) (wcslen(szPassword) + 1) * sizeof(WCHAR);
		dwBufferSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + dwPasswordSize + pContext->cbCertEncoded); //+ dwProviderSize + dwContainerSize;

		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwBufferSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!szUsername) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"szUsername null");
			pBuffer->dwRid = GetCurrentRid();
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"szUsername = %s", szUsername);
			pBuffer->dwRid = GetRidFromUsername(szUsername);
		}
		pBuffer->MessageType = EIDCMCreateStoredCredential;
		pBuffer->usPasswordLen = 0;
		pPointer = (PBYTE) &(pBuffer[1]);

		pBuffer->szPassword = (PWSTR) pPointer;
		memcpy(pPointer, szPassword, dwPasswordSize);
		pPointer += dwPasswordSize;
	
		if (pContext->cbCertEncoded > 0xFFFF)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pContext->cbCertEncoded > 0xFFFF (0x%08X)",pContext->cbCertEncoded);
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
		pBuffer->fEncryptPassword = fEncryptPassword;

		pBuffer->pbCertificate = (PBYTE) pPointer;
		memcpy(pPointer, pContext->pbCertEncoded, pBuffer->dwCertificateSize);
		pPointer += pBuffer->dwCertificateSize;
	
		if (!pBuffer->dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			__leave;
		}

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwBufferSize, NULL, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) 
		{
			SecureZeroMemory(pBuffer, dwBufferSize);
			EIDFree(pBuffer);
		}
		if (pProvInfo) EIDFree(pProvInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

/** return RID = 0 if failure */
DWORD LsaEIDGetRIDFromStoredCredential(__in PCCERT_CONTEXT pContext)
{
	PEID_CALLPACKAGE_BUFFER pBuffer = NULL;
    HANDLE hLsa = NULL;
	DWORD dwSize;
	NTSTATUS status;
	PBYTE pPointer;
	DWORD dwError = 0;
	DWORD dwRid = 0;
	__try
	{
		if (pContext->cbCertEncoded > 0xFFFF)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pContext->cbCertEncoded > 0xFFFF (0x%08X)",pContext->cbCertEncoded);
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		dwSize = (DWORD) (sizeof(EID_CALLPACKAGE_BUFFER) + pContext->cbCertEncoded); 
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		pBuffer->dwRid = 0;

		pBuffer->MessageType = EIDCMGetStoredCredentialRid;
		pBuffer->usPasswordLen = 0;
		pBuffer->szPassword = NULL;	
		pBuffer->dwCertificateSize = (USHORT) pContext->cbCertEncoded;
		pPointer = (PBYTE) &(pBuffer[1]);
		pBuffer->pbCertificate = (PBYTE) pPointer;
		memcpy(pPointer, pContext->pbCertEncoded, pContext->cbCertEncoded);
		pPointer += pContext->cbCertEncoded;
	
		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			__leave;
		}

		ULONG ulAuthPackage;
		LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		dwRid = pBuffer->dwRid;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Rid = 0x%x",dwRid);
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return dwRid;
}

BOOL IsEIDPackageAvailable()
{
    BOOL fReturn = FALSE;
	HANDLE hLsa;
	NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status == STATUS_SUCCESS)
    {
        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status == STATUS_SUCCESS)
		{
			fReturn = TRUE;
		}
		LsaClose(hLsa);
	}
	return fReturn;
}

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = NULL;
    HANDLE hLsa = NULL;
	DWORD dwSize;
	NTSTATUS status;
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
			__leave;
		}
		if (!szUsername) 
		{
			pBuffer->dwRid = GetCurrentRid();
		}
		else
		{
			pBuffer->dwRid = GetRidFromUsername(szUsername);
		}
		pBuffer->MessageType = EIDCMRemoveStoredCredential;
		if (!pBuffer->dwRid)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = status;
			__leave;
		}

		ULONG ulAuthPackage;
		LSA_STRING lsaszPackageName;
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDRemoveAllStoredCredential()
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = NULL;
    HANDLE hLsa = NULL;
	DWORD dwSize;
	NTSTATUS status;
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null 0x%08X",dwError);
			__leave;
		}
		pBuffer->dwRid = GetCurrentRid();
	
		pBuffer->MessageType = EIDCMRemoveAllStoredCredential;
		if (!pBuffer->dwRid)
		{
			dwError = ERROR_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
		}

        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}

        status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if (pBuffer->dwError != 0)
		{
			// fail if the registration doesn't succeed
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
    }
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername)
{
	BOOL fReturn = FALSE;
	PEID_CALLPACKAGE_BUFFER pBuffer = NULL;
    HANDLE hLsa = NULL;
	DWORD dwSize;
	NTSTATUS status;
	DWORD dwError = 0;
	__try
	{
		dwSize = sizeof(EID_CALLPACKAGE_BUFFER);
		pBuffer = (PEID_CALLPACKAGE_BUFFER) EIDAlloc(dwSize);
		if( !pBuffer) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pBuffer null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!szUsername) 
		{
			pBuffer->dwRid = GetCurrentRid();
		}
		else
		{
			pBuffer->dwRid = GetRidFromUsername(szUsername);
		}
		pBuffer->MessageType = EIDCMHasStoredCredential;
		if (!pBuffer->dwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid = 0");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}

		status = LsaConnectUntrusted(&hLsa);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaConnectUntrusted 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
        ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
        LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
        if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaLookupAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pBuffer, dwSize, NULL, NULL, NULL);
		if (status != STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaCallAuthenticationPackage 0x%08x",status);
			dwError = LsaNtStatusToWinError(status);
			__leave;
		}
		if( pBuffer->dwError != 0)
		{
			dwError = pBuffer->dwError;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Error = 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hLsa) LsaClose(hLsa);
		if (pBuffer) EIDFree(pBuffer);
	}
	SetLastError(dwError);
	return fReturn;
}
