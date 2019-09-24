#include <ntstatus.h>
#define WIN32_NO_STATUS 1
#include <windows.h>
#include <tchar.h>
#pragma warning(push)
#pragma warning(disable : 4201)
#include <winscard.h>
#pragma warning(pop)

// cardmoh.h can be found in "Microsoft CNG Development Kit"
#include <cardmod.h>
#include "Tracing.h"
#include "EIDCardLibrary.h"
//
// Internal context structure for interfacing with a card module
//

typedef struct _MGSC_CONTEXT
{
    //
    // Internal context
    //

    PVOID                           pvContext;

} MGSC_CONTEXT, *PMGSC_CONTEXT;


typedef struct _INTERNAL_CONTEXT
{
    HMODULE hModule;
    CARD_DATA CardData;

} INTERNAL_CONTEXT, *PINTERNAL_CONTEXT;

//
// Macros for error checking and flow control
//

#define CHECK_DWORD(_X) {                                                   \
    if (ERROR_SUCCESS != (status = (_X))) {                                 \
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,TEXT("%s"), TEXT(#_X));  \
        __leave;                                                            \
    }                                                                       \
}

#define CHECK_BOOL(_X) {                                                    \
    if (FALSE == (_X)) {                                                    \
        status = GetLastError();                                            \
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,TEXT("%s"), TEXT(#_X));  \
        __leave;                                                            \
    }                                                                       \
}

#define CHECK_ALLOC(_X) {                                                   \
    if (NULL == (_X)) {                                                     \
        status = ERROR_NOT_ENOUGH_MEMORY;                                   \
        __leave;                                                            \
    }                                                                       \
}

extern "C" {

//
// Heap helpers
//

LPVOID 
WINAPI
_Alloc(
    __in        SIZE_T cBytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cBytes);
}

LPVOID 
WINAPI 
_ReAlloc(
    __in        LPVOID pvMem,
    __in        SIZE_T cBytes)
{
    return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pvMem, cBytes);
}

void
WINAPI
_Free(
    __in        LPVOID pvMem)
{
    HeapFree(GetProcessHeap(), 0, pvMem);
}

//
// Dummy data caching stubs to satisfy the card module callback requirements
//

DWORD 
WINAPI 
_CacheAddFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,
    IN      DWORD       dwFlags,
    IN      PBYTE       pbData,
    IN      DWORD       cbData)
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(pbData);
    UNREFERENCED_PARAMETER(cbData);

    return ERROR_SUCCESS;
}

DWORD 
WINAPI
_CacheLookupFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,
    IN      DWORD       dwFlags,
    IN      PBYTE      *ppbData,
    IN      PDWORD      pcbData)
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);
    UNREFERENCED_PARAMETER(ppbData);
    UNREFERENCED_PARAMETER(pcbData);

    return ERROR_NOT_FOUND;
}

DWORD 
WINAPI 
_CacheDeleteFileStub(
    IN      PVOID       pvCacheContext,
    IN      LPWSTR      wszTag,
    IN      DWORD       dwFlags)
{
    UNREFERENCED_PARAMETER(pvCacheContext);
    UNREFERENCED_PARAMETER(wszTag);
    UNREFERENCED_PARAMETER(dwFlags);

    return ERROR_SUCCESS;
}

//
// Cleanup resources consumed by the INTERNAL_CONTEXT struct
//
void
WINAPI
_FreeManagedContext(
    __inout         PINTERNAL_CONTEXT pInternal)
{
    if (NULL == pInternal)
        return;

    if (NULL != pInternal->hModule)
        FreeLibrary(pInternal->hModule);
    if (NULL != pInternal->CardData.pbAtr)
        _Free(pInternal->CardData.pbAtr);
    if (NULL != pInternal->CardData.pwszCardName)
        _Free(pInternal->CardData.pwszCardName);

    _Free(pInternal);
}

}
//
// Dll export functions
//

//
// Build a card module context handle to the specified card
//

DWORD MgScCardAcquireContext(
    __inout                     PMGSC_CONTEXT pMgSc,
    __in                        SCARDCONTEXT hSCardContext,
    __in                        SCARDHANDLE hSCardHandle,
    __in                        LPWSTR wszCardName,
    __in_bcount(cbAtr)          PBYTE pbAtr,
    __in                        DWORD cbAtr,
    __in                        DWORD dwFlags)
{
    DWORD status = ERROR_SUCCESS;
    LPWSTR wszCardModule = NULL;
    DWORD cchCardModule = SCARD_AUTOALLOCATE;
    PINTERNAL_CONTEXT pInternal = NULL;
    PFN_CARD_ACQUIRE_CONTEXT pfnCardAcquireContext = NULL;
    DWORD cch = 0;

    pMgSc->pvContext = NULL;

    __try
    {
        CHECK_ALLOC(pInternal = (PINTERNAL_CONTEXT) _Alloc(
            sizeof(INTERNAL_CONTEXT)));

        //
        // Lookup a card module for this card name
        //

        CHECK_DWORD(SCardGetCardTypeProviderName(
            hSCardContext,
            wszCardName,
            SCARD_PROVIDER_CARD_MODULE,
            (LPWSTR) &wszCardModule,
            &cchCardModule));
        if (0 == cchCardModule)
        {
            status = (DWORD) SCARD_E_UNKNOWN_CARD;
            __leave;
        }

        //
        // Load the card module dll and initial entry point
        //

        if (NULL == (pInternal->hModule = LoadLibrary(wszCardModule)))
        {
            status = GetLastError();
            __leave;
        }

        if (NULL == (pfnCardAcquireContext = 
                     (PFN_CARD_ACQUIRE_CONTEXT) GetProcAddress(
                         pInternal->hModule, "CardAcquireContext")))
        {
            status = GetLastError();
            __leave;
        }

        //
        // Setup the context structures
        //

        pInternal->CardData.dwVersion = CARD_DATA_CURRENT_VERSION;
        pInternal->CardData.pfnCspAlloc = _Alloc;
        pInternal->CardData.pfnCspFree = _Free;
        pInternal->CardData.pfnCspReAlloc = _ReAlloc;
        pInternal->CardData.pfnCspCacheAddFile = _CacheAddFileStub;
        pInternal->CardData.pfnCspCacheLookupFile = _CacheLookupFileStub;
        pInternal->CardData.pfnCspCacheDeleteFile = _CacheDeleteFileStub;
        pInternal->CardData.hScard = hSCardHandle;
        pInternal->CardData.hSCardCtx = hSCardContext;

        pInternal->CardData.cbAtr = cbAtr;
        CHECK_ALLOC(pInternal->CardData.pbAtr = (PBYTE) _Alloc(cbAtr));
        memcpy(pInternal->CardData.pbAtr, pbAtr, cbAtr);

        cch = (DWORD) wcslen(wszCardName) + 1;
        CHECK_ALLOC(pInternal->CardData.pwszCardName = (LPWSTR) _Alloc(
            sizeof(WCHAR) * cch));
        _tcscpy_s(
            pInternal->CardData.pwszCardName, cch, wszCardName);

        //
        // Call the card module
        //

        CHECK_DWORD(pfnCardAcquireContext(&pInternal->CardData, dwFlags));

        //
        // Output the context structure
        //

        pMgSc->pvContext = pInternal;
        pInternal = NULL;
    }
    __finally
    {
        if (NULL != wszCardModule)
            SCardFreeMemory(hSCardContext, wszCardModule);
        if (NULL != pInternal)
            _FreeManagedContext(pInternal);
    }

    return status;
}

//
// Authenticate to the card as the specified user
//

DWORD 
MgScCardAuthenticatePin(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPWSTR      pwszUserId,
    //__in_bcount(cbPin)          PBYTE       pbPin,
    //__in                        DWORD       cbPin,
	__in                        LPWSTR      pwszPin,
    __out_opt                   PDWORD      pcAttemptsRemaining)
{
    DWORD status = ERROR_SUCCESS;
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;
    
    LPSTR szPin = NULL;
    DWORD cbPin = 0;

    __try
    {
        //
        // Convert the PIN to ANSI
        //

        if (0 == (cbPin = WideCharToMultiByte(
            CP_ACP,
            0,
            pwszPin,
            -1,
            NULL,
            0,
            NULL,
            NULL)))
        {
            status = GetLastError();
            __leave;
        }

        CHECK_ALLOC(szPin = (LPSTR) _Alloc(cbPin));

        if (0 == (cbPin = WideCharToMultiByte(
            CP_ACP,
            0,
            pwszPin,
            -1,
            szPin,
            cbPin,
            NULL,
            NULL)))
        {
            status = GetLastError();
            __leave;
        }

        //
        // Call the card module
        //
		status = pInternal->CardData.pfnCardAuthenticatePin(
					&pInternal->CardData,
					pwszUserId,
					(PBYTE) szPin,
					cbPin - 1,
					pcAttemptsRemaining);
        CHECK_DWORD(status);
    }
    __finally
    {
        if (NULL != szPin)
            _Free(szPin);
    }

    return status;
    

    /*return pInternal->CardData.pfnCardAuthenticatePin(
        &pInternal->CardData,
        pwszUserId,
        pbPin,
        cbPin,
        pcAttemptsRemaining);*/
}

//
// Create a new file on the card
//

DWORD 
MgScCardCreateFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       cbInitialCreationSize,
    __in                        CARD_FILE_ACCESS_CONDITION AccessCondition)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;

    return pInternal->CardData.pfnCardCreateFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        cbInitialCreationSize,
        AccessCondition);
}

//
// Deauthenticate the card
//

DWORD 
MgScCardDeauthenticate(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPWSTR      pwszUserId,
    __in                        DWORD       dwFlags)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;

    if (NULL != pInternal->CardData.pfnCardDeauthenticate)
        return pInternal->CardData.pfnCardDeauthenticate(
            &pInternal->CardData,
            pwszUserId,
            dwFlags);
    else
        return ERROR_CALL_NOT_IMPLEMENTED;
}

//
// Free context and card module resources
//

void
MgScCardDeleteContext(
    __inout                     PMGSC_CONTEXT pMgSc)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;

    pInternal->CardData.pfnCardDeleteContext(&pInternal->CardData);

    _FreeManagedContext(pInternal);
}

//
// Delete a file from the card
//

DWORD 
WINAPI
MgScCardDeleteFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;

    return pInternal->CardData.pfnCardDeleteFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        dwFlags);
}

//
// Read a file from the card
//

DWORD
WINAPI
MgScCardReadFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags,
    __out_bcount_opt(*pcbData)  PBYTE       pbData,
    __inout                     PDWORD      pcbData)
{
    DWORD status = ERROR_SUCCESS;
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;
    PBYTE pbLocal = NULL;
    DWORD cbLocal = 0;

    __try
    {
        CHECK_DWORD(pInternal->CardData.pfnCardReadFile(
            &pInternal->CardData,
            pszDirectoryName,
            pszFileName,
            dwFlags,
            &pbLocal,
            &cbLocal));

        if (*pcbData < cbLocal)
        {
            if (NULL != pbData)
                status = ERROR_INSUFFICIENT_BUFFER;
        }
        else if (NULL != pbData)
        {
            memcpy(pbData, pbLocal, cbLocal);
        }

        *pcbData = cbLocal;
    }
    __finally
    {
        if (NULL != pbLocal)
            _Free(pbLocal);
    }
    
    return status;
}

//
// Write a file to the card
//

DWORD
WINAPI
MgScCardWriteFile(
    __in                        PMGSC_CONTEXT pMgSc,
    __in                        LPSTR       pszDirectoryName,
    __in                        LPSTR       pszFileName,
    __in                        DWORD       dwFlags,
    __in_bcount(cbData)         PBYTE       pbData,
    __in                        DWORD       cbData)
{
    PINTERNAL_CONTEXT pInternal = (PINTERNAL_CONTEXT) pMgSc->pvContext;

    return pInternal->CardData.pfnCardWriteFile(
        &pInternal->CardData,
        pszDirectoryName,
        pszFileName,
        dwFlags,
        pbData,
        cbData);
}

BOOL CheckPINandGetRemainingAttempts(PTSTR szReader, PTSTR szCard, PTSTR szPin, PDWORD pdwAttempts)
{
	MGSC_CONTEXT pContext = {0};
	SCARDCONTEXT hSCardContext = NULL;
	SCARDHANDLE hSCardHandle = NULL;
	BYTE bAtr[32];
	DWORD cbAtr = ARRAYSIZE(bAtr);
	LONG lReturn;
	DWORD dwSize, dwState, dwProtocol;
	DWORD dwError = 0;
	TCHAR szReaderTemp[256];
	BOOL fReturn = FALSE;
	__try
	{
		if (pdwAttempts == NULL)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pdwAttempts = NULL");
			__leave;
		}
		*pdwAttempts = 0xFFFFFFFF;
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
								NULL,
								NULL,
								&hSCardContext );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		lReturn = SCardConnect(hSCardContext,szReader,SCARD_SHARE_SHARED,SCARD_PROTOCOL_Tx, &hSCardHandle, &dwProtocol);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		dwSize = ARRAYSIZE(szReaderTemp);
		lReturn = SCardStatus(hSCardHandle, szReaderTemp, &dwSize, &dwState, &dwProtocol, bAtr,&cbAtr);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardStatus 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		lReturn = SCardBeginTransaction(hSCardHandle);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardBeginTransaction 0x%08X",lReturn);
			dwError = lReturn;
			__leave;
		}
		dwError = MgScCardAcquireContext(&pContext,hSCardContext,hSCardHandle,szCard,bAtr,cbAtr,0);
		if ( dwError )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MgScCardAcquireContext 0x%08X",lReturn);
			__leave;
		}
		dwError = MgScCardAuthenticatePin(&pContext,wszCARD_USER_USER,szPin,pdwAttempts);
		if ( dwError )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"MgScCardAuthenticatePin 0x%08X *pdwAttempts=%d",lReturn, *pdwAttempts);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"cardmodule authentication successfull");
		fReturn = TRUE;
	}
	__finally
	{
		BOOL fDeAuthenticated = FALSE;
		if (pContext.pvContext)
		{
			if (MgScCardDeauthenticate(&pContext, wszCARD_USER_USER, 0) == ERROR_SUCCESS)
			{
				fDeAuthenticated = TRUE;
			}
			MgScCardDeleteContext(&pContext);
		}
		if (hSCardHandle)
		{
			if (!fDeAuthenticated)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reset Card");
				SCardEndTransaction(hSCardHandle,SCARD_RESET_CARD);
			}
			else
			{
				SCardEndTransaction(hSCardHandle,SCARD_LEAVE_CARD);
			}
			SCardDisconnect(hSCardHandle,0);
		}
		if (hSCardContext)
			SCardReleaseContext(hSCardContext);
	}
	SetLastError(dwError);
	return fReturn;
}

NTSTATUS CheckPINandGetRemainingAttemptsIfPossible(PEID_SMARTCARD_CSP_INFO pCspInfo, PTSTR szPin, NTSTATUS *pSubStatus)
{
	DWORD dwAttempts;
	LPTSTR szCSPName = pCspInfo->bBuffer + pCspInfo->nCSPNameOffset;
	LPTSTR szCardName = pCspInfo->bBuffer + pCspInfo->nCardNameOffset;
	LPTSTR szReaderName = pCspInfo->bBuffer + pCspInfo->nReaderNameOffset;
	// do the test only if it is a mini driver
	if (_tcscmp(MS_SCARD_PROV, szCSPName) != 0)
	{
		return 0;
	}
	if (_tcscmp(TEXT("Identity Device (NIST SP 800-73 [PIV])"), szCardName) == 0)
	{
		return 0;
	}
	EIDImpersonate();
	BOOL fReturn = CheckPINandGetRemainingAttempts(szReaderName, szCardName, szPin, &dwAttempts);
	DWORD dwError = GetLastError();
	EIDRevertToSelf();
	if (fReturn)
	{
		return STATUS_SUCCESS;
	}
	else if (dwError == SCARD_W_WRONG_CHV)
	{
		*pSubStatus = dwAttempts;
		return STATUS_SMARTCARD_WRONG_PIN;
	}
	else if (dwError == SCARD_W_CHV_BLOCKED)
	{
		return STATUS_SMARTCARD_CARD_BLOCKED;
	}
	else
	{
		// ignore this test
		return STATUS_SUCCESS;
	}
}