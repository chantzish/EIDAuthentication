#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winwlx.h>
//#include <Sddl.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/Package.h"
#include "../EIDCardLibrary/CContainer.h"
#include "global.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "../EIDCardLibrary/SmartCardModule.h"

PWSTR DuplicateUnicodeStringWithShift(PUNICODE_STRING source, PVOID pShift)
{
	PWSTR szReturn = NULL;
	if (!source) return NULL;
	if (source->Length == 0) return NULL;
	DWORD dwNum = source->Length/2 + 1;
	szReturn = (PWSTR) EIDAlloc(dwNum * sizeof(WCHAR));
	if (!szReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
		return NULL;
	}
	memcpy(szReturn, (PUCHAR)pShift + (ULONG_PTR) (source->Buffer), source->Length);
	szReturn[source->Length/2] = L'\0';
	return szReturn;
}	

/*
BOOL CanSmartCardBeUsedByEIDAuthenticate(PWLX_SC_NOTIFICATION_INFO pNotificationInfo, PDWORD pdwKeySpec, PDWORD pdwRid)
{
	BOOL fReturn = FALSE;
	HCRYPTPROV hProv = NULL;
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};
	HCRYPTKEY hKey = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Container = %s, provider = %s",pNotificationInfo->pszContainer, pNotificationInfo->pszCryptoProvider);
		if (!CryptAcquireContext(&hProv, pNotificationInfo->pszContainer, pNotificationInfo->pszCryptoProvider, PROV_RSA_FULL, CRYPT_SILENT))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptAcquireContext 0x%08x", GetLastError());
			__leave;
		}
		for (DWORD i = 0; i < ARRAYSIZE(pKeySpecs); i++)
		{
			if (CryptGetUserKey(hProv,
					pKeySpecs[i],
					&hKey) )
			{
				BYTE Data[4096];
				DWORD DataSize = 4096;
				if (CryptGetKeyParam(hKey,
						KP_CERTIFICATE,
						Data,
						&DataSize,
						0))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"with i = %d", i);
					pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize);
					if (pCertContext)
					{
						*pdwKeySpec = pKeySpecs[i];
						*pdwRid = LsaEIDGetRIDFromStoredCredential(pCertContext);
						CertFreeCertificateContext(pCertContext);
						if (*pdwRid) 
						{
							EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Certificate found rid = %d", *pdwRid);
							fReturn = TRUE;
							__leave;
						}
					}
				}
				CryptDestroyKey(hKey);
				hKey = NULL;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"No certificate found");
	}
	__finally
	{
		if (hProv) CryptReleaseContext(hProv, 0);
		if (hKey) CryptDestroyKey(hKey);
	}
	return fReturn;
}
*/
/*
BOOL CallLsaLogonUserEIDAuthenticate(
									SECURITY_LOGON_TYPE logonType,
									PEID_INTERACTIVE_LOGON pLogonRequest,
									DWORD cbLogonRequest,
									__out PLUID pLogonSessionId,
									__out PHANDLE phToken,
									__out MSV1_0_INTERACTIVE_PROFILE** ppProfile,
									__out PDWORD pWin32Error) 
{

    BOOL fResult      = FALSE;
    DWORD win32Error = 0;
    *phToken         = 0;
	HANDLE hLsa = NULL;

    LUID ignoredLogonSessionId;
	MSV1_0_INTERACTIVE_PROFILE* pProfile = 0;
	LSA_STRING logonProcessName            = { 0 };
	LSA_STRING lsaszPackageName            = { 0 };
	NTSTATUS status;
	
	__try
	{
		// optional arguments
		if (ppProfile)        *ppProfile   = 0;
		if (pWin32Error)      *pWin32Error = 0;
		if (!pLogonSessionId) pLogonSessionId = &ignoredLogonSessionId;

		TOKEN_SOURCE sourceContext             = { 's', 'a', 'm', 'p', 'l', 'e' };
		
		ULONG cbProfile = 0;
		QUOTA_LIMITS quotaLimits;
		NTSTATUS substatus;
		ULONG ulAuthPackage = 0;
		
		LsaInitString(&logonProcessName, "EIDGina");
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);
		LSA_OPERATIONAL_MODE SecurityMode;
		status = LsaRegisterLogonProcess(&logonProcessName, &hLsa, &SecurityMode);
		if (status)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaRegisterLogonProcess 0x%08X", status);
			win32Error = LsaNtStatusToWinError(status);
			__leave;
		}
		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaLookupAuthenticationPackage 0x%08X", status);
			win32Error = LsaNtStatusToWinError(status);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Login (logonType = %d)",logonType);
		// LsaLogonUser - the function from hell
		status = LsaLogonUser(
			hLsa,
			&logonProcessName,  // we use our logon process name for the "origin name"
			logonType,
	        ulAuthPackage,
			pLogonRequest,
			cbLogonRequest,
			0,                  // we do not add any group SIDs
			&sourceContext,
			(void**)&pProfile,  // caller must free this via LsaFreeReturnBuffer 
			&cbProfile,
			pLogonSessionId,
			phToken,
			&quotaLimits,       // we ignore this, but must pass in anyway
			&substatus);

		if (status) {
			win32Error = LsaNtStatusToWinError(status);

			if ((ERROR_ACCOUNT_RESTRICTION == win32Error && STATUS_PASSWORD_EXPIRED == substatus)) {
				win32Error = ERROR_PASSWORD_EXPIRED;
			}

			*phToken = 0;
			pProfile = 0;
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"LsaLogonUser failed. Status = %d, substatus = 0x%08X", win32Error, substatus);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"LsaLogonUser success ! hToken = 0x%08x", *phToken);
		if (ppProfile) {
			*ppProfile = (MSV1_0_INTERACTIVE_PROFILE*)pProfile;
			pProfile = 0;
		}
		
		fResult = TRUE;
	}
	__finally
	{
		// if caller cares about the details, pass them on
		if (pWin32Error) *pWin32Error = win32Error;

		if (pProfile) LsaFreeReturnBuffer(pProfile);
		if (hLsa) LsaDeregisterLogonProcess(hLsa);
	}
    return fResult;
}*/
/*
BOOL AllocateProfil(PMSV1_0_INTERACTIVE_PROFILE pMSVProfile, PWLX_PROFILE_V1_0 *pProfile)
{
	BOOL fReturn = FALSE;
	__try
	{
		if (pMSVProfile->ProfilePath.Length == 0)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"no profile");
			*pProfile = NULL;
			fReturn = TRUE;
			__leave;
		}
		*pProfile = (PWLX_PROFILE_V1_0)LocalAlloc(LMEM_FIXED, sizeof(WLX_PROFILE_V1_0));
		if (!pProfile)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		(*pProfile)->dwType = WLX_PROFILE_TYPE_V1_0;
		(*pProfile)->pszProfile = (PWSTR) LocalAlloc(LMEM_FIXED, pMSVProfile->ProfilePath.Length + sizeof(WCHAR));
		if (!(*pProfile)->pszProfile)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memcpy( (*pProfile)->pszProfile, pMSVProfile->ProfilePath.Buffer, pMSVProfile->ProfilePath.Length);
		(*pProfile)->pszProfile[pMSVProfile->ProfilePath.Length/2] = L'\0';
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"profile = %s", (*pProfile)->pszProfile);
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			LocalFree(pProfile);
			pProfile = NULL;
		}
	}
	return fReturn;
}*/
/*
BOOL GetLogonSid(HANDLE hToken,PSID pSid)
{
    BOOL fReturn = FALSE;
	DWORD dwSize;
	PTOKEN_GROUPS ptg;
	PWSTR szSid = NULL;
	__try
	{
		GetTokenInformation(hToken, TokenGroups, 0, 0, &dwSize);
		ptg = (TOKEN_GROUPS*) EIDAlloc(dwSize);
		if (!ptg) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}

		if (!GetTokenInformation(hToken, TokenGroups, ptg, dwSize, &dwSize)) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetTokenInformation(TokenGroups) 0x%08x", GetLastError());
			__leave;
		}
		// search for the logon SID
		for (DWORD i = 0; i < ptg->GroupCount; ++i) 
		{
			if (ptg->Groups[i].Attributes & SE_GROUP_LOGON_ID) 
			{
				PSID logonSid = ptg->Groups[i].Sid;
				dwSize = GetLengthSid(logonSid);
				if (!CopySid(dwSize, pSid, logonSid)) {
					EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CopySid failed: %d", GetLastError());
					break;
				}
				ConvertSidToStringSid(pSid,&szSid);
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Sid = %s",szSid);
				LocalFree(szSid);
				fReturn = TRUE;
				__leave;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Failed to find a logon SID in the user's access token!");
	}
	__finally
	{
		EIDFree(ptg);
	}
    return fReturn;
}*/
/*
BOOL PrepareNprNotifyInfo(PEID_INTERACTIVE_LOGON pLogonStruct, PWLX_MPR_NOTIFY_INFO pNprNotifyInfo)
{
	BOOL fReturn = FALSE;
	__try
	{
		// username
		pNprNotifyInfo->pszUserName = (PWSTR) LocalAlloc(LMEM_FIXED, pLogonStruct->UserName.Length + sizeof(WCHAR));
		if (!pNprNotifyInfo->pszUserName)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memcpy(pNprNotifyInfo->pszUserName, ((PUCHAR) pLogonStruct) + (ULONG_PTR) pLogonStruct->UserName.Buffer, pLogonStruct->UserName.Length);
		pNprNotifyInfo->pszUserName [pLogonStruct->UserName.Length/2] = L'\0';
		// domain
		pNprNotifyInfo->pszDomain = (PWSTR) LocalAlloc(LMEM_FIXED, pLogonStruct->LogonDomainName.Length + sizeof(WCHAR));
		if (!pNprNotifyInfo->pszDomain)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memcpy(pNprNotifyInfo->pszDomain, ((PUCHAR) pLogonStruct) + (ULONG_PTR) pLogonStruct->LogonDomainName.Buffer, pLogonStruct->LogonDomainName.Length);
		pNprNotifyInfo->pszDomain [pLogonStruct->LogonDomainName.Length/2] = L'\0';
		pNprNotifyInfo->pszPassword = (PWSTR) LocalAlloc(LMEM_FIXED,sizeof(WCHAR));
		if (!pNprNotifyInfo->pszPassword)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		pNprNotifyInfo->pszPassword[0]=L'\0';
		pNprNotifyInfo->pszOldPassword = NULL;
		// success
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (pNprNotifyInfo->pszUserName) 
			{
				LocalFree(pNprNotifyInfo->pszUserName);
				pNprNotifyInfo->pszUserName = NULL;
			}
			if (pNprNotifyInfo->pszDomain) 
			{
				LocalFree(pNprNotifyInfo->pszDomain);
				pNprNotifyInfo->pszDomain = NULL;
			}
			if (pNprNotifyInfo->pszPassword) 
			{
				LocalFree(pNprNotifyInfo->pszPassword);
				pNprNotifyInfo->pszPassword = NULL;
			}
			if (pNprNotifyInfo->pszOldPassword) 
			{
				LocalFree(pNprNotifyInfo->pszOldPassword);
				pNprNotifyInfo->pszOldPassword = NULL;
			}
		}
	}
	return fReturn;
}*/
/*
BOOL LogonUsingSmartCard(__in PWSTR szPin,
						__in CContainer* pContainer,
						__in SECURITY_LOGON_TYPE logonType,
						__out PLUID                   pAuthenticationId,
						__out PHANDLE                 phToken,
						__out PWSTR *                 pszUserName,
						__out PWSTR *                 pszDomain,
						__out PMSV1_0_INTERACTIVE_PROFILE *     pProfile,
						__out PDWORD pdwError)
{
	BOOL fReturn = FALSE, fResult;
	PEID_INTERACTIVE_LOGON pLogonStruct = NULL;
	DWORD dwSize;
	_ASSERTE( _CrtCheckMemory( ) );
	__try
	{
		pLogonStruct = pContainer->AllocateLogonStruct(szPin, &dwSize);
		if (!pLogonStruct)
		{
			__leave;
		}
		fResult = CallLsaLogonUserEIDAuthenticate(logonType, pLogonStruct, dwSize, pAuthenticationId, phToken,  pProfile, pdwError);
		if (!fResult)
		{
			__leave;
		}
		*pszUserName = DuplicateUnicodeStringWithShift(&(pLogonStruct->UserName), pLogonStruct);
		*pszDomain = DuplicateUnicodeStringWithShift(&(pLogonStruct->LogonDomainName), pLogonStruct);
		fReturn = TRUE;
	}
	__finally
	{
		if (pLogonStruct)
		{
			SecureZeroMemory(pLogonStruct, dwSize);
			EIDFree(pLogonStruct);
		}
		if (!fReturn)
		{
			if (pProfile && *pProfile) LsaFreeReturnBuffer(*pProfile);
		}
		
	}
	// sanity check because the memory used here is critical
	_ASSERTE( _CrtCheckMemory( ) );
	return fReturn;
}
*/

BOOL GetPassword(__in PWSTR szPin,
				 __in CContainer* pContainer,
				 __out PWSTR *pszUserName,
				 __out PWSTR *pszPassword,
				 __out PWSTR *pszDomain,
				 __out_opt PDWORD pdwError,
				 __out_opt PDWORD pdwRemainingPin)
{
	BOOL fReturn = FALSE;
	EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST ChallengeRequest;
	PEID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER pChallengeAnswer = NULL;
	PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST pResponseRequest = NULL;
	PEID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER pResponseAnswer = NULL;
	PEID_SMARTCARD_CSP_INFO pSmartCardCspInfo = NULL;
	HANDLE hLsa = NULL;
	NTSTATUS status, protocolStatus;
	DWORD dwSize = 0;
	LSA_STRING logonProcessName            = { 0 };
	LSA_STRING lsaszPackageName            = { 0 };
	ULONG ulAuthPackage, ulSize;
	DWORD dwError = 0;
	PBYTE pbResponse = NULL;
	DWORD dwResponseSize = 0;
	DWORD dwRemainingPin = 0xFFFFFFFF;
	__try
	{
		*pszUserName = NULL;
		*pszPassword = NULL;
		*pszDomain = NULL;

		CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
		if (!manager)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
			dwError = ERROR_INTERNAL_ERROR;
			__leave;
		}
		pSmartCardCspInfo = pContainer->GetCSPInfo();
		if (!pSmartCardCspInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pSmartCardCspInfo NULL");
			dwError = ERROR_INTERNAL_ERROR;
			__leave;
		}
		status = CheckPINandGetRemainingAttemptsIfPossible(pSmartCardCspInfo, szPin, (PNTSTATUS) &dwRemainingPin);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckPINandGetRemainingAttemptsIfPossible 0x%08X", status);
			__leave;
		}
		LsaInitString(&logonProcessName, "EIDGina");
		LsaInitString(&lsaszPackageName, AUTHENTICATIONPACKAGENAME);

		LSA_OPERATIONAL_MODE SecurityMode;
		status = LsaRegisterLogonProcess(&logonProcessName, &hLsa, &SecurityMode);
		if (status)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaRegisterLogonProcess 0x%08X", status);
			__leave;
		}
		status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaLookupAuthenticationPackage 0x%08X", status);
			__leave;
		}
		ChallengeRequest.MessageType = EIDCMEIDGinaAuthenticationChallenge;
		ChallengeRequest.dwRid = pContainer->GetRid();
		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, &ChallengeRequest, sizeof(EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST), (PVOID*) &pChallengeAnswer, &ulSize, &protocolStatus);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaCallAuthenticationPackage 0x%08X", status);
			__leave;
		}
		if (!manager->GetResponseFromChallenge(pChallengeAnswer->pbChallenge,pChallengeAnswer->dwChallengeSize, pChallengeAnswer->dwChallengeType, pContainer->GetCertificate(),szPin, &pbResponse, &dwResponseSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"GetResponseFromChallenge 0x%08X", dwError);
			__leave;
		}
		dwSize = sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST) + pChallengeAnswer->dwChallengeSize + dwResponseSize;
		pResponseRequest = (PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST) EIDAlloc(dwSize);
		if (!pResponseRequest)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"manager NULL");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		pResponseRequest->MessageType = EIDCMEIDGinaAuthenticationResponse;
		pResponseRequest->dwRid = pContainer->GetRid();
		pResponseRequest->dwChallengeSize = pChallengeAnswer->dwChallengeSize;
		pResponseRequest->dwChallengeType = pChallengeAnswer->dwChallengeType;
		pResponseRequest->dwResponseSize = dwResponseSize;
		pResponseRequest->pbChallenge = (PBYTE) sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST);
		pResponseRequest->pbResponse = (PBYTE)  sizeof(EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST) + pResponseRequest->dwChallengeSize;
		memcpy(pResponseRequest->pbChallenge + (ULONG_PTR) pResponseRequest, pChallengeAnswer->pbChallenge, pChallengeAnswer->dwChallengeSize);
		memcpy(pResponseRequest->pbResponse + (ULONG_PTR) pResponseRequest, pbResponse, dwResponseSize);

		status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, pResponseRequest, dwSize, (PVOID*) &pResponseAnswer, &ulSize, &protocolStatus);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"LsaCallAuthenticationPackage 0x%08X", status);
			__leave;
		}
		if (pResponseAnswer->dwError)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"error 0x%08X", pResponseAnswer->dwError);
			dwError = pResponseAnswer->dwError;
			__leave;
		}
		// password
		*pszPassword = (PWSTR) EIDAlloc(pResponseAnswer->Password.Length + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		memcpy(*pszPassword , pResponseAnswer->Password.Buffer,pResponseAnswer->Password.Length);
		(*pszPassword)[pResponseAnswer->Password.Length/2] = L'\0';
		// username
		*pszUserName = GetUsernameFromRid(pContainer->GetRid());
		if (!*pszUserName)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"szUserName not found");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		//domain
		*pszDomain = (PWSTR) EIDAlloc((MAX_COMPUTERNAME_LENGTH +1) * sizeof(WCHAR));
		if (!*pszDomain)
		{
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		dwSize = MAX_COMPUTERNAME_LENGTH +1;
		GetComputerName(*pszDomain, &dwSize);
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pszUserName) EIDFree(*pszUserName);
			if (*pszPassword) EIDFree(*pszPassword);
			if (*pszDomain) EIDFree(*pszDomain);
		}
		if (pChallengeAnswer)
			LsaFreeReturnBuffer(pChallengeAnswer);
		if (pResponseRequest)
			EIDFree(pResponseRequest);
		if (pResponseAnswer)
			LsaFreeReturnBuffer(pResponseAnswer);
		if (pbResponse) EIDFree(pbResponse);
		if (hLsa) LsaClose(hLsa);
		if (pSmartCardCspInfo) pContainer->FreeCSPInfo(pSmartCardCspInfo);
	}
	if (fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Leaving with error 0x%08X", dwError);
	}
	if (pdwError) *pdwError = dwError;
	if (pdwRemainingPin) *pdwRemainingPin = dwRemainingPin;
	return fReturn;
}