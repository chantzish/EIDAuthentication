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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <sspi.h>

#include <shlobj.h>
#include <Ntsecapi.h>
#include <lm.h>

#include <Ntsecpkg.h>

#include "EidCardLibrary.h"
#include "Tracing.h"

#define CREDENTIALPROVIDER MS_ENH_RSA_AES_PROV
#define CREDENTIALKEYLENGTH 256
#define CREDENTIALCRYPTALG CALG_AES_256
#define CREDENTIAL_LSAPREFIX L"L$_EID_"
#define CREDENTIAL_CONTAINER TEXT("EIDCredential")

#pragma comment(lib,"Crypt32")
#pragma comment(lib,"advapi32")
#pragma comment(lib,"Netapi32")



extern "C"
{
	NTSTATUS WINAPI SystemFunction007 (PUNICODE_STRING string, LPBYTE hash);
}

// level 1
#include "StoredCredentialManagement.h"
CStoredCredentialManager *CStoredCredentialManager::theSingleInstance = NULL;

BOOL CStoredCredentialManager::GetUsernameFromCertContext(__in PCCERT_CONTEXT pContext, __out PWSTR *pszUsername, __out PDWORD pdwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = NULL;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pPrivateData = NULL;
	DWORD dwError = 0;
	__try
	{
		if (!pContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pszUsername)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pszUsername null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pdwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pdwRid null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		*pdwRid = 0;
		Status = NetUserEnum(NULL, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			// for each credential
			if (RetrievePrivateData(pUserInfo[dwI].usri3_user_id, &pPrivateData))
			{
				if (pPrivateData->dwCertificatSize == pContext->cbCertEncoded)
				{
					if (memcmp(pPrivateData->Data + pPrivateData->dwCertificatOffset, pContext->pbCertEncoded, pContext->cbCertEncoded) == 0)
					{
						// found
						*pdwRid = pUserInfo[dwI].usri3_user_id;
						PWSTR Username = pUserInfo[dwI].usri3_name;
						*pszUsername = (PWSTR) EIDAlloc((DWORD)(wcslen(Username) +1) * sizeof(WCHAR));
						
						if (*pszUsername)
						{
							wcscpy_s(*pszUsername, wcslen(Username) +1, Username);
							EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Found 0x%x %s",*pdwRid, *pszUsername);
							fReturn = TRUE;
						}
						else
						{
							dwError = GetLastError();
							EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
						}
						EIDFree(pPrivateData);
						break;
					}
					else
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"%d don't match", pUserInfo[dwI].usri3_user_id);
					}
				}
				EIDFree(pPrivateData);
			}
		}
		if (!fReturn)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not found");
		}
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::HasStoredCredential(__in PCCERT_CONTEXT pContext)
{
	DWORD dwRid;
	PWSTR szUsername = NULL;
	if (GetUsernameFromCertContext(pContext, &szUsername, &dwRid))
	{
		EIDFree(szUsername);
		return TRUE;
	}
	return FALSE;
}

BOOL CStoredCredentialManager::GetCertContextFromHash(__in PBYTE pbHash, __out PCCERT_CONTEXT* ppContext, __out PDWORD pdwRid)
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = NULL;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pPrivateData = NULL;
	DWORD dwError = 0;
	__try
	{
		if (!ppContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pdwRid)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"pdwRid null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		Status = NetUserEnum(NULL, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			dwError = Status;
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			// for each credential
			if (RetrievePrivateData(pUserInfo[dwI].usri3_user_id, &pPrivateData))
			{
				if (memcmp(pPrivateData->Hash, pbHash, CERT_HASH_LENGTH) == 0)
				{
					// found
					*pdwRid = pUserInfo[dwI].usri3_user_id;
					*ppContext = CertCreateCertificateContext(X509_ASN_ENCODING,
								pPrivateData->Data + pPrivateData->dwCertificatOffset, pPrivateData->dwCertificatSize);
					if (*ppContext)
					{
						fReturn = TRUE;
					}
					else
					{
						dwError = GetLastError();
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
					}
					EIDFree(pPrivateData);
					break;
				}
				EIDFree(pPrivateData);
			}
		}
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::GetCertContextFromRid(__in DWORD dwRid, __out PCCERT_CONTEXT* ppContext, __out PBOOL pfEncryptPassword)
{
	BOOL fReturn = FALSE, fStatus;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	DWORD dwError = 0;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (!ppContext)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppContext null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		if (!pfEncryptPassword)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"fEncryptPassword null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		*ppContext = CertCreateCertificateContext(X509_ASN_ENCODING, 
						pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset,
						pEidPrivateData->dwCertificatSize);
		if (!*ppContext) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		*pfEncryptPassword = (pEidPrivateData->dwType == eidpdtCrypted);
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			CertFreeCertificateContext(*ppContext);
			*ppContext = NULL;
		}
		if (pEidPrivateData)
		{
			EIDFree(pEidPrivateData);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::CreateCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPassword, __in_opt USHORT usPasswordLen, __in BOOL fEncryptPassword, __in BOOL fCheckPassword)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwError = 0;
	NTSTATUS Status;
	HCRYPTKEY hKey = NULL;
	HCRYPTKEY hSymetricKey = NULL;
	PBYTE pSymetricKey = NULL;
	USHORT usSymetricKeySize;
	PBYTE pEncryptedPassword = NULL;
	USHORT usEncryptedPasswordSize;
	PEID_PRIVATE_DATA pbSecret = NULL;
	USHORT usSecretSize;
	USHORT usPasswordSize;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;
	PBYTE pbPublicKey = NULL;
	DWORD dwSize = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter fEncryptPassword = %d",fEncryptPassword);
		// check password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (fCheckPassword)
		{
			Status = CheckPassword(dwRid, szPassword);
			if (Status != STATUS_SUCCESS)
			{
				dwError = LsaNtStatusToWinError(Status);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckPassword 0x%08x",dwError);
				__leave;
			}
		}
		if (usPasswordLen > 0)
		{
			usPasswordSize = usPasswordLen;
		}
		else if (szPassword == NULL)
		{
			usPasswordSize = 0;
		}
		else
		{
			usPasswordSize = (USHORT) (wcslen(szPassword) * sizeof(WCHAR));
		}
		
		if (!usPasswordSize) fEncryptPassword = FALSE;
		if (fEncryptPassword)
		{
			fStatus = CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
				0, NULL, &dwSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptDecodeObject 0x%08x",GetLastError());
				__leave;
			}
			pbPublicKey = (PBYTE) EIDAlloc(dwSize);
			if (!pbPublicKey)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
				__leave;
			}
			fStatus = CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB, 
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				pCertContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
				0, pbPublicKey, &dwSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptDecodeObject 0x%08x",GetLastError());
				__leave;
			}
						// import the public key into hKey
			fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
			if(!fStatus)
			{
				dwError = GetLastError();
				if (dwError == NTE_BAD_KEYSET)
				{
					fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
					dwError = GetLastError();
				}
				if (!fStatus)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
			}
			fStatus = CryptImportKey(hProv, pbPublicKey, dwSize, NULL, 0, &hKey);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
				__leave;
			}
			// create a symetric key which can be used to crypt data and
			// which is saved and protected by the public key
			fStatus = GenerateSymetricKeyAndEncryptIt(hProv, hKey, &hSymetricKey, &pSymetricKey, &usSymetricKeySize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GenerateSymetricKeyAndSaveIt");
				__leave;
			}
			// encrypt the password and save it
			fStatus = EncryptPasswordAndSaveIt(hSymetricKey,szPassword,usPasswordLen, &pEncryptedPassword, &usEncryptedPasswordSize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EncryptPasswordAndSaveIt");
				__leave;
			}
			usSecretSize = (USHORT) sizeof(EID_PRIVATE_DATA) + usEncryptedPasswordSize + usSymetricKeySize + (USHORT) pCertContext->cbCertEncoded;
			pbSecret = (PEID_PRIVATE_DATA) EIDAlloc(usSecretSize);
			if (!pbSecret)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
				__leave;
			}
			DWORD dwHashSize = 20;
			fStatus = CryptHashCertificate(NULL, CALG_SHA1, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, pbSecret->Hash, &dwHashSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashCertificate 0x%08x",GetLastError());
				__leave;
			}

			// copy data
			pbSecret->dwType = eidpdtCrypted;
			pbSecret->dwCertificatSize = (USHORT) pCertContext->cbCertEncoded;
			pbSecret->dwSymetricKeySize = usSymetricKeySize;
			pbSecret->dwPasswordSize = usEncryptedPasswordSize;
			pbSecret->dwCertificatOffset = 0;
			memcpy(pbSecret->Data + pbSecret->dwCertificatOffset, pCertContext->pbCertEncoded, pbSecret->dwCertificatSize);
			pbSecret->dwSymetricKeyOffset = pbSecret->dwCertificatOffset + pbSecret->dwCertificatSize;
			memcpy(pbSecret->Data + pbSecret->dwSymetricKeyOffset, pSymetricKey, pbSecret->dwSymetricKeySize);
			pbSecret->dwPasswordOffset = pbSecret->dwSymetricKeyOffset + usSymetricKeySize;
			memcpy(pbSecret->Data + pbSecret->dwPasswordOffset, pEncryptedPassword, pbSecret->dwPasswordSize);
		}
		else
		{
		// uncrypted
			usSecretSize = (USHORT) sizeof(EID_PRIVATE_DATA) + usPasswordSize + (USHORT) pCertContext->cbCertEncoded;
			pbSecret = (PEID_PRIVATE_DATA) EIDAlloc(usSecretSize);
			if (!pbSecret)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
				__leave;
			}
			pbSecret->dwType = eidpdtClearText;
			pbSecret->dwCertificatSize = (USHORT) pCertContext->cbCertEncoded;
			pbSecret->dwSymetricKeySize = 0;
			pbSecret->dwPasswordSize = usPasswordSize;
			pbSecret->dwCertificatOffset = 0;
			memcpy(pbSecret->Data + pbSecret->dwCertificatOffset, pCertContext->pbCertEncoded, pbSecret->dwCertificatSize);
			pbSecret->dwSymetricKeyOffset = pbSecret->dwCertificatOffset + pbSecret->dwCertificatSize;
			pbSecret->dwPasswordOffset = pbSecret->dwSymetricKeyOffset;
			memcpy(pbSecret->Data + pbSecret->dwPasswordOffset, szPassword, pbSecret->dwPasswordSize);
		}
		// save the data
		if (!StorePrivateData(dwRid, (PBYTE) pbSecret, usSecretSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StorePrivateData");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbPublicKey)
			EIDFree(pbPublicKey);
		if (hHash)
			CryptDestroyHash(hHash);
		if (pSymetricKey)
			EIDFree(pSymetricKey);
		if (pEncryptedPassword)
			EIDFree(pEncryptedPassword);
		if (pbSecret)
			EIDFree(pbSecret);
		if (hSymetricKey)
			CryptDestroyKey(hSymetricKey);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::UpdateCredential(__in PLUID pLuid, __in PUNICODE_STRING Password)
{
	DWORD dwRid = 0;
	WCHAR szComputer[UNLEN+1];
	WCHAR szUser[256];
	DWORD dwSize = ARRAYSIZE(szComputer);
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	USER_INFO_3* pUserInfo = NULL;
	PSECURITY_LOGON_SESSION_DATA pLogonSessionData = NULL;
	NTSTATUS status;
	__try
	{
		status = LsaGetLogonSessionData(pLuid, &pLogonSessionData);
		if (status != STATUS_SUCCESS)
		{
			dwError = LsaNtStatusToWinError(status);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaGetLogonSessionData 0x%08x",status);
			__leave;
		}
		GetComputerName(szComputer,&dwSize);
		if (!((pLogonSessionData->LogonDomain.Length == dwSize * sizeof(WCHAR)
			&& memcmp(pLogonSessionData->LogonDomain.Buffer,szComputer, dwSize * sizeof(WCHAR)) == 0)))
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"not a local account '%wZ'", &(pLogonSessionData->LogonDomain));
			__leave;
		}
		// get the user ID (RID)
		PUNICODE_STRING UserName = &(pLogonSessionData->UserName);
		if (!UserName)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"UserName null");
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"using userName '%wZ'", UserName);

		if (UserName->Buffer && UserName->Length)
		{
			memcpy(szUser, UserName->Buffer,UserName->Length);
		}
		szUser[UserName->Length/2] = L'\0';
		dwError = NetUserGetInfo(szComputer, szUser, 3, (LPBYTE*) &pUserInfo);
		if (NERR_Success != dwError)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",dwError);
			__leave;
		}
		dwRid = pUserInfo->usri3_user_id;
		if (!UpdateCredential(dwRid, (Password->Length > 0 ? Password->Buffer:  NULL), Password->Length))
		{
			dwError = GetLastError();
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo) NetApiBufferFree(pUserInfo);
		if (pLogonSessionData) LsaFreeReturnBuffer(pLogonSessionData);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::UpdateCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwError = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fEncrypt;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		fStatus = GetCertContextFromRid(dwRid, &pCertContext, &fEncrypt);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetCertContextFromRid 0x%08x",dwError);
			__leave;
		}
		fStatus = CreateCredential(dwRid, pCertContext, szPassword, usPasswordLen, fEncrypt, FALSE);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCredential 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{

	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CStoredCredentialManager::GetChallenge(__in DWORD dwRid, __out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize, __out PDWORD pType)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	HCRYPTPROV hProv = NULL;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (!ppChallenge)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"ppChallenge null");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		*pType = pEidPrivateData->dwType;
		switch(*pType)
		{
		case eidpdtCrypted:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwType = eidpdtCrypted");
			*pdwChallengeSize = pEidPrivateData->dwSymetricKeySize;
			*ppChallenge = (PBYTE) EIDAlloc(pEidPrivateData->dwSymetricKeySize);
			if (*ppChallenge == NULL)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
				__leave;
			}
			memcpy(*ppChallenge, pEidPrivateData->Data + pEidPrivateData->dwSymetricKeyOffset, pEidPrivateData->dwSymetricKeySize); 
			break;
		case eidpdtClearText:
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"dwType = eidpdtClearText");
			fStatus = GetSignatureChallenge(ppChallenge, pdwChallengeSize);
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetSignatureChallenge 0x%08x",dwError);
				__leave;
			}
			break;
		default:
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwType not implemented");
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pEidPrivateData)
			EIDFree(pEidPrivateData);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::GetSignatureChallenge(__out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize)
{
	BOOL fReturn = FALSE, fStatus;
	HCRYPTPROV hProv = NULL;
	DWORD dwError = 0;
	__try
	{
		fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
		if(!fStatus)
		{
			dwError = GetLastError();
			if (dwError == NTE_BAD_KEYSET)
			{
				fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
				dwError = GetLastError();
			}
			if (!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
		}
		*pdwChallengeSize = CREDENTIALKEYLENGTH;
		*ppChallenge = (PBYTE) EIDAlloc(CREDENTIALKEYLENGTH);
		if (*ppChallenge == NULL)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		fStatus = CryptGenRandom(hProv, CREDENTIALKEYLENGTH, *ppChallenge);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenRandom 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{

		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}
BOOL CStoredCredentialManager::RemoveStoredCredential(__in DWORD dwRid)
{
	return StorePrivateData(dwRid, NULL, 0);
}
BOOL CStoredCredentialManager::RemoveAllStoredCredential()
{
	NET_API_STATUS Status;
	PUSER_INFO_3 pUserInfo = NULL;
	DWORD dwEntriesRead = 0, dwTotalEntries = 0;
	BOOL fReturn = FALSE;
	__try
	{
		Status = NetUserEnum(NULL, 3,0, (PBYTE*) &pUserInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead, &dwTotalEntries, NULL);
		if (Status != NERR_Success)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum 0x%08x",Status);
			SetLastError(Status);
			__leave;
		}
		for (DWORD dwI = 0; dwI < dwEntriesRead; dwI++)
		{
			RemoveStoredCredential(pUserInfo[dwI].usri3_user_id);
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pUserInfo)
			NetApiBufferFree(pUserInfo);
	}
	return fReturn;
}

BOOL CStoredCredentialManager::GetPassword(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PWSTR *pszPassword)
{
	BOOL fReturn = FALSE, fStatus;
	PBYTE pChallenge = NULL;
	PBYTE pResponse = NULL;
	DWORD dwResponseSize = 0, dwChallengeSize = 0;
	DWORD dwError = 0;
	DWORD type;
	__try
	{
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetChallenge");
		fStatus = GetChallenge(dwRid, &pChallenge, &dwChallengeSize, &type);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetChallenge 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetResponseFromChallenge");
		EIDImpersonate();
		fStatus = GetResponseFromChallenge(pChallenge, dwChallengeSize, type, pContext, szPin, &pResponse, &dwResponseSize);
		EIDRevertToSelf();
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetResponseFromChallenge 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"GetPasswordFromChallengeResponse");
		fStatus = GetPasswordFromChallengeResponse(dwRid, pChallenge, dwChallengeSize, type, pResponse, dwResponseSize, pszPassword);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetPasswordFromChallengeResponse 0x%08x",dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pChallenge)
		{
			SecureZeroMemory(pChallenge, dwChallengeSize);
			EIDFree(pChallenge);
		}
		if (pResponse)
		{
			SecureZeroMemory(pResponse, dwResponseSize);
			EIDFree(pResponse);
		}
	}
	SetLastError(dwError);
	return fReturn;
}
// level 2
////////////////////////////////////////////////////////////////////////////////
// LEVEL 1
////////////////////////////////////////////////////////////////////////////////

NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials)
{

	// futur : use MSV1_0_SUPPLEMENTAL_CREDENTIAL instead of clear password ?
	
	// general comment about the SECPKG_PRIMARY_CRED structure and DPAPI
	// grabbed from the kerberos SSP output :
	// Password logon :
	//  2 credentials added through AddCredentials (and not LsaApLogonUserEx2)
	//    password = the password in clear
	//    flag = 0x10000009 ( PRIMARY_CRED_CLEAR_PASSWORD | PRIMARY_CRED_CACHED_LOGON )
	//    password = the password in clear
	//    flag = 0x00000001 ( PRIMARY_CRED_CLEAR_PASSWORD )
	//
	// smart card logon :
	//  2 credentials added through AddCredentials (and not LsaApLogonUserEx2)
	//    password = the PIN in clear
	//    flag = 0x10000048 ( PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON | PRIMARY_CRED_CACHED_LOGON )
	//    password = the PIN in clear
	//    flag = 0x00000040 ( PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON )
	//
	// grabbed from the MSV_10 output :
	//     password = the password in clear
	//     flag = 0x0A000001 ( PRIMARY_CRED_CLEAR_PASSWORD )

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	memset(PrimaryCredentials, 0, sizeof(SECPKG_PRIMARY_CRED));
	PrimaryCredentials->LogonId.HighPart = LogonId->HighPart;
	PrimaryCredentials->LogonId.LowPart = LogonId->LowPart;

	PrimaryCredentials->DownlevelName.Length = AccountName->Length;
	PrimaryCredentials->DownlevelName.MaximumLength = AccountName->MaximumLength;
	PrimaryCredentials->DownlevelName.Buffer = (PWSTR) EIDAlloc(AccountName->MaximumLength);
	memcpy(PrimaryCredentials->DownlevelName.Buffer, AccountName->Buffer, AccountName->MaximumLength);

	PrimaryCredentials->DomainName.Length = AuthenticatingAuthority->Length;
	PrimaryCredentials->DomainName.MaximumLength = AuthenticatingAuthority->MaximumLength;
	PrimaryCredentials->DomainName.Buffer = (PWSTR) EIDAlloc(AuthenticatingAuthority->MaximumLength);
	if (PrimaryCredentials->DomainName.Buffer)
	{
		memcpy(PrimaryCredentials->DomainName.Buffer, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->MaximumLength);
	}

	PrimaryCredentials->Password.Length = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
	PrimaryCredentials->Password.MaximumLength = PrimaryCredentials->Password.Length;
	PrimaryCredentials->Password.Buffer = (PWSTR) EIDAlloc(PrimaryCredentials->Password.MaximumLength);
	if (PrimaryCredentials->Password.Buffer)
	{
		memcpy(PrimaryCredentials->Password.Buffer, szPassword, PrimaryCredentials->Password.Length);
	}

	// we decide that the password cannot be changed so copy it into old pass
	PrimaryCredentials->OldPassword.Length = 0;
	PrimaryCredentials->OldPassword.MaximumLength = 0;
	PrimaryCredentials->OldPassword.Buffer = NULL;//(PWSTR) FunctionTable->AllocateLsaHeap(PrimaryCredentials->OldPassword.MaximumLength);;
	
	// the flag PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON is used for the "force smart card policy"
	// the flag PRIMARY_CRED_CLEAR_PASSWORD is used to tell the password to DPAPI
	PrimaryCredentials->Flags = PRIMARY_CRED_CLEAR_PASSWORD | PRIMARY_CRED_INTERACTIVE_SMARTCARD_LOGON;

	PrimaryCredentials->UserSid = (PSID)EIDAlloc(GetLengthSid(UserSid));
	if (PrimaryCredentials->UserSid)
	{
		CopySid(GetLengthSid(UserSid),PrimaryCredentials->UserSid,UserSid);
	}

	PrimaryCredentials->DnsDomainName.Length = 0;
	PrimaryCredentials->DnsDomainName.MaximumLength = 0;
	PrimaryCredentials->DnsDomainName.Buffer = NULL;

	PrimaryCredentials->Upn.Length = 0;
	PrimaryCredentials->Upn.MaximumLength = 0;
	PrimaryCredentials->Upn.Buffer = NULL;

	PrimaryCredentials->LogonServer.Length = AuthenticatingAuthority->Length;
	PrimaryCredentials->LogonServer.MaximumLength = AuthenticatingAuthority->MaximumLength;
	PrimaryCredentials->LogonServer.Buffer = (PWSTR) EIDAlloc(AuthenticatingAuthority->MaximumLength);
	if (PrimaryCredentials->LogonServer.Buffer)
	{
		memcpy(PrimaryCredentials->LogonServer.Buffer, AuthenticatingAuthority->Buffer, AuthenticatingAuthority->MaximumLength);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return STATUS_SUCCESS;	
}

BOOL CStoredCredentialManager::GetResponseFromChallenge(__in PBYTE pChallenge, __in DWORD dwChallengeSize,__in DWORD dwChallengeType, __in PCCERT_CONTEXT pCertContext, __in PWSTR Pin, __out PBYTE *pSymetricKey, __out DWORD *usSize)
{
	switch(dwChallengeType)
	{
	case eidpdtClearText:
		return GetResponseFromSignatureChallenge(pChallenge,dwChallengeSize,pCertContext,Pin,pSymetricKey,usSize);
		break;
	case eidpdtCrypted:
		return GetResponseFromCryptedChallenge(pChallenge,dwChallengeSize,pCertContext,Pin,pSymetricKey,usSize);
		break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Type not implemented");
	return FALSE;
}
BOOL CStoredCredentialManager::GetResponseFromCryptedChallenge(__in PBYTE pChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR Pin, __out PBYTE *pSymetricKey, __out DWORD *usSize)
{
	BOOL fReturn = FALSE;
	// check private key
	HCRYPTPROV hProv = NULL;
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = FALSE;
	HCRYPTKEY hCertKey = NULL;
	LPSTR pbPin = NULL;
	DWORD dwPinLen = 0;
	HCRYPTKEY hKey = NULL;
	DWORD dwSize;
	DWORD dwBlockLen = 20000;
	DWORD dwError = 0;
	PCRYPT_KEY_PROV_INFO pProvInfo = NULL;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
		if (!pSymetricKey)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pSymetricKey NULL");
			dwError = ERROR_INVALID_PARAMETER;
			__leave;
		}
		*pSymetricKey = NULL;
		// acquire context on private key
		dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pProvInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pProvInfo null");
			dwError = ERROR_OUTOFMEMORY;
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		dwKeySpec = pProvInfo->dwKeySpec;
		if (!CryptAcquireCertificatePrivateKey(pCertContext,CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,NULL,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptAcquireCertificatePrivateKey", GetLastError());
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIV fallback");
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pProvInfo->pwszContainerName, pProvInfo->pwszProvName);
			if (!CryptAcquireContext(&hProv, NULL, pProvInfo->pwszProvName, pProvInfo->dwProvType, CRYPT_SILENT))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptAcquireContext", GetLastError());
				__leave;
			}
		}

		if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetUserKey", GetLastError());
			__leave;
		}
		dwPinLen = (DWORD) (wcslen(Pin) + sizeof(CHAR));
		pbPin = (LPSTR) EIDAlloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_ACP, 0, Pin, -1, pbPin, dwPinLen, NULL, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			dwBlockLen = 20000; 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam - using %d as KP_BLOCKLEN", GetLastError(), dwBlockLen);
			dwError = 0;
		}
		*pSymetricKey = (PBYTE) EIDAlloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, pChallenge, dwChallengeSize);
		dwSize = dwChallengeSize;
		if (!CryptDecrypt(hKey, NULL, TRUE, 0, *pSymetricKey, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptDecrypt", GetLastError());
			__leave;
		}
		*usSize = (USHORT) dwSize;

		
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pSymetricKey)
			{
				EIDFree(*pSymetricKey );
				*pSymetricKey = NULL;
			}
		}
		if (pbPin)
		{
			SecureZeroMemory(pbPin , dwPinLen);
			EIDFree(pbPin);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hCertKey)
			CryptDestroyKey(hCertKey);
		if (fCallerFreeProv && hProv) 
			CryptReleaseContext(hProv,0);
		if (pProvInfo) 
			EIDFree(pProvInfo);
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL CStoredCredentialManager::GetResponseFromSignatureChallenge(__in PBYTE pbChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize)
{
	UNREFERENCED_PARAMETER(dwChallengeSize);
	BOOL fReturn = FALSE;
	LPSTR pbPin = NULL;
	HCRYPTPROV hProv = NULL;
	DWORD dwKeySpec;
	BOOL fCallerFreeProv = FALSE;
	HCRYPTKEY hCertKey = NULL;
	HCRYPTHASH hHash = NULL;
	DWORD dwPinLen = 0;
	DWORD dwError = 0;
	LPCTSTR sDescription = TEXT("");
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	__try
	{
		DWORD dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pKeyProvInfo)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		*pdwResponseSize = 0;
		dwKeySpec = pKeyProvInfo->dwKeySpec;
		if (!CryptAcquireCertificatePrivateKey(pCertContext,CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,NULL,&hProv,&dwKeySpec,&fCallerFreeProv))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptAcquireCertificatePrivateKey", GetLastError());
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"Keyspec %S container %s provider %s", (pKeyProvInfo->dwKeySpec == AT_SIGNATURE ?"AT_SIGNATURE":"AT_KEYEXCHANGE"),
					pKeyProvInfo->pwszContainerName, pKeyProvInfo->pwszProvName);
			__leave;
		}
		dwPinLen = (DWORD) wcslen(szPin) + 1;
		pbPin = (LPSTR) EIDAlloc(dwPinLen);
		if (!pbPin)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!WideCharToMultiByte(CP_ACP, 0, szPin, -1, pbPin, dwPinLen, NULL, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by WideCharToMultiByte", GetLastError());
			__leave;
		}
		if (!CryptSetProvParam(hProv, (dwKeySpec == AT_KEYEXCHANGE?PP_KEYEXCHANGE_PIN:PP_SIGNATURE_PIN), (PBYTE) pbPin , 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetProvParam - correct PIN ?", GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, pbChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, NULL, pdwResponseSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash1", GetLastError());
			__leave;
		}
		*ppResponse = (PBYTE) EIDAlloc(*pdwResponseSize);
		if (!*ppResponse)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CryptSignHash(hHash,dwKeySpec, sDescription, 0, *ppResponse, pdwResponseSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSignHash2", GetLastError());
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (pbPin)
		{
			SecureZeroMemory(pbPin , dwPinLen);
			EIDFree(pbPin);
		}
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (hCertKey)
			CryptDestroyKey(hCertKey);
		if (hHash)
			CryptDestroyHash(hHash);
		if (fCallerFreeProv && hProv) 
			CryptReleaseContext(hProv,0);
	}
	SetLastError(dwError);
	return fReturn;
}


typedef struct _KEY_BLOB {
  BYTE   bType;
  BYTE   bVersion;
  WORD   reserved;
  ALG_ID aiKeyAlg;
  ULONG cb;
  BYTE Data[CREDENTIALKEYLENGTH/8];
} KEY_BLOB;

// create a symetric key which can be used to crypt data and
// which is saved and protected by the public key
BOOL CStoredCredentialManager::GenerateSymetricKeyAndEncryptIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize)
{
	BOOL fReturn = FALSE;
	BOOL fStatus;
	HCRYPTHASH hHash = NULL;
	DWORD dwSize;
	KEY_BLOB bKey;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		*pSymetricKey = NULL;
		*phKey = NULL;
		dwSize = sizeof(DWORD);
		DWORD dwBlockLen;
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		bKey.cb = CREDENTIALKEYLENGTH/8;
		fStatus = CryptGenRandom(hProv,bKey.cb,bKey.Data);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGenRandom 0x%08x",GetLastError());
			__leave;
		}
		fStatus = CryptImportKey(hProv,(PBYTE)&bKey,sizeof(KEY_BLOB),NULL,CRYPT_EXPORTABLE,phKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// save
		/*dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(*phKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}*/
		dwBlockLen = 0;
		fStatus = CryptEncrypt(hKey, hHash,TRUE,0,NULL,&dwBlockLen, 0);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
			__leave;
		}
		*pSymetricKey = (PBYTE) EIDAlloc(dwBlockLen);
		if (!*pSymetricKey)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*pSymetricKey, bKey.Data, CREDENTIALKEYLENGTH/8);
		dwSize = CREDENTIALKEYLENGTH/8;
		fStatus = CryptEncrypt(hKey, hHash,TRUE,0,*pSymetricKey,&dwSize, dwBlockLen);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x",GetLastError());
			__leave;
		}
		*usSize = (USHORT) dwSize;
		// bKey is know encrypted
		
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pSymetricKey)
			{
				EIDFree(*pSymetricKey);
				*pSymetricKey = NULL;
			}
			if (*phKey)
			{
				CryptDestroyKey(*phKey);
				*phKey = NULL;
			}
		}
		if (hHash)
			CryptDestroyHash(hHash);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwPasswordSize, dwSize, dwBlockLen, dwEncryptedSize;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		dwPasswordSize = (DWORD) (dwPasswordLen?dwPasswordLen:wcslen(szPassword)* sizeof(WCHAR));
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwBlockLen = %d",dwBlockLen);
		// block size = 256             100 => 1     256 => 1      257  => 2
		dwRoundNumber = ((DWORD)(dwPasswordSize/dwBlockLen)) + ((dwPasswordSize%dwBlockLen) ? 1 : 0);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRoundNumber = %d",dwRoundNumber);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwPasswordSize = %d",dwPasswordSize);
		*pEncryptedPassword = (PBYTE) EIDAlloc(dwRoundNumber * dwBlockLen);
		if (!*pEncryptedPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",GetLastError());
			__leave;
		}	
		memset(*pEncryptedPassword, 0, dwRoundNumber * dwBlockLen);
		memcpy(*pEncryptedPassword, szPassword, dwPasswordSize);
		
		dwEncryptedSize = 0;
		for (DWORD dwI = 0; dwI < dwRoundNumber; dwI++)
		{
			dwEncryptedSize = (dwI == dwRoundNumber-1 ? dwPasswordSize%dwBlockLen : dwBlockLen);
			fStatus = CryptEncrypt(hKey, NULL,(dwI == dwRoundNumber-1 ? TRUE:FALSE),0,
						*pEncryptedPassword + dwI * dwBlockLen,
						&dwEncryptedSize, dwBlockLen);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptEncrypt 0x%08x round = %d",GetLastError(), dwI);
				__leave;
			}
		}
		*usSize = (USHORT) ((dwRoundNumber -1 ) * dwBlockLen + dwEncryptedSize);
		// szPassword is know encrypted

		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pEncryptedPassword)
			{
				EIDFree(*pEncryptedPassword);
				*pEncryptedPassword = NULL;
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::GetPasswordFromChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in DWORD dwChallengeType, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)
{
	switch(dwChallengeType)
	{
	case eidpdtClearText:
		return GetPasswordFromSignatureChallengeResponse(dwRid,ppChallenge,dwChallengeSize,pResponse,dwResponseSize,pszPassword);
		break;
	case eidpdtCrypted:
		return GetPasswordFromCryptedChallengeResponse(dwRid,ppChallenge,dwChallengeSize,pResponse,dwResponseSize,pszPassword);
		break;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Type not implemented");
	return FALSE;
}

BOOL CStoredCredentialManager::GetPasswordFromCryptedChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)
{
	UNREFERENCED_PARAMETER(ppChallenge);
	UNREFERENCED_PARAMETER(dwChallengeSize);
	BOOL fReturn = FALSE, fStatus;
	DWORD dwSize;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	KEY_BLOB bKey;
	*pszPassword = NULL;
	DWORD dwBlockLen;
	DWORD dwRoundNumber;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		if (pEidPrivateData->dwSymetricKeySize != dwChallengeSize)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x",dwChallengeSize);
			__leave;
		}
		// key is generated here
		bKey.bType = PLAINTEXTKEYBLOB;
		bKey.bVersion = CUR_BLOB_VERSION;
		bKey.reserved = 0;
		bKey.aiKeyAlg = CREDENTIALCRYPTALG;
		bKey.cb = dwResponseSize;
		memcpy(bKey.Data, pResponse, dwResponseSize);
		// import the aes key
		fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
		if(!fStatus)
		{
			dwError = GetLastError();
			if (dwError == NTE_BAD_KEYSET)
			{
				fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
				dwError = GetLastError();
			}
			if (!fStatus)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
		}
		fStatus = CryptImportKey(hProv,(PBYTE) &bKey,sizeof(KEY_BLOB),0,CRYPT_EXPORTABLE,&hKey);
		if(!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		// decode it
		dwSize = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (PBYTE) &dwBlockLen, &dwSize, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CryptGetKeyParam", GetLastError());
			__leave;
		}
		dwRoundNumber = (DWORD)(pEidPrivateData->dwPasswordSize / dwBlockLen) + 
			((pEidPrivateData->dwPasswordSize % dwBlockLen) ? 1 : 0);
		*pszPassword = (PWSTR) EIDAlloc(dwRoundNumber *  dwBlockLen + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", GetLastError());
			__leave;
		}
		memcpy(*pszPassword, pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset, pEidPrivateData->dwPasswordSize);

		for (DWORD dwI = 0; dwI < dwRoundNumber ; dwI++)
		{
			dwSize = (dwI == dwRoundNumber -1 ? pEidPrivateData->dwPasswordSize%dwBlockLen : dwBlockLen);
			fStatus = CryptDecrypt(hKey, NULL,(dwI == dwRoundNumber -1 ?TRUE:FALSE),0,
				((PBYTE) *pszPassword) + dwI * dwBlockLen,&dwSize);
			if(!fStatus)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptDecrypt 0x%08x",GetLastError());
				__leave;
			}
		}
		(*pszPassword)[((dwRoundNumber-1) * dwBlockLen + dwSize)/sizeof(WCHAR)] = '\0';
		fReturn = TRUE;
	}
	__finally
	{
		if (!fReturn)
		{
			if (*pszPassword) 
			{
				EIDFree(*pszPassword);
				*pszPassword = NULL;
			}
		}
		if (pEidPrivateData)
		{
			EIDFree(pEidPrivateData);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::GetPasswordFromSignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, PWSTR *pszPassword)
{
	BOOL fReturn = FALSE, fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	PCCERT_CONTEXT pCertContextVerif = NULL;
	PCRYPT_KEY_PROV_INFO pKeyProvInfo = NULL;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		if (CREDENTIALKEYLENGTH != dwChallengeSize)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwChallengeSize = 0x%08x",dwChallengeSize);
			__leave;
		}
		if (pszPassword == NULL)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pszPassword null");
			__leave;
		}
		*pszPassword = NULL;
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		/*
		DWORD dwSize = 0;
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}
		pKeyProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pKeyProvInfo)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by malloc", GetLastError());
			__leave;
		}
		if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, (PBYTE) pKeyProvInfo, &dwSize))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CertGetCertificateContextProperty", GetLastError());
			__leave;
		}*/
		pCertContextVerif = CertCreateCertificateContext(X509_ASN_ENCODING, 
			(PBYTE)pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset, pEidPrivateData->dwCertificatSize);
		if (!pCertContextVerif)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		// import the public key
		fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
		if(!fStatus)
		{
			dwError = GetLastError();
			if (dwError == NTE_BAD_KEYSET)
			{
				fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
				dwError = GetLastError();
			}
			if (!fStatus)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
		}
		fStatus = CryptImportPublicKeyInfo(hProv, pCertContextVerif->dwCertEncodingType, &(pCertContextVerif->pCertInfo->SubjectPublicKeyInfo),&hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, ppChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHash, pResponse, dwResponseSize, hKey, TEXT(""), 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}
		*pszPassword = (PWSTR) EIDAlloc(pEidPrivateData->dwPasswordSize + sizeof(WCHAR));
		if (!*pszPassword)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", GetLastError());
			__leave;
		}
		memcpy(*pszPassword, (PBYTE)pEidPrivateData->Data + pEidPrivateData->dwPasswordOffset,pEidPrivateData->dwPasswordSize);
		(*pszPassword)[pEidPrivateData->dwPasswordSize / sizeof(WCHAR)] = '\0';
		fReturn = TRUE;

	}
	__finally
	{
		if (!fReturn)
		{
			if (pszPassword)
			{
				if (*pszPassword) 
				{
					EIDFree(*pszPassword);
					*pszPassword = NULL;
				}
			}
		}
		if (pEidPrivateData)
		{
			EIDFree(pEidPrivateData);
		}
		if (pKeyProvInfo)
			EIDFree(pKeyProvInfo);
		if (pCertContextVerif)
			CertFreeCertificateContext(pCertContextVerif);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	return fReturn;
}

BOOL CStoredCredentialManager::VerifySignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize)
{
	UNREFERENCED_PARAMETER(dwChallengeSize);
	BOOL fReturn = FALSE, fStatus;
	DWORD dwError = 0;
	PEID_PRIVATE_DATA pEidPrivateData = NULL;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	HCRYPTHASH hHash = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		// read the encrypted password
		if (!dwRid)
		{
			dwError = ERROR_NONE_MAPPED;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"dwRid 0x%08x",dwError);
			__leave;
		}
		fStatus = RetrievePrivateData(dwRid,&pEidPrivateData);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"RetrievePrivateData 0x%08x",dwError);
			__leave;
		}
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, 
			(PBYTE)pEidPrivateData->Data + pEidPrivateData->dwCertificatOffset, pEidPrivateData->dwCertificatSize);
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext 0x%08x",dwError);
			__leave;
		}
		// import the public key
		fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,0);
		if(!fStatus)
		{
			dwError = GetLastError();
			if (dwError == NTE_BAD_KEYSET)
			{
				fStatus = CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_NEWKEYSET);
				dwError = GetLastError();
			}
			if (!fStatus)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Container already existed !!");
		}
		fStatus = CryptImportPublicKeyInfo(hProv, pCertContext->dwCertEncodingType, &(pCertContext->pCertInfo->SubjectPublicKeyInfo),&hKey);
		if (!fStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptCreateHash(hProv,CALG_SHA,NULL,0,&hHash))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptCreateHash", GetLastError());
			__leave;
		}
		if (!CryptSetHashParam(hHash, HP_HASHVAL, ppChallenge, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptSetHashParam", GetLastError());
			__leave;
		}

		if (!CryptVerifySignature(hHash, pResponse, dwResponseSize, hKey, TEXT(""), 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%x returned by CryptVerifySignature", GetLastError());
			__leave;
		}
		fReturn = TRUE;

	}
	__finally
	{
		if (pEidPrivateData)
		{
			EIDFree(pEidPrivateData);
		}
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hHash)
			CryptDestroyHash(hHash);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
		{
			CryptReleaseContext(hProv, 0);
			CryptAcquireContext(&hProv,CREDENTIAL_CONTAINER,CREDENTIALPROVIDER,PROV_RSA_AES,CRYPT_DELETEKEYSET);
		}
	}
	return fReturn;
}
////////////////////////////////////////////////////////////////////////////////
// LEVEL 3
////////////////////////////////////////////////////////////////////////////////

BOOL CStoredCredentialManager::StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize)
{

	if (!EIDIsComponentInLSAContext())
 	{
		return StorePrivateDataDebug(dwRid,pbSecret, usSecretSize);
	}

	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = NULL;

    LSA_UNICODE_STRING lusSecretName;
    LSA_UNICODE_STRING lusSecretData;
	WCHAR szLsaKeyName[256];
    NTSTATUS ntsResult = STATUS_SUCCESS;
    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		//  Get a handle to the Policy object.
		ntsResult = LsaOpenPolicy(
			NULL,    // local machine
			&ObjectAttributes, 
			POLICY_CREATE_SECRET | READ_CONTROL | WRITE_OWNER | WRITE_DAC,
			&LsaPolicyHandle);

		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		} 

		//  Initialize an LSA_UNICODE_STRING for the name of the
		wsprintf(szLsaKeyName, L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid);
	
		lusSecretName.Buffer = szLsaKeyName;
		lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
		lusSecretName.MaximumLength = lusSecretName.Length;
		//  If the pwszSecret parameter is NULL, then clear the secret.
		if( NULL == pbSecret )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Clearing %x",dwRid);
			ntsResult = LsaStorePrivateData(
				LsaPolicyHandle,
				&lusSecretName,
				NULL);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Setting %x",dwRid);
			//  Initialize an LSA_UNICODE_STRING for the value
			//  of the private data. 
			lusSecretData.Buffer = (PWSTR) pbSecret;
			lusSecretData.Length = usSecretSize;
			lusSecretData.MaximumLength = usSecretSize;
			ntsResult = LsaStorePrivateData(
				LsaPolicyHandle,
				&lusSecretName,
				&lusSecretData);
		}
		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaStorePrivateData", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
	} 
	SetLastError(dwError);
    return fReturn;

}

BOOL CStoredCredentialManager::StorePrivateDataDebug(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	TCHAR szFileName[MAX_PATH];
	TCHAR szTempPath[MAX_PATH];
	BOOL fReturn = FALSE;
	DWORD dwError = 0, dwWritten;
	__try
	{
		if (!GetTempPath(ARRAYSIZE(szTempPath), szTempPath))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTempPath 0x%08x", dwError);
			__leave;
		}
		_stprintf_s(szFileName, ARRAYSIZE(szFileName),TEXT("%sEIDCredential%4x.txt"),szTempPath,dwRid);
		if (!pbSecret)
		{
			DeleteFile(szFileName);
		}
		else
		{
			hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0,NULL);
			if (hFile == INVALID_HANDLE_VALUE)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateFile 0x%08x", dwError);
				__leave;
			}
			if (!WriteFile(hFile, pbSecret, usSecretSize,&dwWritten, NULL))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WriteFile 0x%08x", dwError);
				__leave;
			}
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData)
{
	if (!EIDIsComponentInLSAContext())
 	{
		return RetrievePrivateDataDebug(dwRid,ppPrivateData);
	}

	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_HANDLE LsaPolicyHandle = NULL;
	PLSA_UNICODE_STRING pData = NULL;
    LSA_UNICODE_STRING lusSecretName;
	WCHAR szLsaKeyName[256];
	NTSTATUS ntsResult = STATUS_SUCCESS;
    //  Object attributes are reserved, so initialize to zeros.
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	__try
	{
		//  Get a handle to the Policy object.
		ntsResult = LsaOpenPolicy(
			NULL,    // local machine
			&ObjectAttributes, 
			POLICY_GET_PRIVATE_INFORMATION,
			&LsaPolicyHandle);

		if( STATUS_SUCCESS != ntsResult )
		{
			//  An error occurred. Display it as a win32 error code.
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaOpenPolicy", ntsResult);
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		} 

		//  Initialize an LSA_UNICODE_STRING for the name of the
		//  private data ("DefaultPassword").
		wsprintf(szLsaKeyName, L"%s_%08X", CREDENTIAL_LSAPREFIX, dwRid);
	
		lusSecretName.Buffer = szLsaKeyName;
		lusSecretName.Length = (USHORT) wcslen(szLsaKeyName)* sizeof(WCHAR);
		lusSecretName.MaximumLength = lusSecretName.Length;
    
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Reading dwRid = 0x%x", dwRid);
		ntsResult = LsaRetrievePrivateData(LsaPolicyHandle,&lusSecretName,&pData);
		if( STATUS_SUCCESS != ntsResult )
		{
			if (0xc0000034 == ntsResult)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Private info not found for dwRid = 0x%x", dwRid);
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by LsaRetrievePrivateData", ntsResult);
			}
			dwError = LsaNtStatusToWinError(ntsResult);
			__leave;
		} 
		*ppPrivateData = (PEID_PRIVATE_DATA) EIDAlloc(pData->Length);
		if (!*ppPrivateData)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
			__leave;
		}
		memcpy(*ppPrivateData, pData->Buffer, pData->Length);
		fReturn = TRUE;
	}
	__finally
	{
		if (LsaPolicyHandle) LsaClose(LsaPolicyHandle);
		if (pData) LsaFreeMemory(pData);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::RetrievePrivateDataDebug(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData)
{
	TCHAR szFileName[MAX_PATH];
	TCHAR szTempPath[MAX_PATH];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	BOOL fReturn = FALSE;
	DWORD dwError = 0, dwRead, dwSize;
	__try
	{
		if (!GetTempPath(ARRAYSIZE(szTempPath), szTempPath))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTempPath 0x%08x", dwError);
			__leave;
		}
		_stprintf_s(szFileName, ARRAYSIZE(szFileName),TEXT("%sEIDCredential%4x.txt"),szTempPath,dwRid);
		hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0,NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateFile 0x%08x", dwError);
			__leave;
		}
		dwSize = GetFileSize(hFile, NULL);
		if (INVALID_FILE_SIZE == dwSize)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetFileSize 0x%08x", dwError);
			__leave;
		}
		*ppPrivateData = (PEID_PRIVATE_DATA) EIDAlloc(dwSize);
		if (!*ppPrivateData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x", dwError);
			__leave;
		}
		if (!ReadFile(hFile, *ppPrivateData, dwSize,&dwRead, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WriteFile 0x%08x", dwError);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
		}
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CStoredCredentialManager::HasStoredCredential(__in DWORD dwRid)
{
	BOOL fReturn = FALSE;
	PEID_PRIVATE_DATA pSecret;
	DWORD dwError = 0;
	if (RetrievePrivateData(dwRid, &pSecret))
	{
		dwError = GetLastError();
		fReturn = TRUE;
		EIDFree(pSecret);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"%s",(fReturn?L"TRUE":L"FALSE"));
	SetLastError(dwError);
	return fReturn;
}
//////////////////////////////////////////////////////////////


typedef struct _ENCRYPTED_LM_OWF_PASSWORD {
    unsigned char data[16];
} ENCRYPTED_LM_OWF_PASSWORD,
  *PENCRYPTED_LM_OWF_PASSWORD,
  ENCRYPTED_NT_OWF_PASSWORD,
  *PENCRYPTED_NT_OWF_PASSWORD;

typedef struct _SAMPR_USER_INTERNAL1_INFORMATION {
    ENCRYPTED_NT_OWF_PASSWORD  EncryptedNtOwfPassword;
    ENCRYPTED_LM_OWF_PASSWORD  EncryptedLmOwfPassword;
    unsigned char              NtPasswordPresent;
    unsigned char              LmPasswordPresent;
    unsigned char              PasswordExpired;
} SAMPR_USER_INTERNAL1_INFORMATION,
  *PSAMPR_USER_INTERNAL1_INFORMATION;

typedef enum _USER_INFORMATION_CLASS {
    UserInternal1Information = 18,
} USER_INFORMATION_CLASS, *PUSER_INFORMATION_CLASS;

typedef PSAMPR_USER_INTERNAL1_INFORMATION PSAMPR_USER_INFO_BUFFER;

typedef WCHAR * PSAMPR_SERVER_NAME;
typedef PVOID SAMPR_HANDLE;


// opnum 0
typedef NTSTATUS  (NTAPI *SamrConnect) (
    __in PSAMPR_SERVER_NAME ServerName,
    __out SAMPR_HANDLE * ServerHandle,
    __in DWORD DesiredAccess,
	__in DWORD
    );

// opnum 1
typedef NTSTATUS  (NTAPI *SamrCloseHandle) (
    __inout SAMPR_HANDLE * SamHandle
    );

// opnum 7
typedef NTSTATUS  (NTAPI *SamrOpenDomain) (
    __in SAMPR_HANDLE ServerHandle,
    __in DWORD   DesiredAccess,
    __in PSID DomainId,
    __out SAMPR_HANDLE * DomainHandle
    );


		// opnum 34
typedef NTSTATUS  (NTAPI *SamrOpenUser) (
    __in SAMPR_HANDLE DomainHandle,
    __in DWORD   DesiredAccess,
    __in DWORD   UserId,
    __out SAMPR_HANDLE  * UserHandle
    );

// opnum 36
typedef NTSTATUS  (NTAPI *SamrQueryInformationUser) (
    __in SAMPR_HANDLE UserHandle,
    __in USER_INFORMATION_CLASS  UserInformationClass,
	__out PSAMPR_USER_INFO_BUFFER * Buffer
    );

typedef NTSTATUS  (NTAPI *SamIFree_SAMPR_USER_INFO_BUFFER) (
	__in PSAMPR_USER_INFO_BUFFER Buffer, 
	__in USER_INFORMATION_CLASS UserInformationClass
	);

HMODULE samsrvDll = NULL;
SamrConnect MySamrConnect;
SamrCloseHandle MySamrCloseHandle;
SamrOpenDomain MySamrOpenDomain;
SamrOpenUser MySamrOpenUser;
SamrQueryInformationUser MySamrQueryInformationUser;
SamIFree_SAMPR_USER_INFO_BUFFER MySamIFree;


NTSTATUS LoadSamSrv()
{
	samsrvDll = LoadLibrary(TEXT("samsrv.dll"));
	if (!samsrvDll)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSam failed 0x%08x",GetLastError());
		return STATUS_FAIL_CHECK;
	}
	MySamrConnect = (SamrConnect) GetProcAddress(samsrvDll,"SamIConnect");
	MySamrCloseHandle = (SamrCloseHandle) GetProcAddress(samsrvDll,"SamrCloseHandle");
	MySamrOpenDomain = (SamrOpenDomain) GetProcAddress(samsrvDll,"SamrOpenDomain");
	MySamrOpenUser = (SamrOpenUser) GetProcAddress(samsrvDll,"SamrOpenUser");
	MySamrQueryInformationUser = (SamrQueryInformationUser) GetProcAddress(samsrvDll,"SamrQueryInformationUser");
	MySamIFree = (SamIFree_SAMPR_USER_INFO_BUFFER) GetProcAddress(samsrvDll,"SamIFree_SAMPR_USER_INFO_BUFFER");
	if (!MySamrConnect || !MySamrCloseHandle || !MySamrOpenDomain || !MySamrOpenUser
		|| !MySamrQueryInformationUser || !MySamIFree)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Null pointer function");
		FreeLibrary(samsrvDll);
		samsrvDll = NULL;
		return STATUS_FAIL_CHECK;
	}
	return STATUS_SUCCESS;
}

NTSTATUS CStoredCredentialManager::CheckPassword( __in DWORD dwRid, __in PWSTR szPassword)
{
	NTSTATUS Status = STATUS_SUCCESS;
	LSA_OBJECT_ATTRIBUTES connectionAttrib;
    LSA_HANDLE handlePolicy = NULL;
    PPOLICY_ACCOUNT_DOMAIN_INFO structInfoPolicy = NULL;// -> http://msdn2.microsoft.com/en-us/library/ms721895(VS.85).aspx.
	SAMPR_HANDLE hSam = NULL, hDomain = NULL, hUser = NULL;
	PSAMPR_USER_INTERNAL1_INFORMATION UserInfo = NULL;
	unsigned char bHash[16];
	UNICODE_STRING EncryptedPassword;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
        samsrvDll = NULL;
		memset(&connectionAttrib,0,sizeof(LSA_OBJECT_ATTRIBUTES));
        connectionAttrib.Length = sizeof(LSA_OBJECT_ATTRIBUTES);
		Status = LoadSamSrv();
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LoadSamSrv failed 0x%08x",Status);
			__leave;
		}
		Status = LsaOpenPolicy(NULL,&connectionAttrib,POLICY_ALL_ACCESS,&handlePolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaOpenPolicy failed 0x%08x",Status);
			__leave;
		}
		Status = LsaQueryInformationPolicy(handlePolicy , PolicyAccountDomainInformation , (PVOID*)&structInfoPolicy);
		if (Status!= STATUS_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaQueryInformationPolicy failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrConnect(NULL , &hSam , MAXIMUM_ALLOWED, 1);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrConnect failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrOpenDomain(hSam , 0xf07ff , structInfoPolicy->DomainSid , &hDomain);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrOpenDomain failed 0x%08x",Status);
			__leave;
		}
		Status = MySamrOpenUser(hDomain , MAXIMUM_ALLOWED , dwRid , &hUser);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrOpenUser failed 0x%08x rid = %d",Status,dwRid);
			__leave;
		}
		Status = MySamrQueryInformationUser(hUser , UserInternal1Information , &UserInfo);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SamrQueryInformationUser failed 0x%08x",Status);
			__leave;
		}
		EncryptedPassword.Length = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
		EncryptedPassword.MaximumLength = (USHORT) wcslen(szPassword) * sizeof(WCHAR);
		EncryptedPassword.Buffer = szPassword;
		Status = SystemFunction007(&EncryptedPassword, bHash);
		if (Status!= STATUS_SUCCESS)	
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SystemFunction007 failed 0x%08x",Status);
			__leave;
		}
		for (DWORD dwI = 0 ; dwI < 16; dwI++)
		{
			if (bHash[dwI] != UserInfo->EncryptedNtOwfPassword.data[dwI])
			{
				Status = STATUS_WRONG_PASSWORD;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_WRONG_PASSWORD");
				break;
			}
		}
	}
	__finally
	{
		if (UserInfo)
			MySamIFree(UserInfo, UserInternal1Information);
		if (hUser)
			MySamrCloseHandle(&hUser);
		if (hDomain)
			MySamrCloseHandle(&hDomain);
		if (hSam)
			MySamrCloseHandle(&hSam);
		if (structInfoPolicy)
			LsaFreeMemory(structInfoPolicy);
		if (handlePolicy)
			LsaClose(handlePolicy);
		if (samsrvDll)
			FreeLibrary(samsrvDll);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with status = 0x%08x",Status);
	return Status;
}