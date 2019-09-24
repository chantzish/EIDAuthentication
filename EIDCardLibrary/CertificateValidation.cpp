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
#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "GPO.h"

#pragma comment(lib,"Crypt32")

PCCERT_CONTEXT GetCertificateFromCspInfo(__in PEID_SMARTCARD_CSP_INFO pCspInfo)
{
	// for TS Smart Card redirection
	PCCERT_CONTEXT pCertContext = NULL;
	EIDImpersonate();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"GetCertificateFromCspInfo");
	HCRYPTPROV hProv = NULL;
	DWORD dwError = 0;
	
	BYTE Data[4096];
	DWORD DataSize = ARRAYSIZE(Data);
	LPTSTR szContainerName = pCspInfo->bBuffer + pCspInfo->nContainerNameOffset;
	LPTSTR szProviderName = pCspInfo->bBuffer + pCspInfo->nCSPNameOffset;
//	LPTSTR szReaderName = pCspInfo->bBuffer + pCspInfo->nReaderNameOffset;
//	LPTSTR szCardName = pCspInfo->bBuffer + pCspInfo->nCardNameOffset;
	HCRYPTKEY phUserKey = NULL;
	BOOL fResult;
	BOOL fSuccess = FALSE;
	__try
	{
		// check input
		if (GetPolicyValue(AllowSignatureOnlyKeys) == 0 && pCspInfo->KeySpec == AT_SIGNATURE)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Policy denies AT_SIGNATURE Key");
			__leave;
		}
		fResult = CryptAcquireContext(&hProv,szContainerName,szProviderName,PROV_RSA_FULL, CRYPT_SILENT);
		if (!fResult)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext : 0x%08x container='%s' provider='%s'",GetLastError(),szContainerName,szProviderName);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"PIV fallback");
			fResult = CryptAcquireContext(&hProv,NULL,szProviderName,PROV_RSA_FULL, CRYPT_SILENT);
			if (!fResult)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext : 0x%08x",GetLastError());
				__leave;
			}
		}
		if (!CryptGetUserKey(hProv, pCspInfo->KeySpec, &phUserKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey : 0x%08x",GetLastError());
			__leave;
		}
		if (!CryptGetKeyParam(phUserKey,KP_CERTIFICATE,(BYTE*)Data,&DataSize,0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetKeyParam : 0x%08x",GetLastError());
			__leave;
		}
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, Data, DataSize); 
		if (!pCertContext)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertCreateCertificateContext : 0x%08x",GetLastError());
			__leave;
		}
		// save reference to CSP (else we can't access private key)
		CRYPT_KEY_PROV_INFO KeyProvInfo;
		memset(&KeyProvInfo, 0, sizeof(CRYPT_KEY_PROV_INFO));
		// this flag enable cache for futher call to CryptAcquireCertificatePrivateKey
		KeyProvInfo.dwFlags = CERT_SET_KEY_CONTEXT_PROP_ID;
		KeyProvInfo.pwszProvName = szProviderName;
		KeyProvInfo.pwszContainerName = szContainerName;
		KeyProvInfo.dwProvType = PROV_RSA_FULL;
		KeyProvInfo.dwKeySpec = pCspInfo->KeySpec;

		if (!CertSetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,0,&KeyProvInfo))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertSetCertificateContextProperty CERT_KEY_PROV_INFO_PROP_ID 0x%08x",dwError);
			__leave;
		}
		// we provide the context to cache it
		CERT_KEY_CONTEXT keyContext;
		memset(&keyContext, 0, sizeof(CERT_KEY_CONTEXT));
		keyContext.cbSize = sizeof(CERT_KEY_CONTEXT);
		keyContext.hCryptProv = hProv;
		keyContext.dwKeySpec = pCspInfo->KeySpec;
		if (!CertSetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, 0, &keyContext))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CertSetCertificateContextProperty CERT_KEY_CONTEXT_PROP_ID 0x%08x",dwError);
			__leave;
		}
		// important : the hprov will be freed if the certificatecontext is freed, and that's a problem
		if (!CryptContextAddRef(hProv, NULL, 0))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptContextAddRef 0x%08x",dwError);
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Certificate OK");
		fSuccess = TRUE;
	}
	__finally
	{
		if (!fSuccess)
		{
			if (pCertContext) 
			{
				CertFreeCertificateContext(pCertContext);
				pCertContext = NULL;
			}
		}
		if (phUserKey)
			CryptDestroyKey(phUserKey);
		if (hProv) 
			CryptReleaseContext(hProv,0);
	}
	// for TS Smart Card redirection
	EIDRevertToSelf();
	SetLastError(dwError);
	return pCertContext;
}

#define ERRORTOTEXT(ERROR) case ERROR: pszName = TEXT(#ERROR);                 break;
LPCTSTR GetTrustErrorText(DWORD Status)
{
    LPCTSTR pszName = NULL;
    switch(Status)
    {
		ERRORTOTEXT(CERT_E_EXPIRED)
		ERRORTOTEXT(CERT_E_VALIDITYPERIODNESTING)
		ERRORTOTEXT(CERT_E_ROLE)
		ERRORTOTEXT(CERT_E_PATHLENCONST)
		ERRORTOTEXT(CERT_E_CRITICAL)
		ERRORTOTEXT(CERT_E_PURPOSE)
		ERRORTOTEXT(CERT_E_ISSUERCHAINING)
		ERRORTOTEXT(CERT_E_MALFORMED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDROOT)
		ERRORTOTEXT(CERT_E_CHAINING)
		ERRORTOTEXT(TRUST_E_FAIL)
		ERRORTOTEXT(CERT_E_REVOKED)
		ERRORTOTEXT(CERT_E_UNTRUSTEDTESTROOT)
		ERRORTOTEXT(CERT_E_REVOCATION_FAILURE)
		ERRORTOTEXT(CERT_E_CN_NO_MATCH)
		ERRORTOTEXT(CERT_E_WRONG_USAGE)
		ERRORTOTEXT(CERT_TRUST_NO_ERROR)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_TIME_NESTED)
		ERRORTOTEXT(CERT_TRUST_IS_REVOKED)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
		ERRORTOTEXT(CERT_TRUST_IS_UNTRUSTED_ROOT)
		ERRORTOTEXT(CERT_TRUST_REVOCATION_STATUS_UNKNOWN)
		ERRORTOTEXT(CERT_TRUST_IS_CYCLIC)
		ERRORTOTEXT(CERT_TRUST_IS_PARTIAL_CHAIN)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_TIME_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_SIGNATURE_VALID)
		ERRORTOTEXT(CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE)
		default:                            
			pszName = NULL;                      break;
    }
	return pszName;
} 
#undef ERRORTOTEXT


BOOL HasCertificateRightEKU(__in PCCERT_CONTEXT pCertContext)
{
	BOOL fValidation = FALSE;
	DWORD dwError = 0, dwSize = 0, dwI;
	PCERT_ENHKEY_USAGE		 pCertUsage        = NULL;
	__try
	{
		if (!GetPolicyValue(AllowCertificatesWithNoEKU))
		{
			// check EKU SmartCardLogon
			if (!CertGetEnhancedKeyUsage(pCertContext, 0, NULL, &dwSize))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetEnhancedKeyUsage", GetLastError());
				__leave;
			}
			pCertUsage = (PCERT_ENHKEY_USAGE)EIDAlloc(dwSize);
			if (!pCertUsage)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by EIDAlloc", GetLastError());
				__leave;
			}
			if (!CertGetEnhancedKeyUsage(pCertContext, 0, pCertUsage, &dwSize))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetEnhancedKeyUsage", GetLastError());
				__leave;
			}
			for (dwI = 0; dwI < pCertUsage->cUsageIdentifier; dwI++)
			{
				if (strcmp(pCertUsage->rgpszUsageIdentifier[dwI],szOID_KP_SMARTCARD_LOGON) == 0)
				{
					break;
				}
			}
			if (dwI >= pCertUsage->cUsageIdentifier)
			{
				dwError = CERT_TRUST_IS_NOT_VALID_FOR_USAGE;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No EKU found in end certificate");
				__leave;
			}
		}
		fValidation = TRUE;
	}
	__finally
	{
		if (pCertUsage)
			EIDFree(pCertUsage);
	}
	SetLastError(dwError);
	return fValidation;
}

BOOL IsCertificateInComputerTrustedPeopleStore(__in PCCERT_CONTEXT pCertContext)
{
	BOOL fReturn = FALSE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Testing trusted certificate");
	HCERTSTORE hTrustedPeople = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG,_T("TrustedPeople"));
	if (hTrustedPeople)
	{
					
		PCCERT_CONTEXT pCertificateFound = CertFindCertificateInStore(hTrustedPeople, pCertContext->dwCertEncodingType, 0, CERT_FIND_EXISTING, pCertContext, NULL);
		if (pCertificateFound)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Certificate found in trusted people store");
			fReturn = TRUE;
			CertFreeCertificateContext(pCertificateFound);
		}
		CertCloseStore(hTrustedPeople, 0);
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"unable to open store 0x%08x", GetLastError());
	}
	return fReturn;
}

BOOL IsTrustedCertificate(__in PCCERT_CONTEXT pCertContext, __in_opt DWORD dwFlag)
{
    //
    // Validate certificate chain.
    //
	BOOL fValidation = FALSE;

	PCCERT_CHAIN_CONTEXT     pChainContext     = NULL;
	CERT_ENHKEY_USAGE        EnhkeyUsage       = {0};
	CERT_USAGE_MATCH         CertUsage         = {0};  
	CERT_CHAIN_PARA          ChainPara         = {0};
	CERT_CHAIN_POLICY_PARA   ChainPolicy       = {0};
	CERT_CHAIN_POLICY_STATUS PolicyStatus      = {0};
	LPSTR					szOid;
	HCERTCHAINENGINE		hChainEngine		= HCCE_LOCAL_MACHINE;
	DWORD dwError = 0;
	//---------------------------------------------------------
    // Initialize data structures for chain building.
	EnhkeyUsage.cUsageIdentifier = 0;
	EnhkeyUsage.rgpszUsageIdentifier=NULL;
	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;

	memset(&ChainPara, 0, sizeof(CERT_CHAIN_PARA));
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

	memset(&ChainPolicy, 0, sizeof(CERT_CHAIN_POLICY_PARA));
    ChainPolicy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);

	memset(&PolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
    PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
    PolicyStatus.lChainIndex = -1;
    PolicyStatus.lElementIndex = -1;

	if (dwFlag & EID_CERTIFICATE_FLAG_USERSTORE)
	{
		hChainEngine = HCCE_CURRENT_USER;
	}
	
	__try
	{
		if (!GetPolicyValue(AllowCertificatesWithNoEKU))
		{
			// check EKU SmartCardLogon
			EnhkeyUsage.cUsageIdentifier = 1;
			szOid = szOID_KP_SMARTCARD_LOGON;
			EnhkeyUsage.rgpszUsageIdentifier=& szOid;
			CertUsage.dwType = USAGE_MATCH_TYPE_OR;
			if (!HasCertificateRightEKU(pCertContext))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by HasCertificateRightEKU", GetLastError());
				__leave;
			}
		}
		// XP doesn't support CERT_CHAIN_ENABLE_PEER_TRUST
		if (IsCertificateInComputerTrustedPeopleStore(pCertContext))
		{
		}
		else
		{
			if(!CertGetCertificateChain(
				hChainEngine,pCertContext,NULL,NULL,&ChainPara,CERT_CHAIN_ENABLE_PEER_TRUST,NULL,&pChainContext))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateChain", GetLastError());
			}

			if (pChainContext->TrustStatus.dwErrorStatus)
			{
				dwError = pChainContext->TrustStatus.dwErrorStatus;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error %s (0x%08x) returned by CertVerifyCertificateChainPolicy",GetTrustErrorText(pChainContext->TrustStatus.dwErrorStatus),pChainContext->TrustStatus.dwErrorStatus);
				__leave;
			}
			if(! CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, &ChainPolicy, &PolicyStatus))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateChain", GetLastError());
				__leave;
			}
			if(PolicyStatus.dwError)
			{
				dwError = PolicyStatus.dwError;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error %s %d returned by CertVerifyCertificateChainPolicy",GetTrustErrorText(PolicyStatus.dwError),PolicyStatus.dwError);
				__leave;
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Chain OK");

		// verifiate time compliance
		if (!GetPolicyValue(AllowTimeInvalidCertificates))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Timecheck");
			LPFILETIME pTimeToVerify = NULL;
			if (CertVerifyTimeValidity(pTimeToVerify, pCertContext->pCertInfo))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Timecheck invalid");
				__leave;
			}
		}

		fValidation = TRUE;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Valid");
	}
	__finally
	{

		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}

	SetLastError(dwError);
	return fValidation;
}

BOOL MakeTrustedCertifcate(PCCERT_CONTEXT pCertContext)
{

	BOOL fReturn = FALSE;
	PCCERT_CHAIN_CONTEXT     pChainContext     = NULL;
	CERT_ENHKEY_USAGE        EnhkeyUsage       = {0};
	CERT_USAGE_MATCH         CertUsage         = {0};  
	CERT_CHAIN_PARA          ChainPara         = {0};
	CERT_CHAIN_POLICY_PARA   ChainPolicy       = {0};
	CERT_CHAIN_POLICY_STATUS PolicyStatus      = {0};
	LPSTR					szOid;
	HCERTSTORE hRootStore = NULL;
	HCERTSTORE hTrustStore = NULL;
	HCERTSTORE hTrustedPeople = NULL;
	// because machine cert are trusted by user,
	// build the chain in user context (if used certifcates are trusted only by the user
	// - think about program running in user space)
	HCERTCHAINENGINE		hChainEngine		= HCCE_CURRENT_USER;
	DWORD dwError = 0;

	//---------------------------------------------------------
    // Initialize data structures for chain building.

	if (GetPolicyValue(AllowCertificatesWithNoEKU))
	{
		EnhkeyUsage.cUsageIdentifier = 0;
		EnhkeyUsage.rgpszUsageIdentifier=NULL;
	}
	else
	{
		EnhkeyUsage.cUsageIdentifier = 1;
		szOid = szOID_KP_SMARTCARD_LOGON;
		EnhkeyUsage.rgpszUsageIdentifier=& szOid;
	}

	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage  = EnhkeyUsage;

	memset(&ChainPara, 0, sizeof(CERT_CHAIN_PARA));
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage=CertUsage;

	memset(&ChainPolicy, 0, sizeof(CERT_CHAIN_POLICY_PARA));
    ChainPolicy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);

	memset(&PolicyStatus, 0, sizeof(CERT_CHAIN_POLICY_STATUS));
    PolicyStatus.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);
    PolicyStatus.lChainIndex = -1;
    PolicyStatus.lElementIndex = -1;

    //-------------------------------------------------------------------
    // Build a chain using CertGetCertificateChain
    __try
	{
		fReturn = CertGetCertificateChain(hChainEngine,pCertContext,NULL,NULL,&ChainPara,CERT_CHAIN_ENABLE_PEER_TRUST,NULL,&pChainContext);
		if (!fReturn)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertGetCertificateChain", dwError);
			__leave;
		}
		// pChainContext->cChain -1 is the final chain num
		DWORD dwCertificateCount = pChainContext->rgpChain[pChainContext->cChain -1]->cElement;
		if (dwCertificateCount == 1)
		{
			hTrustedPeople = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("TrustedPeople"));
			if (!hTrustedPeople)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			fReturn = CertAddCertificateContextToStore(hTrustedPeople,
					pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[0]->pCertContext,
					CERT_STORE_ADD_USE_EXISTING,NULL);
		}
		else
		{
			hRootStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hRootStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			hTrustStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("CA"));
			if (!hTrustStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertOpenStore", dwError);
				fReturn = FALSE;
				__leave;
			}
			for (DWORD i = dwCertificateCount - 1 ; i > 0 ; i--)
			{
				if (i < dwCertificateCount - 1)
				{
					// second & so on don't have to be trusted
					fReturn = CertAddCertificateContextToStore(hTrustStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,NULL);
				}
				else
				{
					// first must be trusted
					fReturn = CertAddCertificateContextToStore(hRootStore,
						pChainContext->rgpChain[pChainContext->cChain -1]->rgpElement[i]->pCertContext,
						CERT_STORE_ADD_USE_EXISTING,NULL);
				}
				if (!fReturn)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Error 0x%08x returned by CertAddCertificateContextToStore", dwError);
					__leave;
				}
			}
		}
	}
	__finally
	{
		if (hTrustedPeople)
			CertCloseStore(hTrustedPeople,0);
		if (hRootStore)
			CertCloseStore(hRootStore,0);
		if (hTrustStore)
			CertCloseStore(hTrustStore,0);
		if (pChainContext)
			CertFreeCertificateChain(pChainContext);
	}
	SetLastError(dwError);
	return fReturn;
}