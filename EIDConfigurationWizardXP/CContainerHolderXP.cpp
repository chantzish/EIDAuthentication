
#include <windows.h>
#include <tchar.h>
#include <credentialProvider.h>
#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"
#include "CContainerHolderXP.h"

#define CHECK_FAILED 0
#define CHECK_WARNING 1
#define CHECK_SUCCESS 2
#define CHECK_INFO 3

//#define CHECK_USERNAME 0
/*
#if WINVER < 0x600
// this function doesn't exists on xp, only since Vista.
// already implemented in EIDCardLibrary
// let the linker grab it
LONG WINAPI RegSetKeyValueXP(
  __in      HKEY hKey,
  __in_opt  LPCTSTR lpSubKey,
  __in_opt  LPCTSTR lpValueName,
  __in      DWORD dwType,
  __in_opt  LPCVOID lpData,
  __in      DWORD cbData
);
#define RegSetKeyValue RegSetKeyValueXP
#endif*/


#define ERRORTOTEXT(ERROR) case ERROR: LoadString( g_hinst,IDS_##ERROR, szName, dwSize);                 break;
BOOL GetTrustErrorMessage(DWORD dwError, PTSTR szName, DWORD dwSize)
{
    BOOL fReturn = TRUE;
	DWORD dwResourceId = 3305;
	if (dwError == CERT_TRUST_NO_ERROR)
	{
		dwResourceId = 3299;
	}
	else if (dwError & CERT_TRUST_IS_NOT_TIME_VALID)
	{
		dwResourceId = 3301;
	}
	else if (dwError & CERT_TRUST_IS_NOT_TIME_NESTED)
	{
		dwResourceId = 3295;
	}
	else if (dwError & CERT_TRUST_IS_REVOKED)
	{
		dwResourceId = 3300;
	}
	else if (dwError & CERT_TRUST_IS_NOT_SIGNATURE_VALID)
	{
		dwResourceId = 3302;
	}
	else if (dwError & CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
	{
		dwResourceId = 3342;
	}
	else if (dwError & CERT_TRUST_IS_UNTRUSTED_ROOT)
	{
		dwResourceId = 3296;
	}
	else if (dwError & CERT_TRUST_IS_PARTIAL_CHAIN)
	{
		dwResourceId = 3294;
	}
	HINSTANCE Handle = LoadLibrary(TEXT("cryptui.dll"));
	if (Handle)
	{
		LoadStringW(Handle, dwResourceId, szName, dwSize);
		FreeLibrary(Handle);
	}
	else
	{
		swprintf_s(szName, dwSize, L"Unknow Error");
	}
	return fReturn;
} 

CContainerHolderTest::CContainerHolderTest(CContainer* pContainer)
{
	_pContainer = pContainer;
	_IsTrusted = IsTrusted();
	_SupportEncryption = SupportEncryption();
	//_HasCurrentUserName = HasCurrentUserName();
}

CContainerHolderTest::~CContainerHolderTest()
{
	if (_pContainer)
	{
		delete _pContainer;
	}
}
void CContainerHolderTest::Release()
{
	delete this;
}

DWORD CContainerHolderTest::GetIconIndex()
{
	if (_IsTrusted && !HasSignatureUsageOnly())
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

BOOL CContainerHolderTest::HasSignatureUsageOnly()
{
	return !(_pContainer->GetKeySpec() == AT_KEYEXCHANGE || GetPolicyValue(AllowSignatureOnlyKeys));
}

BOOL CContainerHolderTest::IsTrusted()
{
	BOOL fReturn = FALSE;
	PCCERT_CONTEXT pCertContext = _pContainer->GetCertificate();
	if (pCertContext)
	{
		fReturn = IsTrustedCertificate(pCertContext);
		_dwTrustError = GetLastError();
		CertFreeCertificateContext(pCertContext);
	}
	return fReturn;
}
BOOL CContainerHolderTest::SupportEncryption()
{
	/*BOOL fReturn = FALSE;
	PCCERT_CONTEXT pCertContext = _pContainer->GetCertificate();
	if (pCertContext)
	{
		fReturn = CanEncryptPassword(NULL,0,pCertContext);
		CertFreeCertificateContext(pCertContext);
	}
	return fReturn;*/
	return _pContainer->GetKeySpec() == AT_KEYEXCHANGE;
}
/*
BOOL CContainerHolderTest::HasCurrentUserName()
{
	TCHAR szUserName[1024] = TEXT("");
	DWORD dwSize = ARRAYSIZE(szUserName);
	GetUserName(szUserName, &dwSize);
	return _tcscmp(_pContainer->GetUserName(),szUserName)==0;
}*/

CContainer* CContainerHolderTest::GetContainer()
{
	return _pContainer;
}

int CContainerHolderTest::GetCheckCount()
{
	return CHECK_MAX;
}
int CContainerHolderTest::GetImage(DWORD dwCheckNum)
{
	
	switch(dwCheckNum)
	{
	case CHECK_SIGNATUREONLY: 
		if (!HasSignatureUsageOnly())
			return CHECK_SUCCESS;
		else
			return CHECK_FAILED;
		break;
	case CHECK_TRUST: 
		if (_IsTrusted)
			return CHECK_SUCCESS;
		else
			return CHECK_FAILED;
		break;
	case CHECK_CRYPTO: 
		if (_SupportEncryption)
			return CHECK_SUCCESS;
		else
			return CHECK_WARNING;
		break;
	}
	return 0;
}
PTSTR CContainerHolderTest::GetDescription(DWORD dwCheckNum)
{
	DWORD dwWords = 1024;
	PTSTR szDescription = (PTSTR) EIDAlloc(dwWords * sizeof(TCHAR));
	if (!szDescription) return NULL;
	szDescription[0] = 0;
	switch(dwCheckNum)
	{
	case CHECK_SIGNATUREONLY: 
		if (!HasSignatureUsageOnly())
			LoadString(g_hinst,IDS_04SIGNATUREONLYOK,szDescription, dwWords);
		else
			LoadString(g_hinst,IDS_04SIGNATUREONLYNOK,szDescription, dwWords);
		break;
	case CHECK_TRUST: 
		if (_IsTrusted)
			LoadString(g_hinst,IDS_04TRUSTOK,szDescription, dwWords);
		else
		{
			if (!GetTrustErrorMessage(_dwTrustError,szDescription,dwWords))
			{
				FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,NULL,_dwTrustError,0,szDescription,dwWords,NULL);
			}
		}
		break;
	case CHECK_CRYPTO: 
		if (_SupportEncryption)
			LoadString(g_hinst,IDS_04ENCRYPTIONOK,szDescription, dwWords);
		else
			LoadString(g_hinst,IDS_04ENCRYPTIONNOK,szDescription, dwWords);
		break;
	}
	return szDescription;
}

PTSTR CContainerHolderTest::GetSolveDescription(DWORD dwCheckNum)
{
	DWORD dwWords = 1024;
	PTSTR szDescription = (PTSTR) EIDAlloc(dwWords * sizeof(TCHAR));
	if (!szDescription) return NULL;
	szDescription[0] = 0;
	switch(dwCheckNum)
	{
	case CHECK_SIGNATUREONLY: 
		if (HasSignatureUsageOnly())
		{
			LoadString(g_hinst,IDS_04CHANGESIGNATUREPOLICY,szDescription, dwWords);
		}
		break;
	case CHECK_TRUST: 
		if (!_IsTrusted)
		{
			if (_dwTrustError & CERT_TRUST_IS_UNTRUSTED_ROOT || _dwTrustError & CERT_TRUST_IS_PARTIAL_CHAIN)
			{
				LoadString(g_hinst,IDS_04TRUSTMAKETRUSTED,szDescription, dwWords);
			}
			else if (_dwTrustError & CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
			{
				LoadString(g_hinst,IDS_04TRUSTENABLENOEKU,szDescription, dwWords);
			}
			else if (_dwTrustError & CERT_TRUST_IS_NOT_TIME_VALID)
			{
				LoadString(g_hinst,IDS_04TRUSTENABLETIMEINVALID,szDescription, dwWords);
			}
		}
		break;
	}
	return szDescription;
}

BOOL CContainerHolderTest::Solve(DWORD dwCheckNum)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	switch(dwCheckNum)
	{
	case CHECK_SIGNATUREONLY:
		{
			DWORD dwValue = 1;
			dwError = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
					TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider"),
					TEXT("AllowSignatureOnlyKeys"), REG_DWORD, &dwValue,sizeof(dwValue));
		}
		fReturn = (dwError == 0);
		break;
	case CHECK_TRUST:
		if (_dwTrustError & CERT_TRUST_IS_UNTRUSTED_ROOT || _dwTrustError & CERT_TRUST_IS_PARTIAL_CHAIN)
		{
			PCCERT_CONTEXT pCertContext = _pContainer->GetCertificate();
			fReturn = MakeTrustedCertifcate(pCertContext);
			dwError = GetLastError();
			CertFreeCertificateContext(pCertContext);
		}
		else if (_dwTrustError & CERT_TRUST_IS_NOT_VALID_FOR_USAGE)
		{
			DWORD dwValue = 1;
			dwError = RegSetKeyValue(HKEY_LOCAL_MACHINE, 
				TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider"),
				TEXT("AllowCertificatesWithNoEKU"), REG_DWORD, &dwValue,sizeof(dwValue));
			fReturn = (dwError == 0);
		}
		else if (_dwTrustError & CERT_TRUST_IS_NOT_TIME_VALID)
		{
			DWORD dwValue = 1;
			dwError = RegSetKeyValue(HKEY_LOCAL_MACHINE, 
				TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider"),
				TEXT("AllowTimeInvalidCertificates"), REG_DWORD, &dwValue,sizeof(dwValue));
			fReturn = (dwError == 0);
		}
	}
	SetLastError(dwError);
	return fReturn;
}
