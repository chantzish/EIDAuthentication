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
#include <AccCtrl.h>
#include <Aclapi.h>
#include "EIDCardLibrary.h"
#include "CertificateUtilities.h"
#include "Tracing.h"

#pragma comment (lib,"Scarddlg")
#pragma comment (lib,"Rpcrt4")


BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen)
{
	// get provider name
	SCARDCONTEXT hSCardContext;
	LONG lCardStatus;
	lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",lCardStatus);
		return FALSE;
	}
	
	lCardStatus = SCardGetCardTypeProviderName(hSCardContext,
									   szCardName,
									   SCARD_PROVIDER_CSP,
									   szProviderName,
									   pdwProviderNameLen);
	if (SCARD_S_SUCCESS != lCardStatus)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardGetCardTypeProviderName 0x%08x",lCardStatus);
		SCardReleaseContext(hSCardContext);
		return FALSE;
	}
	SCardReleaseContext(hSCardContext);
	return TRUE;
}

// the string must be freed using RpcStringFree
PTSTR GetUniqueIDString()
{
	UUID pUUID;
	PTSTR sTemp = NULL;
	RPC_STATUS hr;
	DWORD dwError = 0;
	hr = UuidCreate(&pUUID);
	if (hr == RPC_S_OK || hr == RPC_S_UUID_LOCAL_ONLY)
	{
		hr = UuidToString(&pUUID, (RPC_WSTR *)&sTemp); 
		if (hr != RPC_S_OK)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UuidToString 0x%08x",hr);
			dwError = HRESULT_CODE(hr);
		}
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UuidCreate 0x%08x",hr);
		dwError = HRESULT_CODE(hr);
	}
	SetLastError(dwError);
	return sTemp;
}

PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd)
{
	PCCERT_CONTEXT returnedContext = NULL;
		
	HCERTSTORE hCertStore,hStore;
	BOOL bShowNoCertificate = TRUE;
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root"));
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		PBYTE dwKeySpec = NULL;
		DWORD dwSize = 0;
		// open a temp store and copy context which have a private key
		hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,NULL,0,	NULL);

		if (hStore)
		{
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			while (pCertContext)
			{
				
				if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,dwKeySpec,&dwSize))
				{
					//The certificate has a private key
					CertAddCertificateContextToStore(hStore,pCertContext,CERT_STORE_ADD_USE_EXISTING,NULL);
					bShowNoCertificate = FALSE;
				}
				pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
			}
			if (bShowNoCertificate)
			{
				MessageBox(hWnd,_T("No Trusted certificate found"),_T("Warning"),0);
			}
			else
			{
				returnedContext = CryptUIDlgSelectCertificateFromStore(
					  hStore,
					  NULL,
					  NULL,
					  NULL,
					  CRYPTUI_SELECT_LOCATION_COLUMN,
					  0,
					  NULL);
			}
			CertCloseStore(hStore,0);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey()
{
	PCCERT_CONTEXT returnedContext = NULL;
	TCHAR szCertName[1024] = TEXT("");
	TCHAR szComputerName[257];
	DWORD dwSize = ARRAYSIZE(szComputerName);
	HCERTSTORE hCertStore = NULL;
	GetComputerName(szComputerName,&dwSize);
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("Root"));
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		while (pCertContext)
		{
			
			PBYTE KeySpec = NULL;
			dwSize = 0;
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,KeySpec,&dwSize))
			{
				//The certificate has a private key
				if (returnedContext) 
					CertFreeCertificateContext(returnedContext);
				// get the subject details for the cert
				CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,szCertName,ARRAYSIZE(szCertName));
				// match computer name ?
				if (_tcscmp(szCertName, szComputerName) == 0)
				{
					returnedContext = pCertContext;
					// return
					break;
				}
				else
				{
					returnedContext = CertDuplicateCertificateContext(pCertContext);
					// continue the loop
				}
				
			}
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		}
		CertCloseStore(hCertStore,0);
	}
	return returnedContext;
}


LPBYTE AllocateAndEncodeObject(LPVOID pvStruct, LPCSTR lpszStructType, LPDWORD pdwSize )
{
   // Get Key Usage blob size   
   LPBYTE pbEncodedObject = NULL;
   BOOL bResult = TRUE;
   DWORD dwError;
	__try
   {
	   *pdwSize = 0;	
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   NULL, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();
		  __leave;   
	   }   

	   // Allocate Memory for Key Usage Blob   
	   pbEncodedObject = (LPBYTE)EIDAlloc(*pdwSize);   
	   if (!pbEncodedObject)   
	   {   
		  bResult = FALSE;
		  dwError = GetLastError();   
		  __leave;   
	   }   

	   // Get Key Usage Extension blob   
	   bResult = CryptEncodeObject(X509_ASN_ENCODING,   
								   lpszStructType,   
								   pvStruct,   
								   pbEncodedObject, pdwSize);   
	   if (!bResult)   
	   {   
		  dwError = GetLastError();  
		  __leave;   
	   }   
   }
   __finally
   {
		if (pbEncodedObject && !bResult)
		{
			EIDFree(pbEncodedObject);
		}
   }
   return pbEncodedObject;
}

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength)
{
	SCARDCONTEXT     hSC = NULL;
	OPENCARDNAME_EX  dlgStruct;
	LONG             lReturn = 0;
	BOOL			 fReturn = FALSE;
	__try
	{
		// Establish a context.
		// It will be assigned to the structure's hSCardContext field.
		lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
										NULL,
										NULL,
										&hSC );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardReleaseContext 0x%08X",lReturn);
			__leave;
		}

		// Initialize the structure.
		memset(&dlgStruct, 0, sizeof(dlgStruct));
		dlgStruct.dwStructSize = sizeof(dlgStruct);
		dlgStruct.hSCardContext = hSC;
		dlgStruct.dwFlags = SC_DLG_MINIMAL_UI;
		dlgStruct.lpstrRdr = szReader;
		dlgStruct.nMaxRdr = ReaderLength;
		dlgStruct.lpstrCard = szCard;
		dlgStruct.nMaxCard = CardLength;
		dlgStruct.lpstrTitle = L"Select Card";
		dlgStruct.dwShareMode = 0;
		// Display the select card dialog box.
		lReturn = SCardUIDlgSelectCard(&dlgStruct);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			szReader[0]=0;
			szCard[0]=0;
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (hSC)
			SCardReleaseContext(hSC);
	}
	// Free the context.
	// lReturn is of type LONG.
	// hSC was set by an earlier call to SCardEstablishContext.
	SetLastError(lReturn);
	return fReturn;
}

BOOL CreateCertificate(PUI_CERTIFICATE_INFO pCertificateInfo)
{
	BOOL fReturn = FALSE;
	CERT_INFO CertInfo = {0};
	CertInfo.rgExtension = 0;
	CERT_NAME_BLOB SubjectIssuerBlob = {0};
	HCRYPTPROV hCryptProvNewCertificate = NULL, hCryptProvRootCertificate = NULL;
	PCCERT_CONTEXT pNewCertificateContext = NULL;
	PCERT_PUBLIC_KEY_INFO pbPublicKeyInfo = NULL;
	HCERTSTORE hCertStore = NULL;
	PBYTE  pbSignedEncodedCertReq = NULL;
	BOOL bDestroyContainer = FALSE;
	HCRYPTKEY hKey = NULL;
	CRYPT_KEY_PROV_INFO KeyProvInfo = {0};
	LPTSTR szContainerName=NULL;
    FILETIME ftTime;   
	BYTE SerialNumber[8];  
	DWORD dwKeyType = 0;
	DWORD cbPublicKeyInfo = 0;
	BOOL pfCallerFreeProvOrNCryptKey = FALSE;
	CRYPT_ALGORITHM_IDENTIFIER SigAlg;
	CRYPT_OBJID_BLOB  Parameters;
	CRYPTUI_WIZ_EXPORT_INFO WizInfo = {0};
	DWORD cbEncodedCertReqSize = 0;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = 1024;
	DWORD dwFlag;
	DWORD dwSize;
	HCRYPTHASH hHash = 0;  
    BYTE ByteData;   
    CRYPT_BIT_BLOB KeyUsage;   
	LPBYTE pbKeyUsage = NULL; 
	LPBYTE pbBasicConstraints = NULL;
	LPBYTE pbEnhKeyUsage = NULL;
	LPBYTE pbKeyIdentifier = NULL;   
	LPBYTE SubjectKeyIdentifier = NULL;   
	CRYPT_DATA_BLOB CertKeyIdentifier;
	CERT_BASIC_CONSTRAINTS2_INFO BasicConstraints;
	CERT_ENHKEY_USAGE CertEnhKeyUsage = { 0, NULL };  
	CERT_EXTENSIONS CertExtensions = {0} ;
	DWORD dwError = 0;
	PSID pSidSystem = NULL;
	PSID pSidAdmins = NULL;
	PACL pDacl = NULL;
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;
	PSECURITY_DESCRIPTOR pSD = NULL;
	__try   
    { 

		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Enter");
		if (pCertificateInfo == NULL)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"pCertificateInfo NULL");
			__leave;
		}

		pCertificateInfo->pNewCertificate = NULL;
		// prepare the container name based on the support
		if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SMARTCARD");
			// provider name
			if (!SchGetProviderNameFromCardName(pCertificateInfo->szCard, szProviderName, &dwProviderNameLen))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SchGetProviderNameFromCardName 0x%08X", dwError);
				__leave;
			}
			// container name from card name
			size_t ulNameLen = _tcslen(pCertificateInfo->szReader);
			szContainerName = (LPTSTR) EIDAlloc( (DWORD) (ulNameLen + 6) * sizeof(TCHAR));
			if (!szContainerName)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			_stprintf_s(szContainerName,(ulNameLen + 6), _T("\\\\.\\%s\\"), pCertificateInfo->szReader);
		}
		else
		{
			// container name = GUID
			szContainerName = GetUniqueIDString();
			if (!szContainerName) 
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"GetUniqueIDString 0x%08X", dwError);
				__leave;
			}
			
			// Provider  MS_ENHANCED_PROV
			_stprintf_s(szProviderName,1024,_T("%s"),MS_ENHANCED_PROV);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"szContainerName = %s", szContainerName);

		dwFlag=CRYPT_NEWKEYSET;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
				dwFlag |= CRYPT_MACHINE_KEYSET;
		}
		// create container
		if (!CryptAcquireContext(
			&hCryptProvNewCertificate,
			szContainerName,   
			szProviderName,
			PROV_RSA_FULL,
			dwFlag))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptAcquireContext 0x%08X", dwError);
			__leave;
		}
		else
		{
			bDestroyContainer=TRUE;
		}
		// generate key
		dwFlag=0;
		switch(pCertificateInfo->dwSaveon)
		{
			case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user
			case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine
			case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
				dwFlag |= CRYPT_EXPORTABLE;
		}
		// Key Size
		dwFlag |= pCertificateInfo->dwKeySizeInBits * 0x10000;
		if (!CryptGenKey(hCryptProvNewCertificate, pCertificateInfo->dwKeyType, dwFlag, &hKey))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGenKey 0x%08X", dwError);
			__leave;
		}

		
		// create the cert data
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,NULL,NULL,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}
		SubjectIssuerBlob.pbData = (PBYTE) EIDAlloc(SubjectIssuerBlob.cbData);
		if (!SubjectIssuerBlob.pbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			__leave;
		}
		if (!CertStrToName(X509_ASN_ENCODING,pCertificateInfo->szSubject,CERT_X500_NAME_STR,NULL,(PBYTE)SubjectIssuerBlob.pbData,&SubjectIssuerBlob.cbData,NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertStrToName 0x%08X", dwError);
			__leave;
		}

		//////////////////////////////////////////////////
		// Key Usage & ...
		
		// max 10 extensions => we don't count them
		CertInfo.rgExtension = (PCERT_EXTENSION) EIDAlloc(sizeof(CERT_EXTENSION) * 10);
		CertInfo.cExtension = 0;
		if (!CertInfo.rgExtension)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			__leave;
		}


		// Set Key Usage according to Public Key Type   
		ZeroMemory(&KeyUsage, sizeof(KeyUsage));   
		KeyUsage.cbData = 1;   
		KeyUsage.pbData = &ByteData;   
    
		if (pCertificateInfo->dwKeyType == AT_SIGNATURE)   
		{   
		   ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE|   
						CERT_NON_REPUDIATION_KEY_USAGE|   
						CERT_KEY_CERT_SIGN_KEY_USAGE |   
						CERT_CRL_SIGN_KEY_USAGE;   
		}   
    
		if (pCertificateInfo->dwKeyType == AT_KEYEXCHANGE)   
		{   
		   ByteData = CERT_DIGITAL_SIGNATURE_KEY_USAGE |   
						CERT_DATA_ENCIPHERMENT_KEY_USAGE|   
						CERT_KEY_ENCIPHERMENT_KEY_USAGE |   
						CERT_KEY_AGREEMENT_KEY_USAGE;   
		}


		pbKeyUsage = AllocateAndEncodeObject(&KeyUsage,X509_KEY_USAGE,&dwSize);
		if (!pbKeyUsage) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_KEY_USAGE;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbKeyUsage;   
		// Increase extension count   
		CertInfo.cExtension++; 
	   //////////////////////////////////////////////////

	   // Zero Basic Constraints structure   
		ZeroMemory(&BasicConstraints, sizeof(BasicConstraints));   
    
		// Self-signed is always a CA   
		if (pCertificateInfo->bIsSelfSigned)   
		{   
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SelfSigned");
			BasicConstraints.fCA = TRUE;   
			BasicConstraints.fPathLenConstraint = TRUE;   
			BasicConstraints.dwPathLenConstraint = 1;   
		}   
		else   
		{   
			BasicConstraints.fCA = pCertificateInfo->bIsCA;   
		}   
		pbBasicConstraints = AllocateAndEncodeObject(&BasicConstraints,X509_BASIC_CONSTRAINTS2,&dwSize);
		if (!pbBasicConstraints) 
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
			__leave;
		}

		// Set Basic Constraints extension   
		CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_BASIC_CONSTRAINTS2;   
		CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbBasicConstraints;   
		// Increase extension count   
		CertInfo.cExtension++;  
		//////////////////////////////////////////////////
		if (pCertificateInfo->bHasClientAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasServerAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasSmartCardAuthentication)
			CertEnhKeyUsage.cUsageIdentifier++;
		if (pCertificateInfo->bHasEFS)
			CertEnhKeyUsage.cUsageIdentifier++;


		if (CertEnhKeyUsage.cUsageIdentifier != 0)   
		{
			CertEnhKeyUsage.rgpszUsageIdentifier = (LPSTR*) EIDAlloc(sizeof(LPSTR)*CertEnhKeyUsage.cUsageIdentifier);
			if (!CertEnhKeyUsage.rgpszUsageIdentifier)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			CertEnhKeyUsage.cUsageIdentifier = 0;
			if (pCertificateInfo->bHasClientAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_CLIENT_AUTH;
			if (pCertificateInfo->bHasServerAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_PKIX_KP_SERVER_AUTH;
			if (pCertificateInfo->bHasSmartCardAuthentication)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_SMARTCARD_LOGON;
			if (pCertificateInfo->bHasEFS)
				CertEnhKeyUsage.rgpszUsageIdentifier[CertEnhKeyUsage.cUsageIdentifier++] = szOID_KP_EFS;
			pbEnhKeyUsage = AllocateAndEncodeObject(&CertEnhKeyUsage,X509_ENHANCED_KEY_USAGE,&dwSize);
			if (!pbEnhKeyUsage)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndEncodeObject 0x%08X", dwError);
				__leave;
			}

		   // Set Basic Constraints extension   
		   CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_ENHANCED_KEY_USAGE;   
		   CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
		   CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = pbEnhKeyUsage;   
		   	// Increase extension count   
			CertInfo.cExtension++; 
		}

		//////////////////////////////////////////////////

		if (pCertificateInfo->bIsSelfSigned)
		{
			CertExtensions.cExtension = CertInfo.cExtension;
			CertExtensions.rgExtension = CertInfo.rgExtension;
			pNewCertificateContext = CertCreateSelfSignCertificate(hCryptProvNewCertificate,&SubjectIssuerBlob,
				0,NULL,NULL,&pCertificateInfo->StartTime,&pCertificateInfo->EndTime,&CertExtensions);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertCreateSelfSignCertificate 0x%08X", dwError);
				__leave;
			}
		}
		else
		{
			CertInfo.Subject = SubjectIssuerBlob;
			CertInfo.dwVersion = CERT_V3;

			// set issuer info
			CertInfo.Issuer = pCertificateInfo->pRootCertificate->pCertInfo->Subject;
			CertInfo.IssuerUniqueId = pCertificateInfo->pRootCertificate->pCertInfo->SubjectUniqueId;

			
			SystemTimeToFileTime(&pCertificateInfo->StartTime, &ftTime);   
			CertInfo.NotBefore = ftTime;  

			SystemTimeToFileTime(&pCertificateInfo->EndTime, &ftTime);   
			CertInfo.NotAfter = ftTime;   

			// Create Random Serial Number   
			if (!CryptGenRandom(hCryptProvNewCertificate, 8, SerialNumber))   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGenRandom 0x%08X", dwError);
				__leave;
			}   

			// Set Serial Number of Certificate   
			CertInfo.SerialNumber.cbData = 8;   
			CertInfo.SerialNumber.pbData = SerialNumber;   
			
			// public key
			//////////////
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,  
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,		
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptExportPublicKeyInfo 0x%08X", dwError);
				__leave;	
			}
			pbPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO) EIDAlloc(cbPublicKeyInfo);
			if (!pbPublicKeyInfo) {
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if(!CryptExportPublicKeyInfo(
				  hCryptProvNewCertificate,
				  pCertificateInfo->dwKeyType,   
				  X509_ASN_ENCODING,      
				  pbPublicKeyInfo,		
				  &cbPublicKeyInfo))     
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptExportPublicKeyInfo 0x%08X", dwError);
				__leave;
			}
			CertInfo.SubjectPublicKeyInfo = *pbPublicKeyInfo;
			// Create Hash     
			if (!CryptCreateHash(hCryptProvNewCertificate, CALG_SHA1, 0, 0, &hHash))   
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptCreateHash 0x%08X", dwError);
			  __leave;   
			}   

			// Hash Public Key Info   
			if (!CryptHashData(hHash, (LPBYTE)pbPublicKeyInfo, dwSize, 0))   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptHashData 0x%08X", dwError);
				__leave;   
			}   

			// Get Size of Hash   
			if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &dwSize, 0))   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGetHashParam 0x%08X", dwError);
				__leave;   
			}   

			// Allocate Memory for Key Identifier (hash of Public Key info)   
			pbKeyIdentifier = (LPBYTE)EIDAlloc(dwSize);   
			if (!pbKeyIdentifier)   
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
			  __leave;   
			}   

			// Get Hash of Public Key Info   
			if (!CryptGetHashParam(hHash, HP_HASHVAL, pbKeyIdentifier, &dwSize, 0))   
			{   
			  dwError = GetLastError();
			  EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptGetHashParam 0x%08X", dwError);
			  __leave;   
			}   

			// We will use this to set the Key Identifier extension   
			CertKeyIdentifier.cbData = dwSize;   
			CertKeyIdentifier.pbData = pbKeyIdentifier;  

			// Get Subject Key Identifier Extension size   
			if (!CryptEncodeObject(X509_ASN_ENCODING,   
									   szOID_SUBJECT_KEY_IDENTIFIER,   
									   (LPVOID)&CertKeyIdentifier,   
									   NULL, &dwSize))
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptEncodeObject 0x%08X", dwError);
				__leave;   
			}   

			// Allocate Memory for Subject Key Identifier Blob   
			SubjectKeyIdentifier = (LPBYTE)EIDAlloc(dwSize);   
			if (!SubjectKeyIdentifier)   
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;   
			}   

			// Get Subject Key Identifier Extension   
			if (!CryptEncodeObject(X509_ASN_ENCODING,   
									   szOID_SUBJECT_KEY_IDENTIFIER,   
									   (LPVOID)&CertKeyIdentifier,   
									   SubjectKeyIdentifier, &dwSize))
			{   
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptEncodeObject 0x%08X", dwError);
				__leave;   
			}   

			// Set Subject Key Identifier   
			CertInfo.rgExtension[CertInfo.cExtension].pszObjId = szOID_SUBJECT_KEY_IDENTIFIER;   
			CertInfo.rgExtension[CertInfo.cExtension].fCritical = FALSE;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.cbData = dwSize;   
			CertInfo.rgExtension[CertInfo.cExtension].Value.pbData = SubjectKeyIdentifier;   

			// Increase extension count   
			CertInfo.cExtension++;   
////////////////////////////////////////////////////////////////////////////////////////////////////////
			// sign certificate
			///////////////////
			memset(&Parameters, 0, sizeof(Parameters));
			SigAlg.pszObjId = szOID_OIWSEC_sha1RSASign;
			SigAlg.Parameters = Parameters;

			CertInfo.SignatureAlgorithm = SigAlg;

			// retrieve crypt context from root cert
			if (!CryptAcquireCertificatePrivateKey(pCertificateInfo->pRootCertificate,0,NULL,
					&hCryptProvRootCertificate,&dwKeyType,&pfCallerFreeProvOrNCryptKey))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptAcquireCertificatePrivateKey 0x%08X", dwError);
				//MessageBox(0,_T("need admin privilege ?"),_T("test"),0);
				__leave;
			}

			// sign certificate
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,    // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,            // Encoding type
				  X509_CERT_TO_BE_SIGNED,      // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                     // Signature algorithm
				  NULL,                        // Not used
				  pbSignedEncodedCertReq,      // Pointer
				  &cbEncodedCertReqSize))  // Length of the message
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSignAndEncodeCertificate 0x%08X", dwError);
				__leave;
			}
			pbSignedEncodedCertReq = (PBYTE) EIDAlloc(cbEncodedCertReqSize);
			if (!pbSignedEncodedCertReq) 
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if(!CryptSignAndEncodeCertificate(
				  hCryptProvRootCertificate,                     // Crypto provider
				  AT_SIGNATURE,                 // Key spec
				  X509_ASN_ENCODING,               // Encoding type
				  X509_CERT_TO_BE_SIGNED, // Struct type
				  &CertInfo,                   // Struct info        
				  &SigAlg,                        // Signature algorithm
				  NULL,                           // Not used
				  pbSignedEncodedCertReq,         // Pointer
				  &cbEncodedCertReqSize))         // Length of the message
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSignAndEncodeCertificate 0x%08X", dwError);
				__leave;
			}
			// create context
			//////////////////
			pNewCertificateContext = CertCreateCertificateContext(X509_ASN_ENCODING,pbSignedEncodedCertReq,cbEncodedCertReqSize);
			if (!pNewCertificateContext)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertCreateCertificateContext 0x%08X", dwError);
				__leave;
			}
		}

		// save context property to access the private key later
		// except for smart card (because certificate is associated to the key
		// (container name doesn't contain the real container name but \\.\ReaderName)
		//////////////////////////////////////////////////////
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			memset(&KeyProvInfo,0, sizeof(KeyProvInfo));
			KeyProvInfo.pwszProvName = szProviderName;
			KeyProvInfo.pwszContainerName = szContainerName;
			KeyProvInfo.dwProvType = PROV_RSA_FULL;
			KeyProvInfo.dwKeySpec = pCertificateInfo->dwKeyType;
			if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE)
			{
				KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
			}

			CertSetCertificateContextProperty(pNewCertificateContext,CERT_KEY_PROV_INFO_PROP_ID,0,&KeyProvInfo);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"certificate generated");
		// save the certificate
		///////////////////////
		switch (pCertificateInfo->dwSaveon)
		{
		case UI_CERTIFICATE_INFO_SAVEON_USERSTORE: // user store
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_USERSTORE");
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("My"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,NULL))
			{
				//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pNewCertificateContext,NULL,NULL,0,NULL);
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE: // machine store
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE");
			// set security -> admin and system
			// create SYSTEM SID

			if (!AllocateAndInitializeSid(&sia, 1, SECURITY_LOCAL_SYSTEM_RID,0, 0, 0, 0, 0, 0, 0, &pSidSystem))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndInitializeSid 0x%08X", dwError);
				__leave;
			}

			// create Local Administrators alias SID
			if (!AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0,0, 0, &pSidAdmins))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"AllocateAndInitializeSid 0x%08X", dwError);
				__leave;
			}
			EXPLICIT_ACCESS ea[2];
			ZeroMemory(&ea, sizeof(ea));
			// fill an entry for the SYSTEM account
			ea[0].grfAccessMode = GRANT_ACCESS;
			ea[0].grfAccessPermissions = GENERIC_ALL;
			ea[0].grfInheritance = NO_INHERITANCE;
			ea[0].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[0].Trustee.pMultipleTrustee = NULL;
			ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ea[0].Trustee.ptstrName = (LPTSTR)pSidSystem;
			// fill an entry for the Administrators alias
			ea[1].grfAccessMode = GRANT_ACCESS;
			ea[1].grfAccessPermissions = GENERIC_ALL;
			ea[1].grfInheritance = NO_INHERITANCE;
			ea[1].Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
			ea[1].Trustee.pMultipleTrustee = NULL;
			ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ea[1].Trustee.TrusteeType = TRUSTEE_IS_ALIAS;
			ea[1].Trustee.ptstrName = (LPTSTR)pSidAdmins;
			// create a DACL
			dwError = SetEntriesInAcl(2, ea, NULL, &pDacl);
			if (dwError != ERROR_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetEntriesInAcl 0x%08X", dwError);
				__leave;
			}
			pSD = (PSECURITY_DESCRIPTOR) EIDAlloc(SECURITY_DESCRIPTOR_MIN_LENGTH);
			if (!pSD)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"EIDAlloc 0x%08X", dwError);
				__leave;
			}
			if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"InitializeSecurityDescriptor 0x%08X", dwError);
				__leave;
			}
			// Add the ACL to the security descriptor.
			if (!SetSecurityDescriptorDacl(pSD,TRUE,pDacl,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorDacl 0x%08X", dwError);
				__leave;
			}
			if (!SetSecurityDescriptorOwner(pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorOwner 0x%08X", dwError);
				__leave;
			}
			if (!SetSecurityDescriptorGroup (pSD,pSidAdmins,FALSE))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"SetSecurityDescriptorGroup 0x%08X", dwError);
				__leave;
			}
			if(!CryptSetProvParam(hCryptProvNewCertificate,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,DACL_SECURITY_INFORMATION))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSetProvParam 0x%08X", dwError);
				__leave;
			}
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("Root"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,NULL))
			{
				//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pNewCertificateContext,NULL,NULL,0,NULL);
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;		
		case UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY:
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY");
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_LOCAL_MACHINE,_T("My"));
			if (!hCertStore)
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertOpenStore 0x%08X", dwError);
				__leave;
			}
			if (CertAddCertificateContextToStore(hCertStore,pNewCertificateContext,CERT_STORE_ADD_ALWAYS,NULL))
			{
				//CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pNewCertificateContext,NULL,NULL,0,NULL);
			}
			else
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CertAddCertificateContextToStore 0x%08X", dwError);
				__leave;
			}
			break;
		case UI_CERTIFICATE_INFO_SAVEON_FILE: // file
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_FILE");
			WizInfo.dwSize = sizeof(CRYPTUI_WIZ_EXPORT_INFO);
			WizInfo.dwSubjectChoice=CRYPTUI_WIZ_EXPORT_CERT_CONTEXT;
			WizInfo.pCertContext=pNewCertificateContext;

			// don't care about return value
//			CryptUIWizExport(0,hMainWnd,_T("Export"),&WizInfo,NULL);
			
			break;
		case UI_CERTIFICATE_INFO_SAVEON_SMARTCARD: // smart card
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"UI_CERTIFICATE_INFO_SAVEON_SMARTCARD");
			if (!CryptSetKeyParam(hKey, KP_CERTIFICATE,pNewCertificateContext->pbCertEncoded, 0))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"CryptSetKeyParam 0x%08X", dwError);
				__leave;
			}
			break;
		}
		if (pCertificateInfo->fReturnCerticateContext)
		{
			pCertificateInfo->pNewCertificate = CertDuplicateCertificateContext(pNewCertificateContext);
		}
		// don't destroy the container is creation is successfull
		if (pCertificateInfo->dwSaveon != UI_CERTIFICATE_INFO_SAVEON_FILE) 
			bDestroyContainer = FALSE;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Success");
		fReturn = TRUE;
	}
	__finally
	{
		if (SubjectKeyIdentifier) EIDFree(SubjectKeyIdentifier);
		if (pbKeyIdentifier) EIDFree(pbKeyIdentifier);
		if (pNewCertificateContext) CertFreeCertificateContext(pNewCertificateContext);
		if (CertInfo.rgExtension) EIDFree(CertInfo.rgExtension);
		if (pbKeyUsage) EIDFree(pbKeyUsage);
		if (pbBasicConstraints) EIDFree(pbBasicConstraints);
		if (pbEnhKeyUsage) EIDFree(pbEnhKeyUsage);
		if (CertEnhKeyUsage.rgpszUsageIdentifier) EIDFree(CertEnhKeyUsage.rgpszUsageIdentifier);
		if (hKey) CryptDestroyKey(hKey);
		if (SubjectIssuerBlob.pbData) EIDFree(SubjectIssuerBlob.pbData);
		if (hCertStore) CertCloseStore(hCertStore,0);
		if (pbSignedEncodedCertReq) EIDFree(pbSignedEncodedCertReq);
		if (pbPublicKeyInfo) EIDFree(pbPublicKeyInfo);
		if (hCryptProvNewCertificate) CryptReleaseContext(hCryptProvNewCertificate,0);
		if (hCryptProvRootCertificate && pfCallerFreeProvOrNCryptKey) 
			CryptReleaseContext(hCryptProvRootCertificate,0);
		if (bDestroyContainer)
		{
			// if a temp container has been created, delete it
			CryptAcquireContext(
				&hCryptProvNewCertificate,
				szContainerName,
				szProviderName,
				PROV_RSA_FULL,
				CRYPT_DELETE_KEYSET);
		}
		
		if (szContainerName) 
		{
			if (pCertificateInfo->dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
				EIDFree(szContainerName);
			else
				RpcStringFree((RPC_WSTR*)&szContainerName);
		}
		if (pSidSystem)
			FreeSid(pSidSystem);
		if (pSidAdmins)
			FreeSid(pSidAdmins);
		if (pDacl)
			LocalFree(pDacl);
		if (pSD)
			EIDFree(pSD);
	}
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Leaving with error 0x%08X", dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName)
{
	//delete
	BOOL bStatus = FALSE;
	WCHAR szProviderName[1024];
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen =  ARRAYSIZE(szContainerName);
	DWORD dwFlags;
	HCRYPTPROV HMainCryptProv = NULL,hProv = NULL;
	DWORD dwError = 0;
	BOOL fReturn = FALSE;
	LPTSTR szMainContainerName = NULL;
	__try
	{
		if (!SchGetProviderNameFromCardName(szCardName, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}

		size_t ulNameLen = _tcslen(szReaderName);
		szMainContainerName = (LPTSTR) EIDAlloc((DWORD)(ulNameLen + 6) * sizeof(TCHAR));
		if (!szMainContainerName)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		_stprintf_s(szMainContainerName,(ulNameLen + 6), _T("\\\\.\\%s\\"), szReaderName);

		bStatus = CryptAcquireContext(&HMainCryptProv,
					szMainContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_VERIFYCONTEXT);
		if (!bStatus)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		dwFlags = CRYPT_FIRST;
		/* Enumerate all the containers */
		while (CryptGetProvParam(HMainCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags)
				)
		{
			// convert the container name to unicode
			int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
			LPWSTR szWideContainerName = (LPWSTR) EIDAlloc(wLen * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Deleting %s with %s", szWideContainerName, szProviderName);

			// Acquire a context on the current container
			if (!CryptAcquireContext(&hProv,
					szWideContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_DELETEKEYSET))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CRYPT_DELETEKEYSET 0x%08x",dwError);
				__leave;
			}
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = ARRAYSIZE(szContainerName);
		}
		fReturn = TRUE;
	}
	__finally
	{
		if (szMainContainerName) EIDFree(szMainContainerName);
		if (HMainCryptProv) CryptReleaseContext(HMainCryptProv,0);
	}
	SetLastError(dwError);
	return fReturn;
}

// see http://msdn.microsoft.com/en-us/library/windows/desktop/aa387401%28v=vs.85%29.aspx
typedef struct _RSAPRIVATEKEY {
	BLOBHEADER blobheader;
	RSAPUBKEY rsapubkey;
#ifdef _DEBUG
#define BITLEN_TO_CHECK 2048
	BYTE modulus[BITLEN_TO_CHECK/8];
	BYTE prime1[BITLEN_TO_CHECK/16];
	BYTE prime2[BITLEN_TO_CHECK/16];
	BYTE exponent1[BITLEN_TO_CHECK/16];
	BYTE exponent2[BITLEN_TO_CHECK/16];
	BYTE coefficient[BITLEN_TO_CHECK/16];
	BYTE privateExponent[BITLEN_TO_CHECK/8];
#endif
} RSAPRIVKEY, *PRSAPRIVKEY;


BOOL CheckRSAKeyLength(PTSTR szContainerName, PTSTR szProviderName, RSAPRIVKEY* pbData)
{
	BOOL fReturn = FALSE;
	HCRYPTPROV hProv = NULL;
	DWORD dwError = 0;
	DWORD dwFlags = CRYPT_FIRST;
	PROV_ENUMALGS_EX alg;
	DWORD dwSize;
	__try
	{
		if (pbData->blobheader.bType != PRIVATEKEYBLOB)
		{
			dwError = ERROR_INVALID_PARAMETER;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ERROR_INVALID_PARAMETER");
			__leave;
		}
		if (! CryptAcquireContext(&hProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
			__leave;
		}
		dwSize = sizeof(PROV_ENUMALGS_EX);
		while (CryptGetProvParam(hProv,
				PP_ENUMALGS_EX,
				(LPBYTE) &alg,
				&dwSize,
				dwFlags)
			)
		{
			if (alg.aiAlgid == pbData->blobheader.aiKeyAlg)
			{
				if (pbData->rsapubkey.bitlen >= alg.dwMinLen && pbData->rsapubkey.bitlen <= alg.dwMaxLen)
				{
					fReturn = TRUE;
				}
				else
				{
					dwError = (DWORD) NTE_BAD_LEN;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Invalid bitlen should be %d < %d < %d",alg.dwMinLen,pbData->rsapubkey.bitlen, alg.dwMaxLen);
				}
				__leave;
			}
			dwSize = sizeof(PROV_ENUMALGS_EX);
			dwFlags = 0;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"no alg data found");
		fReturn = TRUE;
	}
	__finally
	{
		if (hProv)
			CryptReleaseContext(hProv, 0);
	}
	SetLastError(dwError);
	return fReturn;
}


BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname)
{
	BOOL fReturn = FALSE;
	CRYPT_DATA_BLOB DataBlob = {0};
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HCERTSTORE hCS = NULL;
	DWORD dwRead = 0;
	TCHAR szProviderName[1024];
	DWORD dwProviderNameLen = ARRAYSIZE(szProviderName);
	PWSTR szContainerName = NULL;
	HCRYPTPROV hCardProv = NULL, hProv = NULL;
	PCCERT_CONTEXT pCertContext = NULL;
	BOOL fFreeProv = FALSE;
	DWORD dwKeySpec = AT_KEYEXCHANGE;
	HCRYPTKEY hKey = NULL, hCardKey = NULL;
	PRSAPRIVKEY pbData = NULL;
	DWORD dwSize = 0;
	DWORD dwError = 0;
	BOOL fSetBackMSBaseSCCryptoFlagImport = FALSE;
	__try
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Importing %s", szFileName);
		hFile = CreateFile(szFileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateFile 0x%08x",dwError);
			__leave;
		}
		DataBlob.cbData = GetFileSize(hFile,NULL);
		if (!DataBlob.cbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetFileSize 0x%08x",dwError);
			__leave;
		}
		DataBlob.pbData = (PBYTE) EIDAlloc(DataBlob.cbData);
		if (!DataBlob.pbData)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		if (!ReadFile(hFile, DataBlob.pbData, DataBlob.cbData, &dwRead, NULL))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ReadFile 0x%08x",dwError);
			__leave;
		}
		hCS = PFXImportCertStore(&DataBlob, szPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET );
		if(!hCS)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"PFXImportCertStore 0x%08x",dwError);
			__leave;
		}
		// provider name
		if (!SchGetProviderNameFromCardName(szCardname, szProviderName, &dwProviderNameLen))
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SchGetProviderNameFromCardName 0x%08x",dwError);
			__leave;
		}
		// container name from card name
		szContainerName = (LPTSTR) EIDAlloc((DWORD)(_tcslen(szReaderName) + 6) * sizeof(TCHAR));
		if (!szContainerName)
		{
			//dwError = GetLastError();
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
			__leave;
		}
		_stprintf_s(szContainerName,(_tcslen(szReaderName) + 6), _T("\\\\.\\%s\\"), szReaderName);
		pCertContext = CertEnumCertificatesInStore(hCS, NULL);
		while( pCertContext )
		{
			dwSize = 0;
			// this check allows to find which certificate has a private key
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
			{	
				if (! CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hProv, &dwKeySpec, &fFreeProv))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireCertificatePrivateKey 0x%08x",dwError);
					__leave;
				}
				if (_tcscmp(szProviderName,MS_SCARD_PROV) == 0)
				{
					// check if MS Base crypto allow the import. If not, enable it
					HKEY hRegKey;
					DWORD dwKeyData = 0;
					dwSize = sizeof(DWORD);
					if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),NULL, KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey))
					{
						if (dwKeySpec == AT_SIGNATURE)
						{
							RegQueryValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, NULL,(PBYTE)&dwKeyData,&dwSize);
						}
						else
						{
							RegQueryValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, NULL,(PBYTE)&dwKeyData,&dwSize);
						}
						if (!dwKeyData)
						{
							fSetBackMSBaseSCCryptoFlagImport = TRUE;
							dwKeyData = 1;
							dwSize = sizeof(DWORD);
							if (dwKeySpec == AT_SIGNATURE)
							{
								RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
							else
							{
								RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
							}
						}
						RegCloseKey(hRegKey);
					}

				}
				if (!CryptGetUserKey(hProv, dwKeySpec, &hKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
					__leave;
				}
				dwSize = 0;
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				pbData = (PRSAPRIVKEY) EIDAlloc(dwSize);
				if (!pbData)
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc 0x%08x",dwError);
					__leave;
				}
				memset(pbData, 0, dwSize);
				if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, (PBYTE) pbData, &dwSize))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptExportKey 0x%08x",dwError);
					__leave;
				}
				// check key length
				if (!CheckRSAKeyLength(szContainerName, szProviderName, pbData))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CheckRSAKeyLength 0x%08x",dwError);
					__leave;
				}
				if (! CryptAcquireContext(&hCardProv,szContainerName, szProviderName, PROV_RSA_FULL,CRYPT_NEWKEYSET))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
					__leave;
				}
				if (!CryptImportKey(hCardProv, (PBYTE) pbData, dwSize, NULL, 0, &hCardKey))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptImportKey 0x%08x",dwError);
					__leave;
				}
				if (!CryptSetKeyParam(hCardKey, KP_CERTIFICATE, pCertContext->pbCertEncoded, 0))
				{
					dwError = GetLastError();
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptSetKeyParam 0x%08x",dwError);
					__leave;
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
				fReturn = TRUE;
				__leave;
			}
			pCertContext = CertEnumCertificatesInStore(hCS, pCertContext);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not found");
	}
	__finally
	{
		if (hCardKey)
			CryptDestroyKey(hCardKey);
		if (pbData)
			EIDFree(pbData);
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv && fFreeProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
		if (hCardProv)
			CryptReleaseContext(hCardProv, 0);
		if (szContainerName) 
			EIDFree(szContainerName);			
		if (hCS)
			CertCloseStore(hCS, 0);
		if (DataBlob.pbData)
			EIDFree(DataBlob.pbData);
		if (hFile != INVALID_HANDLE_VALUE)
			CloseHandle(hFile);
		if (fSetBackMSBaseSCCryptoFlagImport)
		{
			HKEY hRegKey;
			DWORD dwKeyData = 0;
			dwSize = sizeof(DWORD);
			if (!RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Base Smart Card Crypto Provider"),0,KEY_READ|KEY_QUERY_VALUE|KEY_WRITE, &hRegKey))
			{
				if (dwKeySpec == AT_SIGNATURE)
				{
					RegSetValueEx(hRegKey,TEXT("AllowPrivateSignatureKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				else
				{
					RegSetValueEx(hRegKey,TEXT("AllowPrivateExchangeKeyImport"),NULL, REG_DWORD,(PBYTE)&dwKeyData,dwSize);
				}
				RegCloseKey(hRegKey);
			}
		}
	}
	SetLastError(dwError);
	return fReturn;
}

// find certificate using its hash

PCCERT_CONTEXT FindCertificateFromHashOnCard(PCRYPT_DATA_BLOB pCertInfo, PTSTR szReaderName, PTSTR szProviderName)
{
	PCCERT_CONTEXT pCertContext = NULL;
	HCRYPTPROV HCryptProv = NULL, hProv = NULL;
	TCHAR szMainContainerName[1024];
	DWORD dwContainerNameLen = ARRAYSIZE(szMainContainerName);
	CHAR szContainerName[1024];
	DWORD dwError = 0;
	DWORD pKeySpecs[2] = {AT_KEYEXCHANGE,AT_SIGNATURE};
	HCRYPTKEY hKey = NULL;
	__try
	{
		if (!pCertInfo)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCertInfo null");
			__leave;
		}
		_stprintf_s(szMainContainerName, dwContainerNameLen, TEXT("\\\\.\\%s\\"), szReaderName);
		if (!CryptAcquireContext(&HCryptProv,
					szMainContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
		{
			// for the spanish EID
			if (!CryptAcquireContext(&HCryptProv,
					NULL,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
			{
				dwError = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptAcquireContext 0x%08x",dwError);
				__leave;
			}
		}
		DWORD dwFlags = CRYPT_FIRST;
		/* Enumerate all the containers */
		while (CryptGetProvParam(HCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags)
				)
		{
			// convert the container name to unicode
	#ifdef UNICODE
			int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
			LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*wLen);
			if (szWideContainerName)
			{
				MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);
	#else
			LPTSTR szWideContainerName = (LPTSTR) EIDAlloc(sizeof(TCHAR)*(_tcslen(szContainerName)+1));
			if (szWideContainerName)
				{
				_tcscpy_s(szWideContainerName,_tcslen(szContainerName)+1,szContainerName);

	#endif
				// create a CContainer item
				if (CryptAcquireContext(&hProv,
					szWideContainerName,
					szProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT))
				{
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
								BYTE pbHash[100];
								DWORD dwHashSize = ARRAYSIZE(pbHash);
								PCCERT_CONTEXT pTempContext = CertCreateCertificateContext(X509_ASN_ENCODING ,Data,DataSize);
								if (CryptHashCertificate(NULL, 0, 0, Data, DataSize, (PBYTE) &pbHash, &dwHashSize))
								{
									if (memcmp(pbHash, pCertInfo->pbData, pCertInfo->cbData) == 0)
									{
										// found
										pCertContext = pTempContext;
										CRYPT_KEY_PROV_INFO KeyProvInfo;
										KeyProvInfo.dwFlags = 0;
										KeyProvInfo.dwKeySpec = pKeySpecs[i];
										KeyProvInfo.dwProvType = PROV_RSA_FULL;
										KeyProvInfo.pwszContainerName = (LPTSTR) szWideContainerName;
										KeyProvInfo.pwszProvName = (LPTSTR) szProviderName;
										KeyProvInfo.rgProvParam = 0;
										KeyProvInfo.cProvParam = NULL;
										CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &KeyProvInfo);
										__leave;
									}
								}
								else
								{
									dwError = GetLastError();
									EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptHashPublicKeyInfo 0x%08x",dwError);
								}
							}
						CryptDestroyKey(hKey);
						hKey = NULL;
						}
					}
				}
				CryptReleaseContext(hProv, 0);
				hProv = NULL;
			}
			dwFlags = CRYPT_NEXT;
			dwContainerNameLen = 1024;
			EIDFree(szWideContainerName);
		}
	
	}
	__finally
	{
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv,0);
		if (HCryptProv)
			CryptReleaseContext(HCryptProv,0);
	}
	SetLastError(dwError);
	return pCertContext;
}

PCCERT_CONTEXT FindCertificateFromHashInReader(PCRYPT_DATA_BLOB pCertInfo, SCARDCONTEXT hSCardContext, PTSTR szReader)
{
	PCCERT_CONTEXT pCertContext = NULL;
	LONG Status = 0;
	SCARDHANDLE hCard = NULL;
	DWORD dwProto;
	DWORD dwState;
	LPTSTR szReaders = NULL;
	DWORD dwSize = SCARD_AUTOALLOCATE;
	PBYTE pbAtr = NULL;
	DWORD dwAtrSize = SCARD_AUTOALLOCATE;
	LPTSTR szCards = NULL;
	DWORD dwCardSize = SCARD_AUTOALLOCATE;
	LPTSTR szProvider = NULL;
	DWORD dwProviderSize = SCARD_AUTOALLOCATE;
	__try
	{
		Status = SCardConnect(hSCardContext, szReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProto);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08x",Status);
			__leave;
		}
		Status = SCardStatus(hCard, (PTSTR) &szReaders, &dwSize, &dwState, &dwProto, (PBYTE)&pbAtr, &dwAtrSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardStatus 0x%08x",Status);
			__leave;
		}
		Status = SCardListCards(hSCardContext, pbAtr, NULL, 0, (PTSTR)&szCards, &dwCardSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListCards 0x%08x",Status);
			__leave;
		}
		Status = SCardGetCardTypeProviderName(hSCardContext, szCards, SCARD_PROVIDER_CSP, (PTSTR)&szProvider, &dwProviderSize);
		if (Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListCards 0x%08x",Status);
			__leave;
		}
		SCardDisconnect(hCard, 0);
		hCard = NULL;
		pCertContext = FindCertificateFromHashOnCard(pCertInfo, szReaders, szProvider);
	}
	__finally
	{
		if (szProvider)
			SCardFreeMemory(hSCardContext, szProvider);
		if (szCards)
			SCardFreeMemory(hSCardContext, szCards);
		if (szReaders)
			SCardFreeMemory(hSCardContext, szReaders);
		if (pbAtr)
			SCardFreeMemory(hSCardContext, pbAtr);
		if (hCard)
			SCardDisconnect(hCard, 0);
	}
	SetLastError(Status);
	return pCertContext;
}

PCCERT_CONTEXT FindCertificateFromHash(PCRYPT_DATA_BLOB pCertInfo)
{
	PCCERT_CONTEXT pCertContext = NULL;
	HCERTSTORE hCertStore = NULL;
	DWORD dwError = 0;
	LONG Status;
	SCARDCONTEXT hSCardContext = NULL;
	DWORD dwReaderCount;
	LPTSTR szReaders = NULL;
	__try
	{
		// first, try to look into user certificate store
		hCertStore = CertOpenSystemStore(NULL, TEXT("MY"));
		if (!hCertStore)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CryptGetUserKey 0x%08x",dwError);
			__leave;
		}
		pCertContext = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, (PVOID) pCertInfo, NULL);
		if (pCertContext)
		{
			// OK, found
			__leave;
		}
		// else, look in every smart card
		Status = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
		if (Status != SCARD_S_SUCCESS)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",dwError);
			__leave;
		}
		dwReaderCount = SCARD_AUTOALLOCATE;
		Status = SCardListReaders(hSCardContext, NULL, (LPTSTR)&szReaders, &dwReaderCount);
		if (Status == SCARD_E_NO_READERS_AVAILABLE)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext SCARD_E_NO_READERS_AVAILABLE");
			__leave;
		}
		if (Status != SCARD_S_SUCCESS)
		{
			dwError = Status;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",dwError);
			__leave;
		}
		LPTSTR szRdr = szReaders;
		while ( 0 != *szRdr ) 
		{
			pCertContext = FindCertificateFromHashInReader(pCertInfo, hSCardContext, szRdr);
			if (pCertContext)
			{
				// OK, found
				__leave;
			}
			szRdr += lstrlen(szRdr) + 1;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Not Found");
	}
	__finally
	{
		if (szReaders)
			SCardFreeMemory(hSCardContext, szReaders);
		if (hSCardContext)
			SCardReleaseContext(hSCardContext);
		if (hCertStore)
			CertCloseStore(hCertStore, 0);
	}
	SetLastError(dwError);
	return pCertContext;
}
