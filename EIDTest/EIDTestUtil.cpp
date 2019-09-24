#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <Sddl.h>
#include <Lm.h>
#include "EIDTestUIUtil.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CertificateUtilities.h"

#pragma comment(lib,"Cryptui")

extern HINSTANCE hInst;
extern HWND hMainWnd;




void menu_UTIL_ListCertificates()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	PCCERT_CONTEXT Context = NULL;
	if (AskForCard(szReader,256,szCard,256))
	{
		Context = SelectCert(szReader,szCard);
		if (Context) CertFreeCertificateContext(Context);
	}
}

void menu_UTIL_DeleteOneCertificate()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	HCRYPTPROV hProv;
	PCCERT_CONTEXT pContext = NULL;
	PCRYPT_KEY_PROV_INFO pProvInfo = NULL;
	__try
	{
		if (!AskForCard(szReader,256,szCard,256)) __leave;
		pContext = SelectCert(szReader,szCard);
		if (!pContext) __leave;
		DWORD dwSize = 0;
		if (!CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize))
		{
			__leave;
		}
		pProvInfo = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
		if (!pProvInfo)
		{
			__leave;
		}
		if (!CertGetCertificateContextProperty(pContext, CERT_KEY_PROV_INFO_PROP_ID, pProvInfo, &dwSize))
		{
			__leave;
		}
		CertFreeCertificateContext(pContext);
		pContext = NULL;
		// Acquire a context on the current container
		if (CryptAcquireContext(&hProv,
				pProvInfo->pwszContainerName,
				pProvInfo->pwszProvName,
				PROV_RSA_FULL,
				CRYPT_DELETEKEYSET))
		{
			WCHAR Buffer[4000];
			_stprintf_s(Buffer,4000,L"Container %s deleted",pProvInfo->pwszContainerName);
			MessageBox(NULL,Buffer,L"",0);
		}
	}
	__finally
	{
		if (pContext) CertFreeCertificateContext(pContext);
		if (pProvInfo) EIDFree(pProvInfo);
	}
}
void menu_UTIL_ClearCard()
{
	WCHAR szReaderName[256];
	WCHAR szCardName[256];

	if (AskForCard(szReaderName,256,szCardName,256))
	{
		if (IDOK == MessageBox(NULL,L"All data will be deleted !!!!!!!",L"",MB_OKCANCEL|MB_DEFBUTTON2))
		{
			ClearCard(szReaderName,szCardName);
			MessageBox(NULL,L"All data has been deleted !!!!!!!",L"",0);
		}
	}
}


DWORD SelectCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo);
void FreeCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo);

void menu_UTIL_CreateCert()
{
	UI_CERTIFICATE_INFO CertificateInfo = {0};
	WCHAR szCard[256];
	WCHAR szReader[256];
	BOOL bContinue = TRUE;
	// get input from user
	if (SelectCertificateInfo(&CertificateInfo)) 
	{
		
		if (CertificateInfo.dwSaveon == UI_CERTIFICATE_INFO_SAVEON_SMARTCARD)
		{
			if (!AskForCard(szReader, 256, szCard,256))
			{
				bContinue = FALSE;
			}
			else
			{
				CertificateInfo.szCard = szCard;
				CertificateInfo.szReader = szReader;
			}
		}
		if (bContinue)
		{
			if (CreateCertificate(&CertificateInfo))
			{
				MessageBox(hMainWnd,TEXT("Success"),TEXT("Success"),0);
			}
			else
			{
				MessageBoxWin32(GetLastError());
			}
		}
	}
	FreeCertificateInfo(&CertificateInfo);
}

void menu_UTIL_ShowSecurityDescriptor()
{
	PCCERT_CONTEXT pCertContext = SelectCertificateWithPrivateKey(hMainWnd);
	HCRYPTPROV hProv = NULL;
	DWORD dwKeyType;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;
	DWORD dwError = 0;
	PSECURITY_DESCRIPTOR pSD = NULL;
	DWORD dwSize = 0;
	PTSTR szSD = NULL;
	if (!pCertContext) return;
	__try
	{
		if (!CryptAcquireCertificatePrivateKey(pCertContext,CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,NULL,
					&hProv,&dwKeyType,&fCallerFreeProvOrNCryptKey))
		{
			dwError = GetLastError();
			__leave;
		}
		if (!CryptGetProvParam(hProv,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,&dwSize, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
		{
			dwError = GetLastError();
			__leave;
		}
		pSD = (PSECURITY_DESCRIPTOR) EIDAlloc(dwSize);
		if (!pSD)
		{
			dwError = GetLastError();
			__leave;
		}
		if (!CryptGetProvParam(hProv,PP_KEYSET_SEC_DESCR,(BYTE*)pSD,&dwSize, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION))
		{
			dwError = GetLastError();
			__leave;
		}
		if (!ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, 
			OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,&szSD,NULL))
		{
			dwError = GetLastError();
			__leave;
		}
		MessageBox(hMainWnd, szSD, TEXT("Security Descriptor"),0);
	}
	__finally
	{
		if (szSD)
			EIDFree(szSD);
		if (pSD)
			EIDFree(pSD);
		if (fCallerFreeProvOrNCryptKey && hProv)
			CryptReleaseContext(hProv, 0);
		if (pCertContext)
			CertFreeCertificateContext(pCertContext);
	}
	if (dwError)
		MessageBoxWin32(dwError);
}

void menu_UTIL_ChangeUserFlag(BOOL fSet)
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	USER_INFO_1008 info1008;
	PUSER_INFO_1 pInfo1 = NULL;
	NET_API_STATUS status;
	if (AskUsername(szUserName, szComputerName))
	{
		
		status = NetUserGetInfo(szComputerName, szUserName, 1, (PBYTE*) &pInfo1);
		if (status == NERR_Success)
		{
			
			info1008.usri1008_flags = pInfo1->usri1_flags;
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"flag before 0x%08x",info1008.usri1008_flags);
			if (fSet)
			{
				info1008.usri1008_flags |= UF_SMARTCARD_REQUIRED;
			}
			else
			{
				info1008.usri1008_flags &= ~(UF_SMARTCARD_REQUIRED);
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE, L"flag after 0x%08x",info1008.usri1008_flags);
			status = NetUserSetInfo(szComputerName, szUserName, 1008, (PBYTE) &info1008, NULL);
			MessageBoxWin32(status)
		}
		else
		{
			MessageBoxWin32(status)
		}
		
	}
	if (pInfo1) NetApiBufferFree(pInfo1);
}