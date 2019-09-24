#include <windows.h>
#include <Winscard.h>
#include <CryptDlg.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <commctrl.h>
#include <lm.h>
#include <wincred.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/GPO.h"

#include "EIDTest.h"
#include "EIDTestUIUtil.h"

#pragma comment (lib,"Scarddlg")
#pragma comment (lib,"Cryptui")


extern HINSTANCE hInst;
extern HWND hMainWnd;


WCHAR* UserNameBuffer;
WCHAR* ComputerNameBuffer;
WCHAR* PinBuffer;

static BOOL CALLBACK GoToProc(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
 
    switch (message) 
    { 
        case WM_INITDIALOG: 
			{
				TCHAR szUserName[200];
				DWORD dwSize = ARRAYSIZE(szUserName);
				WCHAR szComputerName[MAX_COMPUTERNAME_LENGTH+1];
				SetFocus(GetDlgItem(hwndDlg,IDC_EDT1));
				GetUserName(szUserName, &dwSize);
				SetWindowText(GetDlgItem(hwndDlg,IDC_EDT1),szUserName);
				dwSize = ARRAYSIZE(szComputerName);
				GetComputerName(szComputerName, &dwSize);
				SetWindowText(GetDlgItem(hwndDlg,IDC_EDT2),szComputerName);
			}
            return TRUE; 
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
                case IDOK: 
					GetWindowText(GetDlgItem(hwndDlg,IDC_EDT1),UserNameBuffer,UNLEN);
					GetWindowText(GetDlgItem(hwndDlg,IDC_EDT2),ComputerNameBuffer,UNLEN);
					EndDialog(hwndDlg,1);
                    return TRUE; 
				case IDCANCEL:
					EndDialog(hwndDlg,0);
                    return TRUE; 
            } 
    } 
    return FALSE; 
} 

BOOL AskUsername(WCHAR* Username, WCHAR* ComputerName)
{
	UserNameBuffer = Username;
	ComputerNameBuffer = ComputerName;

	BOOL fStatus = (DialogBox(hInst, MAKEINTRESOURCE(IDD_NAMETOTTOKEN), hMainWnd, (DLGPROC)GoToProc) > 0);
	return fStatus;
}



static BOOL CALLBACK GoToProcPin(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
 
    switch (message) 
    { 
        case WM_INITDIALOG: 
			SetFocus(GetDlgItem(hwndDlg,IDC_PIN));
			SetWindowText(GetDlgItem(hwndDlg,IDC_PIN),L"");
            return TRUE; 
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
                case IDC_PINOK: 
					GetWindowText(GetDlgItem(hwndDlg,IDC_PIN),PinBuffer,UNLEN);
					EndDialog(hwndDlg,1);
                    return TRUE; 
				case IDC_PINCANCEL:
					EndDialog(hwndDlg,0);
                    return TRUE; 
            } 
    } 
    return FALSE; 
} 

typedef struct _KERB_SMARTCARD_CSP_INFO {
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID   ContextInformation;
    ULONG64 SpaceHolderForWow64;
  };
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer;
} KERB_SMARTCARD_CSP_INFO, *PKERB_SMARTCARD_CSP_INFO;

BOOL AskPin(__out PWSTR szPin, __in PWSTR szReader,__in PWSTR szCard)
{

	CREDUI_INFO credUiInfo;
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.pszCaptionText = TEXT("test");
	credUiInfo.pszMessageText = TEXT("test");
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;
	ULONG authPackage = 0xffffeb34;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	DWORD dwTotalSize;
	PKERB_CERTIFICATE_LOGON pRequest = NULL;
	TCHAR szContainer[] = TEXT("");
	TCHAR szProvider[256];
	DWORD dwProviderNameLen = ARRAYSIZE(szProvider);
	BOOL fReturn = FALSE;
	SCARDCONTEXT hSCardContext = NULL;
	SCARDHANDLE hCard = NULL;
	LONG lCardStatus;
	DWORD dwError = 0;
	PBYTE pbAtr = NULL;
	DWORD dwAtrSize = SCARD_AUTOALLOCATE;
	SCARD_READERSTATE state;
	__try
	{
		if (!SchGetProviderNameFromCardName(szCard, szProvider, &dwProviderNameLen))
		{
			dwError = GetLastError();
			__leave;
		}
		// get provider name
	
		lCardStatus = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&hSCardContext);
		if (SCARD_S_SUCCESS != lCardStatus)
		{
			dwError = lCardStatus;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext 0x%08x",lCardStatus);
			__leave;
		}
		
		memset(&state,0,sizeof(SCARD_READERSTATE));
		state.szReader = szReader;
		state.dwCurrentState = SCARD_STATE_UNAWARE;
		lCardStatus = SCardGetStatusChange(hSCardContext, 0, &state, 1);
		if (SCARD_S_SUCCESS != lCardStatus)
		{
			dwError = lCardStatus;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardConnect 0x%08x",lCardStatus);
			__leave;
		}
		DWORD dwCspBufferLength = (DWORD) (wcslen(szCard)+1
						+ wcslen(szContainer)+1
						+ wcslen(szProvider)+1
						+ wcslen(szReader)+1);
		DWORD dwCspDataLength = sizeof(KERB_SMARTCARD_CSP_INFO)
						+ (dwCspBufferLength) * sizeof(WCHAR);
		dwTotalSize = (DWORD) (sizeof(KERB_CERTIFICATE_LOGON) 
						+ dwCspDataLength);
    
		pRequest = (PKERB_CERTIFICATE_LOGON) EIDAlloc(dwTotalSize);
		if (!pRequest)
		{
			dwError = GetLastError();
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
			__leave;
		}
		memset(pRequest, 0, dwTotalSize);
		pRequest->MessageType = KerbCertificateUnlockLogon;
		PVOID pPointer = (PUCHAR) pRequest + sizeof(KERB_CERTIFICATE_LOGON);
		pRequest->CspDataLength = dwCspDataLength;
		pRequest->CspData = (PUCHAR) pPointer;
		PKERB_SMARTCARD_CSP_INFO pCspInfo = (PKERB_SMARTCARD_CSP_INFO) pPointer;
		pCspInfo->dwCspInfoLen = pRequest->CspDataLength;
		// CSPInfo + content
		pCspInfo->MessageType = 1;
		pCspInfo->flags = 0x1 | ((state.dwEventState >> 16)<<16);
		pCspInfo->nCardNameOffset = 0;
		pCspInfo->nReaderNameOffset = (DWORD) (pCspInfo->nCardNameOffset + wcslen(szCard) + 1 );
		pCspInfo->nContainerNameOffset = (DWORD) (pCspInfo->nReaderNameOffset + wcslen(szReader) + 1 );
		pCspInfo->nCSPNameOffset = (DWORD) (pCspInfo->nContainerNameOffset + wcslen(szContainer) + 1 );
		wcscpy_s(&pCspInfo->bBuffer + pCspInfo->nCardNameOffset , dwCspBufferLength  - pCspInfo->nCardNameOffset, szCard);
		wcscpy_s(&pCspInfo->bBuffer + pCspInfo->nReaderNameOffset ,dwCspBufferLength  - pCspInfo->nReaderNameOffset, szReader);
		wcscpy_s(&pCspInfo->bBuffer + pCspInfo->nContainerNameOffset ,dwCspBufferLength  - pCspInfo->nContainerNameOffset, szContainer);
		wcscpy_s(&pCspInfo->bBuffer + pCspInfo->nCSPNameOffset , dwCspBufferLength  - pCspInfo->nCSPNameOffset, szProvider);	
		pRequest->CspData = (pRequest->CspData - (ULONG_PTR) pRequest);
		// sucess !
		

		CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 
		DWORD result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
						pRequest, dwTotalSize, &authBuffer, &authBufferSize, NULL, CREDUIWIN_IN_CRED_ONLY);
		if (result != ERROR_SUCCESS)
		{
			dwError = result;
			__leave;
		}
		PKERB_CERTIFICATE_LOGON output = (PKERB_CERTIFICATE_LOGON) authBuffer;
		for (int i = 0; i< output->Pin.Length; i++)
		{
			szPin[i] = (CHAR) *((PBYTE) output + (DWORD) output->Pin.Buffer + i);
		}
		szPin[output->Pin.Length]=0;
		fReturn = TRUE;
	}
	__finally
	{
		if (pRequest) EIDFree(pRequest);
		if (authBuffer) CoTaskMemFree(authBuffer);
		if (pbAtr) SCardFreeMemory(hSCardContext, pbAtr);
		if (hCard) SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		if (hSCardContext)	SCardReleaseContext(hSCardContext);

	}
	SetLastError(dwError);
	return fReturn;
}

BOOL AskPassword(WCHAR* Pin)
{
	PinBuffer = Pin;

	BOOL fStatus = (DialogBox(hInst, MAKEINTRESOURCE(IDD_PASSWORD), hMainWnd, (DLGPROC)GoToProcPin)>0);
	return fStatus;
}


class CMyCertificate
{
public:
	CMyCertificate(CContainer* pContainer)
	{
		_pContainer = pContainer;
	}

	virtual ~CMyCertificate()
	{
		if (_pContainer)
		{
			delete _pContainer;
		}
	}
	void Release()
	{
		delete this;
	}
	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags){return S_OK;}
	CContainer* GetContainer()
	{
		return _pContainer;
	}
private:
	CContainer* _pContainer;
};

PCCERT_CONTEXT SelectCert(__in LPCWSTR szReader,__in LPCWSTR szCard)
{
	HCERTSTORE hStore = NULL;
	PCCERT_CONTEXT pReturnedContext = NULL, pSelectedContext = NULL;
	CContainerHolderFactory<CMyCertificate> MyCertificateList;
	MyCertificateList.SetUsageScenario(CPUS_INVALID, 0);
	MyCertificateList.ConnectNotification(szReader,szCard,0);
	if (!MyCertificateList.HasContainerHolder())
	{
		goto cleanup;
	}
	//create a certificate store in memory
	hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
				X509_ASN_ENCODING,
				NULL,
				0,
				NULL);

	if (!hStore)
	{
		goto cleanup;
	}

	//add the certificate contexts to this store
	for (DWORD i=0; i < MyCertificateList.ContainerHolderCount(); i++)
	{
		CContainer* container = MyCertificateList.GetContainerHolderAt(i)->GetContainer();
		PCCERT_CONTEXT pCertContext = container->GetCertificate();
		// see remark in CertAddCertificateContextToStore
		// the certificate is cloned, and the reference count is not changed
		if (!CertAddCertificateContextToStore( hStore,
				pCertContext,
				CERT_STORE_ADD_ALWAYS,
				NULL) )
		{
			goto cleanup;
		}
		CertFreeCertificateContext(pCertContext);
	}
			
	pSelectedContext = CryptUIDlgSelectCertificateFromStore(hStore, NULL, NULL, NULL,CRYPTUI_SELECT_LOCATION_COLUMN,0, NULL);
	if (!pSelectedContext) goto cleanup;
	// match certificate
	// note : we are doing this to preservate the CERT_KEY_PROV_HANDLE_PROP_ID and CERT_KEY_CONTEXT_PROP_ID properties
	for (DWORD i=0; i < MyCertificateList.ContainerHolderCount(); i++)
	{
		CContainer* container = MyCertificateList.GetContainerHolderAt(i)->GetContainer();
		PCCERT_CONTEXT pCertContext = container->GetCertificate();
		if (CertCompareCertificate(X509_ASN_ENCODING,pSelectedContext->pCertInfo,
			pCertContext->pCertInfo))
		{
			pReturnedContext = pCertContext;
			// found
			break;
		//true
		}
		CertFreeCertificateContext(pCertContext);
	}
cleanup:
	if (pSelectedContext) 
		CertFreeCertificateContext(pSelectedContext);
	if (hStore) 
		CertCloseStore(hStore,0);
	MyCertificateList.DisconnectNotification(szReader);
	return pReturnedContext;
}
/*
PCCERT_CONTEXT SelectCerts(__in LPCWSTR szReaderName,__in LPCWSTR szCardName, 
				__out LPWSTR szOutProviderName,__in DWORD dwOutProviderLength,
				__out LPWSTR szOutContainerName,__in DWORD dwOutContainerLength,
				__in_opt PDWORD pdwKeySpec)
{
	HCRYPTPROV HMainCryptProv = NULL;
	BOOL bStatus = FALSE;
	LPTSTR szMainContainerName = NULL;
	CHAR szContainerName[1024];
	DWORD dwContainerNameLen = sizeof(szContainerName);
	DWORD dwErr = 0;
	DWORD dwFlags = CRYPT_FIRST;
	PCCERT_CONTEXT pContextArray[128];
	LPWSTR pContainerName[128];
	DWORD dwKeySpecs[128];
	DWORD dwContextArrayLen = 0;
	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	LPBYTE pbCert = NULL;
	DWORD dwCertLen = 0;
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD pKeySpecs[2] = { AT_KEYEXCHANGE,AT_SIGNATURE};
	PCCERT_CONTEXT pSelectedContext = NULL;
	HCERTSTORE hStore = NULL;
	szOutContainerName[0]=0;

	__try
	{
		if (!SchGetProviderNameFromCardName(szCardName, szOutProviderName, &dwOutProviderLength))
		{
			return NULL;
		}

		size_t ulNameLen = _tcslen(szReaderName);
		szMainContainerName = (LPWSTR) EIDAlloc((DWORD)(ulNameLen + 6) * sizeof(WCHAR));
		if (!szMainContainerName)
		{
			return NULL;
		}
		swprintf_s(szMainContainerName,(ulNameLen + 6), L"\\\\.\\%s\\", szReaderName);

		bStatus = CryptAcquireContext(&HMainCryptProv,
					szMainContainerName,
					szOutProviderName,
					PROV_RSA_FULL,
					CRYPT_SILENT);
		if (!bStatus)
		{
			dwErr = GetLastError();
			if (dwErr == NTE_BAD_KEYSET)
			{
				bStatus = CryptAcquireContext(&HMainCryptProv,NULL,	szOutProviderName,	PROV_RSA_FULL,	CRYPT_SILENT);
				if (!bStatus)
				{
					dwErr = GetLastError();
					if (dwErr == NTE_BAD_KEYSET)
					{
						MessageBox(NULL,L"No certificate on the card",L"",0);
						__leave;
					}
					else
					{
						MessageBoxWin32(dwErr);
						__leave;
					}
				}
			}
			else
			{
				MessageBoxWin32(dwErr);
				__leave;
			}
				
		}



		// Enumerate all the containers 
		while (CryptGetProvParam(HMainCryptProv,
					PP_ENUMCONTAINERS,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					dwFlags) &&
				(dwContextArrayLen < 128)
				)
		{

			if (szContainerName[0] == '\\' && szContainerName[0] == '\\')
			{
				dwContainerNameLen = sizeof(szContainerName);
				if (!CryptGetProvParam(HMainCryptProv,
					PP_CONTAINER,
					(LPBYTE) szContainerName,
					&dwContainerNameLen,
					0))
				{

				}
			}
			// convert the container name to unicode
			int wLen = MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, NULL, 0);
			LPWSTR szWideContainerName = (LPWSTR) EIDAlloc(wLen * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, szContainerName, -1, szWideContainerName, wLen);

			// Acquire a context on the current container
			if (CryptAcquireContext(&hProv,
					szWideContainerName,
					szOutProviderName,
					PROV_RSA_FULL,
					0))
			{
				// Loop over all the key specs
				for (int i = 0; i < 2; i++)
				{
					if (CryptGetUserKey(hProv,
							pKeySpecs[i],
							&hKey) )
					{
						if (CryptGetKeyParam(hKey,
								KP_CERTIFICATE,
								NULL,
								&dwCertLen,
								0))
						{
							pbCert = (LPBYTE) EIDAlloc(dwCertLen);
							if (!pbCert)
							{
								dwErr = GetLastError();
								__leave;
							}
							if (CryptGetKeyParam(hKey,
										KP_CERTIFICATE,
										pbCert,
										&dwCertLen,
										0))
							{
								pCertContext = CertCreateCertificateContext(
												X509_ASN_ENCODING, 
												pbCert,
												dwCertLen);
								if (pCertContext)
								{
									pContextArray[dwContextArrayLen] = pCertContext;
									pContainerName[dwContextArrayLen] = (LPWSTR) EIDAlloc(wLen * sizeof(WCHAR));
									dwKeySpecs[dwContextArrayLen] = pKeySpecs[i];
									memcpy((PVOID)pContainerName[dwContextArrayLen],szWideContainerName, wLen * sizeof(WCHAR));
									dwContextArrayLen++;
									CRYPT_KEY_PROV_INFO keyProvInfo;
									keyProvInfo.pwszProvName = szOutProviderName;
									keyProvInfo.dwKeySpec = pKeySpecs[i];
									keyProvInfo.dwProvType = PROV_RSA_FULL;
									keyProvInfo.pwszContainerName = szWideContainerName;
									keyProvInfo.cProvParam = 0;
									keyProvInfo.rgProvParam = NULL;
									keyProvInfo.dwFlags = 0;
									CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo);
								}
							}
							EIDFree(pbCert);
							pbCert = NULL;
						}
						CryptDestroyKey(hKey);
						hKey = NULL;
					}
				}
				CryptReleaseContext(hProv, 0);
				hProv = NULL;
			}
			EIDFree(szWideContainerName);
				
			// prepare parameters for the next loop
			dwContainerNameLen = sizeof(szContainerName);
			dwFlags = 0;
		}

		if (dwFlags == CRYPT_FIRST) 
		{
			// the default container can be enumerated but PP_ENUMCONTAINERS doesn't work
			// find the name of the default container
			CHAR szDefautContainerName[1024];
			WCHAR wszDefautContainerName[1024];
			DWORD dwSize = ARRAYSIZE(szDefautContainerName);
			if (CryptGetProvParam(HMainCryptProv,PP_CONTAINER,(PBYTE) szDefautContainerName, &dwSize, 0))
			{
				MultiByteToWideChar(CP_ACP, 0, szDefautContainerName, -1, wszDefautContainerName, ARRAYSIZE(szDefautContainerName));
			}
			else
			{
				wcscpy_s(wszDefautContainerName, ARRAYSIZE(wszDefautContainerName), szMainContainerName);
			}

			for (DWORD i = 0; i < 2; i++)
			{
				if (CryptGetUserKey(HMainCryptProv,
						pKeySpecs[i],
						&hKey) )
				{
					if (CryptGetKeyParam(hKey,
							KP_CERTIFICATE,
							NULL,
							&dwCertLen,
							0))
					{
						pbCert = (LPBYTE) EIDAlloc(dwCertLen);
						if (!pbCert)
						{
							dwErr = GetLastError();
							__leave;
						}
						if (CryptGetKeyParam(hKey,
									KP_CERTIFICATE,
									pbCert,
									&dwCertLen,
									0))
						{
							pCertContext = CertCreateCertificateContext(
											X509_ASN_ENCODING, 
											pbCert,
											dwCertLen);
							if (pCertContext)
							{
								pContextArray[dwContextArrayLen] = pCertContext;
								pContainerName[dwContextArrayLen] = (LPWSTR) EIDAlloc((DWORD)(wcslen(wszDefautContainerName)+1) * sizeof(WCHAR));
								dwKeySpecs[dwContextArrayLen] = pKeySpecs[i];
								memcpy((PVOID)pContainerName[dwContextArrayLen],wszDefautContainerName, (wcslen(wszDefautContainerName)+1) * sizeof(WCHAR));
								dwContextArrayLen++;
								CRYPT_KEY_PROV_INFO keyProvInfo;
								keyProvInfo.pwszProvName = szOutProviderName;
								keyProvInfo.dwKeySpec = pKeySpecs[i];
								keyProvInfo.dwProvType = PROV_RSA_FULL;
								keyProvInfo.pwszContainerName = wszDefautContainerName;
								keyProvInfo.cProvParam = 0;
								keyProvInfo.rgProvParam = NULL;
								keyProvInfo.dwFlags = 0;
								CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo);
							}
						}
						EIDFree(pbCert);
						pbCert = NULL;
					}
					CryptDestroyKey(hKey);
					hKey = NULL;
				}
			}
		}

		if (dwContextArrayLen == 0) 
		{
			MessageBox(NULL,L"No certificate contexts found on card. However the card is not empty",L"",0);
			dwErr = 1;
		}
		else
		{
			
			//create a certificate store in memory
			hStore = CertOpenStore(CERT_STORE_PROV_MEMORY,
						X509_ASN_ENCODING,
						NULL,
						0,
						NULL);

			if (!hStore)
			{
				dwErr = GetLastError();
				printf("CertOpenStore failed with error 0x%.8X\n",dwErr);
				__leave;
			}

			//add the certificate contexts to this store
			for (DWORD i=0; i < dwContextArrayLen; i++)
			{
				if (!CertAddCertificateContextToStore( hStore,
						pContextArray[i],
						CERT_STORE_ADD_ALWAYS,
						NULL) )
				{
					dwErr = GetLastError();
					printf("CertAddCertificateContextToStore failed with error 0x%.8X\n", dwErr);
					__leave;
				}
			}
			
			if((pSelectedContext = CryptUIDlgSelectCertificateFromStore(
				hStore, NULL, NULL, NULL,CRYPTUI_SELECT_LOCATION_COLUMN,0, NULL)))
			{
				// match certificate
				for (DWORD i=0; i < dwContextArrayLen; i++)
				{
					if (CertCompareCertificate(X509_ASN_ENCODING,pSelectedContext->pCertInfo,
						pContextArray[i]->pCertInfo))
					{
						wcscpy_s(szOutContainerName,dwOutContainerLength,pContainerName[i]);
						if (pdwKeySpec) *pdwKeySpec = dwKeySpecs[i];
						break;
					//true
					}
				}
			}
		}
	}
	__finally
	{
		if (hStore) 
			CertCloseStore(hStore,0);
		for (DWORD i=0; i < dwContextArrayLen; i++)
		{
			CertFreeCertificateContext(pContextArray[i]);
			EIDFree(pContainerName[i]);
		}
		if (hKey)
			CryptDestroyKey(hKey);
		if (hProv)
			CryptReleaseContext(hProv, 0);
		if (szMainContainerName)
			EIDFree(szMainContainerName);
		if (HMainCryptProv)
			CryptReleaseContext(HMainCryptProv, 0);
		if (szOutContainerName[0]==0 && dwErr == 0) dwErr = 1;
	}
	return pSelectedContext;
}
*/
PUI_CERTIFICATE_INFO _pCertificateInfo;

void FreeCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo);

static BOOL CALLBACK SelectCertificateInfoCallBack(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
	SYSTEMTIME systemTime;
	DWORD dwSize;
    switch (message) 
    { 
        case WM_INITDIALOG: 
			
			//default
			CheckDlgButton(hwndDlg,IDC_ATSIGN,BST_CHECKED);
			CheckDlgButton(hwndDlg,IDC_SELFSIGNED,BST_CHECKED);
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_ADDSTRING,0,(LPARAM) _T("On User Store"));
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_ADDSTRING,0,(LPARAM) _T("On Machine Store"));
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_ADDSTRING,0,(LPARAM) _T("On Machine Store : My Certificates"));
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_ADDSTRING,0,(LPARAM) _T("On File"));
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_ADDSTRING,0,(LPARAM) _T("On Smart Card"));
			SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_SETCURSEL, 0, 0);
			SendDlgItemMessage(hwndDlg,IDC_KEYSIZE,CB_ADDSTRING,0,(LPARAM) _T("1024"));
			SendDlgItemMessage(hwndDlg,IDC_KEYSIZE,CB_ADDSTRING,0,(LPARAM) _T("2048"));
			SendDlgItemMessage(hwndDlg,IDC_KEYSIZE,CB_SETCURSEL, 0, 0);
			// set system date
			GetSystemTime(&systemTime);
			SendDlgItemMessage(hwndDlg,IDC_DTP1,DTM_SETSYSTEMTIME, 0, (LPARAM) &systemTime);
			systemTime.wYear += 5;
			SendDlgItemMessage(hwndDlg,IDC_DTP2,DTM_SETSYSTEMTIME, 0, (LPARAM) &systemTime);
// Forme = SendDlgItemMessage(hDlg, ID_CB1, CB_GETCURSEL, 0, 0);

			SetDlgItemText(hwndDlg,IDC_SUBJECT,_T("CN="));
			SetFocus(GetDlgItem(hwndDlg,IDC_SUBJECT));
            return TRUE; 
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
                // save or cancel
				/////////////////
				case IDC_OK: 
					if (IsDlgButtonChecked(hwndDlg,IDC_ATKEY))
					{
						_pCertificateInfo->dwKeyType = AT_KEYEXCHANGE;
					}
					else
					{
						_pCertificateInfo->dwKeyType = AT_SIGNATURE;
					}
					dwSize = 256;
					_pCertificateInfo->szSubject = (LPTSTR) EIDAlloc(dwSize*sizeof(TCHAR));
					GetDlgItemText(hwndDlg,IDC_SUBJECT,_pCertificateInfo->szSubject,dwSize);
					switch ((DWORD) SendDlgItemMessage(hwndDlg,IDC_KEYSIZE,CB_GETCURSEL, 0, 0))
					{
					case 0:
					default:
						_pCertificateInfo->dwKeySizeInBits = 1024;
						break;
					case 1:
						_pCertificateInfo->dwKeySizeInBits = 2048;
						break;
					}
					_pCertificateInfo->dwSaveon = (DWORD) SendDlgItemMessage(hwndDlg,IDC_SAVEON,CB_GETCURSEL, 0, 0);
					_pCertificateInfo->bIsSelfSigned = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_SELFSIGNED);
					_pCertificateInfo->bHasSmartCardAuthentication = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_SCAUTH);
					_pCertificateInfo->bHasServerAuthentication = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_SERVERAUTH);
					_pCertificateInfo->bHasClientAuthentication = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_CLIENTAUTH);
					_pCertificateInfo->bHasEFS = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_EFS);
					_pCertificateInfo->bIsCA = (BOOL) IsDlgButtonChecked(hwndDlg,IDC_CA);
					SendDlgItemMessage(hwndDlg,IDC_DTP1,DTM_GETSYSTEMTIME, 0, (LPARAM) &_pCertificateInfo->StartTime);
					SendDlgItemMessage(hwndDlg,IDC_DTP2,DTM_GETSYSTEMTIME, 0, (LPARAM) &_pCertificateInfo->EndTime);
					EndDialog(hwndDlg,1); 
                    return TRUE; 
				case IDC_Cancel: 
					// free what need to be free
					FreeCertificateInfo(_pCertificateInfo);
					EndDialog(hwndDlg,0); 
					return TRUE; 

				// select if certificate is self signed or signed with trusted cert
				///////////////////////////////////////////////////////////////////
				case IDC_SELFSIGNED:
					if (HIWORD(wParam) == BN_CLICKED) {
						SendDlgItemMessage(hwndDlg,IDC_DTP2, BCM_SETSHIELD, 0, (LPARAM)FALSE);
						// forget previous selected certificate
						if (_pCertificateInfo->pRootCertificate)
						{
							CertFreeCertificateContext(_pCertificateInfo->pRootCertificate);
							_pCertificateInfo->pRootCertificate = NULL;
						}
					}
					break;
				case IDC_SIGNEDBY:
					if ((HIWORD(wParam) == BN_CLICKED) &&
						!_pCertificateInfo->pRootCertificate)
					{
						SendDlgItemMessage(hwndDlg,IDC_DTP2, BCM_SETSHIELD, 0, (LPARAM)TRUE);
						// click on select certificate
						// => don't break and continue on IDC_SELECTROOT
					}
					else
					{
						break;
					}
				case IDC_SELECTROOT:
					CheckDlgButton(hwndDlg,IDC_SELFSIGNED,0);
					CheckDlgButton(hwndDlg,IDC_SIGNEDBY,BST_CHECKED);						
					_pCertificateInfo->pRootCertificate = SelectCertificateWithPrivateKey();
					if (_pCertificateInfo->pRootCertificate)
					{
						CheckDlgButton(hwndDlg,IDC_SELFSIGNED,0);
						CheckDlgButton(hwndDlg,IDC_SIGNEDBY,BST_CHECKED);	
						CheckDlgButton(hwndDlg,IDC_ATKEY,BST_CHECKED);
						CheckDlgButton(hwndDlg,IDC_ATSIGN,0);
					}
					else
					{
						CheckDlgButton(hwndDlg,IDC_SELFSIGNED,BST_CHECKED);
						CheckDlgButton(hwndDlg,IDC_SIGNEDBY,0);
						CheckDlgButton(hwndDlg,IDC_ATKEY,0);
						CheckDlgButton(hwndDlg,IDC_ATSIGN,BST_CHECKED);

					}

				default:
					return FALSE;
	        } 
			return FALSE;
		default:
			return FALSE;
    } 
    return FALSE; 
} 

DWORD SelectCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo) 
{
	DWORD dwStatus = -1;
	_pCertificateInfo = pCertificateInfo;
	_pCertificateInfo->pRootCertificate = NULL;
	dwStatus = (DWORD) DialogBox(hInst, MAKEINTRESOURCE(IDD_CERTIFICATE), hMainWnd, (DLGPROC)SelectCertificateInfoCallBack);
	// cancel or error => return
	if (!dwStatus) return 0;



	return dwStatus;
}

void FreeCertificateInfo(PUI_CERTIFICATE_INFO pCertificateInfo)
{
	if (pCertificateInfo->szSubject)
	{
		EIDFree(pCertificateInfo->szSubject);
		pCertificateInfo->szSubject = NULL;
	}
	if (pCertificateInfo->pRootCertificate)
	{
		CertFreeCertificateContext(pCertificateInfo->pRootCertificate);
		pCertificateInfo->pRootCertificate = NULL;
	}
}


typedef void (TracingWindowsCallback)(void);

TracingWindowsCallback *onDestroy;
HANDLE hThread;
HWND hTracing;
HANDLE hEvent;

static BOOL CALLBACK TracingCallBack(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{
    switch (message) 
    { 
        case WM_INITDIALOG: 
			return TRUE;
        case WM_SIZE:
			            MoveWindow(GetDlgItem(hwndDlg, IDC_TRACE), 
                       0, 0,                  // starting x- and y-coordinates 
                       LOWORD(lParam),        // width of client area 
                       HIWORD(lParam),        // height of client area 
                       TRUE);  
			//SendDlgItemMessage(hwndDlg, IDC_TRACE, WM_SIZE, wParam, lParam);
			break;
		case WM_CLOSE:
			DestroyWindow(hwndDlg);
			(*onDestroy)();
			return TRUE;
		case WM_DESTROY:
			TerminateThread(hThread, 0);
			return TRUE;
	}
	return FALSE; 
}

DWORD WINAPI WindowThreadTracing(LPVOID lpParameter) 
{
	MSG Msg;
	hTracing = CreateDialog(hInst, MAKEINTRESOURCE(IDD_TRACE), hMainWnd, (DLGPROC)TracingCallBack);
	if (hTracing) 
	{
		ShowWindow(hTracing, SW_SHOW);
	}
	SetEvent(hEvent);
	while(GetMessage(&Msg, NULL, 0, 0))
    {
        if(!IsDialogMessage(hTracing, &Msg))
        {
            TranslateMessage(&Msg);
            DispatchMessage(&Msg);
        }
    }
	return 0;
}

HWND CreateDialogTracing(TracingWindowsCallback *ponDestroy)
{
	onDestroy = ponDestroy;
	hEvent = CreateEvent(NULL,FALSE,FALSE,NULL);
	hThread = CreateThread(NULL, 0, WindowThreadTracing, NULL, 0, NULL);
	WaitForSingleObject(hEvent, INFINITE);
	return hTracing;
}

BOOL DisplayTrace(HWND hTracingWindow, PCTSTR szMessage)
{
	SendDlgItemMessage(hTracingWindow, IDC_TRACE, EM_SETSEL, -1, 0);
	SendDlgItemMessage(hTracingWindow, IDC_TRACE, EM_LINESCROLL, 0, -1);
	SendDlgItemMessage(hTracingWindow, IDC_TRACE, EM_SCROLLCARET, 0, 0);
	SendDlgItemMessage(hTracingWindow, IDC_TRACE, EM_REPLACESEL, FALSE, (LPARAM)szMessage);
	//SendDlgItemMessage(hTracingWindow, IDC_TRACE, EM_REPLACESEL, FALSE, (LPARAM)TEXT("\r\n"));
	return TRUE;
}

VOID menu_UTIL_DisplayCSPInfoFromUserCertificate()
{
	PCCERT_CONTEXT returnedContext = NULL;
	TCHAR szCertName[1024] = TEXT("");
	TCHAR szComputerName[257];
	DWORD dwSize = ARRAYSIZE(szComputerName);
	HCERTSTORE hCertStore = NULL;
	GetComputerName(szComputerName,&dwSize);
	// open trusted root store
	hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,0,NULL,CERT_SYSTEM_STORE_CURRENT_USER,_T("My"));
	if (hCertStore)
	{
		PCCERT_CONTEXT pCertContext = NULL;
		pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		while (pCertContext)
		{
			
			// get the subject details for the cert
			CertGetNameString(pCertContext,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,szCertName,ARRAYSIZE(szCertName));
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"szCertName %s",szCertName);
			PCRYPT_KEY_PROV_INFO info = NULL;
			dwSize = 0;
			if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,(PBYTE) info,&dwSize))
			{
				info = (PCRYPT_KEY_PROV_INFO) EIDAlloc(dwSize);
				if (CertGetCertificateContextProperty(pCertContext,CERT_KEY_PROV_INFO_PROP_ID,(PBYTE) info,&dwSize))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Container %s CSP %s flag %d",info->pwszContainerName, info->pwszProvName, info->dwFlags);
				}
			}
			pCertContext = CertEnumCertificatesInStore(hCertStore,pCertContext);
		}
		CertCloseStore(hCertStore,0);
	}
} 