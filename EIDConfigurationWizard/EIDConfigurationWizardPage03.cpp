#include <windows.h>
#include <tchar.h>
#include <Cryptuiapi.h>
#include <shobjidl.h>
#include "global.h"
#include "EIDConfigurationWizard.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/Tracing.h"

// used to know what root certicate we are refering
// null = unknown
PCCERT_CONTEXT pRootCertificate = NULL;

BOOL SelectFile(HWND hWnd)
{
	// select file to open
	PWSTR szFileName = NULL;
	TCHAR szSpecContainer[256] = TEXT("");
	TCHAR szSpecAll[256] = TEXT("");
	LoadString(g_hinst,IDS_03CONTAINERFILES,szSpecContainer,ARRAYSIZE(szSpecContainer));
	LoadString(g_hinst,IDS_03ALLFILES,szSpecAll,ARRAYSIZE(szSpecAll));
	/*IFileDialog *pfd;
	COMDLG_FILTERSPEC rgSpec[] =
	{ 
		{ szSpecContainer, L"*.pfx;*.p12" },
		{ szSpecAll, L"*.*" },
	};
    CoInitialize(NULL);
    // CoCreate the dialog object.
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, 
                                  NULL, 
                                  CLSCTX_INPROC_SERVER, 
								  IID_IFileDialog,
                                  (void**)&pfd);
    
    if (SUCCEEDED(hr))
    {
		pfd->SetFileTypes(ARRAYSIZE(rgSpec), rgSpec);
		// Show the dialog
        hr = pfd->Show(hWnd);
        
        if (SUCCEEDED(hr))
        {
            // Obtain the result of the user's interaction with the dialog.
            IShellItem *psiResult;
            hr = pfd->GetResult(&psiResult);
            
            if (SUCCEEDED(hr))
            {
				hr = psiResult->GetDisplayName( SIGDN_FILESYSPATH, &szFileName);
				if (SUCCEEDED(hr))
				{
					SetWindowText(GetDlgItem(hWnd,IDC_03FILENAME),szFileName);
					CoTaskMemFree(szFileName);
					CheckDlgButton(hWnd,IDC_03IMPORT,BST_CHECKED);
					CheckDlgButton(hWnd,IDC_03USETHIS,BST_UNCHECKED);
					CheckDlgButton(hWnd,IDC_03_CREATE,BST_UNCHECKED);
				}
                psiResult->Release();
            }
        }
        pfd->Release();
    }
    return SUCCEEDED(hr);*/
	OPENFILENAME ofn;
	TCHAR szFile[MAX_PATH], szFilter[256];
	_stprintf_s(szFilter, 256, TEXT("%s%c*.pfx;*.p12%c%s%c*.*%c"),szSpecContainer,0,0,szSpecAll,0,0);
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(ofn);
	ofn.hwndOwner = hWnd;
	ofn.lpstrFile = szFile;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFile);
	ofn.lpstrFilter = szFilter;
	ofn.nFilterIndex = 1;
	ofn.lpstrFileTitle = NULL;
	ofn.nMaxFileTitle = 0;
	ofn.lpstrInitialDir = NULL;
	ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (GetOpenFileName(&ofn)==TRUE) 
	{
		SetWindowText(GetDlgItem(hWnd,IDC_03FILENAME),szFile);
		CheckDlgButton(hWnd,IDC_03IMPORT,BST_CHECKED);
		CheckDlgButton(hWnd,IDC_03USETHIS,BST_UNCHECKED);
		CheckDlgButton(hWnd,IDC_03_CREATE,BST_UNCHECKED);
		return TRUE;
	}
	return FALSE;
}

BOOL CreateRootCertificate()
{
	BOOL fReturn;
	TCHAR szComputerName[MAX_COMPUTERNAME_LENGTH + 1 ];
	TCHAR szSubject[MAX_COMPUTERNAME_LENGTH + 4];
	DWORD dwSize = ARRAYSIZE(szComputerName);
	GetComputerName(szComputerName, &dwSize);
	_stprintf_s(szSubject,ARRAYSIZE(szSubject),TEXT("CN=%s"),szComputerName);
	UI_CERTIFICATE_INFO CertificateInfo;
	memset(&CertificateInfo, 0, sizeof(CertificateInfo));
	CertificateInfo.dwSaveon = UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE;
	CertificateInfo.dwKeyType = AT_SIGNATURE;
	CertificateInfo.bIsSelfSigned = TRUE;
	CertificateInfo.bHasSmartCardAuthentication = TRUE;
	CertificateInfo.bIsCA = TRUE;
	GetSystemTime(&(CertificateInfo.StartTime));
	GetSystemTime(&(CertificateInfo.EndTime));
	CertificateInfo.EndTime.wYear += 10;
	CertificateInfo.fReturnCerticateContext = TRUE;
	CertificateInfo.szSubject = szSubject;
	fReturn = CreateCertificate(&CertificateInfo);
	DWORD dwError = GetLastError();
	if (fReturn)
	{
		pRootCertificate = CertificateInfo.pNewCertificate;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCertificate 0x%08X", dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

BOOL CreateSmartCardCertificate(PCCERT_CONTEXT pCertificate, PWSTR szReader, PWSTR szCard)
{
	BOOL fReturn;
	UI_CERTIFICATE_INFO CertificateInfo;
	TCHAR szSubject[256];
	_stprintf_s(szSubject,ARRAYSIZE(szSubject),TEXT("CN=%s"),szUserName);
	memset(&CertificateInfo, 0, sizeof(CertificateInfo));
	CertificateInfo.dwSaveon = UI_CERTIFICATE_INFO_SAVEON_SMARTCARD;
	CertificateInfo.szReader = szReader;
	CertificateInfo.szCard = szCard;
	CertificateInfo.dwKeyType = AT_KEYEXCHANGE;
	CertificateInfo.bHasSmartCardAuthentication = TRUE;
	CertificateInfo.pRootCertificate = pCertificate;
	CertificateInfo.szSubject = szSubject;
	GetSystemTime(&(CertificateInfo.StartTime));
	GetSystemTime(&(CertificateInfo.EndTime));
	CertificateInfo.EndTime.wYear += 10;
	fReturn = CreateCertificate(&CertificateInfo);
	DWORD dwError = GetLastError();
	if (fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OK");
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateCertificate 0x%08X", dwError);
	}
	SetLastError(dwError);
	return fReturn;
}

VOID UpdateCertificatePanel(HWND hWnd)
{
	TCHAR szBuffer[1024];
	TCHAR szBuffer2[1024];
	TCHAR szMessage[256] = TEXT("");
	TCHAR szLocalDate[255], szLocalTime[255];
	SYSTEMTIME st;
	SendDlgItemMessage(hWnd,IDC_03CERTIFICATEPANEL,LB_RESETCONTENT,0,0);
	// object : 
	CertGetNameString(pRootCertificate,CERT_NAME_SIMPLE_DISPLAY_TYPE,0,NULL,szBuffer2,ARRAYSIZE(szBuffer2));
	LoadString(g_hinst, IDS_03OBJECT, szMessage, ARRAYSIZE(szMessage));
	_stprintf_s(szBuffer, ARRAYSIZE(szBuffer), szMessage,  szBuffer2);
	SendDlgItemMessage(hWnd,IDC_03CERTIFICATEPANEL,LB_ADDSTRING,0,(LPARAM) szBuffer);
	// delivered :
	FileTimeToSystemTime( &(pRootCertificate->pCertInfo->NotBefore), &st );
	GetDateFormat( LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL, szLocalDate, ARRAYSIZE(szLocalDate));
    GetTimeFormat( LOCALE_USER_DEFAULT, 0, &st, NULL, szLocalTime, ARRAYSIZE(szLocalTime) );

	LoadString(g_hinst, IDS_03DELIVERED, szMessage, ARRAYSIZE(szMessage));
	_stprintf_s(szBuffer, ARRAYSIZE(szBuffer), szMessage, szLocalDate, szLocalTime);
	SendDlgItemMessage(hWnd,IDC_03CERTIFICATEPANEL,LB_ADDSTRING,0,(LPARAM) szBuffer);

	// expires :
	FileTimeToSystemTime( &(pRootCertificate->pCertInfo->NotAfter), &st );
	GetDateFormat( LOCALE_USER_DEFAULT, DATE_LONGDATE, &st, NULL, szLocalDate, ARRAYSIZE(szLocalDate));
    GetTimeFormat( LOCALE_USER_DEFAULT, 0, &st, NULL, szLocalTime, ARRAYSIZE(szLocalTime) );

	LoadString(g_hinst, IDS_03EXPIRES, szMessage, ARRAYSIZE(szMessage));
	_stprintf_s(szBuffer, ARRAYSIZE(szBuffer), szMessage, szLocalDate, szLocalTime);
	SendDlgItemMessage(hWnd,IDC_03CERTIFICATEPANEL,LB_ADDSTRING,0,(LPARAM) szBuffer);

	// select option
	CheckDlgButton(hWnd,IDC_03IMPORT,BST_UNCHECKED);
	CheckDlgButton(hWnd,IDC_03USETHIS,BST_CHECKED);
	CheckDlgButton(hWnd,IDC_03_CREATE,BST_UNCHECKED);
}

INT_PTR CALLBACK	WndProc_03NEW(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId;
	int wmEvent;
	LPNMHDR pnmh;
	CRYPTUI_VIEWCERTIFICATE_STRUCT certViewInfo;
	BOOL fPropertiesChanged = FALSE;
	switch(message)
	{
		case WM_NOTIFY :
        pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
				//this is an interior page
				PropSheet_SetWizButtons(hWnd, PSWIZB_BACK | PSWIZB_NEXT);
				if (pRootCertificate)
				{
					CertFreeCertificateContext(pRootCertificate);
					pRootCertificate = NULL;
				}
				pRootCertificate = SelectFirstCertificateWithPrivateKey();
				if (pRootCertificate)
				{
					CheckDlgButton(hWnd,IDC_03USETHIS,BST_CHECKED);
					UpdateCertificatePanel(hWnd);
				}
				else
				{
					CheckDlgButton(hWnd,IDC_03_CREATE,BST_CHECKED);
				}
				break;
			case PSN_WIZBACK:
				if (pRootCertificate)
				{
					CertFreeCertificateContext(pRootCertificate);
					pRootCertificate = NULL;
				}
				break;
			case PSN_WIZNEXT:
				if (IsDlgButtonChecked(hWnd,IDC_03DELETE))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IDC_03DELETE");
					// delete all data
					if (!ClearCard(szReader, szCard))
					{
						DWORD dwError = GetLastError();
						if (dwError != SCARD_W_CANCELLED_BY_USER)
							MessageBoxWin32Ex(dwError,hWnd);
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				if (IsDlgButtonChecked(hWnd,IDC_03_CREATE))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IDC_03_CREATE");
					// create self signed certificate as root
					DWORD dwReturn = -1;
					if (CreateRootCertificate())
					{
						if (CreateSmartCardCertificate(pRootCertificate, szReader, szCard))
						{
							//  OK
						}
						else
						{
							DWORD dwError = GetLastError();
							if (dwError != SCARD_W_CANCELLED_BY_USER)
								MessageBoxWin32Ex(dwError,hWnd);
							SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
							return TRUE;
						}
					}
					else
					{
						MessageBoxWin32Ex(GetLastError(),hWnd);
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
					// cancel
					break;
				}
				else if (IsDlgButtonChecked(hWnd,IDC_03USETHIS))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IDC_03USETHIS");
					if (!pRootCertificate)
					{
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
					if (!CreateSmartCardCertificate(pRootCertificate, szReader, szCard))
					{
						DWORD dwError = GetLastError();
						if (dwError != SCARD_W_CANCELLED_BY_USER)
							MessageBoxWin32Ex(dwError,hWnd);
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				else if (IsDlgButtonChecked(hWnd,IDC_03IMPORT))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"IDC_03IMPORT");
					TCHAR szFileName[1024] = TEXT("");
					TCHAR szPassword[1024] = TEXT("");
					GetWindowText(GetDlgItem(hWnd,IDC_03FILENAME),szFileName,ARRAYSIZE(szFileName));
					GetWindowText(GetDlgItem(hWnd,IDC_03IMPORTPASSWORD),szPassword,ARRAYSIZE(szPassword));
					if (!ImportFileToSmartCard(szFileName, szPassword, szReader, szCard))
					{
						MessageBoxWin32Ex(GetLastError(),hWnd);
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}

				}
				break;
		}
		break;
		case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{	
			case IDC_03SELECT:
				if (pRootCertificate)
				{
						CertFreeCertificateContext(pRootCertificate);
						pRootCertificate = NULL;
				}
				pRootCertificate = SelectCertificateWithPrivateKey(hWnd);
				if (pRootCertificate)
				{
					UpdateCertificatePanel(hWnd);
				}
				break;
			case IDC_03SHOW:
				if (pRootCertificate)
				{
					TCHAR szTitle[256] = TEXT("");
					LoadString(g_hinst, IDS_03CERTVIEWTITLE, szTitle, ARRAYSIZE(szTitle));
					certViewInfo.dwSize = sizeof(CRYPTUI_VIEWCERTIFICATE_STRUCT);
					certViewInfo.hwndParent = hWnd;
					certViewInfo.dwFlags = CRYPTUI_DISABLE_EDITPROPERTIES | CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EXPORT | CRYPTUI_DISABLE_HTMLLINK;
					certViewInfo.szTitle = szTitle;
					certViewInfo.pCertContext = pRootCertificate;
					certViewInfo.cPurposes = 0;
					certViewInfo.rgszPurposes = 0;
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

					CryptUIDlgViewCertificate(&certViewInfo,&fPropertiesChanged);
				}
				break;
			case IDC_03SELECTFILE:
				SelectFile(hWnd);
				break;
		}
		break;
    }
	return FALSE;
}