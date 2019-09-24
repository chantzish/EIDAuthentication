#include <windows.h>
#include <tchar.h>

#include "../EIDCardLibrary/Tracing.h"

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"

#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"
#include "CContainerHolderXP.h"

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
// selected credential
extern DWORD dwCurrentCredential;

extern BOOL PopulateListViewListData(HWND hWndListView);
extern BOOL InitListViewListIcon(HWND hWndListView);

extern BOOL fHasDeselected;

DWORD dwWizardError = 0;

BOOL WizardFinishButton(PTSTR szPassword)
{
	BOOL fReturn = FALSE;
	DWORD dwError = 0;
	
	CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
	CContainer* container = MyTest->GetContainer();
	PCCERT_CONTEXT pCertContext = container->GetCertificate();
	fReturn = LsaEIDCreateStoredCredential(szUserName, szPassword, pCertContext, container->GetKeySpec() == AT_KEYEXCHANGE);
	if (!fReturn)
	{
		dwError = GetLastError();
	}
	CertFreeCertificateContext(pCertContext);
	SetLastError(dwError);
	return fReturn;
}

BOOL TestLogon(HWND hMainWnd);

HWND hwndInvalidPasswordBalloon = NULL;
VOID ShowInvalidPasswordBalloon(HWND hWnd)
{
	if (hwndInvalidPasswordBalloon) 
	{ 
		DestroyWindow(hwndInvalidPasswordBalloon); 
		hwndInvalidPasswordBalloon = NULL; 
	}
	hwndInvalidPasswordBalloon = CreateWindowEx(NULL, TOOLTIPS_CLASS, NULL,
                            WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP | TTS_BALLOON | TTS_CLOSE,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            CW_USEDEFAULT, CW_USEDEFAULT,
                            hWnd, NULL, g_hinst,
                            NULL);

	if (hwndInvalidPasswordBalloon)
	{
		LPTSTR szError = NULL;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,ERROR_INVALID_PASSWORD,0,(LPTSTR)&szError,0,NULL);
		TOOLINFO ti;
		memset(&ti,0,sizeof(TOOLINFO));
		ti.cbSize   = sizeof(ti);
		ti.uFlags   = TTF_TRANSPARENT | TTF_CENTERTIP | TTF_IDISHWND | TTF_SUBCLASS;
		ti.hwnd     = hWnd;
		ti.uId      = (UINT_PTR) GetDlgItem(hWnd, IDC_05PASSWORD);
		ti.hinst    = g_hinst;
		ti.lpszText = L" ";
		SendMessage(hwndInvalidPasswordBalloon, TTM_SETTITLE, TTI_ERROR, (LPARAM) szError);
		SendMessage(hwndInvalidPasswordBalloon, TTM_ADDTOOL, 0, (LPARAM) &ti );
		SendMessage(hwndInvalidPasswordBalloon,TTM_TRACKACTIVATE,(WPARAM)TRUE,(LPARAM)&ti);
		LocalFree(szError);
	}
}


#define WM_MYMESSAGE WM_USER + 10
INT_PTR CALLBACK	WndProc_05PASSWORD(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		InitListViewListIcon(GetDlgItem(hWnd,IDC_05LIST));
		SendMessage(GetDlgItem(hWnd,IDC_05TEST), BM_SETCHECK, BST_CHECKED,0);
		PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_FINISH | PSWIZB_BACK);
		PropSheet_SetTitle(GetParent(hWnd), 0, MAKEINTRESOURCE(IDS_TITLE4));
		break;
	case WM_MYMESSAGE:
		if (fHasDeselected)
		{
			ListView_SetItemState(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_Update(GetDlgItem(hWnd,IDC_05LIST), dwCurrentCredential);
		}
		return TRUE;
		break;
	case WM_COMMAND:
		switch(LOWORD(wParam))
		{
		case IDC_05TEST:
			if (IsDlgButtonChecked(hWnd,IDC_05TEST))
			{
				PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_NEXT |	PSWIZB_BACK);
			}
			else
			{
				PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_FINISH | PSWIZB_BACK);
			}
			break;
		}
		break;

	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
				//this is an interior page
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_05LIST));
				PopulateListViewListData(GetDlgItem(hWnd, IDC_05LIST));	
				//if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
				//{
					PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_NEXT |	PSWIZB_BACK);
				//}
				//else
				//{
				//	PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK);
				//}
				// load string from ressource
				break;
			case PSN_WIZFINISH :
			case PSN_WIZNEXT:
				if (hwndInvalidPasswordBalloon) 
				{
					DestroyWindow(hwndInvalidPasswordBalloon); 
					hwndInvalidPasswordBalloon = NULL; 
				}
				GetWindowText(GetDlgItem(hWnd,IDC_05PASSWORD),szPassword,dwPasswordSize);
				if (!WizardFinishButton(szPassword))
				{
					// go to the error page
					dwWizardError = GetLastError();
					if (pnmh->code == PSN_WIZNEXT && dwWizardError != ERROR_INVALID_PASSWORD)
					{
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						PropSheet_SetCurSelByID(GetParent(hWnd), IDD_07TESTRESULTNOTOK);
					}
					else
					{
						if (dwWizardError != ERROR_INVALID_PASSWORD)
						{
							MessageBoxWin32Ex(dwWizardError,hWnd);
						}
						else
						{
							ShowInvalidPasswordBalloon((hWnd));
						}
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,(LONG_PTR)IDD_05PASSWORD);
					}
					return TRUE;
				}
				if (IsDlgButtonChecked(hWnd,IDC_05TEST))
				{
					if (!TestLogon(hWnd))
					{
						// handle if the credential test is cancelled
						dwWizardError = GetLastError();
						if (dwWizardError == ERROR_CANCELLED)
						{
							SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
							return TRUE;
						}
						// go to the error page
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						PropSheet_SetCurSelByID(GetParent(hWnd), IDD_07TESTRESULTNOTOK);
						return TRUE;
					}
					// go by default to the success page
				}
				break;
			case PSN_RESET:
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
				}
				break;

			case LVN_ITEMCHANGED:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->uNewState & LVIS_SELECTED )
					{
						if ((DWORD)(((LPNMITEMACTIVATE)lParam)->iItem) < pCredentialList->ContainerHolderCount())
						{
							fHasDeselected = FALSE;
							dwCurrentCredential = ((LPNMITEMACTIVATE)lParam)->iItem;
							if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
							{
								PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_FINISH |	PSWIZB_BACK);
							}
							else
							{
								PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK);
							}
						}
					}
					else
					{
						fHasDeselected = TRUE;
						PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK);
						PostMessage(hWnd, WM_MYMESSAGE, 0, 0);
					}
				}
				break;
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_05LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->iItem >= 0 && (DWORD)((LPNMITEMACTIVATE)lParam)->iItem < pCredentialList->ContainerHolderCount())
					{
						pCredentialList->GetContainerHolderAt(((LPNMITEMACTIVATE)lParam)->iItem)->GetContainer()->ViewCertificate(hWnd);
					}
				}
				break;
			
		}

    }
	return FALSE;
}