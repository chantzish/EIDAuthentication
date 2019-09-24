#include <Windows.h>
#include <Commctrl.h>

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "CContainerHolderXP.h"
#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"

// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;
extern DWORD dwCurrentCredential;
extern DWORD dwWizardError;

void SetErrorMessage(HWND hWnd)
{
	LPTSTR Error;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,dwWizardError,0,(LPTSTR)&Error,0,NULL);
	SetWindowText(GetDlgItem(hWnd,IDC_WIZARDERROR),Error);
	LocalFree(Error);
}

INT_PTR CALLBACK	WndProc_07TESTRESULTNOTOK(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LPNMHDR pnmh = (LPNMHDR)lParam;
	switch(message)
	{
		case WM_INITDIALOG:
			PropSheet_SetTitle(GetParent(hWnd), 0, MAKEINTRESOURCE(IDS_TITLE5));
			{
				HMODULE hDll = LoadLibrary(TEXT("wuaucpl.cpl") );
				if (hDll)
				{
					HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(5)); 
					SendMessage(GetDlgItem(hWnd,IDC_07SHIELD),STM_SETIMAGE,IMAGE_ICON, (LPARAM) hIcon);
					DestroyIcon(hIcon);
					FreeLibrary(hDll);
				}
			}
			break;
		case WM_NOTIFY :
			switch(pnmh->code)
			{
				case NM_CLICK:
				case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idReport") == 0)
					{
						TCHAR szEmail[256];
						GetWindowText(GetDlgItem(hWnd,IDC_07EMAIL),szEmail,ARRAYSIZE(szEmail));
						CContainerHolderTest* MyTest = pCredentialList->GetContainerHolderAt(dwCurrentCredential);
						CContainer* container = MyTest->GetContainer();
						SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_WAIT)));
						BOOL fReturn = SendReport(dwWizardError, szEmail, container->GetCertificate());
						SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_ARROW)));
						if (!fReturn)
						{
							if (GetLastError() == SPAPI_E_MACHINE_UNAVAILABLE || GetLastError() == ERROR_INTERNAL_ERROR)
							{
								MessageBox(hWnd,GetAdvancedErrorMessage(),TEXT("Error"),0);
							}
							else
							{
								MessageBoxWin32Ex(GetLastError(), hWnd);
							}
						}
						else
						{
							//success !
							MessageBoxWin32Ex(0, hWnd);
						}
					}
				}
				case PSN_SETACTIVE:
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
					PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK | PSWIZB_FINISH);
					SetErrorMessage(hWnd);
					break;
				case PSN_WIZBACK:
					// get to the test again (avoid test result page positive)
					PropSheet_PressButton(GetParent(hWnd), PSBTN_BACK);
					break;
				case PSN_WIZFINISH:
					if (pCredentialList)
					{
						delete pCredentialList;
						pCredentialList = NULL;
					}
					break;
			}
			break;
		
	}
	return FALSE;
}
