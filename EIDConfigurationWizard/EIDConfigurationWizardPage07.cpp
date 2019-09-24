#include <Windows.h>
#include <Commctrl.h>

#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "CContainerHolder.h"
#include "global.h"
#include "EIDConfigurationWizard.h"

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
	int wmId;
	int wmEvent;
	LPNMHDR pnmh = (LPNMHDR)lParam;
	switch(message)
	{
		case WM_INITDIALOG:
			if (!IsElevated())
			{
				Button_SetElevationRequiredState(GetDlgItem(hWnd,IDC_07SENDREPORT),TRUE);
			}
			{
				HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
				if (hDll)
				{
					HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(105)); 
					SendMessage(GetDlgItem(hWnd,IDC_07SHIELD),STM_SETIMAGE,IMAGE_ICON, (LPARAM) hIcon);
					DestroyIcon(hIcon);
					FreeLibrary(hDll);
				}
			}
			break;
		case WM_NOTIFY :
			switch(pnmh->code)
			{
				case PSN_SETACTIVE:
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
					PropSheet_SetWizButtons(hWnd, PSWIZB_BACK | PSWIZB_FINISH);
					SetErrorMessage(hWnd);
					break;
				case PSN_WIZBACK:
					// get to the test again (avoid test result page positive)
					PropSheet_PressButton(hWnd, PSBTN_BACK);
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
		case WM_COMMAND:
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			// Analyse les sélections de menu :
			switch (wmId)
			{	
				case IDC_07SENDREPORT:
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
					break;
			}
			break;
		
	}
	return FALSE;
}
