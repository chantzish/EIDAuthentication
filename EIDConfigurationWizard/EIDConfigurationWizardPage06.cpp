#include <Windows.h>
#include <tchar.h>
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "CContainerHolder.h"
#include "global.h"
#include "EIDConfigurationWizard.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/OnlineDatabase.h"
// from previous step
// credentials
extern CContainerHolderFactory<CContainerHolderTest> *pCredentialList;


INT_PTR CALLBACK	WndProc_06TESTRESULTOK(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		/*if (!IsElevated())
		{
			// Set shield icon
			HICON ShieldIcon;
			SHSTOCKICONINFO sii = {0}; 
			sii.cbSize = sizeof(sii);
			SHGetStockIconInfo(SIID_SHIELD, SHGFI_ICON | SHGFI_SMALLICON, &sii);
			ShieldIcon = sii.hIcon;
			SendMessage(GetDlgItem(hWnd,IDC_05FORCEPOLICYICON),STM_SETICON ,(WPARAM)ShieldIcon,0);
			SendMessage(GetDlgItem(hWnd,IDC_05REMOVEPOLICYICON),STM_SETICON ,(WPARAM)ShieldIcon,0);
		}*/
		
		{
			HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
			if (hDll)
			{
				HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(106)); 
				SendMessage(GetDlgItem(hWnd,IDC_06SHIELD),STM_SETIMAGE,IMAGE_ICON, (LPARAM) hIcon);
				DestroyIcon(hIcon);
				FreeLibrary(hDll);
			}
		}
		break;
	case WM_COMMAND:
		// Analyse les sélections de menu :
		switch (LOWORD(wParam))
		{	
		case IDC_06UPDATEDATABASE:
			{
				SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_WAIT)));
				BOOL fReturn = CommunicateTestOK();
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
					// success !
					MessageBoxWin32Ex(0, hWnd);
				}
			}
			break;
		}
		break;
	case WM_NOTIFY :
			LPNMHDR pnmh = (LPNMHDR)lParam;
			switch(pnmh->code)
			{
			case NM_CLICK:
			case NM_RETURN:
				{
					// enable / disable policy
					/*PNMLINK pNMLink = (PNMLINK)lParam;
					TCHAR szMessage[256] = TEXT("");
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idActRemove") == 0)
					{
						DialogRemovePolicy();
					}
					else if (wcscmp(item.szID, L"idActForce") == 0)
					{
						DialogForceSmartCardLogonPolicy();
					}*/
				}	
			case PSN_SETACTIVE:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
				PropSheet_SetWizButtons(hWnd, PSWIZB_BACK | PSWIZB_FINISH);
				/*{
				TCHAR szMessage[256] = TEXT("");
				LoadString(g_hinst, IDS_05ACTIVATEREMOVE, szMessage, ARRAYSIZE(szMessage));
				SetWindowText(GetDlgItem(hWnd,IDC_05REMOVEPOLICYLINK),szMessage);
				LoadString(g_hinst, IDS_05ACTIVATEFORCE, szMessage, ARRAYSIZE(szMessage));
				SetWindowText(GetDlgItem(hWnd,IDC_05FORCEPOLICYLINK),szMessage);
				}*/
				break;

			case PSN_WIZFINISH:
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
				}
				break;
			}
	}
	return FALSE;
}
