#include <windows.h>
#include <tchar.h>
#include <Commctrl.h>
#include <shellapi.h>

#include "globalXP.h"
#include "EIDConfigurationWizardXP.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Package.h"


void CheckIfCardHasADriver(HWND hWnd)
{
	LONG             lReturn = 0;
	SCARDCONTEXT     hSC = NULL;
	PTSTR szReaders = NULL;
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
		DWORD dwReaderCount = SCARD_AUTOALLOCATE;
		lReturn = SCardListReaders(hSC, NULL,  (LPTSTR)&szReaders, &dwReaderCount);
		if ( SCARD_S_SUCCESS != lReturn )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardListReaders 0x%08X",lReturn);
			__leave;
		}
		// foreach reader, try to know if there is a smart card
		PTSTR szCurrentReader = szReaders;
		while(szCurrentReader[0] != 0)
		{
			SCARDHANDLE hCard = NULL;
			DWORD dwProtocol;
			LPTSTR szTempReader = NULL;
			DWORD dwTempReaderSize = SCARD_AUTOALLOCATE;
			PBYTE pbAtr = NULL;
			DWORD dwAtrSize = SCARD_AUTOALLOCATE;
			LPTSTR szCards = NULL;
			DWORD dwzCardsSize = SCARD_AUTOALLOCATE;
			__try
			{
				lReturn = SCardConnect(hSC, szCurrentReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_Tx, &hCard, &dwProtocol);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardConnect 0x%08X",lReturn);
					__leave;
				}
				// get the ATR
				lReturn = SCardStatus(hCard, (PTSTR) &szTempReader, &dwTempReaderSize, NULL, NULL, (PBYTE)&pbAtr, &dwAtrSize);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardStatus 0x%08X",lReturn);
					__leave;
				}
				// get the name
				lReturn = SCardListCards(hSC, pbAtr, NULL, 0, (PTSTR) &szCards, &dwzCardsSize);
				if ( SCARD_S_SUCCESS != lReturn )
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failed SCardListCards 0x%08X",lReturn);
					__leave;
				}
				if (szCards[0] == 0)
				{
					// unknown card
					// put the ATR into a string
					TCHAR szATR[256];
					for(DWORD i=0; i< dwAtrSize; i++)
					{
						_stprintf_s(szATR + 2*i, ARRAYSIZE(szATR) - 2*i,TEXT("%02X"),pbAtr[i]);
					}
					TCHAR szMessageFormat[256] = TEXT("ATR: %s");
					TCHAR szMessage[356];
					LoadString(g_hinst,IDS_CHECKDRIVERONLINE,szMessageFormat,ARRAYSIZE(szMessageFormat));
					_stprintf_s(szMessage, ARRAYSIZE(szMessage), szMessageFormat, szATR);
					if (IDOK == MessageBox(hWnd,szMessage,L"",MB_OKCANCEL|MB_DEFBUTTON1))
					{
						OpenBrowserOnDatabase(pbAtr, dwAtrSize, NULL);
					}
				}
			}
			__finally
			{
				if (hCard != NULL)
					SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				if (pbAtr)
					SCardFreeMemory(hSC, pbAtr);
				if (szCards)
					SCardFreeMemory(hSC, szCards);
			}
			// for the next loop
			szCurrentReader = szCurrentReader + _tcslen(szCurrentReader) + 1;
		}
	}
	__finally
	{
		if (szReaders)
			SCardFreeMemory(hSC, szReaders);
		if (hSC)
			SCardReleaseContext(hSC);
	}
}

INT_PTR CALLBACK	WndProc_02ENABLE(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch(message)
	{
	case WM_INITDIALOG:
		PropSheet_SetTitle(GetParent(hWnd), 0, MAKEINTRESOURCE(IDS_TITLE1));
		CenterWindow(GetParent(hWnd));
		CheckDlgButton(hWnd, IDC_02EXISTING, BST_CHECKED);
		if (!LsaEIDHasStoredCredential(NULL))
		{
			EnableWindow(GetDlgItem(hWnd,IDC_01DELETE), FALSE);
		}
		{
			DWORD dwAttrib = GetFileAttributes(TEXT("c:\\windows\\system32\\Pintool.exe"));
			if ((dwAttrib != INVALID_FILE_ATTRIBUTES && 
							!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY)))
			{
				ShowWindow(GetDlgItem(hWnd,IDC_02CHANGEPIN), SW_SHOW);
			}
		}
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				/*//this is an interior page
				if (fHasAlreadySmartCardCredential)
				{
					PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_BACK | PSWIZB_NEXT);
				}
				else
				{
					PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_NEXT);
				}*/
				PropSheet_SetWizButtons(GetParent(hWnd), PSWIZB_NEXT);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
				break;
			case PSN_WIZNEXT:
				if (IsDlgButtonChecked(hWnd, IDC_02EXISTING) == BST_CHECKED)
				{
					if (AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
					{
						//next screen
						fShowNewCertificatePanel = FALSE;
						PropSheet_SetCurSelByID(GetParent(hWnd),IDD_04CHECKS);
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
					else
					{
						LONG lReturn = GetLastError();
						if (lReturn != SCARD_W_CANCELLED_BY_USER)
						{
							MessageBoxWin32Ex(lReturn,hWnd);
						}
						else
						{
							CheckIfCardHasADriver(hWnd);
						}
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				else if (IsDlgButtonChecked(hWnd, IDC_01DELETE) == BST_CHECKED)
				{
					TCHAR szMessage[256] = TEXT("");
					LoadString(g_hinst,IDS_AREYOUSURE,szMessage,ARRAYSIZE(szMessage));
					if (IDYES == MessageBox(hWnd,szMessage,TEXT(""),MB_ICONWARNING|MB_YESNO))
					{
						if (!LsaEIDRemoveStoredCredential(NULL))
						{
							MessageBoxWin32Ex(GetLastError(),hWnd);
						}
						else
						{
							// delete
							PropSheet_PressButton(GetParent(hWnd),PSBTN_CANCEL);
						}
					}
					SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
					return TRUE;
				}
				else
				{
					if (AskForCard(szReader, dwReaderSize, szCard, dwCardSize))
					{
						//next screen
						fShowNewCertificatePanel = TRUE;
						//PropSheet_SetCurSelByID(GetParent(hWnd),IDD_03NEW);
					}
					else
					{
						LONG lReturn = GetLastError();
						if (lReturn != SCARD_W_CANCELLED_BY_USER)
						{
							MessageBoxWin32Ex(lReturn, hWnd);
						}
						else
						{
							CheckIfCardHasADriver(hWnd);
						}
						SetWindowLongPtr(hWnd,DWLP_MSGRESULT,-1);
						return TRUE;
					}
				}
				break;
			case NM_CLICK:
			case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idDatabase") == 0)
					{
						if (!OpenBrowserOnDatabase())
						{
							LONG lReturn = GetLastError();
							if (lReturn != SCARD_W_CANCELLED_BY_USER)
							{
								MessageBoxWin32Ex(lReturn, hWnd);
							}
						}
					}
					else if (wcscmp(item.szID, L"idChangePin") == 0)
					{
						ShellExecute(NULL, L"open", TEXT("PinTool.exe"), NULL, NULL, SW_SHOWNORMAL);
					}
					/*if ((((LPNMHDR)lParam)->hwndFrom == GetDlgItem(hWnd,IDC_SYSLINKHELP)) && (item.iLink == 0))
					{
						ShellExecute(NULL, L"open", item.szUrl, NULL, NULL, SW_SHOW);
					}*/
					break;
				}

		}
		break;
    }
	return FALSE;
}