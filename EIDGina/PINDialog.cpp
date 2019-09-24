// GinaModalDialog.cpp
//
// Gather user credentials for Modal.
//
#include <Windows.h>
#include <WinWlx.h>
#include "PINDialog.h"
#include "SmartCardHelper.h"


PINDialog::PINDialog(CGina* pGina,PWSTR* pszUserName,PWSTR* pszPassword,PWSTR* pszDomain) : _pGina(pGina)
{
	pCredential = 0;
	_pCredentialList.SetUsageScenario(CPUS_LOGON,0);
	_pWinLogon = _pGina->GetCWinLogon();
	wcscpy_s(_szReader,ARRAYSIZE(_szReader), _pWinLogon->_szReader);
	wcscpy_s(_szCard,ARRAYSIZE(_szCard), _pWinLogon->_szCard);
	_pszUserName = pszUserName;
	_pszPassword = pszPassword;
	_pszDomain = pszDomain;
}

PINDialog::~PINDialog()
{
}

int PINDialog::Show()
{
    return _pWinLogon->DialogBoxParam(GetMyInstance(), MAKEINTRESOURCE(IDD_PIN), 0, _dialogProc, (LPARAM)this);
}

INT_PTR CALLBACK PINDialog::_dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (WM_INITDIALOG == msg) {
        ((PINDialog*)lp)->_hwnd = hwnd;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, lp);
    }
	PINDialog* dlg = (PINDialog*)GetWindowLongPtr(hwnd, GWLP_USERDATA);

    // WM_SETFONT is coming in before WM_INITDIALOG
    // in which case GWLP_USERDATA won't be set yet.
	if (dlg) {
		return dlg->DialogProc(msg, wp, lp);
	}
    return FALSE;
}

INT_PTR PINDialog::DialogProc(UINT msg, WPARAM wp, LPARAM lParam)
{
    switch (msg) 
	{
	case WM_INITDIALOG:
		{
			_pWinLogon->_LastHwndUsed = _hwnd;
			CenterWindow();
			BOOL fHasSmartCardCompatible = this->Populate();
			if (! fHasSmartCardCompatible )
			{
				_pWinLogon->MessageBox(_hwnd, L"The smart card doesn't contain any valid credential",NULL,0);
				EndDialog(_hwnd, IDCANCEL);
				break;
			}
			DWORD dwCount = _pCredentialList.ContainerHolderCount();
			if (dwCount > 0)
			{
				SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_RESETCONTENT,0,0);
				for (DWORD i = 0; i< dwCount; i++)
				{
					DWORD dwRid = _pCredentialList.GetContainerHolderAt(i)->GetContainer()->GetRid();
					PWSTR szName = GetUsernameFromRid(dwRid);
					if (szName)
					{
						SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_INSERTSTRING,i,(LPARAM) szName);
						EIDFree(szName);
					}
				}
				SendMessage(GetDlgItem(this->_hwnd,IDC_CONTAINER),CB_SETCURSEL,0,0);
				SendMessage(_hwnd, WM_NEXTDLGCTL, (WPARAM)GetDlgItem(this->_hwnd,IDC_PIN), TRUE);
			}
		}
		break;
	case WM_COMMAND: {
            switch (LOWORD(wp)) {
                case IDOK:
                    {
						DWORD index = SendMessage(GetDlgItem(_hwnd,IDC_CONTAINER),CB_GETCURSEL,0,0);
						pCredential = _pCredentialList.GetContainerHolderAt(index);
						GetWindowText(GetDlgItem(_hwnd,IDC_PIN), szPin, ARRAYSIZE(szPin));
						Login();
						break;
					}
                case IDCANCEL:
                    EndDialog(_hwnd, IDCANCEL);
                    break;
            }
            return TRUE;
        }
	case WLX_WM_SAS:
		// cancel Ctrl-Alt-Del SAS notification
		if (wp == WLX_SAS_TYPE_CTRL_ALT_DEL)
		{
			return TRUE;
		}
		break;
	case WM_EID_REMOVE:
		 EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed");
		 EndDialog(_hwnd, IDCANCEL);
         break;
    }
	return FALSE;
}

void PINDialog::CenterWindow() 
{
    RECT rc;
    if (!GetWindowRect(_hwnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(_hwnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}

// enable or disable all buttons on the dialog, set the cursor
void PINDialog::SetWaitStatus(BOOL fDisableButton)
{
	EnableWindow(GetDlgItem(_hwnd,IDC_CONTAINER), !fDisableButton);
	//EnableWindow(GetDlgItem(_hwnd,IDC_PIN), !fDisableButton);
	SendMessage(GetDlgItem(_hwnd,IDC_PIN), EM_SETREADONLY, (WPARAM)(fDisableButton), 0L);
	EnableWindow(GetDlgItem(_hwnd,IDOK), !fDisableButton);
	EnableWindow(GetDlgItem(_hwnd,IDCANCEL), !fDisableButton);
	if (fDisableButton)
	{
		SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_WAIT)));
	}
	else
	{
		SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_ARROW)));
	}
}

BOOL PINDialog::Populate()
{
	BOOL fReturn = FALSE;
	_pGina->DisplayStatusMessage(GetThreadDesktop(GetCurrentThreadId()),0, NULL, L"Reading smart card ...");
	_pCredentialList.ConnectNotification(_szReader,_szCard,0);
	if (_pCredentialList.HasContainerHolder())
	{
		pCredential = _pCredentialList.GetContainerHolderAt(0);
		fReturn = TRUE;
	}
	_pGina->RemoveStatusMessage();
	return fReturn;
}

BOOL PINDialog::Login()
{
	DWORD dwError, dwRemaingPinAttempt;
	BOOL fReturn = FALSE;
	if (!_pWinLogon->_fSmartCardPresent)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed ?");
		EndDialog(_hwnd, IDCANCEL);
	}
	SetWaitStatus(TRUE);
	BOOL fLogonSuccess = GetPassword(szPin, pCredential->GetContainer(), 
								_pszUserName, _pszPassword, _pszDomain, &dwError, &dwRemaingPinAttempt);
	SetWaitStatus(FALSE);
	if (!fLogonSuccess)
	{
		WCHAR szMessage[2048] = L"Unable to logon";
		if (dwError == SCARD_W_WRONG_CHV && dwRemaingPinAttempt != 0xFFFFFFFF)
		{
			swprintf_s(szMessage, ARRAYSIZE(szMessage), L"Wrong PIN : %d attempts remaining",dwRemaingPinAttempt); 
		}
		else
		{
			LookUpErrorMessage(szMessage, ARRAYSIZE(szMessage), dwError);
		}
		_pWinLogon->MessageBox(_hwnd,szMessage,L"",0);
	}
	else
	{
		fReturn = TRUE;
		EndDialog(_hwnd, IDOK);
	}
	return fReturn;
}