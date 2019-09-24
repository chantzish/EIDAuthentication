#include <Windows.h>
#include <WinWlx.h>
#include <Wtsapi32.h>
#include "global.h"
#include "CWinlogon.h"
#include "..\EIDCardLibrary\EIDCardLibrary.h"
#include "..\EIDCardLibrary\Tracing.h"
#include "..\EIDCardLibrary\Gpo.h"
#include "WinLoginInterface.h"
#include <crtdbg.h>

PWSTR DuplicateString(PWSTR source)
{
	PWSTR szReturn = NULL;
	if (!source) return NULL;
	DWORD dwNum = wcslen(source) + 1;
	szReturn = (PWSTR) LocalAlloc(LMEM_FIXED, dwNum * sizeof(WCHAR));
	if (!szReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
		return NULL;
	}
	wcscpy_s(szReturn, dwNum, source);
	return szReturn;
}	

PWSTR DuplicateUnicodeString(PUNICODE_STRING source)
{
	PWSTR szReturn = NULL;
	if (!source) return NULL;
	if (source->Length == 0) return NULL;
	DWORD dwNum = source->Length/2 + 1;
	szReturn = (PWSTR) LocalAlloc(LMEM_FIXED, dwNum * sizeof(WCHAR));
	if (!szReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory");
		return NULL;
	}
	memcpy(szReturn, source->Buffer, source->Length);
	szReturn[source->Length/2] = L'\0';
	return szReturn;
}	
template<typename Target, typename Source>
inline Target brute_cast(const Source s)
{
    _ASSERTE(sizeof(Target) == sizeof(Source));
    union { Target t; Source s; } u;
    u.s = s;
    return u.t;
}

CWinLogon::CWinLogon(HANDLE                  hWlx,
				DWORD                   dwWinLogonVersion,
				PVOID                   pWinlogonFunctions) :
	_winLogonHandle(hWlx), _winLogonVersion(dwWinLogonVersion), _pDispatchTable((PWLX_DISPATCH_VERSION_1_4)pWinlogonFunctions)
{
	
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_fSmartCardPresentHook = FALSE;
	_fSmartCardSAS = FALSE;
	_fAutologonHook = FALSE;
	_fEnableRemovePolicy = FALSE;
	_LastHwndUsed = NULL;
	_dwMessageBoxCount = 0;
	DispatchTable.WlxUseCtrlAltDel = WlxUseCtrlAltDel;
    DispatchTable.WlxSetContextPointer = WlxSetContextPointer;
    DispatchTable.WlxSasNotify = WlxSasNotify;
    DispatchTable.WlxSetTimeout = WlxSetTimeout;
    DispatchTable.WlxAssignShellProtection = WlxAssignShellProtection;
    DispatchTable.WlxMessageBox = WlxMessageBox;
    DispatchTable.WlxDialogBox = WlxDialogBox;
    DispatchTable.WlxDialogBoxParam = WlxDialogBoxParam;
    DispatchTable.WlxDialogBoxIndirect = WlxDialogBoxIndirect;
    DispatchTable.WlxDialogBoxIndirectParam = WlxDialogBoxIndirectParam;
    DispatchTable.WlxSwitchDesktopToUser = WlxSwitchDesktopToUser;
    DispatchTable.WlxSwitchDesktopToWinlogon = WlxSwitchDesktopToWinlogon;
    DispatchTable.WlxChangePasswordNotify = WlxChangePasswordNotify;
    DispatchTable.WlxGetSourceDesktop = WlxGetSourceDesktop;
    DispatchTable.WlxSetReturnDesktop = WlxSetReturnDesktop;
    DispatchTable.WlxCreateUserDesktop = WlxCreateUserDesktop;
    DispatchTable.WlxChangePasswordNotifyEx = WlxChangePasswordNotifyEx;
    DispatchTable.WlxCloseUserDesktop  = WlxCloseUserDesktop;
    DispatchTable.WlxSetOption = WlxSetOption;
    DispatchTable.WlxGetOption = WlxGetOption;
    DispatchTable.WlxWin31Migrate = WlxWin31Migrate;
    DispatchTable.WlxQueryClientCredentials = (PWLX_QUERY_CLIENT_CREDENTIALS) 
									CreateThunk(brute_cast<ULONG>(&CWinLogon::QueryClientCredentials));
    DispatchTable.WlxQueryInetConnectorCredentials = (PWLX_QUERY_IC_CREDENTIALS) 
									CreateThunk(brute_cast<ULONG>(&CWinLogon::QueryInetConnectorCredentials));
    DispatchTable.WlxDisconnect = (PWLX_DISCONNECT) 
									CreateThunk(brute_cast<ULONG>(&CWinLogon::Disconnect));
    DispatchTable.WlxQueryTerminalServicesData = WlxQueryTerminalServicesData;
	if (dwWinLogonVersion >= WLX_VERSION_1_4)
	{
		DispatchTable.WlxQueryConsoleSwitchCredentials = (PWLX_QUERY_CONSOLESWITCH_CREDENTIALS) 
									CreateThunk(brute_cast<ULONG>(&CWinLogon::QueryConsoleSwitchCredentials));
		DispatchTable.WlxQueryTsLogonCredentials = (PWLX_QUERY_TS_LOGON_CREDENTIALS) 
									CreateThunk(brute_cast<ULONG>(&CWinLogon::QueryTsLogonCredentials));
	}
	// enable smart card thread
	_fSmartCardPresent = FALSE;
	_szReader[0] = L'\0';
	_szCard[0] = L'\0';
	_pSmartCardConnectionNotifier = new CSmartCardConnectionNotifier(this);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

CWinLogon::~CWinLogon()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	if (_pSmartCardConnectionNotifier) _pSmartCardConnectionNotifier->Stop();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

// used to convert non static member as function pointer
// inspired from http://www.codeproject.com/KB/cpp/thunk32.aspx
//
// the idea is to dynamically create a function, which will then call a function (member) related to an object
// (the pointer to the object and to the function are stored in the created function)
PVOID CWinLogon::CreateThunk(ULONG somefunction)
{
	THUNK* callbackThunk = reinterpret_cast<THUNK*>(
        VirtualAlloc(NULL, 
                     sizeof(THUNK), 
                     MEM_COMMIT, 
                     PAGE_EXECUTE_READWRITE));
    if(callbackThunk == NULL) 
    { 
        EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"big failure");
		/* throw an exception to notify about 
           the allocation problem. */ 
		return NULL;
    }
        
    // See declaration of the THUNK struct for a byte code explanation
    callbackThunk->stub1 = 0x0D8D;
    callbackThunk->nThisPtr = reinterpret_cast<ULONG>(this);

    callbackThunk->stub2 = 0xB8;
    // Fetch address to the destination function
    callbackThunk->nJumpProc = somefunction;
    callbackThunk->stub3 = 0xE0FF;

    // Flush instruction cache. May be required on some architectures which
    // don't feature strong cache coherency guarantees, though not on neither
    // x86, x64 nor AMD64.
    FlushInstructionCache(GetCurrentProcess(), callbackThunk, sizeof(THUNK));
	return callbackThunk;
}

// called when smart card are insert / removed
void CWinLogon::Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) 
{
	switch(Message)
	{
	case EIDCPRSConnecting:
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"EIDCPRSConnecting");
		wcscpy_s(_szReader, ARRAYSIZE(_szReader), szReader);
		wcscpy_s(_szCard, ARRAYSIZE(_szCard), szCardName);
		_ActivityCount = ActivityCount;
		_fSmartCardPresent = TRUE;
		if (_fSmartCardSAS && _LastHwndUsed) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WM_EID_INSERT to %d", _LastHwndUsed);
			PostMessage(_LastHwndUsed, WM_EID_INSERT,0,0);
		}
		break;
	case EIDCPRSDisconnected:
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"EIDCPRSDisconnected");
		_szReader[0] = L'\0';
		_szCard[0] = L'\0';
		_fSmartCardPresent = FALSE;
		if (_fSmartCardSAS && _LastHwndUsed) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WM_EID_REMOVE to %d", _LastHwndUsed);
			PostMessage(_LastHwndUsed, WM_EID_REMOVE,0,0);
		}
		if (_fEnableRemovePolicy)
		{
			ExecuteRemovePolicy();
			_fEnableRemovePolicy = FALSE;
		}
		break;
	}
}

VOID CWinLogon::UseCtrlAltDel()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pDispatchTable->WlxUseCtrlAltDel(_winLogonHandle);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID CWinLogon::SetContextPointer(PVOID pWlxContext)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pDispatchTable->WlxSetContextPointer(_winLogonHandle, pWlxContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID CWinLogon::SasNotify(DWORD dwSasType)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pDispatchTable->WlxSasNotify(_winLogonHandle, dwSasType);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

BOOL CWinLogon::SetTimeout(DWORD Timeout)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxSetTimeout(_winLogonHandle, Timeout);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

int CWinLogon::AssignShellProtection(HANDLE hToken, HANDLE hProcess, HANDLE hThread)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxAssignShellProtection(_winLogonHandle, hToken, hProcess, hThread);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::MessageBox(HWND hwndOwner, LPWSTR lpszText, LPWSTR lpszTitle, UINT fuStyle)
{
	_dwMessageBoxCount++;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Message : %s", lpszText);
	int iReturn =  _pDispatchTable->WlxMessageBox(_winLogonHandle, hwndOwner, lpszText, lpszTitle, fuStyle);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::DialogBox( HANDLE hInst, LPWSTR lpszTemplate, HWND hwndOwner, DLGPROC dlgprc)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxDialogBox(_winLogonHandle, hInst, lpszTemplate, hwndOwner, dlgprc);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::DialogBoxIndirect(HANDLE hInst, LPCDLGTEMPLATE hDialogTemplate, HWND hwndOwner, DLGPROC dlgprc)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxDialogBoxIndirect(_winLogonHandle, hInst, hDialogTemplate, hwndOwner, dlgprc);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::DialogBoxParam(HANDLE hInst, LPWSTR lpszTemplate, HWND hwndOwner, DLGPROC dlgprc, LPARAM dwInitParam)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn;
	BOOL fHooked = FALSE;
	// Redirected WlxDialogBoxParam() function.
	if (!HIWORD(LOW32(lpszTemplate)))
	{
		// Make sure we only hook the dialog we want
		switch (LOW32(lpszTemplate))
		{
			case IDD_WLXLOGGEDOUTSAS_DIALOG:
			{
			// Save out 
			_pfOriginalDlgProc = dlgprc;
			DLGPROC MyWlxDlgProc = (DLGPROC) CreateThunk(brute_cast<ULONG>(&CWinLogon::LoggedOutSASDlgProc));
			// And redirect through our own callback
			iReturn = _pDispatchTable->WlxDialogBoxParam(_winLogonHandle, hInst, lpszTemplate, hwndOwner, MyWlxDlgProc, dwInitParam);
			VirtualFree(MyWlxDlgProc, sizeof(THUNK), MEM_DECOMMIT);
			fHooked = TRUE;
			}
			break;
			case IDD_WLXDIAPLAYSASNOTICE_DIALOG:
			{
			// Save out 
			_pfOriginalDlgProc = dlgprc;
			DLGPROC MyWlxDlgProc = (DLGPROC) CreateThunk(brute_cast<ULONG>(&CWinLogon::DisplaySASNoticeDlgProc));
			// And redirect through our own callback
			iReturn = _pDispatchTable->WlxDialogBoxParam(_winLogonHandle, hInst, lpszTemplate, hwndOwner, MyWlxDlgProc, dwInitParam);
			VirtualFree(MyWlxDlgProc, sizeof(THUNK), MEM_DECOMMIT);
			fHooked = TRUE;
			}
			break;
			case IDD_WLXDISPLAYLOCKEDNOTICE_DIALOG:
			{
			// Save out 
			_pfOriginalDlgProc = dlgprc;
			DLGPROC MyWlxDlgProc = (DLGPROC) CreateThunk(brute_cast<ULONG>(&CWinLogon::DisplayLockedNoticeDlgProc));
			// And redirect through our own callback
			iReturn = _pDispatchTable->WlxDialogBoxParam(_winLogonHandle, hInst, lpszTemplate, hwndOwner, MyWlxDlgProc, dwInitParam);
			VirtualFree(MyWlxDlgProc, sizeof(THUNK), MEM_DECOMMIT);
			fHooked = TRUE;
			}
			break;
			case IDD_WLXWKSTALOCKEDSAS_DIALOG:
			{
			// Save out 
			_pfOriginalDlgProc = dlgprc;
			DLGPROC MyWlxDlgProc = (DLGPROC) CreateThunk(brute_cast<ULONG>(&CWinLogon::WkstaLockedSASDlgProc));
			// And redirect through our own callback
			iReturn = _pDispatchTable->WlxDialogBoxParam(_winLogonHandle, hInst, lpszTemplate, hwndOwner, MyWlxDlgProc, dwInitParam);
			VirtualFree(MyWlxDlgProc, sizeof(THUNK), MEM_DECOMMIT);
			fHooked = TRUE;
			}
			break;
				
		}
	}
	_LastHwndUsed = NULL;
	if (!fHooked)
	{
 		iReturn =  _pDispatchTable->WlxDialogBoxParam(_winLogonHandle, hInst, lpszTemplate, hwndOwner, dlgprc, dwInitParam);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

INT_PTR CWinLogon::DisplaySASNoticeDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// let msgina do the job
	INT_PTR iReturn;
	iReturn = _pfOriginalDlgProc(hwndDlg, uMsg,wParam, lParam);
	_LastHwndUsed = hwndDlg;
	if (uMsg == WM_EID_INSERT)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_SAS_TYPE_EID_INSERT");
		_pDispatchTable->WlxSasNotify(_winLogonHandle, WLX_SAS_TYPE_EID_INSERT);
	}
	return iReturn;
}

INT_PTR CWinLogon::LoggedOutSASDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	INT_PTR iReturn;
	DWORD dwMessageBoxCount = GetMessageBoxCount();
	_LastHwndUsed = hwndDlg;
	if (uMsg == WM_WINDOWPOSCHANGING)
	{
		//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"WM_WINDOWPOSCHANGING");
		PWINDOWPOS pPos = (PWINDOWPOS) lParam;
		if (_fAutologonHook)
		{
			pPos->flags &= ~SWP_SHOWWINDOW;
		}
	}
	// let msgina do the job
	iReturn = _pfOriginalDlgProc(hwndDlg, uMsg,wParam, lParam);
	// overwrite the user fields
	if (uMsg == WM_INITDIALOG && _fAutologonHook)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter uMsg=%d",uMsg);
		SendMessage(GetDlgItem(hwndDlg, IDC_WLXLOGGEDOUTSAS_DOMAIN), CB_SELECTSTRING, -1, (LPARAM)_alDomain);
		SetDlgItemText(hwndDlg,IDC_WLXLOGGEDOUTSAS_USERNAME,_alUserName);
		SetDlgItemText(hwndDlg,IDC_WLXLOGGEDOUTSAS_PASSWORD,_alPassword);
		// And "hit" OK ;)
		SendMessage(hwndDlg,WM_COMMAND,IDC_WLXLOGGEDOUTSAS_OK,1);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	}
	else if (uMsg == WM_EID_INSERT && IsRemote())
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_SAS_TYPE_EID_INSERT");
		_pDispatchTable->WlxSasNotify(_winLogonHandle, WLX_SAS_TYPE_EID_INSERT);
	}
	else if (uMsg == WLX_WM_SAS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_WM_SAS %d ireturn = %d",wParam, iReturn);
		if ( wParam == WLX_SAS_TYPE_EID_INSERT || wParam == WLX_SAS_TYPE_EID_REMOVE )
		{
			iReturn = FALSE;
		}
	}
	if (_fAutologonHook)
	{
		// check if an error message was displayed.
		// if so, cancel the dialog
		if (GetMessageBoxCount() > dwMessageBoxCount)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Cancel Window");
			// And "hit" cancel ;)
			EndDialog(hwndDlg, IDCANCEL);
		}
	}
	return iReturn;
}

INT_PTR CWinLogon::WkstaLockedSASDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	INT_PTR iReturn;
	DWORD dwMessageBoxCount = GetMessageBoxCount();
	_LastHwndUsed = hwndDlg;
	// let msgina do the job
	iReturn = _pfOriginalDlgProc(hwndDlg, uMsg,wParam, lParam);
	// overwrite the user fields
	if (uMsg == WM_INITDIALOG && _fAutologonHook)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter uMsg=%d",uMsg);
		SendMessage(GetDlgItem(hwndDlg, IDC_WLXWKSTALOCKEDSAS_DOMAIN), CB_SELECTSTRING, -1, (LPARAM)_alDomain);
		SetDlgItemText(hwndDlg,IDC_WLXWKSTALOCKEDSAS_USERNAME,_alUserName);
		SetDlgItemText(hwndDlg,IDC_WLXWKSTALOCKEDSAS_PASSWORD,_alPassword);
		// And "hit" OK ;)
		SendMessage(hwndDlg,WM_COMMAND,IDC_WLXWKSTALOCKEDSAS_OK,1);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	}
	else if (uMsg == WM_EID_INSERT && IsRemote())
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_SAS_TYPE_EID_INSERT");
		_pDispatchTable->WlxSasNotify(_winLogonHandle, WLX_SAS_TYPE_EID_INSERT);
	}
	else if (uMsg == WLX_WM_SAS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_WM_SAS %d ireturn = %d",wParam, iReturn);
		if ( wParam == WLX_SAS_TYPE_EID_INSERT || wParam == WLX_SAS_TYPE_EID_REMOVE )
		{
			iReturn = FALSE;
		}
	}
	if (_fAutologonHook)
	{
		// check if an error message was displayed.
		// if so, cancel the dialog
		if (GetMessageBoxCount() > dwMessageBoxCount)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Cancel Window");
			// And "hit" cancel ;)
			EndDialog(hwndDlg, IDCANCEL);
		}
	}
	return iReturn;
}
INT_PTR CWinLogon::DisplayLockedNoticeDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	// let msgina do the job
	INT_PTR iReturn;
	iReturn = _pfOriginalDlgProc(hwndDlg, uMsg,wParam, lParam);
	_LastHwndUsed = hwndDlg;
	if (uMsg == WM_EID_INSERT)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"WLX_SAS_TYPE_EID_INSERT");
		_pDispatchTable->WlxSasNotify(_winLogonHandle, WLX_SAS_TYPE_EID_INSERT);
	}
	return iReturn;
}
int CWinLogon::DialogBoxIndirectParam(HANDLE hInst, LPCDLGTEMPLATE hDialogTemplate, HWND hwndOwner, DLGPROC dlgprc, LPARAM dwInitParam )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxDialogBoxIndirectParam(_winLogonHandle, hInst, hDialogTemplate, hwndOwner, dlgprc, dwInitParam);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::SwitchDesktopToUser()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxSwitchDesktopToUser(_winLogonHandle);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::SwitchDesktopToWinlogon()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxSwitchDesktopToWinlogon(_winLogonHandle);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

int CWinLogon::ChangePasswordNotify(PWLX_MPR_NOTIFY_INFO pMprInfo, DWORD dwChangeInfo)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxChangePasswordNotify(_winLogonHandle, pMprInfo, dwChangeInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

BOOL CWinLogon::GetSourceDesktop(PWLX_DESKTOP * ppDesktop)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxGetSourceDesktop(_winLogonHandle, ppDesktop);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::SetReturnDesktop(PWLX_DESKTOP pDesktop)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxSetReturnDesktop(_winLogonHandle, pDesktop);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::CreateUserDesktop(HANDLE hToken, DWORD Flags, PWSTR pszDesktopName, PWLX_DESKTOP * ppDesktop)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxCreateUserDesktop(_winLogonHandle, hToken,Flags, pszDesktopName, ppDesktop);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

int CWinLogon::ChangePasswordNotifyEx(PWLX_MPR_NOTIFY_INFO pMprInfo, DWORD dwChangeInfo, PWSTR ProviderName, PVOID Reserved)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn =  _pDispatchTable->WlxChangePasswordNotifyEx(_winLogonHandle, pMprInfo, dwChangeInfo, ProviderName, Reserved);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

BOOL CWinLogon::CloseUserDesktop(PWLX_DESKTOP pDesktop, HANDLE hToken )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxCloseUserDesktop(_winLogonHandle, pDesktop, hToken);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::SetOption ( __in DWORD Option,
						__in ULONG_PTR Value,
						__out_opt ULONG_PTR * OldValue
						)
{
	BOOL fReturn = FALSE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Option = %d Value = %d", Option, Value);
	fReturn = _pDispatchTable->WlxSetOption(_winLogonHandle, Option, Value, OldValue);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}
	
WCHAR szCard[] = L"Fake Card";
WCHAR szReader[] = L"Fake Reader";
WCHAR szContainer[] = L"Fake Container";
WCHAR szRCryptoProvier[] = L"Fake CryptoProvier";
WLX_SC_NOTIFICATION_INFO SmartCardInfo = {szCard, szReader, szContainer, szRCryptoProvier};

BOOL CWinLogon::GetOption(
						DWORD Option,
						ULONG_PTR * Value
						)
{
	BOOL fReturn = FALSE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Option = %d", Option);
	if (_fSmartCardPresentHook && 
		(Option == WLX_OPTION_SMART_CARD_PRESENT || Option == WLX_OPTION_SMART_CARD_INFO))
	{
		switch(Option)
		{
		case WLX_OPTION_SMART_CARD_PRESENT:
			*Value = 1;
			break;
		case WLX_OPTION_SMART_CARD_INFO:
			*Value = (ULONG_PTR) &SmartCardInfo;
			break;
		}
		fReturn = TRUE;
	}
	else
	{
		fReturn = _pDispatchTable->WlxGetOption(_winLogonHandle, Option, Value);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave Value = %d", *Value);
	return fReturn;
}
VOID CWinLogon::Win31Migrate()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pDispatchTable->WlxWin31Migrate(_winLogonHandle);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

BOOL CWinLogon::QueryClientCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V1_0 pCred)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxQueryClientCredentials(pCred);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::QueryInetConnectorCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V1_0 pCred)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxQueryInetConnectorCredentials(pCred);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::QueryTsLogonCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V2_0 pCred)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxQueryTsLogonCredentials(pCred);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CWinLogon::Disconnect()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = _pDispatchTable->WlxDisconnect();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

DWORD CWinLogon::QueryTerminalServicesData( PWLX_TERMINAL_SERVICES_DATA pTSData, WCHAR * UserName, WCHAR * Domain )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	DWORD dwReturn;
	dwReturn = _pDispatchTable->WlxQueryTerminalServicesData(_winLogonHandle, pTSData, UserName, Domain);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return dwReturn;
}

DWORD CWinLogon::QueryConsoleSwitchCredentials( PWLX_CONSOLESWITCH_CREDENTIALS_INFO_V1_0 pCred )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	DWORD dwReturn;
	dwReturn = _pDispatchTable->WlxQueryConsoleSwitchCredentials(pCred);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return dwReturn;
}

VOID CWinLogon::EnableAutoLogon(PWSTR szUserName, PWSTR szPassword, PWSTR szDomain)
{
	_alUserName = szUserName;
	_alPassword = szPassword;
	_alDomain = szDomain;
	_fAutologonHook = TRUE;
}

VOID CWinLogon::DisableAutoLogon()
{
	_fAutologonHook = FALSE;
}

VOID CWinLogon::EnableRemovePolicy(HANDLE hToken, PWSTR szDesktop)
{
	_hToken = hToken;
	_fEnableRemovePolicy = TRUE;
	wcscpy_s(_szDesktop, ARRAYSIZE(_szDesktop),szDesktop);
	_dwRemovePolicyValue = GetPolicyValue(scremoveoption);
}

VOID CWinLogon::DisableRemovePolicy()
{
	_fEnableRemovePolicy = FALSE;
}

VOID CWinLogon::ExecuteRemovePolicy()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO, L"Enter");
	/*STARTUPINFO si = { sizeof si, 0, _szDesktop };
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi,sizeof(PROCESS_INFORMATION));
	BOOL fMustRevertToSelf = FALSE;
	WCHAR szRunDLLActionsLock[] = L"RUNDLL32.exe user32.dll, LockWorkStation";
	WCHAR szRunDLLActionsLogoff[] = L"RUNDLL32.exe user32.dll, ExitWindowEx";
	// disconnect : WinStationDisconnect(0, WTSGetActiveConsoleSessionId, True)
	PWSTR szCommandLine = NULL;
	__try
	{
		switch(_dwRemovePolicyValue)
		{
		case 1: // lock
			szCommandLine = szRunDLLActionsLock;
			break;
		case 2: // logoff
			szCommandLine = szRunDLLActionsLogoff;
			break;
		default:
			__leave;
		}
		 // impersonate the user to ensure that they are allowed
		// to execute the program in the first place
		if (!ImpersonateLoggedOnUser(_hToken)) {
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ImpersonateLoggedOnUser failed: %d", GetLastError());
			__leave;
		}
		fMustRevertToSelf = TRUE;
		if (!CreateProcessAsUser(_hToken, NULL, szCommandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateProcessAsUser failed for image %s with error code %d", szCommandLine, GetLastError());
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success");
	}
	__finally
	{
		if (pi.hProcess) CloseHandle(pi.hProcess);
		if (pi.hThread) CloseHandle(pi.hThread);
		if (fMustRevertToSelf) RevertToSelf();
	}*/
	DWORD dwSessionId = WTS_CURRENT_SESSION, dwSize;
	__try
	{
		if (!GetTokenInformation(_hToken, TokenSessionId, &dwSessionId, sizeof(DWORD), &dwSize))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetTokenInformation 0x%08x", GetLastError());
			__leave;
		}
		switch(_dwRemovePolicyValue)
		{
		case 1: // lock
			if (0 != GetSystemMetrics(SM_REMOTESESSION))
			{
				if (!WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, dwSessionId, FALSE))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WTSDisconnectSession 0x%08x", GetLastError());
					__leave;
				}
			}
			else
			{
				if (!LockWorkStation())
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LockWorkStation 0x%08x", GetLastError());
					__leave;
				}
			}
			break;
		case 2: // logoff
			if (!WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, dwSessionId, FALSE))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WTSLogoffSession 0x%08x", GetLastError());
				__leave;
			}
			break;
		default:
			__leave;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Success");
	}
	__finally
	{
	}
}

BOOL CWinLogon::IsRemote()
{
	return 0 != GetSystemMetrics(SM_REMOTESESSION);
}