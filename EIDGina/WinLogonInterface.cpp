#include <Windows.h>
#include <WinWlx.h>
#include "CWinlogon.h"
#include "..\EIDCardLibrary\Tracing.h"

VOID WINAPI WlxUseCtrlAltDel(HANDLE hWlx)
{
	((CWinLogon*)hWlx)->UseCtrlAltDel();
}

VOID WINAPI WlxSetContextPointer(HANDLE hWlx, PVOID pWlxContext)
{
	((CWinLogon*)hWlx)->SetContextPointer(pWlxContext);
}

VOID WINAPI WlxSasNotify(HANDLE hWlx, DWORD dwSasType)
{
	((CWinLogon*)hWlx)->SasNotify(dwSasType);
}

BOOL WINAPI WlxSetTimeout(HANDLE hWlx,DWORD Timeout)
{
	return ((CWinLogon*)hWlx)->SetTimeout(Timeout);
}

int WINAPI WlxAssignShellProtection(
    HANDLE hWlx,
    HANDLE                  hToken,
    HANDLE                  hProcess,
    HANDLE                  hThread
    )
{
	return ((CWinLogon*)hWlx)->AssignShellProtection(hToken, hProcess, hThread);
}

int WINAPI WlxMessageBox(
    HANDLE hWlx,
    HWND  hwndOwner,
    LPWSTR                  lpszText,
    LPWSTR                  lpszTitle,
    UINT  fuStyle
    )
{
	return ((CWinLogon*)hWlx)->MessageBox(hwndOwner, lpszText, lpszTitle, fuStyle);
}

int WINAPI WlxDialogBox(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPWSTR                  lpszTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc
    )
{
	return ((CWinLogon*)hWlx)->DialogBox(hInst, lpszTemplate, hwndOwner, dlgprc);
}

int WINAPI WlxDialogBoxIndirect(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPCDLGTEMPLATE          hDialogTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc
    )
{
	return ((CWinLogon*)hWlx)->DialogBoxIndirect(hInst, hDialogTemplate, hwndOwner, dlgprc);
}

int WINAPI WlxDialogBoxParam(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPWSTR                  lpszTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc,
    LPARAM                  dwInitParam
    )
{
	return ((CWinLogon*)hWlx)->DialogBoxParam(hInst, lpszTemplate, hwndOwner, dlgprc, dwInitParam);
}

int WINAPI WlxDialogBoxIndirectParam(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPCDLGTEMPLATE          hDialogTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc,
    LPARAM                  dwInitParam
    )
{
	return ((CWinLogon*)hWlx)->DialogBoxIndirectParam(hInst, hDialogTemplate, hwndOwner, dlgprc, dwInitParam);
}

int WINAPI WlxSwitchDesktopToUser(
    HANDLE hWlx)
{
	return ((CWinLogon*)hWlx)->SwitchDesktopToUser();
}

int WINAPI WlxSwitchDesktopToWinlogon(
    HANDLE hWlx)
{
	return ((CWinLogon*)hWlx)->SwitchDesktopToWinlogon();
}


int WINAPI WlxChangePasswordNotify(
    HANDLE hWlx,
    PWLX_MPR_NOTIFY_INFO    pMprInfo,
    DWORD dwChangeInfo
    )
{
	return ((CWinLogon*)hWlx)->ChangePasswordNotify(pMprInfo, dwChangeInfo);
}

BOOL WINAPI WlxGetSourceDesktop(
    HANDLE hWlx,
    PWLX_DESKTOP *          ppDesktop)
{
	return ((CWinLogon*)hWlx)->GetSourceDesktop(ppDesktop);
}

BOOL WINAPI WlxSetReturnDesktop(
    HANDLE hWlx,
    PWLX_DESKTOP            pDesktop)
{
	return ((CWinLogon*)hWlx)->SetReturnDesktop(pDesktop);
}

BOOL WINAPI WlxCreateUserDesktop(
    HANDLE hWlx,
    HANDLE                  hToken,
    DWORD Flags,
    PWSTR pszDesktopName,
    PWLX_DESKTOP *          ppDesktop)
{
	return ((CWinLogon*)hWlx)->CreateUserDesktop(hToken, Flags, pszDesktopName, ppDesktop);
}


int WINAPI WlxChangePasswordNotifyEx(
    HANDLE hWlx,
    PWLX_MPR_NOTIFY_INFO    pMprInfo,
    DWORD dwChangeInfo,
    PWSTR ProviderName,
    PVOID Reserved)
{
	return ((CWinLogon*)hWlx)->ChangePasswordNotifyEx(pMprInfo, dwChangeInfo, ProviderName, Reserved);
}

BOOL WINAPI WlxCloseUserDesktop(
    HANDLE          hWlx,
    PWLX_DESKTOP    pDesktop,
    HANDLE          hToken )
{
	return ((CWinLogon*)hWlx)->CloseUserDesktop(pDesktop, hToken);
}



BOOL WINAPI WlxSetOption(
						__in HANDLE hWlx,
						__in DWORD Option,
						__in ULONG_PTR Value,
						__out_opt ULONG_PTR * OldValue
						)
{
	BOOL fReturn = ((CWinLogon*)hWlx)->SetOption(Option, Value, OldValue);
	return fReturn;
}

BOOL WINAPI WlxGetOption(
						HANDLE hWlx,
						DWORD Option,
						ULONG_PTR * Value
						)
{
	BOOL fReturn = ((CWinLogon*)hWlx)->GetOption(Option, Value);
	return fReturn;
}


VOID WINAPI WlxWin31Migrate(
    HANDLE hWlx
    )
{
	((CWinLogon*)hWlx)->Win31Migrate();
}

DWORD WINAPI WlxQueryTerminalServicesData(
    HANDLE hWlx,
    PWLX_TERMINAL_SERVICES_DATA pTSData,
    WCHAR * UserName,
    WCHAR * Domain
    )
{
	return ((CWinLogon*)hWlx)->QueryTerminalServicesData(pTSData, UserName, Domain);
}

