
VOID WINAPI WlxUseCtrlAltDel(HANDLE hWlx);
VOID WINAPI WlxSetContextPointer(HANDLE hWlx, PVOID pWlxContext);
VOID WINAPI WlxSasNotify(HANDLE hWlx, DWORD dwSasType);
BOOL WINAPI WlxSetTimeout(HANDLE hWlx,DWORD Timeout);
int WINAPI WlxAssignShellProtection(
    HANDLE hWlx,
    HANDLE                  hToken,
    HANDLE                  hProcess,
    HANDLE                  hThread
    );
int WINAPI WlxMessageBox(
    HANDLE hWlx,
    HWND  hwndOwner,
    LPWSTR                  lpszText,
    LPWSTR                  lpszTitle,
    UINT  fuStyle
    );
int WINAPI WlxDialogBox(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPWSTR                  lpszTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc
    );
int WINAPI WlxDialogBoxIndirect(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPCDLGTEMPLATE          hDialogTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc
    );
int WINAPI WlxDialogBoxParam(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPWSTR                  lpszTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc,
    LPARAM                  dwInitParam
    );
int WINAPI WlxDialogBoxIndirectParam(
    HANDLE hWlx,
    HANDLE                  hInst,
    LPCDLGTEMPLATE          hDialogTemplate,
    HWND  hwndOwner,
    DLGPROC                 dlgprc,
    LPARAM                  dwInitParam
    );
int WINAPI WlxSwitchDesktopToUser(HANDLE hWlx);
int WINAPI WlxSwitchDesktopToWinlogon(HANDLE hWlx);
int WINAPI WlxChangePasswordNotify(
    HANDLE hWlx,
    PWLX_MPR_NOTIFY_INFO    pMprInfo,
    DWORD dwChangeInfo
    );
BOOL WINAPI WlxGetSourceDesktop(HANDLE hWlx, PWLX_DESKTOP *ppDesktop);
BOOL WINAPI WlxSetReturnDesktop(HANDLE hWlx, PWLX_DESKTOP pDesktop);
BOOL WINAPI WlxCreateUserDesktop(
    HANDLE hWlx,
    HANDLE                  hToken,
    DWORD Flags,
    PWSTR pszDesktopName,
    PWLX_DESKTOP *          ppDesktop);
int WINAPI WlxChangePasswordNotifyEx(
    HANDLE hWlx,
    PWLX_MPR_NOTIFY_INFO    pMprInfo,
    DWORD dwChangeInfo,
    PWSTR ProviderName,
    PVOID Reserved);
BOOL WINAPI WlxCloseUserDesktop(
    HANDLE          hWlx,
    PWLX_DESKTOP    pDesktop,
    HANDLE          hToken );
BOOL WINAPI WlxSetOption(
						__in HANDLE hWlx,
						__in DWORD Option,
						__in ULONG_PTR Value,
						__out_opt ULONG_PTR * OldValue
						);
BOOL WINAPI WlxGetOption(
						HANDLE hWlx,
						DWORD Option,
						ULONG_PTR * Value
						);
VOID WINAPI WlxWin31Migrate(
    HANDLE hWlx
    );
DWORD WINAPI WlxQueryTerminalServicesData(
    HANDLE hWlx,
    PWLX_TERMINAL_SERVICES_DATA pTSData,
    WCHAR * UserName,
    WCHAR * Domain
    );
