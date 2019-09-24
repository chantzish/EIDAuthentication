// WINLOGON & WLX INTERFACE STUFF

typedef BOOL (WINAPI * PFWlxNegotiate)  (DWORD, DWORD *);
typedef BOOL (WINAPI * PFWlxInitialize) (LPWSTR, HANDLE, PVOID, PVOID, PVOID *);
typedef VOID (WINAPI * PFWlxDisplaySASNotice) (PVOID);
typedef int  (WINAPI * PFWlxLoggedOutSAS) (PVOID, DWORD, PLUID, PSID, PDWORD,
                                           PHANDLE, PWLX_MPR_NOTIFY_INFO, 
                                           PVOID *);
typedef BOOL (WINAPI * PFWlxActivateUserShell) (PVOID, PWSTR, PWSTR, PVOID);
typedef int  (WINAPI * PFWlxLoggedOnSAS) (PVOID, DWORD, PVOID);
typedef VOID (WINAPI * PFWlxDisplayLockedNotice) (PVOID);
typedef int  (WINAPI * PFWlxWkstaLockedSAS) (PVOID, DWORD);
typedef BOOL (WINAPI * PFWlxIsLockOk) (PVOID);
typedef BOOL (WINAPI * PFWlxIsLogoffOk) (PVOID);
typedef VOID (WINAPI * PFWlxLogoff) (PVOID);
typedef VOID (WINAPI * PFWlxShutdown) (PVOID, DWORD);
typedef BOOL (WINAPI * PFWlxScreenSaverNotify) (PVOID, BOOL *);
typedef BOOL (WINAPI * PFWlxStartApplication) (PVOID, PWSTR, PVOID, PWSTR);
typedef BOOL (WINAPI * PFWlxNetworkProviderLoad) (PVOID, PWLX_MPR_NOTIFY_INFO);
typedef BOOL (WINAPI * PFWlxDisplayStatusMessage) (PVOID, HDESK, DWORD, PWSTR, PWSTR);
typedef BOOL (WINAPI * PFWlxGetStatusMessage) (PVOID, DWORD *, PWSTR, DWORD);
typedef BOOL (WINAPI * PFWlxRemoveStatusMessage) (PVOID);
typedef BOOL (WINAPI * PFWlxGetConsoleSwitchCredentials) (PVOID, PVOID); // New for XP
typedef BOOL (WINAPI * PFWlxReconnectNotify) (PVOID); // RDP needs this
typedef BOOL (WINAPI * PFWlxDisconnectNotify) (PVOID); // RDP needs this as well

PFWlxNegotiate                pfWlxNegotiate;
PFWlxInitialize               pfWlxInitialize;
PFWlxDisplaySASNotice         pfWlxDisplaySASNotice;
PFWlxLoggedOutSAS             pfWlxLoggedOutSAS;
PFWlxActivateUserShell        pfWlxActivateUserShell;
PFWlxLoggedOnSAS              pfWlxLoggedOnSAS;
PFWlxDisplayLockedNotice      pfWlxDisplayLockedNotice;
PFWlxWkstaLockedSAS           pfWlxWkstaLockedSAS;
PFWlxIsLockOk                 pfWlxIsLockOk;
PFWlxIsLogoffOk               pfWlxIsLogoffOk;
PFWlxLogoff                   pfWlxLogoff;
PFWlxShutdown                 pfWlxShutdown;
PFWlxScreenSaverNotify        pfWlxScreenSaverNotify;
PFWlxStartApplication         pfWlxStartApplication;
PFWlxNetworkProviderLoad      pfWlxNetworkProviderLoad;
PFWlxDisplayStatusMessage     pfWlxDisplayStatusMessage;
PFWlxGetStatusMessage         pfWlxGetStatusMessage;
PFWlxRemoveStatusMessage      pfWlxRemoveStatusMessage;
PFWlxGetConsoleSwitchCredentials	pfWlxGetConsoleSwitchCredentials; 
PFWlxReconnectNotify                pfWlxReconnectNotify;
PFWlxDisconnectNotify               pfWlxDisconnectNotify;