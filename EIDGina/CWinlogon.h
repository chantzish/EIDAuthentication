#undef DialogBox
#undef DialogBoxIndirect

#pragma once

#include "..\EIDCardLibrary\CSmartCardNotifier.h"

struct THUNK
{
#pragma pack(push, 1)
  unsigned short stub1;      // lea ecx, 
  unsigned long  nThisPtr;   // this
  unsigned char  stub2;      // mov eax,
  unsigned long  nJumpProc;  // pointer to destination function
  unsigned short stub3;      // jmp eax
#pragma pack(pop)
};

class CWinLogon : public ISmartCardConnectionNotifierRef 
{
public:
	CWinLogon (HANDLE                  hWlx,
				DWORD                   dwWinLogonVersion,
				PVOID                   pWinlogonFunctions);
	~CWinLogon();

	VOID UseCtrlAltDel();
	VOID SetContextPointer(PVOID pWlxContext);
	VOID SasNotify(DWORD dwSasType);
	BOOL SetTimeout(DWORD Timeout);
	int AssignShellProtection(HANDLE hToken, HANDLE hProcess, HANDLE hThread);
	int MessageBox(HWND hwndOwner, LPWSTR lpszText, LPWSTR lpszTitle, UINT fuStyle);
	int DialogBox( HANDLE hInst, LPWSTR lpszTemplate, HWND hwndOwner, DLGPROC dlgprc);
	int DialogBoxIndirect(HANDLE hInst, LPCDLGTEMPLATE hDialogTemplate, HWND hwndOwner, DLGPROC dlgprc);
	int DialogBoxParam(HANDLE hInst, LPWSTR lpszTemplate, HWND hwndOwner, DLGPROC dlgprc, LPARAM dwInitParam);
	int DialogBoxIndirectParam(HANDLE hInst, LPCDLGTEMPLATE hDialogTemplate, HWND hwndOwner, DLGPROC dlgprc, LPARAM dwInitParam );
	int SwitchDesktopToUser();
	int SwitchDesktopToWinlogon();
	int ChangePasswordNotify(PWLX_MPR_NOTIFY_INFO pMprInfo, DWORD dwChangeInfo);
	BOOL GetSourceDesktop(PWLX_DESKTOP * ppDesktop);
	BOOL SetReturnDesktop(PWLX_DESKTOP pDesktop);
	BOOL CreateUserDesktop(HANDLE hToken, DWORD Flags, PWSTR pszDesktopName, PWLX_DESKTOP * ppDesktop);
	int ChangePasswordNotifyEx(PWLX_MPR_NOTIFY_INFO pMprInfo, DWORD dwChangeInfo, PWSTR ProviderName, PVOID Reserved);
	BOOL CloseUserDesktop(PWLX_DESKTOP pDesktop, HANDLE hToken );
	BOOL SetOption ( __in DWORD Option, __in ULONG_PTR Value, __out_opt ULONG_PTR * OldValue);
	BOOL GetOption(__in DWORD Option,__out ULONG_PTR * Value);
	VOID Win31Migrate();
	BOOL QueryClientCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V1_0 pCred);
	BOOL QueryInetConnectorCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V1_0 pCred);
	BOOL QueryTsLogonCredentials(PWLX_CLIENT_CREDENTIALS_INFO_V2_0 pCred);
	BOOL Disconnect();
	DWORD QueryTerminalServicesData( PWLX_TERMINAL_SERVICES_DATA pTSData, WCHAR * UserName, WCHAR * Domain );
	DWORD QueryConsoleSwitchCredentials( PWLX_CONSOLESWITCH_CREDENTIALS_INFO_V1_0 pCred );
	// behovior of the hooks
	VOID SetSmartCardLogonPresentHook(BOOL fSet) { _fSmartCardPresentHook = fSet;}
	VOID EnableSmartCardSAS(BOOL fSet) { _fSmartCardSAS = fSet;}
	VOID EnableAutoLogon(PWSTR szUserName, PWSTR szPassword, PWSTR szDomain);
	VOID DisableAutoLogon();
	WLX_DISPATCH_VERSION_1_4 DispatchTable;
	// custom dlg proc
	INT_PTR LoggedOutSASDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	INT_PTR DisplaySASNoticeDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	INT_PTR WkstaLockedSASDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	INT_PTR DisplayLockedNoticeDlgProc (HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
	// remove policy
	VOID EnableRemovePolicy(HANDLE hToken, PWSTR szDesktop);
	VOID DisableRemovePolicy();

	BOOL _fSmartCardPresent;
	WCHAR _szReader[255];
	WCHAR _szCard[255];
	USHORT _ActivityCount;
	HWND _LastHwndUsed;
	// terminal server
	VOID SmartCardThreadStop() {if (_pSmartCardConnectionNotifier) _pSmartCardConnectionNotifier->Stop();}
	VOID SmartCardThreadStart() {if (_pSmartCardConnectionNotifier) _pSmartCardConnectionNotifier->Start();}
	// messagebox / error detection
	DWORD GetMessageBoxCount() {return _dwMessageBoxCount;}
private:
	CWinLogon();
    HANDLE _winLogonHandle;
    DWORD  _winLogonVersion;
    PWLX_DISPATCH_VERSION_1_4  _pDispatchTable;
	// flags
	BOOL _fSmartCardPresentHook;
	BOOL _fSmartCardSAS;

	// autologon
	BOOL _fAutologonHook;
	DLGPROC _pfOriginalDlgProc;
	PWSTR _alUserName;
	PWSTR _alPassword;
	PWSTR _alDomain;
	// messagebox
	DWORD _dwMessageBoxCount;
	// remove policy
	BOOL _fEnableRemovePolicy;
	HANDLE _hToken;
	WCHAR _szDesktop[256];
	DWORD _dwRemovePolicyValue;
	VOID ExecuteRemovePolicy();
	BOOL IsRemote();
protected:
	PVOID CreateThunk(ULONG somefunction);
	CSmartCardConnectionNotifier*			_pSmartCardConnectionNotifier;
	void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) ;
};