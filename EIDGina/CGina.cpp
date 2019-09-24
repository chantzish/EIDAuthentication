#include <Windows.h>
#include <WinWlx.h>
#include <Ntsecapi.h>
#include "CGina.h"
#include "CWinlogon.h"
// declaration of msgina entry points
#include "MsGinaImports.h"
#include "..\EIDCardLibrary\Tracing.h"

#include "Global.h"
#include "..\EIDCardLibrary\CContainer.h"
#include "SmartCardHelper.h"
#include "PINDialog.h"

// how to force msgina to update its internal variables ?
// if we don't, we can login with success, but WlxActivateUserShell doesn't work (don't know the token returned in loggedoutsas).
// haking the msgina struct (htoken + pAuthenticationId) allows the logon, but it fail in the locked screen
// we tried to simulate a SAS event (WLX_SAS_TYPE_AUTHENTICATED) so it will read the token using WlxQueryConsoleSwitchCredentials hooked
// it works for the logon but the desktop is unreadable (refreshed like TS session) and the computer can't shutdown (the shutdown dialog never closes)
// finally, got the password and hook the gina dialog to silently input it like a user can do


#define LOADMSGINAENTRY(ENTRYPOINT) \
	pf ## ENTRYPOINT = (PF ## ENTRYPOINT) GetProcAddress(hDll, #ENTRYPOINT); \
	if (!pf ## ENTRYPOINT) \
	{ \
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"Unable to load %S 0x%08x",#ENTRYPOINT,GetLastError()); \
		__leave; \
	}

DWORD CGina::_WlxVersion = 0;

BOOL CGina::Negotiate(DWORD dwWinlogonVersion, DWORD* pdwDllVersion)
{
	BOOL fReturn = FALSE;
	HINSTANCE hDll;
	DWORD dwWlxVersion = dwWinlogonVersion;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	__try
	{
		if(!(hDll = LoadLibrary(TEXT("msgina.dll"))))
		{
			__leave;
		}
		LOADMSGINAENTRY(WlxInitialize)
		LOADMSGINAENTRY(WlxNegotiate)
		LOADMSGINAENTRY(WlxInitialize)
		LOADMSGINAENTRY(WlxDisplaySASNotice)
		LOADMSGINAENTRY(WlxLoggedOutSAS)
		LOADMSGINAENTRY(WlxActivateUserShell)
		LOADMSGINAENTRY(WlxLoggedOnSAS)
		LOADMSGINAENTRY(WlxDisplayLockedNotice)
		LOADMSGINAENTRY(WlxWkstaLockedSAS)
		LOADMSGINAENTRY(WlxIsLockOk)
		LOADMSGINAENTRY(WlxIsLogoffOk)
		LOADMSGINAENTRY(WlxLogoff)
		LOADMSGINAENTRY(WlxShutdown)
	
		//
		// Negotiate with MSGINA for version that we can support.
		//
		if(!pfWlxNegotiate(dwWinlogonVersion, &dwWlxVersion))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"pfWlxNegotiate error");
			__leave;
		}
		if (dwWlxVersion < WLX_VERSION_1_3 || dwWlxVersion > WLX_VERSION_1_4)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"version not supported %d", dwWlxVersion);
			__leave;
		}
		LOADMSGINAENTRY(WlxScreenSaverNotify)
		LOADMSGINAENTRY(WlxStartApplication)
		LOADMSGINAENTRY(WlxNetworkProviderLoad)
		LOADMSGINAENTRY(WlxDisplayStatusMessage)
		LOADMSGINAENTRY(WlxGetStatusMessage)
		LOADMSGINAENTRY(WlxRemoveStatusMessage)
		if(dwWlxVersion > WLX_VERSION_1_3)
		{
			LOADMSGINAENTRY(WlxGetConsoleSwitchCredentials)
			LOADMSGINAENTRY(WlxReconnectNotify)
			LOADMSGINAENTRY(WlxDisconnectNotify)
		}
		*pdwDllVersion = dwWlxVersion;
		CGina::SetWinLogonVersion(dwWlxVersion);
		fReturn = TRUE;
	}
	__finally
	{
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

CGina::CGina(CWinLogon* pWinLogon): _pWinLogon(pWinLogon), _hToken(0)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

CGina::~CGina()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	if (_pWinLogon) delete _pWinLogon;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

BOOL CGina::Initialize(LPWSTR                  lpWinsta,
				HANDLE                  hWlx,
				PVOID                   pvReserved,
				PVOID                   pWinlogonFunctions,
				CGina** ppNewGina)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = FALSE;
	CWinLogon* pWinLogon = NULL;
	CGina* pGina = NULL;
	pWinLogon = new CWinLogon(hWlx, CGina::GetWinLogonVersion(), pWinlogonFunctions);
	if (!pWinLogon) {
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory pWinLogon");
		return FALSE;
	}
	pGina = new CGina(pWinLogon);
	if (!pGina) {
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"Out of memory pGina");
		delete pWinLogon;
		return FALSE;
	}
	fReturn = pfWlxInitialize(lpWinsta, pWinLogon, pvReserved, (PVOID) &(pWinLogon->DispatchTable), &(pGina->pMsGinaContext));
	if (!fReturn)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR,L"pfWlxInitialize failed");
		delete pGina;
		return FALSE;
	}
	*ppNewGina = pGina;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return TRUE;
}

VOID CGina::DisplaySASNotice()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pWinLogon->DisableRemovePolicy();
	// tricky case : when in terminal server, msgina overwrite a CtrlAltDel sas 
	// even if there was another a WLX_SAS_TYPE_EID_INSERT SAS
	if (IsRemote() && _pWinLogon->_fSmartCardPresent)
	{
		//_pWinLogon->SasNotify(WLX_SAS_TYPE_EID_INSERT);
	}
	else
	{
		_pWinLogon->SetSmartCardLogonPresentHook(TRUE);
		_pWinLogon->EnableSmartCardSAS(TRUE);
		pfWlxDisplaySASNotice(pMsGinaContext);
		_pWinLogon->EnableSmartCardSAS(FALSE);
		_pWinLogon->SetSmartCardLogonPresentHook(FALSE);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	}
}

PWSTR DuplicateString(PWSTR source);

int CGina::LoggedOutSAS(
    __in DWORD                   dwSasType,
    __out PLUID                   pAuthenticationId,
    __out PSID                    pLogonSid,
    __out PDWORD                  pdwOptions,
    __out PHANDLE                 phToken,
    __out PWLX_MPR_NOTIFY_INFO    pNprNotifyInfo,
    __out PVOID *                 pProfile
    )
{
	int iReturn = WLX_SAS_ACTION_NONE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter SAS = %d", dwSasType);
	_dwLastSasType = dwSasType;
	if (dwSasType == WLX_SAS_TYPE_EID_INSERT)
	{
		PWSTR szUserName = NULL;
		PWSTR szPassword = NULL;
		PWSTR szDomain = NULL;
		if (!_pWinLogon->_fSmartCardPresent)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed ?");
			return WLX_SAS_ACTION_NONE;
		}
		PINDialog dlg(this, &szUserName, &szPassword, &szDomain);
		if (IDOK != dlg.Show())
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed ? or cancelled ?");
			return WLX_SAS_ACTION_NONE;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card card login successfull");
		
		// enable the hook - the hook is automatically disabled after one logon attempt
		EnableAutoLogon(szUserName, szPassword, szDomain);
		iReturn = pfWlxLoggedOutSAS(pMsGinaContext,WLX_SAS_TYPE_CTRL_ALT_DEL,pAuthenticationId,pLogonSid,pdwOptions,phToken,pNprNotifyInfo,pProfile);
		DisableAutoLogon();
		EIDFree(szUserName);
		EIDFree(szDomain);
		EIDFree(szPassword);
	}
	else if (dwSasType == WLX_SAS_TYPE_EID_REMOVE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed");
		iReturn = WLX_SAS_ACTION_NONE;
	}
	else
	{
		_pWinLogon->EnableSmartCardSAS(TRUE);
		iReturn = pfWlxLoggedOutSAS(pMsGinaContext,dwSasType,pAuthenticationId,pLogonSid,pdwOptions,phToken,pNprNotifyInfo,pProfile);
		_pWinLogon->EnableSmartCardSAS(FALSE);
		
	}
	if (iReturn == WLX_SAS_ACTION_LOGON)
	{
		_hToken = *phToken;
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with action = %d", iReturn);
	return iReturn;
}

BOOL CGina::ActivateUserShell(
    PWSTR                   pszDesktopName,
    PWSTR                   pszMprLogonScript,
    PVOID                   pEnvironment
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Desktop = %s", pszDesktopName);
	BOOL fReturn = pfWlxActivateUserShell(pMsGinaContext,pszDesktopName,pszMprLogonScript,pEnvironment);
	if (fReturn)
	{
		wcscpy_s(_szDesktop, ARRAYSIZE(_szDesktop),pszDesktopName);
		if (_dwLastSasType == WLX_SAS_TYPE_EID_INSERT)
		{
			_pWinLogon->EnableRemovePolicy(_hToken, _szDesktop);
		}
		else
		{
			_pWinLogon->DisableRemovePolicy();
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

/* Winlogon calls this function when it receives a secure attention sequence (SAS)
   event while the user is logged on and the workstation is not locked.*/
int CGina::LoggedOnSAS(
    DWORD                   dwSasType,
    PVOID                   pReserved
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn = pfWlxLoggedOnSAS(pMsGinaContext,dwSasType,pReserved);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return iReturn;
}

/* Winlogon calls this function when the workstation is placed in the locked state.*/
VOID CGina::DisplayLockedNotice()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pWinLogon->DisableRemovePolicy();
	if (IsRemote() // isRemote ?
		&& _pWinLogon->_fSmartCardPresent)
	{
		//_pWinLogon->SasNotify(WLX_SAS_TYPE_EID_INSERT);
	}
	else
	{
		_pWinLogon->SetSmartCardLogonPresentHook(TRUE);
		_pWinLogon->EnableSmartCardSAS(TRUE);
		pfWlxDisplayLockedNotice(pMsGinaContext);
		_pWinLogon->EnableSmartCardSAS(FALSE);
		_pWinLogon->SetSmartCardLogonPresentHook(FALSE);
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

int CGina::WkstaLockedSAS(
    DWORD                   dwSasType
    )
{
	int iReturn = WLX_SAS_ACTION_NONE;
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter SAS = %d", dwSasType);
	if (dwSasType == WLX_SAS_TYPE_EID_INSERT)
	{
		PWSTR szUserName = NULL;
		PWSTR szPassword = NULL;
		PWSTR szDomain = NULL;
		if (!_pWinLogon->_fSmartCardPresent)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed ?");
			return WLX_SAS_ACTION_NONE;
		}
		PINDialog dlg(this, &szUserName, &szPassword, &szDomain);
		if (IDOK != dlg.Show())
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed ? or cancelled ?");
			return WLX_SAS_ACTION_NONE;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card card login successfull");
		
		// enable the hooh - the hook is automatically disabled after one logon attempt
		EnableAutoLogon(szUserName, szPassword, szDomain);
		iReturn = pfWlxWkstaLockedSAS(pMsGinaContext,WLX_SAS_TYPE_CTRL_ALT_DEL);
		DisableAutoLogon();
		EIDFree(szUserName);
		EIDFree(szDomain);
		EIDFree(szPassword);
	}
	else if (dwSasType == WLX_SAS_TYPE_EID_REMOVE)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Smart card removed");
		iReturn = WLX_SAS_ACTION_NONE;
	}
	else
	{
		_pWinLogon->EnableSmartCardSAS(TRUE);
		iReturn = pfWlxWkstaLockedSAS(pMsGinaContext,dwSasType);
		_pWinLogon->EnableSmartCardSAS(FALSE);
		
	}
	if (iReturn == WLX_SAS_ACTION_UNLOCK_WKSTA)
	{
		if (dwSasType == WLX_SAS_TYPE_EID_INSERT)
		{
			_pWinLogon->EnableRemovePolicy(_hToken, _szDesktop);
		}
		else
		{
			_pWinLogon->DisableRemovePolicy();
		}
	}
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with action = %d", iReturn);
	return iReturn;
}

BOOL CGina::IsLockOk()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxIsLockOk(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CGina::IsLogoffOk()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxIsLogoffOk(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

VOID CGina::Logoff()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	pfWlxLogoff(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}


VOID CGina::Shutdown(
    DWORD                   ShutdownType
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	pfWlxShutdown(pMsGinaContext, ShutdownType);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}


//
// NEW for version 1.1
//
BOOL CGina::ScreenSaverNotify(
    BOOL *                  pSecure)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxScreenSaverNotify(pMsGinaContext, pSecure);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CGina::StartApplication(
    PWSTR                   pszDesktopName,
    PVOID                   pEnvironment,
    PWSTR                   pszCmdLine
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxStartApplication(pMsGinaContext, pszDesktopName, pEnvironment, pszCmdLine);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

//
// New for 1.3
//

BOOL CGina::NetworkProviderLoad(
    PWLX_MPR_NOTIFY_INFO    pNprNotifyInfo
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxNetworkProviderLoad(pMsGinaContext, pNprNotifyInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}


BOOL CGina::DisplayStatusMessage(
    HDESK                   hDesktop,
    DWORD                   dwOptions,
    PWSTR                   pTitle,
    PWSTR                   pMessage
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Message '%s'", pMessage);
	BOOL fReturn = pfWlxDisplayStatusMessage(pMsGinaContext, hDesktop, dwOptions, pTitle, pMessage);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CGina::GetStatusMessage(
								DWORD *                 pdwOptions,
								PWSTR                   pMessage,
								DWORD                   dwBufferSize
							    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxGetStatusMessage(pMsGinaContext, pdwOptions, pMessage, dwBufferSize);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL CGina::RemoveStatusMessage()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxRemoveStatusMessage(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}


//
// New for 1.4
//
BOOL CGina::GetConsoleSwitchCredentials (PVOID pCredInfo)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = pfWlxGetConsoleSwitchCredentials(pMsGinaContext, pCredInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

VOID CGina::ReconnectNotify ()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pWinLogon->SmartCardThreadStart();
	pfWlxReconnectNotify(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID CGina::DisconnectNotify ()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	_pWinLogon->SmartCardThreadStop();
	pfWlxDisconnectNotify(pMsGinaContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID CGina::EnableAutoLogon(PWSTR szUserName, PWSTR szPassword, PWSTR szDomain)
{
	_pWinLogon->EnableAutoLogon(szUserName, szPassword, szDomain);
	dwForcePolicy = GetPolicyValue(scforceoption);
	if (dwForcePolicy) SetPolicyValue(scforceoption,0);
	// unexpire the password ...
	PUSER_MODALS_INFO_0 pInfo = NULL;
	NET_API_STATUS status;
	_dwMaxPasswordAge = TIMEQ_FOREVER;
	USER_MODALS_INFO_1002 info;
	__try
	{
		status = NetUserModalsGet(NULL, 0, (PBYTE*) &pInfo);
		if (NERR_Success != status)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"NetUserModalsGet 0x%08X", status);
			__leave;
		}
		_dwMaxPasswordAge = pInfo->usrmod0_max_passwd_age;
		info.usrmod1002_max_passwd_age = TIMEQ_FOREVER;
		 status = NetUserModalsSet(NULL, 1002, (PBYTE) &info, NULL);
		if (NERR_Success != status)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"NetUserModalsSet 0x%08X", status);
		}
	}
	__finally
	{
		if (pInfo) NetApiBufferFree(pInfo);
	}
}

VOID CGina::DisableAutoLogon()
{
	_pWinLogon->DisableAutoLogon();
	if (dwForcePolicy) SetPolicyValue(scforceoption,dwForcePolicy);
	USER_MODALS_INFO_1002 info;
	info.usrmod1002_max_passwd_age = _dwMaxPasswordAge;
	NET_API_STATUS status = NetUserModalsSet(NULL, 1002, (PBYTE) &info, NULL);
	if (NERR_Success != status)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_ERROR, L"NetUserModalsSet 0x%08X", status);
	}
}

BOOL CGina::IsRemote()
{
	return 0 != GetSystemMetrics(SM_REMOTESESSION);
}