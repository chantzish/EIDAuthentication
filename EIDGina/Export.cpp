#include <windows.h>
#include <winwlx.h>

#include "..\EIDCardLibrary\Tracing.h"
#include "CGina.h"
//
// Hook into the real MSGINA.
//

DWORD g_WlxVersion = 0;


/* The WlxNegotiate function must be implemented by a replacement GINA DLL. 
This is the first call made by Winlogon to the GINA DLL. WlxNegotiate allows
the GINA to verify that it supports the installed version of Winlogon. */

BOOL WINAPI WlxNegotiate (DWORD   dwWinlogonVersion,  DWORD *pdwDllVersion)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = CGina::Negotiate(dwWinlogonVersion, pdwDllVersion);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}


BOOL WINAPI WlxInitialize(
    LPWSTR                  lpWinsta,
    HANDLE                  hWlx,
    PVOID                   pvReserved,
    PVOID                   pWinlogonFunctions,
    PVOID *                 pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = CGina::Initialize(lpWinsta, hWlx, pvReserved, pWinlogonFunctions, (CGina**) pWlxContext);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

VOID WINAPI WlxDisplaySASNotice(
    PVOID                   pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->DisplaySASNotice();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

#define TRANSLATETOSTRING(action) \
	case action: \
	szReturn = L#action ; \
		break;
PWSTR GetSASResult(int iReturn)
{
	PWSTR szReturn = L"Unknown";
	switch(iReturn)
	{
		TRANSLATETOSTRING(WLX_SAS_ACTION_LOGON)
		TRANSLATETOSTRING(WLX_SAS_ACTION_NONE)
		TRANSLATETOSTRING(WLX_SAS_ACTION_LOCK_WKSTA)
		TRANSLATETOSTRING(WLX_SAS_ACTION_LOGOFF)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN)
		TRANSLATETOSTRING(WLX_SAS_ACTION_PWD_CHANGED)
		TRANSLATETOSTRING(WLX_SAS_ACTION_TASKLIST)
		TRANSLATETOSTRING(WLX_SAS_ACTION_UNLOCK_WKSTA)
		TRANSLATETOSTRING(WLX_SAS_ACTION_FORCE_LOGOFF)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN_POWER_OFF)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN_REBOOT)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN_SLEEP)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN_SLEEP2)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SHUTDOWN_HIBERNATE)
		TRANSLATETOSTRING(WLX_SAS_ACTION_RECONNECTED)
		TRANSLATETOSTRING(WLX_SAS_ACTION_DELAYED_FORCE_LOGOFF)
		TRANSLATETOSTRING(WLX_SAS_ACTION_SWITCH_CONSOLE)
	}
	return szReturn;
}

/* Winlogon calls this function when it receives a secure attention sequence (SAS)
   event while no user is logged on.*/
int WINAPI WlxLoggedOutSAS(
    __in PVOID                   pWlxContext,
    __in DWORD                   dwSasType,
    __out PLUID                   pAuthenticationId,
    __out PSID                    pLogonSid,
    __out PDWORD                  pdwOptions,
    __out PHANDLE                 phToken,
    __out PWLX_MPR_NOTIFY_INFO    pNprNotifyInfo,
    __out PVOID *                 pProfile
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter SAS = %d", dwSasType);
	int iReturn = ((CGina*)pWlxContext)->LoggedOutSAS(dwSasType, pAuthenticationId, pLogonSid, pdwOptions, phToken, pNprNotifyInfo, pProfile);
	
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with action = %s", GetSASResult(iReturn));
	return iReturn;
}

/* Winlogon calls this function following a successful logon to request that 
   the GINA activate the shell program of the user.*/
BOOL WINAPI WlxActivateUserShell(
    PVOID                   pWlxContext,
    PWSTR                   pszDesktopName,
    PWSTR                   pszMprLogonScript,
    PVOID                   pEnvironment
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->ActivateUserShell(pszDesktopName,pszMprLogonScript,pEnvironment);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

/* Winlogon calls this function when it receives a secure attention sequence (SAS)
   event while the user is logged on and the workstation is not locked.*/
int WINAPI WlxLoggedOnSAS(
    PVOID                   pWlxContext,
    DWORD                   dwSasType,
    PVOID                   pReserved
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn = ((CGina*)pWlxContext)->LoggedOnSAS(dwSasType,pReserved);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with action = %s", GetSASResult(iReturn));
	return iReturn;
}

/* Winlogon calls this function when the workstation is placed in the locked state.*/
VOID WINAPI WlxDisplayLockedNotice(
    PVOID                   pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->DisplayLockedNotice();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

int WINAPI WlxWkstaLockedSAS(
    PVOID                   pWlxContext,
    DWORD                   dwSasType
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	int iReturn = ((CGina*)pWlxContext)->WkstaLockedSAS(dwSasType);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with action = %s", GetSASResult(iReturn));
	return iReturn;
}

BOOL WINAPI WlxIsLockOk(
    PVOID                   pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->IsLockOk();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL WINAPI WlxIsLogoffOk(
    PVOID                   pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->IsLogoffOk();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

VOID WINAPI WlxLogoff(
    PVOID                   pWlxContext
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->Logoff();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}


VOID WINAPI WlxShutdown(
    PVOID                   pWlxContext,
    DWORD                   ShutdownType
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->Shutdown(ShutdownType);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}


//
// NEW for version 1.1
//
BOOL WINAPI WlxScreenSaverNotify(
    PVOID                   pWlxContext,
    BOOL *                  pSecure)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->ScreenSaverNotify(pSecure);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL WINAPI WlxStartApplication(
    PVOID                   pWlxContext,
    PWSTR                   pszDesktopName,
    PVOID                   pEnvironment,
    PWSTR                   pszCmdLine
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->StartApplication(pszDesktopName, pEnvironment, pszCmdLine);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

//
// New for 1.3
//

BOOL WINAPI WlxNetworkProviderLoad(
    PVOID                   pWlxContext,
    PWLX_MPR_NOTIFY_INFO    pNprNotifyInfo
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->NetworkProviderLoad(pNprNotifyInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}


BOOL WINAPI WlxDisplayStatusMessage(
    PVOID                   pWlxContext,
    HDESK                   hDesktop,
    DWORD                   dwOptions,
    PWSTR                   pTitle,
    PWSTR                   pMessage
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->DisplayStatusMessage(hDesktop, dwOptions, pTitle, pMessage);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL WINAPI WlxGetStatusMessage(
								PVOID                   pWlxContext,
								DWORD *                 pdwOptions,
								PWSTR                   pMessage,
								DWORD                   dwBufferSize
							    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->GetStatusMessage(pdwOptions, pMessage, dwBufferSize);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

BOOL WINAPI WlxRemoveStatusMessage(PVOID                   pWlxContext)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->RemoveStatusMessage();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}


//
// New for 1.4
//
BOOL WINAPI WlxGetConsoleSwitchCredentials (
											PVOID                   pWlxContext,
											PVOID                   pCredInfo
											)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	BOOL fReturn = ((CGina*)pWlxContext)->GetConsoleSwitchCredentials(pCredInfo);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return fReturn;
}

VOID WINAPI WlxReconnectNotify (
								PVOID                   pWlxContext
								)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->ReconnectNotify();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}

VOID WINAPI WlxDisconnectNotify (PVOID                   pWlxContext)
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	((CGina*)pWlxContext)->DisconnectNotify();
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
}