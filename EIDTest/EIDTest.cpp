// EIDCardLibraryTest.cpp : définit le point d'entrée pour l'application.
//
#include <ntstatus.h>
#define WIN32_NO_STATUS 1
#include <windows.h>
#include <tchar.h>

#include <Ntsecapi.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <ntsecpkg.h>

#include <Commctrl.h>
#include <crtdbg.h>

#include "stdafx.h"
#include "resource.h"

#include "EIDTest.h"
#include "CSmartCardNotifierTest.h"
//#include "CWinBioNotifierTest.h"
#include "CompleteTokenTest.h"
#include "CompleteProfileTest.h"
#include "GPOTest.h"
#include "CContainerTest.h"
#include "PackageTest.h"
#include "EIDAuthenticationPackageTest.h"
#include "EIDCredentialProviderTest.h"
#include "EIDTestUtil.h"
#include "EIDTestInfo.h"
#include "CertificateValidationTest.h"
#include "StoredCredentialManagementTest.h"
#include "SmartCardModuleTest.h"
#include "EIDSecuritySupportProviderTest.h"
#include "OnlineDatabaseTest.h"
#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/XPCompatibility.h"

#ifdef UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

// Variables globales :
HINSTANCE hInst;								// instance actuelle
HWND hMainWnd;
// Pré-déclarations des fonctions incluses dans ce module de code :

INT_PTR CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);

BOOL IsElevated()
{
	BOOL fReturn = FALSE;
	HANDLE hToken	= NULL;

	if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
	{
		return FALSE;
	}

	TOKEN_ELEVATION te = { 0 };
	DWORD dwReturnLength = 0;

	if ( GetTokenInformation(
				hToken,
				TokenElevation,
				&te,
				sizeof( te ),
				&dwReturnLength ) )
	{
		fReturn = te.TokenIsElevated ? TRUE : FALSE; 
	}

	CloseHandle(hToken);
	return fReturn;
}

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	hInst = hInstance;
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF| _CRTDBG_LEAK_CHECK_DF);
	
	int iNumArgs;
	LPWSTR *pszCommandLine =  CommandLineToArgvW(lpCmdLine,&iNumArgs);

	if (iNumArgs >= 1)
	{
		if (_tcscmp(pszCommandLine[0],TEXT("TRACE")) == 0)
		{
			if (IsElevated())
			{
				menu_TRACE_TRACING_Thread(NULL);
			}
			return 0;
		}
	}

    DialogBox (hInst, MAKEINTRESOURCE (IDD_MAIN), 0, WndProc);
    return 0;

}


//
//  FONCTION : WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  BUT :  traite les messages pour la fenêtre principale.
//
//  WM_COMMAND	- traite le menu de l'application
//  WM_PAINT	- dessine la fenêtre principale
//  WM_DESTROY	- génère un message d'arrêt et retourne
//
//
INT_PTR CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int wmId, wmEvent;
	SHSTOCKICONINFO sii = {0};
//	HICON g_hShieldIcon;
	MENUITEMINFO mii= {0};
	HMENU hmenu;
	switch (message)
	{
	case WM_INITDIALOG:
		hMainWnd = hWnd;
		
		// shield icon
		/*sii.cbSize = sizeof(sii);
		SHGetStockIconInfo(SIID_SHIELD, SHGFI_ICON | SHGFI_SMALLICON, &sii);
		g_hShieldIcon = sii.hIcon;
		mii.cbSize = sizeof(mii);
		mii.fMask = MIIM_BITMAP | MIIM_DATA;
		mii.hbmpItem = HBMMENU_CALLBACK;
		mii.dwItemData = (ULONG_PTR)g_hShieldIcon;
		
		SetMenuItemInfo(GetMenu(hWnd), IDM_CRED_RP_TRIGGER, FALSE, &mii);
		SetMenuItemInfo(GetMenu(hWnd), IDM_INFO_TRACING, FALSE, &mii);*/
		// default authentication mean
		CheckMenuRadioItem(GetMenu(hWnd),IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_SSPI,MF_BYCOMMAND);
		SetAuthentication(SSPI);
		return TRUE;
		break;

	case WM_MEASUREITEM:
	{
		LPMEASUREITEMSTRUCT pms = (LPMEASUREITEMSTRUCT)lParam;
		if (pms->CtlType == ODT_MENU) {
			pms->itemWidth  = 16;
			pms->itemHeight = 16;
			return TRUE;
		} 
	}
	break;

	case WM_DRAWITEM: 
	{
	   LPDRAWITEMSTRUCT pds = (LPDRAWITEMSTRUCT)lParam;
	   if (pds->CtlType == ODT_MENU) {
		   DrawIconEx(pds->hDC, pds->rcItem.left - 15, 
			   pds->rcItem.top, 
			   (HICON)pds->itemData, 
			   16, 16, 0, NULL, DI_NORMAL);
		   return TRUE;
	   }
	}
	break; 

	case WM_CLOSE:
         EndDialog(hWnd, IDOK);
		return TRUE;
	case WM_COMMAND:
		wmId    = LOWORD(wParam);
		wmEvent = HIWORD(wParam);
		// Analyse les sélections de menu :
		switch (wmId)
		{
	// test thread detection function	
		case IDM_STARTWAITTHREAD:
			Menu_STARTWAITTHREAD();
			break;
		case IDM_STOPWAITTHREAD:
			Menu_STOPWAITTHREAD();
			break;
		case IDM_WINBIOSTARTWAITTHREAD:
			//Menu_WINBIOSTARTWAITTHREAD();
			break;
		case IDM_WINBIOSTOPWAITTHREAD:
			//Menu_WINBIOSTOPWAITTHREAD();
			break;
	// test authentification package
		case IDM_AP_TOKEN:
			 Menu_AP_Token();
			break;
		case IDM_AP_PROFILE:
			Menu_AP_Profile();
			break;
		case IDM_AP_REGISTRATION:
			Menu_TestPackageRegistration();
			break;
		case IDM_AP_PROTECT:
			menu_AP_Protect();
			break;
		case IDM_AP_LOAD:
			Menu_TestPackageLoad();
			break;
		case IDM_AP_GPO:
			Menu_AP_GPO();
			break;
		case IDM_AP_EXCEPTION:
			Menu_AP_Exception();
			break;
		case IDM_CRED_RP_TRACE:
			menu_TRACE_REMOVE_POLICY();
			break;
		case IDM_CRED_RP_TRIGGER:
			menu_CRED_RP_Trigger();
			break;
		case IDM_CRED_LSA:
			hmenu = GetMenu(hWnd);
			CheckMenuRadioItem(hmenu,IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_LSA,MF_BYCOMMAND);
			SetAuthentication(LSA);
			break;
		case IDM_CRED_NEGOTIATE:
			hmenu = GetMenu(hWnd);
			CheckMenuRadioItem(hmenu,IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_NEGOTIATE,MF_BYCOMMAND);
			SetAuthentication(Negociate);
			break;
		case IDM_CRED_NTLM:
			hmenu = GetMenu(hWnd);
			CheckMenuRadioItem(hmenu,IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_NTLM,MF_BYCOMMAND);
			SetAuthentication(NTLM);
			break;
		case IDM_CRED_SSPI:
			hmenu = GetMenu(hWnd);
			CheckMenuRadioItem(hmenu,IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_SSPI,MF_BYCOMMAND);
			SetAuthentication(SSPI);
			break;
		case IDM_CRED_CredSSP:
			hmenu = GetMenu(hWnd);
			CheckMenuRadioItem(hmenu,IDM_CRED_LSA,IDM_CRED_CredSSP,IDM_CRED_CredSSP,MF_BYCOMMAND);
			SetAuthentication(CredSSP);
			break;
		case IDM_CRED_UI:
			Menu_CREDENTIALUID();
			break;
		case IDM_CRED_UI_ADMIN:
			Menu_CREDENTIALUID_ADMIN();
			break;
		case IDM_CRED_ONLYEID:
			Menu_CREDENTIALUID_ONLY_EID();
			break;
		case IDM_CRED_OLD:
			menu_CREDENTIALUID_OldBehavior();
			break;
		case IDM_CREDSSP_REG_DEL:
			menu_CREDSSP_DEL_REG();
			break;
		case IDM_CREDSSP_REG_ADD:
			menu_CREDSSP_ADD_REG();
			break;
		case IDM_CRED_LIST:
			menu_CREDENTIAL_List();
			break;
		case IDM_CRED_CSPINFO:
			menu_CREDENTIAL_CspInfo();
			break;
		case IDM_CRED_LOGONSTRUCT:
			menu_CREDENTIAL_AllocateLogonStruct();
			break;
		case IDM_CRED_CERT:
			menu_CREDENTIAL_Certificate();
			break;
		case IDM_CRED_TILE:
			menu_CRED_CallAuthPackage();
			break;
		case IDM_CRED_COM:
			menu_CRED_COM();
			break;
		case IDM_CRED_RESETPASS:
			menu_ResetPasswordWizard();
			break;
		case IDM_SSP_ACQUIRE:
			menu_SSP_AcquireCredentialHandle();
			break;
		case IDM_SSP_LOGIN:
			menu_SSP_login();
			break;
		case IDM_PASS_CREATE:
			menu_CREDMGMT_CreateStoredCredential(TRUE);
			break;
		case IDM_PASS_CREATE2:
			menu_CREDMGMT_CreateStoredCredential(FALSE);
			break;
		case IDM_PASS_UPDATE:
			menu_CREDMGMT_UpdateStoredCredential();
			break;
		case IDM_PASS_DELETE:
			menu_CREDMGMT_DeleteStoredCredential();
			break;
		case IDM_PASS_RETRIEVE:
			menu_CREDMGMT_RetrieveStoredCredential();
			break;
		case IDM_REG_AP:
			EIDAuthenticationPackageDllRegister();
			break;
		case IDM_UNREG_AP:
			EIDAuthenticationPackageDllUnRegister();
			break;
		case IDM_REG_CP:
			EIDCredentialProviderDllRegister();
			break;
		case IDM_UNREG_CP:
			EIDCredentialProviderDllUnRegister();
			break;
		case IDM_REG_PF:
			EIDPasswordChangeNotificationDllRegister();
			break;
		case IDM_UNREG_PF:
			EIDPasswordChangeNotificationDllUnRegister();
			break;
		case IDM_REG_WIZ:
			EIDConfigurationWizardDllRegister();
			break;
		case IDM_UNREG_WIZ:
			EIDConfigurationWizardDllUnRegister();
			break;
		case IDM_ONLINE_OK:
			menu_Wizard_CommunicateTestOK();
			break;
		case IDM_UTIL_LIST:
			menu_UTIL_ListCertificates();
			break;
		case IDM_UTIL_CERT:
			menu_UTIL_CreateCert();
			break;
		case IDM_UTIL_SHOWSD:
			menu_UTIL_ShowSecurityDescriptor();
			break;
		case IDM_UTIL_DELETE:
			menu_UTIL_DeleteOneCertificate();
			break;
		case IDM_UTIL_CLEAR:
			menu_UTIL_ClearCard();
			break;
		case IDM_UTIL_CSPINFO:
			menu_UTIL_DisplayCSPInfoFromUserCertificate();
			break;
		case IDM_UTIL_SETSMARTCARDFLAG:
			menu_UTIL_ChangeUserFlag(TRUE);
			break;
		case IDM_UTIL_UNSETSMARTCARDFLAG:
			menu_UTIL_ChangeUserFlag(FALSE);
			break;
		case IDM_INFO_TRACING:
			if (IsElevated())
			{
				menu_TRACE_TRACING();
			}
			else
			{
				// elevate
				SHELLEXECUTEINFO shExecInfo;
				TCHAR szName[1024];
				GetModuleFileName(GetModuleHandle(NULL),szName, ARRAYSIZE(szName));
				shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);

				shExecInfo.fMask = NULL;
				shExecInfo.hwnd = NULL;
				shExecInfo.lpVerb = TEXT("runas");
				shExecInfo.lpFile = szName;
				shExecInfo.lpParameters = TEXT("TRACE");
				shExecInfo.lpDirectory = NULL;
				shExecInfo.nShow = SW_NORMAL;
				shExecInfo.hInstApp = NULL;

				ShellExecuteEx(&shExecInfo);
			}
			break;
		case IDM_INFO_CSP:
			menu_INFO_Provider();
			break;
		case IDM_INFO_HASHSHA1:
			menu_INFO_ComputeHashSha1();
			break;
		case IDM_INFO_HASHNT:
			menu_INFO_ComputeHashNT();
			break;
		case IDM_SM_KSP:
			test_SmartCardModule();
			break;
		case IDM_EXIT:
			DestroyWindow(hWnd);
			break;
		default:
			return FALSE;
		}
		
		
		
	//_CrtDumpMemoryLeaks();
		break;
	default:
		return FALSE;
	}
	return FALSE;
}
