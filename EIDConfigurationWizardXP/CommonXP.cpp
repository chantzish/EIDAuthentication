#include <windows.h>
#include <tchar.h>
#include <Lm.h>

#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/Tracing.h"
#include "EIDConfigurationWizardXP.h"

extern HINSTANCE g_hinst;

VOID CenterWindow(HWND hWnd)
{
	RECT rc;
    if (!GetWindowRect(hWnd, &rc)) return;

    const int width  = rc.right  - rc.left;
    const int height = rc.bottom - rc.top;

    MoveWindow(hWnd,
        (GetSystemMetrics(SM_CXSCREEN) - width)  / 2,
        (GetSystemMetrics(SM_CYSCREEN) - height) / 2,
        width, height, true);
}


VOID SetIcon(HWND hWnd)
{
	HMODULE hDll = LoadLibrary(TEXT("shell32.dll") );
	if (hDll)
	{
		HANDLE hbicon = LoadImage(hDll, MAKEINTRESOURCE(13),IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM) hbicon);
		hbicon = LoadImage(hDll, MAKEINTRESOURCE(13),IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0);
		if (hbicon)
			SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM) hbicon);
		FreeLibrary(hDll);
	}
}

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

BOOL IsCurrentUserBelongToADomain()
{
	BOOL fReturn = FALSE;
	HANDLE hToken	= NULL;
	PTOKEN_USER  ptiUser  = NULL;
	__try
	{
		if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) )
		{
			__leave;
		}
		
		DWORD        cbti     = 0;
		// Obtain the size of the user information in the token.
		if (GetTokenInformation(hToken, TokenUser, NULL, 0, &cbti)) {

			// Call should have failed due to zero-length buffer.
			__leave;
   
		} else {

			// Call should have failed due to zero-length buffer.
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			__leave;
		}

		// Allocate buffer for user information in the token.
		ptiUser = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), 0, cbti);
		if (!ptiUser)
			__leave;

		// Retrieve the user information from the token.
		if (!GetTokenInformation(hToken, TokenUser, ptiUser, cbti, &cbti))
			__leave;

		TCHAR szUser[255];
		DWORD cchUser = ARRAYSIZE(szUser);
		TCHAR szDomain[255];
		DWORD cchDomain = ARRAYSIZE(szDomain);
		SID_NAME_USE snu;
		if (!LookupAccountSid(NULL, ptiUser->User.Sid, szUser, &cchUser, 
            szDomain, &cchDomain, &snu))
		{
			__leave;
		}
		TCHAR szComputerName[255];
		DWORD cchComputerName = ARRAYSIZE(szComputerName);
		if (!GetComputerName(szComputerName,&cchComputerName))
		{
			__leave;
		}
		if (_tcsicmp(szComputerName,szDomain) != 0)
		{
			fReturn = TRUE;
		}
	}
	__finally
	{
		if (hToken)
			CloseHandle(hToken);
		if (ptiUser)
			HeapFree(GetProcessHeap(), 0, ptiUser);
	}
	return fReturn;
}

INT_PTR CALLBACK WndProc_ForcePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

BOOL DialogForceSmartCardLogonPolicy(HWND hWndParent)
{
	BOOL fReturn = FALSE;
	DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGFORCEPOLICY), hWndParent, WndProc_ForcePolicy);
	return fReturn;
}

INT_PTR CALLBACK	WndProc_RemovePolicy(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

BOOL DialogRemovePolicy(HWND hWndParent)
{
	BOOL fReturn = FALSE;
	DialogBox(g_hinst, MAKEINTRESOURCE(IDD_DIALOGREMOVEPOLICY), hWndParent, WndProc_RemovePolicy);
	return fReturn;
}
