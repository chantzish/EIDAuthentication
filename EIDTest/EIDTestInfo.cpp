#include <windows.h>
#include <tchar.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Ntsecapi.h>
#include "EIDTest.h"
#include "EIDTestUIUtil.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"

extern HINSTANCE hInst;
extern HWND hMainWnd;

HWND hwndProviderDlg;

void populateAlgList()
{
	LPTSTR szProvider = NULL;
	BYTE pbData[1024];
    DWORD cbData = 1024;
	DWORD dwFlags = CRYPT_FIRST;
	BYTE* ptr;
    ALG_ID aiAlgid;
    DWORD dwBits;
    DWORD dwIncrement = sizeof(DWORD);
    DWORD dwNameLen;
    CHAR szName[100];
    TCHAR* pszAlgType = NULL;
	TCHAR szBuffer[1024];

	// prov type
	DWORD dwIndex = (DWORD) SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE, CB_GETCURSEL, 0 ,0);
	DWORD dwProviderType = (DWORD) SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_GETITEMDATA, dwIndex ,0);

	// prov name
	dwIndex = (DWORD) SendDlgItemMessage(hwndProviderDlg,IDC_PROVNAME, CB_GETCURSEL, 0 ,0);
	DWORD dwLen = (DWORD) SendDlgItemMessage(hwndProviderDlg, IDC_PROVNAME , CB_GETLBTEXTLEN, 0 ,0) + 1;
	szProvider = (LPTSTR) EIDAlloc(dwLen*sizeof(TCHAR));
	SendDlgItemMessage(hwndProviderDlg, IDC_PROVNAME , CB_GETLBTEXT,  0 , (LPARAM)szProvider);

	SendDlgItemMessage(hwndProviderDlg,IDC_LSTALG,LB_RESETCONTENT, 0, 0);
	//
	HCRYPTPROV hProv;
	BOOL fMore = TRUE;
	if(!CryptAcquireContext(
        &hProv, 
        NULL,
        szProvider,
        dwProviderType, CRYPT_VERIFYCONTEXT
        ))  
    {
		EIDFree(szProvider);
		return;
	}
		EIDFree(szProvider);

	while(fMore)
    {
        //------------------------------------------------------
        // Retrieve information about an algorithm.
        if(CryptGetProvParam(
            hProv, 
            PP_ENUMALGS, 
            pbData, 
            &cbData, 
            dwFlags))
        {       
            //-------------------------------------------------------
            // Extract algorithm information from the pbData buffer.
           dwFlags = 0;
           ptr = pbData;
           aiAlgid = *(ALG_ID *)ptr;
           ptr += sizeof(ALG_ID);
           dwBits = *(DWORD *)ptr;
           ptr += dwIncrement;
           dwNameLen = *(DWORD *)ptr;
           ptr += dwIncrement;
           strncpy_s(szName,(char *) ptr, dwNameLen);
           
            //-------------------------------------------------------
            // Determine the algorithm type.
           switch(GET_ALG_CLASS(aiAlgid)) 
           {
           case ALG_CLASS_DATA_ENCRYPT: 
               pszAlgType = TEXT("Encrypt  ");
               break;
            
            case ALG_CLASS_HASH:         
                pszAlgType = TEXT("Hash     ");
                break;

            case ALG_CLASS_KEY_EXCHANGE: 
                pszAlgType = TEXT("Exchange ");
                break;

            case ALG_CLASS_SIGNATURE:    
                pszAlgType = TEXT("Signature");
                break;

            default:
                pszAlgType = TEXT("Unknown  ");
                break;
           }

           //--------------------------------------------------------
            // Print information about the algorithm.
           _stprintf_s(szBuffer,1024,TEXT("    %8.8xh    %-4d    %s     %-2d          %S"),
                aiAlgid, 
                dwBits, 
                pszAlgType, 
                dwNameLen, 
                szName);
		   SendDlgItemMessage(hwndProviderDlg,IDC_LSTALG,LB_ADDSTRING,0,(LPARAM) szBuffer);
        }
        else
        {
            fMore = FALSE;
        }
    }
    CryptReleaseContext(hProv, 0);
}

void populateProviderName()
{
    //---------------------------------------------------------------
    // Loop through enumerating providers.
    DWORD dwIndex = 0;
    DWORD dwType;
	LPTSTR pszName;
	DWORD cbName;
	DWORD dwProviderType;
	// get the Provider type
	
	dwIndex = (DWORD) SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE, CB_GETCURSEL, 0 ,0);
	dwProviderType = (DWORD) SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_GETITEMDATA, dwIndex ,0);

	dwIndex = 0;
	SendDlgItemMessage(hwndProviderDlg,IDC_PROVNAME,CB_RESETCONTENT, 0, 0);
	while(CryptEnumProviders(
        dwIndex,
        NULL,
        0,
        &dwType,
        NULL,
        &cbName))
    {
        
		if (dwProviderType == dwType)
		{
				//-----------------------------------------------------------
			// cbName is the length of the name of the next provider.
			// Allocate memory in a buffer to retrieve that name.
			if (!(pszName = (LPTSTR)EIDAlloc(cbName)))
			{
			   break;
			}

			//-----------------------------------------------------------
			// Get the provider name.
			if (CryptEnumProviders(
				dwIndex,
				NULL,
				0,
				&dwType,
				pszName,
				&cbName))
			{
				SendDlgItemMessage(hwndProviderDlg,IDC_PROVNAME,CB_ADDSTRING,0,(LPARAM) pszName);
			}
			EIDFree(pszName);
		}
		dwIndex++;
    } // End while loop.
	SendDlgItemMessage(hwndProviderDlg,IDC_PROVNAME,CB_SETCURSEL, 0, 0);
	populateAlgList();
}


void populateProviderType()
{
// Loop through enumerating provider types.
    DWORD dwIndex = 0;
	DWORD dwType;
	LPTSTR pszName;
	DWORD cbName;
	SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_RESETCONTENT, 0, 0);
    while(CryptEnumProviderTypes(
        dwIndex,
        NULL,
        0,
        &dwType,
        NULL,
        &cbName))
    {
        //-----------------------------------------------------------
        // cbName is the length of the name of the next provider 
        // type.

        // Allocate memory in a buffer to retrieve that name.
        if (!(pszName = (LPTSTR)EIDAlloc(cbName)))
        {
           break;
        }

        //-----------------------------------------------------------
        // Get the provider type name.
        if (CryptEnumProviderTypes(
            dwIndex,
            NULL,
            NULL,
            &dwType,   
            pszName,
            &cbName))     
        {
            SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_ADDSTRING,0,(LPARAM) pszName);
			SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_SETITEMDATA,dwIndex,(WPARAM) dwType);
        }

        EIDFree(pszName);
		dwIndex++;
    }
	SendDlgItemMessage(hwndProviderDlg,IDC_PROVTYPE,CB_SETCURSEL, 0, 0);
	populateProviderName();
}

static BOOL CALLBACK SelectProviderInfoCallBack(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 

    switch (message) 
    { 
        case WM_INITDIALOG: 
			hwndProviderDlg = hwndDlg;		
			//default
			populateProviderType();

            return TRUE; 
 
        case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
                // save or cancel
				/////////////////
			case IDC_CSPOK:
				EndDialog(hwndDlg,1); 
				return TRUE;
			case IDC_CSPCANCEL:
				EndDialog(hwndDlg,0); 
				return TRUE;
			case IDC_PROVTYPE:
				if (HIWORD(wParam) == CBN_SELCHANGE) {
					populateProviderName();
				}	
				break;
			case IDC_PROVNAME:
				if (HIWORD(wParam) == CBN_SELCHANGE) {
					populateAlgList();
				}	
				break;
			default:
				return FALSE;
	        } 
			return FALSE;
		default:
			return FALSE;
    } 
    return FALSE; 
} 

DWORD SelectProviderInfo() 
{
	DWORD dwStatus;
	dwStatus = (DWORD) DialogBox(hInst, MAKEINTRESOURCE(IDD_CSPINFO), hMainWnd, (DLGPROC)SelectProviderInfoCallBack);
	// cancel or error => return
	return dwStatus;
}
	

void menu_INFO_Provider()
{
 // Declare and initialize variables.
	SelectProviderInfo();
}


void menu_INFO_ComputeHashSha1()
{
	WCHAR szPassword[256];
	BOOL fStatus;
	BYTE bHash[1024];
	WCHAR szEncryptedPassword[2048];
	DWORD dwError = 0;
	if (AskPassword(szPassword))
	{
		HCRYPTPROV hProv = NULL;
		HCRYPTHASH hHash = NULL;
		DWORD dwHashSize, dwSize;
		__try
		{
			fStatus = CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,0);
			if (!fStatus) 
			{	
				dwError = GetLastError();
				if (dwError == NTE_BAD_KEYSET)
				{
					dwError = 0;
					fStatus = CryptAcquireContext(&hProv,NULL,NULL,PROV_RSA_FULL,CRYPT_NEWKEYSET);
				}
				if (!fStatus) 
				{
					__leave;
				}
			}
			fStatus = CryptCreateHash(hProv, CALG_SHA1, NULL, 0, &hHash);
			if (!fStatus) 
			{	
				dwError = GetLastError();
				__leave;
			}
			fStatus = CryptHashData(hHash,(PBYTE) szPassword, (DWORD) wcslen(szPassword) * sizeof(WCHAR),0);
			if (!fStatus) 
			{	
				dwError = GetLastError();
				__leave;
			}
			dwSize = sizeof(DWORD);
			fStatus = CryptGetHashParam(hHash, HP_HASHSIZE, (PBYTE) &dwHashSize,&dwSize, 0);
			if (!fStatus) 
			{	
				dwError = GetLastError();
				__leave;
			}
			if (dwHashSize>sizeof(bHash)) __leave;
			fStatus = CryptGetHashParam(hHash, HP_HASHVAL, bHash,&dwHashSize, 0);
			if (!fStatus) 
			{	
				dwError = GetLastError();
				__leave;
			}
			for (DWORD i = 0; i< dwHashSize; i++)
			{
				swprintf_s(szEncryptedPassword+i*3, ARRAYSIZE(szEncryptedPassword)-i*3, L"%02X ", bHash[i]);
			}
			MessageBoxW(hMainWnd,szEncryptedPassword,L"Encrypted Password",0);
		}
		__finally
		{
			
			if (hHash) CryptDestroyHash(hHash);
			if (hProv) CryptReleaseContext(hProv, 0);
		}
	}
	if (dwError)
		MessageBoxWin32(dwError);
}

extern "C"
{
	NTSTATUS WINAPI SystemFunction007 (PUNICODE_STRING string, LPBYTE hash);
}

void menu_INFO_ComputeHashNT()
{
	WCHAR szPassword[256];
	BYTE bHash[16];
	WCHAR szEncryptedPassword[2048];
	if (AskPassword(szPassword))
	{
		UNICODE_STRING MyPass = {(USHORT) (wcslen(szPassword) * sizeof(WCHAR)),(USHORT) (wcslen(szPassword) * sizeof(WCHAR)),szPassword};
		SystemFunction007(&MyPass, bHash);
		for (DWORD i = 0; i< 16; i++)
		{
			swprintf_s(szEncryptedPassword+i*3, ARRAYSIZE(szEncryptedPassword)-i*3, L"%02X ", bHash[i]);
		}
		MessageBoxW(hMainWnd,szEncryptedPassword,L"Encrypted Password",0);
	}
}

// structure used internally by RegFindFirst/NextChange()
typedef struct _REG_CHANGE_DATA {
   HKEY   hKey;
   BOOL   bWatchSubtree;
   DWORD  dwNotifyFilter;
} REG_CHANGE_DATA, *LPREG_CHANGE_DATA;

HANDLE RegFindFirstChange( HKEY hKey, BOOL bWatchSubtree, 
      DWORD dwNotifyFilter, LPREG_CHANGE_DATA lprcd ) {

   LONG lResult;
   HANDLE hChange;

   lprcd->hKey = hKey;
   lprcd->bWatchSubtree = bWatchSubtree;
   lprcd->dwNotifyFilter = dwNotifyFilter;

   // create event to be signaled when changes occur
   hChange = CreateEvent( NULL, TRUE, FALSE, NULL );

   // request registry change notifications
   lResult = RegNotifyChangeKeyValue( lprcd->hKey,
         lprcd->bWatchSubtree, lprcd->dwNotifyFilter, 
         hChange, TRUE );

   if ( lResult != ERROR_SUCCESS ) {
      SetLastError( lResult );
      return NULL;
   }

   // It is possible that this key handle has been used to receive
   // registry notifications already. Thus, you will wait with a timeout
   // of zero to clear interim notifications that might have occurred
   if ( WaitForSingleObject( hChange, 0 ) == WAIT_OBJECT_0 ) {

      // There were some interim changes; they are cleared now, but
      // you must call the API again to request future notifications
      lResult = RegNotifyChangeKeyValue( lprcd->hKey, 
            lprcd->bWatchSubtree, lprcd->dwNotifyFilter, 
            hChange, TRUE );

      if ( lResult != ERROR_SUCCESS ) {
         SetLastError( lResult );
         return NULL;
      }
   }

   return hChange;
}


BOOL RegFindNextChange( HANDLE hChange, LPREG_CHANGE_DATA lprcd ) {
   
   LONG lResult;

   // reset the event so the handle can be waited on again
   if ( !ResetEvent( hChange ) )
      return FALSE;
   
   // If you call this function, you want to catch interim changes, 
   // so simply call the API again.
   lResult = RegNotifyChangeKeyValue( lprcd->hKey,
         lprcd->bWatchSubtree, lprcd->dwNotifyFilter, 
         hChange, TRUE );

   if ( lResult != ERROR_SUCCESS ) {
      SetLastError( lResult );
      return FALSE;
   }

   return TRUE;
}



BOOL RegFindCloseChange( HANDLE hChange ) {

   // free event
   if ( hChange ) {
      CloseHandle( hChange );
      hChange = NULL;
   }

   return TRUE;
}

HKEY hRemovePolicyKey = NULL;
HANDLE hChange = NULL;
HWND hTracingWindow;

void EndTracingCallback()
{
	if (hChange) RegFindCloseChange(hChange);
	if (hRemovePolicyKey) RegCloseKey( hRemovePolicyKey );

}

void DisplayKeys()
{
	if (!hRemovePolicyKey) return;
	DisplayTrace(hTracingWindow, TEXT("\r\nDisplay key\r\n"));
	DisplayTrace(hTracingWindow, TEXT("===========\r\n"));
	LONG lReturn;
	DWORD dwI=0, dwJ, dwDataSize, dwValueSize, dwType;
	TCHAR szValueName[256];
	TCHAR szDisplay[2048];
	PBYTE pbData;

    //parcourt la partie concernee de la base de registre
    do {
        //ouverture d'une clé
		dwDataSize = 0;
		dwValueSize = ARRAYSIZE(szValueName);
        lReturn = RegEnumValue(hRemovePolicyKey,dwI,szValueName,&dwValueSize,0,0,NULL,&dwDataSize);
		if (lReturn != ERROR_SUCCESS) 
			break;
		dwValueSize = ARRAYSIZE(szValueName);
		pbData = (PBYTE) EIDAlloc(dwDataSize);
		lReturn = RegEnumValue(hRemovePolicyKey,dwI,szValueName,&dwValueSize,0,&dwType,pbData,&dwDataSize);
		if (lReturn != ERROR_SUCCESS) 
			break;
		DisplayTrace(hTracingWindow, szValueName);
		DisplayTrace(hTracingWindow, TEXT(" : "));
		switch(dwType)
		{
		case REG_DWORD:
			_stprintf_s(szDisplay, ARRAYSIZE(szDisplay),TEXT("%d (0x%08X)"),*(PDWORD) pbData,*(PDWORD) pbData );
			DisplayTrace(hTracingWindow, szDisplay);
				break;
		case REG_SZ:
			DisplayTrace(hTracingWindow, (PTSTR) pbData);
			break;
		case REG_BINARY:
			for(dwJ = 0; dwJ < dwDataSize ; dwJ++ )
			{
				_stprintf_s(szDisplay, ARRAYSIZE(szDisplay),TEXT("%02X "),pbData[dwJ]);
				DisplayTrace(hTracingWindow, szDisplay);		
			}
			break;

		default:
			DisplayTrace(hTracingWindow, TEXT("Unable to display"));
		}
		DisplayTrace(hTracingWindow, TEXT("\r\n"));
		EIDFree(pbData);
        //si pas d'erreur
        dwI++;
    } while (lReturn != ERROR_NO_MORE_ITEMS);

}

#define REMOVALPOLICYKEY TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Removal Policy")

DWORD WINAPI menu_TRACE_REMOVE_POLICY_Thread(LPVOID lpParameter) 
{
	LONG lResult;
	REG_CHANGE_DATA   rcd;
	DWORD dwFilter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES
            | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;

	hTracingWindow = CreateDialogTracing(&EndTracingCallback);
	if (!hTracingWindow) return 0;

	lResult = RegOpenKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY ,&hRemovePolicyKey);
	if (lResult !=ERROR_SUCCESS)
	{
		DisplayTrace(hTracingWindow, TEXT("Removal Policy Service Not Launched\r\n"));
		lResult = RegCreateKey(HKEY_LOCAL_MACHINE, REMOVALPOLICYKEY, &hRemovePolicyKey);
		if (lResult != ERROR_SUCCESS)
		{
			MessageBox(hTracingWindow,TEXT("Not enough right to create Removal Policy Key"),TEXT("Error"),0);
			return 0;
		}
	}
	DisplayTrace(hTracingWindow, TEXT("Monitoring Active\r\n"));
	DisplayKeys();
	hChange = RegFindFirstChange( hRemovePolicyKey, TRUE, dwFilter, &rcd );
	while(hChange)
	{
		WaitForSingleObject( hChange, INFINITE );
		DisplayKeys();
		if (!RegFindNextChange( hChange, &rcd ) )
			break;

		
	}



	DisplayTrace(hTracingWindow, TEXT("Test"));
	return 0;
}

void menu_TRACE_REMOVE_POLICY()
{
	CreateThread(NULL, 0, menu_TRACE_REMOVE_POLICY_Thread, NULL, 0, NULL);
}


TRACEHANDLE handle;

void EndTracingCallbackTracing()
{
	if (handle)
	{
		CloseTrace(handle);
		handle = NULL;
	}

}

VOID WINAPI ProcessEvents(PEVENT_TRACE pEvent)
{
  // Is this the first event of the session? The event is available only if
  // you are consuming events from a log file, not a real-time session.
  {
    //Process the event. The pEvent->MofData member is a pointer to 
    //the event specific data, if it exists.
	  if (pEvent->MofLength && pEvent->Header.Class.Level > 0)
	  {
		DisplayTrace(hTracingWindow, (PTSTR) pEvent->MofData);
		DisplayTrace(hTracingWindow, (PTSTR) L"\r\n");
	  }
  }

  return;
}

DWORD WINAPI  menu_TRACE_TRACING_Thread(LPVOID lpParameter) 
{
	ULONG rc;
	EVENT_TRACE_LOGFILE trace;

	hTracingWindow = CreateDialogTracing(&EndTracingCallbackTracing);
	if (!hTracingWindow) return 0;

	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = TEXT("EIDCredentialProvider"); 
	trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvents);

	handle = OpenTrace(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
	  // Handle error as appropriate for your application.
	  DisplayTrace(hTracingWindow, TEXT("OpenTrace failed"));
	}
	else
	{
	  DisplayTrace(hTracingWindow, TEXT("Monitoring Active\r\n"));
	  rc = ProcessTrace(&handle, 1, 0, 0);
	  if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
	  {
		if (rc ==  0x00001069)
		{
			DisplayTrace(hTracingWindow, TEXT("Tracing was not started"));
		}
		else
		{
		  DisplayTrace(hTracingWindow, TEXT("ProcessTrace failed"));
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ProcessTrace 0x%08x",rc);
	  }

	  rc = CloseTrace(handle);
	  handle = NULL;
	}
	return 0;
}

void menu_TRACE_TRACING()
{
	CreateThread(NULL, 0, menu_TRACE_TRACING_Thread, NULL, 0, NULL);
}
