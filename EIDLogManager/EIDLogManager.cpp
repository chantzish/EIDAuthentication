// EIDLogManager.cpp : définit le point d'entrée pour l'application.
//

#include "stdafx.h"
#include "EIDLogManager.h"
#include <tchar.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Shobjidl.h>
#include <Shlobj.h>
#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/Tracing.h"

#pragma comment(lib,"comctl32")
#pragma comment(lib,"Shell32")
#pragma comment(lib,"crypt32")

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

#define CLSCTX_INPROC_SERVER  1

// Variables globales :
HINSTANCE hInst;								// instance actuelle

INT_PTR CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

 	DialogBox(hInst, MAKEINTRESOURCE(IDD_EIDLOGMANAGER_DIALOG), NULL, WndProc);
}

void SaveLog(HWND hDlg);
void DeleteLog(HWND hDlg);

void ShowHideLogButtons(HWND hDlg)
{
	if (IsLoggingEnabled())
	{
		EnableWindow(GetDlgItem(hDlg,IDC_ENABLELOG), FALSE);
		EnableWindow(GetDlgItem(hDlg,IDC_DISABLELOG), TRUE);
	}
	else
	{
		EnableWindow(GetDlgItem(hDlg,IDC_ENABLELOG), TRUE);
		EnableWindow(GetDlgItem(hDlg,IDC_DISABLELOG), FALSE);
	}
}

void ShowHideCrashDumpButtons(HWND hDlg)
{
	if (IsCrashDumpEnabled())
	{
		EnableWindow(GetDlgItem(hDlg,IDC_ENABLECRASHDUMP), FALSE);
		EnableWindow(GetDlgItem(hDlg,IDC_DISABLECRASHDUMP), TRUE);
	}
	else
	{
		EnableWindow(GetDlgItem(hDlg,IDC_ENABLECRASHDUMP), TRUE);
		EnableWindow(GetDlgItem(hDlg,IDC_DISABLECRASHDUMP), FALSE);
	}
}
// Gestionnaire de messages pour la boîte de dialogue À propos de.
INT_PTR CALLBACK WndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(lParam);
	switch (message)
	{
		case WM_CLOSE:
          EndDialog(hDlg, 0);
          break;

		case WM_INITDIALOG:
			ShowHideLogButtons(hDlg);
			ShowHideCrashDumpButtons(hDlg);
			return (INT_PTR)TRUE;

		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case IDC_ENABLELOG:
					if (!EnableLogging())
					{
						MessageBoxWin32Ex(GetLastError(), hDlg);
					}
					/*else
					{
						MessageBoxWin32Ex(0, hDlg);
					}*/
					ShowHideLogButtons(hDlg);
					break;	
				case IDC_DISABLELOG:
					if (!DisableLogging())
					{
						MessageBoxWin32Ex(GetLastError(), hDlg);
					}
					/*else
					{
						MessageBoxWin32Ex(0, hDlg);
					}*/
					ShowHideLogButtons(hDlg);
					break;
				case IDC_SAVELOG:
					SaveLog(hDlg);
					break;
				case IDC_CLEARLOG:
					DeleteLog(hDlg);
					break;
				case IDC_ENABLECRASHDUMP:
					{
						TCHAR strPath[ MAX_PATH ];
						SHGetSpecialFolderPath(hDlg,  strPath, CSIDL_DESKTOPDIRECTORY, FALSE );
						EnableCrashDump(strPath);
						ShowHideCrashDumpButtons(hDlg);
					}
					break;
				case IDC_DISABLECRASHDUMP:
					DisableCrashDump();
					ShowHideCrashDumpButtons(hDlg);
					break;
			}
			break;
	}
	return (INT_PTR)FALSE;
}

HANDLE hFile = NULL;

VOID WINAPI ProcessEvents(PEVENT_TRACE pEvent)
{
  // Is this the first event of the session? The event is available only if
  // you are consuming events from a log file, not a real-time session.
  {
    //Process the event. The pEvent->MofData member is a pointer to 
    //the event specific data, if it exists.
	  if (pEvent->MofLength && pEvent->Header.Class.Level > 0)
	  {
		DWORD dwWritten;
		FILETIME ft;
		SYSTEMTIME st;
		ft.dwHighDateTime = pEvent->Header.TimeStamp.HighPart;
		ft.dwLowDateTime = pEvent->Header.TimeStamp.LowPart;
		FileTimeToSystemTime(&ft,&st);
		TCHAR szLocalDate[255], szLocalTime[255];
		_stprintf_s(szLocalDate, ARRAYSIZE(szLocalDate),TEXT("%04d-%02d-%02d"),st.wYear,st.wMonth,st.wDay);
		_stprintf_s(szLocalTime, ARRAYSIZE(szLocalTime),TEXT("%02d:%02d:%02d"),st.wHour,st.wMinute,st.wSecond);
		WriteFile ( hFile, szLocalDate, (DWORD)_tcslen(szLocalDate) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, szLocalTime, (DWORD)_tcslen(szLocalTime) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT(";"), 1 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, pEvent->MofData, (DWORD)_tcslen((PTSTR) pEvent->MofData) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, TEXT("\r\n"), 2 * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
	  }
  }

  return;
}

void ExportOneTraceFile(PTSTR szTraceFile)
{
	TRACEHANDLE handle = NULL;
	ULONG rc;
	EVENT_TRACE_LOGFILE trace;
	memset(&trace,0, sizeof(EVENT_TRACE_LOGFILE));
	trace.LoggerName = TEXT("EIDCredentialProvider"); 
	//trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
	trace.LogFileName = szTraceFile;
	trace.EventCallback = (PEVENT_CALLBACK) (ProcessEvents);
	handle = OpenTrace(&trace);
	if ((TRACEHANDLE)INVALID_HANDLE_VALUE == handle)
	{
		// Handle error as appropriate for your application.
	}
	else
	{
		FILETIME now, start;
		SYSTEMTIME sysNow, sysstart;
		GetLocalTime(&sysNow);
		SystemTimeToFileTime(&sysNow, &now);
		memcpy(&sysstart, &sysNow, sizeof(SYSTEMTIME));
		sysstart.wYear -= 1;
		SystemTimeToFileTime(&sysstart, &start);
		DWORD dwWritten;
		TCHAR szBuffer[256];
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		WriteFile ( hFile, szTraceFile, (DWORD)_tcslen(szTraceFile) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		_tcscpy_s(szBuffer,ARRAYSIZE(szBuffer),TEXT("================================================\r\n"));
		WriteFile ( hFile, szBuffer, (DWORD)_tcslen(szBuffer) * (DWORD)sizeof(TCHAR), &dwWritten, NULL);
		rc = ProcessTrace(&handle, 1, 0, 0);
		if (rc != ERROR_SUCCESS && rc != ERROR_CANCELLED)
		{
			if (rc ==  0x00001069)
			{
			}
			else
			{
			}
		}
		CloseTrace(handle);
	}
}

void SaveLog(HWND hDlg)
{
	IFileSaveDialog *pSaveDialog;
	
	LPOLESTR pszPath = NULL;
    __try
	{
		HRESULT hr = CoCreateInstance(CLSID_FileSaveDialog, 
									  NULL, 
									  CLSCTX_INPROC_SERVER, 
									  IID_PPV_ARGS(&pSaveDialog));

		if (!SUCCEEDED(hr))
		{
			return;
		}
		pSaveDialog->SetDefaultExtension(TEXT("txt"));
		pSaveDialog->SetFileName(TEXT("Report.txt"));
        pSaveDialog->SetOptions(FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_OVERWRITEPROMPT | FOS_DONTADDTORECENT);
		// show the dialog:
        hr = pSaveDialog->Show(hDlg);

        if(SUCCEEDED(hr))
        {
            IShellItem *ppsi;
            // this will fail if Cancel has been clicked:
            hr = pSaveDialog->GetResult(&ppsi);

            if(SUCCEEDED(hr))
            {
                    // extract the path:
                    hr = ppsi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath);
                    ppsi->Release();
            }
        }

        pSaveDialog->Release();

		if (!SUCCEEDED(hr))
		{
			__leave;
		}
	
		

		hFile = CreateFile(pszPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			__leave;
		}
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.001"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.002"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.003"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.004"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.005"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.006"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.007"));
		ExportOneTraceFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.008"));
	}
	__finally
	{
		if (pszPath)
			CoTaskMemFree(pszPath);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hFile);
			hFile = INVALID_HANDLE_VALUE;
		}
	}
}

void DeleteLog(HWND hDlg)
{
	if (IsLoggingEnabled())
	{
		MessageBox(hDlg, TEXT("Tracing must be disabled"),TEXT("Error"),0);
	}
	else
	{
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.001"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.002"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.003"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.004"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.005"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.006"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.007"));
		DeleteFile(TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl.008"));
	}
}