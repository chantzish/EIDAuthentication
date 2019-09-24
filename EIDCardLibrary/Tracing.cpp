/*	EID Authentication
    Copyright (C) 2009 Vincent Le Toux

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <Evntprov.h>
#include <crtdbg.h>
#include <Wmistr.h>
#include <Evntrace.h>
// load lib on the Vista tracing function
#include <DelayImp.h>
#define _CRTDBG_MAPALLOC
#include <Dbghelp.h>
#include <winhttp.h>

#include "EIDCardLibrary.h"
#include "Tracing.h"
#include "guid.h"

#pragma comment(lib,"Dbghelp")

#define WINEVENT_LEVEL_CRITICAL 1
#define WINEVENT_LEVEL_ERROR    2
#define WINEVENT_LEVEL_WARNING  3
#define WINEVENT_LEVEL_INFO     4
#define WINEVENT_LEVEL_VERBOSE  5

#define EVENT_CONTROL_CODE_ENABLE_PROVIDER 1

REGHANDLE hPub;
BOOL bFirst = TRUE;
WCHAR Section[100];

// to enable tracing in kernel debugger, issue the following command in windbg : ed nt!Kd_DEFAULT_MASK  0xFFFFFFFF
// OR
// Open up the registry and go to this path,
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter 
// and add the following value "DEFAULT" : REG_DWORD : 0xFFFFFFFF and then reboot
//
// Note : you don't need this in Windows XP as the tracing is shown automatically
/**
 *  Tracing function.
 *  Extract data using :
 * C:\Windows\System32\LogFiles\WMI>tracerpt EIDCredentialProvider.etl.001 -o c:\users\Adiant\Desktop\report.txt -of csv
 */

BOOL LookUpErrorMessage(PWSTR buf, int cch, DWORD err)
{
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, err, 0, buf, cch, 0)) {
        return TRUE;
    }
    else 
	{
        swprintf_s(buf, cch, (err < 15000) ? L"Error number: %d" :
                                                  L"Error number: 0x%08X", err);
        return false;
    }
}

BOOL IsTracingEnabled = FALSE;

void NTAPI EnableCallback(
  __in      LPCGUID SourceId,
  __in      ULONG IsEnabled,
  __in      UCHAR Level,
  __in      ULONGLONG MatchAnyKeyword,
  __in      ULONGLONG MatchAllKeywords,
  __in_opt  PEVENT_FILTER_DESCRIPTOR FilterData,
  __in_opt  PVOID CallbackContext
)
{
	UNREFERENCED_PARAMETER(SourceId);
	UNREFERENCED_PARAMETER(Level);
	UNREFERENCED_PARAMETER(MatchAnyKeyword);
	UNREFERENCED_PARAMETER(MatchAllKeywords);
	UNREFERENCED_PARAMETER(FilterData);
	UNREFERENCED_PARAMETER(CallbackContext);
	IsTracingEnabled = (IsEnabled == EVENT_CONTROL_CODE_ENABLE_PROVIDER);
}

void EIDCardLibraryTracingRegister() {
	bFirst = FALSE;
	EventRegister(&CLSID_CEIDProvider,EnableCallback,NULL,&hPub);
}

void EIDCardLibraryTracingUnRegister() {
	EventUnregister(hPub);
}

// see http://www.codeproject.com/Articles/16598/Get-Your-DLL-s-Path-Name for the "__ImageBase"
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

void EIDCardLibraryTraceEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...) {
	_ASSERTE( _CrtCheckMemory( ) );
#ifndef _DEBUG
	UNREFERENCED_PARAMETER(dwLine);
	UNREFERENCED_PARAMETER(szFile);
#endif
	WCHAR Buffer[256];
	WCHAR Buffer2[356];
	int ret;
	va_list ap;

	if (bFirst) 
	{
		EIDCardLibraryTracingRegister();
	}

	va_start (ap, szFormat);
	ret = _vsnwprintf_s (Buffer, 256, 256, szFormat, ap);
	va_end (ap);
	if (ret < 0) return;
	if (ret > 256) ret = 255;
	Buffer[255] = L'\0';/*
	if ((ret>2) && (ret< 254) && (Buffer[ret-1] != L'\n') && (Buffer[ret-2] != L'\n')) {
		wcscat_s(Buffer,256,L"\r\n");
		ret+=2;
	}*/
#ifdef _DEBUG
	swprintf_s(Buffer2,356,L"%S(%d) : %S - %s\r\n",szFile,dwLine,szFunction,Buffer);
	OutputDebugString(Buffer2);
#endif
	swprintf_s(Buffer2,356,L"%S(%d) : %s",szFunction,dwLine,Buffer);

	EventWriteString(hPub,dwLevel,0,Buffer2);

}


	// common exception handler
	LONG EIDExceptionHandlerDebug( PEXCEPTION_POINTERS pExceptPtrs, BOOL fMustCrash )
	{
		EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"New Exception");
		if (fMustCrash)
		{
			// crash on debug to allow kernel debugger to break were the exception was triggered 
			return EXCEPTION_CONTINUE_SEARCH;
		}
		else
		{
			// may contain sensitive information - generate a dump only if the debugging is active
			if (IsTracingEnabled)
			{
				HANDLE fileHandle = CreateFile (TEXT("c:\\EIDAuthenticateDump.dmp"), GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				if (fileHandle == INVALID_HANDLE_VALUE)
				{
					if (GetLastError() == 0x5)
					{
						EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"Unable to create minidump file c:\\EIDAuthenticate.dmp");
						TCHAR szFileName[MAX_PATH];
						GetTempPath(MAX_PATH, szFileName);
						_tcscat_s(szFileName, MAX_PATH, TEXT("EIDAuthenticateDump.dmp"));
						EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"Trying to create dump file %s",szFileName);
						fileHandle = CreateFile (szFileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					}
				}
				if (fileHandle == INVALID_HANDLE_VALUE)
				{
					EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"Unable to create minidump file 0x%08X", GetLastError());
				}
				else
				{
					_MINIDUMP_EXCEPTION_INFORMATION dumpExceptionInfo;
					dumpExceptionInfo.ThreadId = GetCurrentThreadId();
					dumpExceptionInfo.ExceptionPointers = pExceptPtrs;
					dumpExceptionInfo.ClientPointers = FALSE;

					BOOL fStatus = MiniDumpWriteDump(GetCurrentProcess(),
										GetCurrentProcessId(),
										fileHandle,MiniDumpWithFullMemory,(pExceptPtrs != 0) ? &dumpExceptionInfo: NULL,NULL,NULL);
					if (!fStatus)
					{
						EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"Unable to write minidump file 0x%08X", GetLastError());
					}
					else
					{
						EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__,WINEVENT_LEVEL_WARNING,L"minidump successfully created");
					}
					CloseHandle(fileHandle);
				}
			}
			return EXCEPTION_EXECUTE_HANDLER;
		}
	}

	// to allow this code to be tested in debug mode using EIDTest.exe
	LONG EIDExceptionHandler( PEXCEPTION_POINTERS pExceptPtrs )
	{
#ifdef _DEBUG
		return EIDExceptionHandlerDebug(pExceptPtrs, TRUE);
#else
		return EIDExceptionHandlerDebug(pExceptPtrs, FALSE);
#endif
	}

void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PVOID memoryParam, DWORD memorysize)
{
	DWORD i,j;
	UCHAR buffer[10];
	WCHAR szFormat[] = L"%3d %3d %3d %3d %3d %3d %3d %3d %3d %3d";
	WCHAR szFormat2[] = L"%c%c%c%c%c%c%c%c%c%c";
	PUCHAR memory = (PUCHAR) memoryParam;
	for (i = 0; i < memorysize; i++)
	{
		buffer[i%10] = memory[i];
		if (i%10 == 9) 
		{
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
		if ((i == memorysize-1) && (i%10 != 9))
		{
			// last bytes
			for (j = 0; j <10; j++)
			{
				buffer[j]=255;
			}
			for (j = memorysize - memorysize%10; j <memorysize; j++) 
			{
				buffer[j%10] = memory[j];
			}
			szFormat[(memorysize%10) * 4] = '\0';
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
	}
	for (i = 0; i < memorysize; i++)
	{
		buffer[i%10] = memory[i];
		if (buffer[i%10] < 30) buffer[i%10] = ' ';
		if (i%10 == 9) 
		{
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat2,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
		if ((i == memorysize-1) && (i%10 != 9))
		{
			// last bytes
			for (j = 0; j <10; j++)
			{
				buffer[j]=' ';
			}
			for (j = memorysize - memorysize%10; j <memorysize; j++) 
			{
				buffer[j%10] = memory[j];
				if (buffer[j%10] < 30) buffer[j%10] = ' ';
			}
			szFormat2[(memorysize%10)] = '\0';
			EIDCardLibraryTraceEx(szFile,dwLine,szFunction, WINEVENT_LEVEL_VERBOSE, szFormat2,
				buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
				buffer[5],buffer[6],buffer[7],buffer[8],buffer[9]);
		}
	}
}

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine) {
	LPVOID Error;
	TCHAR szMessage[1024];
	TCHAR szTitle[1024];
	_stprintf_s(szTitle,ARRAYSIZE(szTitle),TEXT("%hs(%d)"),szFile, dwLine);
	if (status >= WINHTTP_ERROR_BASE && status <= WINHTTP_ERROR_LAST)
	{
		// winhttp error message
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER| FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE,
			GetModuleHandle(_T("winhttp.dll")),status,0,(LPTSTR)&Error,0,NULL);
	}
	else
	{
		// system error message
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER|FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,status,0,(LPTSTR)&Error,0,NULL);
	}
	_stprintf_s(szMessage,ARRAYSIZE(szMessage),TEXT("0x%08X - %s"),status,Error);
	EIDCardLibraryTraceEx(szFile, dwLine, "MessageBoxWin32Ex2", WINEVENT_LEVEL_INFO, L"%s", szMessage);
	MessageBox(hWnd,szMessage, szTitle ,MB_ICONASTERISK);
	LocalFree(Error);
}

BOOL StartLogging()
{
	BOOL fReturn = FALSE;
	TRACEHANDLE SessionHandle;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	ULONG err;
	__try
	{
		memset(&Properties, 0, sizeof(Properties));
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.Wnode.ClientContext = 1;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
		Properties.TraceProperties.MaximumFileSize = 8;
		_tcscpy_s(Properties.LogFileName,1024,TEXT("c:\\Windows\\system32\\LogFiles\\WMI\\EIDCredentialProvider.etl"));
		//_tcscpy_s(Properties.LoggerName,1024,TEXT("EIDCredentialProvider"));
		DeleteFile(Properties.LogFileName);
		err = StartTrace(&SessionHandle, TEXT("EIDCredentialProvider"), &(Properties.TraceProperties));
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"StartTrace 0x%08x", err);
			__leave;
		}
		err = EnableTraceEx(&CLSID_CEIDProvider,NULL,SessionHandle,TRUE,WINEVENT_LEVEL_VERBOSE,0,0,0,NULL);
		if (err != ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EnableTraceEx 0x%08x", err);
			__leave;
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	return fReturn;
}

BOOL StopLogging()
{
	LONG err = 0;
	BOOL fReturn = FALSE;
	struct _Prop
	{
		EVENT_TRACE_PROPERTIES TraceProperties;
		TCHAR LogFileName[1024];
		TCHAR LoggerName[1024];
	} Properties;
	memset(&Properties, 0, sizeof(Properties));
	__try
	{
		Properties.TraceProperties.Wnode.BufferSize = sizeof(Properties);
		Properties.TraceProperties.Wnode.Guid = CLSID_CEIDProvider;
		Properties.TraceProperties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		Properties.TraceProperties.LogFileMode = 4864; 
		Properties.TraceProperties.LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		Properties.TraceProperties.LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + 1024 * sizeof(TCHAR);
		Properties.TraceProperties.MaximumFileSize = 8;
		err = ControlTrace(NULL, TEXT("EIDCredentialProvider"), &(Properties.TraceProperties),EVENT_TRACE_CONTROL_STOP);
		if (err != ERROR_SUCCESS && err != 0x00001069)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ControlTrace 0x%08x", err);
		}
		fReturn = TRUE;
	}
	__finally
	{
	}
	SetLastError(err);
	return fReturn;
}