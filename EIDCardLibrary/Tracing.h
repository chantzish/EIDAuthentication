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

/**
 *  Tracing function.
 */



/*
WINEVENT_LEVEL_CRITICAL Abnormal exit or termination events.
WINEVENT_LEVEL_ERROR Severe error events.
WINEVENT_LEVEL_WARNING Warning events such as allocation failures.
WINEVENT_LEVEL_INFO Non-error events such as entry or exit events.
WINEVENT_LEVEL_VERBOSE Detailed trace events.
*/

#pragma once

#define WINEVENT_LEVEL_CRITICAL 1
#define WINEVENT_LEVEL_ERROR    2
#define WINEVENT_LEVEL_WARNING  3
#define WINEVENT_LEVEL_INFO     4
#define WINEVENT_LEVEL_VERBOSE  5

void EIDCardLibraryTracingRegister();
void EIDCardLibraryTracingUnRegister();

#define EIDCardLibraryTrace(dwLevel, ...) \
	EIDCardLibraryTraceEx(__FILE__,__LINE__,__FUNCTION__, dwLevel, __VA_ARGS__);

void EIDCardLibraryTraceEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction, UCHAR dwLevel, PCWSTR szFormat,...);

#define EIDCardLibraryDumpMemory(memory, memorysize) \
	EIDCardLibraryDumpMemoryEx(__FILE__,__LINE__,__FUNCTION__, memory, memorysize);

void EIDCardLibraryDumpMemoryEx(LPCSTR szFile, DWORD dwLine, LPCSTR szFunction, PVOID memory, DWORD memorysize);

/**
 *  Display a messagebox giving an error code
 */
void MessageBoxWin32Ex2(DWORD status, HWND hWnd, LPCSTR szFile, DWORD dwLine);
#define MessageBoxWin32(status) MessageBoxWin32Ex2 (status, NULL, __FILE__,__LINE__);
#define MessageBoxWin32Ex(status, hwnd ) MessageBoxWin32Ex2 (status, hwnd, __FILE__,__LINE__);

BOOL LookUpErrorMessage(PWSTR buf, int cch, DWORD err);

LONG EIDExceptionHandler( PEXCEPTION_POINTERS pExceptPtrs );
LONG EIDExceptionHandlerDebug( PEXCEPTION_POINTERS pExceptPtrs, BOOL fMustCrash );

BOOL StartLogging();
BOOL StopLogging();