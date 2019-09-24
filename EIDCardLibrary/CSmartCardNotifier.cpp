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

#include "CSmartCardNotifier.h"
#include "Tracing.h"
#include "CContainer.h"

#define TIMEOUT 300

#pragma comment(lib,"Winscard")
//#define  _CRTDBG_MAP_ALLOC
//#include <crtdbg.h>




CSmartCardConnectionNotifier::CSmartCardConnectionNotifier(ISmartCardConnectionNotifierRef* CallBack, BOOL fImmediateStart) 
{
	_CallBack = CallBack;
	_hAccessStartedEvent = NULL;
	_hThread = NULL;
	if (fImmediateStart)
	{
		Start();
	}
}

CSmartCardConnectionNotifier::~CSmartCardConnectionNotifier() 
{
	if (_hThread != NULL) 
	{
		Stop();
	}
}


HRESULT CSmartCardConnectionNotifier::Start() 
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	
	// check callback
	if(NULL == _CallBack)
	{
		// no callback defined : don't launch
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No callback definied");
		return E_FAIL;
	}
	if (_hThread != NULL)
	{
		// Thread already launched
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread already launched");
		return E_FAIL;
	}
	_hThread = CreateThread(NULL, 0, CSmartCardConnectionNotifier::_ThreadProc, (LPVOID) this, 0, NULL);
    if (_hThread == NULL)
    {
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to launch the thread : %d",GetLastError());
		return E_FAIL;
    }
	_hAccessStartedEvent = CreateEvent(NULL,TRUE,FALSE,NULL);

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return S_OK;
}


HRESULT CSmartCardConnectionNotifier::Stop()
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	LONG lReturn;

	if (_hThread != NULL) 
	{
		if (WaitForSingleObject(_hThread,0)==WAIT_TIMEOUT) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Wait for thread");
			// blocked on SCardAccessStartedEvent ?
			if (_hAccessStartedEvent != NULL) {
				SetEvent( _hAccessStartedEvent );
			}
			if (_hSCardContext != NULL)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardCancel");
				if (SCARD_S_SUCCESS != (lReturn=SCardCancel(_hSCardContext)))
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to SCardCancel %X",lReturn);
				}
			}
			WaitForSingleObject(_hThread,INFINITE);
			//TerminateThread(_hThread,0);
		}
		else
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread already finished");
		}
		CloseHandle(_hThread);
		_hThread = NULL;
	}
	else
	{
		// no thread to stop
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Thread handle NULL");
		return E_FAIL;
	}

	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return S_OK;
}

DWORD WINAPI CSmartCardConnectionNotifier::_ThreadProc(LPVOID lpParameter) 
{
	CSmartCardConnectionNotifier *pSmartCardConnectionNotifier = static_cast<CSmartCardConnectionNotifier *>(lpParameter);
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
	pSmartCardConnectionNotifier->WaitForSmartCardInsertion();

	return 0;
}





// try to know if there are an existing card or wait for this card
// then call ValidateCard
// TRUE = Validate
// FALSE = Not Validate or error
LONG CSmartCardConnectionNotifier::WaitForSmartCardInsertion() 
{

	LONG					Status;

	SCARD_READERSTATE 		rgscState[MAXIMUM_SMARTCARD_READERS];
	DWORD             		dwI, dwRdrCount;
	HANDLE					hAccessStartedEvent[2];


	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	do {
		// Establish the Resource Manager Context.
		Status = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&_hSCardContext);
		if(Status == SCARD_E_NO_SERVICE) 
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext : SCARD_E_NO_SERVICE");
			// Wait for the launch of the Resource Manager
			hAccessStartedEvent[0] = SCardAccessStartedEvent();
			if (_hAccessStartedEvent == NULL)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent : %d",GetLastError());
				return SCARD_E_NO_SERVICE;
			}
			hAccessStartedEvent[1] = _hAccessStartedEvent;
			Status = WaitForMultipleObjects(2,hAccessStartedEvent,FALSE,INFINITE);
			SCardReleaseStartedEvent();
			if (Status == WAIT_TIMEOUT) 
			{
				// canceled
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent Cancelled");
				return SCARD_E_NO_SERVICE;
			}
			else if (Status == (WAIT_OBJECT_0 + 1))
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent-Cancelled");
				return SCARD_E_NO_SERVICE;
			}
			else if (Status != WAIT_OBJECT_0) 
			{
				// error
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardAccessStartedEvent-WaitForSingleObject :%X",Status);
				return SCARD_E_NO_SERVICE;
			}
			// no error and manager available
			Status = SCardEstablishContext(SCARD_SCOPE_USER,NULL,NULL,&_hSCardContext);
			if(Status != SCARD_S_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext2 :%X",Status);
				return Status;
			}
		}
		else if(Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardEstablishContext :%X",Status);
			return Status;
		}

		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Main loop started");
		///////////////////////////////////////////////////////////
		// Main loop : wait for any changes
		///////////////////////////////////////////////////////////
		dwRdrCount = 0; // for PNP fake Reader
		Status = GetReaderStates(rgscState,&dwRdrCount);
		if(Status != SCARD_S_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetReaderStates :%X",Status);
			SCardReleaseContext(_hSCardContext);
			return Status;
		}
		
		// Call the SCardGetStatusChange to detect configuration changes on all the detected
		// readers.
		Status = SCardGetStatusChange(_hSCardContext, (DWORD) 2000 ,rgscState,dwRdrCount);
		while((Status == SCARD_S_SUCCESS) || (Status == SCARD_E_TIMEOUT))
		{ 
			for ( dwI=0; dwI < dwRdrCount; dwI++)
			{
				
				if (!(SCARD_STATE_MUTE & rgscState[dwI].dwEventState))
				{
					// Report the status for all the reader where a change has been detected.
					if ((0 != ( SCARD_STATE_CHANGED & rgscState[dwI].dwEventState)))
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"SCardGetStatusChange :0x%08X",rgscState[dwI].dwEventState);
						if ( (SCARD_STATE_PRESENT  & rgscState[dwI].dwEventState) &&
								!(SCARD_STATE_PRESENT & rgscState[dwI].dwCurrentState))
						{
							LPTSTR pmszCards = NULL;
							DWORD cch = SCARD_AUTOALLOCATE;
							for (DWORD dwJ = 0; dwJ < 4; dwJ++)
							{
								EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"ATR :%02X %02X %02X %02X %02X %02X %02X %02X",
									rgscState[dwI].rgbAtr[dwJ * 8 + 0],
									rgscState[dwI].rgbAtr[dwJ * 8 + 1],
									rgscState[dwI].rgbAtr[dwJ * 8 + 2],
									rgscState[dwI].rgbAtr[dwJ * 8 + 3],
									rgscState[dwI].rgbAtr[dwJ * 8 + 4],
									rgscState[dwI].rgbAtr[dwJ * 8 + 5],
									rgscState[dwI].rgbAtr[dwJ * 8 + 6],
									rgscState[dwI].rgbAtr[dwJ * 8 + 7]
								);
							}
							Status = SCardListCards(_hSCardContext,rgscState[dwI].rgbAtr,NULL,NULL, (LPTSTR)&pmszCards,&cch );
							if (Status != SCARD_S_SUCCESS)
							{
								EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Unable to retrieve smart card name 0x%08x",Status);
							}
							Callback(EIDCPRSConnecting,rgscState[dwI].szReader, pmszCards, (rgscState[dwI].dwEventState)>>16);
							SCardFreeMemory(_hSCardContext,pmszCards);
							rgscState[dwI].dwCurrentState = SCARD_STATE_PRESENT;

						}
						if ( !(SCARD_STATE_PRESENT & rgscState[dwI].dwEventState) &&
								(SCARD_STATE_PRESENT & rgscState[dwI].dwCurrentState) &&
								!(SCARD_STATE_MUTE & rgscState[dwI].dwCurrentState)
								)
						{
								Callback(EIDCPRSDisconnected,rgscState[dwI].szReader, NULL, 0);
								rgscState[dwI].dwCurrentState = SCARD_STATE_EMPTY;
						}
					}				
				}
				// Memorize the current state.
				rgscState[dwI].dwCurrentState = rgscState[dwI].dwEventState;
			}	
			//update reader list (add or remove readers)
			Status = GetReaderStates(rgscState,&dwRdrCount);
			if(Status != SCARD_S_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetReaderStates :%X",Status);
				SCardReleaseContext(_hSCardContext);
				return Status;
			}
			if( WaitForSingleObject(_hAccessStartedEvent,0) != WAIT_TIMEOUT) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Event signaled _hAccessStartedEvent");
				break;
			}
			Status = SCardGetStatusChange(_hSCardContext, INFINITE ,rgscState,dwRdrCount);
		} // end while

		// free memory
		for ( dwI=0; dwI < dwRdrCount; dwI++)
		{
			// if the system cancelled our notification, we need to notify
			// that a card has been removed
			// so it can be added again
			if (Status == SCARD_E_SYSTEM_CANCELLED)
			{
				if (SCARD_STATE_PRESENT  & rgscState[dwI].dwEventState)
				{
					Callback(EIDCPRSDisconnected,rgscState[dwI].szReader, NULL, 0);
				}
			}
			EIDFree((PVOID)rgscState[dwI].szReader);
		}
		// Resource Manager Context: Release
		Status = SCardReleaseContext(_hSCardContext);
		_hSCardContext = NULL;

		// cf http://blogs.msdn.com/shivaram/archive/2007/02/26/smart-card-logon-on-windows-vista.aspx
		// SCARD_E_SYSTEM_CANCELLED is received when logonui is launched
	} while (Status == SCARD_E_SYSTEM_CANCELLED);

	if (Status != SCARD_E_CANCELLED)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardGetStatusChange cancelled :%X",Status);
	}
	// synchronization event
	CloseHandle(_hAccessStartedEvent);
	_hAccessStartedEvent = NULL;
	Callback(EIDCPRSThreadFinished,_T(""), NULL, 0);
	return Status;
}



// Look for readers in system
// and then for connected card
LONG CSmartCardConnectionNotifier::GetReaderStates(SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS],PDWORD dwRdrCount) {
	LONG					Status;
	DWORD   				dwReadersLength;	
	LPTSTR					szRdr, szListReaders;
	
	DWORD					dwPreviousRdrCount;
	DWORD					dwI, dwJ;
	DWORD					dwOldListToNewList[MAXIMUM_SMARTCARD_READERS];
	DWORD					dwNewListToOldList[MAXIMUM_SMARTCARD_READERS];
	LPTSTR					szReader[MAXIMUM_SMARTCARD_READERS];
	
	//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
	// initialise matrix
	for ( dwI = 1; dwI < MAXIMUM_SMARTCARD_READERS; dwI++ )
	{
		dwOldListToNewList[dwI] = (DWORD)-1;
		dwNewListToOldList[dwI] = (DWORD)-1;
	}
	
	
	if (! *dwRdrCount)
	{
		// init fake PNP reader
		memset(&rgscState[0],0,sizeof(SCARD_READERSTATE));
		rgscState[0].szReader = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(wcslen(L"\\\\?PNP?\\NOTIFICATION")+1)));
		wcscpy_s((WCHAR*) rgscState[0].szReader,wcslen(L"\\\\?PNP?\\NOTIFICATION")+1,L"\\\\?PNP?\\NOTIFICATION");
		rgscState[0].dwCurrentState = SCARD_STATE_UNAWARE;
		rgscState[0].dwEventState = SCARD_STATE_UNAWARE;
		*dwRdrCount = 1;
		dwPreviousRdrCount = 1;
	}
	else
	{
		dwPreviousRdrCount = *dwRdrCount;
	}

	dwReadersLength = SCARD_AUTOALLOCATE;
	szListReaders = NULL;
	Status = SCardListReaders(_hSCardContext,NULL,(LPTSTR)&szListReaders,&dwReadersLength);
	// No reader is connected to the system.
	if (Status == SCARD_E_NO_READERS_AVAILABLE)
	{
		*dwRdrCount = 1;
	}
	// An error condition was raised.
	else if (Status != SCARD_S_SUCCESS)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SCardListReaders: %Xh",Status);
		return Status;
	}
	// else : At least one reader is available !
	else
	{
	}
	

	// Track events on found readers.
	
	//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Count new entries");
	if (Status == SCARD_S_SUCCESS) {
		// Flag Reader removed or added
		szRdr = szListReaders;
		dwJ = 1;
		while ( 0 != *szRdr ) 
		{
			szReader[dwJ] = szRdr;
			for (dwI = 1; dwI < dwPreviousRdrCount; dwI++) {
				if (wcscmp(rgscState[dwI].szReader,szRdr) == 0)
				{
					dwOldListToNewList[dwI] = dwJ;
					dwNewListToOldList[dwJ] = dwI;
					break;
				}
			}
			szRdr += lstrlen(szRdr) + 1;
			dwJ++;
		}
		*dwRdrCount = dwJ;
	}
	
	// remove old entries
	for (dwI = 1; dwI < dwPreviousRdrCount; dwI++) {
		if (dwOldListToNewList[dwI] == ((DWORD)-1))
		{
			// to remove
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Remove old entries %s",rgscState[dwI].szReader);
			if (dwI != (dwPreviousRdrCount -1) )
			{
				// not the last
				// free memory
				EIDFree((PVOID)rgscState[dwI].szReader);
				// so move the last to this place
				rgscState[dwI].szReader = rgscState[dwPreviousRdrCount -1].szReader;
				rgscState[dwI].cbAtr = rgscState[dwPreviousRdrCount -1].cbAtr;
				rgscState[dwI].dwCurrentState = rgscState[dwPreviousRdrCount -1].dwCurrentState;
				rgscState[dwI].dwEventState = rgscState[dwPreviousRdrCount -1].dwEventState;
				rgscState[dwI].pvUserData = rgscState[dwPreviousRdrCount -1].pvUserData;
				for(dwJ = 0; dwJ < 36; dwJ++)
				{
					rgscState[dwI].rgbAtr[dwJ] = rgscState[dwPreviousRdrCount -1].rgbAtr[dwJ];
				}
				// update matrix
				dwOldListToNewList[dwI] = dwOldListToNewList[dwPreviousRdrCount -1];
				for (dwJ = 1; dwJ < MAXIMUM_SMARTCARD_READERS; dwJ++)
				{
					if (dwNewListToOldList[dwJ] == dwPreviousRdrCount -1) {
						dwNewListToOldList[dwJ] = dwI;
					}
				}
				// redo the work on this item
				dwI--;
			}
			dwPreviousRdrCount--;
		}
		else
		{
			// update the pointer in szListReaders
			//rgscState[dwI].szReader = szReader[dwOldListToNewList[dwI]];
		}
	}
	
	
	// add new entries
	for (dwI = 1; dwI < *dwRdrCount; dwI++) {
		if (dwNewListToOldList[dwI] == (DWORD) -1)
		{
			// to add
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Add new entries %s",szReader[dwI]);
			memset(&rgscState[dwPreviousRdrCount],0,sizeof(SCARD_READERSTATE));

			rgscState[dwPreviousRdrCount].szReader = (LPWSTR) EIDAlloc((DWORD)(sizeof(WCHAR)*(wcslen(szReader[dwI])+1)));
			wcscpy_s((WCHAR*) rgscState[dwPreviousRdrCount].szReader,wcslen(szReader[dwI])+1,szReader[dwI]);
			//rgscState[dwPreviousRdrCount].szReader =  szReader[dwI];
			rgscState[dwPreviousRdrCount].dwCurrentState = SCARD_STATE_UNAWARE;
			rgscState[dwPreviousRdrCount].dwEventState = SCARD_STATE_UNAWARE;
			dwPreviousRdrCount++;
		}
	}
	SCardFreeMemory(_hSCardContext,szListReaders);
	//EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
	return SCARD_S_SUCCESS;
}

void CSmartCardConnectionNotifier::Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount)
{
	_CallBack->Callback(Message,Reader,CardName,ActivityCount);
}
