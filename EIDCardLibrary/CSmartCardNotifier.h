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

#pragma once
#include <iostream>
#include <list>
#include <credentialprovider.h>
#include "EIDCardLibrary.h"

class ISmartCardConnectionNotifierRef
{
	public:
	virtual ~ISmartCardConnectionNotifierRef() {}
	virtual void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount) 
	{
		UNREFERENCED_PARAMETER(Message);
		UNREFERENCED_PARAMETER(Reader);
		UNREFERENCED_PARAMETER(CardName);
		UNREFERENCED_PARAMETER(ActivityCount);
	
	};
};

class CSmartCardConnectionNotifier 
{

  public:
    CSmartCardConnectionNotifier() ;
	CSmartCardConnectionNotifier(ISmartCardConnectionNotifierRef*, BOOL fImmediateStart = TRUE);

    virtual ~CSmartCardConnectionNotifier();
	
	HRESULT Start();
	HRESULT Stop();
  private:

	BOOL ValidateCard(SCARD_READERSTATE rgscState);
	LONG GetReaderStates(SCARD_READERSTATE rgscState[MAXIMUM_SMARTCARD_READERS],PDWORD dwRdrCount);
	LONG WaitForSmartCardInsertion();
	static DWORD WINAPI _ThreadProc(LPVOID lpParameter);
	
	void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount);

	HANDLE                  _hThread;
	HANDLE					_hAccessStartedEvent;
	SCARDCONTEXT			_hSCardContext;
	ISmartCardConnectionNotifierRef*			 _CallBack;
};
