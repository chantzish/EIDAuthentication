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
#include "../EIDCardLibrary/EIDCardLibrary.h"

class CContainer 
{

  public:
    CContainer(__in LPCTSTR szReaderName, __in LPCTSTR szCardName, __in LPCTSTR szProviderName, 
		__in LPCTSTR szContainerName, __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext);

    virtual ~CContainer();

	PTSTR GetUserName();
	PTSTR GetProviderName();
	PTSTR GetContainerName();
	DWORD GetRid();
	DWORD GetKeySpec();

	PCCERT_CONTEXT GetCertificate();
	BOOL IsOnReader(__in LPCTSTR szReaderName);
	
	PEID_SMARTCARD_CSP_INFO GetCSPInfo();
	void FreeCSPInfo(PEID_SMARTCARD_CSP_INFO);

	BOOL Erase();
	BOOL ViewCertificate(HWND hWnd = NULL);

	BOOL TriggerRemovePolicy();
	PEID_INTERACTIVE_LOGON AllocateLogonStruct(PWSTR szPin, PDWORD pdwSize);
//	PEID_MSGINA_AUTHENTICATION CContainer::AllocateGinaStruct(PWSTR szPin, PDWORD pdwSize);
  private:

	LPTSTR					_szReaderName;
	LPTSTR					_szCardName;
	LPTSTR					_szProviderName;
	LPTSTR					_szContainerName;
	LPTSTR					_szUserName;
	DWORD					_KeySpec;
	USHORT					_ActivityCount;
	PCCERT_CONTEXT			_pCertContext;
	DWORD					_dwRid;
};
