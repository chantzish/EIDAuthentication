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

class IWinBioNotifierRef
{
	public:
	virtual ~IWinBioNotifierRef() {}
	virtual void WinBioCallbackSuccess(PTSTR szText) 
	{
		UNREFERENCED_PARAMETER(szText);
	};
	virtual void WinBioCallbackFailure(PTSTR szText) 
	{
		UNREFERENCED_PARAMETER(szText);
	};
};

class CWinBioNotifier
{

  public:
    CWinBioNotifier() ;
	CWinBioNotifier(IWinBioNotifierRef* CallBack);

    virtual ~CWinBioNotifier();
	
	HRESULT Start();
	HRESULT Stop();
  private:
	  	IWinBioNotifierRef* _CallBack;
		WINBIO_SESSION_HANDLE _SessionHandle;
		static VOID CALLBACK CWinBioNotifier::CaptureCallback(
    __in_opt PVOID CaptureCallbackContext,
    __in HRESULT OperationStatus,
    __in WINBIO_UNIT_ID UnitId,
    __in_bcount(SampleSize) PWINBIO_BIR Sample,
    __in SIZE_T SampleSize,
    __in WINBIO_REJECT_DETAIL RejectDetail
    );
};
