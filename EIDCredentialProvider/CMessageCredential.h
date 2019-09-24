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

//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
//

#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

//#include <shlguid.h>
#include "helpers.h"
#include "dll.h"
#include "EIDCredentialProvider.h"

enum CMessageCredentialStatus
{
	Idle,
	Reading,
	EndReading,
	Error,
};

/**
  * Used to display message when no credential is available
  */
class CMessageCredential : public ICredentialProviderCredential
{
    public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        return _cRef++;
    }
    
    STDMETHOD_(ULONG, Release)()
    {
        LONG cRef = _cRef--;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
    {
        HRESULT hr;
        if (ppv != NULL)
        {
            if (IID_IUnknown == riid ||
                IID_ICredentialProviderCredential == riid)
            {
                *ppv = static_cast<IUnknown*>(this);
                reinterpret_cast<IUnknown*>(*ppv)->AddRef();
                hr = S_OK;
            }
            else
            {
                *ppv = NULL;
                hr = E_NOINTERFACE;
            }
        }
        else
        {
            hr = E_INVALIDARG;
        }
        return hr;
    }
  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
                                    PWSTR* ppwszOptionalStatusText, 
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, 
                                NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText, 
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

  public:
    HRESULT Initialize(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       PWSTR szMessage);
    CMessageCredential();

    virtual ~CMessageCredential();
	void IncreaseSmartCardCount()
	{
		_dwSmartCardCount++;
	}
	void DecreaseSmartCardCount()
	{
		_dwSmartCardCount--;
	}
	void SetStatus(DWORD dwStatus) 
	{
		if (dwStatus == EndReading)
		{
			if (_dwSmartCardCount)
			{
				_dwStatus = Error;
			}
			else
			{
				_dwStatus = Idle;
			}
		}
		else
		{
			_dwStatus = dwStatus;
		}
	}
	void SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,DWORD dwFlags)
	{
		_cpus = cpus;
		_dwFlags = dwFlags;
	}

	DWORD GetStatus()
	{
		return _dwStatus;
	}

  private:
    LONG                                    _cRef;
    
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SMFI_NUM_FIELDS];   // An array holding the 
                                                                                            // type and name of each 
                                                                                            // field in the tile.
    
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SMFI_NUM_FIELDS];            // An array holding the 
                                                                                            // state of each field in 
                                                                                            // the tile.

    PWSTR                                   _rgFieldStrings[SMFI_NUM_FIELDS];               // An array holding the 
                                                                                            // string value of each 
                                                                                            // field. This is different 
                                                                                            // from the name of the 
                                                                                            // field held in 
                                                                                            // _rgCredProvFieldDescriptors.
	ICredentialProviderCredentialEvents*	_pCredProvCredentialEvents;    
	DWORD									_dwSmartCardCount;
	DWORD									_dwStatus;
	DWORD									_dwOldStatus;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus; // The usage scenario for which we were enumerated.
	DWORD								  _dwFlags;
};

