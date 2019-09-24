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
// CEIDCredential is our implementation of ICredentialProviderCredential.
// ICredentialProviderCredential is what LogonUI uses to let a credential
// provider specify what a user tile looks like and then tell it what the
// user has entered into the tile.  ICredentialProviderCredential is also
// responsible for packaging up the users credentials into a buffer that
// LogonUI then sends on to LSA.

#pragma once

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#include "helpers.h"
#include "dll.h"
#include "EIDCredentialProvider.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"

/**
  * Used to represent a credential
  */
class CEIDCredential : public ICredentialProviderCredential
{
    public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        LONG cRef = InterlockedIncrement(&_cRef);
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"AddRef %X (%d)",this,_cRef);
		return cRef;
    }
    
    STDMETHOD_(ULONG, Release)()
    {
        
		LONG cRef = InterlockedDecrement(&_cRef);
        EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Release %X (%d)",this,_cRef);
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
    HRESULT Initialize();
    CEIDCredential(CContainer* container);
	void SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
    virtual ~CEIDCredential();
	CContainer* GetContainer();
  private:
    LONG                                  _cRef;

    CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus; // The usage scenario for which we were enumerated.
	DWORD								  _dwFlags;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];  // An array holding the type 
                                                                                        // and name of each field in 
                                                                                        // the tile.

    FIELD_STATE_PAIR                      _rgFieldStatePairs[SFI_NUM_FIELDS];           // An array holding the state 
                                                                                        // of each field in the tile.

    PWSTR                                 _rgFieldStrings[SFI_NUM_FIELDS];              // An array holding the string 
                                                                                        // value of each field. This is 
                                                                                        // different from the name of 
                                                                                        // the field held in 
                                                                                        // _rgCredProvFieldDescriptors.
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;           
	CContainer* _pContainer;

};
