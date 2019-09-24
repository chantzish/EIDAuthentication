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

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <tchar.h>

#include <credentialprovider.h>

#include "helpers.h"

#include "../EIDCardLibrary/CSmartCardNotifier.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"
#include "../EIDCardLibrary/Tracing.h"

// Forward references for classes used here.
class CEIDCredential;
class CMessageCredential;

/**
  * Main class
  */
class CEIDProvider : public ICredentialProvider, public ISmartCardConnectionNotifierRef
{
  public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        InterlockedIncrement(&_cRef);
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"AddRef %X (%d)",this,_cRef);
		return _cRef;
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
        if (IID_IUnknown == riid || 
            IID_ICredentialProvider == riid)
        {
            *ppv = this;
            reinterpret_cast<IUnknown*>(*ppv)->AddRef();
            hr = S_OK;
        }
        else
        {
            *ppv = NULL;
            hr = E_NOINTERFACE;
        }
        return hr;
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, 
                                   __out ICredentialProviderCredential** ppcpc);

    friend HRESULT CEIDProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

public:
	virtual void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount);

  protected:
    CEIDProvider();
    __override ~CEIDProvider();
    HRESULT Initialize();
private:
	
	

    LONG                        _cRef;                  // Reference counter.
	CMessageCredential          *_pMessageCredential;   // Our "disconnected" credential.
    ICredentialProviderEvents   *_pcpe;                    // Used to tell our owner to re-enumerate credentials.
    UINT_PTR                    _upAdviseContext;       // Used to tell our owner who we are when asking to 
                                                        // re-enumerate credentials.
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
	DWORD									_dwFlags;
	BOOL									_fDontShowAnything;
	CContainerHolderFactory<CEIDCredential>	_CredentialList;
	CSmartCardConnectionNotifier*			_pSmartCardConnectionNotifier;
};
