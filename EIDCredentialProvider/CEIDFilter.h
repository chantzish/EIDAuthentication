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

#include <windows.h>
#include <credentialprovider.h>
#include "../EIDCardLibrary/Tracing.h"

/**
  * Used to filter password credential when smart card logon is mandatory
  */
class CEIDFilter : public ICredentialProviderFilter
{
	public:
	CEIDFilter();
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
            IID_ICredentialProviderFilter == riid)
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
	IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags, GUID *rgclsidProviders, BOOL *rgbAllow, DWORD cProviders);
	IFACEMETHODIMP UpdateRemoteCredential(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut);
    
private:
	LONG                        _cRef;                  // Reference counter.
};



// Boilerplate method to create an instance of our provider. 
HRESULT CEIDFilter_CreateInstance(REFIID riid, void** ppv)
{
    HRESULT hr;
	if (riid != IID_ICredentialProviderFilter) return E_NOINTERFACE;
    CEIDFilter* pFilter = new CEIDFilter();

    if (pFilter)
    {
        hr = pFilter->QueryInterface(riid, ppv);
        pFilter->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    
    return hr;
}

