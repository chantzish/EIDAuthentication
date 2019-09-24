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
// Standard dll required functions and class factory implementation.

#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

#include <windows.h>
#include <unknwn.h>
#include <credentialprovider.h>

#include "Dll.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/Registration.h"

static LONG g_cRef = 0;   // global dll reference count

// IClassFactory ///////////////////////////////////////////////////////////////////////

extern HRESULT CEIDProvider_CreateInstance(REFIID riid, void** ppv);
extern HRESULT CEIDFilter_CreateInstance(REFIID riid, void** ppv);

HINSTANCE g_hinst = NULL;   // global dll hinstance

class CClassFactory : public IClassFactory
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
            if (IID_IClassFactory == riid || IID_IUnknown == riid)
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

    // IClassFactory
    STDMETHOD (CreateInstance)(IUnknown* pUnkOuter, REFIID riid, void** ppv)
    {
        HRESULT hr;
        if (!pUnkOuter)
        {
            if (IID_ICredentialProviderFilter == riid)
			{
				hr = CEIDFilter_CreateInstance(riid, ppv);
			}
			else
			{
				hr = CEIDProvider_CreateInstance(riid, ppv);
			}
        }
        else
        {
            hr = CLASS_E_NOAGGREGATION;
        }
        return hr;
    }

    STDMETHOD (LockServer)(BOOL bLock)
    {
        if (bLock)
        {
            DllAddRef();
        }
        else
        {
            DllRelease();
        }
        return S_OK;
    }

  private:
     CClassFactory() : _cRef(1) {}
    ~CClassFactory(){}

  private:
    LONG _cRef;

    friend HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, void** ppv);
};

HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, void** ppv)
{
    HRESULT hr;
    if (CLSID_CEIDProvider == rclsid )
    {
        CClassFactory* pcf = new CClassFactory;
        if (pcf)
        {
            hr = pcf->QueryInterface(riid, ppv);
            pcf->Release();
        }
        else
        {
            hr = E_OUTOFMEMORY;
        }
    }
    else
    {
        hr = CLASS_E_CLASSNOTAVAILABLE;
    }
    return hr;
}

// DLL Functions ///////////////////////////////////////////////////////////////////////

BOOL WINAPI DllMain(
    HINSTANCE hinstDll,
    DWORD dwReason,
    LPVOID pReserved
    )
{
    UNREFERENCED_PARAMETER(pReserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDll);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    
    g_hinst = hinstDll;
    return TRUE;

}

void DllAddRef()
{
    InterlockedIncrement(&g_cRef);
}

void DllRelease()
{
    InterlockedDecrement(&g_cRef);
}

// DLL entry point.
STDAPI DllCanUnloadNow()
{
    HRESULT hr;

    if (g_cRef > 0)
    {
        hr = S_FALSE;   // cocreated objects still exist, don't unload
    }
    else
    {
        hr = S_OK;      // refcount is zero, ok to unload
    }

    return hr;
}

// DLL entry point.
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    return CClassFactory_CreateInstance(rclsid, riid, ppv);
}

