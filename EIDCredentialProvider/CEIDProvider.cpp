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
// CEIDProvider implements ICredentialProvider, which is the main
// interface that logonUI uses to decide which tiles to display.
// This sample illustrates processing asynchronous external events and 
// using them to provide the user with an appropriate set of credentials.
// In this sample, we provide two credentials: one for when the system
// is "connected" and one for when it isn't. When it's "connected", the
// tile provides the user with a field to log in as the administrator.
// Otherwise, the tile asks the user to connect first.
//
#define _SEC_WINNT_AUTH_TYPES 0
#pragma comment(lib,"credui")
#include "CEIDProvider.h"
#include "CEIDCredential.h"
#include "CMessageCredential.h"

#include <credentialprovider.h>

#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CSmartCardNotifier.h"
#include "../EIDCardLibrary/GPO.h"

// CEIDProvider ////////////////////////////////////////////////////////

CEIDProvider::CEIDProvider():
    _cRef(1)
{
    EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Creation");
	DllAddRef();
    _pcpe = NULL;
    _pMessageCredential = NULL;
	_pSmartCardConnectionNotifier = NULL;
	_fDontShowAnything = FALSE;
}

CEIDProvider::~CEIDProvider()
{
	if (_pSmartCardConnectionNotifier)
	{
		_pSmartCardConnectionNotifier->Stop();
		delete _pSmartCardConnectionNotifier;
	}
    DllRelease();
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Deletion");
}

// This method acts as a callback for the hardware emulator. When it's called, it simply
// tells the infrastructure that it needs to re-enumerate the credentials.
void CEIDProvider::Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message, __in LPCTSTR szReader,__in_opt LPCTSTR szCardName, __in_opt USHORT ActivityCount) {
	switch(Message)
	{
	case EIDCPRSConnecting:
		if (szCardName)
		{
			if (_pMessageCredential) 
			{
				_pMessageCredential->SetStatus(Reading);
				_pMessageCredential->IncreaseSmartCardCount();
			}
			if (_pcpe != NULL)
			{
				_pcpe->CredentialsChanged(_upAdviseContext);
				Sleep(100);
			}
			_CredentialList.ConnectNotification(szReader,szCardName,ActivityCount);
			if (_pMessageCredential) _pMessageCredential->SetStatus(EndReading);
			
			if (_pcpe != NULL)
			{
				_pcpe->CredentialsChanged(_upAdviseContext);
			}
		}
		break;
	case EIDCPRSDisconnected:
		if (_pMessageCredential) 
		{
			_pMessageCredential->SetStatus(Reading);
			_pMessageCredential->DecreaseSmartCardCount();
		}
		if (_pcpe != NULL)
		{
			_pcpe->CredentialsChanged(_upAdviseContext);
			Sleep(100);
		}		
		_CredentialList.DisconnectNotification(szReader);
		if (_pMessageCredential) _pMessageCredential->SetStatus(EndReading);
		
		if (_pcpe != NULL)
		{
			_pcpe->CredentialsChanged(_upAdviseContext);
		}

		break;
	}
}

HRESULT CEIDProvider::Initialize()
{
	// Create the CEIDCredential (for connected scenarios), the CMessageCredential
    // (for disconnected scenarios), and the CEIDDetection (to detect commands, such
    // as the connect/disconnect here).  We can get SetUsageScenario multiple times
    // (for example, cancel back out to the CAD screen, and then hit CAD again), 
    // but there's no point in recreating our creds, since they're the same all the
    // time
    HRESULT hr;
    if (!_pMessageCredential)
    {
        // For the locked case, a more advanced credprov might only enumerate tiles for the 
        // user whose owns the locked session, since those are the only creds that will work

        _pMessageCredential = new CMessageCredential();
        if (_pMessageCredential)
        {
  
			hr = _pMessageCredential->Initialize(s_rgMessageCredProvFieldDescriptors, s_rgMessageFieldStatePairs, L"Please connect");
			_CredentialList.Lock();
			_CredentialList.SetUsageScenario(_cpus,_dwFlags);
			_CredentialList.Unlock();
			_pMessageCredential->SetUsageScenario(_cpus,_dwFlags);
			_pSmartCardConnectionNotifier = new CSmartCardConnectionNotifier(this);
        }
        else
        {
            hr = E_OUTOFMEMORY;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
        }
    }
    else
    {
        //everything's already all set up
        hr = S_OK;
    }
	return hr;
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CEIDProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
    HRESULT hr;
    // Decide which scenarios to support here. Returning E_NOTIMPL simply tells the caller
    // that we're not designed for that scenario.
	EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Scenario: %d",cpus);
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:       
    case CPUS_CREDUI:
        _cpus = cpus;
		_dwFlags = dwFlags;
		if (_dwFlags & CREDUIWIN_AUTHPACKAGE_ONLY || _dwFlags & CREDUIWIN_IN_CRED_ONLY)
		{
			// postpone the initialization in SetSerialization
			hr = S_OK;
		}
		else
		{
			hr = Initialize();
		}
        
        break;
    case CPUS_CHANGE_PASSWORD:
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_NOTIMPL");
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to LogonUI for
// an authentication attempt.  It's the opposite of ICredentialProviderCredential::GetSerialization.
// GetSerialization is implement by a credential and serializes that credential.  Instead,
// SetSerialization takes the serialization and uses it to create a tile.
//
// SetSerialization is called for two main scenarios.  The first scenario is in the credui case
// where it is prepopulating a tile with credentials that the user chose to store in the OS.
// The second situation is in a remote logon case where the remote client may wish to 
// prepopulate a tile with a username, or in some cases, completely populate the tile and
// use it to logon without showing any UI.
//
// If you wish to see an example of SetSerialization, please see either the SampleCredentialProvider
// sample or the SampleCredUICredentialProvider sample.  [The logonUI team says, "The original sample that
// this was built on top of didn't have SetSerialization.  And when we decided SetSerialization was
// important enough to have in the sample, it ended up being a non-trivial amount of work to integrate
// it into the main sample.  We felt it was more important to get these samples out to you quickly than to
// hold them in order to do the work to integrate the SetSerialization changes from SampleCredentialProvider 
// into this sample.]
STDMETHODIMP CEIDProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
	EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"");
	if (_dwFlags & CREDUIWIN_AUTHPACKAGE_ONLY || _dwFlags & CREDUIWIN_IN_CRED_ONLY)
	{
		if (pcpcs->ulAuthenticationPackage > 0)
		{
			ULONG ulAuthenticationPackage;
			RetrieveNegotiateAuthPackage(&ulAuthenticationPackage);
			if (pcpcs->ulAuthenticationPackage != ulAuthenticationPackage)
			{
				_fDontShowAnything = TRUE;
			}
			else
			{
				Initialize();
			}
		}
	}
	PSEC_WINNT_CREDUI_CONTEXT pCredUIContext = NULL;
	SECURITY_STATUS status;
	status= SspiUnmarshalCredUIContext(pcpcs->rgbSerialization, pcpcs->cbSerialization, &pCredUIContext);
	//SspiGetCredUIContext(

    return S_OK;
}

// Called by LogonUI to give you a callback. Providers often use the callback if they
// some event would cause them to need to change the set of tiles that they enumerated
HRESULT CEIDProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext
    )
{
	if (_pcpe != NULL)
    {
        _pcpe->Release();
    }
    _pcpe = pcpe;
    _pcpe->AddRef();
    _upAdviseContext = upAdviseContext;
    return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CEIDProvider::UnAdvise()
{
	if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }
    return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles. We return the number
// of fields to be displayed on our active tile, which depends on our connected state. The
// "connected" CEIDCredential has SFI_NUM_FIELDS fields, whereas the "disconnected" 
// CMessageCredential has SMFI_NUM_FIELDS fields.
HRESULT CEIDProvider::GetFieldDescriptorCount(
    DWORD* pdwCount
    )
{
	_CredentialList.Lock();
	if (_CredentialList.HasContainerHolder())
    {
        *pdwCount = SFI_NUM_FIELDS;
    }
    else
    {
        *pdwCount = SMFI_NUM_FIELDS;
    }
   _CredentialList.Unlock();
   EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"pdwCount %d",*pdwCount);
    return S_OK;
}

// Gets the field descriptor for a particular field. Note that we need to determine which
// tile to use based on the "connected" status.
HRESULT CEIDProvider::GetFieldDescriptorAt(
    DWORD dwIndex, 
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{    
    HRESULT hr;
	_CredentialList.Lock();
    if (_CredentialList.HasContainerHolder())
    {
        // Verify dwIndex is a valid field.
        if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
        {
            if (dwIndex != SFI_PIN)
			{
				hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
			}
			else
			{
				*ppcpfd = (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));
				if (*ppcpfd)
				{
					(*ppcpfd)->pszLabel = NULL;
					(*ppcpfd)->dwFieldID = s_rgCredProvFieldDescriptors[dwIndex].dwFieldID;
					(*ppcpfd)->cpft = s_rgCredProvFieldDescriptors[dwIndex].cpft;
					HINSTANCE Handle = LoadLibrary(TEXT("SmartcardCredentialProvider.dll"));
					if (Handle)
					{
						DWORD dwMessageLen = 256;
						PWSTR Message = (PWSTR) CoTaskMemAlloc(dwMessageLen*sizeof(WCHAR));
						if (Message)
						{
							LoadString(Handle, 4, Message, dwMessageLen);
							(*ppcpfd)->pszLabel = Message;
							hr = S_OK;
						}
						else
						{
							hr = HRESULT_FROM_WIN32(GetLastError());
							CoTaskMemFree(Message);
						}
						FreeLibrary(Handle);
					}
					else
					{

						hr = S_OK;
					}
				}
				else
				{
					hr = E_OUTOFMEMORY;
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
				}
			}
        }
        else
        { 
            hr = E_INVALIDARG;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        }
    }
    else
    {
        // Verify dwIndex is a valid field.
        if ((dwIndex < SMFI_NUM_FIELDS) && ppcpfd)
        {
            hr = FieldDescriptorCoAllocCopy(s_rgMessageCredProvFieldDescriptors[dwIndex], ppcpfd);
        }
        else
        { 
            hr = E_INVALIDARG;
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_INVALIDARG");
        }
    }
	if (!SUCCEEDED(hr))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not SUCCEEDED hr=0x%08x",hr);
	}
	_CredentialList.Unlock();
	//EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"dwIndex %d pszLabel %s dwFieldID %d cpft %d",dwIndex,(*ppcpfd)->pszLabel, (*ppcpfd)->dwFieldID, (*ppcpfd)->cpft );
    return hr;
}


HRESULT CEIDProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault
    )
{
	if (_fDontShowAnything)
	{
		*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		*pdwCount = 0;
	}
	else
	{
		_CredentialList.Lock();
		if (_CredentialList.HasContainerHolder())
		{
			*pdwCount = _CredentialList.ContainerHolderCount();
			if (*pdwCount > 1)
			{
				*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
			}
			else
			{
				*pdwDefault = 0;
			}
		}
		else
		{
			// hide the tile when :
			// in Logon
			// and Smart Card Logon requiered active
			*pdwCount = 1;
			if (_cpus == CPUS_LOGON)
			{
				if (!GetPolicyValue(scforceoption))
				{
					*pdwCount = 0;
				}
			}
			if (!_pMessageCredential) *pdwCount = 0;
			*pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
		}
		_CredentialList.Unlock();
	}
    *pbAutoLogonWithDefault = FALSE;
	//EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"pdwCount %d, pdwDefault %d", *pdwCount, *pdwDefault);
    return S_OK;
}

// Returns the credential at the index specified by dwIndex. This function is called
// to enumerate the tiles. Note that we need to return the right credential, which depends
// on whether we're connected or not.
HRESULT CEIDProvider::GetCredentialAt(
    DWORD dwIndex, 
    ICredentialProviderCredential** ppcpc
    )
{
    HRESULT hr;
	// Make sure the parameters are valid.
    if (ppcpc)
    {
        _CredentialList.Lock();
		if (_CredentialList.HasContainerHolder())
        {
			CEIDCredential* EIDCredential = _CredentialList.GetContainerHolderAt(dwIndex);
			if (EIDCredential != NULL)
			{
				hr = EIDCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
			}
			else
			{
				hr = E_INVALIDARG;
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDCredential NULL");
			}
			
        }
        else
        {
            hr = _pMessageCredential->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
        }
		_CredentialList.Unlock();
    }
    else
    {
        hr = E_INVALIDARG;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ppcpc NULL");
    }
    if (!SUCCEEDED(hr))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not SUCCEEDED hr=0x%08x",hr);
	}
    return hr;
}

// Boilerplate method to create an instance of our provider. 
HRESULT CEIDProvider_CreateInstance(REFIID riid, void** ppv)
{
    HRESULT hr;
	if (riid != IID_ICredentialProvider) return E_NOINTERFACE;
    CEIDProvider* pProvider = new CEIDProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"E_OUTOFMEMORY");
    }
    if (!SUCCEEDED(hr))
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"not SUCCEEDED hr=0x%08x",hr);
	}
    return hr;
}

