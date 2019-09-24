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

#include "CEIDFilter.h"
#include "../EIDCardLibrary/GPO.h"

CEIDFilter::CEIDFilter():
    _cRef(1)
{
}

HRESULT CEIDFilter::UpdateRemoteCredential(      
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *pcpcsOut
)
{
	UNREFERENCED_PARAMETER(pcpcsIn);
	UNREFERENCED_PARAMETER(pcpcsOut);
	return S_OK;
}

HRESULT CEIDFilter::Filter(      
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags,
    GUID *rgclsidProviders,
    BOOL *rgbAllow,
    DWORD cProviders
)
{
	UNREFERENCED_PARAMETER(cpus);
	UNREFERENCED_PARAMETER(dwFlags);
	UNREFERENCED_PARAMETER(rgclsidProviders);
	UNREFERENCED_PARAMETER(rgbAllow);
	UNREFERENCED_PARAMETER(cProviders);
	/*BOOL fFilter = FALSE;
	if (cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION)
	{
		fFilter = (GetPolicyValue(scforceoption) == 1);
	}
	if (fFilter)
	{
		for (DWORD dwI = 0; dwI < cProviders; dwI++)
		{
			if (rgclsidProviders[dwI] == CLSID_PasswordCredentialProvider)
			{
				rgbAllow[dwI] = FALSE;
			}
		}
	}*/
	return S_OK;
}