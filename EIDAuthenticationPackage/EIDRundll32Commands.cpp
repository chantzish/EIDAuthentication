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

#include <windows.h>
#include <Msiquery.h>

#pragma comment(lib,"Msi.lib")

#include "../EIDCardLibrary/Registration.h"
#include "../EIDCardLibrary/XPCompatibility.h"
#include "../EIDCardLibrary/Tracing.h"

BOOL LsaEIDRemoveAllStoredCredential();

extern "C"
{
	
	void NTAPI DllRegister()
	{
		EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();
		RegisterTheSecurityPackage();
	}

	void NTAPI DllUnRegister()
	{
		EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();
		UnRegisterTheSecurityPackage();
	}

	void NTAPI DllEnableLogging()
	{
		if (!EnableLogging())
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	void NTAPI DllDisableLogging()
	{
		if (!DisableLogging())
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBoxWin32(0);
		}
	}

	int NTAPI Commit(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllRegister();
		EIDCredentialProviderDllRegister();
		EIDPasswordChangeNotificationDllRegister();
		EIDConfigurationWizardDllRegister();*/
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			if (!RegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				// a deferred action cannot order a reboot through MSI functions (setmode, set property, ...)
				// hopefully, Wix has a immediate action which checks an ATOM to set the reboot flag
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}

	int NTAPI Uninstall(MSIHANDLE hInstall)
	{
		UNREFERENCED_PARAMETER(hInstall);
		/*EIDAuthenticationPackageDllUnRegister();
		EIDCredentialProviderDllUnRegister();
		EIDPasswordChangeNotificationDllUnRegister();
		EIDConfigurationWizardDllUnRegister();*/
		DWORD dwError = 0;
		int ret = ERROR_INSTALL_FAILURE;
		__try
		{
			if (!LsaEIDRemoveAllStoredCredential())
			{
				dwError = GetLastError();
				__leave;
			}
			// this function is unimplemented and trigger the reboot,
			// but call it anyway
			if (!UnRegisterTheSecurityPackage())
			{
				dwError = GetLastError();
				__leave;
			}
			ret = ERROR_SUCCESS;
		}
		__finally
		{
			if (dwError == ERROR_FAIL_NOACTION_REBOOT)
			{
				GlobalAddAtom(TEXT("WcaDeferredActionRequiresReboot"));
				ret = ERROR_SUCCESS;
			}
			else if (dwError != 0)
			{
				MessageBoxWin32(dwError);
			}
		}
		return ret;
	}
}