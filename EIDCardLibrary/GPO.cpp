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
#include <tchar.h>
// needed to avoid LNK2001 with the gpedit.h file (IID_IGroupPolicyObject)
#include <initguid.h>
#include <Gpedit.h>
#include "GPO.h"
#include "Tracing.h"

#pragma comment(lib,"Advapi32")

/** Used to manage policy key retrieval */

TCHAR szMainGPOKey[] = _T("SOFTWARE\\Policies\\Microsoft\\Windows\\SmartCardCredentialProvider");
TCHAR szRemoveGPOKey[] = _T("Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
TCHAR szForceGPOKey[] = _T("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
typedef struct _GPOInfo
{
	LPCTSTR Key;
	LPCTSTR Value;
} GPOInfo;

GPOInfo MyGPOInfo[] = 
{
  {szMainGPOKey, _T("AllowSignatureOnlyKeys") },
  {szMainGPOKey, _T("AllowCertificatesWithNoEKU") },
  {szMainGPOKey, _T("AllowTimeInvalidCertificates") },
  {szMainGPOKey, _T("AllowIntegratedUnblock") },
  {szMainGPOKey, _T("ReverseSubject") },
  {szMainGPOKey, _T("X509HintsNeeded") },
  {szMainGPOKey, _T("IntegratedUnblockPromptString") },
  {szMainGPOKey, _T("CertPropEnabledString") },
  {szMainGPOKey, _T("CertPropRootEnabledString") },
  {szMainGPOKey, _T("RootsCleanupOption") },
  {szMainGPOKey, _T("FilterDuplicateCertificates") },
  {szMainGPOKey, _T("ForceReadingAllCertificates") },
  {szForceGPOKey, _T("scforceoption") },
  {szRemoveGPOKey, _T("scremoveoption") }
};

DWORD GetPolicyValue( GPOPolicy Policy)
{
	HKEY key;
	DWORD value = 0;
	DWORD size = sizeof(DWORD);
	DWORD type=REG_SZ;
	TCHAR szValue[2]=TEXT("0");
	DWORD size2 = sizeof(szValue);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,MyGPOInfo[Policy].Key,NULL, KEY_READ, &key)==ERROR_SUCCESS){
		// for the scremoveoption : DWORD value stored as PTSTR !!!!
		if (Policy == scremoveoption && RegQueryValueEx(key,MyGPOInfo[Policy].Value,NULL, &type,(LPBYTE) &szValue, &size2)==ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s found = %s",MyGPOInfo[Policy].Value,szValue);
			value = _tstoi(szValue);
		}
		else if (RegQueryValueEx(key,MyGPOInfo[Policy].Value,NULL, &type,(LPBYTE) &value, &size)==ERROR_SUCCESS)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s found = %x",MyGPOInfo[Policy].Value,value);
		}
		else
		{
			value = 0;
			EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s value not found = %x",MyGPOInfo[Policy].Value,value);
		}
		RegCloseKey(key);
	}
	else
	{
		value = 0;
		EIDCardLibraryTrace(WINEVENT_LEVEL_INFO,L"Policy %s key not found = %x",MyGPOInfo[Policy].Value,value);
		
	}
	return value;
}
/*
DWORD GetPolicyValue(GPOPolicy Policy)
{
	HRESULT hr=S_OK;
	IGroupPolicyObject* p = NULL;
	DWORD dwSection = GPO_SECTION_MACHINE;
	HKEY hGPOSectionKey = NULL; 
	DWORD dwValue = 0;
    __try
	{
		hr = CoInitialize(NULL);
		if (!SUCCEEDED(hr))
		{ 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CoInitialize");
			__leave;
		}
		hr = CoCreateInstance(CLSID_GroupPolicyObject, NULL,
							  CLSCTX_INPROC_SERVER, IID_IGroupPolicyObject,
							  (LPVOID*)&p);

		if (!SUCCEEDED(hr))
		{ 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CoCreateInstance");
			__leave;
		}
		hr = p->OpenLocalMachineGPO(GPO_OPEN_LOAD_REGISTRY | GPO_OPEN_READ_ONLY);
		if (!SUCCEEDED(hr))
		{ 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"OpenLocalMachineGPO");
			__leave;
		}
		hr = p->GetRegistryKey(dwSection, &hGPOSectionKey); 
		if (!SUCCEEDED(hr))
		{ 
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetRegistryKey");
			__leave;
		}
		dwValue = GetPolicyValueFromReg(hGPOSectionKey, Policy);
	}
	__finally
	{
		if (p)
			hr = p->Release(); 
		if (hGPOSectionKey)
			RegCloseKey(hGPOSectionKey);
		CoUninitialize();
	}
	return dwValue;
}*/

BOOL SetRemovePolicyValue(DWORD dwActivate)
{
	TCHAR szValue[2];
	LONG lReturn;
	DWORD dwError = 0;
	SC_HANDLE hService = NULL;
	SC_HANDLE hServiceManager = NULL;
	SERVICE_STATUS ServiceStatus;
	
	_stprintf_s(szValue, ARRAYSIZE(szValue), TEXT("%d"),dwActivate);
	__try
	{
		lReturn = RegSetKeyValue(HKEY_LOCAL_MACHINE, 
			MyGPOInfo[scremoveoption].Key,
			MyGPOInfo[scremoveoption].Value, REG_SZ, szValue,sizeof(TCHAR)*ARRAYSIZE(szValue));
		if ( lReturn != ERROR_SUCCESS)
		{
			dwError = lReturn;
			__leave;
		}
		hServiceManager = OpenSCManager(NULL,NULL,SC_MANAGER_CONNECT);
		if (!hServiceManager)
		{
			dwError = GetLastError();
			__leave;
		}
		hService = OpenService(hServiceManager, TEXT("ScPolicySvc"), SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
		if (!hService)
		{
			dwError = GetLastError();
			__leave;
		}
		if (dwActivate)
		{	
			// start service
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!StartService(hService,0,NULL))
			{
				dwError = GetLastError();
				__leave;
			}
		}
		else
		{ 
			// stop service
			if (!ChangeServiceConfig(hService, SERVICE_NO_CHANGE, SERVICE_DEMAND_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
			{
				dwError = GetLastError();
				__leave;
			}
			if (!ControlService(hService,SERVICE_CONTROL_STOP,&ServiceStatus))
			{
				dwError = GetLastError();
				if (dwError == ERROR_SERVICE_NOT_ACTIVE)
				{
					// service not active is not an error
					dwError = 0;
				}
				__leave;
			}
			//Boucle d'attente de l'arret
			do{
				if (!QueryServiceStatus(hService,&ServiceStatus))
				{
					dwError = GetLastError();
					__leave;
				}
				Sleep(100);
			} while(ServiceStatus.dwCurrentState != SERVICE_STOPPED); 
		}
	}
	__finally
	{
		if (hService)
			CloseServiceHandle(hService);
		if (hServiceManager)
			CloseServiceHandle(hServiceManager);
	}
	return dwError == 0;
}

BOOL SetPolicyValue(GPOPolicy Policy, DWORD dwValue)
{
	BOOL fReturn = FALSE;
	if (Policy == scremoveoption)
	{
		// special case because a service has to be configured and the value is stored as string instead of DWORD
		fReturn = SetRemovePolicyValue(dwValue);
	}
	else
	{
		fReturn = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
				MyGPOInfo[Policy].Key,
				MyGPOInfo[Policy].Value, REG_DWORD, &dwValue,sizeof(dwValue));
	}
	return fReturn;
}