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

#include <credentialprovider.h>

template <typename T> 

class CContainerHolderFactory
{
public:	
	CContainerHolderFactory();
	virtual ~CContainerHolderFactory();

	HRESULT SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
	BOOL DisconnectNotification(__in LPCTSTR szReaderName);
	BOOL ConnectNotification(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL CContainerHolderFactory<T>::CreateContainer(__in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szWideContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount, __in PCCERT_CONTEXT pCertContext);
	BOOL CreateItemFromCertificateBlob(__in HCRYPTPROV hProv, __in LPCTSTR szReaderName,__in LPCTSTR szCardName,
															   __in LPCTSTR szProviderName, __in LPCTSTR szContainerName,
															   __in DWORD KeySpec, __in USHORT ActivityCount,
															   __in PBYTE Data, __in DWORD DataSize);
	VOID Lock();
	VOID Unlock();
	BOOL HasContainerHolder();
	DWORD ContainerHolderCount();
	T* GetContainerHolderAt(DWORD dwIndex);
private:
	BOOL ConnectNotificationGeneric(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL ConnectNotificationBeid(__in LPCTSTR szReaderName,__in LPCTSTR szCardName, __in USHORT ActivityCount);
	BOOL CleanList();
	CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    DWORD _dwFlags;
	std::list<T*> _CredentialList;
	CRITICAL_SECTION CriticalSection;
	
};



#include "CContainerHolderFactory.cpp"