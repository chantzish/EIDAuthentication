#include <Windows.h>
#include <WinCrypt.h>
#include <credentialprovider.h>
#include "../EIDCardLibrary/CContainer.h"
#include "GinaSmartCardCredential.h"


GinaSmartCardCredential::GinaSmartCardCredential(CContainer* container)
{
	_pContainer = container;
}

GinaSmartCardCredential::~GinaSmartCardCredential()
	{
		if (_pContainer)
		{
			delete _pContainer;
		}
	}

CContainer* GinaSmartCardCredential::GetContainer()
{
	return _pContainer;
}
void GinaSmartCardCredential::Release()
{
}

void GinaSmartCardCredential::SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags)
{

}