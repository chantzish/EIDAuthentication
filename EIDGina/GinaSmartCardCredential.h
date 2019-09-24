#pragma once

class GinaSmartCardCredential
{
public:
	GinaSmartCardCredential(CContainer* container);
	virtual ~GinaSmartCardCredential();

	
	CContainer* GetContainer();
	void Release();
	void SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,__in DWORD dwFlags);
private:
	CContainer* _pContainer;

};