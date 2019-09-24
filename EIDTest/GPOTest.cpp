
#include <windows.h>
#include <tchar.h>
#include "../EIDCardLibrary/GPO.h"

void Menu_AP_GPO()
{
	WCHAR buffer[4096];
	
	LPWSTR pMessage = L"AllowSignatureOnlyKeys: %d\r\n\
AllowCertificatesWithNoEKU %d\r\n\
AllowTimeInvalidCertificates %d\r\n\
AllowIntegratedUnblock %d\r\n\
ReverseSubject %d\r\n\
X509HintsNeeded %d\r\n\
IntegratedUnblockPromptString %d\r\n\
CertPropEnabledString %d\r\n\
CertPropRootEnabledString %d\r\n\
RootsCleanupOption %d\r\n\
FilterDuplicateCertificates %d\r\n\
ForceReadingAllCertificates %d\r\n\
scforceoption %d\r\n\
scremoveoption %d";

	swprintf_s(buffer,4096,pMessage,GetPolicyValue(AllowSignatureOnlyKeys),
		GetPolicyValue(AllowCertificatesWithNoEKU),
		GetPolicyValue(AllowTimeInvalidCertificates),
		GetPolicyValue(AllowIntegratedUnblock),
		GetPolicyValue(ReverseSubject),
		GetPolicyValue(X509HintsNeeded),
		GetPolicyValue(IntegratedUnblockPromptString),
		GetPolicyValue(CertPropEnabledString),
		GetPolicyValue(CertPropRootEnabledString),
		GetPolicyValue(RootsCleanupOption),
		GetPolicyValue(FilterDuplicateCertificates),
		GetPolicyValue(ForceReadingAllCertificates),
		GetPolicyValue(scforceoption),
		GetPolicyValue(scremoveoption));
	MessageBox(NULL,buffer,L"Policy",0);

}