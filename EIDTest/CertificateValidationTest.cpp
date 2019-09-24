#include <windows.h>
#include <tchar.h>
#include "EIDTestUIUtil.h"
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/CertificateValidation.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CertificateUtilities.h"

void menu_CREDENTIAL_Certificate()
{
	WCHAR szReader[256];
	WCHAR szCard[256];
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD dwProviderNameLen = 256;
	if (AskForCard(szReader,256,szCard,256))
	{
		if (pCertContext = SelectCert(szReader,szCard))
		{
		
			/*LPTSTR szUserName = GetUserNameFromCertificate(pCertContext);
			DWORD dwError = 0;
			if (szUserName)
			{
				MessageBox(NULL,szUserName,_T("UserName = "),0);
			}
			else
			{
				MessageBox(NULL,_T("UserName not found"),_T("UserName not found"),0);
			}
			EIDFree(szUserName);*/
			if (IsTrustedCertificate(pCertContext))
			{
				MessageBox(NULL,_T("The Certificate is valid"),_T("The Certificate is valid"),0);
			}
			else
			{
				MessageBoxWin32(GetLastError());
			}
			CertFreeCertificateContext(pCertContext);
		}
	}
}