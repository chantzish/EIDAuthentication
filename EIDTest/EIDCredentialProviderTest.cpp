#include "stdafx.h"

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <WinCred.h>
#include <tchar.h>
#include <credentialprovider.h>
#define SECURITY_WIN32
#include <Security.h>
#include <sspi.h>
#include <schannel.h>
#include <credssp.h>
#include <Ntdsapi.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/guid.h"
#include "../EIDCardLibrary/package.h"

#include "EIDTestUIUtil.h"

#pragma comment(lib,"Credui")
#pragma comment(lib,"Ntdsapi")
extern HWND hMainWnd;

#include "EIDCredentialProviderTest.h"

AuthenticationType authenticationType;

void SetAuthentication(AuthenticationType type)
{
	authenticationType = type;
}

void menu_CREDSSP_DEL_REG()
{
	RegDeleteTree(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"));
}


void menu_CREDSSP_ADD_REG()
{
	menu_CREDSSP_DEL_REG();
	DWORD dwValue = 1;
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowDefCredentialsWhenNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowDefNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowDefaultCredentials"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowDefault"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowFreshCredentials"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowFresh"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowFreshCredentialsWhenNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowFreshNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowSavedCredentials"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowSaved"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("AllowSavedCredentialsWhenNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation"), 
		TEXT("ConcatenateDefaults_AllowSavedNTLMOnly"), REG_DWORD, &dwValue,sizeof(DWORD));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowDefaultCredentials"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowDefCredentialsWhenNTLMOnly"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowFreshCredentials"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowFreshCredentialsWhenNTLMOnly"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowSavedCredentials"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
	RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
		TEXT("SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\AllowSavedCredentialsWhenNTLMOnly"), 
		TEXT("1"), REG_SZ, TEXT("EIDAuthenticate"),sizeof(TEXT("EIDAuthenticate")));
}

BOOL AuthenticateWithLsaLogonUser(LONG authPackage, PVOID authBuffer, DWORD authBufferSize)
{
	BOOL fReturn = FALSE;
	LSA_HANDLE hLsa;
	MSV1_0_INTERACTIVE_PROFILE *Profile;
	ULONG ProfileLen;
	LSA_STRING Origin = { (USHORT)strlen("MYTEST"), (USHORT)sizeof("MYTEST"), "MYTEST" };
	TOKEN_SOURCE Source = { "TEST", { 0, 101 } };
	QUOTA_LIMITS Quota = {0};
	LUID Luid;
	NTSTATUS err,stat;
	HANDLE Token;
	err = LsaConnectUntrusted(&hLsa);
	
	err = LsaLogonUser(hLsa, &Origin, (SECURITY_LOGON_TYPE)  Interactive , authPackage, authBuffer,authBufferSize,NULL, &Source, (PVOID*)&Profile, &ProfileLen, &Luid, &Token, &Quota, &stat);
	
	LsaDeregisterLogonProcess(hLsa);
	if (err)
	{
		SetLastError(LsaNtStatusToWinError(err));
	}
	else
	{
		fReturn = TRUE;
		LsaFreeReturnBuffer(Profile);
		CloseHandle(Token);
		
	}
	return fReturn;
}

BOOL IsElevated();
BOOL AddServerCertInfo(IN OUT PSCHANNEL_CRED pSchannelCred)
{
    BOOL fRet = FALSE;
 
    LPWSTR pwszSubjectName = NULL;
    TCHAR szMachineName[256];
    DWORD cchMachineName  = ARRAYSIZE(szMachineName);
 
    HCERTSTORE  hCertStore = NULL;
    PCCERT_CONTEXT*  ppCertContext   = NULL; // server cert array
    BOOL fCloseStore = FALSE;
 
	__try
	{
		if (!IsElevated())
		{
			MessageBox(hMainWnd,TEXT("Must be admin to access certificate"),TEXT("Error"),0);
			__leave;
		}
		if (!pSchannelCred)
		{
			__leave;
		}
	 
		
		if (!pwszSubjectName)
		{
			if( !GetComputerNameExW( ComputerNameNetBIOS,
									szMachineName,
									&cchMachineName) )
			{     
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"hCertStore null"); 
				__leave;
			}
			pwszSubjectName = szMachineName;
		} 
	   
	  
		if( !hCertStore )
		{
			// Open LM:MY store
			hCertStore = CertOpenStore(
							   CERT_STORE_PROV_SYSTEM,
							   X509_ASN_ENCODING,
							   0,
							   CERT_SYSTEM_STORE_LOCAL_MACHINE,
							   TEXT("MY") );
	           
			if(!hCertStore)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"hCertStore null");
				__leave;
			}
		}
	 
		ppCertContext = (PCCERT_CONTEXT *) EIDAlloc( sizeof(PCCERT_CONTEXT) * 1);
		memset(ppCertContext, 0, sizeof(PCCERT_CONTEXT) * 1);
		if( !ppCertContext )
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ppCertContext null");
			__leave;
		}
	   
		// Find server certificates using the server cert CN
		// Simply searching for a certificate that contains
		// the supplied name somewhere in the subject name.
		ppCertContext[0] = CertFindCertificateInStore(
								   hCertStore,
								   X509_ASN_ENCODING,
								   0,
								   CERT_FIND_SUBJECT_STR_A,
								   pwszSubjectName,
								   ppCertContext[0]);
	   
		if(!ppCertContext[0])
		{    
			MessageBox(hMainWnd,TEXT("Certificate must found. Do not forget to create it "),TEXT("Error"),0);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ppCertContext[0] null");
			__leave;
		}
	 
		pSchannelCred->cCreds = 1;
		pSchannelCred->paCred =  ppCertContext;
		pSchannelCred->dwCredFormat = 0;
	   
		fRet = TRUE;
	}
	__finally
	{
  
		if(hCertStore)
		{
			CertCloseStore(hCertStore, 0);
		}   
	}
    return fRet;
}

BOOL AuthenticateWithSSPI(PTSTR szPrincipal, PTSTR szPassword, PTSTR szSSP)
{

	BOOL fReturn = FALSE;
	DWORD err;
	TCHAR szDomain[255] = TEXT("");
	TCHAR szUser[255] = TEXT("");

	TCHAR szTarget[256]=TEXT("EIDAuthenticate");
	PTSTR szSeparator = _tcschr(szPrincipal, '\\');
	if (szSeparator)
	{
		_tcscpy_s(szUser,ARRAYSIZE(szUser),szSeparator +1);
		_tcscpy_s(szDomain,ARRAYSIZE(szDomain),szPrincipal);
		szSeparator = _tcschr(szDomain, '\\');
		szSeparator[0] = 0;

	}
	else
	{
		_tcscpy_s(szUser,ARRAYSIZE(szUser),szPrincipal);
	}
	SEC_WINNT_AUTH_IDENTITY_EX authIdent = {
        SEC_WINNT_AUTH_IDENTITY_VERSION,
        sizeof authIdent,
        (unsigned short *)szUser,
		(DWORD)_tcsclen(szUser),
        (unsigned short *)szDomain,
		(DWORD)_tcsclen(szDomain),
		(unsigned short *)szPassword,
		(DWORD)_tcsclen(szPassword),
#ifdef UNICODE
        SEC_WINNT_AUTH_IDENTITY_UNICODE
#else
		SEC_WINNT_AUTH_IDENTITY_ANSI
#endif
        ,0, 0
    };
	CtxtHandle hctxClient = {0,0};
	CtxtHandle hctxServer = {0,0};
	// create two buffers:
	//    one for the client sending tokens to the server,
	//    one for the server sending tokens to the client
	// (buffer size chosen based on current Kerb SSP setting
	//  for cbMaxToken - you may need to adjust this)
	BYTE bufC2S[8000];
	BYTE bufS2C[8000];
	SecBuffer sbufC2S = { sizeof bufC2S, SECBUFFER_TOKEN, bufC2S };
	SecBuffer sbufS2C = { sizeof bufS2C, SECBUFFER_TOKEN, bufS2C };
	SecBufferDesc bdC2S = { SECBUFFER_VERSION, 1, &sbufC2S };
	SecBufferDesc bdS2C = { SECBUFFER_VERSION, 1, &sbufS2C };

	// don't really need any special context attributes
	DWORD grfRequiredCtxAttrsClient = NULL;//ASC_REQ_DELEGATE | ASC_REQ_CONNECTION | ASC_REQ_ALLOCATE_MEMORY;
	DWORD grfRequiredCtxAttrsServer = NULL;//ASC_REQ_DELEGATE | ASC_REQ_CONNECTION | ASC_REQ_ALLOCATE_MEMORY;

	// set up some aliases to make it obvious what's happening
	PCtxtHandle    pClientCtxHandleIn  = 0;
	PCtxtHandle    pClientCtxHandleOut = &hctxClient;
	PCtxtHandle    pServerCtxHandleIn  = 0;
	PCtxtHandle    pServerCtxHandleOut = &hctxServer;
	SecBufferDesc* pClientInput  = 0;
	SecBufferDesc* pClientOutput = &bdC2S;
	SecBufferDesc* pServerInput  = &bdC2S;
	SecBufferDesc* pServerOutput = &bdS2C;
	DWORD          grfCtxAttrsClient = 0;
	DWORD          grfCtxAttrsServer = 0;
	TimeStamp      expiryClientCtx;
	TimeStamp      expiryServerCtx;
	bool bClientContinue = true;
	bool bServerContinue = true;
	CredHandle hcredClient;
	CredHandle hcredServer;
	TimeStamp expiryClient;
	TimeStamp expiryServer;
	CREDSSP_CRED CredClient, CredServer;
	SCHANNEL_CRED SchannelServerCred, SchannelClientCred;
	PVOID pCredClient = NULL, pCredServer = NULL;
	memset(&CredClient, 0, sizeof(CREDSSP_CRED));
	memset(&CredServer, 0, sizeof(CREDSSP_CRED));
	memset(&SchannelServerCred, 0, sizeof(SCHANNEL_CRED));
	memset(&SchannelClientCred, 0, sizeof(SCHANNEL_CRED));
	__try
	{
		if (_tcscmp(szSSP,TEXT("credssp")) == 0)
		{
			
			
			CredServer.pSchannelCred = &SchannelServerCred;
			CredClient.pSchannelCred = &SchannelClientCred;
			CredClient.pSpnegoCred  = &authIdent;

			SchannelServerCred.dwVersion = SCHANNEL_CRED_VERSION;
			SchannelClientCred.dwVersion = SCHANNEL_CRED_VERSION;
			if (!AddServerCertInfo(&SchannelServerCred))
			{
				err = GetLastError();
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AddServerCertInfo 0x%08x",err);
				__leave;
			}

			pCredServer = &CredServer;
			pCredClient = &CredClient;
			grfRequiredCtxAttrsClient = ASC_REQ_DELEGATE | ASC_REQ_CONNECTION | ASC_REQ_ALLOCATE_MEMORY;
			grfRequiredCtxAttrsServer = ASC_REQ_DELEGATE | ASC_REQ_CONNECTION | ASC_REQ_ALLOCATE_MEMORY;
		}
		else
		{
			pCredClient = &authIdent;
		}
		
		err = AcquireCredentialsHandle(NULL, szSSP, SECPKG_CRED_OUTBOUND,
											0, pCredClient, 0, 0,
											&hcredClient, &expiryClient);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcquireCredentialsHandle client 0x%08x",err);
		if (err != SEC_E_OK)
		{
			__leave;
		}
		AcquireCredentialsHandle(0, szSSP, SECPKG_CRED_INBOUND,
											  0, pCredServer, 0, 0, &hcredServer,
											  &expiryServer);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcquireCredentialsHandle server 0x%08x",err);
		if (err != SEC_E_OK)
		{
			__leave;
		}
		int packetnum = 1;
		// since the caller is acting as the server, we need
		// a server principal name so that the client will
		// be able to get a Kerb ticket (if Kerb is used)
		// perform the authentication handshake, playing the
		// role of both client *and* server.
		while (bClientContinue || bServerContinue) {
			if (bClientContinue) {
				sbufC2S.cbBuffer = sizeof bufC2S;
				err = InitializeSecurityContext(
					&hcredClient, pClientCtxHandleIn,
					szTarget,
					grfRequiredCtxAttrsClient,
					0, SECURITY_NATIVE_DREP,
					pClientInput, 0,
					pClientCtxHandleOut,
					pClientOutput,
					&grfCtxAttrsClient,
					&expiryClientCtx);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContext 0x%08x",err);
				switch (err) {
					case 0:
						bClientContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pClientCtxHandleIn = pClientCtxHandleOut;
						pClientInput       = pServerOutput;
						break;
					default:
						__leave;
				}
				
				if (packetnum == 1 && _tcscmp(szSSP,TEXT("Negotiate")) == 0)
				{
					// on essaie de vérifier la négotiation
					if (strcmp((PCHAR)bufC2S,("NTLMSSP")) == 0)
					{
						MessageBox(hMainWnd,TEXT("Only NTLM SSP availale"),TEXT("test"),0);
					}
				}
				packetnum++;
			}
			
			if (bServerContinue) {
				sbufS2C.cbBuffer = sizeof bufS2C;
				err = AcceptSecurityContext(
					&hcredServer, pServerCtxHandleIn,
					pServerInput,
					grfRequiredCtxAttrsServer,
					SECURITY_NATIVE_DREP,
					pServerCtxHandleOut,
					pServerOutput,
					&grfCtxAttrsServer,
					&expiryServerCtx);
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContext 0x%08x",err);
				switch (err) {
					case 0:
						bServerContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pServerCtxHandleIn = pServerCtxHandleOut;
						break;
					default:
						__leave;
				}
				packetnum++;
			}
		}
		if (_tcscmp(szSSP,TEXT("Negotiate")) == 0)
		{
			SecPkgContext_NegotiationInfo negoinfo;
			err = QueryContextAttributes(pClientCtxHandleOut,SECPKG_ATTR_NEGOTIATION_INFO, &negoinfo);
			if (err != SEC_E_OK)
			{
				MessageBoxWin32(err);
			}
			else
			{
				MessageBox(hMainWnd, negoinfo.PackageInfo->Name, TEXT("Security Package Used"),NULL);
			}
		}
		else if (_tcscmp(szSSP,TEXT("credssp")) == 0)
		{
			SecPkgContext_PackageInfo negoinfo;
			err = QueryContextAttributes(pClientCtxHandleOut,SECPKG_ATTR_NEGOTIATION_PACKAGE, &negoinfo);
			if (err != SEC_E_OK)
			{
				MessageBoxWin32(err);
			}
			else
			{
				MessageBox(hMainWnd, negoinfo.PackageInfo->Name, TEXT("Security Package Used"),NULL);
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"before  ImpersonateSecurityContext",err);
		err = ImpersonateSecurityContext(pServerCtxHandleOut);
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"after  ImpersonateSecurityContext",err);
		if (err  != SEC_E_OK)
		{
			MessageBoxWin32(err);
		}
		else
		{
			TCHAR szUserName[256];
			DWORD cbUserName = ARRAYSIZE(szUserName);
			GetUserName (szUserName, &cbUserName);
			MessageBox(hMainWnd, szUserName, TEXT("Connected as"),NULL);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"before  RevertSecurityContext",err);
			RevertSecurityContext (pServerCtxHandleOut);
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"after  RevertSecurityContext",err);
		}
		// clean up
		FreeCredentialsHandle(&hcredClient);
		FreeCredentialsHandle(&hcredServer);
		DeleteSecurityContext(pServerCtxHandleOut);
		DeleteSecurityContext(pClientCtxHandleOut);
		fReturn = TRUE;
	}
	__finally
	{
		if (SchannelServerCred.paCred)
		{
			PCCERT_CONTEXT* ppCertContext = (PCCERT_CONTEXT*) SchannelServerCred.paCred;
			CertFreeCertificateContext(ppCertContext[0]);
			EIDFree(ppCertContext);
		}

	}
	SetLastError(err);
	return fReturn;
}

BOOL AuthenticateWithSSPIWrapper(LONG authPackage, PVOID authBuffer, DWORD authBufferSize)
{
	 
    TCHAR szSSP[255] = TEXT("Negotiate");
	SECURITY_STATUS err;
	DWORD dwNbPackage;
	PSecPkgInfo pPackageInfo;
	HANDLE hLsa;
	NTSTATUS status = LsaConnectUntrusted(&hLsa);
	if (status != STATUS_SUCCESS)
	{
		SetLastError(LsaNtStatusToWinError(status));
		return FALSE;
	}
	err = EnumerateSecurityPackages(&dwNbPackage, &pPackageInfo);
	if (err != SEC_E_OK)
	{
		SetLastError(err);
		return FALSE;
	}
	for(DWORD dwI = 0; dwI < dwNbPackage; dwI++)
	{
		ULONG ulAuthPackage;
        LSA_STRING lsaszPackageName;
		CHAR szTemp[255];
		WideCharToMultiByte(CP_ACP, 0, pPackageInfo[dwI].Name,(int) _tcsclen(pPackageInfo[dwI].Name) +1,
				szTemp, ARRAYSIZE(szTemp), NULL, NULL);
		LsaInitString(&lsaszPackageName,szTemp );

        status = LsaLookupAuthenticationPackage(hLsa, &lsaszPackageName, &ulAuthPackage);
		if (status == STATUS_SUCCESS && ulAuthPackage == authPackage)
		{
			_tcscpy_s(szSSP, ARRAYSIZE(szSSP), pPackageInfo[dwI].Name);
			break;
		}
	}
	FreeContextBuffer(pPackageInfo);
	LsaDeregisterLogonProcess(hLsa);

	if (authenticationType == CredSSP)
	{
		_tcscpy_s(szSSP, ARRAYSIZE(szSSP),TEXT("credssp"));
	}

	TCHAR szPrincipal[255] = TEXT("");
	DWORD dwPrincipalSize = ARRAYSIZE(szPrincipal);
	TCHAR szDomain[255] = TEXT("");
	DWORD dwDomainSize = ARRAYSIZE(szDomain);
	TCHAR szPassword[255] = TEXT("");
	DWORD dwPasswordSize = ARRAYSIZE(szPassword);
	if (!CredUnPackAuthenticationBuffer(0, authBuffer, authBufferSize, 
						szPrincipal, &dwPrincipalSize,
						szDomain, &dwDomainSize,
						szPassword, &dwPasswordSize))
	{
		
		return FALSE;
	}
	return AuthenticateWithSSPI(szPrincipal,szPassword, szSSP);
}

void Menu_CREDENTIALUID_GENERIC(DWORD dwFlag)
{
	BOOL save = false;
	DWORD authPackage = 0;
	LPVOID authBuffer;
	ULONG authBufferSize = 0;
	CREDUI_INFO credUiInfo;

	if (dwFlag & CREDUIWIN_AUTHPACKAGE_ONLY)
	{
		RetrieveNegotiateAuthPackage(&authPackage);
	}

	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 

	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;

	DWORD result = 0;
	result = CredUIPromptForWindowsCredentials(&(credUiInfo), 0, &(authPackage), 
		NULL, 0, &authBuffer, &authBufferSize, &(save), dwFlag);
	if (result == ERROR_SUCCESS)
	{
		//AuthenticateWithLsaLogonUser(authPackage,authBuffer,authBufferSize);
		if (AuthenticateWithSSPIWrapper(authPackage,authBuffer,authBufferSize))
		{
			MessageBox(hMainWnd,_T("Credential Valid"),_T("result"),0);
		}
		else
		{
			MessageBoxWin32(GetLastError());
		}
		CoTaskMemFree(authBuffer);
	}
	else if (result == ERROR_CANCELLED)
	{

	}
	else
	{
		MessageBoxWin32(result);
	}
	result = CredUIConfirmCredentials(NULL,FALSE);
}

void Menu_CREDENTIALUID()
{
	Menu_CREDENTIALUID_GENERIC(0);
}

void Menu_CREDENTIALUID_ADMIN()
{
	Menu_CREDENTIALUID_GENERIC(CREDUIWIN_ENUMERATE_ADMINS);
}

void Menu_CREDENTIALUID_ONLY_EID()
{
	Menu_CREDENTIALUID_GENERIC(CREDUIWIN_AUTHPACKAGE_ONLY);
}

void menu_CREDENTIALUID_OldBehavior()
{
	DWORD dwStatus;
	CREDUI_INFO credUiInfo;
	TCHAR szUsername[CREDUI_MAX_USERNAME_LENGTH+1] = TEXT("");
	TCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH+1] = TEXT("");
	TCHAR szTarget[256];
	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;
	DWORD dwSize = ARRAYSIZE(szTarget);
	GetComputerName(szTarget,&dwSize);
	dwStatus = CredUIPromptForCredentials(&credUiInfo, szTarget, NULL, 0, 
		szUsername, CREDUI_MAX_USERNAME_LENGTH,
		szPassword, CREDUI_MAX_PASSWORD_LENGTH,
		FALSE, 0);
	PTSTR szSSP;
	if (dwStatus == NO_ERROR)
	{
		if (authenticationType == Negociate)
		{
			szSSP = TEXT("Negotiate");
		}
		else if (authenticationType == NTLM)
		{
			szSSP = TEXT("NTLM");
		}
		else if (authenticationType == CredSSP)
		{
			szSSP = TEXT("credssp");
		}
		else
		{
			szSSP = AUTHENTICATIONPACKAGENAMET;
		}
		
		if (!AuthenticateWithSSPI(szUsername, szPassword,szSSP))
		{
			MessageBoxWin32(GetLastError());
		}
		else
		{
			MessageBox(hMainWnd,_T("Credential Valid"),_T("result"),0);
		}
	}
	else if (dwStatus == ERROR_CANCELLED)
	{
	}
	else
	{
		MessageBoxWin32(dwStatus);
	}
	CredUIConfirmCredentials(NULL,FALSE);
}

void menu_CRED_COM()
{
	ICredentialProvider* m_pIMyCredentialProvider = NULL;
	DWORD dwCount;
	DWORD dwCountDefault;
	BOOL bAutoLogon;
	ICredentialProviderCredential* m_pMyID = NULL;
	PWSTR pwszOptionalStatusText;
	CREDENTIAL_PROVIDER_STATUS_ICON cpsiOptionalStatusIcon;
	CoInitializeEx(NULL,COINIT_APARTMENTTHREADED); 
	CoCreateInstance(CLSID_CEIDProvider,NULL,CLSCTX_INPROC_SERVER,IID_ICredentialProvider,(void**)&m_pIMyCredentialProvider);
	//CoCreateInstance(CLSID_SmartcardCredentialProvider,NULL,CLSCTX_INPROC_SERVER,IID_ICredentialProvider,(void**)&m_pIMyCredentialProvider);
	m_pIMyCredentialProvider->SetUsageScenario(CPUS_CREDUI,0);
	Sleep(1000);
	m_pIMyCredentialProvider->GetCredentialCount(&dwCount,&dwCountDefault,&bAutoLogon);
	m_pIMyCredentialProvider->GetCredentialAt(0,&m_pMyID);
	m_pMyID->ReportResult(STATUS_ACCOUNT_RESTRICTION,STATUS_SUCCESS,&pwszOptionalStatusText,&cpsiOptionalStatusIcon);
	Sleep(1000);
	m_pMyID->Release();
	m_pIMyCredentialProvider->Release();
}

typedef BOOL (NTAPI * PRShowRestoreFromMsginaW) (DWORD, DWORD, PWSTR, DWORD);
void menu_ResetPasswordWizard()
{
	WCHAR szUserName[256];
	WCHAR szComputerName[256];
	HMODULE keymgrDll = NULL;
	if (AskUsername(szUserName, szComputerName))
	{
		__try
		{
			keymgrDll = LoadLibrary(TEXT("keymgr.dll"));
			if (!keymgrDll)
			{
				__leave;
			}
			PRShowRestoreFromMsginaW MyPRShowRestoreFromMsginaW = (PRShowRestoreFromMsginaW) GetProcAddress(keymgrDll,"PRShowRestoreFromMsginaW");
			if (!MyPRShowRestoreFromMsginaW)
			{
				__leave;
			}
			MyPRShowRestoreFromMsginaW(NULL,NULL,szUserName,NULL);
		}
		__finally
		{
			if (keymgrDll)
				FreeLibrary(keymgrDll);
		}
	}
}