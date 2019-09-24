#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>
#include <tchar.h>
#include <Ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <NTSecPkg.h> 
#include <WinCred.h>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CredentialManagement.h"
#include "LSAFunctionSubstitute.h"

extern HWND hMainWnd;

HMODULE Handle = NULL;
PSECPKG_FUNCTION_TABLE functionTable = NULL;
ULONG functionCount = 0;
ULONG_PTR PackageId = 1;
LSA_SECPKG_FUNCTION_TABLE LSAfunction;

void InitializeDll()
{
	ULONG PackageVersion = 0;
	if (!Handle)
	{
		SpLsaModeInitializeFn init = NULL;
		Handle = LoadLibrary(TEXT("EIDAuthenticationPackage.dll"));
		init = (SpLsaModeInitializeFn) GetProcAddress(Handle, SECPKG_LSAMODEINIT_NAME);
		NTSTATUS Status = init(SECPKG_INTERFACE_VERSION, &PackageVersion, &functionTable, &functionCount); 
		if (Status != STATUS_SUCCESS)
		{
			MessageBoxWin32(LsaNtStatusToWinError(Status));
			return;
		}
		memset(&LSAfunction, 0, sizeof(LSA_SECPKG_FUNCTION_TABLE));
		LSAfunction.AllocateClientBuffer = EIDCardLibraryTestMyAllocateClientBuffer;
		LSAfunction.FreeClientBuffer = EIDCardLibraryMyFreeClientBuffer;
		LSAfunction.CopyToClientBuffer =  EIDCardLibraryMyCopyToClientBuffer;
		LSAfunction.GetClientInfo =  EIDCardLibraryMyGetClientInfo;
		LSAfunction.AllocateLsaHeap = EIDCardLibraryMyAllocateLsaHeap;
		LSAfunction.FreeLsaHeap = EIDCardLibraryMyFreeLsaHeap;
		LSAfunction.CopyFromClientBuffer = EIDCardLibraryMyCopyFromClientBuffer;
		LSAfunction.CreateLogonSession = EIDCardLibraryMyCreateLogonSession;
		LSAfunction.CreateToken = EIDCardLibraryMyCreateToken;
		Status = functionTable->Initialize(PackageId, NULL, &LSAfunction);
		if (Status != STATUS_SUCCESS)
		{
			MessageBoxWin32(LsaNtStatusToWinError(Status));
			return;
		}
		
	}
}

ULONG_PTR AcquireTestCredential()
{
	DWORD dwStatus;
	ULONG_PTR handle = NULL;
	TimeStamp ExpirationTime;
	CREDUI_INFO credUiInfo;
	TCHAR szUsername[CREDUI_MAX_USERNAME_LENGTH+1] = TEXT("");
	TCHAR szPassword[CREDUI_MAX_PASSWORD_LENGTH+1] = TEXT("");
	credUiInfo.pszCaptionText = TEXT("My caption");
	credUiInfo.pszMessageText = TEXT("My message");
	credUiInfo.cbSize = sizeof(credUiInfo);
	credUiInfo.hbmBanner = NULL;
	credUiInfo.hwndParent = hMainWnd;
	dwStatus = CredUIPromptForCredentials(&credUiInfo, TEXT("test"), NULL, 0, 
		szUsername, CREDUI_MAX_USERNAME_LENGTH,
		szPassword, CREDUI_MAX_PASSWORD_LENGTH,
		FALSE, 0);
	if (dwStatus == NO_ERROR)
	{
		TCHAR szDomain[255] = TEXT("");
		SEC_WINNT_AUTH_IDENTITY_EX authIdent = {
			SEC_WINNT_AUTH_IDENTITY_VERSION,
			sizeof authIdent,
			(unsigned short *)szUsername,
			(DWORD)_tcsclen(szUsername),
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
		SpAcquireCredentialsHandleFn *acqhandle = functionTable->AcquireCredentialsHandle;
		
		acqhandle(NULL,SECPKG_CRED_BOTH,NULL,(PVOID) &authIdent, NULL,NULL,&handle,&ExpirationTime);
	}
	else if (dwStatus == ERROR_CANCELLED)
	{
	}
	else
	{
		MessageBoxWin32(dwStatus);
	}
	CredUIConfirmCredentials(NULL,FALSE);
	return handle;
}

void menu_SSP_AcquireCredentialHandle()
{
	InitializeDll();
	ULONG_PTR handle = AcquireTestCredential();
	functionTable->FreeCredentialsHandle(handle);
}

void menu_SSP_login()
{
	InitializeDll();
	ULONG_PTR handle = AcquireTestCredential();
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
	DWORD grfRequiredCtxAttrsClient = ISC_REQ_CONNECTION;
	DWORD grfRequiredCtxAttrsServer = ISC_REQ_CONNECTION;

	// set up some aliases to make it obvious what's happening
	LSA_SEC_HANDLE    pClientCtxHandleIn  = 0;
	LSA_SEC_HANDLE    pClientCtxHandleOut = 0;
	LSA_SEC_HANDLE    pServerCtxHandleIn  = 0;
	LSA_SEC_HANDLE    pServerCtxHandleOut = 0;
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
	NTSTATUS err;
	BOOLEAN mapped;
	SecBuffer ContextData;
	__try
	{
	while (bClientContinue || bServerContinue) {
			if (bClientContinue) {
				sbufC2S.cbBuffer = sizeof bufC2S;
				err =  functionTable->InitLsaModeContext(
					handle, pClientCtxHandleIn,
					NULL,
					grfRequiredCtxAttrsClient,
					0, 					pClientInput, 
					&pClientCtxHandleOut,
					pClientOutput,
					&grfCtxAttrsClient,
					&expiryClientCtx,&mapped, &ContextData);
				switch (err) {
					case 0:
						bClientContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pClientCtxHandleIn = pClientCtxHandleOut;
						pClientInput       = pServerOutput;
						break;
					default:
						MessageBoxWin32(err);
						__leave;
				}
			}

			if (bServerContinue) {
				sbufS2C.cbBuffer = sizeof bufS2C;
				err = functionTable->AcceptLsaModeContext(
					handle, pServerCtxHandleIn,
					pServerInput,
					grfRequiredCtxAttrsServer,
					0,
					&pServerCtxHandleOut,
					pServerOutput,
					&grfCtxAttrsServer,
					&expiryServerCtx,&mapped, &ContextData);
				switch (err) {
					case 0:
						bServerContinue = false;
						break;
					case SEC_I_CONTINUE_NEEDED:
						pServerCtxHandleIn = pServerCtxHandleOut;
						break;
					default:
						MessageBoxWin32(err);
						__leave;
				}
			}
		}
		MessageBox(hMainWnd,TEXT("OK"),TEXT("Login"),0);
	}
	__finally
	{
	}
	functionTable->FreeCredentialsHandle(handle);

}