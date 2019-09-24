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

#include <ntstatus.h>
#define WIN32_NO_STATUS 1

#include <windows.h>
#include <tchar.h>
#include <Ntsecapi.h>
#define SECURITY_WIN32
#include <sspi.h>
#include <Sddl.h>
#include <ntsecpkg.h>
#include <WinCred.h>
#include <Lm.h>
#include <list>

#include <Imagehlp.h>
#pragma comment(lib,"imagehlp")

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CredentialManagement.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "../EIDCardLibrary/StoredCredentialManagement.h"

void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap);
void SetFree(PLSA_FREE_LSA_HEAP FreeHeap);
void SetImpersonate(PLSA_IMPERSONATE_CLIENT Impersonate);

extern "C"
{
	// Save LsaDispatchTable
	PLSA_SECPKG_FUNCTION_TABLE MyLsaDispatchTable;
	PSECPKG_PARAMETERS MyParameters;
	SECPKG_FUNCTION_TABLE MyExportedFunctions;
	ULONG MyExportedFunctionsCount = 1;
	BOOL DoUnicode = TRUE; 
	LUID PackageUid;
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);
	ULONG MutualAuthLevel=0;
	// 1.3.6.1.4.1.35000.1
	// cf http://msdn.microsoft.com/en-us/library/bb540809%28VS.85%29.aspx
	// 1.3 . 6  .  1 .  4 .1   .35000    .1
	// 0x2B,0x06,0x01,0x04,0x01,0x88,0xB8,0x01
	UCHAR GssOid[] = {0x2B,0x06,0x01,0x04,0x01,0x88,0xB8,0x01};
	DWORD GssOidLen = ARRAYSIZE(GssOid);
	// guid for negoEx
	// 6550d49b-a716-484e-8955-a8e666df45d1
	UCHAR AUTHENTICATIONNAGOTIATEGUID[16] = 
			{0x65,0x50,0xd4,0x9b,0xa7,0x16,0x48,0x4e,0x89,0x55,0xa8,0xe6,0x66,0xdf,0x45,0xd1};


	TimeStamp Forever = {0x7fffffff,0xfffffff};
	TimeStamp Never = {0,0};

	/** The SpLsaModeInitialize function is called once by the  LSA for each registered  
	security support provider/ authentication package (SSP/AP) DLL it loads. This function 
	provides the LSA with pointers to the functions implemented by each  security package 
	in the SSP/AP DLL.*/

	NTSTATUS NTAPI SpLsaModeInitialize(
	  __in   ULONG LsaVersion,
	  __out  PULONG PackageVersionOut,
	  __out  PSECPKG_FUNCTION_TABLE *ppTables,
	  __out  PULONG pcTables
	  )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_INVALID_PARAMETER;
		__try
		{
			if (LsaVersion != SECPKG_INTERFACE_VERSION) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"LsaVersion = %d",LsaVersion);
				__leave;
			}
			*PackageVersionOut = 1;
			memset(&MyExportedFunctions, 0, sizeof(SECPKG_FUNCTION_TABLE));
			initializeExportedFunctionsTable(&MyExportedFunctions);
			*ppTables = &MyExportedFunctions;
			*pcTables = MyExportedFunctionsCount;
			// see remark in NTSecPkg.h line 1889
			Status = SECPKG_INTERFACE_VERSION_6;
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpInitialize function is called once by the  LSA to provide a  security package
	with general security information and a dispatch table of support functions. The security
	package should save the information and do internal initialization processing, if any is needed.*/
	NTSTATUS NTAPI SpInitialize(
		  __in  ULONG_PTR PackageId,
		  __in  PSECPKG_PARAMETERS Parameters,
		  __in  PLSA_SECPKG_FUNCTION_TABLE FunctionTable
		)
	{
		UNREFERENCED_PARAMETER(PackageId);
		MyParameters = Parameters;
		MyLsaDispatchTable = FunctionTable;
		SetAlloc(MyLsaDispatchTable->AllocateLsaHeap);
		SetFree(MyLsaDispatchTable->FreeLsaHeap);
		SetImpersonate(MyLsaDispatchTable->ImpersonateClient);
		AllocateLocallyUniqueId(&PackageUid);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpShutDown function is called by the  LSA before the  security support 
	provider/ authentication package (SSP/AP) is unloaded. The implementation of 
	this function should release any allocated resources, such as  credentials.*/
	NTSTATUS NTAPI SpShutDown()
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/**The SpGetInfo function provides general information about the  security package, such as
		its name and capabilities.
		The SpGetInfo function is called when the client calls the QuerySecurityPackageInfo 
		function of the Security Support Provider Interface. */
	NTSTATUS NTAPI SpGetInfo(
		__out  PSecPkgInfo PackageInfo
	)
	{
		PackageInfo->fCapabilities = SECPKG_FLAG_LOGON |
			SECPKG_FLAG_MULTI_REQUIRED|
			SECPKG_FLAG_CLIENT_ONLY|
			SECPKG_FLAG_IMPERSONATION|
			SECPKG_FLAG_NEGOTIABLE| 
			SECPKG_FLAG_NEGOTIABLE2 |
			SECPKG_FLAG_ACCEPT_WIN32_NAME |
			SECPKG_FLAG_GSS_COMPATIBLE;
		PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
		PackageInfo->wRPCID = SECPKG_ID_NONE;
		PackageInfo->cbMaxToken = 5000;
		PackageInfo->Name = AUTHENTICATIONPACKAGENAMET;
		PackageInfo->Comment = AUTHENTICATIONPACKAGENAMET;
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return STATUS_SUCCESS;
	}

	/** The SpGetExtendedInformation function provides extended information about a  security package. */
	NTSTATUS NTAPI SpGetExtendedInformation(
		  __in   SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __out  PSECPKG_EXTENDED_INFORMATION *ppInformation
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;
		switch(Class)
		{
			case SecpkgGssInfo:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION)+GssOidLen);
				(*ppInformation)->Class = SecpkgGssInfo;
				(*ppInformation)->Info.GssInfo.EncodedIdLength = GssOidLen;
				memcpy((*ppInformation)->Info.GssInfo.EncodedId, GssOid,GssOidLen);
				Status = STATUS_SUCCESS ; 
				break;
			case SecpkgContextThunks:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION));
				(*ppInformation)->Class = SecpkgContextThunks;
				(*ppInformation)->Info.ContextThunks.InfoLevelCount = 0; 
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgMutualAuthLevel:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION));
				(*ppInformation)->Class = SecpkgMutualAuthLevel;
				(*ppInformation)->Info.MutualAuthLevel.MutualAuthLevel = MutualAuthLevel; 
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgWowClientDll:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION));
				(*ppInformation)->Class = SecpkgWowClientDll;
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.Buffer = NULL; 
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.Length = 0;
				(*ppInformation)->Info.WowClientDll.WowClientDllPath.MaximumLength = 0;
				Status = STATUS_SUCCESS; 
				break;
			case SecpkgExtraOids:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION));
				(*ppInformation)->Class = SecpkgExtraOids;
				(*ppInformation)->Info.ExtraOids.OidCount = 0; 
				Status = STATUS_SUCCESS;
				break;
			case SecpkgNego2Info:
				*ppInformation = (PSECPKG_EXTENDED_INFORMATION) EIDAlloc(sizeof(SECPKG_EXTENDED_INFORMATION));
				(*ppInformation)->Class = SecpkgNego2Info;
				(*ppInformation)->Info.Nego2Info.PackageFlags = 0;
				memcpy((*ppInformation)->Info.Nego2Info.AuthScheme,AUTHENTICATIONNAGOTIATEGUID,16);
				Status = STATUS_SUCCESS;
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X", Status);
		return Status;
	}

	/** The SpSetExtendedInformation function is used to set extended information about the  security package.*/
	NTSTATUS NTAPI SpSetExtendedInformation(
		  __in  SECPKG_EXTENDED_INFORMATION_CLASS Class,
		  __in  PSECPKG_EXTENDED_INFORMATION Info
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter Class = %d",Class);
		UNREFERENCED_PARAMETER(Info);
		NTSTATUS Status = SEC_E_UNSUPPORTED_FUNCTION;
		switch(Class)
		{
			case SecpkgGssInfo:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgContextThunks:
				Status = SEC_E_UNSUPPORTED_FUNCTION ; 
				break;
			case SecpkgMutualAuthLevel:
				MutualAuthLevel = Info->Info.MutualAuthLevel.MutualAuthLevel ; 
				Status = STATUS_SUCCESS;
				break;
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpGetUserInfo function retrieves information about a logon  session.*/
	NTSTATUS NTAPI SpGetUserInfo( 
		IN PLUID LogonId, 
		IN ULONG Flags, 
		OUT PSecurityUserData * UserData 
		) 
	{ 
	 
		UNREFERENCED_PARAMETER(LogonId); 
		UNREFERENCED_PARAMETER(Flags); 
		UNREFERENCED_PARAMETER(UserData); 
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return(STATUS_NOT_SUPPORTED); 
	} 

	//////////////////////////////////////////////////////////////////////////////////////
	// Credential management
	//////////////////////////////////////////////////////////////////////////////////////

	/** Applies a control token to a  security context. This function is not currently called 
	by the  Local Security Authority (LSA).*/
	NTSTATUS NTAPI SpApplyControlToken(
		LSA_SEC_HANDLE              phContext,          // Context to modify
		PSecBufferDesc              pInput              // Input token to apply
		)
	{
		UNREFERENCED_PARAMETER(phContext);
		UNREFERENCED_PARAMETER(pInput);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return(STATUS_SUCCESS);

	}

	/** Called by the  Local Security Authority (LSA) to pass the  security package any  
	credentials stored for the authenticated  security principal. This function is called
	once for each set of credentials stored by the LSA.*/
	NTSTATUS NTAPI SpAcceptCredentials(
		  __in  SECURITY_LOGON_TYPE LogonType,
		  __in  PUNICODE_STRING AccountName,
		  __in  PSECPKG_PRIMARY_CRED PrimaryCredentials,
		  __in  PSECPKG_SUPPLEMENTAL_CRED SupplementalCredentials
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ type=%d",AccountName, LogonType);
		UNREFERENCED_PARAMETER(SupplementalCredentials);
		if ( PrimaryCredentials && (PrimaryCredentials->Flags & PRIMARY_CRED_UPDATE) 
								&& (PrimaryCredentials->Flags & PRIMARY_CRED_CLEAR_PASSWORD))
		{
			// is here the password update
			// note : this function is called for each session opened (even the networked one)
			// and twice is the user is an administrator (elevated token and the normal one)
			// so this function is called in average 4 times.
			// the job is also done in the notification package, if the change password is done offline
			// (for example using  net.exe)
			// this function exists because a security package can be loaded immedialty after the install
			// into LSASS.exe while a notification package requires a reboot.
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Password change with flag 0x%x", PrimaryCredentials->Flags);
			CStoredCredentialManager* manager = CStoredCredentialManager::Instance();
			manager->UpdateCredential(&(PrimaryCredentials->LogonId), &(PrimaryCredentials->Password));
			
		}
		return STATUS_SUCCESS;
	}

	/** Called to obtain a handle to a principal's  credentials. The  security package can 
	deny access to the caller if the caller does not have permission to access the credentials.

	If the credentials handle is returned to the caller, the package should also specify an expiration time for the handle.*/
	NTSTATUS NTAPI SpAcquireCredentialsHandle(
		  __in   PUNICODE_STRING PrincipalName,
		  __in   ULONG CredentialUseFlags,
		  __in   PLUID LogonId,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PLSA_SEC_HANDLE pCredentialHandle,
		  __out  PTimeStamp ExpirationTime
		)
	{
		UNREFERENCED_PARAMETER(LogonId);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter PrincipalName = %wZ",PrincipalName);
		PSEC_WINNT_AUTH_IDENTITY_EXW pAuthIdentityEx = NULL;
		PSEC_WINNT_AUTH_IDENTITY pAuthIdentity = NULL; 
		CCredential* pCredential;
		ULONG CredSize = 0; 
		ULONG Offset = 0; 
		NTSTATUS Status = STATUS_SUCCESS;
		PCERT_CREDENTIAL_INFO pCertInfo = NULL;
		CRED_MARSHAL_TYPE CredType;
		PVOID szCredential = NULL;
		PVOID szPassword = NULL;
		PWSTR szPasswordW = NULL;
		DWORD dwCharSize = 0;
		BOOL UseUnicode = TRUE;
		SECPKG_CLIENT_INFO ClientInfo; 
		PLUID LogonIdToUse; 
		__try
		{
			if ((CredentialUseFlags & (SECPKG_CRED_BOTH)) == 0)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"flag not ok");
				Status = SEC_E_UNKNOWN_CREDENTIALS;
				__leave;
			}
			if (GetKeyFunction)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyFunction not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
			if (GetKeyArgument)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyArgument not ok");
				Status = SEC_E_UNSUPPORTED_FUNCTION;
				__leave;
			}
				// 
			// First get information about the caller. 
			// 	 
			Status = MyLsaDispatchTable->GetClientInfo(&ClientInfo); 
			if (Status != STATUS_SUCCESS) 
			{ 
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"GetKeyArgument not ok 0x%08x", Status); 
				__leave;
			} 
	 
			// 
			// If the caller supplied a logon ID, and it doesn't match the caller, 
			// they must have the TCB privilege 
			// 
		 
			if (LogonId && 
				((LogonId->LowPart != 0) || (LogonId->HighPart != 0)) && 
				!(( LogonId->HighPart == ClientInfo.LogonId.HighPart) && ( LogonId->LowPart == ClientInfo.LogonId.LowPart))) 
				 
			{ 
				if (!ClientInfo.HasTcbPrivilege) 
				{ 
					Status = STATUS_PRIVILEGE_NOT_HELD; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_PRIVILEGE_NOT_HELD"); 
					__leave;
				} 
				LogonIdToUse = LogonId; 
			} 
			else 
			{ 
				LogonIdToUse = &ClientInfo.LogonId; 
			}
			
			if (AuthorizationData != NULL) 
			{ 
				// copy the authorization data to our user space
				pAuthIdentityEx = (PSEC_WINNT_AUTH_IDENTITY_EXW)
												EIDAlloc(sizeof(SEC_WINNT_AUTH_IDENTITY_EXW)); 
				if (!pAuthIdentityEx) 
				{ 
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc is 0x%08x", Status); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer( 
							NULL, 
							sizeof(SEC_WINNT_AUTH_IDENTITY), 
							pAuthIdentityEx, 
							AuthorizationData);

				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				} 
				// 
				// Check for the ex version 
				// 
		 
				if (pAuthIdentityEx->Version == SEC_WINNT_AUTH_IDENTITY_VERSION) 
				{ 
					Status = MyLsaDispatchTable->CopyFromClientBuffer( 
								NULL, 
								sizeof(SEC_WINNT_AUTH_IDENTITY_EXW), 
								pAuthIdentityEx, 
								AuthorizationData); 
		 
					if (Status != STATUS_SUCCESS) 
					{ 
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
						__leave;
					} 
					pAuthIdentity = (PSEC_WINNT_AUTH_IDENTITY) &pAuthIdentityEx->User; 
					CredSize = pAuthIdentityEx->Length; 
					Offset = FIELD_OFFSET(SEC_WINNT_AUTH_IDENTITY_EXW, User); 
				} 
				else 
				{ 
					pAuthIdentity = (PSEC_WINNT_AUTH_IDENTITY_W) pAuthIdentityEx; 
					CredSize = sizeof(SEC_WINNT_AUTH_IDENTITY_W); 
				} 
		 
				if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_ANSI) 
				{ 
					dwCharSize = sizeof(CHAR);
					UseUnicode = FALSE;
				} 
				else if (pAuthIdentity->Flags & SEC_WINNT_AUTH_IDENTITY_UNICODE)
				{
					dwCharSize = sizeof(WCHAR);
					UseUnicode = TRUE;
				}
				else
				{
					Status = SEC_E_INVALID_TOKEN; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pAuthIdentity->Flags is 0x%lx", pAuthIdentity->Flags); 
					__leave;
				}
				szCredential = EIDAlloc((pAuthIdentity->UserLength + 1) * dwCharSize);
				if (!szCredential)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->UserLength + 1) * dwCharSize, 
															szCredential,
															pAuthIdentity->User); 
				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				} 
				BOOL fRes;
				if (UseUnicode)
				{
					fRes = CredUnmarshalCredentialW((LPCWSTR)szCredential,&CredType, (PVOID*) &pCertInfo);
				}
				else
				{
					fRes = CredUnmarshalCredentialA((LPCSTR)szCredential,&CredType, (PVOID*) &pCertInfo);
				}
				if (!fRes) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredUnmarshalCredential is 0x%08x UseUnicode=%d", GetLastError(), UseUnicode); 
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}				
				if (CredType != CertCredential)
				{
					Status = SEC_E_UNKNOWN_CREDENTIALS; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredType is 0x%lx", CredType); 
					__leave;
				}
				szPassword = EIDAlloc((pAuthIdentity->PasswordLength + 1) * dwCharSize);
				if (!szPassword)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES; 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
					__leave;
				}
				Status = MyLsaDispatchTable->CopyFromClientBuffer(NULL, 
															(pAuthIdentity->PasswordLength + 1) * dwCharSize, 
															szPassword,
															pAuthIdentity->Password); 
				if (Status != STATUS_SUCCESS) 
				{ 
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyFromClientBuffer is 0x%08x", Status); 
					__leave;
				}
				// convert to unicode
				if (UseUnicode)
				{
					szPasswordW = (PWSTR) szPassword;
					szPassword = NULL;
				}
				else
				{
					szPasswordW = (PWSTR) EIDAlloc((pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR));
					if (!szPasswordW)
					{
						Status = STATUS_INSUFFICIENT_RESOURCES; 
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
						__leave;
					}
					MultiByteToWideChar(CP_ACP, 0, (PSTR) szPassword, -1, szPasswordW, pAuthIdentity->PasswordLength + 1);
				}
			}
			else
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"No Authorization data"); 
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"CreateCredential"); 
			pCredential = CCredential::CreateCredential(LogonIdToUse,pCertInfo, szPasswordW, CredentialUseFlags);
			if (!pCredential)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"EIDAlloc"); 
					__leave;
			}
			*pCredentialHandle = (LSA_SEC_HANDLE) pCredential;
			*ExpirationTime = Forever;
		}
		__finally
		{
			if (pCertInfo)
				CredFree(pCertInfo);
			if (szCredential)
				MyLsaDispatchTable->FreeLsaHeap(szCredential);
			if (szPasswordW)
			{
				SecureZeroMemory(szPasswordW,(pAuthIdentity->PasswordLength + 1) * sizeof(WCHAR));
				MyLsaDispatchTable->FreeLsaHeap(szPasswordW);
			}
			if (szPassword)
			{
				SecureZeroMemory(szPassword,(pAuthIdentity->PasswordLength + 1) * dwCharSize);
				MyLsaDispatchTable->FreeLsaHeap(szPassword);
			}
			if (pAuthIdentityEx)
				MyLsaDispatchTable->FreeLsaHeap(pAuthIdentityEx);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Credential %p Status = 0x%08x",*pCredentialHandle, Status);
		return Status;
	}

	/** Frees  credentials acquired by calling the  SpAcquireCredentialsHandle function.*/
	NTSTATUS NTAPI SpFreeCredentialsHandle(
		__in LSA_SEC_HANDLE                 CredentialHandle        // Handle to free
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Credential %p",CredentialHandle);
		if (!CCredential::Delete(CredentialHandle))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Credential %p not found",CredentialHandle);
			return(STATUS_INVALID_HANDLE);
		}
		return(STATUS_SUCCESS);
	}

	/** Used to add  credentials for a  security principal.*/
	NTSTATUS NTAPI SpAddCredentials(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   PUNICODE_STRING PrincipalName,
		  __in   PUNICODE_STRING Package,
		  __in   ULONG CredentialUseFlags,
		  __in   PVOID AuthorizationData,
		  __in   PVOID GetKeyFunction,
		  __in   PVOID GetKeyArgument,
		  __out  PTimeStamp ExpirationTime
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter for account name = %wZ package=%wZ",PrincipalName, Package);
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(CredentialUseFlags);
		UNREFERENCED_PARAMETER(AuthorizationData);
		UNREFERENCED_PARAMETER(GetKeyFunction);
		UNREFERENCED_PARAMETER(GetKeyArgument);
		// forever
		*ExpirationTime = Forever;
		return STATUS_SUCCESS;
	}

	/** Deletes  credentials from a  security package's list of  primary or  supplemental credentials.*/
	NTSTATUS NTAPI SpDeleteCredentials(
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key
		)
	{
		UNREFERENCED_PARAMETER(Key);
		UNREFERENCED_PARAMETER(CredentialHandle);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		return STATUS_SUCCESS;
	}

	/** Saves a  supplemental credential to the user object.*/
	NTSTATUS NTAPI SpSaveCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __in  PSecBuffer Key
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Key);
		return STATUS_SUCCESS;
	}
	
	/** The SpGetCredentials function retrieves the  primary and  supplemental credentials from the user object.*/
	NTSTATUS NTAPI SpGetCredentials (
		  __in  LSA_SEC_HANDLE CredentialHandle,
		  __out  PSecBuffer Credentials
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(Credentials);
		return STATUS_NOT_IMPLEMENTED;
	}

		/** The SpQueryCredentialsAttributes function retrieves the attributes for a  credential.

	The SpQueryCredentialsAttributes function is the dispatch function for the 
	QueryCredentialsAttributes function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryCredentialsAttributes(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   ULONG CredentialAttribute,
		  __out  PVOID Buffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter CredentialAttribute = %d",CredentialAttribute);
		NTSTATUS status = STATUS_SUCCESS;
		PTSTR szName;
		DWORD dwSize;
		CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
		if (!pCredential)
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CredentialHandle = %d : STATUS_INVALID_HANDLE",CredentialHandle);
			return STATUS_INVALID_HANDLE;
		}
		switch(CredentialAttribute)
		{
			case SECPKG_CRED_ATTR_NAMES:
				__try
				{
					szName = pCredential->GetName();
					if (!szName)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"szName NULL");
						status = SEC_E_INSUFFICIENT_MEMORY;
						__leave;
					}
					dwSize = (DWORD)(_tcslen(szName)+1) * sizeof(TCHAR);
					status = MyLsaDispatchTable->AllocateClientBuffer(NULL, dwSize, (PVOID*) Buffer);
					if (status != STATUS_SUCCESS)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AllocateClientBuffer status = 0x%08x",status);
						__leave;
					}
					status = MyLsaDispatchTable->CopyToClientBuffer(NULL, dwSize, *((PVOID*) Buffer), szName);
					if (status != STATUS_SUCCESS)
					{
						EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CopyToClientBuffer status = 0x%08x",status);
						__leave;
					}
					status = STATUS_SUCCESS;
				}
				__finally
				{	
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SECPKG_CRED_ATTR_NAMES status = 0x%08x",status);
				return status;
				break;
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"STATUS_INVALID_PARAMETER_2");
				return STATUS_INVALID_PARAMETER_2;
		}
	}

	

	//////////////////////////////////////////////////////////////////////////////////////
	// Context management
	//////////////////////////////////////////////////////////////////////////////////////

	
	/** Deletes a  security context.*/
	NTSTATUS NTAPI SpDeleteSecurityContext(
		__in LSA_SEC_HANDLE                 phContext           // Context to delete
    )
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"delete Context 0x%08X",phContext);
		if (!CSecurityContext::Delete(phContext))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Context 0x%08X not found",phContext);
			return(SEC_E_INVALID_HANDLE);
		}
		return(SEC_E_OK);
	}

	/**  The SpQueryContextAttributes function retrieves the attributes of a  security context.

	The SpQueryContextAttributes function is the dispatch function for the 
	QueryContextAttributes (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryContextAttributes(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   ULONG ContextAttribute,
		  __out  PVOID pBuffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter ContextAttribute = %d",ContextAttribute);
		CSecurityContext* pContext;
		PSecPkgContext_Sizes ContextSizes;
		PSecPkgContext_NamesW ContextNames;
		PSecPkgContext_Lifespan ContextLifespan;
		switch(ContextAttribute) 
		{
			case SECPKG_ATTR_SIZES:
				ContextSizes = (PSecPkgContext_Sizes) pBuffer;
				ContextSizes->cbMaxSignature = 0;
				ContextSizes->cbSecurityTrailer = 0;
				ContextSizes->cbBlockSize = 0;
				ContextSizes->cbMaxToken = 300;
				break;
			case SECPKG_ATTR_NAMES:
				if (!ContextHandle)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"ContextHandle = %d",ContextHandle);
					return STATUS_INVALID_HANDLE;
				}
				pContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				ContextNames = (PSecPkgContext_Names) pBuffer;
				ContextNames->sUserName = pContext->GetUserName();
				if (ContextNames->sUserName == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INSUFFICIENT_MEMORY");
					return(SEC_E_INSUFFICIENT_MEMORY);
				}
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Username = %s",ContextNames->sUserName);
				break;
			case SECPKG_ATTR_LIFESPAN:
				ContextLifespan = (PSecPkgContext_Lifespan) pBuffer;
				ContextLifespan->tsStart = Never;
				ContextLifespan->tsExpiry = Forever;
				break;
			default:
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SEC_E_INVALID_TOKEN");
				return(SEC_E_INVALID_TOKEN);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"SEC_E_OK");
		return(SEC_E_OK);
	}



	/**  The SpInitLsaModeContext function is the client dispatch function used to establish a 
	security context between a server and client.

	The SpInitLsaModeContext function is called when the client calls the 
	InitializeSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpInitLsaModeContext(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PUNICODE_STRING TargetName,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __in   PSecBufferDesc InputBuffers,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter TargetName = %wZ",TargetName);
		NTSTATUS Status = STATUS_SUCCESS;
		__try
		{
			CSecurityContext* newContext = NULL;
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			if (ContextHandle == NULL)
			{
				// locate credential
				CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
				if (pCredential == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %p",pCredential);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				if ((pCredential->Use & SECPKG_CRED_OUTBOUND) == 0)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Use = %d",pCredential->Use);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				// create new context : first message
				newContext = CSecurityContext::CreateContext(pCredential);
				*NewContextHandle = (LSA_SEC_HANDLE) newContext;
			}
			else
			{
				// retrieve previous context
				CSecurityContext* currentContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (currentContext == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"currentContext = %d",currentContext);
					Status = SEC_E_INVALID_HANDLE;
					__leave;
				}
				*NewContextHandle = ContextHandle;
				newContext = currentContext;
				Status = currentContext->InitializeSecurityContextInput(InputBuffers);
				if (Status != STATUS_SUCCESS)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextInput = 0x%08X",Status);
					__leave;
				}
			}
			// forever
			*ExpirationTime = Forever;
			Status = newContext->InitializeSecurityContextOutput(OutputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"InitializeSecurityContextOutput = 0x%08X",Status);
				__leave;
			}
			
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpCreateToken(DWORD dwRid, PHANDLE phToken)
	{
		NTSTATUS Status = STATUS_SUCCESS, SubStatus = STATUS_SUCCESS;
		LUID LogonId;
		TOKEN_SOURCE tokenSource = { "EIDAuth", PackageUid};
		UNICODE_STRING AccountName;
		UNICODE_STRING AuthorityName;
		UNICODE_STRING Workstation;
		UNICODE_STRING ProfilePath;
		UNICODE_STRING Prefix = {0,0,NULL};
		PLSA_TOKEN_INFORMATION_V2 MyTokenInformation = NULL;
		DWORD TokenLength;
		WCHAR szComputer[UNLEN+1];
		WCHAR szUserName[256];
		DWORD dwSize;
		USER_INFO_3 *pInfo = NULL;
		DWORD dwEntriesRead, dwTotalEntries;
		NET_API_STATUS NetStatus ;
		DWORD dwI;
		__try
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
			// create session
			if (!phToken)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"phToken null");
				Status = STATUS_INVALID_PARAMETER;
				__leave;
			}
			*phToken = INVALID_HANDLE_VALUE;
			// create the sid from the rid
			
			NetStatus = NetUserEnum(NULL, 3, 0, (PBYTE*)&pInfo, MAX_PREFERRED_LENGTH, &dwEntriesRead,&dwTotalEntries, NULL);
			if (NetStatus != NERR_Success)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"NetUserEnum = 0x%08X",NetStatus);
				__leave;
			}
			for (dwI = 0; dwI < dwEntriesRead; dwI++)
			{
				if ( pInfo[dwI].usri3_user_id == dwRid)
				{
					wcscpy_s(szUserName, ARRAYSIZE(szUserName), pInfo[dwI].usri3_name);
					break;
				}
			}
			if (dwI >= dwEntriesRead)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Userid not found");
				__leave;
			}
			dwSize = ARRAYSIZE(szComputer);
			GetComputerNameW(szComputer, &dwSize);
			Workstation.Buffer = szComputer;
			AuthorityName.Buffer = szComputer;
			Workstation.Length = Workstation.MaximumLength = (USHORT) (wcslen(szComputer) * sizeof(WCHAR));
			AuthorityName.Length = AuthorityName.MaximumLength = (USHORT) (wcslen(szComputer) * sizeof(WCHAR));
			AccountName.Buffer = szUserName;
			AccountName.Length = AccountName.MaximumLength = (USHORT)(wcslen(szUserName) * sizeof(WCHAR));
			ProfilePath.Length = ProfilePath.MaximumLength = (USHORT)(wcslen(pInfo[dwI].usri3_profile) * sizeof(WCHAR));
			ProfilePath.Buffer = pInfo[dwI].usri3_profile;
			Status = MyLsaDispatchTable->GetAuthDataForUser((PSECURITY_STRING)&AccountName, SecNameSamCompatible, (PSECURITY_STRING)&Prefix, (PUCHAR*) &MyTokenInformation, &TokenLength, NULL);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"UserNameToToken failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
			Status = MyLsaDispatchTable->ConvertAuthDataToToken(MyTokenInformation, TokenLength, SecurityImpersonation, &tokenSource,
							Network, &AuthorityName, phToken, &LogonId,&AccountName, &SubStatus);
			if (Status != STATUS_SUCCESS) 
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"CreateToken failed 0x%08X 0x%08X",Status, SubStatus);
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Token = 0x%08X",*phToken);
		}
		__finally
		{
			if (pInfo)
				NetApiBufferFree(pInfo);
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave with Status = 0x%08X",Status);
		return Status;
	}

	/** Server dispatch function used to create a  security context shared by a server and client.

	The SpAcceptLsaModeContext function is called when the server calls the 
	AcceptSecurityContext (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpAcceptLsaModeContext(
		  __in   LSA_SEC_HANDLE CredentialHandle,
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc InputBuffers,
		  __in   ULONG ContextRequirements,
		  __in   ULONG TargetDataRep,
		  __out  PLSA_SEC_HANDLE NewContextHandle,
		  __out  PSecBufferDesc OutputBuffers,
		  __out  PULONG ContextAttributes,
		  __out  PTimeStamp ExpirationTime,
		  __out  PBOOLEAN MappedContext,
		  __out  PSecBuffer ContextData
		)
	{
		UNREFERENCED_PARAMETER(ContextData);
		UNREFERENCED_PARAMETER(TargetDataRep);
		UNREFERENCED_PARAMETER(ContextRequirements);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = STATUS_SUCCESS;
		PEID_SSP_CALLBACK_MESSAGE callbackMessage = NULL;
		HANDLE hToken;
		__try
		{
			CSecurityContext* newContext = NULL;
			*MappedContext = FALSE;
			*ContextAttributes = ASC_REQ_CONNECTION | ASC_REQ_REPLAY_DETECT;
			if (ContextHandle == NULL)
			{
				// locate credential
				CCredential* pCredential = CCredential::GetCredentialFromHandle(CredentialHandle);
				if (pCredential == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"pCredential = %p",pCredential);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				if ((pCredential->Use & SECPKG_CRED_INBOUND) == 0)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Use = %d",pCredential->Use);
					Status = SEC_E_UNKNOWN_CREDENTIALS;
					__leave;
				}
				// create new context : first message
				newContext = CSecurityContext::CreateContext(pCredential);
				*NewContextHandle = (LSA_SEC_HANDLE) newContext;
			}
			else
			{
				// retrieve previous context
				CSecurityContext* currentContext = CSecurityContext::GetContextFromHandle(ContextHandle);
				if (currentContext == NULL)
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"currentContext = %p",currentContext);
					Status = SEC_E_INVALID_HANDLE;
					__leave;
				}
				*NewContextHandle = ContextHandle;
				newContext = currentContext;
			}
			Status = newContext->AcceptSecurityContextInput(InputBuffers);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextInput = 0x%08X",Status);
				__leave;
			}
			Status = newContext->AcceptSecurityContextOutput(OutputBuffers);
			// forever
			*ExpirationTime = Forever;
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"AcceptSecurityContextOutput = 0x%08X",Status);
				__leave;
			}
			// final call :
			// create a token and send it to the client

			Status = SpCreateToken(newContext->GetRid(), &hToken);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"SpCreateToken = 0x%08X",Status);
				__leave;
			}
			callbackMessage = (PEID_SSP_CALLBACK_MESSAGE) EIDAlloc(sizeof(EID_SSP_CALLBACK_MESSAGE));
			if (!callbackMessage)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"callbackMessage no memory");
				__leave;
			}
			// duplicate the handle to the process space
			callbackMessage->Caller = EIDSSPAccept;
			Status = MyLsaDispatchTable->DuplicateHandle(hToken, &callbackMessage->hToken);
			if (Status != STATUS_SUCCESS)
			{
				EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"DuplicateHandle = 0x%08X",Status);
				__leave;
			}
			EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"token = 0x%08X",callbackMessage->hToken);
			*MappedContext = TRUE;
			ContextData->BufferType = SECBUFFER_DATA;
			ContextData->cbBuffer = sizeof(EID_SSP_CALLBACK_MESSAGE);
			ContextData->pvBuffer = callbackMessage;
			
		}
		__finally
		{
			if (Status != STATUS_SUCCESS)
			{
				if (callbackMessage)
					EIDFree(callbackMessage);
			}
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpSetContextAttributes (
					__in LSA_SEC_HANDLE ContextHandle,
					__in ULONG ContextAttribute,
					__in PVOID Buffer,
					__in ULONG BufferSize )
	{
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(ContextAttribute);
		UNREFERENCED_PARAMETER(Buffer);
		UNREFERENCED_PARAMETER(BufferSize);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpSetCredentialsAttributes(
					__in LSA_SEC_HANDLE CredentialHandle,
					__in ULONG CredentialAttribute,
					__in PVOID Buffer,
					__in ULONG BufferSize )
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(CredentialAttribute);
		UNREFERENCED_PARAMETER(Buffer);
		UNREFERENCED_PARAMETER(BufferSize);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpChangeAccountPassword(
					__in PUNICODE_STRING      pDomainName,
					__in PUNICODE_STRING      pAccountName,
					__in PUNICODE_STRING      pOldPassword,
					__in PUNICODE_STRING      pNewPassword,
					__in BOOLEAN              Impersonating,
					__inout PSecBufferDesc   pOutput
					)
	{
		UNREFERENCED_PARAMETER(pDomainName);
		UNREFERENCED_PARAMETER(pAccountName);
		UNREFERENCED_PARAMETER(pOldPassword);
		UNREFERENCED_PARAMETER(pNewPassword);
		UNREFERENCED_PARAMETER(Impersonating);
		UNREFERENCED_PARAMETER(pOutput);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpQueryMetaData(
					__in_opt LSA_SEC_HANDLE CredentialHandle,
					__in_opt PUNICODE_STRING TargetName,
					__in ULONG ContextRequirements,
					__out PULONG MetaDataLength,
					__deref_out_bcount(*MetaDataLength) PUCHAR* MetaData,
					__inout PLSA_SEC_HANDLE ContextHandle
					)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(TargetName);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(MetaDataLength);
		UNREFERENCED_PARAMETER(MetaData);
		UNREFERENCED_PARAMETER(ContextHandle);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpExchangeMetaData(
					__in_opt LSA_SEC_HANDLE CredentialHandle,
					__in_opt PUNICODE_STRING TargetName,
					__in ULONG ContextRequirements,
					__in ULONG MetaDataLength,
					__in_bcount(MetaDataLength) PUCHAR MetaData,
					__inout PLSA_SEC_HANDLE ContextHandle
					)
	{
		UNREFERENCED_PARAMETER(CredentialHandle);
		UNREFERENCED_PARAMETER(TargetName);
		UNREFERENCED_PARAMETER(ContextRequirements);
		UNREFERENCED_PARAMETER(MetaDataLength);
		UNREFERENCED_PARAMETER(MetaData);
		UNREFERENCED_PARAMETER(ContextHandle);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpGetCredUIContext(
				   __in LSA_SEC_HANDLE ContextHandle,
				   __in GUID* CredType,
				   __out PULONG FlatCredUIContextLength,
				   __deref_out_bcount(*FlatCredUIContextLength)  PUCHAR* FlatCredUIContext
				   )
	  {
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(CredType);
		UNREFERENCED_PARAMETER(FlatCredUIContextLength);
		UNREFERENCED_PARAMETER(FlatCredUIContext);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	  }

	NTSTATUS NTAPI SpUpdateCredentials(
				  __in LSA_SEC_HANDLE ContextHandle,
				  __in GUID* CredType,
				  __in ULONG FlatCredUIContextLength,
				  __in_bcount(FlatCredUIContextLength) PUCHAR FlatCredUIContext
				  )
	{
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(CredType);
		UNREFERENCED_PARAMETER(FlatCredUIContextLength);
		UNREFERENCED_PARAMETER(FlatCredUIContext);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	NTSTATUS NTAPI SpValidateTargetInfo (
				__in_opt PLSA_CLIENT_REQUEST ClientRequest,
				__in_bcount(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
				__in PVOID ClientBufferBase,
				__in ULONG SubmitBufferLength,
				__in PSECPKG_TARGETINFO TargetInfo
				)
	{
		UNREFERENCED_PARAMETER(ClientRequest);
		UNREFERENCED_PARAMETER(ProtocolSubmitBuffer);
		UNREFERENCED_PARAMETER(ClientBufferBase);
		UNREFERENCED_PARAMETER(SubmitBufferLength);
		UNREFERENCED_PARAMETER(TargetInfo);
		NTSTATUS Status = STATUS_NOT_IMPLEMENTED;
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Status = 0x%08X",Status);
		return Status;
	}

	void initializeLSAExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions);
	/** Called during system initialization to permit the authentication package to perform
	initialization tasks.*/
	// at the end to avoid double declaration of functions
	void initializeExportedFunctionsTable(PSECPKG_FUNCTION_TABLE exportedFunctions)
	{
		initializeLSAExportedFunctionsTable(exportedFunctions);
		exportedFunctions->Initialize = SpInitialize;
		exportedFunctions->Shutdown = SpShutDown;
		exportedFunctions->GetInfo = SpGetInfo;
		exportedFunctions->AcceptCredentials = SpAcceptCredentials;
		exportedFunctions->AcquireCredentialsHandle = SpAcquireCredentialsHandle;
		exportedFunctions->QueryCredentialsAttributes = SpQueryCredentialsAttributes;
		exportedFunctions->FreeCredentialsHandle = SpFreeCredentialsHandle;
		exportedFunctions->SaveCredentials = SpSaveCredentials;
		exportedFunctions->GetCredentials = SpGetCredentials;
		exportedFunctions->DeleteCredentials = SpDeleteCredentials;
		exportedFunctions->InitLsaModeContext = SpInitLsaModeContext;
		exportedFunctions->AcceptLsaModeContext = SpAcceptLsaModeContext;
		exportedFunctions->DeleteContext = SpDeleteSecurityContext;
		exportedFunctions->ApplyControlToken = SpApplyControlToken;
		exportedFunctions->GetUserInfo = SpGetUserInfo;
		exportedFunctions->GetExtendedInformation = SpGetExtendedInformation;
		exportedFunctions->QueryContextAttributes = SpQueryContextAttributes;
		exportedFunctions->AddCredentials = SpAddCredentials;
		exportedFunctions->SetExtendedInformation = SpSetExtendedInformation;
		exportedFunctions->SetContextAttributes = SpSetContextAttributes; // only schanel implements this
		exportedFunctions->SetCredentialsAttributes = SpSetCredentialsAttributes; // not documented
		exportedFunctions->ChangeAccountPassword = SpChangeAccountPassword; // not documented
		exportedFunctions->QueryMetaData = SpQueryMetaData;
		exportedFunctions->ExchangeMetaData = SpExchangeMetaData;
		exportedFunctions->GetCredUIContext = SpGetCredUIContext;
		exportedFunctions->UpdateCredentials = SpUpdateCredentials;
		exportedFunctions->ValidateTargetInfo = SpValidateTargetInfo;
	}
}