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

#include <ntsecpkg.h>
#include <WinCred.h>
#include <list>

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CredentialManagement.h"

void SetAlloc(PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap);
void SetFree(PLSA_FREE_LSA_HEAP FreeHeap);

extern "C"
{

	SECPKG_USER_FUNCTION_TABLE MyExportedUserFunctions;
	ULONG MyExportedUserFunctionsCount = 1;
	PSECPKG_DLL_FUNCTIONS MyUserDispatchTable;

	void initializeExportedUserFunctionsTable(PSECPKG_USER_FUNCTION_TABLE exportedFunctions);

	/** The SpUserModeInitialize function is called when a security support
	provider/authentication package (SSP/AP) DLL is loaded into the process 
	space of a client/server application. This function provides the SECPKG_USER_FUNCTION_TABLE
	tables for each security package in the SSP/AP DLL.*/
	NTSTATUS NTAPI SpUserModeInitialize(
		  __in   ULONG LsaVersion,
		  __out  PULONG PackageVersion,
		  __out  PSECPKG_USER_FUNCTION_TABLE *ppTables,
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
			*PackageVersion = 1;
			memset(&MyExportedUserFunctions, 0, sizeof(SECPKG_USER_FUNCTION_TABLE));
			initializeExportedUserFunctionsTable(&MyExportedUserFunctions);
			*ppTables = &MyExportedUserFunctions;
			*pcTables = MyExportedUserFunctionsCount;
			Status = STATUS_SUCCESS;
		}
		__finally
		{
		}
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave");
		return Status;
	}

	/** The SpInstanceInit function is called once for each security package contained 
	in an SSP/AP, when the SSP/AP is loaded into a client/server process. Security packages 
	should use this function to perform any user mode-specific initialization.*/
	NTSTATUS NTAPI SpInstanceInit(
		  __in   ULONG Version,
		  __in   PSECPKG_DLL_FUNCTIONS FunctionTable,
		  __out  PVOID *UserFunctions
		)
	{
		UNREFERENCED_PARAMETER(Version);
		UNREFERENCED_PARAMETER(UserFunctions);
		MyUserDispatchTable = FunctionTable;
		SetAlloc(MyUserDispatchTable->AllocateHeap);
		SetFree(MyUserDispatchTable->FreeHeap);
		return STATUS_SUCCESS;
	}

	/** The SpInitUserModeContext function creates a user-mode security context from 
	a packed Local Security Authority (LSA)-mode context.*/
	NTSTATUS NTAPI SpInitUserModeContext(
		  __in  LSA_SEC_HANDLE ContextHandle,
		  __in  PSecBuffer PackedContext
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		CUsermodeContext::AddContextInfo(ContextHandle, (PEID_SSP_CALLBACK_MESSAGE) PackedContext->pvBuffer);
		return STATUS_SUCCESS; 
	}

	NTSTATUS NTAPI SpDeleteContext(
		  __in  LSA_SEC_HANDLE ContextHandle
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		CUsermodeContext::DeleteContextInfo(ContextHandle);
		return STATUS_SUCCESS;
	}
	/** The SpMakeSignature function generates a signature based on the specified message and security context.

	The SpMakeSignature function is the dispatch function for the MakeSignature
	function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpMakeSignature(
		  __in     LSA_SEC_HANDLE ContextHandle,
		  __in     ULONG QualityOfProtection,
		  __inout  PSecBufferDesc MessageBuffers,
		  __in     ULONG MessageSequenceNumber
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(QualityOfProtection);
		UNREFERENCED_PARAMETER(MessageBuffers);
		UNREFERENCED_PARAMETER(MessageSequenceNumber);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Verifies that the message received is correct according to the signature.

	The SpVerifySignature function is the dispatch function for the VerifySignature function
	of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpVerifySignature(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc MessageBuffers,
		  __in   ULONG MessageSequenceNumber,
		  __out  PULONG QualityOfProtection
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(MessageBuffers);
		UNREFERENCED_PARAMETER(MessageSequenceNumber);
		UNREFERENCED_PARAMETER(QualityOfProtection);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Encrypts a message exchanged between a client and server.

	The SpSealMessage function is the dispatch function for the 
	EncryptMessage (General) function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpSealMessage(
		  __in     LSA_SEC_HANDLE ContextHandle,
		  __in     ULONG QualityOfProtection,
		  __inout  PSecBufferDesc MessageBuffers,
		  __in     ULONG MessageSequenceNumber
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(MessageBuffers);
		UNREFERENCED_PARAMETER(MessageSequenceNumber);
		UNREFERENCED_PARAMETER(QualityOfProtection);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Decrypts a message that was previously encrypted with the SpSealMessage function.

	The SpUnsealMessage function is the dispatch function for the DecryptMessage (General) 
	function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpUnsealMessage(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   PSecBufferDesc MessageBuffers,
		  __in   ULONG MessageSequenceNumber,
		  __out  PULONG QualityOfProtection
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(MessageBuffers);
		UNREFERENCED_PARAMETER(MessageSequenceNumber);
		UNREFERENCED_PARAMETER(QualityOfProtection);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Obtains the token to impersonate. The SpGetContextToken function is used by the SSPI 
	ImpersonateSecurityContext function to obtain the token to impersonate.*/
	NTSTATUS NTAPI SpGetContextToken(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __out  PHANDLE ImpersonationToken
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		NTSTATUS Status = CUsermodeContext::GetImpersonationHandle(ContextHandle, ImpersonationToken);
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Leave Status = 0x%08X", Status);
		return Status; 
	}

	/**  The SpQueryContextAttributes function retrieves the attributes of a security context.

	The SpQueryContextAttributes function is the dispatch function for the QueryContextAttributes (General)
	function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpQueryUserModeContextAttributes(
		  __in   LSA_SEC_HANDLE ContextHandle,
		  __in   ULONG ContextAttribute,
		  __out  PVOID Buffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(ContextAttribute);
		UNREFERENCED_PARAMETER(Buffer);
		return STATUS_NOT_IMPLEMENTED;
	}

	/** The SpCompleteAuthToken function completes an authentication token.

	The SpCompleteAuthToken function is the dispatch function for the CompleteAuthToken
	function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpCompleteAuthToken(
		  __in  LSA_SEC_HANDLE ContextHandle,
		  __in  PSecBufferDesc InputBuffer
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(ContextHandle);
		UNREFERENCED_PARAMETER(InputBuffer);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Formats credentials to be stored in a user object.*/
	NTSTATUS NTAPI SpFormatCredentials(
		  __in   PSecBuffer Credentials,
		  __out  PSecBuffer FormattedCredentials
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(Credentials);
		UNREFERENCED_PARAMETER(FormattedCredentials);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** The SpMarshallSupplementalCreds function converts supplemental credentials from 
	a public format into a format suitable for local procedure calls.*/
	NTSTATUS NTAPI SpMarshallSupplementalCreds(
		  __in   ULONG CredentialSize,
		  __in   PUCHAR Credentials,
		  __out  PULONG MarshalledCredSize,
		  __out  PVOID *MarshalledCreds
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(CredentialSize);
		UNREFERENCED_PARAMETER(Credentials);
		UNREFERENCED_PARAMETER(MarshalledCredSize);
		UNREFERENCED_PARAMETER(MarshalledCreds);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** Exports a security context to another process.

	The SpExportSecurityContext function is the dispatch function for the
	ExportSecurityContext function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpExportSecurityContext(
		  __in   LSA_SEC_HANDLE phContext,
		  __in   ULONG fFlags,
		  __out  PSecBuffer pPackedContext,
		  __out  PHANDLE pToken
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(phContext);
		UNREFERENCED_PARAMETER(fFlags);
		UNREFERENCED_PARAMETER(pPackedContext);
		UNREFERENCED_PARAMETER(pToken);
		return STATUS_NOT_IMPLEMENTED; 
	}

	/** The SpImportSecurityContext function imports a security context from another process.

	The SpImportSecurityContext function is the dispatch function for the ImportSecurityContext 
	function of the Security Support Provider Interface.*/
	NTSTATUS NTAPI SpImportSecurityContext(
		  __in   PSecBuffer pPackedContext,
		  __in   HANDLE Token,
		  __out  PLSA_SEC_HANDLE phContext
		)
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_VERBOSE,L"Enter");
		UNREFERENCED_PARAMETER(pPackedContext);
		UNREFERENCED_PARAMETER(Token);
		UNREFERENCED_PARAMETER(phContext);
		return STATUS_NOT_IMPLEMENTED; 
	}

	void initializeExportedUserFunctionsTable(PSECPKG_USER_FUNCTION_TABLE exportedFunctions)
	{
		exportedFunctions->InstanceInit = SpInstanceInit;
		exportedFunctions->InitUserModeContext = SpInitUserModeContext;
		exportedFunctions->MakeSignature = SpMakeSignature;
		exportedFunctions->VerifySignature = SpVerifySignature;
		exportedFunctions->SealMessage = SpSealMessage;
		exportedFunctions->UnsealMessage = SpUnsealMessage;
		exportedFunctions->GetContextToken = SpGetContextToken;
		exportedFunctions->QueryContextAttributes = SpQueryUserModeContextAttributes;
		exportedFunctions->CompleteAuthToken = SpCompleteAuthToken;
		exportedFunctions->DeleteUserModeContext = SpDeleteContext;
		exportedFunctions->FormatCredentials = SpFormatCredentials;
		exportedFunctions->MarshallSupplementalCreds = SpMarshallSupplementalCreds;
		exportedFunctions->ExportContext = SpExportSecurityContext;
		exportedFunctions->ImportContext = SpImportSecurityContext;

	}
}