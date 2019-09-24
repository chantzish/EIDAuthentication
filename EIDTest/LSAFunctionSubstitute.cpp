
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>

#define SECURITY_WIN32
#include <sspi.h>

#include <Ntsecapi.h>
#include <NtSecPkg.h>
#include <SubAuth.h>
#include <lm.h>
#include <Sddl.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"


NTSTATUS NTAPI EIDCardLibraryTestMyAllocateClientBuffer(PLSA_CLIENT_REQUEST ClientRequest,
								IN ULONG LengthRequired,
								OUT PVOID *ClientBaseAddress
								) {
	UNREFERENCED_PARAMETER(ClientRequest);
	*ClientBaseAddress = EIDAlloc(LengthRequired);
	return STATUS_SUCCESS;
}
NTSTATUS NTAPI EIDCardLibraryMyFreeClientBuffer(PLSA_CLIENT_REQUEST ClientRequest,
													PVOID ClientBaseAddress) {
	UNREFERENCED_PARAMETER(ClientRequest);
	EIDFree(ClientBaseAddress);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI EIDCardLibraryMyCopyToClientBuffer(
								IN PLSA_CLIENT_REQUEST ClientRequest,
								IN ULONG Length,
								IN PVOID ClientBaseAddress,
								IN PVOID BufferToCopy
								) 
{
	UNREFERENCED_PARAMETER(ClientRequest);
	memcpy(ClientBaseAddress,BufferToCopy,Length);
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI EIDCardLibraryMyCopyFromClientBuffer (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG Length,
    IN PVOID BufferToCopy,
    IN PVOID ClientBaseAddress
    )
{
	UNREFERENCED_PARAMETER(ClientRequest);
	memcpy(BufferToCopy,ClientBaseAddress,Length);
	return STATUS_SUCCESS;
}


NTSTATUS NTAPI EIDCardLibraryMyGetClientInfo(
								OUT PSECPKG_CLIENT_INFO ClientInfo)
{
	AllocateLocallyUniqueId(&(ClientInfo->LogonId));
	return STATUS_SUCCESS;
}

PVOID NTAPI EIDCardLibraryMyAllocateLsaHeap (
    IN ULONG Length
    )
{
	return EIDAlloc(Length);
}

VOID NTAPI EIDCardLibraryMyFreeLsaHeap ( PVOID Buffer)
{
	EIDFree(Buffer);
}

NTSTATUS NTAPI EIDCardLibraryMyCreateLogonSession(
  __in  PLUID LogonId
)
{
	return STATUS_SUCCESS;
}

NTSTATUS NTAPI EIDCardLibraryMyCreateToken(
  __in   PLUID LogonId,
  __in   PTOKEN_SOURCE TokenSource,
  __in   SECURITY_LOGON_TYPE LogonType,
  __in   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
  __in   LSA_TOKEN_INFORMATION_TYPE TokenInformationType,
  __in   PVOID TokenInformation,
  __in   PTOKEN_GROUPS TokenGroups,
  __in   PUNICODE_STRING AccountName,
  __in   PUNICODE_STRING AuthorityName,
  __in   PUNICODE_STRING Workstation,
  __in   PUNICODE_STRING ProfilePath,
  __out  PHANDLE Token,
  __out  PNTSTATUS SubStatus
)
{
	return STATUS_SUCCESS;
}