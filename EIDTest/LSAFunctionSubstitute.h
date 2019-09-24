NTSTATUS NTAPI EIDCardLibraryTestMyAllocateClientBuffer(PLSA_CLIENT_REQUEST ClientRequest,
								IN ULONG LengthRequired,
								OUT PVOID *ClientBaseAddress
								);


NTSTATUS NTAPI EIDCardLibraryMyFreeClientBuffer(PLSA_CLIENT_REQUEST ClientRequest,
													PVOID ClientBaseAddress);

NTSTATUS NTAPI EIDCardLibraryMyCopyToClientBuffer(
								IN PLSA_CLIENT_REQUEST ClientRequest,
								IN ULONG Length,
								IN PVOID ClientBaseAddress,
								IN PVOID BufferToCopy
								) ;

NTSTATUS NTAPI EIDCardLibraryMyCopyFromClientBuffer (
    IN PLSA_CLIENT_REQUEST ClientRequest,
    IN ULONG Length,
    IN PVOID BufferToCopy,
    IN PVOID ClientBaseAddress
    );
NTSTATUS NTAPI EIDCardLibraryMyGetClientInfo(
								OUT PSECPKG_CLIENT_INFO ClientInfo);

PVOID NTAPI EIDCardLibraryMyAllocateLsaHeap (
    IN ULONG Length
    );
VOID NTAPI EIDCardLibraryMyFreeLsaHeap ( PVOID Buffer);
NTSTATUS NTAPI EIDCardLibraryMyCreateLogonSession(
  __in  PLUID LogonId
);

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
);