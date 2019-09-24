
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
#include "resource.h"

#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/CompleteProfile.h"
#include "EIDTestUIUtil.h"
#include "LSAFunctionSubstitute.h"

extern HINSTANCE hInst;
extern HWND hMainWnd;




void Menu_AP_Profile()
{
	NTSTATUS Status;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING ComputerName;
	LSA_DISPATCH_TABLE FunctionTable;
	PEID_INTERACTIVE_PROFILE ProfileInformation;
	ULONG ProfileLength;
	WCHAR UserNameBuffer[UNLEN+1];
	WCHAR ComputerNameBuffer[UNLEN+1];
	if (!AskUsername(UserNameBuffer,ComputerNameBuffer)) return;

	// ask for a username
	UserName.Buffer = UserNameBuffer;
	UserName.Length = (USHORT) wcslen(UserNameBuffer)*sizeof(WCHAR);
	UserName.MaximumLength = (USHORT) UserName.Length+sizeof(WCHAR);

	// ask for a computer
	ComputerName.Buffer = ComputerNameBuffer;
	ComputerName.Length = (USHORT) wcslen(ComputerNameBuffer)*sizeof(WCHAR);
	ComputerName.MaximumLength = (USHORT) ComputerName.Length+sizeof(WCHAR);

	// function table
	FunctionTable.AllocateClientBuffer = (PLSA_ALLOCATE_CLIENT_BUFFER)EIDCardLibraryTestMyAllocateClientBuffer;
	FunctionTable.FreeClientBuffer = (PLSA_FREE_CLIENT_BUFFER)EIDCardLibraryMyFreeClientBuffer;
	FunctionTable.CopyToClientBuffer = (PLSA_COPY_TO_CLIENT_BUFFER) EIDCardLibraryMyCopyToClientBuffer;
	// call function
	Status = UserNameToProfile(&UserName,&FunctionTable,NULL,&ProfileInformation,&ProfileLength);

	// analyze results & free buffer
	if (Status == STATUS_SUCCESS)
	{
		MessageBox(NULL,TEXT("Success !"),TEXT(""),0);
		if (ProfileInformation!=NULL)
			EIDCardLibraryMyFreeClientBuffer(NULL,ProfileInformation);
	}
	else
	{
		MessageBox(NULL,TEXT("Unknown Failure !"),TEXT(""),0);
	}
}