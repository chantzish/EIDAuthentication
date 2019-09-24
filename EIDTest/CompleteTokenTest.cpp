
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
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/CompleteToken.h"
#include "EIDTestUIUtil.h"

extern HINSTANCE hInst;
extern HWND hMainWnd;


void Menu_AP_Token()
{
	NTSTATUS Status, SubStatus;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING ComputerName;
	PLSA_TOKEN_INFORMATION_V2 TokenInformation;
	DWORD TokenLength;
	WCHAR UserNameBuffer[UNLEN+1];
	WCHAR ComputerNameBuffer[UNLEN+1];
	if (!AskUsername(UserNameBuffer,ComputerNameBuffer)) return;

	// ask for a username
	UserName.Buffer = UserNameBuffer;
	UserName.Length = (USHORT) (wcslen(UserNameBuffer)*sizeof(WCHAR));
	UserName.MaximumLength = (USHORT) (UserName.Length+sizeof(WCHAR));

	// ask for a computer
	ComputerName.Buffer = ComputerNameBuffer;
	ComputerName.Length = (USHORT) wcslen(ComputerNameBuffer)*sizeof(WCHAR);
	ComputerName.MaximumLength = (USHORT) ComputerName.Length+sizeof(WCHAR);


	// call function
	Status = UserNameToToken(&UserName,&TokenInformation,&TokenLength, &SubStatus);
	//Status = GetTokenInformationv2(NULL,ComputerNameBuffer,UserNameBuffer,&TokenInformation);
	// analyze results & free buffer
	if (Status == STATUS_SUCCESS)
	{
		MessageBox(NULL,TEXT("Success !"),TEXT(""),0);
		EIDFree(TokenInformation);
	}
	else
	{
		/*switch(Status)
		{
			case STATUS_ACCESS_DENIED:
				MessageBox(NULL,TEXT("STATUS_ACCESS_DENIED"),TEXT(""),0);
				break;
			case STATUS_NO_SUCH_DOMAIN:
				MessageBox(NULL,TEXT("STATUS_NO_SUCH_DOMAIN"),TEXT(""),0);
				break;
			case STATUS_NO_SUCH_USER:
				MessageBox(NULL,TEXT("STATUS_NO_SUCH_USER"),TEXT(""),0);
				break;
			case STATUS_ACCOUNT_RESTRICTION:
				MessageBox(NULL,TEXT("STATUS_ACCOUNT_RESTRICTION"),TEXT(""),0);
				break;
			default:
				MessageBox(NULL,TEXT("Unknown Failure !"),TEXT(""),0);
		}*/
		MessageBoxWin32(LsaNtStatusToWinError(Status));
	}
}