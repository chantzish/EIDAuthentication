#include <Windows.h>
#include "../EIDCardLibrary/OnlineDatabase.h"
#include "../EIDCardLibrary/Tracing.h"

void menu_Wizard_CommunicateTestOK()
{
	if (!CommunicateTestOK())
	{
		DWORD dwError = GetLastError();
		if (dwError == SPAPI_E_MACHINE_UNAVAILABLE || dwError == ERROR_INTERNAL_ERROR)
		{
			MessageBox(NULL,GetAdvancedErrorMessage(),TEXT("Error"),0);
		}
		else
		{
			MessageBoxWin32(GetLastError());
		}
	}
	else
	{
		MessageBoxWin32(0);
	}
}