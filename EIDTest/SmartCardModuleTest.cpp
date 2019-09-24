#include <windows.h>
#include <tchar.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/CertificateUtilities.h"
#include "../EIDCardLibrary/SmartCardModule.h"
#include "../EIDCardLibrary/Tracing.h"
#include "EIDTestUIUtil.h"

void test_SmartCardModule()
{
	TCHAR szReader[256];
	TCHAR szCard[256];
	TCHAR szPin[256];
	DWORD dwRemainingAttempts = 0;
	if (AskForCard(szReader,ARRAYSIZE(szReader),szCard,ARRAYSIZE(szCard)))
	{
		if (AskPin(szPin, szReader, szCard))
		{
			BOOL fReturn = CheckPINandGetRemainingAttempts(szReader, szCard, szPin, &dwRemainingAttempts);
			DWORD dwError = GetLastError();
			if (fReturn)
			{
				MessageBox(NULL, TEXT("Authentification Successfull"),TEXT("CheckPINandGetRemainingAttempts"),0);
			}
			else if (dwError == SCARD_W_WRONG_CHV)
			{
				TCHAR szMessage[256];
				_stprintf_s(szMessage, ARRAYSIZE(szMessage),TEXT("Wrong PIN : %d attempts remaining"),dwRemainingAttempts);
				MessageBox(NULL, szMessage,TEXT("CheckPINandGetRemainingAttempts"),0);
			}
			else if (dwError == SCARD_W_CHV_BLOCKED)
			{
				MessageBox(NULL, TEXT("Card blocked"),TEXT("CheckPINandGetRemainingAttempts"),0);
			}
			else
			{
				MessageBoxWin32(dwError);
			}
		}
	}
}