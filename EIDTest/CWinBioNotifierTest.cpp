#include <windows.h>
#include <tchar.h>
#include <winbio.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/CWinBioNotifier.h"


/*
class CWinBioNotifierTest : public IWinBioNotifierRef
{
public:
	virtual void WinBioCallbackSuccess(PTSTR szText) 
	{
		MessageBox(0,szText,_T("Success"),0);
	}
	virtual void WinBioCallbackFailure(PTSTR szText) 
	{
		MessageBox(0,szText,_T("Failure"),0);
	}
};

CWinBioNotifier *_pWinBioNotifier;
CWinBioNotifierTest _WinBioNotifierTest;
*/
void Menu_WINBIOSTARTWAITTHREAD()
{
	/*if (_pWinBioNotifier == NULL)
	{
		_pWinBioNotifier = new CWinBioNotifier(&_WinBioNotifierTest);
	}
	else
	{
		MessageBox(0,_T("Thread already launched"),_T("WinBioThread"),0);
	}*/
}

void Menu_WINBIOSTOPWAITTHREAD()
{
	/*if (_pWinBioNotifier != NULL)
	{
		_pWinBioNotifier->Stop();
		delete _pWinBioNotifier;
		_pWinBioNotifier = NULL;
	}
	else
	{
		MessageBox(0,_T("Thread not launched"),_T("WinBioThread"),0);
	}*/
}