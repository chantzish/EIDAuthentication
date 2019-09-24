#include <windows.h>
#include <tchar.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/CSmartCardNotifier.h"



class CSmartCardConnectionNotifierTest : public ISmartCardConnectionNotifierRef
{
public:
	virtual void Callback(EID_CREDENTIAL_PROVIDER_READER_STATE Message,__in LPCTSTR Reader,__in_opt LPCTSTR CardName, __in_opt USHORT ActivityCount) 
	{
		switch(Message)
		{
		case EIDCPRSConnecting:
			MessageBox(0,_T("OnCardInsert"),_T("SmartCardThread"),0);
			break;
		case EIDCPRSDisconnected:
			MessageBox(0,_T("OnCardRemove"),_T("SmartCardThread"),0);
			break;
		case EIDCPRSThreadFinished:
			MessageBox(0,_T("OnThreadFinished"),_T("SmartCardThread"),0);
			break;
		}
	}
};

CSmartCardConnectionNotifier *_pSmartCardConnectionNotifier;
CSmartCardConnectionNotifierTest _SmartCardConnectionNotifierTest;

void Menu_STARTWAITTHREAD()
{
	if (_pSmartCardConnectionNotifier == NULL)
	{
		_pSmartCardConnectionNotifier = new CSmartCardConnectionNotifier(&_SmartCardConnectionNotifierTest);
	}
	else
	{
		MessageBox(0,_T("Thread already launched"),_T("SmartCardThread"),0);
	}
}

void Menu_STOPWAITTHREAD()
{
	if (_pSmartCardConnectionNotifier != NULL)
	{
		_pSmartCardConnectionNotifier->Stop();
		delete _pSmartCardConnectionNotifier;
		_pSmartCardConnectionNotifier = NULL;
	}
	else
	{
		MessageBox(0,_T("Thread not launched"),_T("SmartCardThread"),0);
	}
}