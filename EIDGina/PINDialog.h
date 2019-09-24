#pragma once

#include <Windows.h>
#include <tchar.h>
#include "global.h"
#include "CWinlogon.h"
#include "CGina.h"
#include "resource.h"
#include <credentialprovider.h>
#include "../EIDCardLibrary/CContainer.h"
#include "GinaSmartCardCredential.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"

class PINDialog {
public:
    PINDialog(CGina* pGina,PWSTR* pszUserName,PWSTR* pszPassword,PWSTR* pszDomain);
	~PINDialog();
    int Show();
	virtual INT_PTR DialogProc(UINT msg, WPARAM wp, LPARAM lp);
	WCHAR szPin[255];
	GinaSmartCardCredential* pCredential;
protected:
	PINDialog();
	CWinLogon* _pWinLogon;
	CGina* _pGina;
    static INT_PTR CALLBACK _dialogProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);
    BOOL Populate();
	BOOL Login();
    void CenterWindow();
	void SetWaitStatus(BOOL fDisableButton);
	HWND       _hwnd;
	CContainerHolderFactory<GinaSmartCardCredential> _pCredentialList;
	WCHAR _szReader[255];
	WCHAR _szCard[255];
	PWSTR *_pszUserName;
	PWSTR *_pszPassword;
	PWSTR *_pszDomain;
};
