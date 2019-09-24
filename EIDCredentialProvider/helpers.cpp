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

//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) 2006 Microsoft Corporation. All rights reserved.
//
// Helper functions for copying parameters and packaging the buffer
// for GetSerialization.


#include "helpers.h"
#include "dll.h"
#include "EIDCredentialProvider.h"
#include <intsafe.h>
#include <wincred.h>
#include <lm.h>
#include "../EIDCardLibrary/EIDCardLibrary.h"
#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/Package.h"

#include <CodeAnalysis/warnings.h>

#pragma warning(push)
#pragma warning(disable : 4995)
#include <shlwapi.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable : 4995)
#include <strsafe.h>
#pragma warning(pop)

#pragma comment(lib,"shlwapi")
#pragma comment(lib,"comctl32")
// 
// Copies the field descriptor pointed to by rcpfd into a buffer allocated 
// using CoTaskMemAlloc. Returns that buffer in ppcpfd.
// 
HRESULT FieldDescriptorCoAllocCopy(
                                   const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
                                   )
{
    HRESULT hr;
    DWORD cbStruct = sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR);

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = 
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(cbStruct);

    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = NULL;
            hr = S_OK;
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hr))
    {
        *ppcpfd = pcpfd;
    }
    else
    {
        CoTaskMemFree(pcpfd);  
        *ppcpfd = NULL;
    }


    return hr;
}

//
// Coppies rcpfd into the buffer pointed to by pcpfd. The caller is responsible for
// allocating pcpfd. This function uses CoTaskMemAlloc to allocate memory for 
// pcpfd->pszLabel.
//
HRESULT FieldDescriptorCopy(
                            const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd
                            )
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR cpfd;

    cpfd.dwFieldID = rcpfd.dwFieldID;
    cpfd.cpft = rcpfd.cpft;

    if (rcpfd.pszLabel)
    {
        hr = SHStrDupW(rcpfd.pszLabel, &cpfd.pszLabel);
    }
    else
    {
        cpfd.pszLabel = NULL;
        hr = S_OK;
    }

    if (SUCCEEDED(hr))
    {
        *pcpfd = cpfd;
    }

    return hr;
}


//
// Return a copy of pwzToProtect encrypted with the CredProtect API.
//
// pwzToProtect must not be NULL or the empty string.
//
static HRESULT ProtectAndCopyString(
                                    PWSTR pwzToProtect, 
                                    PWSTR* ppwzProtected
                                    )
{
    *ppwzProtected = NULL;

    HRESULT hr = E_FAIL;

    // The first call to CredProtect determines the length of the encrypted string.
    // Because we pass a NULL output buffer, we expect the call to fail.
    //
    // Note that the third parameter to CredProtect, the number of characters of pwzToProtect
    // to encrypt, must include the NULL terminator!
    DWORD cchProtected = 0;
	PWSTR pwzProtected = L"";
    if (!CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, NULL))
    {
        DWORD dwErr = GetLastError();

        if ((ERROR_INSUFFICIENT_BUFFER == dwErr) && (0 < cchProtected))
        {
            // Allocate a buffer long enough for the encrypted string.
            pwzProtected = (PWSTR)CoTaskMemAlloc(cchProtected * sizeof(WCHAR));

            if (pwzProtected)
            {
                // The second call to CredProtect actually encrypts the string.
                if (CredProtectW(FALSE, pwzToProtect, (DWORD)wcslen(pwzToProtect)+1, pwzProtected, &cchProtected, NULL))
                {
                    *ppwzProtected = pwzProtected;
                    hr = S_OK;
                }
                else
                {
                    CoTaskMemFree(pwzProtected);

                    dwErr = GetLastError();
                    hr = HRESULT_FROM_WIN32(dwErr);
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
        else
        {
            hr = HRESULT_FROM_WIN32(dwErr);
        }
    }

    return hr;
}

//
// If pwzPassword should be encrypted, return a copy encrypted with CredProtect.
// 
// If not, just return a copy.
//
HRESULT ProtectIfNecessaryAndCopyPassword(
                                          PWSTR pwzPassword,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
										  DWORD dwFlags,
                                          PWSTR* ppwzProtectedPassword
                                          )
{
    *ppwzProtectedPassword = NULL;

    HRESULT hr;

    // ProtectAndCopyString is intended for non-empty strings only.  Empty passwords
    // do not need to be encrypted.
    if (pwzPassword && *pwzPassword)
    {
        bool bCredAlreadyEncrypted = false;
        CRED_PROTECTION_TYPE protectionType;

        // If the password is already encrypted, we should not encrypt it again.
        // An encrypted password may be received through SetSerialization in the 
        // CPUS_LOGON scenario during a Terminal Services connection, for instance.
        if(CredIsProtectedW(pwzPassword, &protectionType))
        {
            if(CredUnprotected != protectionType)
            {
                bCredAlreadyEncrypted = true;
            }
        }

        // Passwords should not be encrypted in the CPUS_CREDUI scenario.  We
        // cannot know if our caller expects or can handle an encryped password.
        if (CPUS_CREDUI == cpus || bCredAlreadyEncrypted || (dwFlags & CREDUIWIN_GENERIC))
        {
            hr = SHStrDupW(pwzPassword, ppwzProtectedPassword);
        }
        else
        {
            hr = ProtectAndCopyString(pwzPassword, ppwzProtectedPassword);
        }
    }
    else
    {
        hr = SHStrDupW(L"", ppwzProtectedPassword);
    }

    return hr;
}

typedef BOOL (NTAPI * PRShowRestoreFromMsginaW) (DWORD, DWORD, PWSTR, DWORD);
static INT_PTR CALLBACK CancelForcePolicyWizardCallBack(HWND hwndDlg, UINT message, WPARAM wParam, LPARAM lParam) 
{ 
 
    switch (message) 
    { 
        case WM_INITDIALOG: 
			break;
		case WM_COMMAND: 
            switch (LOWORD(wParam)) 
            { 
            case IDC_OK: 
				
				{
					WCHAR szUserName[256];
					WCHAR szPassword[256];
					HANDLE hToken = INVALID_HANDLE_VALUE;
					DWORD dwValue = 0;
					LONG lStatus;
					__try
					{
						GetWindowTextW(GetDlgItem(hwndDlg,IDC_USERNAME),szUserName,ARRAYSIZE(szUserName));
						GetWindowTextW(GetDlgItem(hwndDlg,IDC_PASSWORD),szPassword,ARRAYSIZE(szPassword));
						if (!LogonUser(szUserName,NULL,szPassword,LOGON32_LOGON_INTERACTIVE,LOGON32_PROVIDER_DEFAULT,&hToken))
						{
							MessageBoxWin32(GetLastError());
							__leave;
						}
						if (!IsAdmin(szUserName))
						{
							MessageBoxWin32(0x5);
							__leave;
						}
						lStatus = RegSetKeyValue(	HKEY_LOCAL_MACHINE, 
								TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Policies\\System"), 
								TEXT("scforceoption"), REG_DWORD, &dwValue,sizeof(DWORD));
						if (lStatus != ERROR_SUCCESS)
						{
							MessageBoxWin32(lStatus);
							__leave;
						}
					}
					__finally
					{
						if (hToken != INVALID_HANDLE_VALUE)
							CloseHandle(hToken);
					}
				}
				EndDialog(hwndDlg,1);
                return TRUE; 
			case IDC_CANCEL:
				EndDialog(hwndDlg,0);
                return TRUE; 
            }
			break;
			// g_hLink is the handle of the SysLink control.
		case WM_NOTIFY:
			switch (((LPNMHDR)lParam)->code)
			{
			case NM_CLICK:
			case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idinfo") == 0)
					{
						// launch the password reset wizard
						HMODULE keymgrDll = NULL;
						WCHAR szUserName[256];
						PBYTE pbBuffer;
						NET_API_STATUS nStatus;
						GetWindowTextW(GetDlgItem(hwndDlg,IDC_USERNAME),szUserName,ARRAYSIZE(szUserName));
						nStatus = NetUserGetInfo(NULL,szUserName,0,&pbBuffer);
						if (nStatus == NERR_Success)
						{
							NetApiBufferFree(pbBuffer);
							__try
							{
								keymgrDll = LoadLibrary(TEXT("keymgr.dll"));
								if (!keymgrDll)
								{
									__leave;
								}
								PRShowRestoreFromMsginaW MyPRShowRestoreFromMsginaW = (PRShowRestoreFromMsginaW) GetProcAddress(keymgrDll,"PRShowRestoreFromMsginaW");
								if (!MyPRShowRestoreFromMsginaW)
								{
									__leave;
								}
								MyPRShowRestoreFromMsginaW(NULL,NULL,szUserName,NULL);
							}
							__finally
							{
								if (keymgrDll)
									FreeLibrary(keymgrDll);
							}
						}
						else
						{
							MessageBoxWin32(nStatus);
						}
					}
					break;
				}
			}

	}
	return FALSE;
}

void ShowCancelForcePolicyWizard(HWND hWnd)
{
	DialogBox(HINST_THISDLL,MAKEINTRESOURCE(IDD_CANCELFORCEPOLICY) ,hWnd,CancelForcePolicyWizardCallBack);
}