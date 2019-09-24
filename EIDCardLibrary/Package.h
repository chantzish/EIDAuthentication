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

BOOL IsEIDPackageAvailable();

HRESULT LsaInitString(PSTRING pszDestinationString, PCSTR pszSourceString);

//get the authentication package that will be used for our logon attempt
HRESULT RetrieveNegotiateAuthPackage(
    ULONG * pulAuthPackage
    );



//packages the credentials into the buffer that the system expects
HRESULT EIDUnlockLogonPack(
    const EID_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
	const PEID_SMARTCARD_CSP_INFO pCspInfo,
    BYTE** prgb,
    DWORD* pcb
    );

//szAuthPackageValue must be freed by  LsaFreeMemory
HRESULT CallAuthPackage(LPCWSTR username ,LPWSTR * szAuthPackageValue, PULONG szAuthPackageLen);

VOID EIDDebugPrintEIDUnlockLogonStruct(UCHAR dwLevel, PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon) ;

NTSTATUS RemapPointer(PEID_INTERACTIVE_UNLOCK_LOGON pUnlockLogon, PVOID ClientAuthenticationBase, ULONG AuthenticationInformationLength);

PTSTR GetUsernameFromRid(__in DWORD dwRid);
DWORD GetRidFromUsername(LPTSTR szUsername);
BOOL HasAccountOnCurrentComputer(PWSTR szUserName);
BOOL IsCurrentUser(PWSTR szUserName);
BOOL IsAdmin(PWSTR szUserName);

BOOL LsaEIDCreateStoredCredential(__in PWSTR szUsername, __in PWSTR szPassword, __in PCCERT_CONTEXT pCertContext, __in BOOL fEncryptPassword);

BOOL LsaEIDRemoveStoredCredential(__in_opt PWSTR szUsername);

BOOL LsaEIDHasStoredCredential(__in_opt PWSTR szUsername);

DWORD LsaEIDGetRIDFromStoredCredential(__in PCCERT_CONTEXT pContext);

//BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);