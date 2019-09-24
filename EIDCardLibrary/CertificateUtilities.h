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

#pragma once

PCCERT_CONTEXT SelectFirstCertificateWithPrivateKey();
PCCERT_CONTEXT SelectCertificateWithPrivateKey(HWND hWnd = NULL);

BOOL AskForCard(LPWSTR szReader, DWORD ReaderLength,LPWSTR szCard,DWORD CardLength);

BOOL SchGetProviderNameFromCardName(__in LPCTSTR szCardName, __out LPTSTR szProviderName, __out PDWORD pdwProviderNameLen);

#define UI_CERTIFICATE_INFO_SAVEON_USERSTORE 0
#define UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE 1
#define UI_CERTIFICATE_INFO_SAVEON_SYSTEMSTORE_MY 2
#define UI_CERTIFICATE_INFO_SAVEON_FILE 3
#define UI_CERTIFICATE_INFO_SAVEON_SMARTCARD 4

typedef struct _UI_CERTIFICATE_INFO
{
	LPTSTR szSubject;
	PCCERT_CONTEXT pRootCertificate;
	DWORD dwSaveon;
	LPTSTR szCard;
	LPTSTR szReader;
	DWORD dwKeyType;
	DWORD dwKeySizeInBits;
	BOOL bIsSelfSigned;
	BOOL bHasSmartCardAuthentication;
	BOOL bHasServerAuthentication;
	BOOL bHasClientAuthentication;
	BOOL bHasEFS;
	BOOL bIsCA;
	SYSTEMTIME StartTime;
	SYSTEMTIME EndTime;
	
	// used to return new certificate context if needed
	// need to free it if returned
	BOOL fReturnCerticateContext;
	PCCERT_CONTEXT pNewCertificate;
} UI_CERTIFICATE_INFO, * PUI_CERTIFICATE_INFO;

PCCERT_CONTEXT GetCertificateWithPrivateKey();
BOOL CreateCertificate(PUI_CERTIFICATE_INFO CertificateInfo);
BOOL ClearCard(PTSTR szReaderName, PTSTR szCardName);
BOOL ImportFileToSmartCard(PTSTR szFileName, PTSTR szPassword, PTSTR szReaderName, PTSTR szCardname);
PCCERT_CONTEXT FindCertificateFromHash(PCRYPT_DATA_BLOB pCertInfo);
