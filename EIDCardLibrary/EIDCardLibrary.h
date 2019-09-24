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

#include <ntsecapi.h>

#define AUTHENTICATIONPACKAGENAME "EIDAuthenticationPackage"
#define AUTHENTICATIONPACKAGENAMEW L"EIDAuthenticationPackage"
#define AUTHENTICATIONPACKAGENAMET TEXT("EIDAuthenticationPackage")


#define CERT_HASH_LENGTH        20  // SHA1 hashes are used for cert hashes

#define EIDAlloc(value) EIDAllocEx(__FILE__,__LINE__,__FUNCTION__,value)
#define EIDFree(value) EIDFreeEx(__FILE__,__LINE__,__FUNCTION__,value)

PVOID EIDAllocEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,DWORD);
VOID EIDFreeEx(PCSTR szFile, DWORD dwLine, PCSTR szFunction,PVOID);
VOID EIDImpersonate();
VOID EIDRevertToSelf();
BOOL EIDIsComponentInLSAContext();

typedef enum _EID_INTERACTIVE_LOGON_SUBMIT_TYPE
{
	EID_INTERACTIVE_LOGON_SUBMIT_TYPE_VANILLIA = 13, //KerbCertificateLogon = 13
} EID_INTERACTIVE_LOGON_SUBMIT_TYPE;

typedef struct _EID_INTERACTIVE_LOGON 
{
    EID_INTERACTIVE_LOGON_SUBMIT_TYPE MessageType; // KerbCertificateLogon
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Pin;
	ULONG Flags;               // additional flags
    ULONG CspDataLength;
    PUCHAR CspData;            // contains the smartcard CSP data
} EID_INTERACTIVE_LOGON, *PEID_INTERACTIVE_LOGON;

typedef struct _EID_INTERACTIVE_UNLOCK_LOGON
{
    EID_INTERACTIVE_LOGON Logon;
    LUID LogonId;
} EID_INTERACTIVE_UNLOCK_LOGON, *PEID_INTERACTIVE_UNLOCK_LOGON;

typedef enum _EID_PROFILE_BUFFER_TYPE
{
	EIDInteractiveProfile = 2,
} EID_PROFILE_BUFFER_TYPE;

#pragma pack(push, EID_SMARTCARD_CSP_INFO, 1)
// based on _KERB_SMARTCARD_CSP_INFO 
typedef struct _EID_SMARTCARD_CSP_INFO 
{
  DWORD dwCspInfoLen;
  DWORD MessageType;
  union {
    PVOID ContextInformation;
    ULONG64 SpaceHolderForWow64;
  } ;
  DWORD flags;
  DWORD KeySpec;
  ULONG nCardNameOffset;
  ULONG nReaderNameOffset;
  ULONG nContainerNameOffset;
  ULONG nCSPNameOffset;
  TCHAR bBuffer[sizeof(DWORD)];
} EID_SMARTCARD_CSP_INFO, 
 *PEID_SMARTCARD_CSP_INFO;
#pragma pack(pop, EID_SMARTCARD_CSP_INFO)

typedef struct _EID_INTERACTIVE_PROFILE
{
  EID_PROFILE_BUFFER_TYPE MessageType;
  USHORT LogonCount;
  USHORT BadPasswordCount;
  LARGE_INTEGER LogonTime;
  LARGE_INTEGER LogoffTime;
  LARGE_INTEGER KickOffTime;
  LARGE_INTEGER PasswordLastSet;
  LARGE_INTEGER PasswordCanChange;
  LARGE_INTEGER PasswordMustChange;
  UNICODE_STRING LogonScript;
  UNICODE_STRING HomeDirectory;
  UNICODE_STRING FullName;
  UNICODE_STRING ProfilePath;
  UNICODE_STRING HomeDirectoryDrive;
  UNICODE_STRING LogonServer;
  ULONG UserFlags;
} EID_INTERACTIVE_PROFILE, 
 *PEID_INTERACTIVE_PROFILE;

typedef enum _EID_CREDENTIAL_PROVIDER_READER_STATE
{
	EIDCPRSConnecting,
	EIDCPRSConnected,
	EIDCPRSDisconnected,
	EIDCPRSThreadFinished,
} EID_CREDENTIAL_PROVIDER_READER_STATE;

typedef enum _EID_CALLPACKAGE_MESSAGE
{
	EIDCMCreateStoredCredential,
	EIDCMUpdateStoredCredential,
	EIDCMRemoveStoredCredential,
	EIDCMHasStoredCredential,
	EIDCMRemoveAllStoredCredential,
	EIDCMGetStoredCredentialRid,
	EIDCMEIDGinaAuthenticationChallenge,
	EIDCMEIDGinaAuthenticationResponse,
} EID_CALLPACKAGE_MESSAGE;

//Message used for LsaApCallPackage
typedef struct _EID_CALLPACKAGE_BUFFER
{
	EID_CALLPACKAGE_MESSAGE MessageType;
	DWORD dwError;
	DWORD dwRid;
	PWSTR szPassword;		// used if EIDCMCreateStoredCredential
	USHORT usPasswordLen;	// can be 0 if null terminated
	PBYTE pbCertificate;
	USHORT dwCertificateSize;
	UCHAR Hash[CERT_HASH_LENGTH]; // to get challenge
	BOOL fEncryptPassword;

} EID_CALLPACKAGE_BUFFER, *PEID_CALLPACKAGE_BUFFER;

typedef struct _EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST
{
	EID_CALLPACKAGE_MESSAGE MessageType;
    DWORD dwRid;
} EID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST, *PEID_MSGINA_AUTHENTICATION_CHALLENGE_REQUEST;

typedef struct _EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER
{
	DWORD dwError;
	DWORD dwChallengeType;
	PBYTE pbChallenge;
	DWORD dwChallengeSize;
} EID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER, *PEID_MSGINA_AUTHENTICATION_CHALLENGE_ANSWER;

typedef struct _EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST
{
	EID_CALLPACKAGE_MESSAGE MessageType;
    DWORD dwRid;
	DWORD dwChallengeType;
	PBYTE pbChallenge;
	DWORD dwChallengeSize;
	PBYTE pbResponse;
	DWORD dwResponseSize;
} EID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST, *PEID_MSGINA_AUTHENTICATION_RESPONSE_REQUEST;

typedef struct _EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER
{
	DWORD dwError;
	UNICODE_STRING Password;
} EID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER, *PEID_MSGINA_AUTHENTICATION_RESPONSE_ANSWER;


#define EID_CERTIFICATE_FLAG_USERSTORE 0x00000001

typedef struct _EID_NEGOCIATE_MESSAGE
{
	BYTE Signature[8];
	DWORD MessageType;
	DWORD Flags;
	USHORT TargetLen;
	USHORT TargetMaxLen;
	DWORD TargetOffset;
	USHORT WorkstationLen;
	USHORT WorkstationMaxLen;
	USHORT WorkstationOffset;
	UCHAR Hash[CERT_HASH_LENGTH];
	DWORD Version;
} EID_NEGOCIATE_MESSAGE, *PEID_NEGOCIATE_MESSAGE;

typedef struct _EID_CHALLENGE_MESSAGE
{
	BYTE Signature[8];
	DWORD MessageType;
	DWORD Flags;
	DWORD UsernameLen;
	DWORD UsernameOffset;
	DWORD ChallengeLen;
	DWORD ChallengeOffset;
	DWORD Version;
} EID_CHALLENGE_MESSAGE, *PEID_CHALLENGE_MESSAGE;

typedef struct _EID_RESPONSE_MESSAGE
{
	BYTE Signature[8];
	DWORD MessageType;
	DWORD ResponseLen;
	DWORD ResponseOffset;
	DWORD Version;
} EID_RESPONSE_MESSAGE, *PEID_RESPONSE_MESSAGE;

typedef enum _EID_MESSAGE_STATE
{
	EIDMSNone,
	EIDMSNegociate,
	EIDMSChallenge,
	EIDMSResponse,
	EIDMSComplete,
} EID_MESSAGE_STATE;

typedef enum _EID_MESSAGE_TYPE
{
	EIDMTNegociate = 1,
	EIDMTChallenge = 2,
	EIDMTResponse = 3,
} EID_MESSAGE_TYPE;

#define EID_MESSAGE_VERSION 1
#define EID_MESSAGE_SIGNATURE "EIDAuth"

typedef enum _EID_SSP_CALLER
{
	EIDSSPInitialize,
	EIDSSPAccept,
} EID_SSP_CALLER;

typedef struct _EID_SSP_CALLBACK_MESSAGE
{
	EID_SSP_CALLER Caller;
	HANDLE hToken;
} EID_SSP_CALLBACK_MESSAGE, *PEID_SSP_CALLBACK_MESSAGE;