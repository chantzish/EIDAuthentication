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

 
typedef enum EID_PRIVATE_DATA_TYPE
{
	eidpdtClearText=1,
	eidpdtCrypted = 2,

}*PEID_PRIVATE_DATA_TYPE;
#define CERT_HASH_LENGTH 20
typedef struct _EID_PRIVATE_DATA
{
	EID_PRIVATE_DATA_TYPE dwType;
	USHORT dwCertificatOffset;
	USHORT dwCertificatSize;
	USHORT dwSymetricKeyOffset;
	USHORT dwSymetricKeySize;
	USHORT dwPasswordOffset;
	USHORT dwPasswordSize;
	UCHAR Hash[CERT_HASH_LENGTH];
	BYTE Data[sizeof(DWORD)];
} EID_PRIVATE_DATA, *PEID_PRIVATE_DATA;

 class CStoredCredentialManager
 {
    // constructeurs/destructeur de OnlyOne accessibles au Singleton
public:
	static CStoredCredentialManager* Instance()
     {
         if (!theSingleInstance)
		 {
			 theSingleInstance = new CStoredCredentialManager;
		 }
		 return theSingleInstance;
     }

    BOOL GetUsernameFromCertContext(__in PCCERT_CONTEXT pContext, __out PWSTR *szUsername, __out PDWORD pdwRid);
	BOOL GetCertContextFromHash(__in PBYTE pbHash, __out PCCERT_CONTEXT* ppContext, __out PDWORD pdwRid);
	BOOL CreateCredential(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPassword, __in_opt USHORT usPasswordLen, __in BOOL fEncryptPassword, __in BOOL fCheckPassword);
	BOOL UpdateCredential(__in PLUID pLuid, __in PUNICODE_STRING Password);
	BOOL UpdateCredential(__in DWORD dwRid, __in PWSTR szPassword, __in_opt USHORT usPasswordLen);
	BOOL GetChallenge(__in DWORD dwRid, __out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize, __out PDWORD pdwType);
	BOOL GetResponseFromChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in DWORD dwChallengeType, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetPasswordFromChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize,  __in DWORD dwChallengeType, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetPassword(__in DWORD dwRid, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PWSTR *pszPassword);
	BOOL RemoveStoredCredential(__in DWORD dwRid);
	BOOL RemoveAllStoredCredential();
	BOOL HasStoredCredential(__in DWORD dwRid);
	BOOL HasStoredCredential(__in PCCERT_CONTEXT pContext);
	BOOL GetResponseFromSignatureChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetSignatureChallenge(__out PBYTE* ppChallenge, __out PDWORD pdwChallengeSize);
	BOOL VerifySignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize);
 private:
	static CStoredCredentialManager* theSingleInstance;	
	BOOL GetResponseFromCryptedChallenge(__in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PCCERT_CONTEXT pCertContext, __in PWSTR szPin, __out PBYTE *ppResponse, __out PDWORD pdwResponseSize);
	BOOL GetPasswordFromCryptedChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetPasswordFromSignatureChallengeResponse(__in DWORD dwRid, __in PBYTE ppChallenge, __in DWORD dwChallengeSize, __in PBYTE pResponse, __in DWORD dwResponseSize, __out PWSTR *pszPassword);
	BOOL GetCertContextFromRid(__in DWORD dwRid, __out PCCERT_CONTEXT* ppContext, __out PBOOL fEncryptPassword);
	BOOL RetrievePrivateData(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData);
	BOOL StorePrivateData(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize);
	BOOL RetrievePrivateDataDebug(__in DWORD dwRid, __out PEID_PRIVATE_DATA *ppPrivateData);
	BOOL StorePrivateDataDebug(__in DWORD dwRid, __in_opt PBYTE pbSecret, __in_opt USHORT usSecretSize);
	BOOL GenerateSymetricKeyAndEncryptIt(__in HCRYPTPROV hProv, __in HCRYPTKEY hKey, __out HCRYPTKEY *phKey, __out PBYTE* pSymetricKey, __out USHORT *usSize);
	BOOL EncryptPasswordAndSaveIt(__in HCRYPTKEY hKey, __in PWSTR szPassword, __in_opt USHORT dwPasswordLen, __out PBYTE *pEncryptedPassword, __out USHORT *usSize);
	virtual NTSTATUS CheckPassword( __in DWORD dwRid, __in PWSTR szPassword);
 };


//BOOL CanEncryptPassword(__in_opt HCRYPTPROV hProv, __in_opt DWORD dwKeySpec,  __in_opt PCCERT_CONTEXT pCertContext);

#ifdef _NTSECPKG_
NTSTATUS CompletePrimaryCredential(__in PLSA_UNICODE_STRING AuthenticatingAuthority,
						__in PLSA_UNICODE_STRING AccountName,
						__in PSID UserSid,
						__in PLUID LogonId,
						__in PWSTR szPassword,
						__out  PSECPKG_PRIMARY_CRED PrimaryCredentials);
#endif