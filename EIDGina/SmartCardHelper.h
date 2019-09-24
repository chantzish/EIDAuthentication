/*
BOOL LogonUsingSmartCard(__in PWSTR szPin,
						__in CContainer* pContainer,
						__in SECURITY_LOGON_TYPE logonType,
						__out PLUID                   pAuthenticationId,
						__out PHANDLE                 phToken,
						__out PWSTR *                 pszUserName,
						__out PWSTR *                 pszDomain,
						__out PMSV1_0_INTERACTIVE_PROFILE *     pProfile,
						__out PDWORD dwError);
*/
BOOL GetPassword(__in PWSTR szPin,
				 __in CContainer* pContainer,
				 __out PWSTR *pszUserName,
				 __out PWSTR *pszPassword,
				 __out PWSTR *pszDomain,
				 __out PDWORD pdwError,
				 __out PDWORD pdwRemainingPin);