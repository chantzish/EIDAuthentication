BOOL CommunicateTestOK();
BOOL CommunicateTestNotOK(DWORD dwErrorCode, PTSTR szEmail, PTSTR szTracingFile, PCCERT_CONTEXT pCertContext);
BOOL OpenBrowserOnDatabase();
BOOL OpenBrowserOnDatabase(__in PBYTE pbAtr, __in DWORD dwAtrSize, __in_opt PTSTR szCardName);
PTSTR GetAdvancedErrorMessage();