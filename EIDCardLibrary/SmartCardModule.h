
BOOL CheckPINandGetRemainingAttempts(PTSTR szReader, PTSTR szCard, PTSTR szPin, PDWORD pdwAttempts);
NTSTATUS CheckPINandGetRemainingAttemptsIfPossible(PEID_SMARTCARD_CSP_INFO pCspInfo, PTSTR szPin, NTSTATUS *pSubStatus);
