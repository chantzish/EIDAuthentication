
extern HINSTANCE g_hinst;

extern BOOL fShowNewCertificatePanel;
extern BOOL fGotoNewScreen;

extern WCHAR szReader[];
extern DWORD dwReaderSize;
extern WCHAR szCard[];
extern DWORD dwCardSize;
extern WCHAR szUserName[];
extern DWORD dwUserNameSize;
extern WCHAR szPassword[];
extern DWORD dwPasswordSize;


VOID CenterWindow(HWND hWnd);
BOOL IsElevated();
BOOL IsCurrentUserBelongToADomain();
BOOL DialogForceSmartCardLogonPolicy(HWND hWndParent = NULL);
BOOL DialogRemovePolicy(HWND hWndParent = NULL);
VOID SetIcon(HWND hWnd);
BOOL SendReport(DWORD dwErrorCode, PTSTR szEmail, PCCERT_CONTEXT pCertContext);

