#pragma once
BOOL AskUsername(WCHAR* Username, WCHAR* ComputerName);
BOOL AskPin(PWSTR Pin, PWSTR szReader, PWSTR szCard);
BOOL AskPassword(WCHAR* Password);


PCCERT_CONTEXT SelectCert(__in LPCWSTR szReaderName,__in LPCWSTR szCardName);




typedef void (TracingWindowsCallback)(void);
HWND CreateDialogTracing(TracingWindowsCallback *ponDestroy);
BOOL DisplayTrace(HWND hTracingWindow, PCTSTR szMessage);