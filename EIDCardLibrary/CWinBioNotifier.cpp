#include <windows.h>
#include <tchar.h>
#include <winbio.h>

#include "CWinBioNotifier.h"
#include "Tracing.h"
#include "../EIDCardLibrary/guid.h"
#pragma comment(lib,"winbio")

CWinBioNotifier::CWinBioNotifier(IWinBioNotifierRef* CallBack)
{
	_CallBack = CallBack;
	_SessionHandle = NULL;
	Start();
}

CWinBioNotifier::~CWinBioNotifier()
{
	Stop();
}

GUID guidtest;
HRESULT EnumDatabases( )
{
    // Declare variables.
    HRESULT hr = S_OK;
    PWINBIO_STORAGE_SCHEMA storageSchemaArray = NULL;
    SIZE_T storageCount = 0;
    SIZE_T index = 0;

    // Enumerate the databases.
    hr = WinBioEnumDatabases( 
            WINBIO_TYPE_FINGERPRINT,    // Type of biometric unit
            &storageSchemaArray,        // Array of database schemas
            &storageCount );            // Number of database schemas
    if (FAILED(hr))
    {
        wprintf_s(L"\nWinBioEnumDatabases failed. hr = 0x%x\n", hr);
        goto e_Exit;
    }

    // Display information for each database.
    wprintf_s(L"\nDatabases:\n");
    for (index = 0; index < storageCount; ++index)
    {
        guidtest = storageSchemaArray[index].DatabaseId;
		wprintf_s(L"\n[%d]: \tBiometric factor: 0x%08x\n", 
                 index, 
                 storageSchemaArray[index].BiometricFactor );
        
        wprintf_s(L"\tDatabase ID: ");
        //DisplayGuid(&storageSchemaArray[index].DatabaseId);
        wprintf_s(L"\n");

        wprintf_s(L"\tData format: ");
        //DisplayGuid(&storageSchemaArray[index].DataFormat);
        wprintf_s(L"\n");

        wprintf_s(L"\tAttributes:  0x%08x\n", 
                 storageSchemaArray[index].Attributes);

        wprintf_s(L"\tFile path:   %ws\n", 
                 storageSchemaArray[index].FilePath );

        wprintf_s(L"\tCnx string:  %ws\n", 
                 storageSchemaArray[index].ConnectionString );

        wprintf_s(L"\n");
    }

e_Exit:
    if (storageSchemaArray != NULL)
    {
        WinBioFree(storageSchemaArray);
        storageSchemaArray = NULL;
    }

    wprintf_s(L"\nPress any key to exit...");

    return hr;
}



HRESULT CWinBioNotifier::Start() 
{
	HRESULT hResult = S_OK;
	WINBIO_UNIT_ID unitId = 0;
	PWINBIO_UNIT_SCHEMA unitSchema = NULL;
		SIZE_T unitCount = 0;
		SIZE_T index = 0;
	__try
	{
		// check callback
		if(NULL == _CallBack)
		{
			// no callback defined : don't launch
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"No callback definied");
			hResult = E_FAIL;
			__leave;
		}
		
		EnumDatabases( );

		// Enumerate the installed biometric units.
		hResult = WinBioEnumBiometricUnits( 
			WINBIO_TYPE_FINGERPRINT,        // Type of biometric unit
			&unitSchema,                    // Array of unit schemas
			&unitCount );                   // Count of unit schemas

		if (FAILED(hResult))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WinBioOpenSession 0x%08X",hResult);
			_CallBack->WinBioCallbackFailure(TEXT("Unable to connect to the biometric device"));
			__leave;
		}
        GUID guid = guidtest;
		WINBIO_UNIT_ID unitid = 1;
		hResult = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT, WINBIO_POOL_SYSTEM, WINBIO_DATA_FLAG_RAW,NULL, 0,WINBIO_DB_DEFAULT , &_SessionHandle);
		if (FAILED(hResult))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WinBioOpenSession 0x%08X",hResult);
			_CallBack->WinBioCallbackFailure(TEXT("Unable to connect to the biometric device"));
			__leave;
		}
		hResult = WinBioCaptureSampleWithCallback(_SessionHandle, 0, WINBIO_DATA_FLAG_RAW, CaptureCallback, this);
		if (FAILED(hResult))
		{
			EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"WinBioCaptureSampleWithCallback 0x%08X",hResult);
			_CallBack->WinBioCallbackFailure(TEXT("Unable to capture biometrics"));
			__leave;
		}
	}
	__finally
	{
	}

	return hResult;
}

HRESULT CWinBioNotifier::Stop()
{
	if (_SessionHandle)
	{
		WinBioCloseSession(_SessionHandle);
		_SessionHandle = NULL;
	}
	return S_OK;
}

VOID CALLBACK CWinBioNotifier::CaptureCallback(
    __in_opt PVOID CaptureCallbackContext,
    __in HRESULT OperationStatus,
    __in WINBIO_UNIT_ID UnitId,
    __in_bcount(SampleSize) PWINBIO_BIR Sample,
    __in SIZE_T SampleSize,
    __in WINBIO_REJECT_DETAIL RejectDetail
    )
{
	UNREFERENCED_PARAMETER(UnitId);
	CWinBioNotifier* notifier = (CWinBioNotifier*) CaptureCallbackContext;
	if (SUCCEEDED(OperationStatus))
	{
		WinBioFree(Sample);
	}
	else
	{
		EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Failure 0x%08X 0x%08X",OperationStatus,RejectDetail);
		if (notifier->_CallBack)
		{
			PTSTR szMessage;
			switch(OperationStatus)
			{
			case E_NOTIMPL:
				szMessage = TEXT("WinBioCaptureSample not implemented");
				break;
			default:
				switch(RejectDetail)
				{
				case WINBIO_FP_TOO_HIGH:
					szMessage = TEXT("WINBIO_FP_TOO_HIGH");
					break;
				case WINBIO_FP_TOO_LOW:
					szMessage = TEXT("WINBIO_FP_TOO_LOW");
					break;
				case WINBIO_FP_TOO_LEFT:
					szMessage = TEXT("WINBIO_FP_TOO_LEFT");
					break;
				case WINBIO_FP_TOO_RIGHT:
					szMessage = TEXT("WINBIO_FP_TOO_RIGHT");
					break;
				case WINBIO_FP_TOO_FAST:
					szMessage = TEXT("WINBIO_FP_TOO_FAST");
					break;
				case WINBIO_FP_TOO_SLOW:
					szMessage = TEXT("WINBIO_FP_TOO_SLOW");
					break;
				case WINBIO_FP_POOR_QUALITY:
					szMessage = TEXT("WINBIO_FP_POOR_QUALITY");
					break;
				case WINBIO_FP_TOO_SKEWED:
					szMessage = TEXT("WINBIO_FP_TOO_SKEWED");
					break;
				case WINBIO_FP_TOO_SHORT:
					szMessage = TEXT("WINBIO_FP_TOO_SHORT");
					break;
				case WINBIO_FP_MERGE_FAILURE:
					szMessage = TEXT("WINBIO_FP_MERGE_FAILURE");
					break;
				default:
					szMessage = TEXT("Unknown failure");
					break;
				}
			}
			notifier->_CallBack->WinBioCallbackFailure(szMessage);
		}
	}
}
