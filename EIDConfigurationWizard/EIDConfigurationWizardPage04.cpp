#include <windows.h>
#include <tchar.h>
#include <commctrl.h>
#include <Winuser.h>
#include "global.h"
#include "EIDConfigurationWizard.h"

#include "../EIDCardLibrary/Tracing.h"
#include "../EIDCardLibrary/GPO.h"
#include "../EIDCardLibrary/CContainer.h"
#include "../EIDCardLibrary/CContainerHolderFactory.h"

#include "CContainerHolder.h"

#pragma comment(lib,"Netapi32")
#pragma comment(lib,"Winscard")
#pragma comment(lib,"Scarddlg")


CContainerHolderFactory<CContainerHolderTest> *pCredentialList = NULL;
DWORD dwCurrentCredential = 0xFFFFFFFF;
BOOL fHasDeselected = TRUE;

PTSTR Columns[] = {TEXT("Comment")};
#define COLUMN_NUM ARRAYSIZE(Columns)

BOOL InitListViewColumns(HWND hWndListView) 
{ 
    LVCOLUMN lvc; 
    int iCol; 

    // Initialize the LVCOLUMN structure.
    // The mask specifies that the format, width, text, and subitem members
    // of the structure are valid. 
    lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_SUBITEM | LVCF_WIDTH; 
	  
    // Add the columns
    for (iCol = 0; iCol < COLUMN_NUM; iCol++) 
    { 
        lvc.iSubItem = iCol;
        lvc.pszText = Columns[iCol];	
        lvc.fmt = LVCFMT_LEFT;
		lvc.cx = 450;

        if (ListView_InsertColumn(hWndListView, iCol, &lvc) == -1) 
            return FALSE; 
    } 
    return TRUE; 
} 

BOOL PopulateListViewCheckData(HWND hWndListViewList, HWND hWndListViewCheck)
{
	LVITEM lvI;
	UINT ColumnsToDisplay[] = {1,2,3};
	TCHAR szMessage[256] = TEXT("");
	// Some code to create the list-view control.
	// Initialize LVITEM members that are common to all items.
	lvI.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM | LVIF_STATE | LVIF_COLUMNS | LVIF_GROUPID; 
	lvI.state = 0; 
	lvI.stateMask = 0; 

	LVGROUP grp;
	
	CContainerHolderTest* pContainerHolder = pCredentialList->GetContainerHolderAt(dwCurrentCredential);

	//GRP
	for (int index = pContainerHolder->GetCheckCount() -1; index >= 0; index--)
	{
		grp.cbSize = sizeof(grp);
		grp.iGroupId = index;
		switch(index)
		{
		case CHECK_SIGNATUREONLY:
			LoadString(g_hinst,IDS_04TESTSIGNATURE, szMessage, ARRAYSIZE(szMessage));
			break;
		case CHECK_TRUST:
			LoadString(g_hinst,IDS_04TESTTRUST, szMessage, ARRAYSIZE(szMessage));
			break;
		case CHECK_CRYPTO:
			LoadString(g_hinst,IDS_04TESTCRYPTO, szMessage, ARRAYSIZE(szMessage));
			break;
		}
		grp.pszHeader = szMessage;
		grp.cchHeader = (int) (grp.pszHeader?_tcslen(grp.pszHeader):0);
		grp.pszTask = pContainerHolder->GetSolveDescription(index);
		grp.mask = LVGF_HEADER | LVGF_GROUPID | LVGF_TASK;
		ListView_InsertGroup(hWndListViewCheck, 0, &grp);
		if (grp.pszTask)
			EIDFree(grp.pszTask);
	}

	// Initialize LVITEM members that are different for each item. 
	for (int index = 0; index < pContainerHolder->GetCheckCount(); index++)
	{
		lvI.iItem = index;
		lvI.iImage = pContainerHolder->GetImage(index);
		lvI.iSubItem = 0;
		lvI.pszText = pContainerHolder->GetDescription(index);
		lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
		lvI.puColumns = ColumnsToDisplay;
		lvI.iGroupId = index;
		ListView_InsertItem(hWndListViewCheck, &lvI);
	}


	return TRUE;
}

BOOL PopulateListViewListData(HWND hWndListView)
{
	LVITEM lvI;
	UINT ColumnsToDisplay[] = {1,2,3};
	// Some code to create the list-view control.
	
	ListView_DeleteAllItems(hWndListView);
	// Initialize LVITEM members that are common to all items.
	lvI.mask = LVIF_TEXT | LVIF_IMAGE |  LVIF_STATE | LVIF_COLUMNS; 
	
	// Initialize LVITEM members that are different for each item. 
	for (DWORD index = 0; index < pCredentialList->ContainerHolderCount(); index++)
	{
		lvI.stateMask = LVIS_OVERLAYMASK;
		lvI.state = INDEXTOOVERLAYMASK(pCredentialList->GetContainerHolderAt(index)->GetIconIndex() +1);
		lvI.iItem = index;
		lvI.iImage = 0;
		lvI.iSubItem = 0;
		lvI.pszText = pCredentialList->GetContainerHolderAt(index)->GetContainer()->GetUserName();
		lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
		lvI.puColumns = ColumnsToDisplay;
		ListView_InsertItem(hWndListView, &lvI);
	}
	
	ListView_SetItemState(hWndListView, dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
	ListView_Update(hWndListView, dwCurrentCredential);
	return TRUE;
}

//  Creates a new icon as a copy of the passed-in icon, overlayed with a shortcut image. 

#define DEBUGH(hbitmap) if( OpenClipboard ( NULL ) ) \
{\
EmptyClipboard();\
SetClipboardData(CF_BITMAP,hbitmap);\
CloseClipboard();\
}
HWND hWndTemp;

HICON MiniIcon(HICON SourceIcon)
{	
	ICONINFO SourceIconInfo,  TargetIconInfo ;
	HICON TargetIcon = NULL;
	BITMAP SourceBitmapInfo;
	HDC SourceDC = NULL,
	  TargetDC = NULL,
	  ScreenDC = NULL;
	HBITMAP OldSourceBitmap = NULL,
	  OldTargetBitmap = NULL;
	HMODULE hDll = NULL;
	__try
	{
		/* Get information about the source icon and shortcut overlay */
		if (! GetIconInfo(SourceIcon, &SourceIconInfo)
			|| 0 == GetObjectW(SourceIconInfo.hbmColor, sizeof(BITMAP), &SourceBitmapInfo))
		{
		  __leave;
		}

		/* search for the shortcut icon only once */
		

		TargetIconInfo = SourceIconInfo;
		TargetIconInfo.hbmMask = NULL;
		TargetIconInfo.hbmColor = NULL;

		/* Setup the source, shortcut and target masks */
		SourceDC = CreateCompatibleDC(NULL);
		if (NULL == SourceDC) __leave;
		OldSourceBitmap = (HBITMAP) SelectObject(SourceDC, SourceIconInfo.hbmMask);
		if (NULL == OldSourceBitmap) __leave;

		TargetDC = CreateCompatibleDC(NULL);
		if (NULL == TargetDC) __leave;
		TargetIconInfo.hbmMask = CreateCompatibleBitmap(TargetDC, GetSystemMetrics(SM_CXICON),
														GetSystemMetrics(SM_CYICON));
		if (NULL == TargetIconInfo.hbmMask) __leave;
		ScreenDC = GetDC(NULL);
		if (NULL == ScreenDC) __leave;
		TargetIconInfo.hbmColor = CreateCompatibleBitmap(ScreenDC, GetSystemMetrics(SM_CXICON),
														 GetSystemMetrics(SM_CYICON));
		ReleaseDC(NULL, ScreenDC);
		if (NULL == TargetIconInfo.hbmColor) __leave;
		OldTargetBitmap = (HBITMAP) SelectObject(TargetDC, TargetIconInfo.hbmMask);
		if (NULL == OldTargetBitmap) __leave;

		/* Create the target mask by ANDing the source and shortcut masks */
		if (! BitBlt(TargetDC, 0, 0, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
					 SourceDC, 0, 0, WHITENESS))
		{
			__leave;
		}
		if (! BitBlt(TargetDC, 0, GetSystemMetrics(SM_CYICON) - SourceBitmapInfo.bmHeight, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
					 SourceDC, 0, 0, SRCCOPY))
		{
			__leave;
		}
		if (NULL == SelectObject(SourceDC, SourceIconInfo.hbmColor) ||
			NULL == SelectObject(TargetDC, TargetIconInfo.hbmColor))
		{
		  __leave;
		}
		

		if (! BitBlt(TargetDC, 0, GetSystemMetrics(SM_CYICON) - SourceBitmapInfo.bmHeight, SourceBitmapInfo.bmWidth, SourceBitmapInfo.bmHeight,
					 SourceDC, 0, 0, SRCCOPY))
		{
			__leave;
		}
		/* Create the icon using the bitmaps prepared earlier */
		TargetIcon = CreateIconIndirect(&TargetIconInfo);
		/* Clean up, we're not goto'ing to 'fail' after this so we can be lazy and not set
		   handles to NULL */
		SelectObject(TargetDC, OldTargetBitmap);
		DeleteObject(TargetDC);

		/* CreateIconIndirect copies the bitmaps, so we can release our bitmaps now */
		DeleteObject(TargetIconInfo.hbmColor);
		DeleteObject(TargetIconInfo.hbmMask);
	}
	__finally
	{
		/* Clean up scratch resources we created */
		if (OldTargetBitmap) 
			SelectObject(TargetDC, OldTargetBitmap);
		if (TargetIconInfo.hbmColor) 
			DeleteObject(TargetIconInfo.hbmColor);
		if (TargetIconInfo.hbmMask) 
			DeleteObject(TargetIconInfo.hbmMask);
		if (TargetDC) 
			DeleteObject(TargetDC);
		if (OldSourceBitmap) 
			SelectObject(SourceDC, OldSourceBitmap);
		if (SourceDC) 
			DeleteObject(SourceDC);
	}
	return TargetIcon;
}

BOOL InitListViewCheckIcon(HWND hWndListView)
{
	HICON hiconItem;     // icon for list-view items 
    HIMAGELIST hLarge;   // image list for icon view 
    HIMAGELIST hSmall;   // image list for other views 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

    hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 
	
    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));

	// Add an icon to each image list.  
	HMODULE hDll = LoadLibrary(TEXT("imageres.dll") );
	//Check if hIcon is valid
	if (hDll)
	{
		// red shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(105)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 
	    
		// yellow shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(107)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 
	    
		// green shield
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(106)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem); 

		// blue circle with a "i" inside
		hiconItem = LoadIcon(hDll, MAKEINTRESOURCE(81)); 
		ImageList_AddIcon(hLarge, hiconItem); 
		ImageList_AddIcon(hSmall, hiconItem); 
		DestroyIcon(hiconItem);
		FreeLibrary(hDll) ;
	}

	// Assign the image lists to the list-view control. 
    ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
    ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
	return TRUE;
}

HICON LoadModIcon(int Num)
{
	HMODULE hDll2 = NULL;
	HRSRC hResInfo = NULL;
	HGLOBAL hGlobal = NULL;
	HRSRC hResInfo2 = NULL;
	HGLOBAL hGlobal2 = NULL;
	int iResourceNum;
	HICON hCertOK = NULL, hOK = NULL;
	HICON hCertNOK = NULL, hNOK = NULL;
	__try
	{
		hDll2 = LoadLibrary(TEXT("imageres.dll") );
		if (!hDll2) __leave;
		hResInfo = FindResource(hDll2,MAKEINTRESOURCE(Num),RT_GROUP_ICON);
		if (!hResInfo) __leave;
		hGlobal = LoadResource(hDll2, hResInfo);
		if (!hGlobal) __leave;
		iResourceNum = LookupIconIdFromDirectoryEx((PBYTE)LockResource(hGlobal), TRUE, 16, 16, 0);
		hResInfo2 = FindResource(hDll2,MAKEINTRESOURCE(iResourceNum),RT_ICON);
		if (!hResInfo2) __leave;
		hGlobal2 = LoadResource(hDll2, hResInfo2);
		if (!hGlobal2) __leave;
		DWORD dwSize = SizeofResource(hDll2,hResInfo2);
		hCertOK = CreateIconFromResourceEx((PBYTE)LockResource(hGlobal2),dwSize,TRUE,0x00030000,0,0,0);
		//Check if hIcon is valid
	}
	__finally
	{
		if (hGlobal) 
			FreeResource(hGlobal);
		if (hGlobal2) 
			FreeResource(hGlobal2);
		if (hDll2)
			FreeLibrary(hDll2) ;
	}
	return hCertOK;
}

BOOL InitListViewListIcon(HWND hWndListView)
{
	HIMAGELIST hLarge;   // image list for icon view 
	HIMAGELIST hSmall;   // image list for icon view 

    // Create the full-sized icon image lists. 

	hLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), 
                              GetSystemMetrics(SM_CYICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

	hSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), 
                              GetSystemMetrics(SM_CYSMICON), 
                               ILC_COLORDDB | ILC_MASK, 3, 3); 

    ImageList_SetBkColor(hLarge, GetSysColor(COLOR_WINDOW));
	ImageList_SetBkColor(hSmall, GetSysColor(COLOR_WINDOW));

	// Add an icon to each image list.  
	HMODULE hDll = LoadLibrary(TEXT("certmgr.dll") );
	if (hDll)
	{
		//Check if hIcon is valid
		HICON hIcon = LoadIcon(hDll, MAKEINTRESOURCE(218));
		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 
		
		DestroyIcon(hIcon ); 
		FreeLibrary(hDll);
	}
	hDll = LoadLibrary(TEXT("imageres.dll") );
	if (hDll)
	{
		HICON hIcon = MiniIcon(LoadModIcon(105));

		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 
		DestroyIcon(hIcon ); 
		hIcon =  MiniIcon(LoadModIcon(106));
		ImageList_AddIcon(hLarge, hIcon ); 
		ImageList_AddIcon(hSmall, hIcon ); 
		DestroyIcon(hIcon ); 
		FreeLibrary(hDll);
	}
	ImageList_SetOverlayImage(hLarge, 1, 1);
	ImageList_SetOverlayImage(hLarge, 2, 2);
	ImageList_SetOverlayImage(hSmall, 1, 1);
	ImageList_SetOverlayImage(hSmall, 2, 2);
	// Assign the image lists to the list-view control. 
    ListView_SetImageList(hWndListView, hLarge, LVSIL_NORMAL); 
	ListView_SetImageList(hWndListView, hSmall, LVSIL_SMALL); 
	
	return TRUE;
}

BOOL InitListViewView(HWND hWndListView)
{
	ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_JUSTIFYCOLUMNS   );
	ListView_EnableGroupView(hWndListView, TRUE);
	return TRUE;
}

void SelectBestCredential()
{
	dwCurrentCredential = 0;
	for (DWORD index = 0; index < pCredentialList->ContainerHolderCount(); index++)
	{
		if (pCredentialList->GetContainerHolderAt(index)->GetIconIndex())
		{
			dwCurrentCredential = index;
			break;
		}
	}
}

#define WM_MYMESSAGE WM_USER + 10
INT_PTR CALLBACK	WndProc_04CHECKS(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	hWndTemp = hWnd;
	NMLVDISPINFO* plvdi = (NMLVDISPINFO*)lParam; 
	switch(message)
	{
	case WM_INITDIALOG:
		InitListViewColumns(GetDlgItem(hWnd, IDC_04CHECKS));
		InitListViewCheckIcon(GetDlgItem(hWnd, IDC_04CHECKS));
		InitListViewListIcon(GetDlgItem(hWnd, IDC_04LIST));
		InitListViewView(GetDlgItem(hWnd, IDC_04CHECKS));
		break;
	case WM_MYMESSAGE:
		if (fHasDeselected)
		{
			ListView_SetItemState(GetDlgItem(hWnd,IDC_04LIST), dwCurrentCredential, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
			ListView_Update(GetDlgItem(hWnd,IDC_04LIST), dwCurrentCredential);
		}
		return TRUE;
		break;
	case WM_NOTIFY :
        LPNMHDR pnmh = (LPNMHDR)lParam;
        switch(pnmh->code)
        {
			case PSN_SETACTIVE :
				// list view
				{
					EIDCardLibraryTrace(WINEVENT_LEVEL_WARNING,L"Activate");
					ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
					ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04LIST));
	
					if (!pCredentialList)
					{
						pCredentialList = new CContainerHolderFactory<CContainerHolderTest>;
						pCredentialList->SetUsageScenario(CPUS_INVALID,0);
						SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_WAIT)));
						pCredentialList->ConnectNotification(szReader,szCard,0);
						SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_ARROW)));
					}
					
					if (pCredentialList->HasContainerHolder())
					{
						//has certificate
						SelectBestCredential();
						PopulateListViewListData(GetDlgItem(hWnd, IDC_04LIST));	
						if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
						{
							PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
						}
						else
						{
							PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						}
					}
					else
					{
						// no certificate
						TCHAR szMessage[256] = TEXT("");
						LoadString(g_hinst,IDS_NO_CERTIFICATE, szMessage, ARRAYSIZE(szMessage));
						LVITEM lvI;
						UINT ColumnsToDisplay[] = {1,2,3};
						// Initialize LVITEM members that are common to all items.
						lvI.mask = LVIF_TEXT | LVIF_IMAGE |  LVIF_COLUMNS; 
						lvI.iItem = 0;
						lvI.iImage = 0;
						lvI.iSubItem = 0;
						lvI.pszText = szMessage;
						lvI.cColumns = ARRAYSIZE(ColumnsToDisplay);
						lvI.puColumns = ColumnsToDisplay;
						ListView_InsertItem(GetDlgItem(hWnd, IDC_04LIST), &lvI);
	
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
					}
				}
				break;
			case PSN_WIZBACK:
				// back
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
				}
				ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
				if (!fShowNewCertificatePanel)
				{
					PropSheet_PressButton(hWnd, PSBTN_BACK);
				}
				break;
			case PSN_RESET:
				// cancel
				if (pCredentialList)
				{
					delete pCredentialList;
					pCredentialList = NULL;
				}
				break;
				
			case LVN_ITEMCHANGED:
				if (pnmh->idFrom == IDC_04LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->uNewState & LVIS_SELECTED )
					{
						if ((DWORD)(((LPNMITEMACTIVATE)lParam)->iItem) < pCredentialList->ContainerHolderCount())
						{
							fHasDeselected = FALSE;
							dwCurrentCredential = ((LPNMITEMACTIVATE)lParam)->iItem;
							PopulateListViewCheckData(GetDlgItem(hWnd, IDC_04LIST),GetDlgItem(hWnd, IDC_04CHECKS));
							if (pCredentialList->GetContainerHolderAt(dwCurrentCredential)->GetIconIndex())
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_NEXT |	PSWIZB_BACK);
							}
							else
							{
								PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
							}
						}
					}
					else
					{
						ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						fHasDeselected = TRUE;
						PostMessage(hWnd, WM_MYMESSAGE, 0, 0);
					}
				}
				break;
			case NM_DBLCLK:
				if (pnmh->idFrom == IDC_04LIST && pCredentialList)
				{
					if (((LPNMITEMACTIVATE)lParam)->iItem >= 0 && (DWORD)((LPNMITEMACTIVATE)lParam)->iItem < pCredentialList->ContainerHolderCount())
					{
						pCredentialList->GetContainerHolderAt(((LPNMITEMACTIVATE)lParam)->iItem)->GetContainer()->ViewCertificate(hWnd);
					}
				}
				break;
			case LVN_LINKCLICK:
				if (pnmh->idFrom == IDC_04CHECKS && pCredentialList)	
				{
					BOOL fReturn;
					fReturn = pCredentialList->GetContainerHolderAt(dwCurrentCredential)->Solve(((NMLVLINK*)lParam)->iSubItem);
					if (!fReturn)
					{
						MessageBoxWin32Ex(GetLastError(),hWnd);
					}
					else
					{
						// refresh
						NMLINK nmh;
						LITEM item;
						nmh.hdr.code = NM_CLICK;
						nmh.hdr.hwndFrom = hWnd;
						nmh.hdr.idFrom = IDC_04CHECKS;
						memset(&item,0,sizeof(LITEM));
						nmh.item = item;
						wcscpy_s(nmh.item.szID,MAX_LINKID_TEXT,L"idrefresh");
						SendMessage(hWnd,WM_NOTIFY,0,(LPARAM)&nmh);
					}
				}
				break;
			case NM_CLICK:
			case NM_RETURN:
				{
					PNMLINK pNMLink = (PNMLINK)lParam;
					LITEM item = pNMLink->item;
					if (wcscmp(item.szID, L"idrefresh") == 0)
					{
						// clear all data
						PropSheet_SetWizButtons(hWnd, PSWIZB_BACK);
						pCredentialList->DisconnectNotification(szReader);
						dwCurrentCredential = 0xFFFFFFFF;
						ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04LIST));
						ListView_DeleteAllItems(GetDlgItem(hWnd, IDC_04CHECKS));
						if (AskForCard(szReader,dwReaderSize,szCard,dwCardSize))
						{
							NMHDR nmh;
							nmh.code = PSN_SETACTIVE;
							SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_WAIT)));
							pCredentialList->ConnectNotification(szReader,szCard,0);
							SetCursor(LoadCursor(NULL,MAKEINTRESOURCE(IDC_ARROW)));
							SendMessage(hWnd, WM_NOTIFY, 0, (LPARAM)&nmh);
						}
						else
						{
							LONG lReturn = GetLastError();
							if (lReturn != SCARD_W_CANCELLED_BY_USER)
							{
								MessageBoxWin32Ex(lReturn,hWnd);
							}
						}
					}
				}
		}
    }
	return FALSE;
}