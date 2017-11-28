#include "PE.h"
#include "resource.h"
#include "Operate_PE.h"

HINSTANCE hInstApp;
TCHAR pszPeFileName[MAX_PATH] = { 0 };		// This is for PE resolver !
TCHAR pszPacker[MAX_PATH] = { 0 };
TCHAR pszSrc[MAX_PATH] = { 0 };
LPVOID lpFileBuffer = NULL;
DWORD nDetailType;

int CALLBACK WinMain(
	_In_ HINSTANCE hInstance,
	_In_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nCmdShow
)
{
	hInstApp = hInstance;
	UpdateProcessPrivilege(hInstance);
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), NULL, DialogMainProc);

	return EXIT_SUCCESS;
}

BOOL CALLBACK DialogMainProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	switch (uMsg)
	{
	case WM_INITDIALOG: {
		HICON hIcon = LoadIcon(hInstApp, MAKEINTRESOURCE(IDI_ICON1));
		SendMessage(hwnd, WM_SETICON, ICON_BIG, (DWORD)hIcon);
		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (DWORD)hIcon);
		InitProcessListView(hwnd);
		InitModuleListView(hwnd);
		return TRUE;
	}

	case WM_NOTIFY: {
		switch (LOWORD(wParam))
		{
		case IDC_LIST_PROCESSES: {
			if (((NMHDR *)lParam)->code == NM_CLICK)
			{
				SetModuleList(((NMHDR *)lParam)->hwndFrom, GetDlgItem(hwnd, IDC_LIST_MODULES));
				return TRUE;
			}

		default:
			return FALSE;
		}
		}
	}

	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		return TRUE;
	}

	case WM_COMMAND: {
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_EXIT: {
			EndDialog(hwnd, 0);
			return TRUE;
		}

		case IDC_BUTTON_ABOUT: {
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_ABOUT), hwnd, DialogAboutProc);
			return TRUE;
		}
		case IDC_BUTTON_PE: {
			OPENFILENAME stFile;
			TCHAR szPeFormat[] = TEXT("PE Files(EXE)\0*.exe;*.dll;*.scr;*.drv;*.sys\0All Files(*.*)\0*.*\0\0");
			memset(&stFile, 0, sizeof(OPENFILENAME));
			stFile.lStructSize = sizeof(OPENFILENAME);
			stFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			stFile.hwndOwner = hwnd;
			stFile.lpstrFilter = szPeFormat;
			stFile.lpstrFile = pszPeFileName;		// 靠全局变量了 ！！
			stFile.nMaxFile = MAX_PATH;

			GetOpenFileName(&stFile);
		
			// THIS ONE!
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_PE), hwnd, DialogPEProc);
			return TRUE;
			// PE this !
		}

		case IDC_BUTTON_PACKER: {
			OPENFILENAME stPacker = { 0 };
			OPENFILENAME stSrc = { 0 };
			TCHAR tPackerFormat[] = TEXT("PE Files(EXE)\0*.exe;*.dll;*.scr;*.drv;*.sys\0\0");
			TCHAR tSrcFormat[] = TEXT("Execution Files(EXE)\0*.exe\0\0");

			stPacker.lStructSize = stSrc.lStructSize = sizeof(OPENFILENAME);
			stSrc.Flags = stPacker.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			stSrc.hwndOwner = stPacker.hwndOwner = hwnd;

			stPacker.lpstrCustomFilter = tSrcFormat;
			stSrc.lpstrCustomFilter = tPackerFormat;

			stPacker.nMaxFile = stSrc.nMaxFile = MAX_PATH;

			stPacker.lpstrFile = pszPacker;
			stSrc.lpstrFile = pszSrc;

			GetOpenFileName(&stPacker);
			GetOpenFileName(&stSrc);

			MessageBox(hwnd, pszPacker, NULL, NULL);
			MessageBox(hwnd, pszSrc, NULL, NULL);

			return TRUE;
		}

		default:
			return FALSE;
		}
	}

	default:
		return FALSE;
	}
	
}

BOOL CALLBACK DialogAboutProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
)
{
	switch (uMsg)
	{
	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		return TRUE;
	}
	case WM_COMMAND: {
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_ABOUT_EXIT: {
			EndDialog(hwnd, 0);
			return TRUE;
		}

		default:
			return FALSE;
		}
	}
	default:
		return FALSE;
	}
}

VOID InitProcessListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListProcess;

	memset(&lv, 0, sizeof(lv));
	hListProcess = GetDlgItem(hDlg, IDC_LIST_PROCESSES);

	SendMessage(hListProcess, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	lv.pszText = TEXT("进程");
	lv.cx = 200;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess, 0, &lv);

	lv.pszText = TEXT("PID");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess, 1, &lv);

	lv.pszText = TEXT("镜像基址");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess, 2, &lv);

	lv.pszText = TEXT("镜像大小");
	lv.cx = 100;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess, 3, &lv);

	SetProcessList(hListProcess);
}

VOID InitModuleListView(HWND hDlg)
{
	LV_COLUMN lv;
	HWND hListModule;

	memset(&lv, 0, sizeof(lv));
	hListModule = GetDlgItem(hDlg, IDC_LIST_MODULES);

	//SendMessage(hListModule, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);

	lv.mask = LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	lv.pszText = TEXT("模块名称");
	lv.cx = 200;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListModule, 0, &lv);

	lv.pszText = TEXT("模块位置");
	lv.cx = 300;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListModule, 1, &lv);

	SetModuleList(hListModule, hListModule);
}

VOID InitSectionListView(HWND hDlg)
{
	LV_COLUMN lv = { 0 };
	HWND hListSection = GetDlgItem(hDlg, IDC_LIST_SECTIONS);

	SendMessage(hListSection, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	lv.mask = LVCF_SUBITEM | LVCF_WIDTH | LVCF_TEXT;

	lv.pszText = TEXT("节名");
	lv.cx = 150;
	lv.iSubItem = 0;
	ListView_InsertColumn(hListSection, 0, &lv);

	lv.pszText = TEXT("节偏移");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListSection, 1, &lv);

	lv.pszText = TEXT("节大小");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListSection, 2, &lv);

	lv.pszText = TEXT("内存偏移");
	lv.cx = 100;
	lv.iSubItem = 3;
	ListView_InsertColumn(hListSection, 3, &lv);

	lv.pszText = TEXT("内存大小");
	lv.cx = 100;
	lv.iSubItem = 4;
	ListView_InsertColumn(hListSection, 4, &lv);

	lv.pszText = TEXT("节区属性");
	lv.cx = 100;
	lv.iSubItem = 5;
	ListView_InsertColumn(hListSection, 5, &lv);
}

VOID SetProcessList(HWND hListProcess)
{
	LV_ITEM vitem;
	memset(&vitem, 0, sizeof(vitem));
	vitem.mask = LVIF_TEXT;

	DWORD ProcessId[MAX_NUM];
	DWORD cbNeeded;
	DWORD processcount;
	//TCHAR szProcessName[MAX_NUM];
	TCHAR buffer[MAX_NUM];
	memset(buffer, 0, sizeof(buffer));

	if (!EnumProcesses(ProcessId, sizeof(ProcessId), &cbNeeded))
	{
		OutputDebugString(TEXT("Get Process Wrong!\n"));
		return;
	}

	processcount = cbNeeded / sizeof(DWORD);
	
	HANDLE hProcess;
	HMODULE hMods[MAX_NUM];
	PROCESS_MEMORY_COUNTERS pmc;
	DWORD nShowN = 0;

	for (DWORD i = 0; i < processcount; i++)
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessId[i]);
		if (hProcess)
		{
			if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
			{
				GetModuleBaseName(hProcess, hMods[0], buffer, MAX_NUM);
				vitem.pszText = buffer;
				vitem.iItem = nShowN;
				vitem.iSubItem = 0;
				ListView_InsertItem(hListProcess, &vitem);

				_itow_s(ProcessId[i], buffer, 10);
				vitem.pszText = buffer;
				vitem.iSubItem = 1;
				ListView_SetItem(hListProcess, &vitem);

				_itow_s((DWORD)hMods[0], buffer, 16);
				vitem.pszText = buffer;
				vitem.iSubItem = 2;
				ListView_SetItem(hListProcess, &vitem);

				if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
				{
					_itow_s(pmc.WorkingSetSize, buffer, 10);
					vitem.pszText = buffer;
					vitem.iSubItem = 3;
					ListView_SetItem(hListProcess, &vitem);
				}

				nShowN++;
			}
		}

		CloseHandle(hProcess);
	}
}

VOID SetModuleList(HWND hListProcess, HWND hListModule)
{
	
	DWORD dwRowId;
	TCHAR buffer[MAX_NUM];
	DWORD dwPid;
	LV_ITEM vitem;

	memset(&vitem, 0, sizeof(vitem));
	memset(buffer, 0, sizeof(buffer));

	dwRowId = SendMessage(hListProcess, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
	if (dwRowId == -1)
	{
	OutputDebugString(L"请选择进程！");
	return;
	}

	ListView_GetItemText(hListProcess, dwRowId, 1, buffer, MAX_NUM);
	dwPid = _wtoi(buffer);

	HMODULE hMods[MAX_NUM];
	DWORD cbNeeded;
	DWORD modulecount;

	//set this
	vitem.mask = LVIF_TEXT;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
	if (hProcess)
	{
	if (EnumProcessModules(hProcess, hMods, MAX_NUM, &cbNeeded))
	{
	modulecount = cbNeeded / sizeof(DWORD);
	for (DWORD i = 0; i < modulecount; i++)
	{
	if (GetModuleBaseName(hProcess, hMods[i], buffer, MAX_NUM))
	{
	vitem.pszText = buffer;
	vitem.iItem = i;
	vitem.iSubItem = 0;
	ListView_InsertItem(hListModule, &vitem);
	}

	if (GetModuleFileName(hMods[i], buffer, MAX_NUM))
	{
	vitem.pszText = buffer;
	vitem.iItem = i;
	vitem.iSubItem = 1;
	ListView_SetItem(hListModule, &vitem);
	}
	}
	}
	}
}

VOID ParsePE(HWND parhwnd, LPCTSTR stPeFile)
{
	
}

BOOL UpdateProcessPrivilege(HANDLE hProcess, LPCTSTR lpPrivilegeName)
{
	HANDLE hToken;
	int iResult;
	TOKEN_PRIVILEGES TokenPrivileges;

	if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		LUID destLuid;
		if (LookupPrivilegeValue(NULL, lpPrivilegeName, &destLuid))
		{
			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			TokenPrivileges.Privileges[0].Luid = destLuid;

			if (iResult = AdjustTokenPrivileges(hToken, FALSE,
				&TokenPrivileges, 0, NULL, NULL)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

BOOL CALLBACK DialogPEProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG: {
		if (_tcscmp(pszPeFileName, TEXT("")) == 0)
		{
			EndDialog(hwnd, 0);
			return TRUE;
		}

		if (!ReadPEFile(pszPeFileName, &lpFileBuffer))
		{
			MessageBox(hwnd, TEXT("无法打开指定的文件！"),TEXT("错误"), NULL);
			EndDialog(hwnd, 0);
			return TRUE;
		}

		ResolveHeader(lpFileBuffer, hwnd);
		return TRUE;
	}

	case WM_CLOSE: {
		free(lpFileBuffer);
		memset(pszPeFileName, 0, MAX_NUM * sizeof(TCHAR));
		EndDialog(hwnd, 0);
		return TRUE;
	}

	case WM_COMMAND: {
		switch (wParam)
		{
		case IDC_BUTTON_PE_EXIT: {
			free(lpFileBuffer);
			memset(pszPeFileName, 0, MAX_NUM * sizeof(TCHAR));
			EndDialog(hwnd, 0);
			return TRUE;
		}

		case IDC_BUTTON_PE_DIR: {
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DIR), hwnd, DialogDirectoryProc);
			return TRUE;
		}

		case IDC_BUTTON_PE_SECTION: {
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_SECTIONS), hwnd, DialogSectionProc);
		}

		default:
			return FALSE;
		}
	}

	default:
		return FALSE;
	}
}

BOOL CALLBACK DialogSectionProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	LPVOID FileBuffer = NULL;
	switch (uMsg)
	{
	case WM_INITDIALOG: {
		InitSectionListView(hwnd);

		if (!ReadPEFile(pszPeFileName, &FileBuffer))
		{
			MessageBox(hwnd, TEXT("无法打开指定的文件！"), TEXT("错误"), NULL);
			EndDialog(hwnd, 0);
			return TRUE;
		}

		ResolveSection(FileBuffer, GetDlgItem(hwnd, IDC_LIST_SECTIONS));
		free(FileBuffer);
		return TRUE;
	}

	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		return TRUE;
	}

	default:
		return FALSE;

	}
}

BOOL CALLBACK DialogDirectoryProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG: {
		nDetailType = 0;
	
		if (lpFileBuffer == NULL)
			return TRUE;

		ResolveDirectory(lpFileBuffer, hwnd);
		return TRUE;
	}

	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		return TRUE;
	}

	case WM_COMMAND: {
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON_DIR_EXIT: {
			EndDialog(hwnd, 0);
			return TRUE;
		}

		case IDC_BUTTON_ExportDetail: {
			nDetailType = 0;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		case IDC_BUTTON_ImportDetail: {
			nDetailType = 1;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		case IDC_BUTTON_ResourceDetail: {
			nDetailType = 2;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		case IDC_BUTTON_RelocatioDetail: {
			nDetailType = 5;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		case IDC_BUTTON_BoundDetail: {
			nDetailType = 0xB;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		case IDC_BUTTON_IATDetail: {
			nDetailType = 0xC;
			DialogBox(hInstApp, MAKEINTRESOURCE(IDD_DIALOG_DETAILS), hwnd, DialogDetailProc);
			return TRUE;
		}

		default:
			return FALSE;
		}
	}

	default:
		return FALSE;
	}
}

BOOL CALLBACK DialogDetailProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG: {
		if (lpFileBuffer == NULL)
			return TRUE;

		ResolveDetails(lpFileBuffer, GetDlgItem(hwnd, IDC_EDIT_DETAIL), nDetailType);
		return TRUE;
	}

	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		return TRUE;
	}

	default:
		return FALSE;
	}
}
