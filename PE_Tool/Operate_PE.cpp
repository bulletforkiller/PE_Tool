#include "Operate_PE.h"

DWORD ReadPEFile(IN LPTSTR peFile, OUT LPVOID * FileBuffer)
{
	if (!peFile)
		return FALSE;

	FILE * pFile = NULL;
	size_t sFileSize = 0;
	DWORD n;

	_tfopen_s(&pFile, peFile, TEXT("rb"));
	if (!pFile) {
		perror("Can't open the file!");
		fclose(pFile);
		return FALSE;
	}

	fseek(pFile, 0, SEEK_END);
	sFileSize = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	if (!(*FileBuffer = malloc(sFileSize)))
	{
		perror("Can't allocate the memory!");
		fclose(pFile);
		return FALSE;
	}

	if (!(n = fread(*FileBuffer, 1, sFileSize, pFile)))
	{
		perror("Can't read from the file!");
		fclose(pFile);
		free(*FileBuffer);
	}

	fclose(pFile);
	return sFileSize;
}

DWORD WriteBack(LPTSTR Name, LPVOID FileBuffer, size_t size)
{
	FILE *fptr = NULL;
	_tfopen_s(&fptr, Name, TEXT("wb"));
	if (!fptr) {
		perror("Can't open the file to write in!\n");
		fclose(fptr);
		return FALSE;
	}

	if (!(fwrite(FileBuffer, 1, size, fptr)))
	{
		perror("内容写入失败！");
		fclose(fptr);
		return NULL;
	}

	fclose(fptr);
	return size;
}

DWORD ResolveHeader(IN LPVOID FileBuffer, IN HWND hDlg)
{
	if (!FileBuffer)
		return FALSE;

	TCHAR buffer[MAX_SIZE];

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = &pNTHeader->FileHeader;
	pOptionHeader = &pNTHeader->OptionalHeader;

	HWND hEntryPoint = GetDlgItem(hDlg, IDC_EDIT_EntryPoint);
	HWND hImageBase = GetDlgItem(hDlg, IDC_EDIT_ImageBase);
	HWND hImageSize = GetDlgItem(hDlg, IDC_EDIT_ImageSize);
	HWND hBaseOfCode = GetDlgItem(hDlg, IDC_EDIT_BaseOfCode);
	HWND hBaseOfData = GetDlgItem(hDlg, IDC_EDIT_BaseOfData);
	HWND hSectionAlign = GetDlgItem(hDlg, IDC_EDIT_SectionAlign);;
	HWND hFileAlign = GetDlgItem(hDlg, IDC_EDIT_FileAlign);
	HWND hSign = GetDlgItem(hDlg, IDC_EDIT_Sign);
	
	HWND hSubSystem = GetDlgItem(hDlg, IDC_EDIT_SubSystem);
	HWND hNumOfSections = GetDlgItem(hDlg, IDC_EDIT_NumOfSections);
	HWND hTimeStamp = GetDlgItem(hDlg, IDC_EDIT_TimeStamp);
	HWND hSizeOfHeader = GetDlgItem(hDlg, IDC_EDIT_SizeOfHeader);
	HWND hCharacters = GetDlgItem(hDlg, IDC_EDIT_Characters);
	HWND hCheckSum = GetDlgItem(hDlg, IDC_EDIT_CheckSum);
	HWND hSizeOfOpt = GetDlgItem(hDlg, IDC_EDIT_SizeOfOpt);
	HWND hNumOfDir = GetDlgItem(hDlg, IDC_EDIT_NumOfDir);

	_itow_s(pOptionHeader->AddressOfEntryPoint, buffer, 16);
	SetWindowText(hEntryPoint, buffer);

	_itow_s(pOptionHeader->ImageBase, buffer, 16);
	SetWindowText(hImageBase, buffer);

	_itow_s(pOptionHeader->SizeOfImage, buffer, 16);
	SetWindowText(hImageSize, buffer);

	_itow_s(pOptionHeader->BaseOfCode, buffer, 16);
	SetWindowText(hBaseOfCode, buffer);

	_itow_s(pOptionHeader->BaseOfData, buffer, 16);
	SetWindowText(hBaseOfData, buffer);

	_itow_s(pOptionHeader->SectionAlignment, buffer, 16);
	SetWindowText(hSectionAlign, buffer);

	_itow_s(pOptionHeader->FileAlignment, buffer, 16);
	SetWindowText(hFileAlign, buffer);

	_itow_s(pNTHeader->Signature, buffer, 16);
	SetWindowText(hSign, buffer);

	_itow_s(pOptionHeader->Subsystem, buffer, 16);
	SetWindowText(hSubSystem, buffer);

	_itow_s(pFileHeader->NumberOfSections, buffer, 16);
	SetWindowText(hNumOfSections, buffer);

	_itow_s(pFileHeader->TimeDateStamp, buffer, 16);
	SetWindowText(hTimeStamp, buffer);

	_itow_s(pFileHeader->Characteristics, buffer, 16);
	SetWindowText(hCharacters, buffer);
	
	_itow_s(pOptionHeader->CheckSum, buffer, 16);
	SetWindowText(hCheckSum, buffer);

	_itow_s(pOptionHeader->SizeOfHeaders, buffer, 16);
	SetWindowText(hSizeOfHeader, buffer);

	_itow_s(pOptionHeader->NumberOfRvaAndSizes, buffer, 16);
	SetWindowText(hNumOfDir, buffer);

	_itow_s(pFileHeader->SizeOfOptionalHeader, buffer, 16);
	SetWindowText(hSizeOfOpt, buffer);
	
	return TRUE;
}

DWORD ResolveSection(IN LPVOID FileBuffer, IN HWND hListSection)
{
	if (!FileBuffer)
		return FALSE;

	TCHAR buffer[MAX_SIZE];

	LV_ITEM vitem = { 0 };
	vitem.mask = LVIF_TEXT;

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = &pNTHeader->FileHeader;
	pOptionHeader = &pNTHeader->OptionalHeader;

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pFileHeader->SizeOfOptionalHeader);
	for (DWORD i = 0; i < pFileHeader->NumberOfSections; i++)
	{
#ifdef UNICODE
		MultiByteToWideChar(CP_ACP, 0, (char*)pSectionHeader->Name, -1, buffer, MAX_SIZE);
#else
		strcpy_s(buffer, pSectionHeader->Name);
#endif

		vitem.pszText = buffer;
		vitem.iItem = i;
		vitem.iSubItem = 0;
		ListView_InsertItem(hListSection, &vitem);

		_itow_s(pSectionHeader->PointerToRawData, buffer, 16);
		vitem.pszText = buffer;
		vitem.iSubItem = 1;
		ListView_SetItem(hListSection, &vitem);

		_itow_s(pSectionHeader->SizeOfRawData, buffer, 16);
		vitem.pszText = buffer;
		vitem.iSubItem = 2;
		ListView_SetItem(hListSection, &vitem);

		_itow_s(pSectionHeader->VirtualAddress, buffer, 16);
		vitem.pszText = buffer;
		vitem.iSubItem = 3;
		ListView_SetItem(hListSection, &vitem);

		
		if (i == pFileHeader->NumberOfSections - 1)
			_itow_s(pOptionHeader->SizeOfImage - pSectionHeader->VirtualAddress, buffer, 16);
		else
			_itow_s((pSectionHeader + 1)->VirtualAddress - pSectionHeader->VirtualAddress, buffer, 16);

		vitem.pszText = buffer;
		vitem.iSubItem = 4;
		ListView_SetItem(hListSection, &vitem);

		
		_itow_s(pSectionHeader->Characteristics, buffer, 16);
		vitem.pszText = buffer;
		vitem.iSubItem = 5;
		ListView_SetItem(hListSection, &vitem);

		// At the end change the sectionheader
		pSectionHeader += 1;
	}
	return TRUE;
}

DWORD ResolveDirectory(IN LPVOID FileBuffer, IN HWND hDlg)
{
	if (!FileBuffer)
		return FALSE;

	TCHAR buffer[20] = { 0 };

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = &pNTHeader->FileHeader;
	pOptionalHeader = &pNTHeader->OptionalHeader;

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)(&pOptionalHeader->NumberOfRvaAndSizes) + 4);

	HWND hExportTableR = GetDlgItem(hDlg, IDC_EDIT_Export_R);
	HWND hExportTableS = GetDlgItem(hDlg, IDC_EDIT_Export_S);
	HWND hImportTableR = GetDlgItem(hDlg, IDC_EDIT_Import_R);
	HWND hImportTableS = GetDlgItem(hDlg, IDC_EDIT_Import_S);
	HWND hResourceR = GetDlgItem(hDlg, IDC_EDIT_Resource_R);
	HWND hResourceS = GetDlgItem(hDlg, IDC_EDIT_Resource_S);
	HWND hExceptionR = GetDlgItem(hDlg, IDC_EDIT_Exception_R);
	HWND hExceptionS = GetDlgItem(hDlg, IDC_EDIT_Exception_S);
	HWND hSecurityR = GetDlgItem(hDlg, IDC_EDIT_Security_R);
	HWND hSecurityS = GetDlgItem(hDlg, IDC_EDIT_Security_S);
	HWND hRelocationR = GetDlgItem(hDlg, IDC_EDIT_Relocation_R);
	HWND hRelocationS = GetDlgItem(hDlg, IDC_EDIT_Relocation_S);
	HWND hDebugR = GetDlgItem(hDlg, IDC_EDIT_Debug_R);
	HWND hDebugS = GetDlgItem(hDlg, IDC_EDIT_Debug_S);
	HWND hCopyrightR = GetDlgItem(hDlg, IDC_EDIT_Copyright_R);
	HWND hCopyrightS = GetDlgItem(hDlg, IDC_EDIT_Copyright_S);
	HWND hGlobalR = GetDlgItem(hDlg, IDC_EDIT_Globalptr_R);
	HWND hGlobalS = GetDlgItem(hDlg, IDC_EDIT_Global_S);
	HWND hTlsR = GetDlgItem(hDlg, IDC_EDIT_Tls_R);
	HWND hTlsS = GetDlgItem(hDlg, IDC_EDIT_Tls_S);
	HWND hLoadConfigR = GetDlgItem(hDlg, IDC_EDIT_LoadConfig_R);
	HWND hLoadConfigS = GetDlgItem(hDlg, IDC_EDIT_LoadConfig_S);
	HWND hBoundImportR = GetDlgItem(hDlg, IDC_EDIT_BoundImport_R);
	HWND hBoundImportS = GetDlgItem(hDlg, IDC_EDIT_BoundImport_S);
	HWND hIATR = GetDlgItem(hDlg, IDC_EDIT_IAT_R);
	HWND hIATS = GetDlgItem(hDlg, IDC_EDIT_IAT_S);
	HWND hDelayImportR = GetDlgItem(hDlg, IDC_EDIT_DelayImport_R);
	HWND hDelayImportS = GetDlgItem(hDlg, IDC_EDIT_DelayImport_S);
	HWND hCOMR = GetDlgItem(hDlg, IDC_EDIT_COM_R);
	HWND hCOMS = GetDlgItem(hDlg, IDC_EDIT_COM_S);
	HWND hReservedR = GetDlgItem(hDlg, IDC_EDIT_Reserved_R);
	HWND hReservedS = GetDlgItem(hDlg, IDC_EDIT_Reversed_S);

	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hExportTableR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hExportTableS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hImportTableR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hImportTableS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hResourceR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hResourceS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hExceptionR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hExceptionS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hSecurityR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hSecurityS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hRelocationR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hRelocationS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hDebugR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hDebugS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hCopyrightR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hCopyrightS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hGlobalR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hGlobalS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hTlsR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hTlsS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hLoadConfigR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hLoadConfigS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hBoundImportR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hBoundImportS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hIATR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hIATS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hDelayImportR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hDelayImportS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hCOMR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hCOMS, buffer);

	pDataDirectory++;
	_itow_s(pDataDirectory->VirtualAddress, buffer, 16);
	SetWindowText(hReservedR, buffer);
	_itow_s(pDataDirectory->Size, buffer, 16);
	SetWindowText(hReservedS, buffer);

	return TRUE;
}

DWORD ResolveDetails(IN LPVOID FileBuffer, IN HWND hText, DWORD nDetailType)
{
	if (!FileBuffer)
		return FALSE;

	TCHAR buffer[MAX_STR_LEN] = { 0 };

	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = &pNTHeaders->FileHeader;
	pOptionalHeader = &pNTHeaders->OptionalHeader;
	pDataDirectory = (PIMAGE_DATA_DIRECTORY)((DWORD)&pOptionalHeader->NumberOfRvaAndSizes + 4);

	switch (nDetailType)
	{
	case 0: {
		//导出表:
		ResolveExport(FileBuffer, pDataDirectory, hText);
		break;
	}

	case 1: {
		//导入表：
		ResolveImport(FileBuffer, pDataDirectory + 1, hText);
		break;
	}

	case 2: {
		//资源表：
		ResolveResource(FileBuffer, pDataDirectory + 2, hText);
		break;
	}

	case 5: {
		//重定位表
		ResolveRelocation(FileBuffer, pDataDirectory + 5, hText);
		break;
	}

	case 0xB: {
		//绑定导入表
		ResolveBound(FileBuffer, pDataDirectory + 0xB, hText);
		break;
	}

	case 0xC: {
		//IAT表
		ResolveIAT(FileBuffer, pDataDirectory + 0xC, hText);
		break;
	}
	}

	return TRUE;
}

DWORD ResolveExport(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };

	if (pData->VirtualAddress == 0 && pData->Size == 0)
		return FALSE;

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);
	_tcscpy_s(buffer, TEXT("********************导出表*********************\n"));
	SetWindowText(hText, buffer);

	_tcscpy_s(buffer, TEXT("Characteristics:\t "));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	_itot_s(pExportDirectory->Characteristics, buffer, 16);
	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	_tcscpy_s(buffer, TEXT("TimeDateStamp:\t "));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	_itot_s(pExportDirectory->TimeDateStamp, buffer, 16);
	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	_tcscpy_s(buffer, TEXT("Name:\t "));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	MultiByteToWideChar(CP_ACP, 0, (char*)(RVAtoFOA(FileBuffer, pExportDirectory->Name) + (DWORD)FileBuffer), -1, buffer, MAX_STR_LEN);

	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	_tcscpy_s(buffer, TEXT("Base:\t"));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	_itot_s(pExportDirectory->Base, buffer, 16);
	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	_tcscpy_s(buffer, TEXT("NumbersOfFunctions:\t"));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	_itot_s(pExportDirectory->NumberOfFunctions, buffer, 16);
	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	_tcscpy_s(buffer, TEXT("NumbersOfNames:\t"));
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	_itow_s(pExportDirectory->NumberOfNames, buffer, 16);
	buffer[wcslen(buffer) + 1] = TEXT('\0');
	buffer[wcslen(buffer)] = TEXT('\n');
	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)TEXT("\n"));

	PDWORD location = (PDWORD)(RVAtoFOA(FileBuffer, pExportDirectory->AddressOfFunctions) + (DWORD)FileBuffer);
	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{
		_tcscpy_s(buffer, TEXT("RVA to functions:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		_itot_s(location[i], buffer, 16);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	}

	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)TEXT("\n"));

	location = (PDWORD)(RVAtoFOA(FileBuffer, pExportDirectory->AddressOfNames) + (DWORD)FileBuffer);
	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{
		_tcscpy_s(buffer, TEXT("The name is:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		MultiByteToWideChar(CP_ACP, 0, (char*)(RVAtoFOA(FileBuffer, location[i]) + (DWORD)FileBuffer), -1, buffer, MAX_STR_LEN);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	}

	SendMessage(hText, EM_SETSEL, -2, -1);
	SendMessage(hText, EM_REPLACESEL, 0, (DWORD)TEXT("\n"));

	location = (PDWORD)(RVAtoFOA(FileBuffer, pExportDirectory->AddressOfNameOrdinals) + (DWORD)FileBuffer);
	for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++)
	{
		_tcscpy_s(buffer, TEXT("The name of ordinal is:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		_itot_s(location[i] + pExportDirectory->Base, buffer, 16);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	}

	return TRUE;
}

DWORD ResolveImport(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };

	if (pData->Size == 0 && pData->VirtualAddress == 0)
		return FALSE;

	_tcscpy_s(buffer, TEXT("********************导入表*********************\n"));
	SetWindowText(hText, buffer);

	PIMAGE_IMPORT_DESCRIPTOR pImportDirectory = NULL;
	PDWORD pOriginalFirstThunk = NULL;
	PDWORD pFirstThunk = NULL;
	PIMAGE_IMPORT_BY_NAME pImportName = NULL;

	pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);
	while (pImportDirectory->Name != NULL)
	{
		_tcscpy_s(buffer, TEXT("Name:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		MultiByteToWideChar(CP_ACP, 0, (char*)(RVAtoFOA(FileBuffer, pImportDirectory->Name) + (DWORD)FileBuffer), -1, buffer, MAX_STR_LEN);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		// Let's start the real work !!!

		_tcscpy_s(buffer, TEXT("The OriginalsFirstThunk:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		pOriginalFirstThunk = (PDWORD)(RVAtoFOA(FileBuffer, pImportDirectory->OriginalFirstThunk) + (DWORD)FileBuffer);
		while (*pOriginalFirstThunk)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(*pOriginalFirstThunk)) {
				_tcscpy_s(buffer, TEXT("The Ordinals is:\t"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
				_itot_s(IMAGE_ORDINAL32(*pOriginalFirstThunk), buffer, 10);
				buffer[wcslen(buffer) + 1] = TEXT('\0');
				buffer[wcslen(buffer)] = TEXT('\n');
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
			}

			else
			{
				_tcscpy_s(buffer, TEXT("The Name is:\t"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
				MultiByteToWideChar(CP_ACP, 0, ((PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(FileBuffer, *pOriginalFirstThunk) + (DWORD)FileBuffer))->Name, -1, buffer, MAX_STR_LEN);
				buffer[wcslen(buffer) + 1] = TEXT('\0');
				buffer[wcslen(buffer)] = TEXT('\n');
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
			}

			pOriginalFirstThunk++;
		}

		_tcscpy_s(buffer, TEXT("The FirstThunk:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		pFirstThunk = (PDWORD)(RVAtoFOA(FileBuffer, pImportDirectory->FirstThunk) + (DWORD)FileBuffer);
		while (*pFirstThunk)
		{
			if (IMAGE_SNAP_BY_ORDINAL32(*pFirstThunk)) {
				_tcscpy_s(buffer, TEXT("The Ordinals is:\t"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
				_itot_s(IMAGE_ORDINAL32(*pFirstThunk), buffer, 10);
				buffer[wcslen(buffer) + 1] = TEXT('\0');
				buffer[wcslen(buffer)] = TEXT('\n');
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
			}

			else
			{
				pImportName = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(FileBuffer, *pFirstThunk) + (DWORD)FileBuffer);
				_tcscpy_s(buffer, TEXT("The HIN-Name is:\t"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

				_itot_s(pImportName->Hint, buffer, 16);
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

				_tcscpy_s(buffer, TEXT("-"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

				MultiByteToWideChar(CP_ACP, 0, pImportName->Name, -1, buffer, MAX_STR_LEN);
				buffer[wcslen(buffer) + 1] = TEXT('\0');
				buffer[wcslen(buffer)] = TEXT('\n');
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
				printf("The HIN-Name is %X-%s\n", pImportName->Hint, pImportName->Name);
			}

			pFirstThunk++;
		}

		pImportDirectory += 1;
	}


	return TRUE;
}

DWORD ResolveResource(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };
	if (pData->VirtualAddress == 0 && pData->Size == 0)
		return FALSE;

	_tcscpy_s(buffer, TEXT("********************资源表*********************\n"));
	SetWindowText(hText, buffer);

	PIMAGE_RESOURCE_DIRECTORY pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);
	LPVOID pStartOffset = (LPVOID)pResourceDir;

	RecursiveResource(pStartOffset, pResourceDir, hText);
	
	return TRUE;
}

DWORD ResolveRelocation(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };
	DWORD i, tmp;
	PWORD pItem;

	if (pData->Size == 0 && pData->VirtualAddress == 0)
		return FALSE;

	_tcscpy_s(buffer, TEXT("********************重定位表********************\n"));
	SetWindowText(hText, buffer);

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);

	// 以全零标志着结构的结束
	while (pBaseRelocation->VirtualAddress && pBaseRelocation->SizeOfBlock)
	{
		_tcscpy_s(buffer, TEXT("********************"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		_itot_s(pBaseRelocation->VirtualAddress, buffer, 16);
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		_tcscpy_s(buffer, TEXT("********************\n"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		tmp = (pBaseRelocation->SizeOfBlock - 8) / 2;
		pItem = (PWORD)((DWORD)pBaseRelocation + 8);

		for (i = 0; i < tmp; i++)
		{
			if ((pItem[i] & 0x3000) == 0x3000)
			{
				_tcscpy_s(buffer, TEXT("\t\tThe RVA is:\t"));
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

				_itot_s(pItem[i] & 0x0fff, buffer, 16);
				buffer[wcslen(buffer) + 1] = TEXT('\0');
				buffer[wcslen(buffer)] = TEXT('\n');
				SendMessage(hText, EM_SETSEL, -2, -1);
				SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
			}
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	return TRUE;
}

DWORD ResolveBound(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };
	if (pData->Size == 0 && pData->VirtualAddress == 0)
		return FALSE;

	_tcscpy_s(buffer, TEXT("********************绑定导入表********************\n"));
	SetWindowText(hText, buffer);

	//PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(RVAtoFOA(FileBuffer, (pData - 0xA)->VirtualAddress) + (DWORD)FileBuffer);
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);
	PIMAGE_BOUND_FORWARDER_REF pBoundForward = NULL;

	DWORD OffsetBegin = pData->VirtualAddress;
	while (pBoundDescriptor->TimeDateStamp || pBoundDescriptor->OffsetModuleName)
	{
		_tcscpy_s(buffer, TEXT("\tTimeDataStamp is:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		_itot_s(pBoundDescriptor->TimeDateStamp, buffer, 16);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		_tcscpy_s(buffer, TEXT("\tModuleName is:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		MultiByteToWideChar(CP_ACP, 0, ((PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(FileBuffer, (OffsetBegin + pBoundDescriptor->OffsetModuleName)) + (DWORD)FileBuffer))->Name, -1, buffer, MAX_STR_LEN);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		for (DWORD i = 0; i < pBoundDescriptor->NumberOfModuleForwarderRefs; i++)
		{
			pBoundForward = (PIMAGE_BOUND_FORWARDER_REF)(pBoundDescriptor + 1);
			_tcscpy_s(buffer, TEXT("\t\tForward:\tTimeDataStamp is:\t"));
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

			_itot_s(pBoundForward->TimeDateStamp, buffer, 16);
			buffer[wcslen(buffer) + 1] = TEXT('\0');
			buffer[wcslen(buffer)] = TEXT('\n');
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

			_tcscpy_s(buffer, TEXT("\t\tModuleName is:\t"));
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

			MultiByteToWideChar(CP_ACP, 0, ((PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(FileBuffer, (OffsetBegin + pBoundForward->OffsetModuleName)) + (DWORD)FileBuffer))->Name, -1, buffer, MAX_STR_LEN);
			buffer[wcslen(buffer) + 1] = TEXT('\0');
			buffer[wcslen(buffer)] = TEXT('\n');
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		}
		pBoundDescriptor += pBoundDescriptor->NumberOfModuleForwarderRefs + 1;
	}

	return TRUE;
}

DWORD ResolveIAT(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText)
{
	TCHAR buffer[MAX_SIZE] = { 0 };
	if (pData->VirtualAddress == 0 && pData->Size == 0)
		return FALSE;

	_tcscpy_s(buffer, TEXT("********************IAT表********************\n"));
	SetWindowText(hText, buffer);

	PDWORD locate = (PDWORD)(RVAtoFOA(FileBuffer, pData->VirtualAddress) + (DWORD)FileBuffer);
	DWORD tmp = pData->Size / 4;

	for(DWORD i = 0; i < tmp; i++, locate++)
	{
		_tcscpy_s(buffer, TEXT("\tThe Item is:\t"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		_itot_s(*locate, buffer, 16);
		buffer[wcslen(buffer) + 1] = TEXT('\0');
		buffer[wcslen(buffer)] = TEXT('\n');
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
	}

	return TRUE;
}

DWORD RVAtoFOA(LPVOID pFileBuffer, DWORD RVA)
{
	DWORD i;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeaders = NULL;
	PIMAGE_FILE_HEADER pFileHeader = NULL;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	pFileHeader = &pNTHeaders->FileHeader;
	pOptionalHeader = &pNTHeaders->OptionalHeader;

	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	if (RVA < pOptionalHeader->SizeOfHeaders)
		return RVA;

	for (i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		// 该死的相等判断条件，边界条件易忽略！！！
		if (RVA >= pSectionHeader->VirtualAddress && RVA < pSectionHeader->VirtualAddress + MemoryPadding(pSectionHeader->Misc.VirtualSize, pOptionalHeader->SectionAlignment))
			return RVA - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
		pSectionHeader += 1;
	}

	return NULL;
}

DWORD MemoryPadding(DWORD size, DWORD ruler)
{
	DWORD times = size / ruler;
	if (!(size % ruler))
		return times * ruler;
	else
		return (times + 1) * ruler;
}

VOID RecursiveResource(LPVOID pStartOffset, PIMAGE_RESOURCE_DIRECTORY pResourceDir, HWND hText)
{
	TCHAR buffer[40] = { 0 };
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDir + 0x10);
	for (int i = 0; i < (pResourceDir->NumberOfIdEntries + pResourceDir->NumberOfNamedEntries); i++)
	{
		if (pResourceDirEntry->NameIsString)
		{
			_tcscpy_s(buffer, TEXT("\tThe name of the entry is:\t"));
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

			MultiByteToWideChar(CP_ACP, 0, (char *)((DWORD)pStartOffset + pResourceDirEntry->NameOffset), -1, buffer, MAX_STR_LEN);
			buffer[wcslen(buffer) + 1] = TEXT('\0');
			buffer[wcslen(buffer)] = TEXT('\n');
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		}
		else
		{
			_tcscpy_s(buffer, TEXT("\tThe ID of the entry is:\t"));
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

			_itot_s(pResourceDirEntry->Id, buffer, 16);
			buffer[wcslen(buffer) + 1] = TEXT('\0');
			buffer[wcslen(buffer)] = TEXT('\n');
			SendMessage(hText, EM_SETSEL, -2, -1);
			SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);
		}
		if (pResourceDirEntry->DataIsDirectory)
			RecursiveResource(LPVOID(pStartOffset), (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pStartOffset + pResourceDirEntry->OffsetToDirectory), hText);

		_tcscpy_s(buffer, TEXT("\n\n"));
		SendMessage(hText, EM_SETSEL, -2, -1);
		SendMessage(hText, EM_REPLACESEL, 0, (DWORD)buffer);

		pResourceDirEntry++;
	}
}

DWORD Encode(LPVOID lpData, DWORD dwSize)
{
	BYTE bMask = 0x5b;
	if (lpData == NULL)
		return FALSE;

	PBYTE pbStart = (PBYTE)lpData;
	for (DWORD i = 0; i < dwSize; i++)
		pbStart[i] = pbStart[i] ^ bMask;
}

DWORD mxPacker(LPTSTR ptPacker, LPTSTR ptSrc)
{
	if (ptPacker == TEXT("") || ptSrc == TEXT(""))
		return FALSE;

	LPVOID lpPackerFile = NULL;
	LPVOID lpSrcFile = NULL;
	LPVOID lpInjected = NULL;
	DWORD dwSrcSize = 0;
	DWORD dwPackerSize = 0;
	DWORD dwInjectedSize = 0;

	if (!(dwPackerSize = ReadPEFile(ptPacker, &lpPackerFile)))
		return FALSE;

	if (!(dwSrcSize = ReadPEFile(ptSrc, &lpSrcFile)))
	{
		free(lpPackerFile);
		return FALSE;
	}

	Encode(lpSrcFile, dwSrcSize);

	if (!(dwInjectedSize = AddNewSection(lpPackerFile, dwPackerSize, dwSrcSize, &lpInjected)))
	{
		free(lpPackerFile);
		free(lpSrcFile);
		return FALSE;
	}

	free(lpPackerFile);
	ContentInject(lpInjected, lpSrcFile, dwSrcSize);
	if (!WriteBack(TEXT("D:\\added.exe"), lpInjected, dwInjectedSize))
	{
		free(lpSrcFile);
		free(lpInjected);
		return FALSE;
	}

	free(lpSrcFile);
	free(lpInjected);
	return TRUE;
}

DWORD AddNewSection(LPVOID lpBuffer, DWORD dwRawSize, DWORD dwInjectedSize, LPVOID * lpOut)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	pSectionHeader += pFileHeader->NumberOfSections;

	if (pSectionHeader->SizeOfRawData != 0x0 && pSectionHeader->PointerToRawData != 0x0 && pSectionHeader->Characteristics != 0x0)
	{
		pDosHeader->e_lfanew = 0x40;
		DWORD dwTemp = (DWORD)pSectionHeader - (DWORD)pNTHeader;
		memcpy((LPVOID)((DWORD)lpBuffer + 0x40), (LPVOID)((DWORD)pNTHeader), dwTemp);

		pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
		pFileHeader = &pNTHeader->FileHeader;
		pOptionalHeader = &pNTHeader->OptionalHeader;
		pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);
		pSectionHeader += pFileHeader->NumberOfSections;
	}

	if (pOptionalHeader->SizeOfHeaders - (DWORD)pSectionHeader + (DWORD)(lpBuffer) < 80)
		return FALSE;

	DWORD dwMemorySize = MemoryPadding(dwInjectedSize, pOptionalHeader->FileAlignment);
	DWORD dwFileSize = MemoryPadding(dwInjectedSize, pOptionalHeader->SectionAlignment);
	DWORD dwFinalSize = dwRawSize + dwFileSize;

	memcpy(pSectionHeader->Name, ".Jnva", 8);
	pSectionHeader->Misc.VirtualSize = dwMemorySize;
	pSectionHeader->SizeOfRawData = dwFileSize;
	pSectionHeader->VirtualAddress = pOptionalHeader->SizeOfImage;
	pSectionHeader->PointerToRawData = (pSectionHeader - 1)->PointerToRawData + (pSectionHeader - 1)->SizeOfRawData;
	pSectionHeader->Characteristics = 0xC0000020;

	memset(pSectionHeader + 1, 0, 0x50);

	pFileHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += dwMemorySize;

	if (!(*lpOut = malloc(dwFinalSize)))
		return FALSE;

	memset(*lpOut, 0, dwFinalSize);
	memcpy(*lpOut, lpBuffer, dwRawSize);
	return dwFinalSize;
}

DWORD ContentInject(LPVOID lpPacker, LPVOID lpData, DWORD dwDataSize)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpPacker;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	pSectionHeader += pFileHeader->NumberOfSections - 1;

	LPVOID lpWritein = (LPVOID)(pSectionHeader->PointerToRawData + (DWORD)lpPacker);

	memcpy(lpWritein, lpData, dwDataSize);

	return TRUE;
}

DWORD SectionInject(LPVOID ptPacker, LPVOID ptData, DWORD dwPackerSize, DWORD dwDataSize, LPVOID * lpInjectedBuffer)
{

	if (ptPacker == NULL || ptData == NULL)
		return FALSE;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ptPacker;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)ptPacker + pDosHeader->e_lfanew);
	PIMAGE_FILE_HEADER pFileHeader = &pNTHeader->FileHeader;
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

	pSectionHeader += pFileHeader->NumberOfSections;

	//判断是否还有插入节表的空间
	if (pOptionalHeader->SizeOfHeaders - ((DWORD)pSectionHeader - (DWORD)ptPacker) < 80)
		return FALSE;

	memcpy(pSectionHeader->Name, ".Jvna", 6);
	pSectionHeader->Misc.VirtualSize = MemoryPadding(dwDataSize, pOptionalHeader->SectionAlignment);
	pSectionHeader->VirtualAddress = pOptionalHeader->SizeOfImage;
	pSectionHeader->SizeOfRawData = MemoryPadding(dwDataSize, pOptionalHeader->FileAlignment);
	pSectionHeader->PointerToRawData = (pSectionHeader - 1)->PointerToRawData + (pSectionHeader - 1)->SizeOfRawData;
	pSectionHeader->Characteristics = 0xC0000020;

	pFileHeader->NumberOfSections += 1;
	pOptionalHeader->SizeOfImage += pSectionHeader->VirtualAddress;

	if (!(*lpInjectedBuffer = (LPVOID)malloc(dwPackerSize + pSectionHeader->SizeOfRawData)))
		return FALSE;

	memset(*lpInjectedBuffer, 0, dwPackerSize + pSectionHeader->SizeOfRawData);
	memcpy(*lpInjectedBuffer, ptPacker, dwPackerSize);

	DWORD dwWriteLocation = (pSectionHeader - 1)->PointerToRawData + (pSectionHeader - 1)->SizeOfRawData;
	memcpy((LPVOID)((DWORD)*lpInjectedBuffer + dwWriteLocation), ptData, dwDataSize);

	return dwPackerSize + pSectionHeader->SizeOfRawData;
}