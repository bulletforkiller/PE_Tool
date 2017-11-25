#pragma once

#ifndef PE_HEAD
#define PE_HEAD
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <CommCtrl.h>
#include "resource.h"

#define MAX_SIZE 256
#define MAX_STR_LEN 2048
#endif

DWORD ReadPEFile(IN LPTSTR peFile, OUT LPVOID * FileBuffer);
DWORD ResolveHeader(IN LPVOID FileBuffer, IN HWND hDlg);
DWORD ResolveSection(IN LPVOID FileBuffer, IN HWND hListSection);
DWORD ResolveDirectory(IN LPVOID FileBuffer, IN HWND hDlg);
DWORD ResolveDetails(IN LPVOID FileBuffer, IN HWND hText, DWORD nDetailType);

DWORD ResolveExport(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);
DWORD ResolveImport(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);
DWORD ResolveResource(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);
DWORD ResolveRelocation(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);
DWORD ResolveBound(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);
DWORD ResolveIAT(IN LPVOID FileBuffer, IN PIMAGE_DATA_DIRECTORY pData, IN HWND hText);

DWORD MemoryPadding(DWORD size, DWORD ruler);
DWORD RVAtoFOA(LPVOID pFileBuffer, DWORD RVA);
VOID RecursiveResource(LPVOID pStartOffset, PIMAGE_RESOURCE_DIRECTORY pResourceDir, HWND hText);
