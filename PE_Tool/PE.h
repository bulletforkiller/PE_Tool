#pragma once

#ifndef PE_HEAD
#define PE_HEAD
#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <Psapi.h>
#include <CommCtrl.h>
#endif

#define MAX_NUM 384


BOOL CALLBACK DialogMainProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL CALLBACK DialogAboutProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL CALLBACK DialogPEProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL CALLBACK DialogSectionProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL CALLBACK DialogDirectoryProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL CALLBACK DialogDetailProc(
	_In_ HWND hwnd,
	_In_ UINT uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

BOOL UpdateProcessPrivilege(HANDLE hProcess, LPCTSTR lpPrivilegeName = SE_DEBUG_NAME);

// 初始化四个窗口
VOID InitProcessListView(HWND hDlg);
VOID InitModuleListView(HWND hDlg);
VOID InitSectionListView(HWND hDlg);

// 第一个功能，有关进程
VOID SetProcessList(HWND hListProcess);
VOID SetModuleList(HWND hListProcess, HWND hListModule);

