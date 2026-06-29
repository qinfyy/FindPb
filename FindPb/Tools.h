#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdio>


DWORD FindProcessId(const std::string& processName);

bool IsReadable(DWORD protect);

std::vector<uintptr_t> ScanMemory(HANDLE hProcess, const std::string& target);

bool GetModuleInfo(DWORD pid, const std::string& moduleName, MODULEENTRY32W& out);

std::vector<uintptr_t> ScanHeapMemory(HANDLE hProcess, const std::string& target);

std::vector<uintptr_t> ScanModuleMemory(HANDLE hProcess, const std::string& moduleName, const std::string& target);

void HexDump(HANDLE hProcess, uintptr_t dataPtr, SIZE_T backward, SIZE_T forward);

std::vector<uintptr_t> ScanFile(const std::string& filePath, const std::string& target);
