#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <filesystem>

bool TryParseProcessId(const std::string& value, DWORD& pid);
DWORD ResolveProcessId(const std::string& processNameOrPid);

bool IsReadable(DWORD protect);

struct DumpSegment {
    uintptr_t base = 0;
    size_t fileOffset = 0;
    size_t size = 0;
};

struct ProcessDumpResult {
    bool ok = false;
    std::filesystem::path dumpPath;
    size_t bytesWritten = 0;
    size_t regionCount = 0;
    size_t skippedRegionCount = 0;
    std::vector<DumpSegment> segments;
    std::string error;
};

ProcessDumpResult DumpProcessMemory(DWORD pid, const std::filesystem::path& dumpPath);
