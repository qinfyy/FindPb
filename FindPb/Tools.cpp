#include "Tools.h"
#include "Util.h"
#include <algorithm>
#include <cctype>
#include <limits>
#include <tlhelp32.h>

namespace {

DWORD FindProcessId(const std::string& processName)
{
    std::wstring wProcessName = AnsiToUtf16(processName);

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &pe))
    {
        do
        {
            if (_wcsicmp(pe.szExeFile, wProcessName.c_str()) == 0)
            {
                CloseHandle(snapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return 0;
}

}  // namespace

bool TryParseProcessId(const std::string& value, DWORD& pid)
{
    if (value.empty())
        return false;

    uint64_t parsed = 0;
    for (unsigned char ch : value)
    {
        if (!std::isdigit(ch))
            return false;

        parsed = parsed * 10 + (ch - '0');
        if (parsed > (std::numeric_limits<DWORD>::max)())
            return false;
    }

    if (parsed == 0)
        return false;

    pid = static_cast<DWORD>(parsed);
    return true;
}

DWORD ResolveProcessId(const std::string& processNameOrPid)
{
    DWORD pid = 0;
    if (TryParseProcessId(processNameOrPid, pid))
        return pid;

    return FindProcessId(processNameOrPid);
}

bool IsReadable(DWORD protect)
{
    if (protect & PAGE_GUARD) return false;
    if (protect & PAGE_NOACCESS) return false;

    return (protect & PAGE_READONLY) ||
        (protect & PAGE_READWRITE) ||
        (protect & PAGE_EXECUTE_READ) ||
        (protect & PAGE_EXECUTE_READWRITE);
}

ProcessDumpResult DumpProcessMemory(DWORD pid, const std::filesystem::path& dumpPath)
{
    ProcessDumpResult result;
    result.dumpPath = dumpPath;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        result.error = "打开进程失败";
        return result;
    }

    FILE* file = nullptr;
    auto dumpPathString = dumpPath.string();
    if (fopen_s(&file, dumpPathString.c_str(), "wb") != 0 || !file)
    {
        CloseHandle(hProcess);
        result.error = "创建 Dump 文件失败";
        return result;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t addr = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi;
    constexpr SIZE_T kChunkSize = 1024 * 1024;
    std::vector<uint8_t> buffer(kChunkSize);

    while (addr < maxAddr)
    {
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
            break;

        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t regionEnd = base + mbi.RegionSize;

        if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
        {
            size_t fileOffset = result.bytesWritten;
            size_t regionBytesWritten = 0;
            uintptr_t current = base;

            while (current < regionEnd)
            {
                SIZE_T toRead = static_cast<SIZE_T>(std::min<uintptr_t>(
                    static_cast<uintptr_t>(buffer.size()),
                    regionEnd - current));
                SIZE_T bytesRead = 0;

                if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(current),
                    buffer.data(), toRead, &bytesRead) || bytesRead == 0)
                {
                    break;
                }

                size_t bytesWritten = fwrite(buffer.data(), 1, bytesRead, file);
                if (bytesWritten != bytesRead)
                {
                    fclose(file);
                    CloseHandle(hProcess);
                    result.error = "写入 Dump 文件失败";
                    return result;
                }

                result.bytesWritten += bytesWritten;
                regionBytesWritten += bytesWritten;
                current += bytesRead;
            }

            if (regionBytesWritten > 0)
            {
                ++result.regionCount;
                result.segments.push_back({ base, fileOffset, regionBytesWritten });
            }
            else
            {
                ++result.skippedRegionCount;
            }
        }

        if (regionEnd <= addr)
            break;
        addr = regionEnd;
    }

    fclose(file);
    CloseHandle(hProcess);

    result.ok = true;
    return result;
}
