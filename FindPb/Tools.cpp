#include "Tools.h"
#include "Util.h"
#include <iostream>
#include <iomanip>

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

bool IsReadable(DWORD protect)
{
    if (protect & PAGE_GUARD) return false;
    if (protect & PAGE_NOACCESS) return false;

    return (protect & PAGE_READONLY) ||
        (protect & PAGE_READWRITE) ||
        (protect & PAGE_EXECUTE_READ) ||
        (protect & PAGE_EXECUTE_READWRITE);
}

std::vector<MODULEENTRY32W> GetAllModules(DWORD pid)
{
    std::vector<MODULEENTRY32W> modules;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return modules;

    MODULEENTRY32W me;
    me.dwSize = sizeof(MODULEENTRY32W);

    if (!Module32FirstW(hSnapshot, &me))
    {
        CloseHandle(hSnapshot);
        return modules;
    }

    do
    {
        modules.push_back(me);
    } while (Module32NextW(hSnapshot, &me));

    CloseHandle(hSnapshot);
    return modules;
}

bool GetModuleInfo(DWORD pid, const std::string& moduleName, MODULEENTRY32W& out)
{
    std::wstring moduleNameW = AnsiToUtf16(moduleName);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    MODULEENTRY32W me{ sizeof(me) };

    if (Module32FirstW(snapshot, &me))
    {
        do
        {
            if (_wcsicmp(me.szModule, moduleNameW.c_str()) == 0)
            {
                out = me;
                CloseHandle(snapshot);
                return true;
            }
        } while (Module32NextW(snapshot, &me));
    }

    CloseHandle(snapshot);
    return false;
}

std::vector<uintptr_t> ScanRange(HANDLE hProcess, const std::vector<std::pair<uintptr_t, uintptr_t>>& ranges, const std::string& target) {
    std::vector<uintptr_t> results;

    for (const auto& r : ranges)
    {
        uintptr_t size = r.second - r.first;
        if (size == 0)
            continue;

        std::vector<char> buffer(size);

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)r.first, buffer.data(), size, &bytesRead))
            continue;

        for (size_t i = 0; i + target.size() <= bytesRead; i++)
        {
            if (memcmp(buffer.data() + i, target.data(), target.size()) == 0)
            {
                results.push_back(r.first + i);
            }
        }
    }

    return results;
}

std::vector<uintptr_t> ScanMemory(HANDLE hProcess, const std::string& target)
{
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (addr < maxAddr)
    {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
        {
            uintptr_t base = (uintptr_t)mbi.BaseAddress;
            uintptr_t end = base + mbi.RegionSize;

            ranges.emplace_back(base, end);
        }

        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    return ScanRange(hProcess, ranges, target);
}

std::vector<uintptr_t> ScanHeapMemory(HANDLE hProcess, const std::string& target)
{
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uintptr_t addr = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t maxAddr = (uintptr_t)sysInfo.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi;

    while (addr < maxAddr)
    {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && IsReadable(mbi.Protect))
        {
            uintptr_t base = (uintptr_t)mbi.BaseAddress;
            uintptr_t end = base + mbi.RegionSize;

            ranges.emplace_back(base, end);
        }

        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }

    return ScanRange(hProcess, ranges, target);
}

std::vector<uintptr_t> ScanModuleMemory(HANDLE hProcess, const std::string& moduleName, const std::string& target)
{
    std::vector<std::pair<uintptr_t, uintptr_t>> ranges;
    DWORD pid = GetProcessId(hProcess);
    if (!pid)
        return {};

    std::vector<MODULEENTRY32W> modules;

    if (moduleName == "*")
        modules = GetAllModules(pid);
    else
    {
        MODULEENTRY32W mod;
        if (!GetModuleInfo(pid, moduleName, mod))
            return {};

        modules.push_back(mod);
    }

    for (auto& mod : modules)
    {
        uintptr_t start = (uintptr_t)mod.modBaseAddr;
        uintptr_t end = start + mod.modBaseSize;

        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = start;

        while (addr < end)
        {
            if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
                break;

            if (mbi.State == MEM_COMMIT && IsReadable(mbi.Protect))
            {
                uintptr_t base = (uintptr_t)mbi.BaseAddress;
                uintptr_t rEnd = base + mbi.RegionSize;

                if (rEnd > end)
                    rEnd = end;

                ranges.emplace_back(base, rEnd);
            }

            addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
    }

    return ScanRange(hProcess, ranges, target);
}

std::vector<uintptr_t> ScanFile(const std::string& filePath, const std::string& target)
{
    std::vector<uintptr_t> results;

    FILE* file = nullptr;
    if (fopen_s(&file, filePath.c_str(), "rb") != 0 || !file)
        return results;

    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (fileSize <= 0 || target.empty())
    {
        fclose(file);
        return results;
    }

    std::vector<char> buffer(fileSize);
    size_t bytesRead = fread(buffer.data(), 1, fileSize, file);
    fclose(file);

    for (size_t i = 0; i + target.size() <= bytesRead; i++)
    {
        if (memcmp(buffer.data() + i, target.data(), target.size()) == 0)
        {
            results.push_back(i);
        }
    }

    return results;
}

void HexDump(HANDLE hProcess, uintptr_t dataPtr, SIZE_T backward, SIZE_T forward)
{
    const int bytesPerLine = 16;
    uint8_t buffer[16];

    uintptr_t startAddr = dataPtr - backward;
    int totalSize = backward + forward;

    for (int i = 0; i < totalSize; i += bytesPerLine)
    {
        SIZE_T toRead = min((SIZE_T)bytesPerLine, (SIZE_T)(totalSize - i));
        SIZE_T bytesRead = 0;

        uintptr_t currentAddr = startAddr + i;

        if (!ReadProcessMemory(hProcess, (LPCVOID)currentAddr, buffer, toRead, &bytesRead))
        {
            std::cout << std::hex << std::setw(12) << std::setfill('0') << currentAddr 
                << "  ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??\n";

            continue;
        }

        // offset
        std::cout << std::hex << std::setw(12) << std::setfill('0')
            << currentAddr << "  ";

        // hex
        for (int j = 0; j < bytesPerLine; j++)
        {
            if (j < (int)bytesRead)
                std::cout << std::setw(2) << std::setfill('0')
                << (int)buffer[j] << " ";
            else
                std::cout << "   ";
        }

        std::cout << " ";

        // ascii
        for (SIZE_T j = 0; j < bytesRead; j++)
        {
            char c = buffer[j];
            std::cout << (isprint((unsigned char)c) ? c : '.');
        }

        std::cout << "\n";
    }
}
