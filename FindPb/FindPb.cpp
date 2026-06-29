// FindPb.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <Windows.h>
#include <filesystem>
#include "Tools.h"
#include "Util.h"
#include "DescriptorFinder.h"

#include <vector>
#include <string>
#include <variant>
#include <cstdint>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>

using PbValue = std::variant<
    uint64_t,     // varint
    std::string,  // length-delimited
    float,        // fixed32
    double        // fixed64
>;

struct PbField {
    uint32_t fieldNumber;
    std::string type;
    PbValue value;
};

uint64_t DecodeVarint(const std::string& data, size_t& pos)
{
    uint64_t result = 0;
    int shift = 0;

    while (pos < data.size()) {
        uint8_t byte = static_cast<uint8_t>(data[pos++]);

        result |= uint64_t(byte & 0x7F) << shift;

        if (!(byte & 0x80))
            return result;

        shift += 7;

        if (shift > 63)
            throw std::runtime_error("Varint too long");
    }

    throw std::runtime_error("Unexpected EOF while reading varint");
}

std::vector<PbField> ParsePb(const std::string& data)
{
    size_t pos = 0;
    std::vector<PbField> result;

    while (pos < data.size()) {
        uint64_t key = DecodeVarint(data, pos);

        uint32_t fieldNumber = static_cast<uint32_t>(key >> 3);
        uint32_t wireType = static_cast<uint32_t>(key & 0x7);

        if (wireType == 0) { // VARINT
            uint64_t value = DecodeVarint(data, pos);
            result.push_back({ fieldNumber, "varint", value });
        }
        else if (wireType == 2) { // LENGTH_DELIMITED
            uint64_t length = DecodeVarint(data, pos);

            if (pos + length > data.size())
                throw std::runtime_error("Invalid length");

            std::string value = data.substr(pos, length);
            pos += length;

            result.push_back({ fieldNumber, "bytes", value });
        }
        else if (wireType == 5) { // FIXED32
            if (pos + 4 > data.size())
                throw std::runtime_error("Unexpected EOF (fixed32)");

            uint32_t raw =
                static_cast<uint8_t>(data[pos]) |
                (static_cast<uint8_t>(data[pos + 1]) << 8) |
                (static_cast<uint8_t>(data[pos + 2]) << 16) |
                (static_cast<uint8_t>(data[pos + 3]) << 24);

            float value;
            memcpy(&value, &raw, sizeof(float));

            pos += 4;

            result.push_back({ fieldNumber, "fixed32", value });
        }
        else if (wireType == 1) { // FIXED64
            if (pos + 8 > data.size())
                throw std::runtime_error("Unexpected EOF (fixed64)");

            double value;
            memcpy(&value, data.data() + pos, 8);

            pos += 8;

            result.push_back({ fieldNumber, "fixed64", value });
        }
        else {
            throw std::runtime_error("Unknown wire type: " + std::to_string(wireType));
        }
    }

    return result;
}

constexpr const char* DEFAULT_TARGET = ".proto";

std::string SanitizeFileNamePart(const std::string& value)
{
    std::string result;
    result.reserve(value.size());

    for (unsigned char ch : value)
    {
        if (std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.')
            result.push_back(static_cast<char>(ch));
        else
            result.push_back('_');
    }

    if (result.empty())
        return "unknown";

    return result;
}

bool ReadWholeFile(const std::string& filePath, std::vector<uint8_t>& data)
{
    FILE* file = nullptr;
    if (fopen_s(&file, filePath.c_str(), "rb") != 0 || !file)
        return false;

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return false;
    }

    long fileSize = ftell(file);
    if (fileSize < 0)
    {
        fclose(file);
        return false;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        return false;
    }

    data.resize(static_cast<size_t>(fileSize));
    size_t bytesRead = data.empty() ? 0 : fread(data.data(), 1, data.size(), file);
    fclose(file);

    return bytesRead == data.size();
}

bool WriteWholeFile(const std::filesystem::path& filePath, const uint8_t* data, size_t size)
{
    FILE* file = nullptr;
    auto pathString = filePath.string();
    if (fopen_s(&file, pathString.c_str(), "wb") != 0 || !file)
        return false;

    size_t bytesWritten = size == 0 ? 0 : fwrite(data, 1, size, file);
    fclose(file);

    return bytesWritten == size;
}

struct Config {
    std::string processName;    // 进程名（进程模式）
    std::string filePath;       // 文件路径（文件模式）
    std::string moduleName;     // 模块名（模块模式）
    std::string scanMode;       // 扫描模式: heap / memory / module
    bool showUsage = false;
};

bool ParseArgs(int argc, char* argv[], Config& cfg)
{
    cfg.scanMode = "heap";

    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            cfg.showUsage = true;
            return true;
        }
        else if (arg == "-p" || arg == "--process")
        {
            if (i + 1 < argc) cfg.processName = argv[++i];
            else { std::cerr << "Error: " << arg << " requires a value\n"; return false; }
        }
        else if (arg == "-f" || arg == "--file")
        {
            if (i + 1 < argc) cfg.filePath = argv[++i];
            else { std::cerr << "Error: " << arg << " requires a value\n"; return false; }
        }
        else if (arg == "-m" || arg == "--mode")
        {
            if (i + 1 < argc) cfg.scanMode = argv[++i];
            else { std::cerr << "Error: " << arg << " requires a value\n"; return false; }
        }
        else if (arg == "--module")
        {
            if (i + 1 < argc) cfg.moduleName = argv[++i];
            else { std::cerr << "Error: " << arg << " requires a value\n"; return false; }
        }
        else
        {
            std::cerr << "Error: unknown argument: " << arg << "\n";
            return false;
        }
    }

    // 验证：必须指定进程或文件之一
    if (cfg.processName.empty() && cfg.filePath.empty())
    {
        std::cerr << "Error: must specify --process or --file\n";
        return false;
    }

    // 验证模式
    if (cfg.scanMode != "heap" && cfg.scanMode != "memory" && cfg.scanMode != "module")
    {
        std::cerr << "Error: --mode must be heap, memory, or module\n";
        return false;
    }

    return true;
}

void ShowUsage(const char* exeName)
{
    std::cout << "Usage:\n"
        << "  " << exeName << " --process <name> [--mode heap|memory|module] [--module <name>]\n"
        << "  " << exeName << " --file <path>\n"
        << "\nOptions:\n"
        << "  -p, --process <name>   Target process name (e.g. StellaSora.exe)\n"
        << "  -f, --file <path>      Target file path\n"
        << "  -m, --mode <mode>      Scan mode for process: heap, memory, module (default: heap)\n"
        << "      --module <name>    Module name for module mode (* for all modules)\n"
        << "  -h, --help             Show this help\n";
}

int main(int argc, char* argv[])
{
    Config cfg;

    if (!ParseArgs(argc, argv, cfg))
    {
        ShowUsage(argv[0]);
        return 1;
    }

    if (cfg.showUsage)
    {
        ShowUsage(argv[0]);
        return 0;
    }

    // 文件模式
    if (!cfg.filePath.empty())
    {
        std::cout << "扫描文件: " << cfg.filePath << "\n";
        std::cout << "锚点: \"" << DEFAULT_TARGET << "\"\n\n";

        std::vector<uint8_t> fileData;
        if (!ReadWholeFile(cfg.filePath, fileData))
        {
            std::cout << "读取文件失败\n";
            return 1;
        }

        auto candidates = FindFileDescriptorProtos(fileData);

        if (candidates.empty())
        {
            std::cout << "未找到可恢复的 FileDescriptorProto\n";
            return 0;
        }

        std::cout << "找到可恢复的 FileDescriptorProto: " << candidates.size() << " 个\n\n";

        std::filesystem::path inputPath(cfg.filePath);
        size_t exportedCount = 0;

        for (size_t i = 0; i < candidates.size(); ++i)
        {
            const auto& candidate = candidates[i];
            size_t length = candidate.end - candidate.start;
            std::string safeName = SanitizeFileNamePart(candidate.name);
            std::filesystem::path outputPath = inputPath;
            outputPath += ".fdp_" + std::to_string(i) + "_" + safeName + ".bin";

            std::cout << "FileDescriptorProto[" << i << "]\n";
            std::cout << "  名称: " << candidate.name << "\n";
            std::cout << "  起始偏移: 0x" << std::hex << candidate.start << std::dec << "\n";
            std::cout << "  结束偏移: 0x" << std::hex << candidate.end << std::dec << "\n";
            std::cout << "  长度: " << length << " 字节\n";
            std::cout << "  分数: " << candidate.score << "\n";
            std::cout << "  原因: " << candidate.reason << "\n";

            if (candidate.end > fileData.size() || candidate.start >= candidate.end)
            {
                std::cout << "  导出失败: 候选范围越界\n\n";
                continue;
            }

            if (!WriteWholeFile(outputPath, fileData.data() + candidate.start, length))
            {
                std::cout << "  导出失败: " << outputPath.string() << "\n\n";
                continue;
            }

            ++exportedCount;
            std::cout << "  导出: " << outputPath.string() << "\n\n";
        }

        std::cout << "导出完成: " << exportedCount << " / " << candidates.size() << "\n";
        return 0;
    }

    // 进程模式
    DWORD pid = FindProcessId(cfg.processName);
    if (pid == 0)
    {
        std::cout << "Process not found: " << cfg.processName << "\n";
        return 0;
    }

    std::cout << "PID: " << pid << "\n";
    std::cout << "Target: \"" << DEFAULT_TARGET << "\"\n";
    std::cout << "Mode: " << cfg.scanMode << "\n\n";

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess)
    {
        std::cout << "OpenProcess failed\n";
        return 0;
    }

    std::vector<uintptr_t> results;

    if (cfg.scanMode == "heap")
        results = ScanHeapMemory(hProcess, DEFAULT_TARGET);
    else if (cfg.scanMode == "memory")
        results = ScanMemory(hProcess, DEFAULT_TARGET);
    else if (cfg.scanMode == "module")
    {
        std::string modName = cfg.moduleName.empty() ? "*" : cfg.moduleName;
        results = ScanModuleMemory(hProcess, modName, DEFAULT_TARGET);
    }

    for (auto addr : results)
    {
        std::cout << "Found at: 0x" << std::hex << addr << std::dec << "\n";
        HexDump(hProcess, addr, 0, 512);
        std::cout << "\n";
    }

    if (results.empty())
        std::cout << "Not found\n";

    CloseHandle(hProcess);
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
