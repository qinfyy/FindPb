// FindPb.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <cctype>
#include <filesystem>
#include "Tools.h"
#include "DescriptorFinder.h"

#include <vector>
#include <string>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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
    std::string outputDir;      // 导出目录
    bool showUsage = false;
};

bool ParseArgs(int argc, char* argv[], Config& cfg)
{
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
            else { std::cerr << "错误: " << arg << " 需要一个进程名\n"; return false; }
        }
        else if (arg == "-f" || arg == "--file")
        {
            if (i + 1 < argc) cfg.filePath = argv[++i];
            else { std::cerr << "错误: " << arg << " 需要一个文件路径\n"; return false; }
        }
        else if (arg == "-o" || arg == "--out-dir" || arg == "--output-dir")
        {
            if (i + 1 < argc) cfg.outputDir = argv[++i];
            else { std::cerr << "错误: " << arg << " 需要一个导出目录\n"; return false; }
        }
        else
        {
            std::cerr << "错误: 未知参数: " << arg << "\n";
            return false;
        }
    }

    // 验证：必须指定进程或文件之一
    if (cfg.processName.empty() && cfg.filePath.empty())
    {
        std::cerr << "错误: 必须指定 --process 或 --file\n";
        return false;
    }

    return true;
}

void ShowUsage(const char* exeName)
{
    std::cout << "用法:\n"
        << "  " << exeName << " --process <name|pid> [--out-dir <dir>]\n"
        << "  " << exeName << " --file <path> [--out-dir <dir>]\n"
        << "\n选项:\n"
        << "  -p, --process <name|pid>  目标进程名或 PID\n"
        << "  -f, --file <path>      目标文件路径\n"
        << "  -o, --out-dir <dir>    FDP/FDS 导出目录，默认当前运行目录\n"
        << "  -h, --help             显示帮助\n";
}

int ScanBufferAndExport(const std::vector<uint8_t>& data, const std::filesystem::path& inputName,
    const std::filesystem::path& outputDir)
{
    auto fdpCandidates = FindFileDescriptorProtos(data);
    auto fdsCandidates = FindFileDescriptorSets(data);

    if (fdpCandidates.empty() && fdsCandidates.empty())
    {
        std::cout << "未找到可恢复的 FileDescriptorProto / FileDescriptorSet\n";
        return 0;
    }

    std::cout << "找到可恢复的 FileDescriptorProto: " << fdpCandidates.size() << " 个\n";
    std::cout << "找到可恢复的 FileDescriptorSet: " << fdsCandidates.size() << " 个\n\n";

    std::error_code fsError;
    std::filesystem::create_directories(outputDir, fsError);
    if (fsError)
    {
        std::cout << "创建导出目录失败: " << outputDir.string() << "\n";
        return 1;
    }

    size_t exportedFdpCount = 0;
    size_t exportedFdsCount = 0;

    for (size_t i = 0; i < fdpCandidates.size(); ++i)
    {
        const auto& candidate = fdpCandidates[i];
        size_t length = candidate.end - candidate.start;
        std::string safeName = SanitizeFileNamePart(candidate.name);
        std::string outputName = inputName.filename().string() +
            ".fdp_" + std::to_string(i) + "_" + safeName + ".bin";
        std::filesystem::path outputPath = outputDir / outputName;

        std::cout << "FileDescriptorProto[" << i << "]\n";
        std::cout << "  名称: " << candidate.name << "\n";
        std::cout << "  起始偏移: 0x" << std::hex << candidate.start << std::dec << "\n";
        std::cout << "  结束偏移: 0x" << std::hex << candidate.end << std::dec << "\n";
        std::cout << "  长度: " << length << " 字节\n";
        std::cout << "  分数: " << candidate.score << "\n";
        std::cout << "  原因: " << candidate.reason << "\n";

        if (candidate.end > data.size() || candidate.start >= candidate.end)
        {
            std::cout << "  导出失败: 候选范围越界\n\n";
            continue;
        }

        if (!WriteWholeFile(outputPath, data.data() + candidate.start, length))
        {
            std::cout << "  导出失败: " << outputPath.string() << "\n\n";
            continue;
        }

        ++exportedFdpCount;
        std::cout << "  导出: " << outputPath.string() << "\n\n";
    }

    for (size_t i = 0; i < fdsCandidates.size(); ++i)
    {
        const auto& candidate = fdsCandidates[i];
        size_t length = candidate.end - candidate.start;
        std::string outputName = inputName.filename().string() +
            ".fds_" + std::to_string(i) + "_" + std::to_string(candidate.fileCount) + "_files.bin";
        std::filesystem::path outputPath = outputDir / outputName;

        std::cout << "FileDescriptorSet[" << i << "]\n";
        std::cout << "  起始偏移: 0x" << std::hex << candidate.start << std::dec << "\n";
        std::cout << "  结束偏移: 0x" << std::hex << candidate.end << std::dec << "\n";
        std::cout << "  长度: " << length << " 字节\n";
        std::cout << "  文件数量: " << candidate.fileCount << "\n";
        std::cout << "  分数: " << candidate.score << "\n";
        std::cout << "  原因: " << candidate.reason << "\n";

        if (candidate.end > data.size() || candidate.start >= candidate.end)
        {
            std::cout << "  导出失败: 候选范围越界\n\n";
            continue;
        }

        if (!WriteWholeFile(outputPath, data.data() + candidate.start, length))
        {
            std::cout << "  导出失败: " << outputPath.string() << "\n\n";
            continue;
        }

        ++exportedFdsCount;
        std::cout << "  导出: " << outputPath.string() << "\n\n";
    }

    std::cout << "导出完成: FDP " << exportedFdpCount << " / " << fdpCandidates.size()
        << "，FDS " << exportedFdsCount << " / " << fdsCandidates.size() << "\n";
    return 0;
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

        std::vector<uint8_t> fileData;
        if (!ReadWholeFile(cfg.filePath, fileData))
        {
            std::cout << "读取文件失败\n";
            return 1;
        }

        std::filesystem::path inputPath(cfg.filePath);
        std::filesystem::path outputDir = cfg.outputDir.empty() ?
            std::filesystem::current_path() :
            std::filesystem::path(cfg.outputDir);

        return ScanBufferAndExport(fileData, inputPath.filename(), outputDir);
    }

    // 进程模式
    DWORD pid = ResolveProcessId(cfg.processName);
    if (pid == 0)
    {
        std::cout << "未找到进程: " << cfg.processName << "\n";
        return 0;
    }

    std::filesystem::path outputDir = cfg.outputDir.empty() ?
        std::filesystem::current_path() :
        std::filesystem::path(cfg.outputDir);
    std::error_code fsError;
    std::filesystem::create_directories(outputDir, fsError);
    if (fsError)
    {
        std::cout << "创建导出目录失败: " << outputDir.string() << "\n";
        return 1;
    }

    std::string dumpPrefix = SanitizeFileNamePart(cfg.processName.empty() ? "process" : cfg.processName);
    std::filesystem::path dumpPath = outputDir / (dumpPrefix + "_" + std::to_string(pid) + ".dump.bin");

    std::cout << "PID: " << pid << "\n";
    std::cout << "进程内存 Dump: " << dumpPath.string() << "\n";

    auto dumpResult = DumpProcessMemory(pid, dumpPath);
    if (!dumpResult.ok)
    {
        std::cout << "进程内存 Dump 失败: " << dumpResult.error << "\n";
        return 1;
    }

    std::cout << "Dump 大小: " << dumpResult.bytesWritten << " 字节\n";
    std::cout << "Dump 区域: " << dumpResult.regionCount << " 个，跳过: "
        << dumpResult.skippedRegionCount << " 个\n\n";

    std::vector<uint8_t> dumpData;
    if (!ReadWholeFile(dumpPath.string(), dumpData))
    {
        std::cout << "读取 Dump 文件失败\n";
        return 1;
    }

    return ScanBufferAndExport(dumpData, dumpPath.filename(), outputDir);
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
