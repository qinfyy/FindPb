#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct FdpCandidate {
    size_t start = 0;
    size_t end = 0;
    std::string name;
    int score = 0;
    std::string reason;
};

struct FdsCandidate {
    size_t start = 0;
    size_t end = 0;
    size_t fileCount = 0;
    int score = 0;
    std::string reason;
};

std::vector<FdpCandidate> FindFileDescriptorProtos(const std::vector<uint8_t>& data);
std::vector<FdsCandidate> FindFileDescriptorSets(const std::vector<uint8_t>& data);
