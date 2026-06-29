#include "DescriptorFinder.h"

#include <algorithm>
#include <cctype>
#include <limits>
#include <set>
#include <string_view>

namespace {

constexpr std::string_view kProtoSuffix = ".proto";
constexpr size_t kMaxNestedDepth = 16;

struct VarintResult {
    bool ok = false;
    uint64_t value = 0;
    size_t next = 0;
};

struct FieldSpan {
    bool ok = false;
    uint32_t fieldNumber = 0;
    uint32_t wireType = 0;
    size_t keyStart = 0;
    size_t valueStart = 0;
    size_t valueEnd = 0;
    size_t next = 0;
};

struct ParseResult {
    bool hasName = false;
    bool hasSignal = false;
    bool hasMessageLikeField = false;
    bool hasSyntax = false;
    bool hasPackage = false;
    bool hasDependency = false;
    size_t end = 0;
    int score = 0;
    std::string name;
    std::string reason;
};

VarintResult ReadVarint(const std::vector<uint8_t>& data, size_t pos, size_t limit)
{
    VarintResult result;
    uint64_t value = 0;
    int shift = 0;

    for (int i = 0; i < 10 && pos < limit; ++i)
    {
        uint8_t byte = data[pos++];
        value |= static_cast<uint64_t>(byte & 0x7F) << shift;

        if ((byte & 0x80) == 0)
        {
            result.ok = true;
            result.value = value;
            result.next = pos;
            return result;
        }

        shift += 7;
    }

    return result;
}

bool EndsWithProto(const std::string& value)
{
    return std::string_view(value).ends_with(kProtoSuffix);
}

bool IsPrintableAsciiString(const std::string& value)
{
    if (value.empty())
        return false;

    for (unsigned char ch : value)
    {
        if (ch == 0 || ch < 0x20 || ch == 0x7F)
            return false;
    }

    return true;
}

bool IsValidProtoName(const std::string& value)
{
    if (!EndsWithProto(value) || !IsPrintableAsciiString(value))
        return false;

    for (unsigned char ch : value)
    {
        if (std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.' || ch == '/' || ch == '\\')
            continue;
        return false;
    }

    return true;
}

bool IsPathLikeProtoName(const std::string& value)
{
    if (!IsValidProtoName(value))
        return false;

    if (value.find('/') != std::string::npos || value.find('\\') != std::string::npos)
        return true;

    auto stem = std::string_view(value).substr(0, value.size() - kProtoSuffix.size());
    return stem.find('.') == std::string::npos;
}

bool IsLikelyIdentifierPath(const std::string& value)
{
    if (!IsPrintableAsciiString(value))
        return false;

    bool hasAlpha = false;
    for (unsigned char ch : value)
    {
        if (std::isalpha(ch))
            hasAlpha = true;

        if (std::isalnum(ch) || ch == '_' || ch == '.' || ch == '/' || ch == '-' || ch == '$')
            continue;
        return false;
    }

    return hasAlpha;
}

bool IsSyntaxValue(const std::string& value)
{
    return value == "proto2" || value == "proto3" || value == "editions";
}

bool IsAllowedTopLevelField(uint32_t fieldNumber)
{
    switch (fieldNumber)
    {
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
    case 8:
    case 9:
    case 10:
    case 11:
    case 12:
    case 14:
    case 15:
        return true;
    default:
        return false;
    }
}

bool IsTopLevelWireTypeValid(uint32_t fieldNumber, uint32_t wireType)
{
    switch (fieldNumber)
    {
    case 1:  // name
    case 2:  // package
    case 3:  // dependency
    case 4:  // message_type
    case 5:  // enum_type
    case 6:  // service
    case 7:  // extension
    case 8:  // options
    case 9:  // source_code_info
    case 12: // syntax
    case 15: // option_dependency
        return wireType == 2;
    case 10: // public_dependency
    case 11: // weak_dependency
    case 14: // edition
        return wireType == 0 || wireType == 2;
    default:
        return false;
    }
}

bool IsStringField(uint32_t fieldNumber)
{
    return fieldNumber == 1 || fieldNumber == 2 || fieldNumber == 3 ||
        fieldNumber == 12 || fieldNumber == 15;
}

bool IsMessageLikeField(uint32_t fieldNumber)
{
    return fieldNumber == 4 || fieldNumber == 5 || fieldNumber == 6 ||
        fieldNumber == 7 || fieldNumber == 8 || fieldNumber == 9;
}

FieldSpan ReadFieldSpan(const std::vector<uint8_t>& data, size_t pos, size_t limit)
{
    FieldSpan field;
    field.keyStart = pos;

    auto key = ReadVarint(data, pos, limit);
    if (!key.ok || key.value == 0)
        return field;

    field.fieldNumber = static_cast<uint32_t>(key.value >> 3);
    field.wireType = static_cast<uint32_t>(key.value & 0x07);
    field.valueStart = key.next;

    switch (field.wireType)
    {
    case 0:
    {
        auto value = ReadVarint(data, field.valueStart, limit);
        if (!value.ok)
            return field;
        field.valueEnd = value.next;
        field.next = value.next;
        break;
    }
    case 1:
        if (field.valueStart + 8 > limit)
            return field;
        field.valueEnd = field.valueStart + 8;
        field.next = field.valueEnd;
        break;
    case 2:
    {
        auto length = ReadVarint(data, field.valueStart, limit);
        if (!length.ok || length.value > static_cast<uint64_t>(limit - length.next))
            return field;
        field.valueStart = length.next;
        field.valueEnd = length.next + static_cast<size_t>(length.value);
        field.next = field.valueEnd;
        break;
    }
    case 5:
        if (field.valueStart + 4 > limit)
            return field;
        field.valueEnd = field.valueStart + 4;
        field.next = field.valueEnd;
        break;
    default:
        return field;
    }

    field.ok = true;
    return field;
}

bool IsGenericWireMessage(const std::vector<uint8_t>& data, size_t start, size_t end, size_t depth)
{
    if (start == end)
        return true;

    if (depth > kMaxNestedDepth)
        return false;

    size_t pos = start;
    bool sawField = false;

    while (pos < end)
    {
        auto field = ReadFieldSpan(data, pos, end);
        if (!field.ok || field.fieldNumber == 0)
            return false;

        if (field.wireType == 2 && field.valueEnd > field.valueStart)
        {
            // length-delimited 在 protobuf 里既可能是字符串/bytes，也可能是子消息。
            // 这里仅尝试校验，不能要求每个 bytes 都能按子消息解开。
            IsGenericWireMessage(data, field.valueStart, field.valueEnd, depth + 1);
        }

        sawField = true;
        pos = field.next;
    }

    return sawField && pos == end;
}

std::string ReadBytesAsString(const std::vector<uint8_t>& data, size_t start, size_t end)
{
    return std::string(reinterpret_cast<const char*>(data.data() + start), end - start);
}

bool IsPotentialNameStart(const std::vector<uint8_t>& data, size_t keyPos, size_t& nameEnd, std::string& name)
{
    if (keyPos >= data.size() || data[keyPos] != 0x0A)
        return false;

    auto length = ReadVarint(data, keyPos + 1, data.size());
    if (!length.ok || length.value == 0 || length.value > std::numeric_limits<size_t>::max())
        return false;

    size_t valueStart = length.next;
    if (length.value > static_cast<uint64_t>(data.size() - valueStart))
        return false;

    size_t valueEnd = valueStart + static_cast<size_t>(length.value);

    auto value = ReadBytesAsString(data, valueStart, valueEnd);
    if (!IsValidProtoName(value))
        return false;

    nameEnd = valueEnd;
    name = value;
    return true;
}

std::vector<size_t> FindNameKeyPositions(const std::vector<uint8_t>& data)
{
    std::vector<size_t> positions;

    for (size_t keyPos = 0; keyPos < data.size(); ++keyPos)
    {
        size_t nameEnd = 0;
        std::string name;
        if (IsPotentialNameStart(data, keyPos, nameEnd, name))
            positions.push_back(keyPos);
    }

    return positions;
}

void ApplyFieldScore(const std::vector<uint8_t>& data, const FieldSpan& field, ParseResult& result)
{
    if (field.fieldNumber == 1 && field.wireType == 2)
    {
        auto value = ReadBytesAsString(data, field.valueStart, field.valueEnd);
        if (IsValidProtoName(value))
        {
            result.hasName = true;
            result.name = value;
            result.score += 40;
        }
        else
        {
            result.score -= 20;
        }
        return;
    }

    if (field.fieldNumber == 12 && field.wireType == 2)
    {
        auto value = ReadBytesAsString(data, field.valueStart, field.valueEnd);
        if (IsSyntaxValue(value))
        {
            result.hasSignal = true;
            result.hasSyntax = true;
            result.score += 25;
        }
        else
        {
            result.score -= 30;
        }
        return;
    }

    if (IsStringField(field.fieldNumber) && field.wireType == 2)
    {
        auto value = ReadBytesAsString(data, field.valueStart, field.valueEnd);
        if (field.fieldNumber == 3 || field.fieldNumber == 15)
        {
            if (IsValidProtoName(value))
            {
                result.hasSignal = true;
                result.hasDependency = true;
                result.score += 12;
            }
            else
            {
                result.score -= 10;
            }
        }
        else if (IsLikelyIdentifierPath(value))
        {
            result.hasSignal = true;
            if (field.fieldNumber == 2)
                result.hasPackage = true;
            result.score += 10;
        }
        else
        {
            result.score -= 10;
        }
        return;
    }

    if (IsMessageLikeField(field.fieldNumber) && field.wireType == 2)
    {
        result.hasSignal = true;
        result.hasMessageLikeField = true;
        result.score += 15;

        if (IsGenericWireMessage(data, field.valueStart, field.valueEnd, 0))
            result.score += 8;
        else
            result.score -= 8;

        return;
    }

    if ((field.fieldNumber == 10 || field.fieldNumber == 11 || field.fieldNumber == 14) &&
        (field.wireType == 0 || field.wireType == 2))
    {
        result.hasSignal = true;
        result.score += 5;
    }
}

bool HasAcceptableFdpShape(const ParseResult& result)
{
    if (!result.hasName || !result.hasSignal)
        return false;

    if (result.hasMessageLikeField)
        return true;

    return result.hasSyntax &&
        (result.hasPackage || result.hasDependency || IsPathLikeProtoName(result.name));
}

bool LooksLikeExternalTerminator(uint32_t fieldNumber, uint32_t wireType)
{
    if (fieldNumber == 1 && wireType == 2)
        return true;

    if (fieldNumber == 0 || wireType == 3 || wireType == 4 || wireType > 5)
        return true;

    return !IsAllowedTopLevelField(fieldNumber);
}

ParseResult ParseCandidate(const std::vector<uint8_t>& data, size_t start)
{
    ParseResult result;
    size_t pos = start;
    size_t fields = 0;

    while (pos < data.size())
    {
        auto field = ReadFieldSpan(data, pos, data.size());
        if (!field.ok)
            break;

        if (!IsAllowedTopLevelField(field.fieldNumber) ||
            !IsTopLevelWireTypeValid(field.fieldNumber, field.wireType))
        {
            break;
        }

        // 如果已经解析出有效 FDP，再遇到另一个 name=1，通常意味着下一个 FDP 开始。
        if (fields > 0 && field.fieldNumber == 1 && field.wireType == 2)
        {
            auto value = ReadBytesAsString(data, field.valueStart, field.valueEnd);
            if (IsValidProtoName(value) && result.hasName && result.hasSignal)
                break;
        }

        ApplyFieldScore(data, field, result);
        result.end = field.next;
        ++fields;
        pos = field.next;

        if (pos < data.size())
        {
            auto next = ReadFieldSpan(data, pos, data.size());
            if (!next.ok || LooksLikeExternalTerminator(next.fieldNumber, next.wireType))
                break;
        }
    }

    if (!result.hasName)
        result.reason = "缺少合法 name 字段";
    else if (!HasAcceptableFdpShape(result))
        result.reason = "缺少 FDP 结构信号字段";
    else if (result.end <= start)
        result.reason = "未能解析字段边界";
    else
        result.reason = "name 锚点和字段结构校验通过";

    return result;
}

bool IsBetterCandidate(const FdpCandidate& left, const FdpCandidate& right)
{
    if (left.score != right.score)
        return left.score > right.score;

    size_t leftSize = left.end - left.start;
    size_t rightSize = right.end - right.start;
    if (leftSize != rightSize)
        return leftSize > rightSize;

    return left.start < right.start;
}

bool IsOverlapped(const FdpCandidate& left, const FdpCandidate& right)
{
    return left.start < right.end && right.start < left.end;
}

std::string BuildReason(const ParseResult& parse)
{
    std::string reason = parse.reason;
    reason += parse.hasMessageLikeField ? "；包含消息/枚举/服务字段" : "；包含 name/package/syntax 弱校验信号";
    return reason;
}

} // namespace

std::vector<FdpCandidate> FindFileDescriptorProtos(const std::vector<uint8_t>& data)
{
    std::vector<FdpCandidate> rawCandidates;
    std::set<size_t> visitedStarts;

    for (size_t start : FindNameKeyPositions(data))
    {
        if (visitedStarts.find(start) != visitedStarts.end())
            continue;

        visitedStarts.insert(start);
        auto parse = ParseCandidate(data, start);
        if (!HasAcceptableFdpShape(parse) || parse.end <= start)
            continue;

        FdpCandidate candidate;
        candidate.start = start;
        candidate.end = parse.end;
        candidate.name = parse.name;
        candidate.score = parse.score;
        candidate.reason = BuildReason(parse);
        rawCandidates.push_back(candidate);
    }

    std::sort(rawCandidates.begin(), rawCandidates.end(), IsBetterCandidate);

    std::vector<FdpCandidate> selected;
    for (const auto& candidate : rawCandidates)
    {
        bool overlapped = false;
        for (const auto& existing : selected)
        {
            if (IsOverlapped(candidate, existing))
            {
                overlapped = true;
                break;
            }
        }

        if (!overlapped)
            selected.push_back(candidate);
    }

    std::sort(selected.begin(), selected.end(), [](const auto& left, const auto& right) {
        return left.start < right.start;
        });

    return selected;
}
