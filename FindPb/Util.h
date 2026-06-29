#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <Windows.h>

std::string ByteArrayToHex(const uint8_t* data, size_t len);

std::string Utf16ToUtf8(const std::wstring& wstr);

std::wstring Utf8ToUtf16(const std::string& str);

std::string Utf16ToAnsi(const std::wstring& wstr);

std::wstring AnsiToUtf16(const std::string& str);

std::string AsciiEscapeToEscapeLiterals(const std::string& input);

bool ContainsIgnoreCaseA(PCSTR haystack, PCSTR needle);

bool ContainsIgnoreCaseW(PCWSTR haystack, PCWSTR needle);
