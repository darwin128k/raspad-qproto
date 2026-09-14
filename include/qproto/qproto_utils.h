#pragma once

#include <cstddef>
#include <cstdint>

// Ported from classic's classic_utils.{h,cpp} (GPLv3) - no engine dependency in these.
size_t strecpy(char* dest, const char* src, size_t maxlen, const char* exceptChars, char repChar = '\0');
bool IsValidId(uint32_t authId);
bool IsHddsnNumber(const char* authstring);
bool IsValidHddsnNumber(const void* data, size_t maxlen);
