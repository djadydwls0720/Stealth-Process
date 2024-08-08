#pragma once
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <string.h>
void Stealth();

#define NewNtQuerySystemInformation_size  (ULONGLONG)NewNtQuerySystemInformation - (ULONGLONG)DumyFunc;
#define Lower(s1) s1 >= 65 && s1 <= 90 ? (wchar_t)s1 + 32 : s1
