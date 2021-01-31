#pragma once

#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <tuple>
#include <map>
#include <cstdint>
#include <string>

#include "usings.h"

#define OBF(x) x
#define OBFI(x) x
#define OBF_ASCII(x) x
#define OBFI_ASCII(x) x
#define ADV_OBF(x) x
#define ADV_OBF_W(x) x
#define OBF_WSTR(x) std::wstring(x)
#define OBF_STR(x) std::string(x)

#define RESOLVE(a, b) auto _ ## b = reinterpret_cast<fn_ ## b *>(::GetProcAddress(::LoadLibraryA(#a), #b));

template<class... Args>
void info(Args... args)
{
	std::wostringstream woss;
	(woss << ... << args);

	auto a = woss.str();
	std::wcout << a << std::endl;
}

template <typename T> static float ShannonEntropy(T data[], int elements) {
	float entropy = 0;
	std::map<T, long> counts;
	typename std::map<T, long>::iterator it;
	//
	for (int dataIndex = 0; dataIndex < elements; ++dataIndex) {
		counts[data[dataIndex]]++;
	}
	//
	it = counts.begin();
	while (it != counts.end()) {
		float p_x = (float)it->second / elements;
		if (p_x > 0) entropy -= p_x * log(p_x) / log(2);
		it++;
	}
	return entropy;
}


BOOL setPrivilege(
	LPCTSTR lpszPrivilege,
	BOOL bEnablePrivilege,
	HANDLE mainToken = nullptr
);

BOOL getProcessModulePath(
	DWORD dwPid, 
	const BYTE* address, 
	LPWSTR imagePath, 
	DWORD dwSize, 
	bool nameInsteadOfPath
);

std::wstring parseMachine(const std::wstring& prefix, DWORD machine);
std::wstring parseSubsystem(const std::wstring& prefix, DWORD subsystem);
std::wstring parseTimestamp(const std::wstring& prefix, DWORD timestamp);
std::wstring parseSectionCharacteristics(const std::wstring& prefix, DWORD characteristics);
std::wstring parseFileCharacteristics(const std::wstring& prefix, DWORD characteristics);
std::wstring parseDllCharacteristics(const std::wstring& prefix, DWORD characteristics);