#include "utils.h"

#define PRINT_CHARACTERISTIC(prefix, chars) \
			out << prefix << std::left << std::setfill(L' ') << std::setw(35) \
				<< std::get<1>(chars) << std::endl << L"\t" << prefix << L"(" << std::get<2>(chars) << L")" << std::endl;


BOOL setPrivilege(
	LPCTSTR lpszPrivilege,
	BOOL bEnablePrivilege,
	HANDLE mainToken
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	RESOLVE(Advapi32, OpenThreadToken);
	RESOLVE(Advapi32, LookupPrivilegeValueW);
	RESOLVE(Advapi32, AdjustTokenPrivileges);
	RESOLVE(Advapi32, ImpersonateSelf);

	if (mainToken == nullptr)
	{
		if (!_OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &mainToken))
		{
			if (GetLastError() == ERROR_NO_TOKEN)
			{
				if (!_ImpersonateSelf(SecurityImpersonation))
				{
					return false;
				}

				if (!_OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, false, &mainToken))
				{
					info(OBF(L"[!] OpenThreadToken error: "), GetLastError());
					return false;
				}
			}
			else
			{
				return false;
			}
		}
	}

	if (!_LookupPrivilegeValueW(
		nullptr,
		lpszPrivilege,
		&luid))
	{
		info(OBF(L"[!] LookupPrivilegeValue error: "), GetLastError());
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

	if (!_AdjustTokenPrivileges(
		mainToken,
		false,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES) nullptr,
		(PDWORD) nullptr))
	{
		info(OBF(L"[!] AdjustTokenPrivileges error: "), GetLastError());
		return false;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		info(OBF(L"[!] The token does not have the specified privilege"));
		return false;
	}

	return true;
}

BOOL getProcessModulePath(DWORD dwPid, const BYTE* address, LPWSTR imagePath, DWORD dwSize, bool nameInsteadOfPath)
{
	HANDLE         hSnap;
	MODULEENTRY32W me32;
	BOOL           bFound = FALSE;

	// create snapshot of system
	RESOLVE(kernel32, CreateToolhelp32Snapshot);
	RESOLVE(kernel32, Module32FirstW);
	RESOLVE(kernel32, Module32NextW);

	hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (hSnap == INVALID_HANDLE_VALUE) return 0;

	me32.dwSize = sizeof(MODULEENTRY32W);

	// get first process
	if (_Module32FirstW(hSnap, &me32)) {
		do {
			if (!address || ((address >= (me32.modBaseAddr)) && (address <= (me32.modBaseAddr + me32.modBaseSize)))) {
				if (nameInsteadOfPath) lstrcpynW(imagePath, me32.szModule, dwSize);
				else lstrcpynW(imagePath, me32.szExePath, dwSize);
				bFound = TRUE;
				break;
			}
		} while (_Module32NextW(hSnap, &me32));
	}
	CloseHandle(hSnap);
	return bFound;
}

std::wstring parseSectionCharacteristics(const std::wstring& prefix, DWORD characteristics)
{
	std::wstringstream out;
	std::vector<std::tuple<DWORD, std::wstring, std::wstring>> characteristicsList = {
		{ IMAGE_SCN_TYPE_NO_PAD, L"IMAGE_SCN_TYPE_NO_PAD", L"Reserved." },
		{ IMAGE_SCN_CNT_CODE, L"IMAGE_SCN_CNT_CODE", L"Section contains code." },
		{ IMAGE_SCN_CNT_INITIALIZED_DATA, L"IMAGE_SCN_CNT_INITIALIZED_DATA", L"Section contains initialized data." },
		{ IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"IMAGE_SCN_CNT_UNINITIALIZED_DATA", L"Section contains uninitialized data." },
		{ IMAGE_SCN_LNK_OTHER, L"IMAGE_SCN_LNK_OTHER", L"Reserved." },
		{ IMAGE_SCN_LNK_INFO, L"IMAGE_SCN_LNK_INFO", L"Section contains comments or some other type of information." },
		{ IMAGE_SCN_LNK_REMOVE, L"IMAGE_SCN_LNK_REMOVE", L"Section contents will not become part of image." },
		{ IMAGE_SCN_LNK_COMDAT, L"IMAGE_SCN_LNK_COMDAT", L"Section contents comdat." },
		{ IMAGE_SCN_NO_DEFER_SPEC_EXC, L"IMAGE_SCN_NO_DEFER_SPEC_EXC", L"Reset speculative exceptions handling bits in the TLB entries for this section." },
		{ IMAGE_SCN_GPREL, L"IMAGE_SCN_GPREL", L"Section content can be accessed relative to GP" },
		{ IMAGE_SCN_MEM_FARDATA, L"IMAGE_SCN_MEM_FARDATA", L"" },
		{ IMAGE_SCN_MEM_PURGEABLE, L"IMAGE_SCN_MEM_PURGEABLE", L"" },
		{ IMAGE_SCN_MEM_16BIT, L"IMAGE_SCN_MEM_16BIT", L"" },
		{ IMAGE_SCN_MEM_LOCKED, L"IMAGE_SCN_MEM_LOCKED", L"" },
		{ IMAGE_SCN_MEM_PRELOAD, L"IMAGE_SCN_MEM_PRELOAD", L"" },
		{ IMAGE_SCN_ALIGN_1BYTES, L"IMAGE_SCN_ALIGN_1BYTES", L"" },
		{ IMAGE_SCN_ALIGN_2BYTES, L"IMAGE_SCN_ALIGN_2BYTES", L"" },
		{ IMAGE_SCN_ALIGN_4BYTES, L"IMAGE_SCN_ALIGN_4BYTES", L"" },
		{ IMAGE_SCN_ALIGN_8BYTES, L"IMAGE_SCN_ALIGN_8BYTES", L"" },
		{ IMAGE_SCN_ALIGN_16BYTES, L"IMAGE_SCN_ALIGN_16BYTES", L"Default alignment if no others are specified." },
		{ IMAGE_SCN_ALIGN_32BYTES, L"IMAGE_SCN_ALIGN_32BYTES", L"" },
		{ IMAGE_SCN_ALIGN_64BYTES, L"IMAGE_SCN_ALIGN_64BYTES", L"" },
		{ IMAGE_SCN_ALIGN_128BYTES, L"IMAGE_SCN_ALIGN_128BYTES", L"" },
		{ IMAGE_SCN_ALIGN_256BYTES, L"IMAGE_SCN_ALIGN_256BYTES", L"" },
		{ IMAGE_SCN_ALIGN_512BYTES, L"IMAGE_SCN_ALIGN_512BYTES", L"" },
		{ IMAGE_SCN_ALIGN_1024BYTES, L"IMAGE_SCN_ALIGN_1024BYTES", L"" },
		{ IMAGE_SCN_ALIGN_2048BYTES, L"IMAGE_SCN_ALIGN_2048BYTES", L"" },
		{ IMAGE_SCN_ALIGN_4096BYTES, L"IMAGE_SCN_ALIGN_4096BYTES", L"" },
		{ IMAGE_SCN_ALIGN_8192BYTES, L"IMAGE_SCN_ALIGN_8192BYTES", L"" },
		{ IMAGE_SCN_ALIGN_MASK, L"IMAGE_SCN_ALIGN_MASK", L"" },
		{ IMAGE_SCN_LNK_NRELOC_OVFL, L"IMAGE_SCN_LNK_NRELOC_OVFL", L"Section contains extended relocations." },
		{ IMAGE_SCN_MEM_DISCARDABLE, L"IMAGE_SCN_MEM_DISCARDABLE", L"Section can be discarded." },
		{ IMAGE_SCN_MEM_NOT_CACHED, L"IMAGE_SCN_MEM_NOT_CACHED", L"Section is not cachable." },
		{ IMAGE_SCN_MEM_NOT_PAGED, L"IMAGE_SCN_MEM_NOT_PAGED", L"Section is not pageable." },
		{ IMAGE_SCN_MEM_SHARED, L"IMAGE_SCN_MEM_SHARED", L"Section is shareable." },
		{ IMAGE_SCN_MEM_EXECUTE, L"IMAGE_SCN_MEM_EXECUTE", L"Section is executable." },
		{ IMAGE_SCN_MEM_READ, L"IMAGE_SCN_MEM_READ", L"Section is readable." },
		{ IMAGE_SCN_MEM_WRITE, L"IMAGE_SCN_MEM_WRITE", L"Section is writeable." },
		{ IMAGE_SCN_SCALE_INDEX, L"IMAGE_SCN_SCALE_INDEX", L"Tls index is scaled" },
	};

	for (const auto& chars : characteristicsList)
	{
		if ((characteristics & std::get<0>(chars)) == std::get<0>(chars))
		{
			PRINT_CHARACTERISTIC(prefix, chars);
		}
	}

	return std::wstring(out.str());
}

std::wstring parseFileCharacteristics(const std::wstring& prefix, DWORD characteristics)
{
	std::wstringstream out;
	std::vector<std::tuple<DWORD, std::wstring, std::wstring>> characteristicsList = {
		{IMAGE_FILE_RELOCS_STRIPPED, L"IMAGE_FILE_RELOCS_STRIPPED", L"Relocation info stripped from file." },
		{IMAGE_FILE_EXECUTABLE_IMAGE, L"IMAGE_FILE_EXECUTABLE_IMAGE", L"File is executable  (i.e. no unresolved external references)." },
		{IMAGE_FILE_LINE_NUMS_STRIPPED, L"IMAGE_FILE_LINE_NUMS_STRIPPED", L"Line nunbers stripped from file." },
		{IMAGE_FILE_LOCAL_SYMS_STRIPPED, L"IMAGE_FILE_LOCAL_SYMS_STRIPPED", L"Local symbols stripped from file." },
		{IMAGE_FILE_AGGRESIVE_WS_TRIM, L"IMAGE_FILE_AGGRESIVE_WS_TRIM", L"Aggressively trim working set" },
		{IMAGE_FILE_LARGE_ADDRESS_AWARE, L"IMAGE_FILE_LARGE_ADDRESS_AWARE", L"App can handle >2gb addresses" },
		{IMAGE_FILE_BYTES_REVERSED_LO, L"IMAGE_FILE_BYTES_REVERSED_LO", L"Bytes of machine word are reversed." },
		{IMAGE_FILE_32BIT_MACHINE, L"IMAGE_FILE_32BIT_MACHINE", L"32 bit word machine." },
		{IMAGE_FILE_DEBUG_STRIPPED, L"IMAGE_FILE_DEBUG_STRIPPED", L"Debugging info stripped from file in .DBG file" },
		{IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, L"IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", L"If Image is on removable media, copy and run from the swap file." },
		{IMAGE_FILE_NET_RUN_FROM_SWAP, L"IMAGE_FILE_NET_RUN_FROM_SWAP", L"If Image is on Net, copy and run from the swap file." },
		{IMAGE_FILE_SYSTEM, L"IMAGE_FILE_SYSTEM", L"System File." },
		{IMAGE_FILE_DLL, L"IMAGE_FILE_DLL", L"File is a DLL." },
		{IMAGE_FILE_UP_SYSTEM_ONLY, L"IMAGE_FILE_UP_SYSTEM_ONLY", L"File should only be run on a UP machine" },
		{IMAGE_FILE_BYTES_REVERSED_HI, L"IMAGE_FILE_BYTES_REVERSED_HI", L"Bytes of machine word are reversed." },
	};

	for (const auto& chars : characteristicsList)
	{
		if ((characteristics & std::get<0>(chars)) == std::get<0>(chars))
		{
			PRINT_CHARACTERISTIC(prefix, chars);
		}
	}

	return std::wstring(out.str());
}

std::wstring parseMachine(const std::wstring& prefix, DWORD machine)
{
	std::wstringstream out;
	std::vector<std::tuple<DWORD, std::wstring, std::wstring>> machinesList = {
		{ IMAGE_FILE_MACHINE_UNKNOWN, L"IMAGE_FILE_MACHINE_UNKNOWN", L"" },
		{ IMAGE_FILE_MACHINE_TARGET_HOST, L"IMAGE_FILE_MACHINE_TARGET_HOST", L"Useful for indicating we want to interact with the host and not a WoW guest." },
		{ IMAGE_FILE_MACHINE_I386, L"IMAGE_FILE_MACHINE_I386", L"Intel 386." },
		{ IMAGE_FILE_MACHINE_R3000, L"IMAGE_FILE_MACHINE_R3000", L"MIPS little-endian, 0x160 big-endian" },
		{ IMAGE_FILE_MACHINE_R4000, L"IMAGE_FILE_MACHINE_R4000", L"MIPS little-endian" },
		{ IMAGE_FILE_MACHINE_R10000, L"IMAGE_FILE_MACHINE_R10000", L"MIPS little-endian" },
		{ IMAGE_FILE_MACHINE_WCEMIPSV2, L"IMAGE_FILE_MACHINE_WCEMIPSV2", L"MIPS little-endian WCE v2" },
		{ IMAGE_FILE_MACHINE_ALPHA, L"IMAGE_FILE_MACHINE_ALPHA", L"Alpha_AXP" },
		{ IMAGE_FILE_MACHINE_SH3, L"IMAGE_FILE_MACHINE_SH3", L"SH3 little-endian" },
		{ IMAGE_FILE_MACHINE_SH3DSP, L"IMAGE_FILE_MACHINE_SH3DSP", L"" },
		{ IMAGE_FILE_MACHINE_SH3E, L"IMAGE_FILE_MACHINE_SH3E", L"SH3E little-endian" },
		{ IMAGE_FILE_MACHINE_SH4, L"IMAGE_FILE_MACHINE_SH4", L"SH4 little-endian" },
		{ IMAGE_FILE_MACHINE_SH5, L"IMAGE_FILE_MACHINE_SH5", L"SH5" },
		{ IMAGE_FILE_MACHINE_ARM, L"IMAGE_FILE_MACHINE_ARM", L"ARM Little-Endian" },
		{ IMAGE_FILE_MACHINE_THUMB, L"IMAGE_FILE_MACHINE_THUMB", L"ARM Thumb/Thumb-2 Little-Endian" },
		{ IMAGE_FILE_MACHINE_ARMNT, L"IMAGE_FILE_MACHINE_ARMNT", L"ARM Thumb-2 Little-Endian" },
		{ IMAGE_FILE_MACHINE_AM33, L"IMAGE_FILE_MACHINE_AM33", L"" },
		{ IMAGE_FILE_MACHINE_POWERPC, L"IMAGE_FILE_MACHINE_POWERPC", L"IBM PowerPC Little-Endian" },
		{ IMAGE_FILE_MACHINE_POWERPCFP, L"IMAGE_FILE_MACHINE_POWERPCFP", L"" },
		{ IMAGE_FILE_MACHINE_IA64, L"IMAGE_FILE_MACHINE_IA64", L"Intel 64" },
		{ IMAGE_FILE_MACHINE_MIPS16, L"IMAGE_FILE_MACHINE_MIPS16", L"MIPS" },
		{ IMAGE_FILE_MACHINE_ALPHA64, L"IMAGE_FILE_MACHINE_ALPHA64", L"ALPHA64" },
		{ IMAGE_FILE_MACHINE_MIPSFPU, L"IMAGE_FILE_MACHINE_MIPSFPU", L"MIPS" },
		{ IMAGE_FILE_MACHINE_MIPSFPU16, L"IMAGE_FILE_MACHINE_MIPSFPU16", L"MIPS" },
		{ IMAGE_FILE_MACHINE_AXP64, L"IMAGE_FILE_MACHINE_AXP64", L"" },
		{ IMAGE_FILE_MACHINE_TRICORE, L"IMAGE_FILE_MACHINE_TRICORE", L"Infineon" },
		{ IMAGE_FILE_MACHINE_CEF, L"IMAGE_FILE_MACHINE_CEF", L"" },
		{ IMAGE_FILE_MACHINE_EBC, L"IMAGE_FILE_MACHINE_EBC", L"EFI Byte Code" },
		{ IMAGE_FILE_MACHINE_AMD64, L"IMAGE_FILE_MACHINE_AMD64", L"AMD64 (K8)" },
		{ IMAGE_FILE_MACHINE_M32R, L"IMAGE_FILE_MACHINE_M32R", L"M32R little-endian" },
		{ IMAGE_FILE_MACHINE_ARM64, L"IMAGE_FILE_MACHINE_ARM64", L"ARM64 Little-Endian" },
		{ IMAGE_FILE_MACHINE_CEE, L"IMAGE_FILE_MACHINE_CEE", L"" },
	};

	if (machine == 0)
	{
		auto chars = machinesList[0];
		PRINT_CHARACTERISTIC(prefix, chars);
	}
	else 
	{
		for (const auto& chars : machinesList)
		{
			if (std::get<0>(chars) == 0) continue;
			if ((machine & std::get<0>(chars)) == std::get<0>(chars))
			{
				PRINT_CHARACTERISTIC(prefix, chars);
			}
		}
	}

	return std::wstring(out.str());
}

std::wstring parseTimestamp(const std::wstring& prefix, DWORD timestamp)
{
	if (!timestamp) return prefix;

	time_t t = static_cast<time_t>(timestamp);
	struct tm ts;
	localtime_s(&ts, &t);

	std::wostringstream woss;
	woss << std::put_time(&ts, L"%Y-%m-%d, %H:%M:%S.%z");
	return prefix + std::wstring(woss.str());
}

std::wstring parseSubsystem(const std::wstring& prefix, DWORD subsystem)
{
	std::wstringstream out;
	std::vector<std::tuple<DWORD, std::wstring, std::wstring>> characteristicsList = {
		{ IMAGE_SUBSYSTEM_UNKNOWN, L"IMAGE_SUBSYSTEM_UNKNOWN", L"Unknown subsystem." },
		{ IMAGE_SUBSYSTEM_NATIVE, L"IMAGE_SUBSYSTEM_NATIVE", L"Image doesn't require a subsystem." },
		{ IMAGE_SUBSYSTEM_WINDOWS_GUI, L"IMAGE_SUBSYSTEM_WINDOWS_GUI", L"Image runs in the Windows GUI subsystem." },
		{ IMAGE_SUBSYSTEM_WINDOWS_CUI, L"IMAGE_SUBSYSTEM_WINDOWS_CUI", L"Image runs in the Windows character subsystem." },
		{ IMAGE_SUBSYSTEM_OS2_CUI, L"IMAGE_SUBSYSTEM_OS2_CUI", L"image runs in the OS/2 character subsystem." },
		{ IMAGE_SUBSYSTEM_POSIX_CUI, L"IMAGE_SUBSYSTEM_POSIX_CUI", L"image runs in the Posix character subsystem." },
		{ IMAGE_SUBSYSTEM_NATIVE_WINDOWS, L"IMAGE_SUBSYSTEM_NATIVE_WINDOWS", L"image is a native Win9x driver." },
		{ IMAGE_SUBSYSTEM_WINDOWS_CE_GUI, L"IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", L"Image runs in the Windows CE subsystem." },
		{ IMAGE_SUBSYSTEM_EFI_APPLICATION, L"IMAGE_SUBSYSTEM_EFI_APPLICATION", L"" },
		{ IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, L"IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", L" " },
		{ IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, L"IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", L"" },
		{ IMAGE_SUBSYSTEM_EFI_ROM, L"IMAGE_SUBSYSTEM_EFI_ROM", L"" },
		{ IMAGE_SUBSYSTEM_XBOX, L"IMAGE_SUBSYSTEM_XBOX", L"" },
		{ IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION, L"IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", L"" },
		{ IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG, L"IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG", L"" },
	};

	if (subsystem == 0)
	{
		auto chars = characteristicsList[0];
		PRINT_CHARACTERISTIC(prefix, chars);
	}
	else
	{
		for (const auto& chars : characteristicsList)
		{
			if (std::get<0>(chars) == 0) continue;
			if ((subsystem & std::get<0>(chars)) == std::get<0>(chars))
			{
				PRINT_CHARACTERISTIC(prefix, chars);
			}
		}
	}

	return std::wstring(out.str());
}

std::wstring parseDllCharacteristics(const std::wstring& prefix, DWORD characteristics)
{
	std::wstringstream out;
	std::vector<std::tuple<DWORD, std::wstring, std::wstring>> characteristicsList = {
		{ 1, L"IMAGE_LIBRARY_PROCESS_INIT", L"Reserved." },
		{ 2, L"IMAGE_LIBRARY_PROCESS_TERM", L"Reserved." },
		{ 4, L"IMAGE_LIBRARY_THREAD_INIT", L"Reserved." },
		{ 8, L"IMAGE_LIBRARY_THREAD_TERM", L"Reserved." },
		{ IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, L"IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", L"Image can handle a high entropy 64-bit virtual address space." },
		{ IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, L"IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", L"DLL can move." },
		{ IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, L"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", L"Code Integrity Image" },
		{ IMAGE_DLLCHARACTERISTICS_NX_COMPAT, L"IMAGE_DLLCHARACTERISTICS_NX_COMPAT", L"Image is NX compatible" },
		{ IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, L"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", L"Image understands isolation and doesn't want it" },
		{ IMAGE_DLLCHARACTERISTICS_NO_SEH, L"IMAGE_DLLCHARACTERISTICS_NO_SEH", L"Image does not use SEH.  No SE handler may reside in this image" },
		{ IMAGE_DLLCHARACTERISTICS_NO_BIND, L"IMAGE_DLLCHARACTERISTICS_NO_BIND", L"Do not bind this image." },
		{ IMAGE_DLLCHARACTERISTICS_APPCONTAINER, L"IMAGE_DLLCHARACTERISTICS_APPCONTAINER", L"Image should execute in an AppContainer" },
		{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, L"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", L"Driver uses WDM model" },
		{ IMAGE_DLLCHARACTERISTICS_GUARD_CF, L"IMAGE_DLLCHARACTERISTICS_GUARD_CF", L"Image supports Control Flow Guard." },
		{ IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, L"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", L"" },
	};

	for (const auto& chars : characteristicsList)
	{
		if ((characteristics & std::get<0>(chars)) == std::get<0>(chars))
		{
			PRINT_CHARACTERISTIC(prefix, chars);
		}
	}

	return std::wstring(out.str());
}