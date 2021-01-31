// peParser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "..\..\PE-lib\PE.h"
#include "Hexdump.hpp"
#include "utils.h"


#define PRINT_FIELD2(fieldName, value, _type, typeWidth)  std::wcout << std::left << L"\t" \
	<< std::setfill(L' ') << std::setw(30) << fieldName << L" : " \
	<< ((static_cast<ULONGLONG>(value) >= 10)? L"0x" : L"") << std::setfill(L' ') \
	<< std::setw(2*typeWidth) << std::hex << (_type) value \
	<< std::wstring((2*sizeof(ULONGLONG) - 2*typeWidth + 6 + 2*(static_cast<ULONGLONG>(value) < 10)), L' ') \
	<< L"( " << std::dec << (_type) value << L" )" << std::endl;

#define PRINT_FIELD(fieldName, value, _type)  PRINT_FIELD2(fieldName, value, _type, sizeof(_type));

#define PRINT_LINE std::wcout << std::endl << std::wstring(50, L'-') << std::endl;

template<typename T>
void printNumbersArray(std::wstring fieldName, T* elements, size_t count)
{
	size_t width = 0;
	size_t typeWidth = sizeof(T);

	std::wostringstream woss;
	std::wostringstream wossline;

	wossline << std::left << L"\t" << std::setfill(L' ') << std::setw(30) << fieldName << L" : ";

	for (size_t i = 0; i < count; i++)
	{
		auto value = elements[i];
		auto f = ((static_cast<ULONGLONG>(value) < 10) ? L"0x" : L"  ");

		wossline << std::left << f << std::hex << value;
		if(i < count-1) wossline << L", ";

		if (wossline.str().length() > 80)
		{
			woss << wossline.str();
			
			if (i < count - 1)
			{
				woss << std::endl;
				wossline.str(std::wstring(36, L' '));
			}
			else
			{
				wossline.str(L"");
			}
		}
	}

	woss << wossline.str();
	std::wcout << woss.str() << std::endl;
}

void dumpDosHeaders(PE& pe)
{
	std::wcout << L"\nIMAGE_DOS_HEADER:\n\n";
	PRINT_FIELD("e_magic", pe.imgDosHdr.e_magic, WORD);
	PRINT_FIELD("e_cblp", pe.imgDosHdr.e_cblp, WORD);
	PRINT_FIELD("e_cp", pe.imgDosHdr.e_cp, WORD);
	PRINT_FIELD("e_crlc", pe.imgDosHdr.e_crlc, WORD);
	PRINT_FIELD("e_cparhdr", pe.imgDosHdr.e_cparhdr, WORD);
	PRINT_FIELD("e_minalloc", pe.imgDosHdr.e_minalloc, WORD);
	PRINT_FIELD("e_maxalloc", pe.imgDosHdr.e_maxalloc, WORD);
	PRINT_FIELD("e_ss", pe.imgDosHdr.e_ss, WORD);
	PRINT_FIELD("e_sp", pe.imgDosHdr.e_sp, WORD);
	PRINT_FIELD("e_csum", pe.imgDosHdr.e_csum, WORD);
	PRINT_FIELD("e_ip", pe.imgDosHdr.e_ip, WORD);
	PRINT_FIELD("e_cs", pe.imgDosHdr.e_cs, WORD);
	PRINT_FIELD("e_lfarlc", pe.imgDosHdr.e_lfarlc, WORD);
	PRINT_FIELD("e_ovno", pe.imgDosHdr.e_ovno, WORD);
	printNumbersArray(L"e_res", pe.imgDosHdr.e_res, _countof(pe.imgDosHdr.e_res));
	PRINT_FIELD("e_oemid", pe.imgDosHdr.e_oemid, WORD);
	PRINT_FIELD("e_oeminfo", pe.imgDosHdr.e_oeminfo, WORD);
	printNumbersArray(L"e_res2", pe.imgDosHdr.e_res2, _countof(pe.imgDosHdr.e_res2));
	PRINT_FIELD("e_lfanew", pe.imgDosHdr.e_lfanew, WORD);
}

void dumpNtHeaders(PE& pe)
{
	if (pe.isArch86())
	{
		std::wcout << L"IMAGE_NT_HEADERS32:\n\n";
		PRINT_FIELD("Signature", pe.imgNtHdrs32.Signature, DWORD);

		std::wcout << L"\nIMAGE_FILE_HEADER:\n\n";

		PRINT_FIELD("Machine", pe.imgNtHdrs32.FileHeader.Machine, WORD);
		std::wcout << parseMachine(L"\t\t\t\t- ", pe.imgNtHdrs32.FileHeader.Machine);

		PRINT_FIELD("NumberOfSections", pe.imgNtHdrs32.FileHeader.NumberOfSections, WORD);
		PRINT_FIELD("TimeDateStamp", pe.imgNtHdrs32.FileHeader.TimeDateStamp, DWORD);
		if(pe.imgNtHdrs32.FileHeader.TimeDateStamp)
			std::wcout << parseTimestamp(std::wstring(40, L' ') + L'(', pe.imgNtHdrs32.FileHeader.TimeDateStamp) << L')' << std::endl;

		PRINT_FIELD("PointerToSymbolTable", pe.imgNtHdrs32.FileHeader.PointerToSymbolTable, DWORD);
		PRINT_FIELD("NumberOfSymbols", pe.imgNtHdrs32.FileHeader.NumberOfSymbols, DWORD);
		PRINT_FIELD("SizeOfOptionalHeader", pe.imgNtHdrs32.FileHeader.SizeOfOptionalHeader, WORD);
		PRINT_FIELD("Characteristics", pe.imgNtHdrs32.FileHeader.Characteristics, WORD);
		std::wcout << parseFileCharacteristics(L"\t\t\t\t- ", pe.imgNtHdrs32.FileHeader.Characteristics);

		std::wcout << L"\nIMAGE_OPTIONAL_HEADER32:\n\n";

		PRINT_FIELD("Magic", pe.imgNtHdrs32.OptionalHeader.Magic, WORD);
		PRINT_FIELD("MajorLinkerVersion", pe.imgNtHdrs32.OptionalHeader.MajorLinkerVersion, BYTE);
		PRINT_FIELD("MinorLinkerVersion", pe.imgNtHdrs32.OptionalHeader.MinorLinkerVersion, BYTE);
		PRINT_FIELD("SizeOfCode", pe.imgNtHdrs32.OptionalHeader.SizeOfCode, DWORD);
		PRINT_FIELD("SizeOfInitializedData", pe.imgNtHdrs32.OptionalHeader.SizeOfInitializedData, DWORD);
		PRINT_FIELD("SizeOfUninitializedData", pe.imgNtHdrs32.OptionalHeader.SizeOfUninitializedData, DWORD);
		PRINT_FIELD("AddressOfEntryPoint", pe.imgNtHdrs32.OptionalHeader.AddressOfEntryPoint, DWORD);
		PRINT_FIELD("BaseOfCode", pe.imgNtHdrs32.OptionalHeader.BaseOfCode, DWORD);
		PRINT_FIELD("BaseOfData", pe.imgNtHdrs32.OptionalHeader.BaseOfData, DWORD);
		PRINT_FIELD("ImageBase", pe.imgNtHdrs32.OptionalHeader.ImageBase, DWORD);
		PRINT_FIELD("SectionAlignment", pe.imgNtHdrs32.OptionalHeader.SectionAlignment, DWORD);
		PRINT_FIELD("FileAlignment", pe.imgNtHdrs32.OptionalHeader.FileAlignment, DWORD);
		PRINT_FIELD("MajorOperatingSystemVersion", pe.imgNtHdrs32.OptionalHeader.MajorOperatingSystemVersion, WORD);
		PRINT_FIELD("MinorOperatingSystemVersion", pe.imgNtHdrs32.OptionalHeader.MinorOperatingSystemVersion, WORD);
		PRINT_FIELD("MajorImageVersion", pe.imgNtHdrs32.OptionalHeader.MajorImageVersion, WORD);
		PRINT_FIELD("MinorImageVersion", pe.imgNtHdrs32.OptionalHeader.MinorImageVersion, WORD);
		PRINT_FIELD("MajorSubsystemVersion", pe.imgNtHdrs32.OptionalHeader.MajorSubsystemVersion, WORD);
		PRINT_FIELD("MinorSubsystemVersion", pe.imgNtHdrs32.OptionalHeader.MinorSubsystemVersion, WORD);
		PRINT_FIELD("Win32VersionValue", pe.imgNtHdrs32.OptionalHeader.Win32VersionValue, DWORD);
		PRINT_FIELD("SizeOfImage", pe.imgNtHdrs32.OptionalHeader.SizeOfImage, DWORD);
		PRINT_FIELD("SizeOfHeaders", pe.imgNtHdrs32.OptionalHeader.SizeOfHeaders, DWORD);
		PRINT_FIELD("CheckSum", pe.imgNtHdrs32.OptionalHeader.CheckSum, DWORD);
		PRINT_FIELD("Subsystem", pe.imgNtHdrs32.OptionalHeader.Subsystem, WORD);
		std::wcout << parseSubsystem(L"\t\t\t\t- ", pe.imgNtHdrs32.OptionalHeader.Subsystem);

		PRINT_FIELD("DllCharacteristics", pe.imgNtHdrs32.OptionalHeader.DllCharacteristics, WORD);
		std::wcout << parseDllCharacteristics(L"\t\t\t\t- ", pe.imgNtHdrs32.OptionalHeader.DllCharacteristics);

		PRINT_FIELD("SizeOfStackReserve", pe.imgNtHdrs32.OptionalHeader.SizeOfStackReserve, DWORD);
		PRINT_FIELD("SizeOfStackCommit", pe.imgNtHdrs32.OptionalHeader.SizeOfStackCommit, DWORD);
		PRINT_FIELD("SizeOfHeapReserve", pe.imgNtHdrs32.OptionalHeader.SizeOfHeapReserve, DWORD);
		PRINT_FIELD("SizeOfHeapCommit", pe.imgNtHdrs32.OptionalHeader.SizeOfHeapCommit, DWORD);
		PRINT_FIELD("LoaderFlags", pe.imgNtHdrs32.OptionalHeader.LoaderFlags, DWORD);
		PRINT_FIELD("NumberOfRvaAndSizes", pe.imgNtHdrs32.OptionalHeader.NumberOfRvaAndSizes, DWORD);
	}
	else
	{
		std::wcout << L"IMAGE_NT_HEADERS64:\n\n";
		PRINT_FIELD("Signature", pe.imgNtHdrs64.Signature, DWORD);

		std::wcout << L"\nIMAGE_FILE_HEADER:\n\n";

		PRINT_FIELD("Machine", pe.imgNtHdrs64.FileHeader.Machine, WORD);
		std::wcout << parseMachine(L"\t\t\t\t- ", pe.imgNtHdrs64.FileHeader.Machine);

		PRINT_FIELD("NumberOfSections", pe.imgNtHdrs64.FileHeader.NumberOfSections, WORD);
		PRINT_FIELD("TimeDateStamp", pe.imgNtHdrs64.FileHeader.TimeDateStamp, DWORD);
		if (pe.imgNtHdrs64.FileHeader.TimeDateStamp)
			std::wcout << parseTimestamp(std::wstring(40, L' ')+L'(', pe.imgNtHdrs64.FileHeader.TimeDateStamp) << L')' << std::endl;

		PRINT_FIELD("PointerToSymbolTable", pe.imgNtHdrs64.FileHeader.PointerToSymbolTable, DWORD);
		PRINT_FIELD("NumberOfSymbols", pe.imgNtHdrs64.FileHeader.NumberOfSymbols, DWORD);
		PRINT_FIELD("SizeOfOptionalHeader", pe.imgNtHdrs64.FileHeader.SizeOfOptionalHeader, WORD);
		PRINT_FIELD("Characteristics", pe.imgNtHdrs64.FileHeader.Characteristics, WORD);
		std::wcout << parseFileCharacteristics(L"\t\t\t\t- ", pe.imgNtHdrs64.FileHeader.Characteristics);

		std::wcout << L"\nIMAGE_OPTIONAL_HEADER64:\n\n";

		PRINT_FIELD("Magic", pe.imgNtHdrs64.OptionalHeader.Magic, WORD);
		PRINT_FIELD("MajorLinkerVersion", pe.imgNtHdrs64.OptionalHeader.MajorLinkerVersion, BYTE);
		PRINT_FIELD("MinorLinkerVersion", pe.imgNtHdrs64.OptionalHeader.MinorLinkerVersion, BYTE);
		PRINT_FIELD("SizeOfCode", pe.imgNtHdrs64.OptionalHeader.SizeOfCode, DWORD);
		PRINT_FIELD("SizeOfInitializedData", pe.imgNtHdrs64.OptionalHeader.SizeOfInitializedData, DWORD);
		PRINT_FIELD("SizeOfUninitializedData", pe.imgNtHdrs64.OptionalHeader.SizeOfUninitializedData, DWORD);
		PRINT_FIELD("AddressOfEntryPoint", pe.imgNtHdrs64.OptionalHeader.AddressOfEntryPoint, DWORD);
		PRINT_FIELD("BaseOfCode", pe.imgNtHdrs64.OptionalHeader.BaseOfCode, DWORD);
		PRINT_FIELD("ImageBase", pe.imgNtHdrs64.OptionalHeader.ImageBase, ULONGLONG);
		PRINT_FIELD("SectionAlignment", pe.imgNtHdrs64.OptionalHeader.SectionAlignment, DWORD);
		PRINT_FIELD("FileAlignment", pe.imgNtHdrs64.OptionalHeader.FileAlignment, DWORD);
		PRINT_FIELD("MajorOperatingSystemVersion", pe.imgNtHdrs64.OptionalHeader.MajorOperatingSystemVersion, WORD);
		PRINT_FIELD("MinorOperatingSystemVersion", pe.imgNtHdrs64.OptionalHeader.MinorOperatingSystemVersion, WORD);
		PRINT_FIELD("MajorImageVersion", pe.imgNtHdrs64.OptionalHeader.MajorImageVersion, WORD);
		PRINT_FIELD("MinorImageVersion", pe.imgNtHdrs64.OptionalHeader.MinorImageVersion, WORD);
		PRINT_FIELD("MajorSubsystemVersion", pe.imgNtHdrs64.OptionalHeader.MajorSubsystemVersion, WORD);
		PRINT_FIELD("MinorSubsystemVersion", pe.imgNtHdrs64.OptionalHeader.MinorSubsystemVersion, WORD);
		PRINT_FIELD("Win32VersionValue", pe.imgNtHdrs64.OptionalHeader.Win32VersionValue, DWORD);
		PRINT_FIELD("SizeOfImage", pe.imgNtHdrs64.OptionalHeader.SizeOfImage, DWORD);
		PRINT_FIELD("SizeOfHeaders", pe.imgNtHdrs64.OptionalHeader.SizeOfHeaders, DWORD);
		PRINT_FIELD("CheckSum", pe.imgNtHdrs64.OptionalHeader.CheckSum, DWORD);
		PRINT_FIELD("Subsystem", pe.imgNtHdrs64.OptionalHeader.Subsystem, WORD);
		std::wcout << parseSubsystem(L"\t\t\t\t- ", pe.imgNtHdrs64.OptionalHeader.Subsystem);

		PRINT_FIELD("DllCharacteristics", pe.imgNtHdrs64.OptionalHeader.DllCharacteristics, WORD);
		std::wcout << parseDllCharacteristics(L"\t\t\t\t- ", pe.imgNtHdrs64.OptionalHeader.DllCharacteristics);

		PRINT_FIELD("SizeOfStackReserve", pe.imgNtHdrs64.OptionalHeader.SizeOfStackReserve, ULONGLONG);
		PRINT_FIELD("SizeOfStackCommit", pe.imgNtHdrs64.OptionalHeader.SizeOfStackCommit, ULONGLONG);
		PRINT_FIELD("SizeOfHeapReserve", pe.imgNtHdrs64.OptionalHeader.SizeOfHeapReserve, ULONGLONG);
		PRINT_FIELD("SizeOfHeapCommit", pe.imgNtHdrs64.OptionalHeader.SizeOfHeapCommit, ULONGLONG);
		PRINT_FIELD("LoaderFlags", pe.imgNtHdrs64.OptionalHeader.LoaderFlags, DWORD);
		PRINT_FIELD("NumberOfRvaAndSizes", pe.imgNtHdrs64.OptionalHeader.NumberOfRvaAndSizes, DWORD);
	}

	std::wcout << L"\nDataDirectory:\n\n";

	std::vector<std::wstring> dataDirectoryNames = {
		L"Export Directory",
		L"Import Directory",
		L"Resource Directory",
		L"Exception Directory",
		L"Security Directory",
		L"Base Relocation Table",
		L"Debug Directory",
		L"Architecture Specific Data",
		L"RVA of GP",
		L"TLS Directory",
		L"Load Configuration Directory",
		L"Bound Imports Directory",
		L"Import Address Table",
		L"Delay Load Import Descriptors",
		L"COM Runtime descriptor",
		L""
	};

	for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES - 1; i++)
	{
		IMAGE_DATA_DIRECTORY dir;
		if (pe.isArch86())
		{
			dir = pe.imgNtHdrs32.OptionalHeader.DataDirectory[i];
		}
		else
		{
			dir = pe.imgNtHdrs64.OptionalHeader.DataDirectory[i];
		}

		std::wcout << L"\t" << std::left << std::setfill(L' ') << std::setw(2) << i << L". "
			<< std::left << std::setfill(L' ') << std::setw(35) << dataDirectoryNames[i]
			<< std::setw(13) << L"VirtualAddress:" << L"  0x" << std::hex << std::setw(8) << std::setfill(L' ')
			<< dir.VirtualAddress
			<< L"  Size:  0x" << std::hex << std::setfill(L' ') << std::setw(8)
			<< dir.Size
			<< L"  (" << std::dec << dir.Size << L")" << std::endl;
	}
}

void dumpSections(PE& pe, bool fast)
{
	std::wcout << L"IMAGE_SECTION_HEADERS (" << pe.GetSectionsCount() << L"):" << std::endl << std::endl;

	for (size_t i = 0; i < pe.GetSectionsCount(); i++)
	{
		auto sect = pe.GetSection(i);
		std::string sectName(sect.szSectionName);
		std::wstring wsectName(sectName.begin(), sectName.end());

		std::wstring prot = L"";

		if ((sect.s.Characteristics & IMAGE_SCN_MEM_READ) != 0)    prot += L"R";
		if ((sect.s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0)   prot += L"W";
		if ((sect.s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) prot += L"X";

		std::vector<uint8_t> buf;
		float entropy = 0;

		if (!fast)
		{
			buf = pe.ReadSection(sect);
			if (!buf.empty())
			{
				entropy = ShannonEntropy(&buf[0], buf.size());
			}
		}

		std::wcout << L"\t" << i+1 << L". Section: (" << wsectName << L"), protection: (" << prot 
			<< L"), section's entropy: (" << entropy << L")" << std::endl;
		std::wcout << L"\t"; PRINT_FIELD("VirtualAddress", sect.s.VirtualAddress, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("Misc.VirtualSize", sect.s.Misc.VirtualSize, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("SizeOfRawData", sect.s.SizeOfRawData, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("PointerToRawData", sect.s.PointerToRawData, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("PointerToRelocations", sect.s.PointerToRelocations, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("PointerToLinenumbers", sect.s.PointerToLinenumbers, DWORD);
		std::wcout << L"\t"; PRINT_FIELD("NumberOfRelocations", sect.s.NumberOfRelocations, WORD);
		std::wcout << L"\t"; PRINT_FIELD("NumberOfLinenumbers", sect.s.NumberOfLinenumbers, WORD);
		std::wcout << L"\t"; PRINT_FIELD("Characteristics", sect.s.Characteristics, DWORD);
		std::wcout << parseSectionCharacteristics(L"\t\t\t\t- ", sect.s.Characteristics);

		if (!buf.empty())
		{
			std::wcout << std::endl;
			std::wcout << getHexdump(&buf[0], min(64, buf.size()));
		}

		std::wcout << std::endl;
	}
}

void dumpImports(PE& pe)
{
	if (pe.vImports.empty() && pe.vImportDescriptors.empty()) return;

	std::wcout << L"IMPORTED FUNCTIONS (" << pe.vImports.size() << L"):" << std::endl << std::endl;

	size_t maxlen = 0;

	for (const auto& imp : pe.vImports)
	{
		std::string n(imp.szFunction);
		if (n.length() > maxlen) maxlen = n.length();
	}

	maxlen += 2;

	size_t i = 0;
	for (const auto& desc : pe.vImportDescriptors)
	{
		std::string sn(desc.szName);
		std::wstring name(sn.begin(), sn.end());

		std::wcout << L"\t" << std::dec << ++i << L". IMAGE_IMPORT_DESCRIPTOR: (" << name << L"), number of functions: " 
			<< desc.vImports.size() << std::endl;

		std::wcout << L"\t"; PRINT_FIELD(L"Characteristics", desc.d.Characteristics, DWORD);
		std::wcout << L"\t"; PRINT_FIELD(L"TimeDateStamp", desc.d.TimeDateStamp, DWORD);
		if(desc.d.TimeDateStamp != 0) 
			std::wcout << parseTimestamp(std::wstring(48, L' ') + L'(', desc.d.TimeDateStamp) << L')' << std::endl;

		std::wcout << L"\t"; PRINT_FIELD(L"ForwarderChain", desc.d.ForwarderChain, DWORD);
		std::wcout << L"\t"; PRINT_FIELD(L"Name", desc.d.Name, DWORD);
		std::wcout << L"\t"; PRINT_FIELD(L"FirstThunk", desc.d.FirstThunk, DWORD);
		std::wcout << std::endl;

		if (!pe.vImports.empty())
		{
			std::wcout << L" ";
			std::wcout << std::setw(5) << std::setfill(L' ') << std::right << L" # " << " | ";
			std::wcout << std::setw(4) << std::setfill(L'0') << std::right << L"Ord." << L" | ";
			std::wcout << std::left << std::setw(maxlen) << std::setfill(L' ') << L"Name" << " | ";
			std::wcout << std::setw(sizeof(void*) * 2 + 4) << std::setfill(L' ') << L"PtrValueVA" << " | ";
			std::wcout << std::setw(9) << std::setfill(L' ') << L"PtrValueRVA" << " | ";
			std::wcout << std::setw(9) << std::setfill(L' ') << L"ThunkRVA" << std::endl;
			std::wcout << L" " << std::wstring(maxlen + 63, L'-');
			std::wcout << std::endl;

			size_t j = 0;
			for (const auto& imp : desc.vImports)
			{
				sn = std::string(imp.szFunction);
				name = std::wstring(sn.begin(), sn.end());

				std::wcout << L" ";
				std::wcout << std::setw(5) << std::setfill(L' ') << std::right << std::dec << ++j << " | ";
				std::wcout << std::setw(4) << std::setfill(L'0') << std::right << std::hex << imp.wOrdinal << L" | ";
				std::wcout << std::left << std::setw(maxlen) << std::setfill(L' ') << name << " | ";
				std::wcout << L"0x" << std::setw(sizeof(void*) * 2 + 2) << std::setfill(L' ') << std::hex << imp.dwPtrValueVA << " | ";
				std::wcout << L"0x" << std::setw(9) << std::setfill(L' ') << std::hex << imp.dwPtrValueRVA << " | ";
				std::wcout << L"0x" << std::setw(9) << std::setfill(L' ') << std::hex << imp.dwThunkRVA;
				std::wcout << std::endl;
			}
		}

		std::wcout << std::endl << std::endl;
	}
}

void dumpExports(PE& pe)
{
	size_t foo = 0;
	
	if (pe.isArch86())
	{
		foo = pe.imgNtHdrs32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}
	else
	{
		foo = pe.imgNtHdrs64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	if (foo == 0) return;

	std::wcout << L"EXPORTED FUNCTIONS (" << std::dec << pe.vExports.size() << L"):" << std::endl << std::endl;

	size_t maxlen = 0;

	for (const auto& imp : pe.vExports)
	{
		std::string n(imp.szFunction);
		if (n.length() > maxlen) maxlen = n.length();
	}

	maxlen += 2;


	std::wcout << L"\tIMAGE_EXPORT_DIRECTORY: " << std::endl;

	std::wcout << L"\t"; PRINT_FIELD(L"Characteristics", pe.imgExportDirectory.d.Characteristics, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"TimeDateStamp", pe.imgExportDirectory.d.TimeDateStamp, DWORD);
	if (pe.imgExportDirectory.d.TimeDateStamp != 0)
		std::wcout << parseTimestamp(std::wstring(48, L' ') + L'(', pe.imgExportDirectory.d.TimeDateStamp) << L')' << std::endl;

	std::wcout << L"\t"; PRINT_FIELD(L"MajorVersion", pe.imgExportDirectory.d.MajorVersion, WORD);
	std::wcout << L"\t"; PRINT_FIELD(L"MinorVersion", pe.imgExportDirectory.d.MinorVersion, WORD);
	std::wcout << L"\t"; PRINT_FIELD(L"Name", pe.imgExportDirectory.d.Name, DWORD);

	std::string names(pe.imgExportDirectory.szName);
	std::wstring name(names.begin(), names.end());

	std::wcout << std::wstring(48, L' ') << L' (' << name << L')' << std::endl;

	std::wcout << L"\t"; PRINT_FIELD(L"Base", pe.imgExportDirectory.d.Base, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"NumberOfFunctions", pe.imgExportDirectory.d.NumberOfFunctions, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"NumberOfNames", pe.imgExportDirectory.d.NumberOfNames, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"AddressOfFunctions", pe.imgExportDirectory.d.AddressOfFunctions, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"AddressOfNames", pe.imgExportDirectory.d.AddressOfNames, DWORD);
	std::wcout << L"\t"; PRINT_FIELD(L"AddressOfNameOrdinals", pe.imgExportDirectory.d.AddressOfNameOrdinals, DWORD);
	std::wcout << std::endl;

	if (!pe.vExports.empty())
	{
		std::wcout << L" ";
		std::wcout << std::setw(5) << std::setfill(L' ') << std::right << L" # " << " | ";
		std::wcout << std::setw(4) << std::setfill(L'0') << std::right << L"Ord." << L" | ";
		std::wcout << std::left << std::setw(maxlen) << std::setfill(L' ') << L"Name" << " | ";
		std::wcout << std::setw(sizeof(void*) * 2 + 4) << std::setfill(L' ') << L"PtrValueVA" << " | ";
		std::wcout << std::setw(9) << std::setfill(L' ') << L"PtrValueRVA" << " | ";
		std::wcout << std::setw(9) << std::setfill(L' ') << L"ThunkRVA" << std::endl;
		std::wcout << L" " << std::wstring(maxlen + 63, L'-');
		std::wcout << std::endl;

		size_t j = 0;
		for (const auto& imp : pe.vExports)
		{
			auto sn = std::string(imp.szFunction);
			name = std::wstring(sn.begin(), sn.end());

			std::wcout << L" ";
			std::wcout << std::setw(5) << std::setfill(L' ') << std::right << std::dec << ++j << " | ";
			std::wcout << std::setw(4) << std::setfill(L'0') << std::right << std::hex << imp.wOrdinal << L" | ";
			std::wcout << std::left << std::setw(maxlen) << std::setfill(L' ') << name << " | ";
			std::wcout << L"0x" << std::setw(sizeof(void*) * 2 + 2) << std::setfill(L' ') << std::hex << imp.dwPtrValue << " | ";
			std::wcout << L"0x" << std::setw(9) << std::setfill(L' ') << std::hex << imp.dwPtrValueRVA << " | ";
			std::wcout << L"0x" << std::setw(9) << std::setfill(L' ') << std::hex << imp.dwThunkRVA;
			std::wcout << std::endl;
		}
	}

	std::wcout << std::endl << std::endl;
}

void parsePeFile(PE& pe)
{
	PRINT_LINE;
	dumpDosHeaders(pe);

	PRINT_LINE;
	std::wcout << L"DOS STUB Dump (" << pe.lpDOSStub.size() << L"):" << std::endl << std::endl;
	std::wcout << getHexdump(pe.lpDOSStub.data(), pe.lpDOSStub.size()) << std::endl;
	
	PRINT_LINE;
	dumpNtHeaders(pe);

	PRINT_LINE;
#ifdef _DEBUG
	dumpSections(pe, true);
#else
	dumpSections(pe, false);
#endif

	PRINT_LINE;
	dumpImports(pe);
	dumpExports(pe);
}

void analyseFile(std::wstring filePath)
{
	if (filePath[0] == L'"' && filePath.back() == L'"')
	{
		filePath = filePath.substr(1, filePath.length() - 1);
	}

    PE pe;
    if (!pe.AnalyseFile(filePath, true))
    {
        std::wcout << L"[!] Could not analyse input file! Error: " << pe.GetErrorString() << std::endl;
        return;
    }

	parsePeFile(pe);
}

void analyseDump(std::wstring filePath)
{
	if (filePath[0] == L'"' && filePath.back() == L'"')
	{
		filePath = filePath.substr(1, filePath.length() - 1);
	}

	PE pe;
	if (!pe.AnalyseDump(filePath, true))
	{
		std::wcout << L"[!] Could not analyse input dump file! Error: " << pe.GetErrorString() << std::endl;
		return;
	}

	parsePeFile(pe);
}

void analyseProcess(DWORD pid)
{
	setPrivilege(SE_DEBUG_NAME, true, nullptr);

	PE pe;
	if (!pe.AnalyseProcess(pid, true))
	{
		std::wcout << L"[!] Could not analyse specified process! Error: " << pe.GetErrorString() << std::endl;
		return;
	}

	parsePeFile(pe);
}

void analyseProcessModule(DWORD pid, ULONGLONG address)
{
	setPrivilege(SE_DEBUG_NAME, true, nullptr);

	PE pe;
	if (!pe.AnalyseProcessModule(pid, reinterpret_cast<HMODULE>(address), true))
	{
		std::wcout << L"[!] Could not analyse process' module! Error: " << pe.GetErrorString() << std::endl;
		return;
	}

	parsePeFile(pe);
}

void analyseProcessMemory(DWORD pid, ULONGLONG address)
{
	setPrivilege(SE_DEBUG_NAME, true, nullptr);

	PE pe;
	if (!pe.AnalyseMemory(pid, reinterpret_cast<LPBYTE>(address), 0, true, false))
	{
		std::wcout << L"[!] Could not analyse process' memory! Error: " << pe.GetErrorString() << std::endl;
		return;
	}

	parsePeFile(pe);
}
void analyseProcessModule(DWORD pid, std::wstring moduleName)
{
	setPrivilege(SE_DEBUG_NAME, true, nullptr);

	PE pe;
    if (!pe.AnalyseProcessModule(pid, moduleName, true))
	{
		std::wcout << L"[!] Could not analyse process' module! Error: " << pe.GetErrorString() << std::endl;
		return;
	}

	parsePeFile(pe);
}

void usage()
{
	std::wcout << LR"FOOBAR(
Usage:

    1) Analyse file:
    cmd> peParser file <filepath>

    2) Analyse process:
    cmd> peParser process <PID>

    3) Analyse process' module:
    cmd> peParser module <PID> <moduleName|0xModuleAddress>

    4) Analyse dump file:
    cmd> peParser dump <filepath>

    5) Analyse injected, not-mapped (MEM_PRIVATE) shellcode:
    cmd> peParser memory <PID> <address>

)FOOBAR";
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    std::string operation(argv[1]);

    if (operation == "file")
    {
        if (argc < 3)
        {
            usage();
            return 1;
        }

        std::string p(argv[2]);
        std::wstring filepath(p.begin(), p.end());

        std::wcout << L"Analysing file: \"" << filepath << L"\"...\n";
        analyseFile(filepath);
    }
	else if (operation == "process")
	{
		if (argc < 3)
		{
			usage();
			return 1;
		}

        std::string p(argv[2]);
        DWORD pid = stoi(p);

		std::wcout << L"Analysing process with PID: " << pid << L" - ";
		wchar_t buf[1024] = L"";
		if (getProcessModulePath(pid, 0, buf, _countof(buf), true)) std::wcout << L"(" << buf << L")" << std::endl;

		analyseProcess(pid);
	}
	else if (operation == "module")
	{
		if (argc < 4)
		{
			usage();
			return 1;
		}

		std::string p(argv[2]);
        std::string m(argv[3]);
		DWORD pid = stoi(p);
        ULONGLONG address = 0;

        try
        {
            address = std::stoull(m, nullptr, 16);
			std::wcout << L"Analysing process' PID: " << pid;
			
			wchar_t buf[1024] = L"";
			if (getProcessModulePath(pid, 0, buf, _countof(buf), true)) std::wcout << L" (" << buf << L") ";
			
			std::wcout << L" with module ";
			if (getProcessModulePath(pid, reinterpret_cast<const BYTE*>(address), buf, _countof(buf), true))
				std::wcout << L" (" << buf << L") ";
			
			std::wcout << "located at address : " << std::hex << address << std::endl;
			analyseProcessModule(pid, address);
        }
        catch (...)
        {
            std::wstring wm(m.begin(), m.end());
			std::wcout << L"Analysing process' PID: " << pid << L" with module named: ", wm, "\n";
			analyseProcessModule(pid, wm);
        }
	}
	else if (operation == "memory")
	{
		if (argc < 4)
		{
			usage();
			return 1;
		}

		std::string p(argv[2]);
		std::string m(argv[3]);
		DWORD pid = stoi(p);
		ULONGLONG address = 0;

		try
		{
			address = std::stoull(m, nullptr, 16);
			std::wcout << L"Analysing process' PID: " << pid;

			wchar_t buf[1024] = L"";
			if (getProcessModulePath(pid, 0, buf, _countof(buf), true)) std::wcout << L" (" << buf << L") ";

			std::wcout << L" with memory allocation ";
			if (getProcessModulePath(pid, reinterpret_cast<const BYTE*>(address), buf, _countof(buf), true))
				std::wcout << L" (" << buf << L") ";

			std::wcout << "located at address : " << std::hex << address << std::endl;
			analyseProcessMemory(pid, address);
		}
		catch (...)
		{
			usage();
		}
	}
	else if (operation == "dump")
	{
		if (argc < 3)
		{
			usage();
			return 1;
		}

		std::string p(argv[2]);
		std::wstring filepath(p.begin(), p.end());

		std::wcout << L"Analysing dump file: \"" << filepath << L"\"...\n";
		analyseDump(filepath);
	}
}
