#include <windows.h>
#include <evntrace.h>
#include <iostream>

using std::cout;

bool flagSilent = false;

PVOID ReadFileInMemory(const char* filePath) {
	HANDLE fileHandle = CreateFileA(
		filePath,				// File path
		GENERIC_READ,			// Read access
		FILE_SHARE_READ,		// Allow other processes to read this file
		NULL,					// Default Security
		OPEN_EXISTING,			// Only open if it exists
		FILE_ATTRIBUTE_NORMAL,	// Normal file: "The file does not have other attributes set"
		NULL					// No template: "When opening an existing file, CreateFile ignores this parameter"
	);

	if (fileHandle == INVALID_HANDLE_VALUE) {
		cout << "[-] Failed to open file (" << filePath << ")\n";
		cout << "[-] Error: " << GetLastError() << "\n";
		return NULL;
	}

	// Check how much memory we need to allocate
	DWORD fileSize = GetFileSize(fileHandle, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		cout << "[-] Failed to get file size\n";
		CloseHandle(fileHandle);
		return NULL;
	}

	// Allocate memory
	PVOID fileBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!fileBuffer) {
		cout << "[-] Can't allocate memory\n";
	}

	// Read file
	DWORD bytesRead;
	if (!ReadFile(fileHandle, fileBuffer, fileSize, &bytesRead, NULL)) {
		cout << "[-] ReadFile failed\n";
		cout << "[-] Error: " << GetLastError() << "\n";
		VirtualFree(fileBuffer, 0, MEM_RELEASE);
		CloseHandle(fileHandle);
		return NULL;
	}

	if (bytesRead != fileSize) {
		cout << "[-] Failed to read file\n";
	}

	CloseHandle(fileHandle);

	if (!flagSilent) {
		cout << "[+] Loaded " << filePath << " in memory at 0x" << fileBuffer << "\n";
	}

	return fileBuffer;
}

// Explanation at https://www.ired.team/offensive-security/defense-evasion/retrieving-ntdll-syscall-stubs-at-run-time
DWORD RvaToRawOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;

		if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
			return rva - sectionAddress + sectionHeader->PointerToRawData;
		}
	}

	return 0;
}

const char* ntdllPath = "C:\\Windows\\System32\\ntdll.dll";

void PrintBanner() {
	cout << R"""( _____ ____  ____    __  __             
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map)""";
}

void EnumerateHookedFunctions() {
	std::cout << "\n\n----- Enumerating Hooked Userland Functions -----\n\n";

	if (!flagSilent) {
		cout << "[!] Loading the clean NTDLL from Disk...\n";
	}

	PVOID diskNtdllBuffer = ReadFileInMemory(ntdllPath);

	if (!diskNtdllBuffer) {
		cout << "[-] Failed to load " << ntdllPath << " from Disk\n";
		return;
	}

	if (!flagSilent) {
		cout << "\n[!] Parsing PE Headers to find Exports...\n";
	}

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)diskNtdllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "[-] DOS Signature != 'MZ'\n";
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)diskNtdllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cout << "[-] NT Signature != 'PE\\0\\0'\n";
		return;
	}

	DWORD exportDirectoryRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportDirectoryRva) {
		cout << "[-] Can't find Export Directory\n";
		return;
	}

	DWORD exportDirectoryOffset = RvaToRawOffset(ntHeaders, exportDirectoryRva);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)diskNtdllBuffer + exportDirectoryOffset);

	if (!flagSilent) {
		cout << "[+] Export Directory found at RVA 0x" << std::hex << exportDirectoryRva << "\n";
		cout << "[+] Found " << exportDirectory->NumberOfNames << " Exported Functions\n";

		cout << "\n[!] Getting handle to the NTDLL from Memory...\n";
	}

	HMODULE memoryNtdllBase = GetModuleHandleA("ntdll.dll");
	if (!memoryNtdllBase) {
		cout << "[-] Can't get handle to the NTDLL from Memory";
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return;
	}

	if (!flagSilent) {
		cout << "[+] Found Memory NTDLL base address at 0x" << memoryNtdllBase << "\n";

		cout << "\n[!] Scanning for hooks in functions...\n";
	}

	PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfFunctions));
	PDWORD addressOfNames = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNames));
	PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals));

	int hooksNumber = 0;

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		char* functionName = (char*)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, addressOfNames[i]));

		if (!strncmp(functionName, "Nt", 2) ||
			!strncmp(functionName, "Zw", 2) ||
			!strncmp(functionName, "Etw", 3) ||
			!strncmp(functionName, "Ldr", 3) ||
			!strncmp(functionName, "Rtl", 3) ||
			!strncmp(functionName, "Ki", 2) ||
			!strncmp(functionName, "RegNt", 5)) {
			DWORD functionRva = addressOfFunctions[addressOfNameOrdinals[i]];
			PVOID diskFunctionAddress = (PVOID)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, functionRva));

			PVOID memoryFunctionAddress = (PVOID)((ULONG_PTR)memoryNtdllBase + functionRva);

			if (memcmp(diskFunctionAddress, memoryFunctionAddress, 16) != 0) {
				std::cout << "[*] HOOKED: " << functionName << "\n";
				hooksNumber++;
			}
		}
	}

	if (!hooksNumber) {
		cout << "\n[-] No hooks detected in the functions";
	}
	else {
		cout << "\n[+] Found " << hooksNumber << " hooks";
	}

	VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
}

void EnumerateETWSessions() {
	std::cout << "\n\n----- Enumerating Active ETW Trace Sessions -----\n\n";

	const ULONG MAX_SESSIONS = 129;

	PEVENT_TRACE_PROPERTIES sessionPropertiesArray[MAX_SESSIONS];
	ULONG sessionCount = 0;

	for (int i = 0; i < MAX_SESSIONS; i++) {
		size_t bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (2 * MAX_PATH * sizeof(WCHAR));

		sessionPropertiesArray[i] = (PEVENT_TRACE_PROPERTIES)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (sessionPropertiesArray[i] == NULL) {
			cout << "[-] Can't allocate memory\n";
			return;
		}

		sessionPropertiesArray[i]->Wnode.BufferSize = (ULONG)bufferSize;
		sessionPropertiesArray[i]->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
		sessionPropertiesArray[i]->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (MAX_PATH * sizeof(WCHAR));
	}

	ULONG status = QueryAllTracesW(sessionPropertiesArray, MAX_SESSIONS, &sessionCount);

	if (status != ERROR_SUCCESS) {
		cout << "[-] QueryAllTracesW failed (" << status << ")\n";
	}
	else {
		if (!flagSilent) {
			cout << "[+] Found " << sessionCount << " active ETW sessions\n";

			cout << "\n[!] Scanning for active trace sessions...\n";
		}
		int securityTelemetryCount = 0;

		for (ULONG i = 0; i < sessionCount; i++) {
			PWCHAR sessionName = (PWCHAR)((char*)sessionPropertiesArray[i] + sessionPropertiesArray[i]->LoggerNameOffset);

			std::wstring nameStr(sessionName);

			if (nameStr.find(L"Defender") != std::wstring::npos ||
				nameStr.find(L"Sense") != std::wstring::npos ||			// Defender for Endpoint (MDE)
				nameStr.find(L"Sysmon") != std::wstring::npos ||		// Sysinternals System Monitor
				nameStr.find(L"CrowdStrike") != std::wstring::npos ||	// CrowdStrike Falcon
				nameStr.find(L"Cylance") != std::wstring::npos ||		// Cylance
				nameStr.find(L"Sentinel") != std::wstring::npos ||		// SentinelOne
				nameStr.find(L"DiagLog") != std::wstring::npos ||		// Windows Diagnostic Logging
				nameStr.find(L"Diagtrack") != std::wstring::npos ||		// Connected User Experiences and Telemetry
				nameStr.find(L"WFP-Diagnostics") != std::wstring::npos)	// Windows Filtering Platform (Network)
			{
				std::wcout << L"[*] FLAGGED: " << nameStr << L"\n";
				securityTelemetryCount++;
			}
		}

		cout << "\n[!] Flagged " << securityTelemetryCount << " Security / Telemetry loggers\n";
	}

	for (int i = 0; i < MAX_SESSIONS; i++) {
		if (sessionPropertiesArray[i] != NULL) {
			VirtualFree(sessionPropertiesArray[i], 0, MEM_RELEASE);
		}
	}
}


int main(int argc, char* argv[]) {
	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
			flagSilent = true;
		}
	}

	if (!flagSilent) {
		PrintBanner();
	}

	EnumerateHookedFunctions();

	EnumerateETWSessions();
	return 0;
}