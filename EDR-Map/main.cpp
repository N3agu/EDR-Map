#include <windows.h>
#include <iostream>

using std::cout;

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
	cout << "[+] Loaded " << filePath << " in memory at 0x" << fileBuffer << "\n";
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

int main() {
	cout << R"""( _____ ____  ____    __  __             
| ____|  _ \|  _ \  |  \/  | __ _ _ __  
|  _| | | | | |_) | | |\/| |/ _` | '_ \ 
| |___| |_| |  _ <  | |  | | (_| | |_) |
|_____|____/|_| \_\ |_|  |_|\__,_| .__/ 
                                 |_|    
        github.com/N3agu/EDR-Map
                               
)""";

	cout << "[!] Loading the clean NTDLL from Disk...\n";
	PVOID diskNtdllBuffer = ReadFileInMemory(ntdllPath);

	if (!diskNtdllBuffer) {
		cout << "[-] Failed to load NTDLL from Disk\n";
		return -1;
	}

	cout << "\n[!] Parsing PE Headers to find Exports...\n";

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)diskNtdllBuffer;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		cout << "[-] DOS Signature != 'MZ'\n";
		return -1;
	}

	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)diskNtdllBuffer + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		cout << "[-] NT Signature != 'PE\\0\\0'\n";
		return -1;
	}

	DWORD exportDirectoryRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!exportDirectoryRva) {
		cout << "[-] Can't find Export Directory\n";
		return -1;
	}

	DWORD exportDirectoryOffset = RvaToRawOffset(ntHeaders, exportDirectoryRva);
	PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)diskNtdllBuffer + exportDirectoryOffset);
	
	cout << "[+] Export Directory found at RVA 0x" << std::hex << exportDirectoryRva << "\n";
	cout << "[+] Found " << exportDirectory->NumberOfNames << " Exported Functions\n";

	cout << "\n[!] Getting handle to the NTDLL from Memory...\n";

	HMODULE memoryNtdllBase = GetModuleHandleA("ntdll.dll");
	if (!memoryNtdllBase) {
		cout << "[-] Can't get handle to the NTDLL from Memory";
		VirtualFree(diskNtdllBuffer, 0, MEM_RELEASE);
		return -1;
	}

	cout << "[+] Found Memory NTDLL base address at 0x" << memoryNtdllBase << "\n";

	cout << "\n[!] Scanning for hooks in functions...\n";

	PDWORD addressOfFunctions = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfFunctions));
	PDWORD addressOfNames = (PDWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNames));
	PWORD addressOfNameOrdinals = (PWORD)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, exportDirectory->AddressOfNameOrdinals));

	int hooksNumber = 0;

	for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
		char* functionName = (char*)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, addressOfNames[i]));

		if (!strncmp(functionName, "Nt", 2)  ||
			!strncmp(functionName, "Zw", 2)  ||
			!strncmp(functionName, "Etw", 3) ||
			!strncmp(functionName, "Ldr", 3) ||
			!strncmp(functionName, "Rtl", 3) ||
			!strncmp(functionName, "Ki", 2)  ||
			!strncmp(functionName, "RegNt", 5)) {
			DWORD functionRva = addressOfFunctions[addressOfNameOrdinals[i]];
			PVOID diskFunctionAddress = (PVOID)((ULONG_PTR)diskNtdllBuffer + RvaToRawOffset(ntHeaders, functionRva));
			
			PVOID memoryFunctionAddress = (PVOID)((ULONG_PTR)memoryNtdllBase + functionRva);

			if (memcmp(diskFunctionAddress, memoryFunctionAddress, 16) != 0) {
				std::cout << "[*] HOOK DETECTED: " << functionName << "\n";
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
	return 0;
}