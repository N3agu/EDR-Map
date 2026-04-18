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

	cout << "[!] Loading the clean NTDLL from disk...\n";
	PVOID cleanNtdllBuffer = ReadFileInMemory(ntdllPath);

	if (!cleanNtdllBuffer) {
		cout << "[-] Failed to load ntdll from disk";
		return -1;
	}

	VirtualFree(cleanNtdllBuffer, 0, MEM_RELEASE);
	return 0;
}