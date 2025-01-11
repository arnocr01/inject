#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <io.h>

static DWORD GetProcId(const char* procName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);
		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!_stricmp(procEntry.szExeFile, procName)) {
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

static BOOL EnableSeDebugPrivilege(BOOL enable) {
	HANDLE hToken = NULL;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return FALSE;
	}
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	TokenPrivileges.PrivilegeCount = 1;
	if (enable) {
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else {
		TokenPrivileges.Privileges[0].Attributes = 0;
	}
	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, 0)) {
		CloseHandle(hToken);
		return FALSE;
	}
	CloseHandle(hToken);
	return TRUE;
}

static LPSTR GetLastErrorStr() {
	LPSTR messageBuffer = NULL;
	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&messageBuffer,
		0,
		NULL
	);
	return messageBuffer;
}

static char* GetFileName(char* path) {
	char* filename = strrchr(path, '\\');
	if (!filename) {
		return path;
	}
	return filename + 1;
}

int main(int argc, char* argv[]) {
	// check we have the right number of args
	if (argc != 3) {
		printf("Invalid number of parameters\n");
		printf("Usage: inject process dll\n");
		return EXIT_FAILURE;
	}
	char* process = argv[1];
	char* dll = argv[2];
	char dllPath[MAX_PATH];
	// make sure we have full path to dll
	if (!GetFullPathName(dll, MAX_PATH, dllPath, NULL)) {
		printf("GetFullPathName Error: '%s'.", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	// check if process exists
	DWORD procId = GetProcId(process);
	if (!procId) {
		printf("Error: Could not find process '%s'.\n", process);
		return EXIT_FAILURE;
	}
	// check if dll exists
	if (_access(dll, 0) == -1) {
		printf("Error: Could not find file '%s'\n", dll);
		return EXIT_FAILURE;
	}
	// get debug privilege
	if (!EnableSeDebugPrivilege(TRUE)) {
		printf("Enable SeDebugPrivilege failed: %s", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	// get target process handle
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
	if (!hProc) {
		printf("OpenProcess Error: %s", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	if (hProc == INVALID_HANDLE_VALUE) {
		printf("OpenProcess Invalid: %s", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	// allocate memory in target process to store the dll path
	void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!loc) {
		printf("VirtualAllocEx Error: %s", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	// write dll path into target process memory
	if (!WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0)) {
		printf("WriteProcessMemory Error: %s", GetLastErrorStr());
		CloseHandle(hProc);
		return EXIT_FAILURE;
	}
	// create thread in target process and load dll
	HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!hThread) {
		printf("CreateRemoteThread Error: %s", GetLastErrorStr());
		return EXIT_FAILURE;
	}
	// cleanup
	if (hThread) {
		CloseHandle(hThread);
	}
	if (hProc) {
		CloseHandle(hProc);
	}
	printf("%s injected into %s!\n", GetFileName(dll), process);
	return EXIT_SUCCESS;
}