#include <iostream>
#include <Windows.h>
#include <string>
#include <winternl.h>
#include <winnt.h>

using namespace std;

#pragma comment(lib, "ntdll.lib")

LPCWSTR g_TargetProc = L"C:\\Windows\\system32\\Notepad.exe";

typedef NTSTATUS(WINAPI* pNtQUeryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL DummyProcCreate(IN LPCWSTR procName) {

	PROCESS_BASIC_INFORMATION pbi;
	ULONG retLen;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	BOOL MakeProcAppear = CreateProcessW(g_TargetProc,
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW | CREATE_SUSPENDED, // Create Suspended to try and acquire PEB or other data structures like CONTEXT
		NULL,
		NULL,
		&si,
		&pi);
	if (!MakeProcAppear) {
		cout << "[!] CreateProcessW failed with error: 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	DWORD pid = pi.dwProcessId;
	HANDLE hProc = pi.hProcess;
	HANDLE hThread = pi.hThread;
	
	if (pid == NULL || hProc == NULL || hThread == NULL) {
		return FALSE;
	}

	cout << "[+] PID: " << pid << endl;


	pNtQUeryInformationProcess NtQueryInformationProcess = (pNtQUeryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		cout << "[!] Error retreiving address of NT function 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
	if (status != 0) {
		cout << "[!] Error acquiring handle to PEB with error 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	PEB peb;
	SIZE_T bytesRead{};

	if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
		cout << "[!] Error Reading from PEB 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	// ENumerate PEB Addr
	// PEB Size
	// PEB Fields - POC
	cout << "============= Gathering PEB Statistics ==============" << endl;
	cout << "[+] PEB Base Address: " << hex << pbi.PebBaseAddress << endl;
	cout << "[+] PEB Size: " << sizeof(peb) << " bytes" << endl;
	cout << "[+] Value of IsDebugged: " << int(peb.BeingDebugged) << endl;

	return TRUE;

}

BOOL evilFunc(PEXCEPTION_POINTERS pExceptionInfo) {

	// Evil Function to invoke after VEH chain registration and invocation
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		cout << "[!] We have a violation! Now Phase 1 of EOP Attack..Read PEB Base Address" << endl;
		if (!DummyProcCreate(g_TargetProc)) {
			cout << "[!] Error creating Process with error 0x" << hex << GetLastError() << endl;
			return FALSE;
		}
	}
	return TRUE;
}

LONG CALLBACK CustomExcHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	// Call evilFunc in the event of an exception
	if (evilFunc(pExceptionInfo)) {
		// Handle BP Exception
		return EXCEPTION_EXECUTE_HANDLER;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}