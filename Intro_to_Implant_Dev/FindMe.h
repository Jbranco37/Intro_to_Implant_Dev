#include <iostream>
#include <Windows.h>
#include <string>
#include <climits>

using namespace std;

BOOL DummyCalcCreation(VOID) {

	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	BOOL MakeCalcAppear = CreateProcessW(L"C:\\Windows\\System32\\calc.exe",
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW | CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi);
	if (!MakeCalcAppear) {
		cout << "[!] CreateProcessW failed with error: 0x" << hex << GetLastError() << endl;
		return FALSE;
	}
	// Cleanup - Don-t Terminate for POC
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return TRUE;
}

BOOL evilFunc(PEXCEPTION_POINTERS pExceptionInfo) {

	// Evil Function to invoke after VEH chain registration and invocation
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
		cout << "[!] We have a violation!" << endl;
		DummyCalcCreation();
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