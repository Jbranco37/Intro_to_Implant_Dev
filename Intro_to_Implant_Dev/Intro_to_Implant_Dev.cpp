// Windows Programming Practice
// Author: Jacob Branco

#include <iostream>
#include <Windows.h>
#include <string>
#include "FindMe.h"

using namespace std;

INT main(VOID) {
	
	// Call function to add custom handler to VEH chain - can be referenced globally in program
	if (!AddVectoredExceptionHandler(1, CustomExcHandler)) {
		cout << "[!] Failed to Add VEH Handler to List! Error: 0x" << hex << GetLastError() << endl;
	}
	
	// WE need to invoke an exception that WONT be handled by system/CPU/runtime
	// Let's try EXCEPTION_BREAKPOINT (Software)
	string Name{ "" };
	cout << "Hey! What is your name: " << endl;
	cin >> Name;

	__debugbreak(); // Trigger BP exception here

	return 0;
}