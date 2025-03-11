// Windows Programming Practice
// Author: Jacob Branco

#include <iostream>
#include <Windows.h>
#include <string>
#include "FindMe.h"

using namespace std;

// Let's clean up our code by defining 2 exception inducing functions

// Function to trigger INT_DIVIDE_BY_ZERO
int DivideByZero(VOID) {
	int x{ 0 };
	int y{ 500 };
	int result = y / x; // Trigger Exception here

	return result;
}

// Second function to trigger ACCESS VIOLATION
VOID DerefNullPtr(VOID) {

	int* ptr = nullptr;
	cout << *ptr; // Trigger exception here

}

INT main(VOID) {

	string Name{ "" };
	string func{ "" };

	
	// WE need to invoke an exception that WONT be handled by system/CPU/runtime
	// Let's try EXCEPTION_ACCESS_VIOLATION
	cout << "Hey! What is your name: " << endl;
	cin >> Name;

	cout << "Nice to Meet you, " << Name << " what function would you like to execute: DIV_BY_ZERO | ACCESS_VIOLATION" << endl;
	cin >> func;
	if (func == "DIV_BY_ZERO") {
		// Call function to add custom handler to VEH chain - can be referenced globally in program
		if (!AddVectoredExceptionHandler(1, CustomExcHandler)) {
			cerr << "[!] Failed to Add VEH Handler to List! Error: 0x" << hex << GetLastError() << endl;
		}
		DivideByZero();
		RemoveVectoredExceptionHandler(CustomExcHandler);
		return 0;
	}
	else if (func == "ACCESS_VIOLATION") {
		if (!AddVectoredExceptionHandler(2, NewExecHandler)) {
			cerr << "[!] Failed to Add VEH Handler to List! Error: 0x" << hex << GetLastError() << endl;
		}
		DerefNullPtr();
		RemoveVectoredExceptionHandler(NewExecHandler);
		return 0;
	}
	else {
		cerr << "[!] Invalid selection! Please choose either DIV_BY_ZERO or ACCESS_VIOLATION" << endl;
		main();
	}
	return 0;
}