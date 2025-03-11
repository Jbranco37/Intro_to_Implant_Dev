/*
Author: Jacob Branco
Purpose: DLL to load into address space of our VEH registration program, to develop a POC for how VEH functions can obfsucate control flow for an attacker
*/
#include <Windows.h>
#include <iostream>
using namespace std;

extern "C" __declspec(dllexport) void __stdcall FuncToCall() {
    int MyMsg = MessageBoxA(NULL, "YOUVE BEEN HACKED", "Sk3lex0r", MB_ICONERROR | MB_OKCANCEL);
    if (MyMsg == IDOK) {
        exit(0);
    }
}

extern "C" __declspec(dllexport) VOID benignFunction(VOID) {
    cout << "Did you notice anything fishy just now?" << endl;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:    
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

