#pragma once

#include <Windows.h>

extern "C" __declspec(dllexport) void FuncToCall() {
    MessageBoxA(NULL, "YOUVE BEEN HACKED", "Sk3lex0r", MB_ICONERROR | MB_OKCANCEL);