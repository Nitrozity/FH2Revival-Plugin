#pragma once

#ifndef UTIL_H
#define UTIL_H
#include "stdafx.h"


FARPROC ResolveFunction(HMODULE hHandle, DWORD Ordinal);
FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal);
VOID PatchInJump(DWORD* addr, DWORD dest, BOOL linked);
extern BOOL g_FH2LogEnabled;
extern BOOL g_FH2Quiet;   // v0.9.10: FH2Synth.txt word 'quiet' drops the high-volume diagnostic log lines
DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress);
BOOL IsTrayOpen();
VOID ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress);
VOID XNotify(LPCWSTR pwszStringParam);
VOID FH2_Log(const CHAR* fmt, ...);

DWORD MountPath(PCHAR Drive, PCHAR Device);
PCHAR GetMountPath();

// DO NOT CALL DIRECTLY. USE DEFINE Sunrise_Dbg instead
VOID Sunrise_Print(const CHAR* fmt, ...);

// Prints are only enabled is DO_PRINTS is defined below
#define DO_PRINTS // Comment out to disable prints

#ifdef DO_PRINTS
#define Sunrise_Dbg(x, ...) { do { Sunrise_Print("[Sunrise2] "  x "\n", __VA_ARGS__); } while(0); }
#else
#define Sunrise_Dbg
#endif

#pragma region Sunrise2 ini
#define BASE_ADDR 0x91A00000
#define MOUNT_POINT	 "SR2:"
#define PATH_INI	MOUNT_POINT "\\Sunrise2.ini"
#define PATH_FH2_LOG MOUNT_POINT "\\FH2Revival.log"
#define PATH_FH2_P2PLOG MOUNT_POINT "\\FH2P2P.log"

VOID Writeini(BOOL GenerateNew);
VOID Readini();
#pragma endregion

#endif