#include "stdafx.h"
#include "Utilities.h"
#include "SimpleIni.h"
#include "Sunrise2.h"

FARPROC ResolveFunction(HMODULE hHandle, DWORD Ordinal) {
	return (hHandle == NULL) ? NULL : GetProcAddress(hHandle, (LPCSTR)Ordinal);
}

FARPROC ResolveFunction(CHAR* ModuleName, DWORD Ordinal)
{
	HMODULE mHandle = GetModuleHandle(ModuleName);
	return (mHandle == NULL) ? NULL : GetProcAddress(mHandle, (LPCSTR)Ordinal);
}

VOID PatchInJump(DWORD* addr, DWORD dest, BOOL linked) {
	DWORD temp[4];

	if (dest & 0x8000) // If bit 16 is 1
		temp[0] = 0x3D600000 + (((dest >> 16) & 0xFFFF) + 1); // lis 	%r11, dest>>16 + 1
	else
		temp[0] = 0x3D600000 + ((dest >> 16) & 0xFFFF); // lis 	%r11, dest>>16

	temp[1] = 0x396B0000 + (dest & 0xFFFF); // addi	%r11, %r11, dest&0xFFFF
	temp[2] = 0x7D6903A6; // mtctr	%r11

	if (linked)
		temp[3] = 0x4E800421; // bctrl
	else
		temp[3] = 0x4E800420; // bctr

	memcpy(addr, temp, 0x10);
}

DWORD PatchModuleImport(PLDR_DATA_TABLE_ENTRY Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
{
	DWORD address = (DWORD)ResolveFunction(ImportedModuleName, Ordinal);
	if (address == NULL)
		return S_FALSE;

	VOID* headerBase = Module->XexHeaderBase;
	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(headerBase, 0x000103FF);
	if (importDesc == NULL)
		return S_FALSE;

	DWORD result = 2;

	CHAR* stringTable = (CHAR*)(importDesc + 1);

	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	for (DWORD x = 0; x < importDesc->ModuleCount; x++)
	{
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for (DWORD y = 0; y < importTable->ImportTable.ImportCount; y++)
		{
			DWORD value = *((DWORD*)importAdd[y]);
			if (value == address)
			{
				memcpy((DWORD*)importAdd[y], &PatchAddress, 4);
				DWORD newCode[4];
				PatchInJump(newCode, PatchAddress, FALSE);
				memcpy((DWORD*)importAdd[y + 1], newCode, 16);
				result = S_OK;
			}
		}
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}
	return result;
}

DWORD PatchModuleImport(CHAR* Module, CHAR* ImportedModuleName, DWORD Ordinal, DWORD PatchAddress)
{
	LDR_DATA_TABLE_ENTRY* moduleHandle = (LDR_DATA_TABLE_ENTRY*)GetModuleHandle(Module);
	return (moduleHandle == NULL) ? S_FALSE : PatchModuleImport(moduleHandle, ImportedModuleName, Ordinal, PatchAddress);
}


BOOL IsTrayOpen()
{
	unsigned char msg[0x10];
	unsigned char resp[0x10];
	memset(msg, 0x0, 0x10);
	msg[0] = 0xA;
	HalSendSMCMessage(msg, resp);

	if (resp[1] == 0x60) return TRUE;

	return FALSE;
}


VOID ThreadMe(LPTHREAD_START_ROUTINE lpStartAddress) {
	HANDLE handle;
	DWORD lpThreadId;
	ExCreateThread(&handle, 0, &lpThreadId, (PVOID)XapiThreadStartup, lpStartAddress, NULL, 0x2 | CREATE_SUSPENDED);
	XSetThreadProcessor(handle, 4);
	SetThreadPriority(handle, THREAD_PRIORITY_ABOVE_NORMAL);
	ResumeThread(handle);
}

VOID XNotify(LPCWSTR pwszStringParam)
{
	if (bIsDevkit) // We don't need a stupid notify on Devkit. Smh...
		return;
	XNotifyQueueUI(XNOTIFYUI_TYPE_PREFERRED_REVIEW, XUSER_INDEX_ANY, XNOTIFYUI_PRIORITY_HIGH, (PWCHAR)pwszStringParam, NULL);
}


// FH2 diagnostic log. The Sunrise plugin already mounts its own folder as SR2:, so
// this creates FH2Revival.log beside the plugin XEX. Open/write/close each time so
// useful evidence survives even if an XNotify is missed or the game exits abruptly.
// v0.9.0: release builds do not write FH2Revival.log unless the optional SR2:\FH2Synth.txt contains the word "log" (or "crashlog").
BOOL g_FH2LogEnabled = FALSE;
BOOL g_FH2Quiet = TRUE;   // v1.0: built-in default

// v0.9.10: every FH2_Log call opens, appends to and closes the log file on the game's thread.  During an invite join the
// probe hooks emit dozens of lines within milliseconds, and every console that went through invite state 8 -> 10/11 stopped
// writing and froze.  'quiet' drops the high-volume families (matched on the format string, so no formatting cost) and keeps
// the sign-in, invite-state, block, launch and error lines.
static BOOL FH2_QuietDrops(const CHAR* fmt)
{
    // v0.9.12: PROVENANCE CALL lines are no longer dropped here (the flush skips only send/WSASend when quiet): they are the
    // only record of the socket/connect/XNetConnect/sendto steps, because FH2_Log calls made on game threads are lost.
    // v0.9.11: matched on the literal format string.  Drops the high-volume families; keeps PEER and the
    // NET TRACE socket/connect/XNet lines (the connection steps), sign-in, invite-state, block and error lines.
    static const CHAR* const prefixes[] =
    {
        "PROBE ", "ROADTRIP ", "v0.8.17 EVT", "PROVENANCE SETUP",
        "SYNTH NET", "SYNTH ENUM", "SYNTH CREATE",
        "v0.8.13 SOCK", "v0.8.12 NETSTATS", "v0.8.13 XNET STATUS",
        "NET TRACE BUFFER", "NET TRACE: XamCreateEnumeratorHandle", "NET TRACE: XamEnumerate",
        "NET TRACE: XGetOverlappedResult", "NET TRACE: async enumeration",
        "v0.8.3 VT ", "v0.8.3 RTTI", "v0.8.3 AVAIL getter", "v0.8.19 TRACE ", "v0.8.22 cand", "v0.8.22 crashlog"
    };
    if (strncmp(fmt, "PROBE SETUP", 11) == 0)
        return FALSE;
    for (int i = 0; i < (int)(sizeof(prefixes) / sizeof(prefixes[0])); ++i)
        if (strncmp(fmt, prefixes[i], strlen(prefixes[i])) == 0)
            return TRUE;
    return FALSE;
}

// v0.9.19: with the 'xgi' word in FH2Synth.txt all log lines go to ONE file family (FH2P2P.log, FH2P2P_2.log ...) and the start-up
// boilerplate and the periodic P2P summary lines are dropped, so a test produces only a few small files per console.
extern BOOL g_FH2Xgi;
static BOOL FH2_TerseDrops(const CHAR* fmt)
{
    static const CHAR* const prefixes[] =
    {
        "PROBE SETUP", "v0.3.7 ", "v0.9.5 TRACE hooks", "Protected-file table", "Native server-down", "v0.8.3 availability",
        "v0.8.2 PROVENANCE", "v0.8.10 config", "v0.8.16", "v0.8.5 SYNTH", "v0.8.5 XNetStartup", "v0.8.7 ", "v0.8.14 SOCK",
        "v0.8.4 XAM", "v0.8.4 XAM PROBE", "v0.9.4 PEER TRACE", "v0.4.0 ", "v0.8.3 IDENTITY", "v0.8.3 ROADTRIP", "v0.8.3 Wireshark",
        "v0.8.3 NETWORK", "v0.9.15 P2P RECV stats", "v0.9.15 P2P SEND to", "v0.9.15 P2P RECV from", "v0.9.9 SIGNINFO"
    };
    for (int i = 0; i < (int)(sizeof(prefixes) / sizeof(prefixes[0])); ++i)
        if (strncmp(fmt, prefixes[i], strlen(prefixes[i])) == 0)
            return TRUE;
    return FALSE;
}

// v0.9.6: several threads log at once (the new 20 ms poller, hook threads, the worker). Without a lock two
// writers could seek to the same end-of-file offset and overwrite each other (a corrupted line was seen in the
// v0.9.5 baseline log). A tiny spin lock serialises the write; if it cannot be taken within ~200 ms (a stuck
// writer) we write anyway rather than risk blocking the game.
static volatile LONG g_FH2LogLock = 0;
#define FH2_LOG_PART_BYTES 16000   // v0.9.19: was 8000 (v0.9.18)

static VOID FH2_LogWrite(const CHAR* message, BOOL toP2P = FALSE)
{
    CHAR line[640] = { 0 };
    BOOL haveLock = FALSE;
    for (int spin = 0; spin < 200; ++spin)
    {
        if (InterlockedCompareExchange(&g_FH2LogLock, 1, 0) == 0) { haveLock = TRUE; break; }
        Sleep(1);
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    sprintf_s(line, sizeof(line),
        "[%04u-%02u-%02u %02u:%02u:%02u] %s\r\n",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        message);

    // v0.9.18: split each log into parts of about 8 KB (FH2Revival.log, FH2Revival_2.log ...; FH2P2P.log, FH2P2P_2.log ...)
    // because the tester's file copies are cut at a fixed size (9-23 KB seen).  Counts this run's bytes only.
    static DWORD partBytes[2] = { 0, 0 };
    static DWORD partNo[2] = { 1, 1 };
    const int ti = toP2P ? 1 : 0;
    const DWORD lineLen = (DWORD)strlen(line);
    if (partBytes[ti] + lineLen > FH2_LOG_PART_BYTES && partBytes[ti] > 0) { ++partNo[ti]; partBytes[ti] = 0; }
    partBytes[ti] += lineLen;
    CHAR path[96];
    if (partNo[ti] <= 1) sprintf_s(path, sizeof(path), "%s", toP2P ? PATH_FH2_P2PLOG : PATH_FH2_LOG);
    else sprintf_s(path, sizeof(path), toP2P ? (MOUNT_POINT "\\FH2P2P_%u.log") : (MOUNT_POINT "\\FH2Revival_%u.log"), partNo[ti]);

    HANDLE hFile = CreateFile(path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        if (haveLock) InterlockedExchange(&g_FH2LogLock, 0);
        return;
    }

    SetFilePointer(hFile, 0, NULL, FILE_END);

    DWORD written = 0;
    WriteFile(hFile, line, (DWORD)strlen(line), &written, NULL);
    CloseHandle(hFile);
    if (haveLock) InterlockedExchange(&g_FH2LogLock, 0);
}

VOID FH2_Log(const CHAR* fmt, ...)
{
    if (!g_FH2LogEnabled)
        return;
    if (g_FH2Quiet && FH2_QuietDrops(fmt))
        return;
    if (g_FH2Xgi && FH2_TerseDrops(fmt))
        return;

    // v0.8.15: CreateFile(OPEN_ALWAYS) on an existing file sets last-error ERROR_ALREADY_EXISTS (183).
    // Hooks call FH2_Log on the game's thread between the game's connect() and its WSAGetLastError(),
    // so the game could see 183 instead of WSAEWOULDBLOCK (10035) and close the socket at once.
    // Preserve both the Win32 and the XNet last-error across the log call.
    DWORD savedLastError = GetLastError();
    int savedWsaError = NetDll_WSAGetLastError();

    CHAR message[512] = { 0 };
    va_list args;
    va_start(args, fmt);
    vsprintf_s(message, sizeof(message), fmt, args);
    va_end(args);

    // v0.9.15: peer-traffic lines go to their own small file (FH2P2P.log) so a capped copy of FH2Revival.log cannot hide them;
    // join/select markers are written to both files so the P2P file has the timeline.
    // v0.9.16: "v0.9.16 XGI" session-call lines and the XamSession lines (v0.4.3 SESSION) also go to the P2P file.
    if (g_FH2Xgi || strncmp(fmt, "v0.9.15 P2P", 11) == 0 || strncmp(fmt, "v0.9.16 XGI", 11) == 0)
        FH2_LogWrite(message, TRUE);   // v0.9.19: with 'xgi' everything goes to the one FH2P2P family
    else
    {
        FH2_LogWrite(message);
        if (strncmp(fmt, "PROVENANCE MARKER", 17) == 0 || strncmp(fmt, "PROVENANCE CALL", 15) == 0)
            FH2_LogWrite(message, TRUE);
    }

    SetLastError(savedLastError);
    NetDll_WSASetLastError(savedWsaError);
}


char SunriseFullPath[MAX_PATH];
DWORD MountPath(PCHAR Drive, PCHAR Device)
{
	CHAR Destination[MAX_PATH] = { 0 };
	sprintf_s(Destination, MAX_PATH, (KeGetCurrentProcessType() == PROC_SYSTEM) ? OBJ_SYS_STRING : OBJ_USR_STRING, Drive);
	ANSI_STRING LinkName, DeviceName;
	RtlInitAnsiString(&LinkName, Destination);
	RtlInitAnsiString(&DeviceName, Device);
	ObDeleteSymbolicLink(&LinkName);
	return (DWORD)ObCreateSymbolicLink(&LinkName, &DeviceName);
}

PCHAR GetMountPath() {
	std::wstring ws;
	PLDR_DATA_TABLE_ENTRY TableEntry;
	XexPcToFileHeader((PVOID)BASE_ADDR, &TableEntry);

	ws = TableEntry->FullDllName.Buffer;
	std::string FullDllName(ws.begin(), ws.end());

	ws = TableEntry->BaseDllName.Buffer;
	std::string BaseDllName(ws.begin(), ws.end());

	std::string::size_type i = FullDllName.find(BaseDllName);

	if (i != std::string::npos)
		FullDllName.erase(i, BaseDllName.length());

	memset(SunriseFullPath, 0x0, MAX_PATH);
	strcpy(SunriseFullPath, FullDllName.c_str());

	Sunrise_Dbg("Running from: %s", FullDllName.c_str());


	return SunriseFullPath;
}

BOOL CWriteFile(const CHAR* FilePath, const VOID* Data, DWORD Size)
{
	// Open our file
	HANDLE fHandle = CreateFile(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (fHandle == INVALID_HANDLE_VALUE)
	{
		//DbgPrint("CWriteFile - CreateFile failed");
		return FALSE;
	}

	// Write our data and close
	DWORD writeSize = Size;
	if (WriteFile(fHandle, Data, writeSize, &writeSize, NULL) != TRUE)
	{
		//DbgPrint("CWriteFile - WriteFile failed");
		return FALSE;
	}
	CloseHandle(fHandle);

	// All done
	return TRUE;
}

// DO NOT CALL DIRECTLY. USE DEFINE Sunrise_Dbg instead
VOID Sunrise_Print(const CHAR* fmt, ...)
{
#ifdef DO_PRINTS
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
#endif
}

#pragma region Sunrise2 ini
// Use an app or site to convert ini to byte array - https://tomeko.net/online_tools/file_to_hex.php
// Default ini with comments
BYTE INIDATA[213] = {
	0x5B, 0x4F, 0x50, 0x54, 0x49, 0x4F, 0x4E, 0x53, 0x5D, 0x0D, 0x0A, 0x3B, 0x20, 0x41, 0x6C, 0x6C,
	0x6F, 0x77, 0x73, 0x20, 0x6D, 0x61, 0x74, 0x63, 0x68, 0x6D, 0x61, 0x6B, 0x69, 0x6E, 0x67, 0x20,
	0x74, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6B, 0x20, 0x77, 0x68, 0x65, 0x6E, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x6C, 0x65, 0x61, 0x64, 0x65, 0x72, 0x62, 0x6F, 0x61, 0x72, 0x64, 0x20, 0x41, 0x50, 0x49,
	0x20, 0x69, 0x73, 0x20, 0x64, 0x6F, 0x77, 0x6E, 0x2F, 0x62, 0x72, 0x6F, 0x6B, 0x65, 0x6E, 0x0D,
	0x0A, 0x3B, 0x20, 0x4F, 0x6E, 0x6C, 0x79, 0x20, 0x77, 0x6F, 0x72, 0x6B, 0x73, 0x20, 0x66, 0x6F,
	0x72, 0x20, 0x6E, 0x6F, 0x6E, 0x2D, 0x72, 0x65, 0x74, 0x61, 0x69, 0x6C, 0x20, 0x70, 0x6C, 0x61,
	0x79, 0x65, 0x72, 0x73, 0x0D, 0x0A, 0x49, 0x67, 0x6E, 0x6F, 0x72, 0x65, 0x54, 0x72, 0x75, 0x65,
	0x73, 0x6B, 0x69, 0x6C, 0x6C, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x3B,
	0x20, 0x45, 0x6E, 0x61, 0x62, 0x6C, 0x65, 0x73, 0x20, 0x6D, 0x61, 0x74, 0x63, 0x68, 0x6D, 0x61,
	0x6B, 0x69, 0x6E, 0x67, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6C,
	0x20, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x73, 0x0D, 0x0A, 0x41, 0x6C, 0x6C, 0x6F, 0x77, 0x52,
	0x65, 0x74, 0x61, 0x69, 0x6C, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x73, 0x20, 0x3D, 0x20, 0x74,
	0x72, 0x75, 0x65, 0x0D, 0x0A
};

// Save changes to (use false) or generate new (use true) Sunrise2.ini
VOID Writeini(BOOL GenerateNew)
{
	CSimpleIniA ini_Sunrise_W;
	ini_Sunrise_W.Reset();
	ini_Sunrise_W.SetSpaces(true);
	if (GenerateNew) {
		if (CWriteFile(PATH_INI, INIDATA, sizeof(INIDATA)) == TRUE)
		{
			Sunrise_Dbg("Sunrise2.ini created successfully!");
			Readini();
		}
		else
			Sunrise_Dbg("Failed to create Sunrise2.ini");

	}
	else {
		if (!ini_Sunrise_W.LoadFile(PATH_INI)) {
			ini_Sunrise_W.SetBoolValue("OPTIONS", "IgnoreTrueskill", bIgnoreTrueskill);
			ini_Sunrise_W.SetBoolValue("OPTIONS", "AllowRetailPlayers", bAllowRetailPlayers);
		}
	}

	if (!GenerateNew && !ini_Sunrise_W.SaveFile(PATH_INI))
	{
		//Sunrise_Dbg("Changes saved to Sunrise2.ini!");
		ini_Sunrise_W.Reset();
	}
	else if (!GenerateNew)
	{
		Sunrise_Dbg("Failed to save changes to Sunrise2.ini!");
	}
}

// Read ini values
VOID Readini()
{
	Sunrise_Dbg("Reading values from Sunrise2.ini");
	CSimpleIniA ini_Sunrise_R;
	ini_Sunrise_R.Reset();
	ini_Sunrise_R.SetSpaces(true);
	if (!ini_Sunrise_R.LoadFile(PATH_INI)) {
		
		bIgnoreTrueskill = ini_Sunrise_R.GetBoolValue("OPTIONS", "IgnoreTrueskill", FALSE);
		bAllowRetailPlayers = ini_Sunrise_R.GetBoolValue("OPTIONS", "AllowRetailPlayers", TRUE);
		ini_Sunrise_R.Reset();


		Writeini(FALSE); // This should ensure that any entries missing from the clients ini will be added with default value
	}
	else {
		Sunrise_Dbg("Error reading Sunrise2.ini. Generating new ini...");
		Writeini(TRUE);
	}
}
#pragma endregion