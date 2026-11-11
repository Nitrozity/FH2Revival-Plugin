#pragma once

#ifndef COREHOOKS_H
#define COREHOOKS_H
#include "stdafx.h"

VOID SetupFH2MessageBoxTraceHooks();
VOID SetupFH2NetworkTraceHooks();
VOID SetupFH2EligibilityTraceHooks();
VOID SetupFH2ConnectivityGateTraceHooks();

#endif
VOID SetupFH2BackendQoSTraceHooks();

VOID SetupFH2SocketIOTraceHooks();
VOID SetupFH2PeerTraceHooks();
VOID SetupFH2V095TraceHooks();
VOID FH2_NtfInstall();
VOID FH2_NtfDrain();
VOID FH2_EarlyLogFlag();
VOID FH2_V095_ResetTraceCounters();

VOID SetupFH2XMsgTraceHooks();
VOID SetupFH2SessionRuntimeTraceHooks();

VOID SetupFH2AvailabilityCallerProfiler();

BOOL SetupFH2ProvenanceTraceHooks();

BOOL SetupFH2XamProbeHooks();
VOID FH2_ProbeTick();
VOID FH2_XgiPoll();   // v0.9.19
VOID FH2_StuckWatch();   // v1.0.29
VOID FH2_GuestNetResync();   // v1.0.33
extern BOOL g_FH2GuestLog, g_FH2GuestArmed;   // v1.0.33
extern BOOL g_FH2GridDiag;   // v1.0.36
extern BOOL g_FH2WaitDiag;   // v1.0.41
extern BOOL g_FH2LockDiag;   // v1.0.43
VOID FH2_WaitDiagPoll(DWORD now);   // v1.0.41
VOID FH2_WaitDiagReset();   // v1.0.41
extern DWORD g_FH2GuestMs;
VOID FH2_SnapObj(const char* tag, DWORD addr, DWORD nWords);   // v1.0.31
VOID FH2_HbSnap(DWORD* xgiSeq, DWORD* sendN, DWORD* recvCalls);   // v0.9.20
extern volatile DWORD g_FH2ProbeUntilTick;
VOID FH2_ProbeOpenWindow();
