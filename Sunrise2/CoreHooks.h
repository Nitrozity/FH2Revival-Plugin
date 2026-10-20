#pragma once

#ifndef COREHOOKS_H
#define COREHOOKS_H
#include "stdafx.h"

VOID RegisterActiveServer(in_addr address, WORD port, const char description[XTITLE_SERVER_MAX_SERVER_INFO_LEN]);
VOID SetupNetDllHooks();
VOID RegisterHaloLogger(DWORD Address);
VOID SetupXUserReadStatsHook(DWORD Address);
VOID SetupFH2MessageBoxTraceHooks();
VOID SetupFH2NetworkTraceHooks();
VOID SetupFH2EligibilityTraceHooks();
VOID SetupFH2ConnectivityGateTraceHooks();

#endif
VOID SetupFH2BackendQoSTraceHooks();

VOID SetupFH2SocketIOTraceHooks();
VOID SetupFH2PeerTraceHooks();
VOID SetupFH2V095TraceHooks();
VOID FH2_EarlyLogFlag();
VOID FH2_V095_ResetTraceCounters();

VOID SetupFH2XMsgTraceHooks();
VOID SetupFH2SessionRuntimeTraceHooks();

VOID SetupFH2AvailabilityCallerProfiler();

BOOL SetupFH2ProvenanceTraceHooks();

BOOL SetupFH2XamProbeHooks();
VOID FH2_ProbeTick();
VOID FH2_XgiPoll();   // v0.9.19
VOID FH2_HbSnap(DWORD* xgiSeq, DWORD* sendN, DWORD* recvCalls);   // v0.9.20
extern volatile DWORD g_FH2ProbeUntilTick;
VOID FH2_ProbeOpenWindow();
