//-----------------------------------------------------------------------------
//  FH2Revival (Forza Horizon 2 Online Road Trip revival).  FH2 only: since v1.0.48 it contains no Halo code and does nothing
//  in any other title, so it can sit next to the Halo Sunrise plugin without the two touching the same game.
//  Originally built on Sunrise 2.0.
//
//  Dev:
//			Byrom
// 
//  Credits:
//			craftycodie - Sunrise (plugin hooks / base project)
//-----------------------------------------------------------------------------

#include "stdafx.h"
#include "CoreHooks.h"
#include "Utilities.h"

const char* SunriseVers = "1.0.48";   // FH2Revival version (was the Sunrise 2.x number)

HANDLE hXam;
BOOL bRunContinuous = TRUE;
BOOL bLoopHasComplete = FALSE;
BOOL bIsDevkit; // Set on plugin load. Skips doing xnotify on devkits
DWORD LastTitleId;

DWORD ForzaHorizon2 = 0x4D530AA4;


// -----------------------------------------------------------------------------
// FH2 v0.6.7 Road Trip completion-chain trace
//
// v0.6.6 narrowed the live Road Trip/request objects and exposed the generic
// completion chain in 0x82FEAF10: it calls request vfunc +0x3C, tests the
// boolean, then calls request vfunc +0x44. v0.6.7 instruments those two exact
// dynamic calls without changing their return values or retail state handling.
// The goal is to identify the precise ready/completion edge and snapshot what
// the +0x44 completion processor changes.
// -----------------------------------------------------------------------------
static volatile DWORD g_FH2RoadTripObject = 0;
static volatile DWORD g_FH2RoadTripRawObject = 0;
static volatile LONG  g_FH2RoadTripTapCalls = 0;
static BOOL g_FH2RoadTripTapInstalled = FALSE;

static DWORD g_FH2RoadTripLastObject = 0;
static DWORD g_FH2RoadTripLastWord280 = 0xFFFFFFFF;
static DWORD g_FH2RoadTripLastWord1EC = 0xFFFFFFFF;
static DWORD g_FH2RoadTripLastWord94 = 0xFFFFFFFF;
static BYTE  g_FH2RoadTripLast4D = 0xFF;
static DWORD g_FH2RoadTripTick = 0;
static LONG g_FH2RoadTripLastLoggedCalls = -1;

// Sticky hot-path observations. These are captured before 0x8283E4A0 consumes
// any transient flags, so a one-frame +0x281 pulse cannot be missed by the
// slower worker logger.
static volatile LONG g_FH2RoadTripSaw281 = 0;
static volatile LONG g_FH2RoadTripSaw282 = 0;
static volatile LONG g_FH2RoadTripSaw1EC = 0;
static volatile LONG g_FH2RoadTripSaw1ED = 0;
static volatile LONG g_FH2RoadTripFirst281Call = 0;
static volatile LONG g_FH2RoadTripFirst282Call = 0;
static volatile LONG g_FH2RoadTripFirst1ECCall = 0;
static volatile LONG g_FH2RoadTripFirst1EDCall = 0;
static LONG g_FH2RoadTripLastEventMaskLogged = -1;
static volatile LONG g_FH2RoadTripCompletionSpoofs = 0;
static volatile LONG g_FH2RoadTripFirstCompletionSpoofCall = 0;
static LONG g_FH2RoadTripLastCompletionSpoofsLogged = -1;


// v0.8.3 worker-thread Wireshark synchronization markers.
// Wireshark display filter: udp.port == 36099
static SOCKET g_FH2MarkerSocket = INVALID_SOCKET;
static DWORD g_FH2MarkerObject = 0;
static BOOL g_FH2MarkerSelectedSent = FALSE;
static BOOL g_FH2MarkerRequestSent = FALSE;
static BOOL g_FH2MarkerCompletionSent = FALSE;
static BOOL g_FH2MarkerConsumedSent = FALSE;
static LONG g_FH2MarkerSequence = 0;

static VOID FH2_ResetMarkerState(DWORD object)
{
    g_FH2MarkerObject = object;
    g_FH2MarkerSelectedSent = FALSE;
    g_FH2MarkerRequestSent = FALSE;
    g_FH2MarkerCompletionSent = FALSE;
    g_FH2MarkerConsumedSent = FALSE;
    // v0.8.3: also clear the sticky hot-event flags so a second Road Trip
    // object (backing out and re-entering) produces fresh markers.
    g_FH2RoadTripSaw281 = FALSE;
    g_FH2RoadTripSaw282 = FALSE;
    g_FH2RoadTripSaw1EC = FALSE;
    g_FH2RoadTripSaw1ED = FALSE;
}

static BOOL FH2_EnsureMarkerSocket()
{
    if (g_FH2MarkerSocket != INVALID_SOCKET)
        return TRUE;

    g_FH2MarkerSocket =
        NetDll_socket(XNCALLER_SYSAPP, AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (g_FH2MarkerSocket == INVALID_SOCKET)
    {
        FH2_Log("PROVENANCE MARKER: socket creation failed wsa=%d",
            NetDll_WSAGetLastError());
        return FALSE;
    }

    FH2_Log("PROVENANCE MARKER: UDP socket=%d target=192.168.137.1:36099",
        (int)g_FH2MarkerSocket);
    return TRUE;
}

static VOID FH2_SendMarkerWorker(const CHAR* eventName, DWORD object,
    DWORD request, DWORD playlist, LONG tapCalls)
{
    if (!eventName)
        return;

    SOCKADDR_IN to;
    ZeroMemory(&to, sizeof(to));
    to.sin_family = AF_INET;

    // Xbox 360/PPC is big-endian; literals below are already network order.
    to.sin_addr.S_un.S_addr = 0xC0A88901; // 192.168.137.1
    to.sin_port = 0x8D03;                 // UDP 36099

    LONG seq = InterlockedIncrement(&g_FH2MarkerSequence);
    DWORD tick = GetTickCount();

    CHAR payload[192];
    sprintf_s(payload, sizeof(payload),
        "FH2RT|%s|seq=%d|tick=%u|calls=%d|obj=%08X|req=%08X|playlist=%u",
        eventName, seq, tick, tapCalls, object, request, playlist);

    // v0.8.3: UDP send disabled (never observed in Wireshark; secure-socket
    // drop suspected). Log-only markers.
    int result = 0;
    FH2_Log("PROVENANCE MARKER: event=%s seq=%d tick=%u calls=%d obj=0x%08X req=0x%08X playlist=%u sendResult=%d wsa=%d",
        eventName, seq, tick, tapCalls, object, request, playlist,
        result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
}

// Legacy v0.6.4 computed +0x282 writer capture state (not hooked by v0.6.6).
static volatile LONG g_FH2Computed282CaptureState = 0; // 0=armed, 1=ready/log later
static volatile LONG g_FH2Computed282HitCount = 0;
static DWORD g_FH2Computed282Object = 0;
static DWORD g_FH2Computed282RawReturn = 0;
static DWORD g_FH2Computed282Bool = 0;
static DWORD g_FH2Computed282State268 = 0;
static DWORD g_FH2Computed282Owner = 0;
static DWORD g_FH2Computed282Owner208 = 0;
static DWORD g_FH2Computed282Owner208Vtable = 0;
static DWORD g_FH2Computed282Vfunc38 = 0;
static DWORD g_FH2Computed282Request = 0;
static DWORD g_FH2Computed282TapCall = 0;
static BOOL  g_FH2Computed282Logged = FALSE;


// v0.6.0 exact-callsite dispatch capture. No file I/O occurs in the hook; the
// worker thread logs the captured snapshot later.
#define FH2_DISPATCH_SNAPSHOT_START 0x80
#define FH2_DISPATCH_SNAPSHOT_END   0x2A0
#define FH2_DISPATCH_SNAPSHOT_WORDS (((FH2_DISPATCH_SNAPSHOT_END - FH2_DISPATCH_SNAPSHOT_START) / 4) + 1)
static volatile LONG  g_FH2DispatchCaptureState = 0; // 0=armed, 1=capturing, 2=ready/logged later
static DWORD g_FH2DispatchCaptureObject = 0;
static DWORD g_FH2DispatchStateArg = 0;
static DWORD g_FH2DispatchReturn = 0;
static DWORD g_FH2DispatchBefore[FH2_DISPATCH_SNAPSHOT_WORDS];
static DWORD g_FH2DispatchAfter[FH2_DISPATCH_SNAPSHOT_WORDS];
static BOOL  g_FH2DispatchCaptureLogged = FALSE;

typedef DWORD (*FH2_DISPATCH_FN)(DWORD object, DWORD state);

static DWORD FH2_CaptureDispatchExact(DWORD object, DWORD state)
{
    BOOL capture = (InterlockedCompareExchange(&g_FH2DispatchCaptureState, 1, 0) == 0);
    if (capture)
    {
        g_FH2DispatchCaptureObject = object;
        g_FH2DispatchStateArg = state;
        DWORD i = 0;
        for (DWORD offset = FH2_DISPATCH_SNAPSHOT_START; offset <= FH2_DISPATCH_SNAPSHOT_END; offset += 4, ++i)
            g_FH2DispatchBefore[i] = *((volatile DWORD*)(object + offset));
    }

    FH2_DISPATCH_FN dispatch = (FH2_DISPATCH_FN)0x827FF930;
    DWORD result = dispatch(object, state);

    if (capture)
    {
        g_FH2DispatchReturn = result;
        DWORD i = 0;
        for (DWORD offset = FH2_DISPATCH_SNAPSHOT_START; offset <= FH2_DISPATCH_SNAPSHOT_END; offset += 4, ++i)
            g_FH2DispatchAfter[i] = *((volatile DWORD*)(object + offset));
        InterlockedExchange(&g_FH2DispatchCaptureState, 2);
    }
    return result;
}

__declspec(naked) VOID FH2_RoadTripExactDispatchCallHook()
{
    __asm
    {
        // v0.6.8 force-transition sweep. Retail reaches this call only after
        // the playlist request completes. Instead of dispatching state 0
        // (the path that produces Server N/A on current hardware), choose a
        // different already-valid dispatcher state based on the selected
        // playlist. This lets one compiled plugin test four transition
        // hypotheses:
        //   Amateur (2)    -> state 1
        //   Pro (3)        -> state 2
        //   Pure Skill (4) -> state 6
        //   Playground (5) -> state 7
        // Unknown playlist falls back to retail state 0.
        //
        // Replaces retail 0x8283E4D4..0x8283E4E0:
        //   li r4,0 ; mr r3,r31 ; bl 0x827FF930 ; li r11,0
        // PatchInJump(..., linked=TRUE) sets LR to 0x8283E4E4.
        mflr    r12
        stwu    r1, -0x70(r1)
        stw     r12, 0x68(r1)

        lbz     r11, 0x280(r31)
        cmpwi   cr6, r11, 2
        bne     cr6, force_check_pro
        li      r4, 1
        b       force_call

force_check_pro:
        cmpwi   cr6, r11, 3
        bne     cr6, force_check_pure
        li      r4, 2
        b       force_call

force_check_pure:
        cmpwi   cr6, r11, 4
        bne     cr6, force_check_playground
        li      r4, 6
        b       force_call

force_check_playground:
        cmpwi   cr6, r11, 5
        bne     cr6, force_retail
        li      r4, 7
        b       force_call

force_retail:
        li      r4, 0

force_call:
        mr      r3, r31
        bl      FH2_CaptureDispatchExact
        lwz     r12, 0x68(r1)
        addi    r1, r1, 0x70
        mtlr    r12
        li      r11, 0
        blr
    }
}

static VOID FH2_LogDispatchCaptureIfReady()
{
    if (g_FH2DispatchCaptureLogged || g_FH2DispatchCaptureState != 2)
        return;

    g_FH2DispatchCaptureLogged = TRUE;
    FH2_Log("ROADTRIP EXACT DISPATCH CAPTURE: obj=0x%08X stateArg=%u return=0x%08X",
        g_FH2DispatchCaptureObject, g_FH2DispatchStateArg, g_FH2DispatchReturn);

    DWORD changes = 0;
    for (DWORD i = 0; i < FH2_DISPATCH_SNAPSHOT_WORDS; ++i)
    {
        if (g_FH2DispatchBefore[i] == g_FH2DispatchAfter[i])
            continue;
        DWORD offset = FH2_DISPATCH_SNAPSHOT_START + (i * 4);
        FH2_Log("ROADTRIP DISPATCH DIFF: +0x%03X %08X -> %08X",
            offset, g_FH2DispatchBefore[i], g_FH2DispatchAfter[i]);
        ++changes;
    }
    FH2_Log("ROADTRIP DISPATCH DIFF SUMMARY: changes=%u", changes);
}

static VOID FH2_LogRuntimeDispatchCode()
{
    // 0x200 bytes is intentionally enough to cover the target and its immediate
    // helper body on the TU1 runtime image while keeping the startup log small.
    FH2_Log("ROADTRIP DISPATCH TARGET CODE: begin 0x827FF900..0x827FFB2C");
    for (DWORD a = 0x827FF900; a <= 0x827FFB2C; a += 4)
        FH2_Log("ROADTRIP DISPATCH TARGET CODE: 0x%08X = 0x%08X", a, *((DWORD*)a));
    FH2_Log("ROADTRIP DISPATCH TARGET CODE: end");
}



static BOOL FH2_IsLikelyReadablePointer(DWORD p);

// -----------------------------------------------------------------------------
// v0.7.7 Road Trip local-method runtime trace
//
// v0.7.6 proved the local E218/E298/E358/E428 methods have no direct BL callers,
// which is exactly what we expect for vtable-dispatched UI/state callbacks.
// v0.7.7 taps three safe points *after their prologues* so we can see which
// method fires when the player enters Road Trip and selects a playlist.
//
// No file I/O occurs in these hooks.  They only snapshot registers/fields;
// FH2_RoadTripStateTick() writes the log later.
// -----------------------------------------------------------------------------
struct FH2_LOCAL_METHOD_SNAPSHOT
{
    volatile LONG serial;
    volatile LONG hits;
    DWORD site;
    DWORD r3;
    DWORD r4;
    DWORD r5;
    DWORD r6;
    DWORD r7;
    DWORD r8;
    DWORD vtable;
    DWORD word94;
    DWORD word200;
    DWORD word204;
    DWORD word26C;
    DWORD word27C;
    DWORD word280;
    DWORD word284;
    BYTE byte1EC;
    BYTE byte1ED;
    BYTE byte281;
    BYTE byte282;
};

static FH2_LOCAL_METHOD_SNAPSHOT g_FH2LocalMethodSnaps[3];
static LONG g_FH2LocalMethodLoggedSerial[3] = { 0, 0, 0 };

static VOID FH2_RecordLocalMethodRuntime(DWORD site, DWORD r3, DWORD r4, DWORD r5, DWORD r6, DWORD r7, DWORD r8)
{
    int idx = -1;
    if (site == 0x8283E22C) idx = 0;       // body of vtable method 0x8283E218
    else if (site == 0x8283E2A8) idx = 1;  // body of vtable method 0x8283E298
    else if (site == 0x8283E36C) idx = 2;  // body of vtable method 0x8283E358
    if (idx < 0)
        return;

    FH2_LOCAL_METHOD_SNAPSHOT* s = &g_FH2LocalMethodSnaps[idx];
    s->site = site;
    s->r3 = r3;
    s->r4 = r4;
    s->r5 = r5;
    s->r6 = r6;
    s->r7 = r7;
    s->r8 = r8;

    if (FH2_IsLikelyReadablePointer(r3))
    {
        s->vtable = *((volatile DWORD*)(r3 + 0x00));
        s->word94 = *((volatile DWORD*)(r3 + 0x94));
        s->word200 = *((volatile DWORD*)(r3 + 0x200));
        s->word204 = *((volatile DWORD*)(r3 + 0x204));
        s->word26C = *((volatile DWORD*)(r3 + 0x26C));
        s->word27C = *((volatile DWORD*)(r3 + 0x27C));
        s->word280 = *((volatile DWORD*)(r3 + 0x280));
        s->word284 = *((volatile DWORD*)(r3 + 0x284));
        s->byte1EC = *((volatile BYTE*)(r3 + 0x1EC));
        s->byte1ED = *((volatile BYTE*)(r3 + 0x1ED));
        s->byte281 = *((volatile BYTE*)(r3 + 0x281));
        s->byte282 = *((volatile BYTE*)(r3 + 0x282));
    }
    else
    {
        s->vtable = 0;
        s->word94 = s->word200 = s->word204 = s->word26C = 0;
        s->word27C = s->word280 = s->word284 = 0;
        s->byte1EC = s->byte1ED = s->byte281 = s->byte282 = 0;
    }

    InterlockedIncrement(&s->hits);
    InterlockedIncrement(&s->serial);
}

static VOID FH2_LogLocalMethodRuntime()
{
    for (int i = 0; i < 3; ++i)
    {
        LONG serial = g_FH2LocalMethodSnaps[i].serial;
        if (serial == 0 || serial == g_FH2LocalMethodLoggedSerial[i])
            continue;

        g_FH2LocalMethodLoggedSerial[i] = serial;
        FH2_LOCAL_METHOD_SNAPSHOT* s = &g_FH2LocalMethodSnaps[i];

        FH2_Log("ROADTRIP LOCAL METHOD HIT: site=0x%08X hits=%d r3=0x%08X r4=0x%08X r5=0x%08X r6=0x%08X r7=0x%08X r8=0x%08X vt=0x%08X",
            s->site, s->hits, s->r3, s->r4, s->r5, s->r6, s->r7, s->r8, s->vtable);
        FH2_Log("ROADTRIP LOCAL METHOD STATE: site=0x%08X +94=0x%08X +200=0x%08X +204=0x%08X +26C=0x%08X +27C=0x%08X +280=0x%08X +284=0x%08X +1EC=%u +1ED=%u +281=%u +282=%u",
            s->site, s->word94, s->word200, s->word204, s->word26C,
            s->word27C, s->word280, s->word284,
            s->byte1EC, s->byte1ED, s->byte281, s->byte282);
    }
}

__declspec(naked) VOID FH2_LocalMethodHook_E22C()
{
    __asm
    {
        // Capture the original method arguments before retail mutates them.
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        lis     r3, 0x8283
        ori     r3, r3, 0xE22C
        lwz     r4, 0x24(r1)
        lwz     r5, 0x28(r1)
        lwz     r6, 0x2C(r1)
        lwz     r7, 0x30(r1)
        lwz     r8, 0x34(r1)
        lwz     r9, 0x38(r1)
        bl      FH2_RecordLocalMethodRuntime

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        // Retail 0x8283E22C..0x8283E238.
        mr      r31, r3
        addi    r3, r11, -0x1C34
        lis     r12, 0x8300
        ori     r12, r12, 0x1ED0
        mtctr   r12
        bctrl
        mr      r4, r3

        lis     r12, 0x8283
        ori     r12, r12, 0xE23C
        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_LocalMethodHook_E2A8()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        lis     r3, 0x8283
        ori     r3, r3, 0xE2A8
        lwz     r4, 0x24(r1)
        lwz     r5, 0x28(r1)
        lwz     r6, 0x2C(r1)
        lwz     r7, 0x30(r1)
        lwz     r8, 0x34(r1)
        lwz     r9, 0x38(r1)
        bl      FH2_RecordLocalMethodRuntime

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        // Retail 0x8283E2A8..0x8283E2B4.
        mr      r31, r3
        mr      r28, r5
        mr      r27, r6
        lwz     r11, 0xA194(r11)

        lis     r12, 0x8283
        ori     r12, r12, 0xE2B8
        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_LocalMethodHook_E36C()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        lis     r3, 0x8283
        ori     r3, r3, 0xE36C
        lwz     r4, 0x24(r1)
        lwz     r5, 0x28(r1)
        lwz     r6, 0x2C(r1)
        lwz     r7, 0x30(r1)
        lwz     r8, 0x34(r1)
        lwz     r9, 0x38(r1)
        bl      FH2_RecordLocalMethodRuntime

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        // Retail 0x8283E36C..0x8283E378.
        mr      r31, r3
        addi    r3, r3, 0x204
        mr      r30, r4
        lis     r12, 0x826C
        ori     r12, r12, 0xED10
        mtctr   r12
        bctrl

        lis     r12, 0x8283
        ori     r12, r12, 0xE37C
        mtctr   r12
        bctr
    }
}


// -----------------------------------------------------------------------------
// v0.7.8 exact playlist-selection callback trace
//
// 0x82838CE0 is the exact TU09 instruction that writes the chosen playlist byte:
//     stb r4,0x280(r31)
// It is shared by Road Trip vtable methods 0x82838C80 / 0x82838C28.
// Immediately after the store, retail calls 0x826D63C0 with r3 = obj+0x204.
//
// Unlike the earlier E218/E298 hooks, this site does not depend on an incoming
// r11 value across PatchInJump, so it is safe to trampoline.
//
// We capture only selection values 2..5 and preserve all retail behavior.
// -----------------------------------------------------------------------------
struct FH2_SELECTION_SNAPSHOT
{
    volatile LONG serial;
    volatile LONG hits;
    DWORD object;
    DWORD vtable;
    DWORD selected;
    DWORD requestBefore;
    DWORD requestAfterHelper;
    DWORD word200;
    DWORD word204;
    DWORD word26C;
    DWORD word27C;
    DWORD word284;
    DWORD savedOuterReturn;
    DWORD currentLR;
    BYTE byte1EC;
    BYTE byte1ED;
    BYTE byte281;
    BYTE byte282;
};

static FH2_SELECTION_SNAPSHOT g_FH2SelectionSnapshot;
static LONG g_FH2SelectionLoggedSerial = 0;

static VOID FH2_RecordSelectionCallbackFast(DWORD object, DWORD selected, DWORD savedOuterReturn, DWORD currentLR)
{
    BYTE playlist = (BYTE)(selected & 0xFF);
    if (playlist < 2 || playlist > 5)
        return;

    if (!FH2_IsLikelyReadablePointer(object))
        return;

    DWORD vt = *((volatile DWORD*)(object + 0x00));
    if (vt != 0x820728D4)
        return;

    FH2_SELECTION_SNAPSHOT* s = &g_FH2SelectionSnapshot;
    s->object = object;
    s->vtable = vt;
    s->selected = playlist;
    s->requestBefore = *((volatile DWORD*)(object + 0x94));
    s->requestAfterHelper = 0xFFFFFFFF;
    s->word200 = *((volatile DWORD*)(object + 0x200));
    s->word204 = *((volatile DWORD*)(object + 0x204));
    s->word26C = *((volatile DWORD*)(object + 0x26C));
    s->word27C = *((volatile DWORD*)(object + 0x27C));
    s->word284 = *((volatile DWORD*)(object + 0x284));
    s->savedOuterReturn = savedOuterReturn;
    s->currentLR = currentLR;
    s->byte1EC = *((volatile BYTE*)(object + 0x1EC));
    s->byte1ED = *((volatile BYTE*)(object + 0x1ED));
    s->byte281 = *((volatile BYTE*)(object + 0x281));
    s->byte282 = *((volatile BYTE*)(object + 0x282));

    InterlockedIncrement(&s->hits);
    InterlockedIncrement(&s->serial);
}

static VOID FH2_RecordSelectionAfterHelperFast(DWORD object)
{
    if (!FH2_IsLikelyReadablePointer(object))
        return;

    if (*((volatile DWORD*)object) != 0x820728D4)
        return;

    g_FH2SelectionSnapshot.requestAfterHelper =
        *((volatile DWORD*)(object + 0x94));
}

static VOID FH2_LogSelectionCallbackIfReady()
{
    LONG serial = g_FH2SelectionSnapshot.serial;
    if (serial == 0 || serial == g_FH2SelectionLoggedSerial)
        return;

    g_FH2SelectionLoggedSerial = serial;
    FH2_SELECTION_SNAPSHOT* s = &g_FH2SelectionSnapshot;

    FH2_Log("ROADTRIP SELECTION CALLBACK HIT: hits=%d obj=0x%08X vt=0x%08X selected=%u requestBefore=0x%08X requestAfterHelper=0x%08X",
        s->hits, s->object, s->vtable, s->selected, s->requestBefore, s->requestAfterHelper);
    FH2_Log("ROADTRIP SELECTION CALLBACK STATE: +200=0x%08X +204=0x%08X +26C=0x%08X +27C=0x%08X +284=0x%08X +1EC=%u +1ED=%u +281=%u +282=%u",
        s->word200, s->word204, s->word26C, s->word27C, s->word284,
        s->byte1EC, s->byte1ED, s->byte281, s->byte282);
    FH2_Log("ROADTRIP SELECTION CALLBACK RETURN: savedOuter=0x%08X currentLR=0x%08X",
        s->savedOuterReturn, s->currentLR);

    // The current LR at this hook is expected to be the return from the vfunc
    // call immediately before the playlist store. The function's saved outer
    // LR is more useful: it identifies the indirect vtable callsite that invoked
    // the playlist callback. Dump a focused window around that return address.
    DWORD ret = s->savedOuterReturn;
    if (ret >= 0x82000040 && ret < 0x84000000)
    {
        DWORD begin = ret - 0x40;
        DWORD end = ret + 0x60;
        FH2_Log("ROADTRIP SELECTION CALLER CODE: begin 0x%08X..0x%08X return=0x%08X", begin, end, ret);
        for (DWORD a = begin; a <= end; a += 4)
            FH2_Log("ROADTRIP SELECTION CALLER CODE: %c 0x%08X = 0x%08X",
                (a == ret ? '>' : ' '), a, *((volatile DWORD*)a));
        FH2_Log("ROADTRIP SELECTION CALLER CODE: end");
    }
    else
    {
        FH2_Log("ROADTRIP SELECTION CALLER CODE: saved outer return 0x%08X outside expected XEX range.", ret);
    }
}

__declspec(naked) VOID FH2_SelectionCallbackHook_CE0()
{
    __asm
    {
        // Preserve volatile state while recording the exact playlist write.
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        // Arguments:
        // r3 = Road Trip object (r31)
        // r4 = selected playlist byte
        // r5 = saved outer LR from the retail frame. The current retail frame
        //      is 0x70 bytes; after our -0xA0 frame, saved LR is at +0x108.
        // r6 = current LR (normally 0x82838CD8 after the preceding bctrl).
        mr      r3, r31
        lwz     r4, 0x28(r1)
        lwz     r5, 0x108(r1)
        lwz     r6, 0x4C(r1)
        bl      FH2_RecordSelectionCallbackFast

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        // Replay retail 0x82838CE0..0x82838CEC exactly.
        stb     r4, 0x280(r31)

        lis     r12, 0x826D
        ori     r12, r12, 0x63C0
        mtctr   r12
        bctrl

        // Exact request-birth checkpoint: did the helper itself populate
        // RoadTrip+0x94?  This runs synchronously before the retail global
        // selection store at 0x82838CF0.
        mr      r3, r31
        bl      FH2_RecordSelectionAfterHelperFast

        lbz     r11, 0x280(r31)
        lis     r10, 0x8338

        // Resume at retail 0x82838CF0 (stw r11,0x7758(r10)).
        lis     r12, 0x8284
        addi    r12, r12, -0x7310
        mtctr   r12
        bctr
    }
}

static const char* FH2_DFormOpName(DWORD opcode)
{
    switch (opcode)
    {
    case 32: return "lwz";
    case 33: return "lwzu";
    case 34: return "lbz";
    case 35: return "lbzu";
    case 36: return "stw";
    case 37: return "stwu";
    case 38: return "stb";
    case 39: return "stbu";
    case 40: return "lhz";
    case 41: return "lhzu";
    case 42: return "lha";
    case 43: return "lhau";
    case 44: return "sth";
    case 45: return "sthu";
    default: return "dform";
    }
}

static VOID FH2_ScanSelectionGlobalRefs(PLDR_DATA_TABLE_ENTRY module)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 0x40)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;

    FH2_Log("ROADTRIP SELECTION GLOBAL SCAN: target=0x83387758 begin");

    // TU09's confirmed writer uses:
    //   lis r10,0x8338
    //   ...
    //   stw r11,0x7758(r10)
    //
    // Find every analogous reference where the same base register was loaded
    // with lis ...,0x8338 within the preceding 8 instructions.
    for (DWORD a = start + 0x20; a + 4 <= end; a += 4)
    {
        DWORD insn = *((volatile DWORD*)a);
        DWORD opcode = insn >> 26;
        if (!(opcode == 32 || opcode == 33 || opcode == 34 || opcode == 35 ||
              opcode == 36 || opcode == 37 || opcode == 38 || opcode == 39 ||
              opcode == 40 || opcode == 41 || opcode == 42 || opcode == 43 ||
              opcode == 44 || opcode == 45))
            continue;

        if ((WORD)(insn & 0xFFFF) != 0x7758)
            continue;

        DWORD ra = (insn >> 16) & 0x1F;
        if (ra == 0)
            continue;

        BOOL baseConfirmed = FALSE;
        DWORD lisAt = 0;
        for (DWORD back = 4; back <= 0x20; back += 4)
        {
            DWORD p = a - back;
            DWORD prev = *((volatile DWORD*)p);
            DWORD prevOp = prev >> 26;
            DWORD rt = (prev >> 21) & 0x1F;
            DWORD prevRa = (prev >> 16) & 0x1F;
            WORD imm = (WORD)(prev & 0xFFFF);

            // lis rN,imm == addis rN,r0,imm
            if (prevOp == 15 && rt == ra && prevRa == 0)
            {
                if (imm == 0x8338)
                {
                    baseConfirmed = TRUE;
                    lisAt = p;
                }
                break;
            }
        }

        if (!baseConfirmed)
            continue;

        ++matches;
        DWORD rt = (insn >> 21) & 0x1F;
        FH2_Log("ROADTRIP SELECTION GLOBAL REF: at=0x%08X op=%s r%u,0x7758(r%u) lisAt=0x%08X insn=%08X",
            a, FH2_DFormOpName(opcode), rt, ra, lisAt, insn);

        DWORD winStart = (a >= start + 0x50) ? a - 0x50 : start;
        DWORD winEnd = a + 0x70;
        if (winEnd + 4 > end)
            winEnd = end - 4;

        FH2_Log("ROADTRIP SELECTION GLOBAL REF CODE: begin 0x%08X..0x%08X ref=0x%08X",
            winStart, winEnd, a);
        for (DWORD p = winStart; p <= winEnd; p += 4)
            FH2_Log("ROADTRIP SELECTION GLOBAL REF CODE: %c 0x%08X = 0x%08X",
                (p == a ? '>' : ' '), p, *((volatile DWORD*)p));
        FH2_Log("ROADTRIP SELECTION GLOBAL REF CODE: end");
    }

    FH2_Log("ROADTRIP SELECTION GLOBAL SCAN: target=0x83387758 matches=%u end", matches);
}

static VOID FH2_DumpSelectionHelperCode()
{
    FH2_Log("ROADTRIP SELECTION HELPER CODE: begin 0x826D6380..0x826D6500");
    for (DWORD a = 0x826D6380; a <= 0x826D6500; a += 4)
        FH2_Log("ROADTRIP SELECTION HELPER CODE: 0x%08X = 0x%08X", a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP SELECTION HELPER CODE: end");
}

// -----------------------------------------------------------------------------
// v0.6.1 completion-producer tracing
// -----------------------------------------------------------------------------
#define FH2_PRODUCER_REQ_WORDS 32
#define FH2_PRODUCER_VT_WORDS  32

static volatile LONG g_FH2ProducerCaptureState = 0; // 0=armed, 1=capturing, 2=ready
static DWORD g_FH2ProducerSite = 0;
static DWORD g_FH2ProducerObject = 0;
static DWORD g_FH2ProducerValue = 0;
static DWORD g_FH2ProducerAux1 = 0;
static DWORD g_FH2ProducerAux2 = 0;
static BYTE  g_FH2ProducerPre281 = 0;
static BYTE  g_FH2ProducerPre282 = 0;
static BYTE  g_FH2ProducerPre1EC = 0;
static BYTE  g_FH2ProducerPre1ED = 0;
static DWORD g_FH2ProducerPlaylistWord = 0;
static DWORD g_FH2ProducerRequest = 0;
static DWORD g_FH2ProducerRequestVtable = 0;
static DWORD g_FH2ProducerRequestWords[FH2_PRODUCER_REQ_WORDS];
static DWORD g_FH2ProducerVtableWords[FH2_PRODUCER_VT_WORDS];
static BOOL  g_FH2ProducerCaptureLogged = FALSE;

static BOOL FH2_IsLikelyReadablePointer(DWORD p)
{
    // v0.8.31: the old version only range-checked the address. The 500 ms worker reads fields up to +0x290 of the
    // Road Trip object; once the game freed that object (lobby created / Online Road Trip exited) the read hit an
    // unmapped page -> access violation in OUR thread -> DashLaunch "Fatal Crash Intercepted". Check real mapping
    // for the whole 0x300-byte span.
    if (p & 3)
        return FALSE;
    if (!((p >= 0x20000000 && p < 0x50000000) || (p >= 0x80000000 && p < 0x90000000)))
        return FALSE;
    for (DWORD o = 0; o < 0x300; o += 0x1000)
        if (!MmIsAddressValid((PVOID)(p + o))) return FALSE;
    return MmIsAddressValid((PVOID)(p + 0x2FF)) ? TRUE : FALSE;
}

static VOID FH2_RecordCompletionProducer(DWORD object, DWORD value, DWORD site, DWORD aux1, DWORD aux2)
{
    if (!object || object != g_FH2RoadTripObject)
        return;

    DWORD playlistWord = *((volatile DWORD*)(object + 0x280));
    BYTE playlist = *((volatile BYTE*)(object + 0x280));
    DWORD request = *((volatile DWORD*)(object + 0x94));

    // Only arm on an actual active playlist request. This prevents screen-entry
    // initialization/reset stores from stealing the one-shot capture.
    if (playlist < 2 || playlist > 5 || !FH2_IsLikelyReadablePointer(request))
        return;

    if (InterlockedCompareExchange(&g_FH2ProducerCaptureState, 1, 0) != 0)
        return;

    g_FH2ProducerSite = site;
    g_FH2ProducerObject = object;
    g_FH2ProducerValue = value;
    g_FH2ProducerAux1 = aux1;
    g_FH2ProducerAux2 = aux2;
    g_FH2ProducerPre281 = *((volatile BYTE*)(object + 0x281));
    g_FH2ProducerPre282 = *((volatile BYTE*)(object + 0x282));
    g_FH2ProducerPre1EC = *((volatile BYTE*)(object + 0x1EC));
    g_FH2ProducerPre1ED = *((volatile BYTE*)(object + 0x1ED));
    g_FH2ProducerPlaylistWord = playlistWord;
    g_FH2ProducerRequest = request;

    DWORD i;
    for (i = 0; i < FH2_PRODUCER_REQ_WORDS; ++i)
        g_FH2ProducerRequestWords[i] = *((volatile DWORD*)(request + (i * 4)));

    DWORD vt = g_FH2ProducerRequestWords[0];
    g_FH2ProducerRequestVtable = vt;
    if (FH2_IsLikelyReadablePointer(vt))
    {
        for (i = 0; i < FH2_PRODUCER_VT_WORDS; ++i)
            g_FH2ProducerVtableWords[i] = *((volatile DWORD*)(vt + (i * 4)));
    }
    else
    {
        for (i = 0; i < FH2_PRODUCER_VT_WORDS; ++i)
            g_FH2ProducerVtableWords[i] = 0;
    }

    InterlockedExchange(&g_FH2ProducerCaptureState, 2);
}

static VOID FH2_LogCompletionProducerIfReady()
{
    if (g_FH2ProducerCaptureLogged || g_FH2ProducerCaptureState != 2)
        return;

    g_FH2ProducerCaptureLogged = TRUE;
    FH2_Log("ROADTRIP PRODUCER HIT: site=0x%08X obj=0x%08X value=0x%08X aux1=0x%08X aux2=0x%08X",
        g_FH2ProducerSite, g_FH2ProducerObject, g_FH2ProducerValue, g_FH2ProducerAux1, g_FH2ProducerAux2);
    FH2_Log("ROADTRIP PRODUCER PRESTATE: +281=%u +282=%u +1EC=%u +1ED=%u +280word=%08X +94=request=0x%08X reqVT=0x%08X",
        g_FH2ProducerPre281, g_FH2ProducerPre282, g_FH2ProducerPre1EC, g_FH2ProducerPre1ED,
        g_FH2ProducerPlaylistWord, g_FH2ProducerRequest, g_FH2ProducerRequestVtable);

    DWORD start = g_FH2ProducerSite - 0x60;
    DWORD end = g_FH2ProducerSite + 0x80;
    FH2_Log("ROADTRIP PRODUCER CODE: begin 0x%08X..0x%08X around site 0x%08X", start, end, g_FH2ProducerSite);
    for (DWORD a = start; a <= end; a += 4)
        FH2_Log("ROADTRIP PRODUCER CODE: %s0x%08X = 0x%08X", (a == g_FH2ProducerSite) ? "> " : "  ", a, *((DWORD*)a));
    FH2_Log("ROADTRIP PRODUCER CODE: end");

    FH2_Log("ROADTRIP REQUEST SNAPSHOT: ptr=0x%08X", g_FH2ProducerRequest);
    for (DWORD i = 0; i < FH2_PRODUCER_REQ_WORDS; i += 4)
    {
        FH2_Log("ROADTRIP REQUEST +0x%02X: %08X %08X %08X %08X",
            i * 4,
            g_FH2ProducerRequestWords[i + 0],
            g_FH2ProducerRequestWords[i + 1],
            g_FH2ProducerRequestWords[i + 2],
            g_FH2ProducerRequestWords[i + 3]);
    }

    FH2_Log("ROADTRIP REQUEST VTABLE SNAPSHOT: vt=0x%08X", g_FH2ProducerRequestVtable);
    for (DWORD i = 0; i < FH2_PRODUCER_VT_WORDS; i += 4)
    {
        FH2_Log("ROADTRIP REQVT +0x%02X: %08X %08X %08X %08X",
            i * 4,
            g_FH2ProducerVtableWords[i + 0],
            g_FH2ProducerVtableWords[i + 1],
            g_FH2ProducerVtableWords[i + 2],
            g_FH2ProducerVtableWords[i + 3]);
    }
}


// -----------------------------------------------------------------------------
// v0.6.2 active-request baseline/completion trace
// -----------------------------------------------------------------------------
#define FH2_REQUEST_TRACE_WORDS 256
#define FH2_REQUEST_TRACE_VT_WORDS 64

// 0 = waiting for active request, 1 = baseline captured,
// 3 = completion capture in progress, 2 = completion captured / ready to log.
static volatile LONG g_FH2RequestTraceState = 0;
static DWORD g_FH2RequestBaselineCall = 0;
static DWORD g_FH2RequestCompletionCall = 0;
static DWORD g_FH2RequestBaselinePtr = 0;
static DWORD g_FH2RequestCompletionPtr = 0;
static DWORD g_FH2RequestBaselineVtable = 0;
static DWORD g_FH2RequestCompletionVtable = 0;
static DWORD g_FH2RequestBaselineWords[FH2_REQUEST_TRACE_WORDS];
static DWORD g_FH2RequestCompletionWords[FH2_REQUEST_TRACE_WORDS];
static DWORD g_FH2RequestVtableWords[FH2_REQUEST_TRACE_VT_WORDS];
static BYTE g_FH2RequestCompletion281 = 0;
static BYTE g_FH2RequestCompletion282 = 0;
static BYTE g_FH2RequestCompletion1EC = 0;
static BYTE g_FH2RequestCompletion1ED = 0;
static BOOL g_FH2RequestTraceLogged = FALSE;


// -----------------------------------------------------------------------------
// v0.6.3 request pointee/payload trace
// -----------------------------------------------------------------------------
#define FH2_PAYLOAD_SCAN_REQ_WORDS 128   // first 0x200 bytes of request
#define FH2_PAYLOAD_MAX_PTRS 32
#define FH2_PAYLOAD_WORDS_PER_PTR 32     // first 0x80 bytes behind each pointer

static DWORD g_FH2PayloadPtrCount = 0;
static DWORD g_FH2PayloadReqOffset[FH2_PAYLOAD_MAX_PTRS];
static DWORD g_FH2PayloadPtr[FH2_PAYLOAD_MAX_PTRS];
static DWORD g_FH2PayloadBaseline[FH2_PAYLOAD_MAX_PTRS][FH2_PAYLOAD_WORDS_PER_PTR];
static DWORD g_FH2PayloadCompletion[FH2_PAYLOAD_MAX_PTRS][FH2_PAYLOAD_WORDS_PER_PTR];
static BOOL  g_FH2PayloadCompletionCaptured = FALSE;
static BOOL  g_FH2PayloadLogged = FALSE;

static BOOL FH2_IsLikelyHeapPointer(DWORD p)
{
    if (p & 3)
        return FALSE;
    return (p >= 0x20000000 && p < 0x40000000);
}

static VOID FH2_CapturePayloadBaseline(DWORD request)
{
    g_FH2PayloadPtrCount = 0;
    g_FH2PayloadCompletionCaptured = FALSE;
    g_FH2PayloadLogged = FALSE;

    for (DWORD i = 0; i < FH2_PAYLOAD_SCAN_REQ_WORDS && g_FH2PayloadPtrCount < FH2_PAYLOAD_MAX_PTRS; ++i)
    {
        DWORD p = *((volatile DWORD*)(request + (i * 4)));
        if (!FH2_IsLikelyHeapPointer(p))
            continue;

        BOOL duplicate = FALSE;
        for (DWORD j = 0; j < g_FH2PayloadPtrCount; ++j)
        {
            if (g_FH2PayloadPtr[j] == p)
            {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate)
            continue;

        DWORD slot = g_FH2PayloadPtrCount++;
        g_FH2PayloadReqOffset[slot] = i * 4;
        g_FH2PayloadPtr[slot] = p;
        for (DWORD w = 0; w < FH2_PAYLOAD_WORDS_PER_PTR; ++w)
            g_FH2PayloadBaseline[slot][w] = *((volatile DWORD*)(p + (w * 4)));
    }
}

static VOID FH2_CapturePayloadCompletion()
{
    if (g_FH2PayloadCompletionCaptured)
        return;

    for (DWORD slot = 0; slot < g_FH2PayloadPtrCount; ++slot)
    {
        DWORD p = g_FH2PayloadPtr[slot];
        for (DWORD w = 0; w < FH2_PAYLOAD_WORDS_PER_PTR; ++w)
            g_FH2PayloadCompletion[slot][w] = *((volatile DWORD*)(p + (w * 4)));
    }
    g_FH2PayloadCompletionCaptured = TRUE;
}

static VOID FH2_LogPayloadTraceIfReady()
{
    if (g_FH2PayloadLogged || !g_FH2PayloadCompletionCaptured)
        return;

    g_FH2PayloadLogged = TRUE;
    FH2_Log("ROADTRIP PAYLOAD TRACE: request=0x%08X ptrs=%u", g_FH2RequestBaselinePtr, g_FH2PayloadPtrCount);

    DWORD changedPtrs = 0;
    DWORD changedWords = 0;
    for (DWORD slot = 0; slot < g_FH2PayloadPtrCount; ++slot)
    {
        BOOL ptrChanged = FALSE;
        for (DWORD w = 0; w < FH2_PAYLOAD_WORDS_PER_PTR; ++w)
        {
            if (g_FH2PayloadBaseline[slot][w] == g_FH2PayloadCompletion[slot][w])
                continue;

            if (!ptrChanged)
            {
                ptrChanged = TRUE;
                ++changedPtrs;
                FH2_Log("ROADTRIP PAYLOAD PTR: req+0x%03X -> 0x%08X", g_FH2PayloadReqOffset[slot], g_FH2PayloadPtr[slot]);
            }
            FH2_Log("ROADTRIP PAYLOAD DIFF: ptr=0x%08X +0x%02X %08X -> %08X",
                g_FH2PayloadPtr[slot], w * 4,
                g_FH2PayloadBaseline[slot][w], g_FH2PayloadCompletion[slot][w]);
            ++changedWords;
        }
    }
    FH2_Log("ROADTRIP PAYLOAD DIFF SUMMARY: changedPtrs=%u changedWords=%u", changedPtrs, changedWords);

    // Always print the request area around the only three fields that v0.6.4
    // observed changing. This keeps their neighboring pointers/metadata visible.
    FH2_Log("ROADTRIP REQUEST HOT AREA: +0x100..+0x14C");
    for (DWORD off = 0x100; off <= 0x14C; off += 0x10)
    {
        DWORD i = off / 4;
        FH2_Log("ROADTRIP REQUEST HOT +0x%03X: %08X %08X %08X %08X",
            off,
            g_FH2RequestCompletionWords[i + 0],
            g_FH2RequestCompletionWords[i + 1],
            g_FH2RequestCompletionWords[i + 2],
            g_FH2RequestCompletionWords[i + 3]);
    }
}

static VOID FH2_CaptureRequestTraceFast(
    DWORD object,
    LONG callNumber,
    BYTE flag281,
    BYTE flag282,
    BYTE flag1EC,
    BYTE flag1ED,
    DWORD request)
{
    if (!object || object != g_FH2RoadTripObject)
        return;

    BYTE playlist = *((volatile BYTE*)(object + 0x280));
    if (playlist < 2 || playlist > 5 || !FH2_IsLikelyReadablePointer(request))
        return;

    LONG state = g_FH2RequestTraceState;
    if (state == 0)
    {
        if (InterlockedCompareExchange(&g_FH2RequestTraceState, 1, 0) != 0)
            return;

        g_FH2RequestBaselineCall = (DWORD)callNumber;
        g_FH2RequestBaselinePtr = request;
        g_FH2RequestBaselineVtable = *((volatile DWORD*)request);

        DWORD i;
        for (i = 0; i < FH2_REQUEST_TRACE_WORDS; ++i)
            g_FH2RequestBaselineWords[i] = *((volatile DWORD*)(request + (i * 4)));

        if (FH2_IsLikelyReadablePointer(g_FH2RequestBaselineVtable))
        {
            for (i = 0; i < FH2_REQUEST_TRACE_VT_WORDS; ++i)
                g_FH2RequestVtableWords[i] = *((volatile DWORD*)(g_FH2RequestBaselineVtable + (i * 4)));
        }
        else
        {
            for (i = 0; i < FH2_REQUEST_TRACE_VT_WORDS; ++i)
                g_FH2RequestVtableWords[i] = 0;
        }

        FH2_CapturePayloadBaseline(request);
        return;
    }

    if (state != 1 || (!flag281 && !flag282))
        return;

    if (InterlockedCompareExchange(&g_FH2RequestTraceState, 3, 1) != 1)
        return;

    g_FH2RequestCompletionCall = (DWORD)callNumber;
    g_FH2RequestCompletionPtr = request;
    g_FH2RequestCompletionVtable = *((volatile DWORD*)request);
    g_FH2RequestCompletion281 = flag281;
    g_FH2RequestCompletion282 = flag282;
    g_FH2RequestCompletion1EC = flag1EC;
    g_FH2RequestCompletion1ED = flag1ED;

    for (DWORD i = 0; i < FH2_REQUEST_TRACE_WORDS; ++i)
        g_FH2RequestCompletionWords[i] = *((volatile DWORD*)(request + (i * 4)));

    FH2_CapturePayloadCompletion();
    InterlockedExchange(&g_FH2RequestTraceState, 2);
}

static VOID FH2_LogRequestTraceIfReady()
{
    if (g_FH2RequestTraceLogged || g_FH2RequestTraceState != 2)
        return;

    g_FH2RequestTraceLogged = TRUE;
    FH2_Log("ROADTRIP REQUEST TRACE: baselineCall=%u completionCall=%u baselineReq=0x%08X completionReq=0x%08X baselineVT=0x%08X completionVT=0x%08X",
        g_FH2RequestBaselineCall, g_FH2RequestCompletionCall,
        g_FH2RequestBaselinePtr, g_FH2RequestCompletionPtr,
        g_FH2RequestBaselineVtable, g_FH2RequestCompletionVtable);
    FH2_Log("ROADTRIP REQUEST COMPLETION FLAGS: +281=%u +282=%u +1EC=%u +1ED=%u",
        g_FH2RequestCompletion281, g_FH2RequestCompletion282,
        g_FH2RequestCompletion1EC, g_FH2RequestCompletion1ED);

    DWORD changes = 0;
    for (DWORD i = 0; i < FH2_REQUEST_TRACE_WORDS; ++i)
    {
        if (g_FH2RequestBaselineWords[i] == g_FH2RequestCompletionWords[i])
            continue;
        FH2_Log("ROADTRIP REQUEST DIFF: +0x%03X %08X -> %08X",
            i * 4, g_FH2RequestBaselineWords[i], g_FH2RequestCompletionWords[i]);
        ++changes;
    }
    FH2_Log("ROADTRIP REQUEST DIFF SUMMARY: changes=%u", changes);

    FH2_Log("ROADTRIP REQUEST VTABLE: ptr=0x%08X", g_FH2RequestBaselineVtable);
    for (DWORD i = 0; i < FH2_REQUEST_TRACE_VT_WORDS; i += 4)
    {
        FH2_Log("ROADTRIP REQUEST VT +0x%02X: %08X %08X %08X %08X",
            i * 4,
            g_FH2RequestVtableWords[i + 0],
            g_FH2RequestVtableWords[i + 1],
            g_FH2RequestVtableWords[i + 2],
            g_FH2RequestVtableWords[i + 3]);
    }
}

__declspec(naked) VOID FH2_ProducerHook_828E77F4()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        mr      r4, r29
        lis     r5, 0x828E
        ori     r5, r5, 0x77F4
        mr      r6, r30
        lwz     r7, 0x28(r1)
        bl      FH2_RecordCompletionProducer

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        stb     r29, 0x281(r31)
        addi    r30, r31, 0x198
        mr      r3, r30
        lis     r11, 0x82D8
        ori     r11, r11, 0x7E08
        mtctr   r11
        bctrl

        lis     r11, 0x828E
        ori     r11, r11, 0x7804
        mtctr   r11
        bctr
    }
}

__declspec(naked) VOID FH2_ProducerHook_828E783C()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        li      r4, 1
        lis     r5, 0x828E
        ori     r5, r5, 0x7844
        mr      r6, r30
        lwz     r7, 0x44(r1)
        bl      FH2_RecordCompletionProducer

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        addi    r3, r3, 0x198
        mr      r4, r30
        li      r10, 1
        stb     r10, 0x281(r31)
        lis     r11, 0x82D8
        ori     r11, r11, 0x7E08
        mtctr   r11
        bctrl

        lis     r11, 0x828E
        ori     r11, r11, 0x784C
        mtctr   r11
        bctr
    }
}

__declspec(naked) VOID FH2_ProducerHook_828E78B4()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        li      r4, 1
        lis     r5, 0x828E
        ori     r5, r5, 0x78B8
        mr      r6, r30
        lwz     r7, 0x28(r1)
        bl      FH2_RecordCompletionProducer

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        addi    r3, r3, 0x198
        li      r10, 1
        stb     r10, 0x281(r31)
        lis     r11, 0x82D8
        ori     r11, r11, 0x7E08
        mtctr   r11
        bctrl
        lis     r11, 0x8345

        lis     r10, 0x828E
        ori     r10, r10, 0x78C4
        mtctr   r10
        bctr
    }
}

__declspec(naked) VOID FH2_ProducerHook_828E9F78()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        li      r4, 1
        lis     r5, 0x828E
        ori     r5, r5, 0x9F7C
        mr      r6, r30
        lwz     r7, 0x28(r1)
        bl      FH2_RecordCompletionProducer

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        addi    r3, r31, 0x198
        li      r11, 1
        stb     r11, 0x281(r31)
        lis     r11, 0x82D8
        ori     r11, r11, 0x7E08
        mtctr   r11
        bctrl
        lis     r11, 0x8345

        lis     r10, 0x828E
        ori     r10, r10, 0x9F88
        mtctr   r10
        bctr
    }
}

__declspec(naked) VOID FH2_ProducerHook_8291729C()
{
    __asm
    {
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        mr      r4, r27
        lis     r5, 0x8291
        ori     r5, r5, 0x729C
        mr      r6, r26
        mr      r7, r30
        bl      FH2_RecordCompletionProducer

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r0,  0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)
        addi    r1, r1, 0xA0

        stb     r27, 0x281(r31)
        stw     r26, 0x26C(r31)
        lis     r11, 0x8345
        mr      r3, r31

        lis     r10, 0x8291
        ori     r10, r10, 0x72AC
        mtctr   r10
        bctr
    }
}

static VOID FH2_ScanRoadTrip282StoresBrief(PLDR_DATA_TABLE_ENTRY module)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    FH2_Log("ROADTRIP E528 ROUTINE CODE: begin 0x8283E508..0x8283E590");
    for (DWORD code = 0x8283E508; code <= 0x8283E590; code += 4)
        FH2_Log("ROADTRIP E528 ROUTINE CODE: 0x%08X = 0x%08X", code, *((DWORD*)code));
    FH2_Log("ROADTRIP E528 ROUTINE CODE: end");

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;
    for (DWORD address = start; address + 4 <= end && matches < 32; address += 4)
    {
        DWORD instruction = *((DWORD*)address);
        if ((instruction >> 26) != 38)
            continue;
        if ((WORD)(instruction & 0xFFFF) != 0x0282)
            continue;

        DWORD rs = (instruction >> 21) & 0x1F;
        DWORD ra = (instruction >> 16) & 0x1F;
        DWORD prev = (address >= start + 4) ? *((DWORD*)(address - 4)) : 0;
        DWORD next = (address + 8 <= end) ? *((DWORD*)(address + 4)) : 0;
        FH2_Log("ROADTRIP +282 STORE: at 0x%08X stb r%u,0x0282(r%u) prev=%08X next=%08X",
            address, rs, ra, prev, next);
        DWORD winStart = (address >= start + 0x40) ? address - 0x40 : start;
        DWORD winEnd = address + 0x60;
        if (winEnd + 4 > end)
            winEnd = end - 4;
        FH2_Log("ROADTRIP +282 CODE: begin 0x%08X..0x%08X around 0x%08X", winStart, winEnd, address);
        for (DWORD a = winStart; a <= winEnd; a += 4)
            FH2_Log("ROADTRIP +282 CODE: %s0x%08X = 0x%08X", (a == address) ? "> " : "  ", a, *((DWORD*)a));
        FH2_Log("ROADTRIP +282 CODE: end");
        ++matches;
    }
    FH2_Log("ROADTRIP +282 STORE SCAN: matches=%u", matches);
}

static const char* FH2_StoreOpcodeName(DWORD opcode)
{
    switch (opcode)
    {
    case 36: return "stw";
    case 37: return "stwu";
    case 38: return "stb";
    case 39: return "stbu";
    case 44: return "sth";
    case 45: return "sthu";
    default: return "store?";
    }
}

static DWORD FH2_StoreOpcodeWidth(DWORD opcode)
{
    if (opcode == 36 || opcode == 37)
        return 4;
    if (opcode == 44 || opcode == 45)
        return 2;
    if (opcode == 38 || opcode == 39)
        return 1;
    return 0;
}

static VOID FH2_ScanRoadTripOverlappingStores(PLDR_DATA_TABLE_ENTRY module)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;
    DWORD detailed = 0;

    FH2_Log("ROADTRIP OVERLAP STORE SCAN: looking for direct stores whose displacement range overlaps +0x281/+0x282.");

    for (DWORD address = start; address + 4 <= end && matches < 160; address += 4)
    {
        DWORD instruction = *((DWORD*)address);
        DWORD opcode = instruction >> 26;
        DWORD width = FH2_StoreOpcodeWidth(opcode);
        if (!width)
            continue;

        SHORT signedDisp = (SHORT)(instruction & 0xFFFF);
        LONG first = (LONG)signedDisp;
        LONG last = first + (LONG)width - 1;
        if (last < 0x281 || first > 0x282)
            continue;

        DWORD rs = (instruction >> 21) & 0x1F;
        DWORD ra = (instruction >> 16) & 0x1F;

        FH2_Log("ROADTRIP OVERLAP STORE: at 0x%08X %s r%u,0x%04X(r%u) width=%u instruction=%08X",
            address, FH2_StoreOpcodeName(opcode), rs, (WORD)signedDisp, ra, width, instruction);
        ++matches;

        BOOL focus = (ra == 31) || (address >= 0x82700000 && address < 0x829A0000);
        if (focus && detailed < 64)
        {
            DWORD winStart = (address >= start + 0x24) ? address - 0x24 : start;
            DWORD winEnd = address + 0x30;
            if (winEnd + 4 > end)
                winEnd = end - 4;

            FH2_Log("ROADTRIP OVERLAP CODE: begin 0x%08X..0x%08X around 0x%08X", winStart, winEnd, address);
            for (DWORD a = winStart; a <= winEnd; a += 4)
                FH2_Log("ROADTRIP OVERLAP CODE: %s0x%08X = 0x%08X", (a == address) ? "> " : "  ", a, *((DWORD*)a));
            FH2_Log("ROADTRIP OVERLAP CODE: end");
            ++detailed;
        }
    }

    FH2_Log("ROADTRIP OVERLAP STORE SCAN: matches=%u detailedWindows=%u", matches, detailed);
}


// -----------------------------------------------------------------------------
// v0.7.3 static completion-writer map
//
// v0.7.2 proved the live request's +0x114 status changes to 0x21/0x22 at the
// exact completion pulse, while the request vtable contains no obvious direct
// writer for +0x114.  Scan the loaded title image for direct D-form stores to
// +0x114 and +0x64.  This is read-only: it does not patch any candidate.
// -----------------------------------------------------------------------------
static BOOL FH2_HasNearbyStatusConstant(DWORD address, DWORD imageStart)
{
    DWORD begin = (address >= imageStart + 0x80) ? address - 0x80 : imageStart;
    for (DWORD a = begin; a < address; a += 4)
    {
        DWORD insn = *((volatile DWORD*)a);
        DWORD opcode = insn >> 26;
        DWORD ra = (insn >> 16) & 0x1F;
        WORD imm = (WORD)(insn & 0xFFFF);

        // addi rD,r0,imm is the usual PPC "li rD,imm" encoding.
        if (opcode == 14 && ra == 0 && (imm == 0x0021 || imm == 0x0022))
            return TRUE;
    }
    return FALSE;
}

static VOID FH2_LogStaticStoreWindow(PLDR_DATA_TABLE_ENTRY module, DWORD center,
    WORD wanted, const char* label)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD winStart = (center >= start + 0x30) ? center - 0x30 : start;
    DWORD winEnd = center + 0x40;
    if (winEnd + 4 > end)
        winEnd = end - 4;

    FH2_Log("ROADTRIP %s CODE: begin 0x%08X..0x%08X around store +0x%04X at 0x%08X",
        label, winStart, winEnd, wanted, center);
    for (DWORD a = winStart; a <= winEnd; a += 4)
        FH2_Log("ROADTRIP %s CODE: %s0x%08X = 0x%08X",
            label, (a == center) ? "> " : "  ", a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP %s CODE: end", label);
}

static VOID FH2_ScanExactStoreDisplacement(PLDR_DATA_TABLE_ENTRY module,
    WORD wanted, const char* label, BOOL commonOffset)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;
    DWORD logged = 0;
    DWORD detailed = 0;

    FH2_Log("ROADTRIP %s STORE SCAN: looking for direct stores to displacement +0x%04X.",
        label, wanted);

    for (DWORD address = start; address + 4 <= end; address += 4)
    {
        DWORD instruction = *((volatile DWORD*)address);
        DWORD opcode = instruction >> 26;
        if (!FH2_StoreOpcodeWidth(opcode))
            continue;
        if ((WORD)(instruction & 0xFFFF) != wanted)
            continue;

        ++matches;
        DWORD rs = (instruction >> 21) & 0x1F;
        DWORD ra = (instruction >> 16) & 0x1F;
        BOOL nearStatus = FH2_HasNearbyStatusConstant(address, start);
        BOOL inFocusRange = (address >= 0x82700000 && address < 0x82A00000);

        // +0x64 is common across unrelated structures, so keep its one-line
        // output focused.  +0x114 is rare enough to list broadly.
        BOOL logLine = !commonOffset || nearStatus || inFocusRange;
        if (logLine && logged < 256)
        {
            FH2_Log("ROADTRIP %s STORE: at 0x%08X %s r%u,0x%04X(r%u) width=%u near21or22=%u instruction=%08X",
                label, address, FH2_StoreOpcodeName(opcode), rs, wanted, ra,
                FH2_StoreOpcodeWidth(opcode), nearStatus ? 1 : 0, instruction);
            ++logged;
        }

        // Dump detailed windows for every +0x114 store (capped), and for +0x64
        // stores that sit near an explicit 0x21/0x22 constant.  These are the
        // highest-value candidates for the completion status writer.
        BOOL wantDetail = (!commonOffset) || nearStatus;
        if (wantDetail && detailed < 96)
        {
            FH2_LogStaticStoreWindow(module, address, wanted, label);
            ++detailed;
        }
    }

    FH2_Log("ROADTRIP %s STORE SCAN: matches=%u logged=%u detailedWindows=%u",
        label, matches, logged, detailed);
}

static VOID FH2_DumpCandidateWindow(const char* label, DWORD start, DWORD end)
{
    FH2_Log("ROADTRIP %s CANDIDATE CODE: begin 0x%08X..0x%08X", label, start, end);
    for (DWORD a = start; a <= end; a += 4)
        FH2_Log("ROADTRIP %s CANDIDATE CODE: 0x%08X = 0x%08X", label, a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP %s CANDIDATE CODE: end", label);
}


// -----------------------------------------------------------------------------
// v0.6.6 Road Trip / request vtable method scan
//
// The v0.6.5 static overlapping-store scan found many unrelated +0x280-range
// stores across the executable, so this build narrows the search to methods
// reachable through the actual live Road Trip object's vtable and the active
// +0x94 request object's vtable.  It does not patch those methods.
// -----------------------------------------------------------------------------
static BOOL g_FH2MethodScanLogged = FALSE;

static BOOL FH2_IsLikelyImageCodePointer(DWORD p)
{
    return (p >= 0x82000000 && p < 0x83700000 && (p & 3) == 0);
}

static BOOL FH2_IsInterestingDFormOpcode(DWORD opcode)
{
    // Integer loads/stores plus common floating-point loads/stores.  We only
    // care about the signed 16-bit displacement field.
    switch (opcode)
    {
    case 32: // lwz
    case 33: // lwzu
    case 34: // lbz
    case 35: // lbzu
    case 36: // stw
    case 37: // stwu
    case 38: // stb
    case 39: // stbu
    case 40: // lhz
    case 41: // lhzu
    case 42: // lha
    case 43: // lhau
    case 44: // sth
    case 45: // sthu
    case 48: // lfs
    case 49: // lfsu
    case 50: // lfd
    case 51: // lfdu
    case 52: // stfs
    case 53: // stfsu
    case 54: // stfd
    case 55: // stfdu
        return TRUE;
    default:
        return FALSE;
    }
}

static BOOL FH2_DisplacementMatches(DWORD instruction, const WORD* wanted, DWORD wantedCount)
{
    DWORD opcode = instruction >> 26;
    if (!FH2_IsInterestingDFormOpcode(opcode))
        return FALSE;

    WORD disp = (WORD)(instruction & 0xFFFF);
    for (DWORD i = 0; i < wantedCount; ++i)
    {
        if (disp == wanted[i])
            return TRUE;
    }
    return FALSE;
}

static VOID FH2_LogVtableMethodOffsetHits(const char* label, DWORD vtable,
    const WORD* wanted, DWORD wantedCount)
{
    if (!FH2_IsLikelyReadablePointer(vtable))
    {
        FH2_Log("%s: invalid vtable 0x%08X", label, vtable);
        return;
    }

    FH2_Log("%s VTABLE: ptr=0x%08X", label, vtable);

    // 0x100 bytes = 64 virtual slots.  This is enough to cover the request
    // vtable we have already observed while keeping the log reasonable.
    for (DWORD slot = 0; slot < 0x100; slot += 4)
    {
        DWORD fn = *((volatile DWORD*)(vtable + slot));
        FH2_Log("%s VT +0x%02X = 0x%08X", label, slot, fn);

        if (!FH2_IsLikelyImageCodePointer(fn))
            continue;

        BOOL hit = FALSE;
        DWORD firstHit = 0;

        // Scan only the first 0x100 bytes of each method.  The goal is to find
        // small getters/setters/state handlers that directly touch the fields
        // we have been tracing.
        for (DWORD off = 0; off < 0x100; off += 4)
        {
            DWORD insn = *((volatile DWORD*)(fn + off));
            if (FH2_DisplacementMatches(insn, wanted, wantedCount))
            {
                hit = TRUE;
                firstHit = fn + off;
                break;
            }

            // Stop at an unconditional blr when encountered early.
            if (insn == 0x4E800020)
                break;
        }

        if (!hit)
            continue;

        FH2_Log("%s METHOD HIT: slot=0x%02X fn=0x%08X firstHit=0x%08X",
            label, slot, fn, firstHit);

        DWORD start = (firstHit >= 0x20) ? firstHit - 0x20 : fn;
        if (start < fn)
            start = fn;
        DWORD end = firstHit + 0x40;

        for (DWORD a = start; a <= end; a += 4)
        {
            DWORD insn = *((volatile DWORD*)a);
            FH2_Log("%s METHOD CODE: %s0x%08X = 0x%08X",
                label, (a == firstHit) ? "> " : "  ", a, insn);
        }
    }
}

static VOID FH2_LogRoadTripAndRequestMethodScans(DWORD object)
{
    if (g_FH2MethodScanLogged || !FH2_IsLikelyReadablePointer(object))
        return;

    DWORD request = *((volatile DWORD*)(object + 0x94));
    if (!FH2_IsLikelyReadablePointer(request))
        return;

    DWORD roadVt = *((volatile DWORD*)object);
    DWORD reqVt = *((volatile DWORD*)request);
    if (!FH2_IsLikelyReadablePointer(roadVt) || !FH2_IsLikelyReadablePointer(reqVt))
        return;

    g_FH2MethodScanLogged = TRUE;

    // Fields directly involved in the Road Trip state machine.
    const WORD roadOffsets[] =
    {
        0x0094, 0x01EC, 0x0280, 0x0281, 0x0282, 0x0283, 0x0284
    };

    // Fields that changed in every captured request completion, plus the two
    // child pointers whose +0x64 words change in lockstep with completion.
    const WORD reqOffsets[] =
    {
        0x0114, 0x0128, 0x012C, 0x0170, 0x0184
    };

    FH2_Log("ROADTRIP METHOD TRACE: obj=0x%08X roadVT=0x%08X request=0x%08X reqVT=0x%08X",
        object, roadVt, request, reqVt);

    FH2_LogVtableMethodOffsetHits("ROADTRIP", roadVt,
        roadOffsets, sizeof(roadOffsets) / sizeof(roadOffsets[0]));
    FH2_LogVtableMethodOffsetHits("REQUEST", reqVt,
        reqOffsets, sizeof(reqOffsets) / sizeof(reqOffsets[0]));

    FH2_Log("ROADTRIP METHOD TRACE: complete");
}

static BOOL FH2_IsLikelyRoadTripObject(DWORD object)
{
    // Retail FH2 uses both heap-style 0x2xxxxxxx objects and image/static
    // 0x8xxxxxxx objects. Earlier builds only accepted 0x2xxxxxxx/0x8xxxxxxx. Hardware capture
    // proved this exact Road Trip object lives in the 0x4xxxxxxx arena too.
    if (object & 3)
        return FALSE;
    if (object >= 0x20000000 && object < 0x40000000)
        return TRUE;
    if (object >= 0x40000000 && object < 0x50000000)
        return TRUE;
    if (object >= 0x80000000 && object < 0x90000000)
        return TRUE;
    return FALSE;
}


// -----------------------------------------------------------------------------
// v0.7.0 request-status success experiment
//
// Every captured Road Trip failure changes request+0x114 from 0 to 0x21/0x22,
// and the two child payloads at request+0x170/+0x184 receive the same value at
// +0x64.  This happens at the exact +0x281/+0x282 completion pulse, BEFORE the
// retail dispatcher consumes the Road Trip result.  v0.7.0 changes only those
// repeatedly-observed failure/status words back to zero and leaves the retail
// completion branch and dispatcher untouched.
// -----------------------------------------------------------------------------
static volatile DWORD g_FH2StatusZeroArmedRequest = 0;
static volatile LONG  g_FH2StatusZeroApplied = 0;
static volatile LONG  g_FH2StatusZeroReady = 0;
static BOOL           g_FH2StatusZeroLogged = FALSE;
static DWORD          g_FH2StatusZeroCall = 0;
static DWORD          g_FH2StatusZeroRequest = 0;
static DWORD          g_FH2StatusZeroStatusBefore = 0;
static DWORD          g_FH2StatusZeroStatusAfter = 0;
static DWORD          g_FH2StatusZeroChild170 = 0;
static DWORD          g_FH2StatusZeroChild184 = 0;
static DWORD          g_FH2StatusZeroChild170Before = 0xFFFFFFFF;
static DWORD          g_FH2StatusZeroChild184Before = 0xFFFFFFFF;
static DWORD          g_FH2StatusZeroChild170After = 0xFFFFFFFF;
static DWORD          g_FH2StatusZeroChild184After = 0xFFFFFFFF;
static BYTE           g_FH2StatusZeroPlaylist = 0;

static BOOL FH2_IsExactRoadTripObject(DWORD object)
{
    if (!FH2_IsLikelyRoadTripObject(object))
        return FALSE;
    return (*((volatile DWORD*)object) == 0x820728D4);
}

static VOID FH2_ApplyRequestStatusZeroFast(DWORD object, LONG callNumber,
    BYTE flag281, BYTE flag282, DWORD request)
{
    if (!FH2_IsExactRoadTripObject(object))
        return;

    BYTE playlist = *((volatile BYTE*)(object + 0x280));
    if (playlist < 2 || playlist > 5 || !FH2_IsLikelyReadablePointer(request))
        return;

    DWORD requestVt = *((volatile DWORD*)request);
    if (requestVt != 0x8205D7C4)
        return;

    // Arm/re-arm on the live in-progress request, before the completion pulse.
    if (!flag281)
    {
        if (g_FH2StatusZeroArmedRequest != request)
        {
            g_FH2StatusZeroArmedRequest = request;
            InterlockedExchange(&g_FH2StatusZeroApplied, 0);
            InterlockedExchange(&g_FH2StatusZeroReady, 0);
            g_FH2StatusZeroLogged = FALSE;
        }
        return;
    }

    // Only touch the exact retail completion pulse that has repeatedly lined up
    // with Server Unavailable.  +0x282 is also 1 in every clean capture.
    if (!flag282 || g_FH2StatusZeroArmedRequest != request)
        return;
    if (InterlockedCompareExchange(&g_FH2StatusZeroApplied, 1, 0) != 0)
        return;

    DWORD status = *((volatile DWORD*)(request + 0x114));
    g_FH2StatusZeroCall = (DWORD)callNumber;
    g_FH2StatusZeroRequest = request;
    g_FH2StatusZeroPlaylist = playlist;
    g_FH2StatusZeroStatusBefore = status;

    DWORD child170 = *((volatile DWORD*)(request + 0x170));
    DWORD child184 = *((volatile DWORD*)(request + 0x184));
    g_FH2StatusZeroChild170 = child170;
    g_FH2StatusZeroChild184 = child184;

    if (FH2_IsLikelyReadablePointer(child170))
        g_FH2StatusZeroChild170Before = *((volatile DWORD*)(child170 + 0x64));
    if (FH2_IsLikelyReadablePointer(child184))
        g_FH2StatusZeroChild184Before = *((volatile DWORD*)(child184 + 0x64));

    // 0x21 and 0x22 are the only nonzero completion values observed in all of
    // our clean failure captures.  Do not broadly zero arbitrary request data.
    if (status == 0x21 || status == 0x22)
        *((volatile DWORD*)(request + 0x114)) = 0;

    if (FH2_IsLikelyReadablePointer(child170))
    {
        DWORD v = *((volatile DWORD*)(child170 + 0x64));
        if (v == 0x21 || v == 0x22)
            *((volatile DWORD*)(child170 + 0x64)) = 0;
        g_FH2StatusZeroChild170After = *((volatile DWORD*)(child170 + 0x64));
    }

    if (FH2_IsLikelyReadablePointer(child184))
    {
        DWORD v = *((volatile DWORD*)(child184 + 0x64));
        if (v == 0x21 || v == 0x22)
            *((volatile DWORD*)(child184 + 0x64)) = 0;
        g_FH2StatusZeroChild184After = *((volatile DWORD*)(child184 + 0x64));
    }

    g_FH2StatusZeroStatusAfter = *((volatile DWORD*)(request + 0x114));
    InterlockedExchange(&g_FH2StatusZeroReady, 1);
}

static VOID FH2_LogRequestStatusZeroIfReady()
{
    if (g_FH2StatusZeroLogged || !g_FH2StatusZeroReady)
        return;

    g_FH2StatusZeroLogged = TRUE;
    FH2_Log("ROADTRIP STATUS ZERO: call=%u playlist=%u request=0x%08X req+114 %08X->%08X",
        g_FH2StatusZeroCall, g_FH2StatusZeroPlaylist, g_FH2StatusZeroRequest,
        g_FH2StatusZeroStatusBefore, g_FH2StatusZeroStatusAfter);
    FH2_Log("ROADTRIP STATUS ZERO CHILDREN: +170=0x%08X child+64 %08X->%08X; +184=0x%08X child+64 %08X->%08X",
        g_FH2StatusZeroChild170, g_FH2StatusZeroChild170Before, g_FH2StatusZeroChild170After,
        g_FH2StatusZeroChild184, g_FH2StatusZeroChild184Before, g_FH2StatusZeroChild184After);
}


// -----------------------------------------------------------------------------
// v0.6.7 exact Road Trip completion-chain instrumentation
//
// Runtime disassembly from v0.6.6 showed 0x82FEAF10 does:
//   request = owner->+0x94
//   if (request->vfunc_3C())
//       request->vfunc_44()
//
// We patch ONLY the two indirect-call sequences inside 0x82FEAF10.  The proxy
// resolves the original target dynamically from the live object's vtable, calls
// it unchanged, and records the return/state only when the object is the active
// Road Trip +0x94 request.  No file I/O occurs in these proxies.
// -----------------------------------------------------------------------------
typedef DWORD (*FH2_VFUNC1)(DWORD object);

static volatile LONG  g_FH2ChainPollCalls = 0;
static volatile DWORD g_FH2ChainActiveRequest = 0;
static volatile DWORD g_FH2ChainPollLastResult = 0xFFFFFFFF;
static volatile DWORD g_FH2ChainPollLastTarget = 0;
static volatile DWORD g_FH2ChainPollLastNested94 = 0;
static volatile DWORD g_FH2ChainPollLastNestedVtable = 0;
static volatile LONG  g_FH2ChainPollLastChangeCall = 0;
static volatile LONG  g_FH2ChainPollLastChangeTapCall = 0;
static volatile LONG  g_FH2ChainPollChangeSerial = 0;
static LONG           g_FH2ChainPollLoggedSerial = -1;
static volatile LONG  g_FH2ChainFirstTruePollCall = 0;
static volatile LONG  g_FH2ChainFirstTrueTapCall = 0;

#define FH2_CHAIN_REQ_START 0x80
#define FH2_CHAIN_REQ_END   0x1A0
#define FH2_CHAIN_REQ_WORDS (((FH2_CHAIN_REQ_END - FH2_CHAIN_REQ_START) / 4) + 1)
#define FH2_CHAIN_NEST_END  0x100
#define FH2_CHAIN_NEST_WORDS ((FH2_CHAIN_NEST_END / 4) + 1)

static volatile LONG g_FH2ChainProcessState = 0; // 0=armed, 1=capturing, 2=ready
static BOOL  g_FH2ChainProcessLogged = FALSE;
static DWORD g_FH2ChainProcessRequest = 0;
static DWORD g_FH2ChainProcessTarget = 0;
static DWORD g_FH2ChainProcessReturn = 0;
static DWORD g_FH2ChainProcessForcedReturn = 0;
static volatile LONG g_FH2ChainProcessFlipCount = 0;
static DWORD g_FH2ChainProcessTapCall = 0;
static DWORD g_FH2ChainProcessNestedBefore = 0;
static DWORD g_FH2ChainProcessNestedAfter = 0;
static DWORD g_FH2ChainProcessNestedVtBefore = 0;
static DWORD g_FH2ChainProcessNestedVtAfter = 0;
static BYTE  g_FH2ChainProcessRoad281Before = 0;
static BYTE  g_FH2ChainProcessRoad282Before = 0;
static BYTE  g_FH2ChainProcessRoad1ECBefore = 0;
static BYTE  g_FH2ChainProcessRoad281After = 0;
static BYTE  g_FH2ChainProcessRoad282After = 0;
static BYTE  g_FH2ChainProcessRoad1ECAfter = 0;
static DWORD g_FH2ChainReqBefore[FH2_CHAIN_REQ_WORDS];
static DWORD g_FH2ChainReqAfter[FH2_CHAIN_REQ_WORDS];
static DWORD g_FH2ChainNestBefore[FH2_CHAIN_NEST_WORDS];
static DWORD g_FH2ChainNestAfter[FH2_CHAIN_NEST_WORDS];
static BOOL  g_FH2ChainNestBeforeValid = FALSE;
static BOOL  g_FH2ChainNestAfterValid = FALSE;

static BOOL FH2_IsActiveRoadTripRequest(DWORD request)
{
    DWORD road = g_FH2RoadTripObject;
    if (!FH2_IsLikelyRoadTripObject(road) || !FH2_IsLikelyReadablePointer(request))
        return FALSE;

    BYTE playlist = *((volatile BYTE*)(road + 0x280));
    if (playlist < 2 || playlist > 5)
        return FALSE;

    DWORD active = *((volatile DWORD*)(road + 0x94));
    return (active == request);
}

static VOID FH2_ResetCompletionChainForRequest(DWORD request)
{
    g_FH2ChainActiveRequest = request;
    g_FH2ChainPollCalls = 0;
    g_FH2ChainPollLastResult = 0xFFFFFFFF;
    g_FH2ChainPollLastTarget = 0;
    g_FH2ChainPollLastNested94 = 0;
    g_FH2ChainPollLastNestedVtable = 0;
    g_FH2ChainPollLastChangeCall = 0;
    g_FH2ChainPollLastChangeTapCall = 0;
    g_FH2ChainPollChangeSerial = 0;
    g_FH2ChainPollLoggedSerial = -1;
    g_FH2ChainFirstTruePollCall = 0;
    g_FH2ChainFirstTrueTapCall = 0;

    g_FH2ChainProcessState = 0;
    g_FH2ChainProcessLogged = FALSE;
    g_FH2ChainProcessRequest = 0;
    g_FH2ChainProcessTarget = 0;
    g_FH2ChainProcessReturn = 0;
    g_FH2ChainProcessForcedReturn = 0;
    g_FH2ChainProcessFlipCount = 0;
    g_FH2ChainProcessTapCall = 0;
    g_FH2ChainProcessNestedBefore = 0;
    g_FH2ChainProcessNestedAfter = 0;
    g_FH2ChainProcessNestedVtBefore = 0;
    g_FH2ChainProcessNestedVtAfter = 0;
    g_FH2ChainNestBeforeValid = FALSE;
    g_FH2ChainNestAfterValid = FALSE;
}

static DWORD FH2_RequestVfunc3CProxy(DWORD request)
{
    if (!FH2_IsLikelyReadablePointer(request))
        return 0;

    DWORD vt = *((volatile DWORD*)request);
    if (!FH2_IsLikelyReadablePointer(vt))
        return 0;

    DWORD target = *((volatile DWORD*)(vt + 0x3C));
    if (!FH2_IsLikelyImageCodePointer(target))
        return 0;

    FH2_VFUNC1 fn = (FH2_VFUNC1)target;
    DWORD result = fn(request);

    if (FH2_IsActiveRoadTripRequest(request))
    {
        if (g_FH2ChainActiveRequest != request)
            FH2_ResetCompletionChainForRequest(request);

        LONG callNo = InterlockedIncrement(&g_FH2ChainPollCalls);
        DWORD nested = *((volatile DWORD*)(request + 0x94));
        DWORD nestedVt = 0;
        if (FH2_IsLikelyReadablePointer(nested))
            nestedVt = *((volatile DWORD*)nested);

        DWORD previous = g_FH2ChainPollLastResult;
        if (previous == 0xFFFFFFFF || previous != result)
        {
            g_FH2ChainPollLastResult = result;
            g_FH2ChainPollLastTarget = target;
            g_FH2ChainPollLastNested94 = nested;
            g_FH2ChainPollLastNestedVtable = nestedVt;
            g_FH2ChainPollLastChangeCall = callNo;
            g_FH2ChainPollLastChangeTapCall = g_FH2RoadTripTapCalls;
            InterlockedIncrement(&g_FH2ChainPollChangeSerial);
        }

        if (result && InterlockedCompareExchange(&g_FH2ChainFirstTruePollCall, callNo, 0) == 0)
            g_FH2ChainFirstTrueTapCall = g_FH2RoadTripTapCalls;
    }

    return result;
}

static DWORD FH2_RequestVfunc44Proxy(DWORD request)
{
    if (!FH2_IsLikelyReadablePointer(request))
        return 0;

    DWORD vt = *((volatile DWORD*)request);
    if (!FH2_IsLikelyReadablePointer(vt))
        return 0;

    DWORD target = *((volatile DWORD*)(vt + 0x44));
    if (!FH2_IsLikelyImageCodePointer(target))
        return 0;

    BOOL activeRoadTrip = FH2_IsActiveRoadTripRequest(request);
    BOOL capture = activeRoadTrip &&
        (InterlockedCompareExchange(&g_FH2ChainProcessState, 1, 0) == 0);

    DWORD road = g_FH2RoadTripObject;
    if (capture)
    {
        g_FH2ChainProcessRequest = request;
        g_FH2ChainProcessTarget = target;
        g_FH2ChainProcessTapCall = g_FH2RoadTripTapCalls;
        g_FH2ChainProcessNestedBefore = *((volatile DWORD*)(request + 0x94));
        if (FH2_IsLikelyReadablePointer(g_FH2ChainProcessNestedBefore))
        {
            g_FH2ChainProcessNestedVtBefore = *((volatile DWORD*)g_FH2ChainProcessNestedBefore);
            g_FH2ChainNestBeforeValid = TRUE;
            for (DWORD i = 0; i < FH2_CHAIN_NEST_WORDS; ++i)
                g_FH2ChainNestBefore[i] = *((volatile DWORD*)(g_FH2ChainProcessNestedBefore + (i * 4)));
        }

        if (FH2_IsLikelyRoadTripObject(road))
        {
            g_FH2ChainProcessRoad281Before = *((volatile BYTE*)(road + 0x281));
            g_FH2ChainProcessRoad282Before = *((volatile BYTE*)(road + 0x282));
            g_FH2ChainProcessRoad1ECBefore = *((volatile BYTE*)(road + 0x1EC));
        }

        DWORD i = 0;
        for (DWORD off = FH2_CHAIN_REQ_START; off <= FH2_CHAIN_REQ_END; off += 4, ++i)
            g_FH2ChainReqBefore[i] = *((volatile DWORD*)(request + off));
    }

    FH2_VFUNC1 fn = (FH2_VFUNC1)target;
    DWORD result = fn(request);
    DWORD forcedResult = result;

    // v0.6.9 progression experiment: let the real completion processor run so
    // it can populate/clean its request data, then invert only the value seen
    // by the caller for an active Road Trip request. This deliberately covers
    // both common conventions without guessing whether success is 0 (HRESULT)
    // or nonzero (BOOL): 0 -> 1, nonzero -> 0.
    if (activeRoadTrip)
    {
        forcedResult = result ? 0 : 1;
        InterlockedIncrement(&g_FH2ChainProcessFlipCount);
    }

    if (capture)
    {
        g_FH2ChainProcessReturn = result;
        g_FH2ChainProcessForcedReturn = forcedResult;
        g_FH2ChainProcessNestedAfter = *((volatile DWORD*)(request + 0x94));
        if (FH2_IsLikelyReadablePointer(g_FH2ChainProcessNestedAfter))
        {
            g_FH2ChainProcessNestedVtAfter = *((volatile DWORD*)g_FH2ChainProcessNestedAfter);
            g_FH2ChainNestAfterValid = TRUE;
            for (DWORD i = 0; i < FH2_CHAIN_NEST_WORDS; ++i)
                g_FH2ChainNestAfter[i] = *((volatile DWORD*)(g_FH2ChainProcessNestedAfter + (i * 4)));
        }

        if (FH2_IsLikelyRoadTripObject(road))
        {
            g_FH2ChainProcessRoad281After = *((volatile BYTE*)(road + 0x281));
            g_FH2ChainProcessRoad282After = *((volatile BYTE*)(road + 0x282));
            g_FH2ChainProcessRoad1ECAfter = *((volatile BYTE*)(road + 0x1EC));
        }

        DWORD i = 0;
        for (DWORD off = FH2_CHAIN_REQ_START; off <= FH2_CHAIN_REQ_END; off += 4, ++i)
            g_FH2ChainReqAfter[i] = *((volatile DWORD*)(request + off));

        InterlockedExchange(&g_FH2ChainProcessState, 2);
    }

    return forcedResult;
}

static VOID FH2_LogCompletionChainIfReady()
{
    LONG serial = g_FH2ChainPollChangeSerial;
    if (serial != g_FH2ChainPollLoggedSerial)
    {
        FH2_Log("ROADTRIP COMPLETION POLL: req=0x%08X calls=%d result=%u target=0x%08X changeCall=%d tapCall=%d nested94=0x%08X nestedVT=0x%08X firstTruePoll=%d firstTrueTap=%d",
            g_FH2ChainActiveRequest, g_FH2ChainPollCalls, g_FH2ChainPollLastResult,
            g_FH2ChainPollLastTarget, g_FH2ChainPollLastChangeCall,
            g_FH2ChainPollLastChangeTapCall, g_FH2ChainPollLastNested94,
            g_FH2ChainPollLastNestedVtable, g_FH2ChainFirstTruePollCall,
            g_FH2ChainFirstTrueTapCall);
        g_FH2ChainPollLoggedSerial = serial;
    }

    if (g_FH2ChainProcessLogged || g_FH2ChainProcessState != 2)
        return;

    g_FH2ChainProcessLogged = TRUE;
    FH2_Log("ROADTRIP COMPLETION PROCESS: req=0x%08X target=0x%08X originalReturn=0x%08X forcedReturn=0x%08X flips=%d tapCall=%u nestedBefore=0x%08X vtBefore=0x%08X nestedAfter=0x%08X vtAfter=0x%08X",
        g_FH2ChainProcessRequest, g_FH2ChainProcessTarget, g_FH2ChainProcessReturn,
        g_FH2ChainProcessForcedReturn, g_FH2ChainProcessFlipCount,
        g_FH2ChainProcessTapCall, g_FH2ChainProcessNestedBefore,
        g_FH2ChainProcessNestedVtBefore, g_FH2ChainProcessNestedAfter,
        g_FH2ChainProcessNestedVtAfter);
    FH2_Log("ROADTRIP COMPLETION PROCESS FLAGS: road +281 %u->%u +282 %u->%u +1EC %u->%u",
        g_FH2ChainProcessRoad281Before, g_FH2ChainProcessRoad281After,
        g_FH2ChainProcessRoad282Before, g_FH2ChainProcessRoad282After,
        g_FH2ChainProcessRoad1ECBefore, g_FH2ChainProcessRoad1ECAfter);

    DWORD changes = 0;
    for (DWORD i = 0; i < FH2_CHAIN_REQ_WORDS; ++i)
    {
        if (g_FH2ChainReqBefore[i] == g_FH2ChainReqAfter[i])
            continue;
        DWORD off = FH2_CHAIN_REQ_START + (i * 4);
        FH2_Log("ROADTRIP COMPLETION PROCESS REQ DIFF: +0x%03X %08X -> %08X",
            off, g_FH2ChainReqBefore[i], g_FH2ChainReqAfter[i]);
        ++changes;
    }
    FH2_Log("ROADTRIP COMPLETION PROCESS REQ DIFF SUMMARY: changes=%u", changes);

    if (g_FH2ChainNestBeforeValid && g_FH2ChainNestAfterValid &&
        g_FH2ChainProcessNestedBefore == g_FH2ChainProcessNestedAfter)
    {
        DWORD nestedChanges = 0;
        for (DWORD i = 0; i < FH2_CHAIN_NEST_WORDS; ++i)
        {
            if (g_FH2ChainNestBefore[i] == g_FH2ChainNestAfter[i])
                continue;
            FH2_Log("ROADTRIP COMPLETION PROCESS NEST DIFF: +0x%03X %08X -> %08X",
                i * 4, g_FH2ChainNestBefore[i], g_FH2ChainNestAfter[i]);
            ++nestedChanges;
        }
        FH2_Log("ROADTRIP COMPLETION PROCESS NEST DIFF SUMMARY: changes=%u", nestedChanges);
    }
    else
    {
        FH2_Log("ROADTRIP COMPLETION PROCESS NEST DIFF: unavailable or nested pointer changed.");
    }
}

static BOOL FH2_InstallCompletionChainTrace()
{
    DWORD* pollSite = (DWORD*)0x82FEAF34;
    const DWORD Poll0 = 0x81630000;
    const DWORD Poll1 = 0x816B003C;
    const DWORD Poll2 = 0x7D6903A6;
    const DWORD Poll3 = 0x4E800421;

    DWORD* processSite = (DWORD*)0x82FEAF50;
    const DWORD Proc0 = 0x81630000;
    const DWORD Proc1 = 0x816B0044;
    const DWORD Proc2 = 0x7D6903A6;
    const DWORD Proc3 = 0x4E800421;

    if (pollSite[0] != Poll0 || pollSite[1] != Poll1 || pollSite[2] != Poll2 || pollSite[3] != Poll3)
    {
        FH2_Log("v0.6.7 COMPLETION POLL hook validation failed at 0x82FEAF34: %08X %08X %08X %08X",
            pollSite[0], pollSite[1], pollSite[2], pollSite[3]);
        return FALSE;
    }
    if (processSite[0] != Proc0 || processSite[1] != Proc1 || processSite[2] != Proc2 || processSite[3] != Proc3)
    {
        FH2_Log("v0.6.7 COMPLETION PROCESS hook validation failed at 0x82FEAF50: %08X %08X %08X %08X",
            processSite[0], processSite[1], processSite[2], processSite[3]);
        return FALSE;
    }

    FH2_Log("ROADTRIP COMPLETION CHAIN CODE: begin 0x827CD738..0x827CD838");
    for (DWORD a = 0x827CD738; a <= 0x827CD838; a += 4)
        FH2_Log("ROADTRIP COMPLETION CHAIN CODE: 0x%08X = 0x%08X", a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP COMPLETION CHAIN CODE: end");

    PatchInJump(pollSite, (DWORD)&FH2_RequestVfunc3CProxy, TRUE);
    PatchInJump(processSite, (DWORD)&FH2_RequestVfunc44Proxy, TRUE);
    FH2_Log("v0.6.9 exact completion chain hooks installed: 0x82FEAF34 -> request vfunc+0x3C proxy, 0x82FEAF50 -> request vfunc+0x44 proxy.");
    return TRUE;
}

static VOID FH2_RecordRoadTripObjectFast(DWORD object)
{
    // Never do file I/O here. This runs in the game's hot update path.
    g_FH2RoadTripRawObject = object;

    LONG callNumber = InterlockedIncrement(&g_FH2RoadTripTapCalls);

    if (!FH2_IsExactRoadTripObject(object))
        return;

    g_FH2RoadTripObject = object;

    // Capture transient state BEFORE the original code at 0x8283E4A0 gets a
    // chance to consume/clear it. v0.5.5 showed +0x1EC and +0x282 changing
    // right around the server-unavailable event; this catches a short +0x281
    // pulse even if it exists for only one update.
    BYTE flag281 = *((volatile BYTE*)(object + 0x281));
    BYTE flag282 = *((volatile BYTE*)(object + 0x282));
    BYTE flag1EC = *((volatile BYTE*)(object + 0x1EC));
    BYTE flag1ED = *((volatile BYTE*)(object + 0x1ED));
    DWORD word94 = *((volatile DWORD*)(object + 0x94));

    // v0.6.4 snapshots the active async/request object at request start and at
    // the exact completion pulse before retail code consumes +0x281.
    FH2_CaptureRequestTraceFast(object, callNumber, flag281, flag282, flag1EC, flag1ED, word94);

    // v0.7.2 diagnostic: do NOT mutate request status here. v0.7.0 proved
    // zeroing req+0x114 and child+0x64 at the completion pulse does not alter
    // the Server Unavailable outcome. Preserve retail request data exactly.

    if (flag281 && InterlockedCompareExchange(&g_FH2RoadTripSaw281, 1, 0) == 0)
        g_FH2RoadTripFirst281Call = callNumber;
    if (flag282 && InterlockedCompareExchange(&g_FH2RoadTripSaw282, 1, 0) == 0)
        g_FH2RoadTripFirst282Call = callNumber;
    if (flag1EC && InterlockedCompareExchange(&g_FH2RoadTripSaw1EC, 1, 0) == 0)
        g_FH2RoadTripFirst1ECCall = callNumber;
    if (flag1ED && InterlockedCompareExchange(&g_FH2RoadTripSaw1ED, 1, 0) == 0)
        g_FH2RoadTripFirst1EDCall = callNumber;

    // v0.6.0 does NOT call readiness or dispatch from this hot tap. The exact
    // retail callsite is hooked separately after the retail readiness check.
    (void)word94;
}

static VOID FH2_RecordComputed282Producer(DWORD object, DWORD rawReturn, DWORD boolValue, DWORD state268, DWORD owner)
{
    InterlockedIncrement(&g_FH2Computed282HitCount);

    if (!object || object != g_FH2RoadTripObject)
        return;

    BYTE playlist = *((volatile BYTE*)(object + 0x280));
    DWORD request = *((volatile DWORD*)(object + 0x94));
    if (playlist < 2 || playlist > 5 || !FH2_IsLikelyReadablePointer(request))
        return;

    if (InterlockedCompareExchange(&g_FH2Computed282CaptureState, 1, 0) != 0)
        return;

    g_FH2Computed282Object = object;
    g_FH2Computed282RawReturn = rawReturn;
    g_FH2Computed282Bool = boolValue & 0xFF;
    g_FH2Computed282State268 = state268 & 0xFF;
    g_FH2Computed282Owner = owner;
    g_FH2Computed282Request = request;
    g_FH2Computed282TapCall = (DWORD)g_FH2RoadTripTapCalls;

    DWORD service = 0;
    DWORD vt = 0;
    DWORD vfunc38 = 0;
    if (FH2_IsLikelyReadablePointer(owner))
        service = *((volatile DWORD*)(owner + 0x208));
    if (FH2_IsLikelyReadablePointer(service))
        vt = *((volatile DWORD*)service);
    if (FH2_IsLikelyReadablePointer(vt))
        vfunc38 = *((volatile DWORD*)(vt + 0x38));

    g_FH2Computed282Owner208 = service;
    g_FH2Computed282Owner208Vtable = vt;
    g_FH2Computed282Vfunc38 = vfunc38;
}

static VOID FH2_LogComputed282ProducerIfReady()
{
    if (g_FH2Computed282Logged || g_FH2Computed282CaptureState != 1)
        return;

    g_FH2Computed282Logged = TRUE;
    FH2_Log("ROADTRIP COMPUTED +282 PRODUCER HIT: tapCall=%u totalWriterHits=%d obj=0x%08X rawReturn=0x%08X bool=%u state268=%u request=0x%08X",
        g_FH2Computed282TapCall, g_FH2Computed282HitCount, g_FH2Computed282Object,
        g_FH2Computed282RawReturn, g_FH2Computed282Bool, g_FH2Computed282State268,
        g_FH2Computed282Request);
    FH2_Log("ROADTRIP COMPUTED +282 OWNER: owner=0x%08X owner+208=0x%08X vt=0x%08X vfunc+38=0x%08X",
        g_FH2Computed282Owner, g_FH2Computed282Owner208,
        g_FH2Computed282Owner208Vtable, g_FH2Computed282Vfunc38);

    if (g_FH2Computed282Object)
    {
        FH2_Log("ROADTRIP COMPUTED +282 OBJECT: +268=%02X +26C=%08X +280=%08X +281=%02X +282=%02X +94=%08X",
            *((volatile BYTE*)(g_FH2Computed282Object + 0x268)),
            *((volatile DWORD*)(g_FH2Computed282Object + 0x26C)),
            *((volatile DWORD*)(g_FH2Computed282Object + 0x280)),
            *((volatile BYTE*)(g_FH2Computed282Object + 0x281)),
            *((volatile BYTE*)(g_FH2Computed282Object + 0x282)),
            *((volatile DWORD*)(g_FH2Computed282Object + 0x94)));
    }
}

__declspec(naked) VOID FH2_Computed282ProducerHook()
{
    __asm
    {
        // Reproduce the four retail instructions overwritten at 0x82855AE0.
        // addic r10,r3,-1 at 0x82855ADC remains in place and supplies XER.CA.
        lbz     r11, 0x268(r31)
        subfe   r10, r10, r3
        cmpwi   cr6, r11, 1
        stb     r10, 0x282(r31)

        // Preserve volatile state and XER while recording the exact retail
        // values. The Xbox 360 compiler does not accept mtcrf in inline asm,
        // so CR6 is reconstructed from the restored r11 before resuming.
        stwu    r1, -0xA0(r1)
        stw     r0,  0x20(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        stw     r11, 0x44(r1)
        stw     r12, 0x48(r1)
        mflr    r0
        stw     r0,  0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r3, r31
        lwz     r4, 0x24(r1)
        lwz     r5, 0x40(r1)
        lwz     r6, 0x44(r1)
        mr      r7, r30
        bl      FH2_RecordComputed282Producer

        lwz     r0, 0x54(r1)
        mtxer   r0
        lwz     r0, 0x50(r1)
        mtctr   r0
        lwz     r0, 0x4C(r1)
        mtlr    r0
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r12, 0x48(r1)
        lwz     r0,  0x20(r1)

        // Recreate the retail CR6 from 0x82855AE8. The next instruction at
        // 0x82855AF0 branches on this exact comparison result.
        cmpwi   cr6, r11, 1
        addi    r1, r1, 0xA0

        // Resume at 0x82855AF0 (the CR6 branch immediately after the store).
        lis     r12, 0x8285
        ori     r12, r12, 0x5AF0
        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_RoadTripStateTapHook()
{
    __asm
    {
        // Reproduce the important semantics of the overwritten sequence:
        //   mr r31,r3
        //   ... availability getter ... -> TRUE
        mr      r31, r3
        mr      r3, r31
        bl      FH2_RecordRoadTripObjectFast
        li      r30, 1

        // Continue at the original TRUE-path target 0x8283E4A0.
        lis     r11, 0x8284
        addi    r11, r11, -0x1B60
        mtctr   r11
        bctr
    }
}

static VOID FH2_V083Tick(DWORD object, DWORD request);

// v0.8.17: dump the popup's UI event table (std::vector of 0x38-byte entries at
// obj+0x208..+0x20C, key at +0x24, functor around +0x28) so the selection
// delegate (the code run by 0x826D63C0) can be located and disassembled.
static DWORD g_FH2EvtDumpObj = 0;
static DWORD g_FH2EvtDumpReq = 0xFFFFFFFF;
static VOID FH2_DumpEventTable(DWORD object)
{
    if (!FH2_IsLikelyReadablePointer(object)) return;
    DWORD req = *((volatile DWORD*)(object + 0x94));
    if (object == g_FH2EvtDumpObj && (req == 0 || req == g_FH2EvtDumpReq)) return;
    g_FH2EvtDumpObj = object;
    g_FH2EvtDumpReq = req;

    DWORD begin = *((volatile DWORD*)(object + 0x208));
    DWORD end   = *((volatile DWORD*)(object + 0x20C));
    FH2_Log("v0.8.17 EVTTABLE: obj=0x%08X +94=0x%08X +204..: %08X %08X %08X %08X %08X %08X begin=0x%08X end=0x%08X",
        object, req,
        *((volatile DWORD*)(object + 0x204)), *((volatile DWORD*)(object + 0x208)),
        *((volatile DWORD*)(object + 0x20C)), *((volatile DWORD*)(object + 0x210)),
        *((volatile DWORD*)(object + 0x214)), *((volatile DWORD*)(object + 0x218)), begin, end);
    if (!FH2_IsLikelyReadablePointer(begin) || end < begin || (end - begin) > 0x38 * 40)
        return;
    int n = 0;
    for (DWORD e = begin; e + 0x38 <= end && n < 40; e += 0x38, ++n)
    {
        volatile DWORD* w = (volatile DWORD*)e;
        FH2_Log("v0.8.17 EVTENTRY[%d] @0x%08X: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
            n, e, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13]);
    }
    // popup request object (+0x94): vtable + first words
    if (FH2_IsLikelyReadablePointer(req))
    {
        volatile DWORD* r = (volatile DWORD*)req;
        FH2_Log("v0.8.17 REQ94 @0x%08X: %08X %08X %08X %08X %08X %08X %08X %08X", req, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    }
}

static VOID FH2_RoadTripStateTick()
{
    if (!g_FH2RoadTripTapInstalled)
        return;

    LONG calls = g_FH2RoadTripTapCalls;
    DWORD rawObject = g_FH2RoadTripRawObject;
    DWORD object = g_FH2RoadTripObject;
    ++g_FH2RoadTripTick;

    // Always prove whether the tap itself is firing. This is deliberately
    // emitted by the 500 ms worker, never by the hot hook.
    if (calls != g_FH2RoadTripLastLoggedCalls && ((g_FH2RoadTripTick & 1) == 0))
    {
        FH2_Log("ROADTRIP TAP: calls=%d raw_r3=0x%08X accepted_obj=0x%08X", calls, rawObject, object);
        g_FH2RoadTripLastLoggedCalls = calls;
    }

    FH2_LogDispatchCaptureIfReady();
    FH2_LogCompletionProducerIfReady();
    FH2_LogRequestTraceIfReady();
    FH2_LogPayloadTraceIfReady();
    FH2_LogComputed282ProducerIfReady();
    FH2_LogRequestStatusZeroIfReady();
    FH2_LogLocalMethodRuntime();
    FH2_LogSelectionCallbackIfReady();
    if (object) FH2_DumpEventTable(object);

    LONG eventMask = (g_FH2RoadTripSaw281 ? 1 : 0) |
                     (g_FH2RoadTripSaw282 ? 2 : 0) |
                     (g_FH2RoadTripSaw1EC ? 4 : 0) |
                     (g_FH2RoadTripSaw1ED ? 8 : 0);
    if (eventMask != g_FH2RoadTripLastEventMaskLogged)
    {
        FH2_Log("ROADTRIP HOT EVENTS: mask=0x%X first281=%d first282=%d first1EC=%d first1ED=%d",
            eventMask, g_FH2RoadTripFirst281Call, g_FH2RoadTripFirst282Call,
            g_FH2RoadTripFirst1ECCall, g_FH2RoadTripFirst1EDCall);
        g_FH2RoadTripLastEventMaskLogged = eventMask;
    }

    if (!FH2_IsExactRoadTripObject(object))
        return;

    // v0.7.2: once the active +0x94 request exists, dump only vtable methods
    // that directly reference the request fields seen changing at failure
    // (+0x114/+0x128/+0x12C/+0x170/+0x184). This is read-only and runs once.
    // v0.8.3: intentionally skip the large request/vtable dump; provenance only.

    // v0.7.2 does not patch the global completion-chain callsites.

    // Capture the whole small state cluster around the flags used by
    // 0x8283E448, plus the readiness fields used by 0x8269C368.
    DWORD vtable  = *((volatile DWORD*)(object + 0x00));
    BYTE byte4D   = *((volatile BYTE*)(object + 0x4D));
    DWORD word94  = *((volatile DWORD*)(object + 0x94));
    DWORD word1EC = *((volatile DWORD*)(object + 0x1EC));
    DWORD word26C = *((volatile DWORD*)(object + 0x26C));
    DWORD word270 = *((volatile DWORD*)(object + 0x270));
    DWORD word274 = *((volatile DWORD*)(object + 0x274));
    DWORD word278 = *((volatile DWORD*)(object + 0x278));
    DWORD word27C = *((volatile DWORD*)(object + 0x27C));
    DWORD word280 = *((volatile DWORD*)(object + 0x280));
    DWORD word284 = *((volatile DWORD*)(object + 0x284));

    if (object != g_FH2MarkerObject)
        FH2_ResetMarkerState(object);

    DWORD markerPlaylist = (word280 >> 24) & 0xFF;

    FH2_V083Tick(object, word94);

    if (!g_FH2MarkerSelectedSent &&
        markerPlaylist >= 2 && markerPlaylist <= 5)
    {
        g_FH2MarkerSelectedSent = TRUE;
        FH2_ProbeOpenWindow();
        FH2_SendMarkerWorker("SELECTED", object, word94, markerPlaylist, calls);
    }

    if (!g_FH2MarkerRequestSent && word94 != 0)
    {
        g_FH2MarkerRequestSent = TRUE;
        FH2_SendMarkerWorker("REQUEST94", object, word94, markerPlaylist, calls);
    }

    if (!g_FH2MarkerCompletionSent &&
        g_FH2RoadTripSaw281 && g_FH2RoadTripSaw282)
    {
        g_FH2MarkerCompletionSent = TRUE;
        FH2_SendMarkerWorker("COMPLETION281282",
            object, word94, markerPlaylist, calls);
    }

    if (!g_FH2MarkerConsumedSent &&
        g_FH2MarkerCompletionSent &&
        ((word1EC >> 24) & 0xFF) != 0)
    {
        g_FH2MarkerConsumedSent = TRUE;
        FH2_SendMarkerWorker("FAILCONSUMED1EC",
            object, word94, markerPlaylist, calls);
    }

    BOOL changed = (object != g_FH2RoadTripLastObject) ||
                   (word280 != g_FH2RoadTripLastWord280) ||
                   (word1EC != g_FH2RoadTripLastWord1EC) ||
                   (word94 != g_FH2RoadTripLastWord94) ||
                   (byte4D != g_FH2RoadTripLast4D);

    // Log immediately on a change and otherwise once per second.
    if (changed || ((g_FH2RoadTripTick & 1) == 0))
    {
        BYTE flag281 = *((volatile BYTE*)(object + 0x281));
        BYTE flag282 = *((volatile BYTE*)(object + 0x282));
        BYTE flag283 = *((volatile BYTE*)(object + 0x283));
        BYTE flag284 = *((volatile BYTE*)(object + 0x284));
        BYTE flag1EC = *((volatile BYTE*)(object + 0x1EC));
        BYTE flag1ED = *((volatile BYTE*)(object + 0x1ED));
        BYTE flag1EE = *((volatile BYTE*)(object + 0x1EE));
        BYTE flag1EF = *((volatile BYTE*)(object + 0x1EF));

        FH2_Log("ROADTRIP STATE: obj=0x%08X vt=0x%08X calls=%d +4D=%u +94=0x%08X +1EC..1EF=%u,%u,%u,%u +281..284=%u,%u,%u,%u",
            object, vtable, calls, byte4D, word94,
            flag1EC, flag1ED, flag1EE, flag1EF,
            flag281, flag282, flag283, flag284);
        FH2_Log("ROADTRIP WORDS: +1EC=%08X +26C=%08X +270=%08X +274=%08X +278=%08X +27C=%08X +280=%08X +284=%08X",
            word1EC, word26C, word270, word274, word278, word27C, word280, word284);

        g_FH2RoadTripLastObject = object;
        g_FH2RoadTripLastWord280 = word280;
        g_FH2RoadTripLastWord1EC = word1EC;
        g_FH2RoadTripLastWord94 = word94;
        g_FH2RoadTripLast4D = byte4D;
    }
}

static VOID FH2_LogFlagStoreWindow(PLDR_DATA_TABLE_ENTRY module, DWORD center, WORD offset)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD startImage = (DWORD)module->ImageBase;
    DWORD endImage = startImage + module->SizeOfNtImage;
    DWORD start = (center >= startImage + 16) ? center - 16 : startImage;
    DWORD end = center + 16;
    if (end + 4 > endImage)
        end = endImage - 4;

    FH2_Log("ROADTRIP STORE CODE: offset=0x%04X window around 0x%08X", offset, center);
    for (DWORD a = start; a <= end; a += 4)
        FH2_Log("ROADTRIP STORE CODE: %s0x%08X = 0x%08X", (a == center) ? "> " : "  ", a, *((DWORD*)a));
}

static VOID FH2_ScanRoadTripFlagStores(PLDR_DATA_TABLE_ENTRY module, WORD offset)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;

    for (DWORD address = start; address + 4 <= end && matches < 24; address += 4)
    {
        DWORD instruction = *((DWORD*)address);
        DWORD opcode = instruction >> 26;
        if (opcode != 38) // stb rS,D(rA)
            continue;
        if ((WORD)(instruction & 0xFFFF) != offset)
            continue;

        DWORD rs = (instruction >> 21) & 0x1F;
        DWORD ra = (instruction >> 16) & 0x1F;
        FH2_Log("ROADTRIP STORE CANDIDATE: stb r%u,0x%04X(r%u) at 0x%08X instruction=0x%08X",
            rs, offset, ra, address, instruction);
        FH2_LogFlagStoreWindow(module, address, offset);
        ++matches;
    }

    FH2_Log("ROADTRIP STORE SCAN: offset=0x%04X matches=%u", offset, matches);
}

static VOID FH2_LogCallWindow(PLDR_DATA_TABLE_ENTRY module, DWORD center, DWORD target)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD startImage = (DWORD)module->ImageBase;
    DWORD endImage = startImage + module->SizeOfNtImage;
    DWORD start = (center >= startImage + 20) ? center - 20 : startImage;
    DWORD end = center + 12;
    if (end + 4 > endImage)
        end = endImage - 4;

    FH2_Log("ROADTRIP DISPATCH CALLSITE: direct BL to 0x%08X at 0x%08X", target, center);
    for (DWORD a = start; a <= end; a += 4)
        FH2_Log("ROADTRIP DISPATCH CODE: %s0x%08X = 0x%08X", (a == center) ? "> " : "  ", a, *((DWORD*)a));
}

static VOID FH2_ScanDirectCallsTo(PLDR_DATA_TABLE_ENTRY module, DWORD wantedTarget)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
        return;

    DWORD start = (DWORD)module->ImageBase;
    DWORD end = start + module->SizeOfNtImage;
    DWORD matches = 0;

    for (DWORD address = start; address + 4 <= end && matches < 32; address += 4)
    {
        DWORD instruction = *((DWORD*)address);
        if ((instruction >> 26) != 18 || !(instruction & 1))
            continue;

        LONG displacement = (LONG)(instruction & 0x03FFFFFC);
        if (displacement & 0x02000000)
            displacement |= (LONG)0xFC000000;

        DWORD target = (instruction & 2) ? (DWORD)displacement : (DWORD)(address + displacement);
        if (target != wantedTarget)
            continue;

        FH2_LogCallWindow(module, address, wantedTarget);
        ++matches;
    }

    FH2_Log("ROADTRIP DISPATCH SCAN: target=0x%08X matches=%u", wantedTarget, matches);
}

static BOOL FH2_SetupRoadTripFocusedProfiler(PLDR_DATA_TABLE_ENTRY module)
{
    // v0.7.6 selection/request flow map. v0.7.0 proved the repeated 0x21/0x22 request
    // words are not the downstream decision by themselves. Keep retail Road Trip
    // completion behavior untouched and map the exact dispatcher plus request
    // vtable methods that can write/read the changing completion fields.
    DWORD* kickoffBranch = (DWORD*)0x8283E4A8;
    const DWORD KickoffOriginal = 0x41820044; // beq 0x8283E4EC
    if (*kickoffBranch != KickoffOriginal)
    {
        FH2_Log("v0.7.7 WARNING: expected original +0x281 branch at 0x8283E4A8, found %08X.", *kickoffBranch);
        return FALSE;
    }

    DWORD* dispatchSite = (DWORD*)0x8283E4D4;
    if (dispatchSite[0] != 0x38800000 ||
        dispatchSite[1] != 0x7FE3FB78 ||
        dispatchSite[2] != 0x4BFC1455 ||
        dispatchSite[3] != 0x39600000)
    {
        FH2_Log("v0.7.7 WARNING: retail Road Trip dispatch callsite not original at 0x8283E4D4: %08X %08X %08X %08X.",
            dispatchSite[0], dispatchSite[1], dispatchSite[2], dispatchSite[3]);
        return FALSE;
    }
    FH2_Log("v0.7.9 retail Road Trip completion dispatch preserved at 0x8283E4D4.");

    DWORD* tap = (DWORD*)0x8283E440;
    const DWORD Expected0 = 0x7C7F1B78;
    const DWORD Expected1 = 0x806B22F0;
    const DWORD Expected2 = 0x4BBB4429;
    const DWORD Expected3 = 0x546B063F;
    if (tap[0] != Expected0 || tap[1] != Expected1 || tap[2] != Expected2 || tap[3] != Expected3)
    {
        FH2_Log("v0.7.9 ROADTRIP TAP FAILED at 0x8283E440. Found %08X %08X %08X %08X.",
            tap[0], tap[1], tap[2], tap[3]);
        return FALSE;
    }

    g_FH2RoadTripObject = 0;
    g_FH2RoadTripRawObject = 0;
    g_FH2RoadTripTapCalls = 0;
    g_FH2RoadTripLastLoggedCalls = -1;
    g_FH2RoadTripTick = 0;
    g_FH2RoadTripLastObject = 0;
    g_FH2RoadTripLastWord280 = 0xFFFFFFFF;
    g_FH2RoadTripLastWord1EC = 0xFFFFFFFF;
    g_FH2RoadTripLastWord94 = 0xFFFFFFFF;
    g_FH2RoadTripLast4D = 0xFF;
    g_FH2RoadTripSaw281 = 0;
    g_FH2RoadTripSaw282 = 0;
    g_FH2RoadTripSaw1EC = 0;
    g_FH2RoadTripSaw1ED = 0;
    g_FH2RoadTripFirst281Call = 0;
    g_FH2RoadTripFirst282Call = 0;
    g_FH2RoadTripFirst1ECCall = 0;
    g_FH2RoadTripFirst1EDCall = 0;
    g_FH2RoadTripLastEventMaskLogged = -1;
    g_FH2MethodScanLogged = FALSE;

    g_FH2RequestTraceState = 0;
    g_FH2RequestBaselineCall = 0;
    g_FH2RequestCompletionCall = 0;
    g_FH2RequestBaselinePtr = 0;
    g_FH2RequestCompletionPtr = 0;
    g_FH2RequestBaselineVtable = 0;
    g_FH2RequestCompletionVtable = 0;
    g_FH2RequestCompletion281 = 0;
    g_FH2RequestCompletion282 = 0;
    g_FH2RequestCompletion1EC = 0;
    g_FH2RequestCompletion1ED = 0;
    g_FH2RequestTraceLogged = FALSE;
    g_FH2PayloadPtrCount = 0;
    g_FH2PayloadCompletionCaptured = FALSE;
    g_FH2PayloadLogged = FALSE;

    g_FH2StatusZeroArmedRequest = 0;
    g_FH2StatusZeroApplied = 0;
    g_FH2StatusZeroReady = 0;
    g_FH2StatusZeroLogged = FALSE;
    g_FH2StatusZeroCall = 0;
    g_FH2StatusZeroRequest = 0;
    g_FH2StatusZeroStatusBefore = 0;
    g_FH2StatusZeroStatusAfter = 0;
    g_FH2StatusZeroChild170 = 0;
    g_FH2StatusZeroChild184 = 0;
    g_FH2StatusZeroChild170Before = 0xFFFFFFFF;
    g_FH2StatusZeroChild184Before = 0xFFFFFFFF;
    g_FH2StatusZeroChild170After = 0xFFFFFFFF;
    g_FH2StatusZeroChild184After = 0xFFFFFFFF;
    g_FH2StatusZeroPlaylist = 0;

    // Keep the risky global completion-chain hooks completely retail.
    // Dump the dispatcher body and every direct BL caller once at startup.
    FH2_LogRuntimeDispatchCode();
    FH2_ScanDirectCallsTo(module, 0x827FF930);

    // Dump the complete Road Trip availability/completion decision block.
    // v0.7.1 showed that our availability tap jumps directly to 0x8283E4A0,
    // so seeing 0x8283E440..0x8283E49C is important for reconstructing the
    // retail false/true paths we have been skipping.
    FH2_Log("ROADTRIP DECISION BLOCK CODE: begin 0x8283E440..0x8283E510");
    for (DWORD a = 0x8283E440; a <= 0x8283E510; a += 4)
        FH2_Log("ROADTRIP DECISION BLOCK CODE: 0x%08X = 0x%08X", a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP DECISION BLOCK CODE: end");

    // 0x8283E4C8 calls 0x8269C368 and branches on its low-byte return before
    // the second state-0 dispatch. Dump that predicate and all direct callers.
    FH2_Log("ROADTRIP PREDICATE CODE: begin 0x8269C320..0x8269C4A0");
    for (DWORD a = 0x8269C320; a <= 0x8269C4A0; a += 4)
        FH2_Log("ROADTRIP PREDICATE CODE: 0x%08X = 0x%08X", a, *((volatile DWORD*)a));
    FH2_Log("ROADTRIP PREDICATE CODE: end");
    FH2_ScanDirectCallsTo(module, 0x8269C368);

    // v0.7.6: v0.7.4 proved that the five guessed +0x281 writers are not the
    // live Road Trip completion producer. Do not install those hooks again.
    //
    // Instead, dump the Road Trip-local methods that surround playlist selection
    // and request creation. These four methods are all in the live Road Trip
    // object's vtable:
    //   +0x0C -> 0x8283E218
    //   +0x24 -> 0x8283E358
    //   +0x6C -> 0x8283E298
    //   +0x08 -> 0x8283E428 (the update/completion method we already know)
    //
    // This is deliberately earlier than the 20-30 second completion failure:
    // the goal is to identify the exact method/branch that creates obj+0x94 and
    // the retail continuation that would normally consume a successful result.
    FH2_Log("ROADTRIP LOCAL FLOW CODE: begin 0x8283E1C0..0x8283E440");
    for (DWORD a = 0x8283E1C0; a <= 0x8283E440; a += 4)
    {
        DWORD insn = *((volatile DWORD*)a);
        FH2_Log("ROADTRIP LOCAL FLOW CODE: 0x%08X = 0x%08X", a, insn);

        // Decode direct PPC b/bl targets in this local region for easier
        // reconstruction without needing another broad trace build.
        if ((insn >> 26) == 18)
        {
            LONG displacement = (LONG)(insn & 0x03FFFFFC);
            if (displacement & 0x02000000)
                displacement |= (LONG)0xFC000000;
            DWORD target = (insn & 2) ? (DWORD)displacement : (DWORD)(a + displacement);
            FH2_Log("ROADTRIP LOCAL FLOW BRANCH: at=0x%08X target=0x%08X LK=%u AA=%u",
                a, target, (insn & 1) ? 1 : 0, (insn & 2) ? 1 : 0);
        }
    }
    FH2_Log("ROADTRIP LOCAL FLOW CODE: end");

    // v0.7.8: E358 was proven to be a per-frame/menu-active method, not the
    // actual playlist selection callback. Leave E218/E298/E358 completely retail.
    //
    // Hook the exact selected-playlist store instead:
    //   0x82838CE0 = stb r4,0x280(r31)
    // followed by the retail helper call to 0x826D63C0.
    BOOL bSelectionHookOK = TRUE;
    DWORD* pSelect = (DWORD*)0x82838CE0;
    const DWORD selectExpected[4] = { 0x989F0280, 0x4BE9D6DD, 0x897F0280, 0x3D408338 };
    for (int i = 0; i < 4; ++i)
        if (pSelect[i] != selectExpected[i]) bSelectionHookOK = FALSE;

    if (bSelectionHookOK)
    {
        PatchInJump(pSelect, (DWORD)&FH2_SelectionCallbackHook_CE0, FALSE);
        FH2_Log("v0.7.9 SELECTION CALLBACK HOOK installed at 0x82838CE0.");
        FH2_Log("v0.7.9 exact retail sequence validated: stb +280 / bl 826D63C0 / lbz +280 / lis 8338.");
    }
    else
    {
        FH2_Log("v0.7.9 SELECTION CALLBACK HOOK validation FAILED at 0x82838CE0: %08X %08X %08X %08X",
            pSelect[0], pSelect[1], pSelect[2], pSelect[3]);
    }

    FH2_DumpSelectionHelperCode();
    FH2_ScanSelectionGlobalRefs(module);

    g_FH2ProducerCaptureState = 0;
    g_FH2ProducerCaptureLogged = FALSE;

    PatchInJump(tap, (DWORD)&FH2_RoadTripStateTapHook, FALSE);
    g_FH2RoadTripTapInstalled = TRUE;

    FH2_Log("v0.7.9 REQUEST-BIRTH MAP armed: E218/E298/E358 hooks disabled.");
    FH2_Log("v0.7.9 selectionHook=%d live Road Trip/request trace remains enabled.", bSelectionHookOK);
    FH2_Log("v0.7.9 ROADTRIP TAP installed at 0x8283E440; forced TRUE-path behavior retained.");
    return TRUE;
}



// ---------------------------------------------------------------------------
// v0.8.3 IDENTITY MAP (read-only diagnostics, no new code hooks)
//  * RTTI class names for the Road Trip and request vtables (if RTTI exists)
//  * Request-vtable method code words (previous dumps were overwritten)
//  * One-shot raw dump of the request object when first seen
// ---------------------------------------------------------------------------
static DWORD g_FH2V083ImageBase = 0;
static DWORD g_FH2V083ImageEnd = 0;
static DWORD g_FH2V083LastDumpedRequest = 0;

static BOOL FH2_V083InImage(DWORD addr, DWORD size)
{
    return g_FH2V083ImageBase && addr >= g_FH2V083ImageBase &&
           addr + size <= g_FH2V083ImageEnd && addr + size >= addr;
}

static VOID FH2_V083LogRtti(const CHAR* label, DWORD vtable)
{
    if (!FH2_V083InImage(vtable - 4, 8)) { FH2_Log("v0.8.3 RTTI %s: vtable 0x%08X outside image", label, vtable); return; }
    DWORD col = *((volatile DWORD*)(vtable - 4));
    if (!FH2_V083InImage(col, 0x10)) { FH2_Log("v0.8.3 RTTI %s: vt=0x%08X no COL (vt[-1]=%08X)", label, vtable, col); return; }
    DWORD td = *((volatile DWORD*)(col + 0x0C));
    if (!FH2_V083InImage(td, 0x10)) { FH2_Log("v0.8.3 RTTI %s: vt=0x%08X COL=0x%08X bad TD=%08X", label, vtable, col, td); return; }
    CHAR name[96];
    int i = 0;
    for (; i < 95; ++i)
    {
        if (!FH2_V083InImage(td + 8 + i, 1)) break;
        CHAR c = *((volatile CHAR*)(td + 8 + i));
        if (c == 0 || c < 0x20 || c > 0x7E) break;
        name[i] = c;
    }
    name[i] = 0;
    FH2_Log("v0.8.3 RTTI %s: vt=0x%08X COL=0x%08X TD=0x%08X name=\"%s\"", label, vtable, col, td, name);
}

static VOID FH2_V083DumpVtable(const CHAR* label, DWORD vtable, int slots, int instrs)
{
    for (int i = 0; i < slots; ++i)
    {
        if (!FH2_V083InImage(vtable + i * 4, 4)) break;
        DWORD fn = *((volatile DWORD*)(vtable + i * 4));
        if (!FH2_V083InImage(fn, 16))
        {
            FH2_Log("v0.8.3 VT %s[%02d]=%08X (not code)", label, i, fn);
            continue;
        }
        CHAR line[320];
        int n = 0;
        for (int k = 0; k < instrs && FH2_V083InImage(fn + k * 4, 4); ++k)
            n += sprintf_s(line + n, sizeof(line) - n, "%08X ", *((volatile DWORD*)(fn + k * 4)));
        FH2_Log("v0.8.3 VT %s[%02d]=%08X : %s", label, i, fn, line);
    }
}

static VOID FH2_V083StaticIdentity(PLDR_DATA_TABLE_ENTRY module)
{
    if (!module || !module->ImageBase || module->SizeOfNtImage < 0x1000)
        return;
    g_FH2V083ImageBase = (DWORD)module->ImageBase;
    g_FH2V083ImageEnd = g_FH2V083ImageBase + module->SizeOfNtImage;

    FH2_Log("v0.8.3 IDENTITY: image 0x%08X..0x%08X", g_FH2V083ImageBase, g_FH2V083ImageEnd);
    FH2_V083LogRtti("RoadTrip", 0x820728D4);
    FH2_V083LogRtti("Request", 0x8205D7C4);
    FH2_V083DumpVtable("Request", 0x8205D7C4, 24, 14);
    // Availability getter (reads +0x2334 and +0x33DC) - original code words.
    if (FH2_V083InImage(0x823F2870, 64))
    {
        CHAR line[320]; int n = 0;
        for (int k = 0; k < 16; ++k)
            n += sprintf_s(line + n, sizeof(line) - n, "%08X ", *((volatile DWORD*)(0x823F2870 + k * 4)));
        FH2_Log("v0.8.3 AVAIL getter @0x823F2870: %s", line);
    }
}

static BOOL FH2_V083Readable(DWORD addr, DWORD bytes)
{
    for (DWORD o = 0; o < bytes; o += 0x1000)
        if (!MmIsAddressValid((PVOID)(addr + o))) return FALSE;
    return MmIsAddressValid((PVOID)(addr + bytes - 1));
}

static VOID FH2_V083Tick(DWORD object, DWORD request)
{
    // NOTE: the availability getter at 0x823F2870 does lwz r11,0x2334(r3);
    // r3 is NOT known to be the Road Trip object, so we do not sample it here.
    // One-shot raw request dump (object memory, heap) + RTTI of its vtable.
    if (request && request != g_FH2V083LastDumpedRequest &&
        request >= 0x10000 && FH2_V083Readable(request, 0x1A0))
    {
        g_FH2V083LastDumpedRequest = request;
        DWORD vt = *((volatile DWORD*)(request));
        FH2_Log("v0.8.3 REQUEST DUMP: req=0x%08X vt=0x%08X tick=%u", request, vt, GetTickCount());
        for (DWORD off = 0; off < 0x1A0; off += 0x20)
        {
            FH2_Log("v0.8.3 REQ+%03X: %08X %08X %08X %08X %08X %08X %08X %08X", off,
                *((volatile DWORD*)(request + off + 0x00)), *((volatile DWORD*)(request + off + 0x04)),
                *((volatile DWORD*)(request + off + 0x08)), *((volatile DWORD*)(request + off + 0x0C)),
                *((volatile DWORD*)(request + off + 0x10)), *((volatile DWORD*)(request + off + 0x14)),
                *((volatile DWORD*)(request + off + 0x18)), *((volatile DWORD*)(request + off + 0x1C)));
        }
    }
}


// v0.8.3b: one-shot dump of the RUNNING (TU-patched) FH2 image to FH2_image.bin
// so offline disassembly matches runtime addresses. Skipped if the file exists.
// Runs from the title loop ~20 s after load (menu reached), takes a few seconds.
static VOID FH2_V083DumpImageOnce()
{
    static BOOL done = FALSE;
    static int ticks = 0;
    if (done || ++ticks < 40)
        return;
    done = TRUE;

    const CHAR* path = MOUNT_POINT "\\FH2_image_cpu.bin";
    if (GetFileAttributes(path) != 0xFFFFFFFF)
    {
        FH2_Log("v0.8.3 IMAGE DUMP: %s already exists, skipping.", path);
        return;
    }
    HANDLE h = CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        FH2_Log("v0.8.3 IMAGE DUMP: cannot create %s", path);
        return;
    }
    static BYTE zeros[0x1000];
    // Code pages are encrypted in RAM; only CPU loads see plaintext. Copy with
    // explicit 32-bit loads into a heap buffer, then write the buffer.
    static DWORD copyBuf[0x10000 / 4];
    DWORD start = 0x82000000, end = 0x83700000, unreadable = 0;
    for (DWORD a = start; a < end; a += 0x10000)
    {
        BOOL ok = TRUE;
        for (DWORD o = 0; o < 0x10000; o += 0x1000)
            if (!MmIsAddressValid((PVOID)(a + o))) { ok = FALSE; break; }
        DWORD wr = 0;
        if (ok)
        {
            volatile DWORD* src = (volatile DWORD*)a;
            for (DWORD i = 0; i < 0x10000 / 4; ++i)
                copyBuf[i] = src[i];
            WriteFile(h, copyBuf, 0x10000, &wr, NULL);
        }
        else
        {
            ++unreadable;
            for (DWORD o = 0; o < 0x10000; o += 0x1000)
            {
                if (MmIsAddressValid((PVOID)(a + o)))
                {
                    volatile DWORD* src = (volatile DWORD*)(a + o);
                    for (DWORD i = 0; i < 0x1000 / 4; ++i)
                        copyBuf[i] = src[i];
                    WriteFile(h, copyBuf, 0x1000, &wr, NULL);
                }
                else
                    WriteFile(h, zeros, 0x1000, &wr, NULL);
            }
        }
    }
    CloseHandle(h);
    FH2_Log("v0.8.3 IMAGE DUMP: wrote 0x%08X..0x%08X to %s (partly unreadable 64K blocks=%u).",
        start, end, path, unreadable);
}

static BOOL FH2_SetupRoadTripProvenanceProfiler(PLDR_DATA_TABLE_ENTRY module)
{
    FH2_V083StaticIdentity(module);

    DWORD* kickoffBranch = (DWORD*)0x8283E4A8;
    if (*kickoffBranch != 0x41820044)
    {
        FH2_Log("v0.8.3 WARNING: expected retail +0x281 branch at 0x8283E4A8, found %08X.",
            *kickoffBranch);
        return FALSE;
    }

    DWORD* dispatchSite = (DWORD*)0x8283E4D4;
    if (dispatchSite[0] != 0x38800000 ||
        dispatchSite[1] != 0x7FE3FB78 ||
        dispatchSite[2] != 0x4BFC1455 ||
        dispatchSite[3] != 0x39600000)
    {
        FH2_Log("v0.8.3 WARNING: retail completion dispatch not original: %08X %08X %08X %08X.",
            dispatchSite[0], dispatchSite[1], dispatchSite[2], dispatchSite[3]);
        return FALSE;
    }

    DWORD* tap = (DWORD*)0x8283E440;
    if (tap[0] != 0x7C7F1B78 ||
        tap[1] != 0x806B22F0 ||
        tap[2] != 0x4BBB4429 ||
        tap[3] != 0x546B063F)
    {
        FH2_Log("v0.8.3 ROADTRIP TAP validation failed: %08X %08X %08X %08X.",
            tap[0], tap[1], tap[2], tap[3]);
        return FALSE;
    }

    g_FH2RoadTripObject = 0;
    g_FH2RoadTripRawObject = 0;
    g_FH2RoadTripTapCalls = 0;
    g_FH2RoadTripLastLoggedCalls = -1;
    g_FH2RoadTripTick = 0;
    g_FH2RoadTripLastObject = 0;
    g_FH2RoadTripLastWord280 = 0xFFFFFFFF;
    g_FH2RoadTripLastWord1EC = 0xFFFFFFFF;
    g_FH2RoadTripLastWord94 = 0xFFFFFFFF;
    g_FH2RoadTripLast4D = 0xFF;

    g_FH2RoadTripSaw281 = 0;
    g_FH2RoadTripSaw282 = 0;
    g_FH2RoadTripSaw1EC = 0;
    g_FH2RoadTripSaw1ED = 0;
    g_FH2RoadTripFirst281Call = 0;
    g_FH2RoadTripFirst282Call = 0;
    g_FH2RoadTripFirst1ECCall = 0;
    g_FH2RoadTripFirst1EDCall = 0;
    g_FH2RoadTripLastEventMaskLogged = -1;

    g_FH2RequestTraceState = 0;
    g_FH2RequestBaselineCall = 0;
    g_FH2RequestCompletionCall = 0;
    g_FH2RequestBaselinePtr = 0;
    g_FH2RequestCompletionPtr = 0;
    g_FH2RequestBaselineVtable = 0;
    g_FH2RequestCompletionVtable = 0;
    g_FH2RequestCompletion281 = 0;
    g_FH2RequestCompletion282 = 0;
    g_FH2RequestCompletion1EC = 0;
    g_FH2RequestCompletion1ED = 0;
    g_FH2RequestTraceLogged = FALSE;
    g_FH2PayloadPtrCount = 0;
    g_FH2PayloadCompletionCaptured = FALSE;
    g_FH2PayloadLogged = FALSE;

    g_FH2MarkerSequence = 0;
    FH2_ResetMarkerState(0);

    PatchInJump(tap, (DWORD)&FH2_RoadTripStateTapHook, FALSE);
    g_FH2RoadTripTapInstalled = TRUE;

    FH2_Log("v0.8.3 ROADTRIP provenance profiler armed; retail completion dispatch preserved.");
    FH2_Log("v0.8.3 Wireshark markers -> 192.168.137.1:36099.");
    return TRUE;
}

// v0.8.31: the worker thread inspects game objects that the game can free at any moment. Catch any access violation
// here so a stale pointer can never reach DashLaunch's last-chance handler (which kills the game).
static volatile LONG g_FH2WorkerFaults = 0;
static VOID FH2_WorkerTickSafe()
{
    __try { FH2_RoadTripStateTick(); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LONG n = InterlockedIncrement(&g_FH2WorkerFaults);
        if (n <= 3) FH2_Log("v0.8.31 worker: caught fault in RoadTripStateTick (#%d)", n);
    }
    __try { FH2_ProbeTick(); }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        LONG n = InterlockedIncrement(&g_FH2WorkerFaults);
        if (n <= 3) FH2_Log("v0.8.31 worker: caught fault in ProbeTick (#%d)", n);
    }
}


// v0.9.19: result tracking for the XGI session calls, polled every loop iteration (50 ms).
static VOID FH2_XgiPollSafe()
{
    __try { FH2_XgiPoll(); }
    __except (EXCEPTION_EXECUTE_HANDLER) { }
    __try { FH2_StuckWatch(); }   // v1.0.29
    __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// =============================================================================
// v0.9.5: invite / relaunch state poller (read-only).
//
// Static analysis of the game shows where a join invite lives after the soft relaunch:
//   * app object pointer     *(0x83422224)  (created by 0x825CD328 -> ctor 0x82493668)
//       app+0x27  byte  "launched with launch data" flag, set when GetLaunchDataSize == 0x58
//       app+0x1F0 dword pointer to the 0x58-byte invite buffer until startup stashes it
//   * invite manager pointer *(0x8344DA6C)  (object size 0x78, stash function 0x829D1E40)
//       mgr+0x04  state (1 = invite pending, 2 = reboot issued, 0 = cleared)
//       mgr+0x08  copy of the 0x58-byte invite block (userIndex, XINVITE_INFO)
//       mgr+0x1C  title id inside the block      mgr+0x60  matched local user object
//       mgr+0x68/0x69/0x6A flag bytes (0x6A = pending)
// The validator at 0x829E06E8 drops the invite (state -> 0) if the title id is wrong or no local
// user matches the invite's user index.
//
// Hooks installed 3-4 s after the relaunch cannot see the earliest startup calls, so this worker
// watches those fields directly every 20 ms, starting before the relaunch (it is armed by the
// first FH2 detection and keeps running across relaunches), and logs every CHANGE with a
// millisecond offset. It also samples the Live sign-in state and the multiplayer privilege once
// per second. It only runs when the log option is enabled in FH2Revival.ini.
// =============================================================================
#define FH2_V095_APP_PTR_ADDR 0x83422224
#define FH2_V095_MGR_PTR_ADDR 0x8344DA6C
#define FH2_V095_LINE_CAP 900

typedef DWORD   (NTAPI* pFH2_V095_UserGetSigninState)(DWORD userIndex);
typedef HRESULT (NTAPI* pFH2_V095_UserGetXUID)(DWORD userIndex, DWORD flags, PULONGLONG xuidOut);
typedef DWORD   (NTAPI* pFH2_V095_UserCheckPrivilege)(DWORD userIndex, DWORD privilege, PBOOL result);
typedef BOOL    (NTAPI* pFH2_V095_UserIsOnlineEnabled)(DWORD userIndex);
typedef DWORD   (NTAPI* pFH2_V099_UserGetSigninInfo)(DWORD userIndex, DWORD flags, PVOID info);

struct FH2V095Snap
{
    DWORD app, mgr;
    DWORD a27, a1f0;
    DWORD m4, m68, m69, m6a, m60, m1c, m8;
};

struct FH2V095Ctx
{
    FH2V095Snap last;
    BOOL haveLast;
    DWORD lastSignTick;
    DWORD signKey[16];
    BOOL haveSign;
    DWORD dumpKey;
    DWORD lastA1f0Dumped;
    LONG blockDumps;
};

static volatile LONG g_FH2_V095_PollStarted = 0;
static volatile LONG g_FH2_V095_PollDone = 0;
static volatile LONG g_FH2_V095_Lines = 0;
static volatile DWORD g_FH2_V095_Epoch = 0;
static volatile DWORD g_FH2_V095_LastFh2Tick = 0;

#define FH2_V095_SAY(...) do { LONG _n = InterlockedIncrement(&g_FH2_V095_Lines); \
    if (_n <= FH2_V095_LINE_CAP) FH2_Log(__VA_ARGS__); \
    else if (_n == FH2_V095_LINE_CAP + 1) FH2_Log("v0.9.5 POLL: line cap reached for this game instance."); } while (0)

static BOOL FH2_V095_RD(DWORD addr, DWORD* out)
{
    if (addr < 0x10000 || (addr & 3) != 0 || !MmIsAddressValid((PVOID)addr))
        return FALSE;
    __try { *out = *(volatile DWORD*)addr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
    return TRUE;
}

static VOID FH2_V095_Sample(FH2V095Snap* s)
{
    DWORD v = 0;
    memset(s, 0, sizeof(*s));

    if (FH2_V095_RD(FH2_V095_APP_PTR_ADDR, &v)) s->app = v;
    if (FH2_V095_RD(FH2_V095_MGR_PTR_ADDR, &v)) s->mgr = v;

    if (s->app >= 0x10000)
    {
        if (FH2_V095_RD(s->app + 0x24, &v)) s->a27 = v & 0xFF;     // byte +0x27 = low byte of the big-endian dword at +0x24
        if (FH2_V095_RD(s->app + 0x1F0, &v)) s->a1f0 = v;
    }
    if (s->mgr >= 0x10000)
    {
        if (FH2_V095_RD(s->mgr + 0x04, &v)) s->m4 = v;
        if (FH2_V095_RD(s->mgr + 0x68, &v))
        {
            s->m68 = (v >> 24) & 0xFF;
            s->m69 = (v >> 16) & 0xFF;
            s->m6a = (v >> 8) & 0xFF;
        }
        if (FH2_V095_RD(s->mgr + 0x60, &v)) s->m60 = v;
        if (FH2_V095_RD(s->mgr + 0x1C, &v)) s->m1c = v;
        if (FH2_V095_RD(s->mgr + 0x08, &v)) s->m8 = v;
    }
}

static VOID FH2_V095_DumpBlock(const CHAR* label, DWORD base)
{
    DWORD d[22];
    for (int i = 0; i < 22; ++i)
    {
        d[i] = 0xFFFFFFFF;
        FH2_V095_RD(base + i * 4, &d[i]);
    }
    FH2_V095_SAY("v0.9.5 BLOCK %s @0x%08X +00: %08X %08X %08X %08X %08X %08X", label, base, d[0], d[1], d[2], d[3], d[4], d[5]);
    FH2_V095_SAY("v0.9.5 BLOCK %s        +18: %08X %08X %08X %08X %08X %08X", label, d[6], d[7], d[8], d[9], d[10], d[11]);
    FH2_V095_SAY("v0.9.5 BLOCK %s        +30: %08X %08X %08X %08X %08X %08X", label, d[12], d[13], d[14], d[15], d[16], d[17]);
    FH2_V095_SAY("v0.9.5 BLOCK %s        +48: %08X %08X %08X %08X", label, d[18], d[19], d[20], d[21]);
}

static VOID FH2_V095_PollOnce(FH2V095Ctx* c, DWORD now)
{
    FH2V095Snap s;
    DWORD epoch = g_FH2_V095_Epoch;
    DWORD ms = now - epoch;

    FH2_V095_Sample(&s);

    // v1.0.23: log-file hold.  Both v1.0.22 freezes (9:38 and 9:45) stopped the whole console, including this thread, about 50 ms
    // after the multiplayer-privilege check of an invite join, in the middle of a log/heartbeat file write.  While the invite
    // manager is in a pending state (1..12) and for 8 s after it returns to 0 (the relaunch gap), at most 40 s in all, no file is
    // opened: the lines stay in the queue and are written afterwards.  FH2Synth.txt word nohold turns this off.
    // v1.0.28: latelog.  The relaunch for an invite join froze a tester's console about 12 s after the title start, right after the sign-in
    // request, with logging on (and not with logging off).  With latelog no log or heartbeat file is opened for the first N seconds
    // after every title start (default 120); the lines stay in the queue (the first ~300 are kept) and are written afterwards.
    BOOL lateActive = FALSE;
    {
        extern BOOL g_FH2LateLog; extern DWORD g_FH2LateMs;
        lateActive = g_FH2LateLog && (DWORD)(now - g_FH2_V095_Epoch) < g_FH2LateMs;
    }
    {
        extern BOOL g_FH2NoHold;
        static DWORD holdStart = 0, holdLast = 0, holdBegan = 0;
        if (g_FH2NoHold)
        {
            extern BOOL g_FH2LateLog;
            if (g_FH2LateLog)
            {
                LONG wantL = lateActive ? 1 : 0;
                if (wantL != g_FH2LogHold)
                {
                    InterlockedExchange(&g_FH2LogHold, wantL);
                    if (!wantL) FH2_Log("v1.0.28 latelog: log-file writes started (%u ms after the title start)", (unsigned)(now - g_FH2_V095_Epoch));
                }
            }
        }
        else
        {
            BOOL pending = (s.mgr >= 0x10000 && s.m4 >= 1 && s.m4 <= 12);
            if (pending)
            {
                if (holdStart == 0) { holdStart = now; holdBegan = now; FH2_Log("v1.0.23 hold: log-file writes paused (invite state %u)", s.m4); }
                holdLast = now;
            }
            else if (holdStart != 0 && (now - holdLast) >= 8000) holdStart = 0;
            LONG want = (holdStart != 0 && (now - holdStart) < 40000) ? 1 : 0;
            if (lateActive) want = 1;   // v1.0.28
            if (want != g_FH2LogHold)
            {
                InterlockedExchange(&g_FH2LogHold, want);
                if (!want) FH2_Log("v1.0.23 hold: log-file writes resumed after %u ms", now - holdBegan);
            }
        }
    }

    // The app object disappearing means the previous game instance was torn down: restart the clock
    // so every offset below is relative to the new instance.
    if (c->haveLast && c->last.app != 0 && s.app == 0)
    {
        g_FH2_V095_Epoch = now;
        InterlockedExchange(&g_FH2_V095_Lines, 0);
        c->dumpKey = 0;
        c->lastA1f0Dumped = 0;
        c->blockDumps = 0;
        c->haveSign = FALSE;
        FH2_V095_ResetTraceCounters();
        FH2_V095_SAY("v0.9.5 POLL: game instance torn down (app object cleared). New epoch tick=%u", now);
        ms = 0;
    }

    if (!c->haveLast || memcmp(&s, &c->last, sizeof(s)) != 0)
    {
        FH2_V095_SAY("v0.9.5 STATE +%ums: app=0x%08X a27=%u a1f0=0x%08X | mgr=0x%08X state=%u pend6A=%u f68=%u f69=%u user60=0x%08X title=0x%08X userIdx=%u",
            ms, s.app, s.a27, s.a1f0, s.mgr, s.m4, s.m6a, s.m68, s.m69, s.m60, s.m1c, s.m8);

        // Dump the invite block the first time a given pending state is seen.
        DWORD key = (s.m4 << 24) | (s.m6a << 16) | (s.m68 << 8) | (s.m60 ? 1 : 0);
        if (s.mgr >= 0x10000 && s.m4 != 0 && key != c->dumpKey && c->blockDumps < 6)
        {
            c->dumpKey = key;
            c->blockDumps++;
            FH2_V095_DumpBlock("mgr+8", s.mgr + 8);
        }
        if (s.a1f0 >= 0x10000 && s.a1f0 != c->lastA1f0Dumped)
        {
            c->lastA1f0Dumped = s.a1f0;
            FH2_V095_DumpBlock("app+1F0", s.a1f0);
        }
        c->last = s;
        c->haveLast = TRUE;
    }

    // Live sign-in / privilege sample, once per second for the first two minutes of an instance.
    if (now - c->lastSignTick >= 1000 && ms < 120000)
    {
        static pFH2_V095_UserGetSigninState pState = NULL;
        static pFH2_V095_UserGetXUID pXuid = NULL;
        static pFH2_V095_UserCheckPrivilege pPriv = NULL;
        static pFH2_V095_UserIsOnlineEnabled pOnline = NULL;
        static pFH2_V099_UserGetSigninInfo pInfo = NULL;
        if (!pState)
        {
            pState = (pFH2_V095_UserGetSigninState)ResolveFunction("xam.xex", 528);
            pXuid = (pFH2_V095_UserGetXUID)ResolveFunction("xam.xex", 522);
            pPriv = (pFH2_V095_UserCheckPrivilege)ResolveFunction("xam.xex", 530);
            pOnline = (pFH2_V095_UserIsOnlineEnabled)ResolveFunction("xam.xex", 545);
            pInfo = (pFH2_V099_UserGetSigninInfo)ResolveFunction("xam.xex", 551);
        }
        c->lastSignTick = now;

        DWORD st = pState ? pState(0) : 0xFFFFFFFF;
        ULONGLONG x1 = 0, x2 = 0;
        HRESULT h1 = pXuid ? pXuid(0, 1, &x1) : (HRESULT)0xFFFFFFFF;
        HRESULT h2 = pXuid ? pXuid(0, 2, &x2) : (HRESULT)0xFFFFFFFF;
        BOOL mp = FALSE;
        DWORD hp = pPriv ? pPriv(0, 254, &mp) : 0xFFFFFFFF;
        DWORD onl = pOnline ? (pOnline(0) ? 1 : 0) : 0xFF;

        // v0.9.9: XUSER_SIGNIN_INFO with flags 0 (what a title that passes no XUID flag sees) and with the two documented flags.
        DWORD infoRc[3] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
        ULONGLONG infoXuid[3] = { 0, 0, 0 };
        DWORD infoFlags[3] = { 0, 0, 0 }, infoState[3] = { 0, 0, 0 };
        if (pInfo)
        {
            static const DWORD tryFlags[3] = { 0, 1, 2 };
            for (int k = 0; k < 3; ++k)
            {
                BYTE ib[64]; memset(ib, 0, sizeof(ib));
                infoRc[k] = pInfo(0, tryFlags[k], ib);
                infoXuid[k] = ((ULONGLONG)*(DWORD*)(ib + 0) << 32) | *(DWORD*)(ib + 4);
                infoFlags[k] = *(DWORD*)(ib + 8);
                infoState[k] = *(DWORD*)(ib + 12);
            }
        }
        DWORD key[16];
        memset(key, 0, sizeof(key));
        for (int k = 0; k < 3; ++k)
        {
            key[8 + k * 2] = (DWORD)(infoXuid[k] >> 32) ^ (DWORD)infoXuid[k] ^ infoRc[k];
            key[9 + k * 2] = infoFlags[k] ^ (infoState[k] << 8);
        }

        key[0] = st; key[1] = (DWORD)h1; key[2] = (DWORD)(x1 >> 32); key[3] = (DWORD)x1;
        key[4] = (DWORD)h2; key[5] = (DWORD)(x2 ^ (x2 >> 32)); key[6] = hp ^ (mp ? 0x100 : 0); key[7] = onl;
        if (!c->haveSign || memcmp(key, c->signKey, sizeof(key)) != 0)
        {
            memcpy(c->signKey, key, sizeof(key));
            c->haveSign = TRUE;
            FH2_V095_SAY("v0.9.9 SIGNINFO +%ums: flags0 rc=0x%08X xuid=0x%08X%08X info=0x%X state=%u | flags1 rc=0x%08X xuid=0x%08X%08X | flags2 rc=0x%08X xuid=0x%08X%08X",
                ms, infoRc[0], (DWORD)(infoXuid[0] >> 32), (DWORD)infoXuid[0], infoFlags[0], infoState[0],
                infoRc[1], (DWORD)(infoXuid[1] >> 32), (DWORD)infoXuid[1], infoRc[2], (DWORD)(infoXuid[2] >> 32), (DWORD)infoXuid[2]);
            FH2_V095_SAY("v0.9.5 SIGNIN +%ums: state=%u (0=none 1=local 2=live) onlineEnabled=%u xuid[flag1,offline-style]=0x%08X%08X hr=0x%08X xuid[flag2,online]=0x%08X%08X hr=0x%08X multiplayerPriv(254)=%u hr=0x%08X",
                ms, st, onl, (DWORD)(x1 >> 32), (DWORD)x1, (DWORD)h1, (DWORD)(x2 >> 32), (DWORD)x2, (DWORD)h2, mp ? 1 : 0, hp);
        }
    }
}


// v0.9.20: heartbeat.  Once a second (only while FH2 runs) ONE short line overwrites FH2P2P_HB.txt.  It never grows.
// After a freeze the file shows the last second the plugin was alive and the game-side counters at that moment: if the
// time stops, the whole console hung; if the time keeps going but xgi/recv stop, only the game hung.
static VOID FH2_V0920_Heartbeat(DWORD now, DWORD title)
{
    static DWORD lastHb = 0;
    if (title != ForzaHorizon2 || !g_FH2LogEnabled) return;
    if (g_FH2LogHold) return;   // v1.0.23: no file I/O while an invite join runs
    if (lastHb != 0 && (now - lastHb) < 1000) return;
    lastHb = now;
    DWORD xs = 0, sn = 0, rc = 0;
    FH2_HbSnap(&xs, &sn, &rc);
    SYSTEMTIME st; GetLocalTime(&st);
    CHAR line[200];
    MEMORYSTATUS ms; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);   // v0.9.26: free memory (MB) in the heartbeat
    sprintf_s(line, sizeof(line), "%02u:%02u:%02u tick=%u xgi=%u send=%u recv=%u freePhysMB=%u freeVirtMB=%u\r\n", st.wHour, st.wMinute, st.wSecond, now, xs, sn, rc,
        (DWORD)(ms.dwAvailPhys >> 20), (DWORD)(ms.dwAvailVirtual >> 20));
    HANDLE h = CreateFile(MOUNT_POINT "\\FH2P2P_HB.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0; WriteFile(h, line, (DWORD)strlen(line), &w, NULL);
    CloseHandle(h);
}

// v1.0.6: note every call of the game's popup builder (0x82887020: r3 = error index, r4 = popup type, caller LR) so the log shows which
// code path produced the NO NETWORK ACCESS popup.  The game thread only writes four words into a ring; the poll thread logs them.
static VOID FH2_FlushCode(VOID* p, DWORD bytes);
static volatile DWORD g_FH2PopupN = 0;
static DWORD g_FH2PopupRing[16][4];
static BOOL g_FH2PopupHookInstalled = FALSE;
VOID FH2_PopupNote(DWORD idx, DWORD type, DWORD caller)
{
	DWORD n = g_FH2PopupN;
	DWORD* e = g_FH2PopupRing[n & 15];
	e[0] = GetTickCount(); e[1] = idx; e[2] = type; e[3] = caller;
	g_FH2PopupN = n + 1;
}
__declspec(naked) VOID FH2_PopupHook()
{
	__asm
	{
		mflr    r12
		stwu    r1, -0x60(r1)
		stw     r3, 0x40(r1)
		stw     r4, 0x44(r1)
		stw     r12, 0x48(r1)
		mr      r5, r12
		bl      FH2_PopupNote
		lwz     r3, 0x40(r1)
		lwz     r4, 0x44(r1)
		lwz     r12, 0x48(r1)
		addi    r1, r1, 0x60

		// the instructions this hook replaced at 0x82887020: mflr r12 / bl 0x832FFF40 / stwu r1,-0x160(r1) / mr r30,r3
		lis     r11, 0x832F
		ori     r11, r11, 0xFF40
		mtctr   r11
		bctrl
		stwu    r1, -0x160(r1)
		mr      r30, r3

		lis     r11, 0x8288
		ori     r11, r11, 0x7030
		mtctr   r11
		bctr
	}
}

// v1.0.47: black FESTIVAL tile.  The game shows a destination picture by asking its own database "SELECT ImagePath FROM RoadTripLocations WHERE Id = %u"
// and loading ...\\DestinationImages\\Images_<size>\\Dest_<ImagePath>_<size>.xds from Textures.zip.  Festival (Id 0) has ImagePath "Festival", but the shipped zip
// has no Dest_Festival_*.xds, so the tile is drawn black.  Three call sites (372x372/1280x720, 372x183, 185x372) load the SQL text address with a lis/addi pair;
// point each at a copy of the query that answers another picture name for Id 0.  Pure data/instruction-word patch, nothing is hooked.
static CHAR g_FH2FestSqlA[192];   // SELECT ImagePath ...
static CHAR g_FH2FestSqlB[192];   // SELECT Name, ImagePath ...
static BOOL FH2_FestPicSite(DWORD lisAddr, DWORD addiAddr, DWORD origAddi, const CHAR* sql)
{
	DWORD* pl = (DWORD*)lisAddr;
	DWORD* pa = (DWORD*)addiAddr;
	DWORD a = (DWORD)sql;
	DWORD hi = ((a + 0x8000) >> 16) & 0xFFFF, lo = a & 0xFFFF;
	if (pl[0] == 0x3D608204 && pa[0] == origAddi)
	{
		pl[0] = 0x3D600000 | hi;          // lis r11, hi
		pa[0] = 0x388B0000 | lo;          // addi r4, r11, lo
		FH2_FlushCode(pl, 4);
		FH2_FlushCode(pa, 4);
		FH2_Log("v1.0.47 Festival picture: query redirected at 0x%08X/0x%08X.", lisAddr, addiAddr);
		return TRUE;
	}
	if ((pl[0] & 0xFFFF0000) == 0x3D600000 && (pa[0] & 0xFFFF0000) == 0x388B0000)
		FH2_Log("v1.0.47 Festival picture: already redirected at 0x%08X.", lisAddr);
	else
		FH2_Log("v1.0.47 Festival picture patch SKIPPED at 0x%08X (found %08X %08X).", lisAddr, pl[0], pa[0]);
	return FALSE;
}
static VOID FH2_FestPicPatch()
{
	extern CHAR g_FH2FestPic[40];
	CHAR nm[40]; int n = 0;
	for (; n < 31 && g_FH2FestPic[n]; ++n) nm[n] = g_FH2FestPic[n];
	nm[n] = 0;
	if (!n) { static const CHAR dflt[] = "NiceMassena"; memcpy(nm, dflt, sizeof(dflt)); }
	// build the two queries by plain copying (no printf family): head + name + tail
	static const CHAR headA[] = "SELECT CASE Id WHEN 0 THEN '";
	static const CHAR headB[] = "SELECT Name, CASE Id WHEN 0 THEN '";
	static const CHAR tail[]  = "' ELSE ImagePath END ImagePath FROM RoadTripLocations WHERE Id = %u";
	for (int k = 0; k < 2; ++k)
	{
		CHAR* o = k ? g_FH2FestSqlB : g_FH2FestSqlA;
		const CHAR* h = k ? headB : headA;
		DWORD hl = (DWORD)strlen(h), nl = (DWORD)strlen(nm), tl = (DWORD)strlen(tail);
		memcpy(o, h, hl); memcpy(o + hl, nm, nl); memcpy(o + hl + nl, tail, tl + 1);
	}
	FH2_Log("v1.0.47 Festival tile picture -> %s.", nm);
	FH2_FestPicSite(0x827ADDFC, 0x827ADE04, 0x388BFA64, g_FH2FestSqlA);   // 372x372 / 1280x720 (lobby, vote)
	FH2_FestPicSite(0x826E8138, 0x826E8140, 0x388BFA64, g_FH2FestSqlA);   // 372x183
	FH2_FestPicSite(0x826977EC, 0x826977F8, 0x388B9F18, g_FH2FestSqlB);   // 185x372
}

static VOID FH2_InstallPopupHook()
{
	DWORD* p = (DWORD*)0x82887020;
	if (p[0] == 0x7D8802A6 && p[1] == 0x48A78F1D && p[2] == 0x9421FEA0 && p[3] == 0x7C7E1B78)
	{
		PatchInJump(p, (DWORD)&FH2_PopupHook, FALSE);
		FH2_FlushCode(p, 16);
		g_FH2PopupHookInstalled = TRUE;
		FH2_Log("v1.0.6 popup note hook installed at 0x82887020.");
	}
	else
		FH2_Log("v1.0.6 popup note hook SKIPPED (found %08X %08X %08X %08X).", p[0], p[1], p[2], p[3]);
}

// v1.0.12: every state change of the game's lobby / party state machine goes through one function (0x829E31F8: r3 = object, r4 = new state,
// object+0x2C = current state; the callers are the individual transitions and their timeouts).  Note each call (old state, new state, caller LR and two
// return addresses further up the stack) so the log shows which transition ended the free-roam invite and why.  Game thread: only writes a ring.
static volatile DWORD g_FH2LobbyN = 0;
static DWORD g_FH2LobbyRing[32][8];
static BOOL g_FH2LobbyHookInstalled = FALSE;
VOID FH2_LobbyNote(DWORD obj, DWORD newState, DWORD caller, DWORD sp)
{
	DWORD n = g_FH2LobbyN;
	DWORD* e = g_FH2LobbyRing[n & 31];
	DWORD oldState = 0xFFFFFFFF;
	if (obj >= 0x10000 && obj < 0x9FFFFF00 && MmIsAddressValid((PVOID)(obj + 0x2C)))
		oldState = *(volatile DWORD*)(obj + 0x2C);
	e[0] = GetTickCount(); e[1] = obj; e[2] = oldState; e[3] = newState; e[4] = caller; e[5] = 0; e[6] = 0; e[7] = 0;
	DWORD s = sp;
	for (int k = 0; k < 3; ++k)
	{
		if (s < 0x70000000 || s >= 0x80000000 || (s & 7) || !MmIsAddressValid((PVOID)s)) break;
		DWORD prev = *(volatile DWORD*)s;
		if (prev <= s || prev >= 0x80000000 || (prev & 7) || !MmIsAddressValid((PVOID)(prev - 8))) break;
		DWORD ra = *(volatile DWORD*)(prev - 8);
		if (ra < 0x82000000 || ra >= 0x84000000) break;
		e[5 + k] = ra;
		s = prev;
	}
	g_FH2LobbyN = n + 1;
}
__declspec(naked) VOID FH2_LobbyHook()
{
	__asm
	{
		mflr    r12
		mr      r6, r1
		stwu    r1, -0x60(r1)
		stw     r3, 0x40(r1)
		stw     r4, 0x44(r1)
		stw     r12, 0x48(r1)
		mr      r5, r12
		bl      FH2_LobbyNote
		lwz     r3, 0x40(r1)
		lwz     r4, 0x44(r1)
		lwz     r12, 0x48(r1)
		addi    r1, r1, 0x60

		// the instructions this hook replaced at 0x829E31F8: mflr r12 / bl 0x832FFF74 / stwu r1,-0x80(r1) / lbz r11,0x9B4(r3)
		lis     r10, 0x832F
		ori     r10, r10, 0xFF74
		mtctr   r10
		bctrl
		stwu    r1, -0x80(r1)
		lbz     r11, 0x9B4(r3)

		lis     r10, 0x829E
		ori     r10, r10, 0x3208
		mtctr   r10
		bctr
	}
}

static VOID FH2_InstallLobbyHook()
{
	DWORD* p = (DWORD*)0x829E31F8;
	if (p[0] == 0x7D8802A6 && p[1] == 0x4891CD79 && p[2] == 0x9421FF80 && p[3] == 0x896309B4)
	{
		PatchInJump(p, (DWORD)&FH2_LobbyHook, FALSE);
		FH2_FlushCode(p, 16);
		g_FH2LobbyHookInstalled = TRUE;
		FH2_Log("v1.0.12 lobby state hook installed at 0x829E31F8.");
	}
	else
		FH2_Log("v1.0.12 lobby state hook SKIPPED (found %08X %08X %08X %08X).", p[0], p[1], p[2], p[3]);
}

// v1.0.13: the lobby stop that ends the free-roam invite comes from a UI message handler (0x8283BD28: r3 = screen, r4 = message id, r6 = message
// data, handled only for r4 == 0 and *(r6+0xC) == 0).  Note every call with r4 == 0 plus the first words of the message data.
BOOL g_FH2NoCancel = FALSE;
BOOL g_FH2Pad = FALSE;   // v1.0.16: word 'pad' = log controller button changes (v1.0.15 did this always and the log stopped before the error)
static volatile DWORD g_FH2MsgN = 0;
static DWORD g_FH2MsgRing[16][26];
static volatile DWORD g_FH2MsgAll = 0;
static BOOL g_FH2MsgHookInstalled = FALSE;
extern BOOL g_FH2NoCancel;
DWORD FH2_MsgNote(DWORD scr, DWORD id, DWORD r5, DWORD r6, DWORD caller, DWORD sp)
{
	g_FH2MsgAll = g_FH2MsgAll + 1;
	if (id != 0) return 0;
	DWORD n = g_FH2MsgN;
	DWORD* e = g_FH2MsgRing[n & 15];
	e[0] = GetTickCount(); e[1] = scr; e[2] = r5; e[3] = r6; e[4] = caller;
	for (int k = 0; k < 7; ++k) e[5 + k] = 0xFFFFFFFE;
	e[24] = 0xFFFFFFFE; e[25] = 0xFFFFFFFE;
	if (scr >= 0x10000 && scr < 0x9FFFFF00 && !(scr & 3) && MmIsAddressValid((PVOID)scr) && MmIsAddressValid((PVOID)(scr + 7))) { e[24] = *(volatile DWORD*)scr; e[25] = *(volatile DWORD*)(scr + 4); }   // v1.0.20: class of the dialog
	if (r6 >= 0x10000 && r6 < 0x9FFFFF00 && !(r6 & 3) && MmIsAddressValid((PVOID)r6) && MmIsAddressValid((PVOID)(r6 + 27)))
		for (int k = 0; k < 7; ++k) e[5 + k] = ((volatile DWORD*)r6)[k];
	// return addresses above the handler: words in the game's code that follow a bl
	DWORD found = 0;
	for (int k = 12; k < 24; ++k) e[k] = 0;
	for (DWORD a = sp; a < sp + 0x600 && found < 12; a += 4)
	{
		if (!MmIsAddressValid((PVOID)a)) break;
		DWORD v = *(volatile DWORD*)a;
		if (v < 0x82000100 || v >= 0x83000000 || (v & 3)) continue;
		DWORD prev = *(volatile DWORD*)(v - 4);
		if ((prev & 0xFC000003) != 0x48000001) continue;
		e[12 + found++] = v;
	}
	g_FH2MsgN = n + 1;
	// opt-in ("nocancel" in FH2Synth.txt): swallow the blank message (+0xC == 0) whose handler stops the lobby
	return 0;
}
__declspec(naked) VOID FH2_MsgHook()
{
	__asm
	{
		mflr    r12
		stwu    r1, -0x70(r1)
		stw     r3, 0x40(r1)
		stw     r4, 0x44(r1)
		stw     r5, 0x48(r1)
		stw     r6, 0x4C(r1)
		stw     r7, 0x50(r1)
		stw     r12, 0x54(r1)
		mr      r7, r12
		addi    r8, r1, 0x70
		bl      FH2_MsgNote
		cmplwi  cr6, r3, 0
		bne     cr6, msg_skip
		lwz     r3, 0x40(r1)
		lwz     r4, 0x44(r1)
		lwz     r5, 0x48(r1)
		lwz     r6, 0x4C(r1)
		lwz     r7, 0x50(r1)
		lwz     r12, 0x54(r1)
		addi    r1, r1, 0x70
		b       msg_replay
msg_skip:
		lwz     r12, 0x54(r1)
		mtlr    r12
		addi    r1, r1, 0x70
		li      r3, 0
		blr
msg_replay:

		// the instructions this hook replaced at 0x8283BD28: mflr r12 / bl 0x832FFF88 / std r31,-0x10(r1) / stwu r1,-0x60(r1)
		lis     r10, 0x832F
		ori     r10, r10, 0xFF88
		mtctr   r10
		bctrl
		std     r31, -0x10(r1)
		stwu    r1, -0x60(r1)

		lis     r10, 0x8283
		ori     r10, r10, 0xBD38
		mtctr   r10
		bctr
	}
}

// v1.0.18: every dialog the game shows goes through the UI manager's ShowMessage method (vtable slot 0x4C = 0x82FF5588; r4 = type,
// r5 = string id, 0x14F = the 'NO NETWORK ACCESS' text).  Log each call with the call chain, so the moment the error APPEARS is known.
// (The id-0 message hooked above turned out to be what pressing OK on that dialog sends.)
static volatile DWORD g_FH2DlgN = 0;
static DWORD g_FH2DlgRing[16][64];   // v1.0.45: 20 -> 64 words per entry (deeper call chain)
VOID FH2_DlgNote(DWORD obj, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8, DWORD lr, DWORD sp)
{
	DWORD n = g_FH2DlgN;
	DWORD* e = g_FH2DlgRing[n & 15];
	e[0] = GetTickCount(); e[1] = a4; e[2] = a5; e[3] = a6; e[4] = a7; e[5] = a8; e[6] = lr;
	for (int k = 7; k < 64; ++k) e[k] = 0;
	DWORD found = 0;
	for (DWORD a = sp; a < sp + 0x1400 && found < 55; a += 4)
	{
		if (!MmIsAddressValid((PVOID)a)) break;
		DWORD v = *(volatile DWORD*)a;
		if (v < 0x82000100 || v >= 0x83000000 || (v & 3)) continue;
		DWORD prev = *(volatile DWORD*)(v - 4);
		if ((prev & 0xFC000003) != 0x48000001 && prev != 0x4E800421) continue;
		e[7 + found++] = v;
	}
	g_FH2DlgN = n + 1;
}
__declspec(naked) VOID FH2_DlgHook()
{
	__asm
	{
		mflr    r12
		stwu    r1, -0x80(r1)
		stw     r3, 0x40(r1)
		stw     r4, 0x44(r1)
		stw     r5, 0x48(r1)
		stw     r6, 0x4C(r1)
		stw     r7, 0x50(r1)
		stw     r8, 0x54(r1)
		stw     r12, 0x58(r1)
		mr      r9, r12
		addi    r10, r1, 0x80
		bl      FH2_DlgNote
		lwz     r3, 0x40(r1)
		lwz     r4, 0x44(r1)
		lwz     r5, 0x48(r1)
		lwz     r6, 0x4C(r1)
		lwz     r7, 0x50(r1)
		lwz     r8, 0x54(r1)
		lwz     r12, 0x58(r1)
		addi    r1, r1, 0x80

		// replayed from 0x82FF5588: mflr r12 / bl 0x832FFF70 / stwu r1,-0x90(r1) / mr r31,r3
		lis     r10, 0x832F
		ori     r10, r10, 0xFF70
		mtctr   r10
		bctrl
		stwu    r1, -0x90(r1)
		mr      r31, r3

		lis     r10, 0x82FF
		ori     r10, r10, 0x5598
		mtctr   r10
		bctr
	}
}

static VOID FH2_InstallDlgHook()
{
	DWORD* p = (DWORD*)0x82FF5588;
	if (p[0] == 0x7D8802A6 && p[1] == 0x4830A9E5 && p[2] == 0x9421FF70 && p[3] == 0x7C7F1B78)
	{
		PatchInJump(p, (DWORD)&FH2_DlgHook, FALSE);
		FH2_FlushCode(p, 16);
		FH2_Log("v1.0.18 dialog hook installed at 0x82FF5588.");
	}
	else
		FH2_Log("v1.0.18 dialog hook SKIPPED (found %08X %08X %08X %08X).", p[0], p[1], p[2], p[3]);
}


// v1.0.20: the error dialog is NOT shown through the ShowMessage routine above (v1.0.19 log is complete and has no such call at the
// moment it appears).  Its OK handler (0x8283BD28) belongs to two screen classes whose constructors both call the common screen base
// constructor 0x826BE720.  Log every call to that base constructor (the lr tells the class: 0x8283B798 / 0x82837A3C) with the call chain,
// so the log shows WHEN the error screen is built and by whom.
static volatile DWORD g_FH2ScrN = 0;
static DWORD g_FH2ScrRing[64][12];
// v1.0.46: make the game report the player's own level / badge / title to the title server.  The game does that (CBadgeTitleManager::UpdateServerData,
// 0x82504DD8 -> SetPlayercardInfo web call) only when a badge/title unlocks, so the server never knew anyone's level and every leaderboard row showed 1.
// Runs on the game's own thread (this hook fires when a screen is built), once, 40 s after the first connect to the title server (logon is done by then).
// The manager object is found the same way the game's UI does (0x827F7150): G=*(0x83422224); profile=*(G+0x6C); R=0x8254F878(profile); manager=R+0x3C.
extern volatile DWORD g_FH2HttpTick; extern BOOL g_FH2NoCard;
static volatile DWORD g_FH2CardDone = 0;
static VOID FH2_CardPush()
{
	if (g_FH2CardDone || g_FH2NoCard) return;
	DWORD t0 = g_FH2HttpTick;
	if (!t0) return;
	DWORD now = GetTickCount();
	if (now - t0 < 40000) return;
	static DWORD lastTry = 0, tries = 0;
	if (lastTry && now - lastTry < 5000) return;
	lastTry = now;
	if (++tries > 8) { g_FH2CardDone = 1; FH2_Log("v1.0.46 PLAYERCARD: giving up after 8 tries."); return; }
	DWORD G = *(volatile DWORD*)0x83422224;
	if (G < 0x10000 || G >= 0x9FFFFF00 || !MmIsAddressValid((PVOID)(G + 0x70))) { FH2_Log("v1.0.46 PLAYERCARD: try %u: game object not ready (G=%08X).", tries, G); return; }
	DWORD prof = *(volatile DWORD*)(G + 0x6C);
	if (prof < 0x10000 || prof >= 0x9FFFFF00 || !MmIsAddressValid((PVOID)prof)) { FH2_Log("v1.0.46 PLAYERCARD: try %u: profile not ready (G=%08X prof=%08X).", tries, G, prof); return; }
	typedef DWORD (*pCardFn)(DWORD);
	DWORD R = ((pCardFn)0x8254F878)(prof);
	if (R < 0x10000 || R >= 0x9FFFFF00 || !MmIsAddressValid((PVOID)(R + 0x40))) { FH2_Log("v1.0.46 PLAYERCARD: try %u: profile data not ready (prof=%08X R=%08X).", tries, prof, R); return; }
	DWORD mgr = R + 0x3C;
	DWORD settings = *(volatile DWORD*)mgr;
	if (settings < 0x10000 || settings >= 0x9FFFFF00) { FH2_Log("v1.0.46 PLAYERCARD: try %u: no settings yet (mgr=%08X settings=%08X).", tries, mgr, settings); return; }
	g_FH2CardDone = 1;
	FH2_Log("v1.0.46 PLAYERCARD: tick=%u calling UpdateServerData(mgr=%08X settings=%08X) G=%08X prof=%08X R=%08X", now, mgr, settings, G, prof, R);
	((pCardFn)0x82504DD8)(mgr);
	FH2_Log("v1.0.46 PLAYERCARD: UpdateServerData returned.");
}

VOID FH2_ScrNote(DWORD obj, DWORD a4, DWORD a5, DWORD a6, DWORD a7, DWORD a8, DWORD lr, DWORD sp)
{
	FH2_CardPush();
	DWORD n = g_FH2ScrN;
	DWORD* e = g_FH2ScrRing[n & 63];
	e[0] = GetTickCount(); e[1] = obj; e[2] = lr; e[3] = a7;
	for (int k = 4; k < 12; ++k) e[k] = 0;
	DWORD found = 0;
	for (DWORD a = sp; a < sp + 0x400 && found < 8; a += 4)
	{
		if (!MmIsAddressValid((PVOID)a)) break;
		DWORD v = *(volatile DWORD*)a;
		if (v < 0x82000100 || v >= 0x83000000 || (v & 3)) continue;
		DWORD prev = *(volatile DWORD*)(v - 4);
		if ((prev & 0xFC000003) != 0x48000001 && prev != 0x4E800421) continue;
		e[4 + found++] = v;
	}
	g_FH2ScrN = n + 1;
}
__declspec(naked) VOID FH2_ScrHook()
{
	__asm
	{
		mflr    r12
		stwu    r1, -0x80(r1)
		stw     r3, 0x40(r1)
		stw     r4, 0x44(r1)
		stw     r5, 0x48(r1)
		stw     r6, 0x4C(r1)
		stw     r7, 0x50(r1)
		stw     r8, 0x54(r1)
		stw     r12, 0x58(r1)
		mr      r9, r12
		addi    r10, r1, 0x80
		bl      FH2_ScrNote
		lwz     r3, 0x40(r1)
		lwz     r4, 0x44(r1)
		lwz     r5, 0x48(r1)
		lwz     r6, 0x4C(r1)
		lwz     r7, 0x50(r1)
		lwz     r8, 0x54(r1)
		lwz     r12, 0x58(r1)
		addi    r1, r1, 0x80

		// replayed from 0x826BE720: mflr r12 / bl 0x832FFF78 / stwu r1,-0x80(r1) / mr r31,r3
		lis     r10, 0x832F
		ori     r10, r10, 0xFF78
		mtctr   r10
		bctrl
		stwu    r1, -0x80(r1)
		mr      r31, r3

		lis     r10, 0x826B
		ori     r10, r10, 0xE730
		mtctr   r10
		bctr
	}
}

static VOID FH2_InstallScrHook()
{
	DWORD* p = (DWORD*)0x826BE720;
	if (p[0] == 0x7D8802A6 && p[1] == 0x48C41855 && p[2] == 0x9421FF80 && p[3] == 0x7C7F1B78)
	{
		PatchInJump(p, (DWORD)&FH2_ScrHook, FALSE);
		FH2_FlushCode(p, 16);
		FH2_Log("v1.0.20 screen constructor hook installed at 0x826BE720.");
	}
	else
		FH2_Log("v1.0.20 screen constructor hook SKIPPED (found %08X %08X %08X %08X).", p[0], p[1], p[2], p[3]);
}

static VOID FH2_InstallMsgHook()
{
	DWORD* p = (DWORD*)0x8283BD28;
	if (p[0] == 0x7D8802A6 && p[1] == 0x48AC425D && p[2] == 0xFBE1FFF0 && p[3] == 0x9421FFA0)
	{
		PatchInJump(p, (DWORD)&FH2_MsgHook, FALSE);
		FH2_FlushCode(p, 16);
		g_FH2MsgHookInstalled = TRUE;
		FH2_Log("v1.0.13 UI message hook installed at 0x8283BD28.");
	}
	else
		FH2_Log("v1.0.13 UI message hook SKIPPED (found %08X %08X %08X %08X).", p[0], p[1], p[2], p[3]);
}

// v1.0.5: the game's online manager (global pointer at 0x8344DB78) keeps its state in the word at +8.  2 = an operation timed out,
// 6 = "cannot connect to Xbox Live" (shows the NO NETWORK ACCESS popup).  Log every change so the log shows what the game decided and when.
// v1.0.31: snapshots of the stunt-start loading screen (ctor 828109D8, 0x5A0 bytes), its dialog data (id 0x4E) and the in-event screen (ctor 827F58E0, 0x3B8 bytes)
static DWORD g_SnapObj = 0, g_SnapT0 = 0, g_SnapDlg = 0, g_SnapStage = 0;
static DWORD g_SnapObj2 = 0, g_SnapT2 = 0, g_SnapStage2 = 0;

// ---------------------------------------------------------------------------------------------------------------------------------------
// (the broadcast info block is 0x58 bytes at CConsole+0x2C in the retail build; the 97-byte ConsoleInfo message = 105-byte datagram in the P2P logs)
// v1.0.36: console flags / game arbiter / starting grid.  READ-ONLY poll from the existing 20 ms thread (no code hooks, nothing is called in
// the game).  Static analysis of the beta build (symbols) matched to the retail image shows that the 3-player co-op start is gated by
// per-console flag words that every console broadcasts (CConsole::BroadcastConsoleInfo, flags at CConsole+0x24, second word at +0x28):
//   0x01/0x02 render-ready, 0x08 session host, 0x10 GAME ARBITER (sends the start message, broadcasts the starting grid), 0x200 has the grid.
// SyncStartingGrid waits until CConsoleManager::AllConsolesHaveGrid (0x8254F0E8) is true: the local console has 0x200 AND every console with
// 0x02 also has 0x200.  The arbiter is elected by UpdateGameArbiterStatus (0x827703C0): lowest XUID among the ready consoles.
// Retail addresses: console manager pointer at 0x83429C74 (+0x18 local CConsole, +0x0C std::map head node, value at node+0x10);
// lobby object pointer at 0x8344DA70 (+0xB0C race synchronisation manager: +0x0C state, +0x04 start time).
static BOOL FH2_GdRead(DWORD a, DWORD* out)
{
	if (a < 0x10000 || a >= 0x9FFFFF00 || (a & 3)) return FALSE;
	if (!MmIsAddressValid((PVOID)a) || !MmIsAddressValid((PVOID)(a + 3))) return FALSE;
	*out = *(volatile DWORD*)a;
	return TRUE;
}
static DWORD g_gdHead = 0;
static BOOL FH2_GdIsNil(DWORD node)   // v1.0.40: the sentinel IS the map's head node (leaves and the root's parent point at it).  v1.0.40's log showed the
{                                      // _Isnil byte of a REAL node is non-zero in this build, so the byte test made every walk end at once (mapcons=0).
	if (node < 0x10000 || node >= 0x9FFFFF00) return TRUE;
	return node == g_gdHead;
}
static DWORD FH2_GdSucc(DWORD node, DWORD head)   // in-order successor, like the iterator ++ the game uses
{
	DWORD right = 0, left = 0, parent = 0;
	if (!FH2_GdRead(node + 8, &right)) return head;
	if (!FH2_GdIsNil(right))
	{
		node = right;
		for (int k = 0; k < 40; ++k)
		{
			if (!FH2_GdRead(node, &left)) return head;
			if (FH2_GdIsNil(left)) break;
			node = left;
		}
		return node;
	}
	for (int k = 0; k < 40; ++k)
	{
		if (!FH2_GdRead(node + 4, &parent)) return head;
		if (FH2_GdIsNil(parent)) return parent;
		if (!FH2_GdRead(parent + 8, &right)) return head;
		if (node != right) return parent;
		node = parent;
	}
	return head;
}
static int FH2_GdName(DWORD f, CHAR* out, int cap)
{
	int p = 0;
	p += sprintf_s(out + p, cap - p, "%s%s%s%s%s", (f & 1) ? "R1 " : "", (f & 2) ? "R2 " : "", (f & 8) ? "HOST " : "", (f & 0x10) ? "ARB " : "", (f & 0x200) ? "GRID" : "");
	DWORD other = f & ~(DWORD)(1 | 2 | 8 | 0x10 | 0x200);
	if (other) p += sprintf_s(out + p, cap - p, " +%X", other);
	return p;
}
// v1.0.40: best-effort player identity.  The 0x58-byte info block each console broadcasts (CConsole+0x2C) should hold its XUID; the layout is
// not verified, so look for the first 64-bit value whose high word starts with 0x0009 (XUID of a real profile) and report its LOW word.
// A guess, so the GRID INFO line (whole block) is still written once per console to confirm it by hand.
static DWORD FH2_GdXuidLo(DWORD con)
{
	for (DWORD o = 0; o + 8 <= 0x58; o += 4)
	{
		DWORD hi = 0, lo = 0;
		if (FH2_GdRead(con + 0x2C + o, &hi) && (hi & 0xFFFF0000) == 0x00090000 && FH2_GdRead(con + 0x2C + o + 4, &lo)) return lo;
	}
	return 0;
}
#define FH2_GD_MAX 8
static VOID FH2_GridDiag(DWORD now)
{
	// v1.0.40: v1.0.36-38 only walked the map of REMOTE consoles and logged "cons=0" the whole time (the local console is kept separately at
	// manager+0x18, outside the map, and the game reads its flags directly).  Now: local flags read directly, the map size and a raw dump of the
	// manager are logged, and the all-grid / arbiter logic follows the game's own functions (local console + every console in the map).
	static DWORD sig[8 + FH2_GD_MAX * 3];
	static BOOL sigInit = FALSE;
	static DWORD lastLog = 0, lastSize = 0xFFFFFFFF, lastFail = 0, failN = 0;
	static DWORD seen[24];
	static DWORD seenN = 0;
	static BOOL armed = FALSE;
	if (!armed) { armed = TRUE; FH2_Log("v1.0.40 GRID armed: console-state poll is running (tick=%u)", now); }
	DWORD mgr = 0, local = 0, head = 0, node = 0, size = 0xFFFFFFFF, lf1 = 0, lf2 = 0;
#define FH2_GD_FAIL(step) { if (failN < 3 || (DWORD)(now - lastFail) >= 30000) { ++failN; lastFail = now; FH2_Log("v1.0.40 GRID unreadable: step=%d mgr=%08X local=%08X head=%08X", step, mgr, local, head); } return; }
	if (!FH2_GdRead(0x83429C74, &mgr) || mgr < 0x10000) FH2_GD_FAIL(1)
	if (!FH2_GdRead(mgr + 0x18, &local) || !FH2_GdRead(mgr + 0x0C, &head) || head < 0x10000) FH2_GD_FAIL(2)
	if (!FH2_GdRead(head, &node)) FH2_GD_FAIL(3)
	g_gdHead = head;
	FH2_GdRead(mgr + 0x10, &size);
	if (local >= 0x10000) { FH2_GdRead(local + 0x24, &lf1); FH2_GdRead(local + 0x28, &lf2); }

	DWORD cp[FH2_GD_MAX], f1[FH2_GD_MAX], f2[FH2_GD_MAX], xl[FH2_GD_MAX], n = 0;
	for (int guard = 0; guard < 40 && node != head && n < FH2_GD_MAX; ++guard)
	{
		if (FH2_GdIsNil(node)) break;
		DWORD con = 0, a = 0, b = 0;
		if (FH2_GdRead(node + 0x10, &con) && con >= 0x10000 && FH2_GdRead(con + 0x24, &a) && FH2_GdRead(con + 0x28, &b))
		{
			cp[n] = con; f1[n] = a; f2[n] = b; xl[n] = FH2_GdXuidLo(con); ++n;
		}
		node = FH2_GdSucc(node, head);
	}
	DWORD xlLocal = (local >= 0x10000) ? FH2_GdXuidLo(local) : 0;

	// race synchronisation manager (start time / state)
	DWORD lobby = 0, rsm = 0, rsmState = 0xFFFFFFFF, rsmStart = 0;
	if (FH2_GdRead(0x8344DA70, &lobby) && lobby >= 0x10000 && FH2_GdRead(lobby + 0xB0C, &rsm) && rsm >= 0x10000)
	{
		if (!FH2_GdRead(rsm + 0x0C, &rsmState)) rsmState = 0xFFFFFFFE;
		FH2_GdRead(rsm + 0x04, &rsmStart);
	}

	// the game's own logic: arbiter = any console (local first, then the map) with 0x10; AllConsolesHaveGrid (retail 0x8254F0E8) =
	// local has 0x200 AND every console in the map that has 0x02 also has 0x200
	DWORD nArb = (lf1 & 0x10) ? 1 : 0, blocker = 0;
	BOOL all = TRUE;
	for (DWORD i = 0; i < n; ++i) if (f1[i] & 0x10) ++nArb;
	if (!(lf1 & 0x200)) { all = FALSE; blocker = 1; }   // 1 = the local console itself has no grid yet
	for (DWORD i = 0; i < n && all; ++i)
		if ((f1[i] & 2) && !(f1[i] & 0x200)) { all = FALSE; blocker = cp[i]; }

	DWORD cur[8 + FH2_GD_MAX * 3];
	memset(cur, 0, sizeof(cur));
	cur[0] = n; cur[1] = local; cur[2] = rsmState; cur[3] = size; cur[4] = lf1; cur[5] = lf2; cur[6] = mgr; cur[7] = head;
	for (DWORD i = 0; i < n; ++i) { cur[8 + i * 3] = cp[i]; cur[9 + i * 3] = f1[i]; cur[10 + i * 3] = f2[i] ^ (xl[i] * 31); }
	BOOL changed = !sigInit || memcmp(cur, sig, sizeof(cur)) != 0;
	BOOL periodic = (n >= 1 || (size != 0xFFFFFFFF && size > 0) || lf1 != 0) && (DWORD)(now - lastLog) >= 5000;
	if (!changed && !periodic) return;

	// line 1: local console + manager
	FH2_Log("v1.0.40 GRID %s tick=%u mgr=%08X head=%08X size=%d mapcons=%u LOCAL con=%08X x=%08X f=%08X/%08X arb=%u allGrid=%d blocker=%s rsm=%08X st=%d start=%d",
		changed ? "CHANGE" : "STATE", now, mgr, head, (int)size, n, local, xlLocal, lf1, lf2, nArb, all ? 1 : 0,
		(blocker == 0) ? "-" : (blocker == 1 ? "LOCAL" : "REMOTE"), rsm, (int)rsmState, (int)rsmStart);

	// line 2: the consoles in the map
	if (n > 0)
	{
		CHAR line[460]; int p = 0;
		p += sprintf_s(line + p, sizeof(line) - p, "v1.0.40 GRID MAP tick=%u |", now);
		for (DWORD i = 0; i < n && p < (int)sizeof(line) - 95; ++i)
		{
			CHAR nm[48]; FH2_GdName(f1[i], nm, sizeof(nm));
			p += sprintf_s(line + p, sizeof(line) - p, " [%s%s con=%08X x=%08X f=%08X/%08X %s]", (cp[i] == local) ? "LOCAL" : "remote", (cp[i] == blocker) ? " BLOCKER" : "", cp[i], xl[i], f1[i], f2[i], nm);
		}
		FH2_Log("%s", line);
	}
	memcpy(sig, cur, sizeof(sig)); sigInit = TRUE; lastLog = now;

	// raw dump of the manager object whenever its map size changes (and once at the start): proves the layout when the walk finds nothing
	if (size != lastSize)
	{
		lastSize = size;
		CHAR hx[300]; int q = 0;
		for (DWORD o = 0; o < 0x40 && q < (int)sizeof(hx) - 12; o += 4)
		{
			DWORD w = 0;
			if (FH2_GdRead(mgr + o, &w)) q += sprintf_s(hx + q, sizeof(hx) - q, "%08X ", w);
			else q += sprintf_s(hx + q, sizeof(hx) - q, "???????? ");
		}
		FH2_Log("v1.0.40 GRID MGR size=%d mgr(+00..3C): %s", (int)size, hx);
		DWORD hw[4] = { 0, 0, 0, 0 };
		FH2_GdRead(head, &hw[0]); FH2_GdRead(head + 4, &hw[1]); FH2_GdRead(head + 8, &hw[2]); FH2_GdRead(head + 12, &hw[3]);
		FH2_Log("v1.0.40 GRID HEAD head=%08X: %08X %08X %08X %08X  (first node=%08X nil=%d)", head, hw[0], hw[1], hw[2], hw[3], hw[0], FH2_GdIsNil(hw[0]) ? 1 : 0);
	}

	// first sight of a console: its broadcast info block (0x58 bytes at +0x2C), once, to tell the consoles apart (local console included)
	DWORD allc[FH2_GD_MAX + 1]; DWORD na = 0;
	if (local >= 0x10000) allc[na++] = local;
	for (DWORD i = 0; i < n; ++i) if (cp[i] != local) allc[na++] = cp[i];
	for (DWORD i = 0; i < na; ++i)
	{
		BOOL known = FALSE;
		for (DWORD k = 0; k < seenN && k < 24; ++k) if (seen[k] == allc[i]) known = TRUE;
		if (known) continue;
		seen[seenN % 24] = allc[i]; ++seenN;
		CHAR hx[240]; int q = 0;
		for (DWORD o = 0; o < 0x58 && q < (int)sizeof(hx) - 12; o += 4)
		{
			DWORD w = 0;
			if (FH2_GdRead(allc[i] + 0x2C + o, &w)) q += sprintf_s(hx + q, sizeof(hx) - q, "%08X ", w);
			else q += sprintf_s(hx + q, sizeof(hx) - q, "???????? ");
		}
		FH2_Log("v1.0.40 GRID INFO con=%08X %s info(+2C): %s", allc[i], (allc[i] == local) ? "LOCAL" : "remote", hx);
	}
}

static VOID FH2_V105_StateSample(DWORD now)
{
	if (g_FH2GridDiag) FH2_GridDiag(now);   // v1.0.36
	if (g_FH2WaitDiag || g_FH2LockDiag) FH2_WaitDiagPoll(now);   // v1.0.41/43
	// v1.0.8: also the game's connection object (global 0x8344DA70: +0x2C = connection state, 0 means "not connected to Live", +0x31 = flag)
	// and the manager's failure fields (+0x14, +0xE0, +0xE4 are written when the failure popup path runs).
	static DWORD last[8] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
	DWORD cur[8] = { 0, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE };
	DWORD mgr = *(volatile DWORD*)0x8344DB78;
	DWORD con = *(volatile DWORD*)0x8344DA70;
	cur[0] = mgr;
	if (mgr >= 0x10000 && mgr < 0x9FFFFF00 && MmIsAddressValid((PVOID)mgr) && MmIsAddressValid((PVOID)(mgr + 0xE8)))
	{
		cur[1] = *(volatile DWORD*)(mgr + 8);
		cur[2] = *(volatile DWORD*)(mgr + 0x14);
		cur[3] = *(volatile DWORD*)(mgr + 0xE0);
		cur[4] = *(volatile DWORD*)(mgr + 0xE4);
	}
	cur[5] = con;
	if (con >= 0x10000 && con < 0x9FFFFF00 && MmIsAddressValid((PVOID)con) && MmIsAddressValid((PVOID)(con + 0x34)))
	{
		cur[6] = *(volatile DWORD*)(con + 0x2C);
		cur[7] = *(volatile BYTE*)(con + 0x31);
	}
	BOOL changed = FALSE;
	for (int k = 0; k < 8; ++k) if (cur[k] != last[k]) changed = TRUE;
	if (changed)
	{
		FH2_Log("v1.0.8 ONLINE STATE: tick=%u mgr=%08X state=%d +14=%d +E0=%d +E4=%d | conn=%08X +2C=%d +31=%d", now, cur[0], (int)cur[1], (int)cur[2], (int)cur[3], (int)cur[4], cur[5], (int)cur[6], (int)cur[7]);
		for (int k = 0; k < 8; ++k) last[k] = cur[k];
	}
	{
		typedef DWORD (*pXamInputGetState)(DWORD, DWORD, PVOID);
		static pXamInputGetState fn = NULL; static BOOL tried = FALSE;
		static WORD lastBtn[4] = {0,0,0,0}; static DWORD lastPkt[4] = {0,0,0,0};
		if (g_FH2Pad && !tried) { tried = TRUE; fn = (pXamInputGetState)ResolveFunction("xam.xex", 401); }
		if (g_FH2Pad && fn)
			for (DWORD u = 0; u < 4; ++u)
			{
				struct { DWORD pkt; WORD btn; BYTE lt, rt; SHORT lx, ly, rx, ry; } st;
				memset(&st, 0, sizeof(st));
				if (fn(u, 0, &st) != 0) continue;
				if (st.btn != lastBtn[u])
				{
					FH2_Log("v1.0.15 PAD %u: tick=%u buttons=%04X -> %04X", u, now, lastBtn[u], st.btn);
					lastBtn[u] = st.btn;
				}
			}
	}
	{
		// v1.0.17: proof of life every 5 s, so a log that ends early can be told apart from a thread that stopped
		static DWORD lastAlive = 0;
		if (now - lastAlive >= 5000)
		{
			lastAlive = now;
			FH2_Log("v1.0.17 ALIVE: tick=%u msgCalls=%u idZero=%u lobbyChanges=%u", now, g_FH2MsgAll, g_FH2MsgN, g_FH2LobbyN);
		}
	}
	{
		static DWORD msgLogged = 0;
		DWORD mn = g_FH2MsgN;
		if (mn != msgLogged) XNotify(L"FH2: OK/cancel message");
		while (msgLogged != mn)
		{
			DWORD* e = g_FH2MsgRing[msgLogged & 15];
			FH2_Log("v1.0.13 UI MESSAGE id=0: tick=%u screen=%08X r5=%08X data=%08X caller=%08X words: %08X %08X %08X %08X %08X %08X %08X (all calls so far %u)",
				e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7], e[8], e[9], e[10], e[11], g_FH2MsgAll);
			FH2_Log("v1.0.20 UI MESSAGE dialog vtable=%08X/%08X", e[24], e[25]);
			FH2_Log("v1.0.13 UI MESSAGE stack: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
				e[12], e[13], e[14], e[15], e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23]);
			++msgLogged;
			if (mn - msgLogged > 16) msgLogged = mn - 16;
		}
	}
	{
		static DWORD scrLogged = 0;
		DWORD sn = g_FH2ScrN;
		if (sn - scrLogged > 64) scrLogged = sn - 64;
		while (scrLogged != sn)
		{
			DWORD* e = g_FH2ScrRing[scrLogged & 63];
			FH2_Log("v1.0.20 SCREEN: tick=%u obj=%08X lr=%08X chain: %08X %08X %08X %08X %08X %08X %08X %08X",
				e[0], e[1], e[2], e[4], e[5], e[6], e[7], e[8], e[9], e[10], e[11]);
			if (e[2] == 0x828109F0) { g_SnapObj = e[1]; g_SnapT0 = GetTickCount(); g_SnapStage = 0; }
			if (e[2] == 0x827F58FC) { g_SnapObj2 = e[1]; g_SnapT2 = GetTickCount(); g_SnapStage2 = 0; }
			++scrLogged;
		}
	}
	{
		static DWORD dlgLogged = 0;
		DWORD dn = g_FH2DlgN;
		if (dn - dlgLogged > 16) dlgLogged = dn - 16;
		while (dlgLogged != dn)
		{
			DWORD* e = g_FH2DlgRing[dlgLogged & 15];
			FH2_Log("v1.0.18 DIALOG: tick=%u type=%d id=0x%X a6=%08X a7=%08X a8=%08X lr=%08X chain: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
				e[0], (int)e[1], e[2], e[3], e[4], e[5], e[6], e[7], e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15], e[16], e[17], e[18], e[19]);
			if (e[2] == 0x4E) g_SnapDlg = e[3];
			// v1.0.45: the rest of the call chain (entries 14..56), 14 per line, for the speed trap 'feature unavailable' investigation
			for (int b = 20; b < 50; b += 14)
			{
				if (!e[b]) break;
				FH2_Log("v1.0.45 DIALOG id=0x%X tick=%u chain+%d: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
					e[2], e[0], b - 7, e[b], e[b+1], e[b+2], e[b+3], e[b+4], e[b+5], e[b+6], e[b+7], e[b+8], e[b+9], e[b+10], e[b+11], e[b+12], e[b+13]);
			}
			++dlgLogged;
		}
	}
	{
		// v1.0.31: snapshots 0.4 s / 1.5 s / 6 s / 30 s after the loading screen appears (and 0.3 s after the in-event screen)
		static const DWORD at[4] = { 400, 1500, 6000, 30000 };
		DWORD nowS = GetTickCount();
		if (g_SnapObj && g_SnapStage < 4 && (DWORD)(nowS - g_SnapT0) >= at[g_SnapStage])
		{
			CHAR tag[48]; sprintf_s(tag, sizeof(tag), "LOAD+%ums", (unsigned)at[g_SnapStage]);
			FH2_SnapObj(tag, g_SnapObj, 0x5A0 / 4);
			if (g_SnapDlg) { sprintf_s(tag, sizeof(tag), "DLG4E+%ums", (unsigned)at[g_SnapStage]); FH2_SnapObj(tag, g_SnapDlg, 48); }
			++g_SnapStage;
		}
		if (g_SnapObj2 && g_SnapStage2 < 1 && (DWORD)(nowS - g_SnapT2) >= 300)
		{
			FH2_SnapObj("EVENT+300ms", g_SnapObj2, 0x3B8 / 4);
			++g_SnapStage2;
		}
	}
	{
		static DWORD lobbyLogged = 0;
		DWORD ln = g_FH2LobbyN;
		while (lobbyLogged != ln)
		{
			DWORD* e = g_FH2LobbyRing[lobbyLogged & 31];
			FH2_Log("v1.0.12 LOBBY STATE: tick=%u obj=%08X %d -> %d caller=%08X up=%08X %08X %08X", e[0], e[1], (int)e[2], (int)e[3], e[4], e[5], e[6], e[7]);
			++lobbyLogged;
			if (ln - lobbyLogged > 32) lobbyLogged = ln - 32;
		}
	}
	{
		static DWORD popupLogged = 0;
		DWORD pn = g_FH2PopupN;
		while (popupLogged != pn)
		{
			DWORD* e = g_FH2PopupRing[popupLogged & 15];
			FH2_Log("v1.0.6 POPUP: tick=%u index=%d type=%d caller=%08X", e[0], (int)e[1], (int)e[2], e[3]);
			++popupLogged;
			if (pn - popupLogged > 16) popupLogged = pn - 16;
		}
	}
}

// v1.0.33: guest log.  Until g_FH2GuestMs after a title start nothing is logged and none of the log-only hooks are installed, so a joiner's
// invite-join relaunch runs exactly like a plain 'skipfiles legacy' console.  Then, from the poll thread, logging is switched on and the
// hooks that 'log' would have installed at the title start are installed now (import-table patches are single-word writes; the five code
// hooks overwrite the first four instructions of rarely-called functions).
static VOID FH2_GuestLogStart(DWORD now)
{
    extern int g_FH2Stage;
    extern BOOL g_FH2NoDiag;
    PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
    FH2_GuestNetResync();
    g_FH2LogEnabled = TRUE;
    FH2_Log("v1.0.33 GUEST LOG started %u ms after the title start (tick=%u). Everything before this point was not logged.", (unsigned)(now - g_FH2_V095_Epoch), now);
    FH2_Log("v1.0.40 GAME BUILD: TimeDateStamp=0x%08X (the build the plugin was written for is 0x542E797E)", mod ? (unsigned)mod->TimeDateStamp : 0u);
    if (g_FH2Stage >= 3 && mod && mod->TimeDateStamp == 0x542E797E) SetupFH2V095TraceHooks();
    if (g_FH2Stage >= 3) SetupFH2PeerTraceHooks();
    if (!g_FH2NoDiag) { FH2_InstallPopupHook(); FH2_InstallLobbyHook(); FH2_InstallMsgHook(); FH2_InstallDlgHook(); FH2_InstallScrHook(); }
    FH2_Log("v1.0.33 GUEST LOG: hooks installed (stage=%d nodiag=%d).", g_FH2Stage, g_FH2NoDiag ? 1 : 0);
}

static VOID FH2_V095_PollWorker()
{
    FH2V095Ctx ctx;
    BOOL wasActive = FALSE;
    memset(&ctx, 0, sizeof(ctx));

    while (bRunContinuous)
    {
        DWORD now = GetTickCount();
        DWORD title = XamGetCurrentTitleId();
        if (title == ForzaHorizon2)
            g_FH2_V095_LastFh2Tick = now;
        FH2_V0920_Heartbeat(now, title);
        FH2_LogFlush();   // v1.0.19

        // v1.0.33: guest log
        if (g_FH2GuestLog && g_FH2GuestArmed && title == ForzaHorizon2 && g_FH2_V095_Epoch != 0 && (DWORD)(now - g_FH2_V095_Epoch) >= g_FH2GuestMs)
        {
            g_FH2GuestArmed = FALSE;
            __try { FH2_GuestLogStart(now); } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }

        // Active while FH2 is running and for 25 s after it last was, so the relaunch gap is covered.
        BOOL active = g_FH2LogEnabled && g_FH2_V095_LastFh2Tick != 0 && (now - g_FH2_V095_LastFh2Tick) < 25000;
        if (active && !wasActive)
        {
            if (g_FH2_V095_Epoch == 0) g_FH2_V095_Epoch = now;
            ctx.haveLast = FALSE;
            ctx.haveSign = FALSE;
            FH2_V095_SAY("v0.9.5 POLL: armed (20 ms) title=0x%08X tick=%u", title, now);
        }
        wasActive = active;

        if (active)
        {
            __try { FH2_V105_StateSample(now); } __except (EXCEPTION_EXECUTE_HANDLER) { }
            __try { FH2_V095_PollOnce(&ctx, now); }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                static volatile LONG faults = 0;
                LONG n = InterlockedIncrement(&faults);
                if (n <= 10) FH2_Log("v0.9.5 POLL: caught fault in PollOnce (#%d)", n);
            }
        }
        Sleep(20);
    }
    FH2_LogFlush();
    g_FH2_V095_PollDone = 1;
}

// v1.0.2: after writing instructions into the game image, push them out of the data cache and invalidate the instruction cache.
static VOID FH2_FlushCode(VOID* p, DWORD bytes)
{
	BYTE* b = (BYTE*)p;
	for (DWORD o = 0; o < bytes; o += 4) __dcbst(0, (VOID*)(b + o));
	__sync();
	typedef VOID (NTAPI *pFH2_Sweep)(PVOID, DWORD);
	pFH2_Sweep sweep = (pFH2_Sweep)ResolveFunction("xboxkrnl.exe", 171);   // KeSweepIcacheRange, same as the crashlog hooks
	if (sweep) sweep((PVOID)b, bytes);
	__sync();
	__isync();
}

// Called every time the FH2 title is detected (first launch and every relaunch).
static VOID FH2_V095_OnTitleDetected()
{
    DWORD now = GetTickCount();
    g_FH2_V095_LastFh2Tick = now;
    g_FH2_V095_Epoch = now;
    if (g_FH2GuestLog) { g_FH2LogEnabled = FALSE; g_FH2GuestArmed = TRUE; }   // v1.0.33: every title start begins with logging off
    { extern BOOL g_FH2LateLog; if (g_FH2LateLog) InterlockedExchange(&g_FH2LogHold, 1); }   // v1.0.28: no file I/O from the first moment of the title start
    InterlockedExchange(&g_FH2_V095_Lines, 0);
    FH2_V095_ResetTraceCounters();
    FH2_WaitDiagReset();   // v1.0.41
    if (InterlockedCompareExchange(&g_FH2_V095_PollStarted, 1, 0) == 0)
        ThreadMe((LPTHREAD_START_ROUTINE)FH2_V095_PollWorker);
}

VOID Initialise()
{
	hXam = GetModuleHandle(MODULE_XAM);

	if (MountPath(MOUNT_POINT, GetMountPath()) != 0)
	{
		Sunrise_Dbg("Failed to set mount point!");
		return;
	}

	while (bRunContinuous)
	{

		DWORD TitleID = XamGetCurrentTitleId();

		if (TitleID != LastTitleId)
		{
			LastTitleId = TitleID; // Set the last title id  to the current title id so we don't loop rechecking

			if (TitleID == ForzaHorizon2)
			{
				PLDR_DATA_TABLE_ENTRY PLDR_FH2xex = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
				Sunrise_Dbg("Forza Horizon 2 detected! TimeDateStamp: 0x%X", PLDR_FH2xex->TimeDateStamp);

				extern int g_FH2Stage;
				extern BOOL g_FH2SkipFiles, g_FH2SkipPopup, g_FH2SkipAvail, g_FH2NoTimeoutPatch, g_FH2NoDiag;
				FH2_EarlyLogFlag();
				FH2_Log("FH2 detected. TitleID=0x%08X TimeDateStamp=0x%08X",
					TitleID, PLDR_FH2xex->TimeDateStamp);

					if (g_FH2Stage >= 1) FH2_V095_OnTitleDetected();
					// v0.9.6: install the v0.9.5 traces FIRST (before the slower patches below) so the game's early startup calls
					// (notification listeners, sign-in, storage checks) are seen as soon as possible after a relaunch.
					if (g_FH2Stage >= 3 && g_FH2LogEnabled && PLDR_FH2xex->TimeDateStamp == 0x542E797E) SetupFH2V095TraceHooks();

				// ProjectRoadTrip's modified default.xex differs from the clean retail
				// image by only 28 bytes: it renames the protected-file table entries
				// for gamemodes.zip and zipmanifest.xml.  TU09 keeps those table
				// strings at the same virtual addresses, so reproduce that exact
				// behavior in memory rather than replacing the user's default.xex.
				if (g_FH2Stage == 0)
				{
					FH2_Log("v1.0.1 stage0: nothing installed (diagnostic).");
					XNotify(L"FH2Revival v1.0.9 stage 0");
				}
				else if (PLDR_FH2xex->TimeDateStamp == 0x542E797E)
				{
					CHAR* pGameModes = (CHAR*)0x83662D39;
					CHAR* pZipManifest = (CHAR*)0x8366D623;

					const CHAR GameModesOriginal[] = "gamemodes.zip";
					const CHAR GameModesPatched[] = "abcdefghijklm";
					const CHAR ZipManifestOriginal[] = "zipmanifest.xml";
					const CHAR ZipManifestPatched[] = "opqrstuvwxyzlhn";

					BOOL bGameModesOK = FALSE;
					BOOL bZipManifestOK = FALSE;

					if (g_FH2SkipFiles)
					{
						bGameModesOK = TRUE; bZipManifestOK = TRUE;
						FH2_Log("v1.0.2 skipfiles: protected-file renames NOT applied.");
					}
					else {
					if (memcmp(pGameModes, GameModesOriginal, sizeof(GameModesOriginal)) == 0)
					{
						memcpy(pGameModes, GameModesPatched, sizeof(GameModesPatched));
						bGameModesOK = TRUE;
						FH2_Log("Protected-file table patch: gamemodes.zip renamed at 0x83662D39.");
					}
					else if (memcmp(pGameModes, GameModesPatched, sizeof(GameModesPatched)) == 0)
					{
						bGameModesOK = TRUE;
						FH2_Log("Protected-file table patch: gamemodes.zip entry was already patched.");
					}
					else
					{
						FH2_Log("Protected-file table patch FAILED at 0x83662D39 (unexpected bytes).");
					}

					if (memcmp(pZipManifest, ZipManifestOriginal, sizeof(ZipManifestOriginal)) == 0)
					{
						memcpy(pZipManifest, ZipManifestPatched, sizeof(ZipManifestPatched));
						bZipManifestOK = TRUE;
						FH2_Log("Protected-file table patch: zipmanifest.xml renamed at 0x8366D623.");
					}
					else if (memcmp(pZipManifest, ZipManifestPatched, sizeof(ZipManifestPatched)) == 0)
					{
						bZipManifestOK = TRUE;
						FH2_Log("Protected-file table patch: zipmanifest.xml entry was already patched.");
					}
					else
					{
						FH2_Log("Protected-file table patch FAILED at 0x8366D623 (unexpected bytes).");
					}

					}
					if (bGameModesOK && bZipManifestOK)
					{
						// TU09 native Turn 10 server-down popup path.
						// 0x8284AD60 is the routine that loads IDS_Turn10ServersDown.
						// At 0x82845194 the retail instruction is:
						//     0x40820054   bne +0x54
						// When the condition is false, execution falls through into the
						// popup-building code (which loads the localized server-down text).
						// For this diagnostic build, make that branch unconditional:
						//     0x48000054   b +0x54
						// This deliberately suppresses the native server-unavailable popup
						// without changing the network stack yet.
						DWORD* pServerDownBranch = (DWORD*)0x82845194;
						const DWORD ServerDownOriginal = 0x40820054;
						const DWORD ServerDownPatched = 0x48000054;

						BOOL bServerPopupPatchOK = FALSE;
						if (g_FH2SkipPopup)
						{
							bServerPopupPatchOK = TRUE;
							FH2_Log("v1.0.2 skippopup: server-down branch NOT patched.");
						}
						else if (*pServerDownBranch == ServerDownOriginal)
						{
							*pServerDownBranch = ServerDownPatched;
							FH2_FlushCode(pServerDownBranch, 4);
							bServerPopupPatchOK = TRUE;
							FH2_Log("Native server-down popup branch patched at 0x82845194: 0x%08X -> 0x%08X.", ServerDownOriginal, ServerDownPatched);
						}
						else if (*pServerDownBranch == ServerDownPatched)
						{
							bServerPopupPatchOK = TRUE;
							FH2_Log("Native server-down popup branch was already patched at 0x82845194.");
						}
						else
						{
							FH2_Log("Native server-down popup patch FAILED at 0x82845194. Found 0x%08X, expected 0x%08X.", *pServerDownBranch, ServerDownOriginal);
						}

						if (bServerPopupPatchOK)
						{
							// v0.5.3 - Road Trip focused build.
							// Keep only the two bypasses already proven useful: the initial internal
							// availability getter and the first native server-down branch.  v0.5.2's
							// forced +0x281 branch is intentionally NOT applied because hardware testing
							// showed it causes an immediate Road Trip failure before playlist selection.
							DWORD* pAvail = (DWORD*)0x823F2870;
							const DWORD Avail0 = 0x81632334;
							const DWORD Avail1 = 0x2F0B0002;
							const DWORD ReturnTrue0 = 0x38600001; // li r3,1
							const DWORD ReturnTrue1 = 0x4E800020; // blr

							BOOL bAvailOK = FALSE;
							if (g_FH2SkipAvail)
							{
								bAvailOK = TRUE;
								FH2_Log("v1.0.2 skipavail: availability getter NOT patched.");
							}
							else if (pAvail[0] == Avail0 && pAvail[1] == Avail1)
							{
								pAvail[0] = ReturnTrue0;
								pAvail[1] = ReturnTrue1;
								FH2_FlushCode(pAvail, 8);
								bAvailOK = TRUE;
								FH2_Log("v0.8.3 availability bypass installed at 0x823F2870: return TRUE.");
							}
							else if (pAvail[0] == ReturnTrue0 && pAvail[1] == ReturnTrue1)
							{
								bAvailOK = TRUE;
								FH2_Log("v0.8.3 availability bypass already present at 0x823F2870.");
							}
							else
							{
								FH2_Log("v0.8.3 availability bypass FAILED at 0x823F2870. Found %08X %08X.", pAvail[0], pAvail[1]);
							}
                            // v1.0.4: the game gives up on an online session operation 40 s after it starts (cmplwi r11,0x9C40 at three
                            // places: 0x829EDFDC, 0x82A04CAC, 0x82A04D48).  Xbox Live now needs 20-60 s to create sessions, which is
                            // enough for Road Trip lobbies but not for the free roam invite.  Raise the limit to 65 s.
                            if (!g_FH2NoTimeoutPatch)
                            {
                                static const DWORD tmSites[3] = { 0x829EDFDC, 0x82A04CAC, 0x82A04D48 };
                                for (int ti = 0; ti < 3; ++ti)
                                {
                                    DWORD* pt = (DWORD*)tmSites[ti];
                                    if (pt[0] == 0x2B0B9C40)
                                    {
                                        pt[0] = 0x2B0BFFFF;
                                        FH2_FlushCode(pt, 4);
                                        FH2_Log("v1.0.4 session timeout 40s -> 65s patched at 0x%08X.", tmSites[ti]);
                                    }
                                    else if (pt[0] == 0x2B0BFFFF)
                                        FH2_Log("v1.0.4 session timeout already patched at 0x%08X.", tmSites[ti]);
                                    else
                                        FH2_Log("v1.0.4 session timeout patch SKIPPED at 0x%08X (found %08X).", tmSites[ti], pt[0]);
                                }
                            }
                            if (g_FH2LogEnabled && !g_FH2NoDiag) { FH2_InstallPopupHook(); FH2_InstallLobbyHook(); FH2_InstallMsgHook(); FH2_InstallDlgHook(); FH2_InstallScrHook(); }
                            else if (g_FH2LogEnabled) FH2_Log("v1.0.22 nodiag: popup/lobby/message/dialog/screen observation hooks NOT installed.");
                            // v1.0.9: the session manager also has a 60 s limit on the whole create sequence (timestamp at +0x144, checked at
                            // 0x82BEF574; blt at 0x82BEF578 skips the timeout).  Free roam needs 21 s + 42 s = 64 s with Live as slow as it is now,
                            // and the log shows the game aborting exactly 60 s after the first create.  Make the branch unconditional (never time out).
                            if (!g_FH2NoTimeoutPatch)
                            {
                                DWORD* pt = (DWORD*)0x82BEF578;
                                if (pt[0] == 0x41980018)
                                {
                                    pt[0] = 0x48000018;
                                    FH2_FlushCode(pt, 4);
                                    FH2_Log("v1.0.9 session sequence 60 s limit removed at 0x82BEF578.");
                                }
                                else if (pt[0] == 0x48000018)
                                    FH2_Log("v1.0.9 session sequence limit already removed at 0x82BEF578.");
                                else
                                    FH2_Log("v1.0.9 session sequence limit patch SKIPPED at 0x82BEF578 (found %08X).", pt[0]);
                            }
                            // v1.0.19: the error in the free roam invite appears about 30 s after the 0x2D create is sent (v1.0.18 run: create
                            // sent 01:17:27, OK pressed 01:18:29 about 30 s after the error), while Live needs 41 s for that create.  The game
                            // keeps a list of pending entries (+0x14 = start time, +0xA = long-operation flag) and gives up on one at start +
                            // 30000 ms (start + 10000 ms when the flag is clear), then reports an error.  Six places compute that deadline:
                            // addi rX,rY,0x7530 (4 x 0x396B7530, 1 x 0x3BAB7530) and li r3,0x7530.  Replace each by addis/lis 1 = +65536 ms.
                            if (!g_FH2NoTimeoutPatch)
                            {
                                static const struct { DWORD addr; DWORD from; DWORD to; } t30[6] = {
                                    { 0x829F80DC, 0x396B7530, 0x3D6B0001 },   // addis r11,r11,1
                                    { 0x829F9D18, 0x396B7530, 0x3D6B0001 },
                                    { 0x829F9E08, 0x396B7530, 0x3D6B0001 },
                                    { 0x82A075E8, 0x396B7530, 0x3D6B0001 },
                                    { 0x82A07A00, 0x3BAB7530, 0x3FAB0001 },   // addis r29,r11,1
                                    { 0x829F9D50, 0x38607530, 0x3C600001 },   // lis r3,1
                                };
                                for (int ti = 0; ti < 6; ++ti)
                                {
                                    DWORD* pt = (DWORD*)t30[ti].addr;
                                    if (pt[0] == t30[ti].from)
                                    {
                                        pt[0] = t30[ti].to;
                                        FH2_FlushCode(pt, 4);
                                        FH2_Log("v1.0.19 pending-entry timeout 30 s -> 65 s patched at 0x%08X.", t30[ti].addr);
                                    }
                                    else if (pt[0] == t30[ti].to)
                                        FH2_Log("v1.0.19 pending-entry timeout already patched at 0x%08X.", t30[ti].addr);
                                    else
                                        FH2_Log("v1.0.19 pending-entry timeout patch SKIPPED at 0x%08X (found %08X).", t30[ti].addr, pt[0]);
                                }
                            }
                            // v1.0.21: FOUND.  The "Creating session" dialog is a screen object whose per-frame update (0x8283BBF8) compares the time since it
                            // was shown (tick stored at +0x190) with a hard-coded 40000.0 ms (float at 0x82011268, read only by the check 0x82790650).  Past that
                            // it switches itself to the error state (+0x18C = 3) and builds the NO NETWORK ACCESS content.  v1.0.20 log: dialog created at tick
                            // 108949, error content built at tick 149014 = 40.07 s later, i.e. 2 s BEFORE Live finishes the 0x2D create (42 s).  The constant is
                            // shared with other code, so change the check instead: use the 100000.0 float at 0x82000B94 (lis r11,-0x7e00 / lfs f0,0xB94(r11)).
                            if (!g_FH2NoTimeoutPatch)
                            {
                                DWORD* pt = (DWORD*)0x82790650;
                                if (pt[0] == 0x3D608201 && pt[1] == 0x38600000 && pt[2] == 0xC00B1268)
                                {
                                    pt[0] = 0x3D608200;
                                    pt[2] = 0xC00B0B94;
                                    FH2_FlushCode(pt, 12);
                                    FH2_Log("v1.0.21 Creating-session dialog timeout 40 s -> 100 s patched at 0x82790650 (limit float now %f).", *(volatile float*)0x82000B94);
                                }
                                else if (pt[0] == 0x3D608200 && pt[2] == 0xC00B0B94)
                                    FH2_Log("v1.0.21 dialog timeout already patched at 0x82790650.");
                                else
                                    FH2_Log("v1.0.21 dialog timeout patch SKIPPED at 0x82790650 (found %08X %08X %08X).", pt[0], pt[1], pt[2]);
                            }
                            // v1.0.47: Festival tile picture (default on; FH2Synth.txt word nofestpic switches it off).
                            {
                                extern BOOL g_FH2NoFestPic;
                                if (!g_FH2NoFestPic) FH2_FestPicPatch();
                            }
                            BOOL bProvenanceOK = FALSE;
                            BOOL bRoadTripTapOK = FALSE;
                            if (bAvailOK && g_FH2Stage >= 2)
                                bProvenanceOK = SetupFH2ProvenanceTraceHooks();
                            if (bAvailOK && g_FH2Stage >= 3)
                            {
                                BOOL bProbeOK = SetupFH2XamProbeHooks();
                                FH2_Log("v0.8.4 XAM probe installed=%d", bProbeOK);
                                if (g_FH2LogEnabled) SetupFH2PeerTraceHooks();
                                bRoadTripTapOK = FH2_SetupRoadTripProvenanceProfiler(PLDR_FH2xex);
                            }

                            FH2_Log("v0.8.3 NETWORK PROVENANCE installed: avail=%d provenance=%d tap=%d.",
                                bAvailOK, bProvenanceOK, bRoadTripTapOK);
                            if (g_FH2Stage >= 3) XNotify(L"FH2Revival v1.0.48!");
                            else if (g_FH2Stage == 2) XNotify(L"FH2Revival v1.0.9 stage 2");
                            else XNotify(L"FH2Revival v1.0.9 stage 1");
						}

						else
						{
							FH2_Log("v0.3.3 protected-file bypass installed, but native server-down popup patch failed; diagnostics not installed.");
							XNotify(L"FH2Revival Patch Failed!");
						}
					}
					else
					{
						FH2_Log("v0.2 protected-file bypass NOT installed completely; leaving networking untouched.");
						XNotify(L"FH2Revival Patch Failed!");
					}
				}
				else
				{
					FH2_Log("Unsupported FH2 XEX timestamp for v0.2 patch: 0x%08X", PLDR_FH2xex->TimeDateStamp);
					XNotify(L"FH2Revival Unsupported XEX!");
				}
			}
		}
		if (TitleID == ForzaHorizon2)
		{
			// v0.9.8: the loop now runs every 50 ms so a (re)launched FH2 is detected sooner; the worker keeps its 500 ms cadence.
			static DWORD s_lastWorkerTick = 0;
			FH2_XgiPollSafe();
			DWORD nowTick = GetTickCount();
			if (nowTick - s_lastWorkerTick >= 500)
			{
				s_lastWorkerTick = nowTick;
				FH2_WorkerTickSafe();
			}
		}

		Sleep(50); // v0.9.8: was 500
	}
	bLoopHasComplete = TRUE;
}


BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (IsTrayOpen())
		{
			Sunrise_Dbg("Plugin load aborted! Disc tray is open");
			HANDLE hSunrise = hModule;
			bLoopHasComplete = TRUE; // Make sure we set this so we don't get stuck in a sleep loop when we unload (DLL_PROCESS_DETACH) in a sec.
			*(WORD*)((DWORD)hSunrise + 64) = 1;
			return FALSE;
		}

		bIsDevkit = *(DWORD*)0x8E038610 & 0x8000 ? FALSE : TRUE; // Simple devkit check
		Sunrise_Dbg("v%s loaded! Running on %s kernel", SunriseVers, bIsDevkit ? "Devkit" : "Retail");
		ThreadMe((LPTHREAD_START_ROUTINE)Initialise);

		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		bRunContinuous = FALSE; // Exit the continuous loop
		while (!bLoopHasComplete) // Wait for loop to complete
			Sleep(100);
		if (g_FH2_V095_PollStarted)
		{
			while (!g_FH2_V095_PollDone) // v0.9.5: wait for the poll worker too
				Sleep(50);
		}

		Sleep(500);
		Sunrise_Dbg("Unloaded!");
		break;

	}
	return TRUE;
}
