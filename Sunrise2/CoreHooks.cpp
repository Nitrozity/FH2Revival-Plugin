#include "stdafx.h"
#include <ppcintrinsics.h>
#include "Sunrise2.h"
#include "Utilities.h"


// v0.8.5: address handed to FH2 as the synthetic title server (network byte order
// as a big-endian DWORD): 192.168.137.1 = the PC the console is cabled to.
DWORD g_FH2SynthIp = 0xC0A88901;
volatile DWORD g_FH2HttpTick = 0;   // v1.0.46: tick of the FIRST connect to the title server (used to time the player card push)
BOOL g_FH2NoCard = FALSE;           // v1.0.46: FH2Synth.txt word "nocard" = do not push the player card (level/badge/title) to the server
BOOL g_FH2NoFestPic = FALSE;         // v1.0.47: FH2Synth.txt word "nofestpic" = leave the black Festival tile picture alone
CHAR g_FH2FestPic[40] = "NiceMassena";   // v1.0.47: picture used for the Festival tile (word "festpic=Name" overrides; must exist in the game's DestinationImages folders)
DWORD g_FH2RealIp = 0;   // v0.8.20: if nonzero, connect() to g_FH2SynthIp is redirected to this real address
static VOID FH2_SynthEvt(DWORD code, DWORD a, DWORD b, DWORD c, DWORD d);

// v0.9.13: peer (UDP) traffic recorder.  Hooks only update these counters (no file I/O on game threads: FH2_Log calls made
// there are lost); the worker thread logs them through FH2_P2PFlush().  Addresses are big-endian DWORDs (a.b.c.d = 0xAABBCCDD).
struct FH2_P2P_DST
{
    volatile DWORD ip; volatile DWORD port; volatile LONG count; volatile LONG bytes;
    DWORD firstTick; DWORD lastTick; volatile LONG lastRes; volatile LONG lastErr; volatile LONG dirty; DWORD lastLogTick;
};
#define FH2_P2P_MAX 16
static FH2_P2P_DST g_FH2P2PSend[FH2_P2P_MAX];
static FH2_P2P_DST g_FH2P2PRecv[FH2_P2P_MAX];
static volatile LONG g_FH2P2PSendN = 0;
static volatile LONG g_FH2P2PRecvN = 0;
static volatile LONG g_FH2P2PRecvCalls = 0, g_FH2P2PRecvOk = 0, g_FH2P2PRecvPending = 0, g_FH2P2PRecvWouldBlock = 0, g_FH2P2PRecvOther = 0, g_FH2P2PRecvLastErr = 0;
static LONG g_FH2P2PRecvLogged = -1;

static VOID FH2_P2PNote(FH2_P2P_DST* tab, volatile LONG* n, const VOID* sa, int len, int res, int err)
{
    if (!sa || !MmIsAddressValid((PVOID)sa) || !MmIsAddressValid((PVOID)((const BYTE*)sa + 7))) return;
    const SOCKADDR_IN* in = (const SOCKADDR_IN*)sa;
    DWORD ip = (DWORD)in->sin_addr.S_un.S_addr;
    DWORD port = (DWORD)in->sin_port;
    LONG cnt = *n; if (cnt > FH2_P2P_MAX) cnt = FH2_P2P_MAX;
    int i = 0;
    for (; i < cnt; ++i) if (tab[i].ip == ip && tab[i].port == port) break;
    if (i == cnt)
    {
        if (cnt >= FH2_P2P_MAX) return;
        LONG k = InterlockedIncrement(n) - 1;
        if (k >= FH2_P2P_MAX) return;
        tab[k].ip = ip; tab[k].port = port; tab[k].firstTick = GetTickCount();
        i = (int)k;
    }
    InterlockedIncrement(&tab[i].count);
    InterlockedExchangeAdd(&tab[i].bytes, len > 0 ? len : 0);
    tab[i].lastTick = GetTickCount();
    tab[i].lastRes = res; tab[i].lastErr = err;
    tab[i].dirty = 1;
}

// receive-call outcome counters (all UDP/TCP recvfrom-style calls the title makes)
static VOID FH2_P2PRecvOutcome(int res, int err, BOOL isWsa)
{
    InterlockedIncrement(&g_FH2P2PRecvCalls);
    if (isWsa) { if (res == 0) InterlockedIncrement(&g_FH2P2PRecvOk); else if (err == 997) InterlockedIncrement(&g_FH2P2PRecvPending); else if (err == 10035) InterlockedIncrement(&g_FH2P2PRecvWouldBlock); else { InterlockedIncrement(&g_FH2P2PRecvOther); g_FH2P2PRecvLastErr = err; } }
    else { if (res > 0) InterlockedIncrement(&g_FH2P2PRecvOk); else if (err == 10035) InterlockedIncrement(&g_FH2P2PRecvWouldBlock); else { InterlockedIncrement(&g_FH2P2PRecvOther); g_FH2P2PRecvLastErr = err; } }
}

// v0.9.14: overlapped (pending) receives.  WSARecvFrom returns "pending" and the data arrives later in the OVERLAPPED, which the
// v0.9.13 counters never saw.  Track up to 16 posted overlapped receives; a receive is "done" when the first two DWORDs of the
// OVERLAPPED (Internal/InternalHigh = status/bytes) differ from what they were just after posting.  Checked when the same
// OVERLAPPED is posted again (before the real call) and by the worker every flush.  Hooks only touch memory, never files.
#define FH2_BIGBYTES 192   // v1.0.30: bytes kept per captured peer message (was 96)
struct FH2_RXOV { volatile DWORD ovl; DWORD from; DWORD init0; DWORD init1; DWORD tick; volatile LONG active; DWORD buf; DWORD buflen; };
#define FH2_RXOV_MAX 16
static FH2_RXOV g_FH2RxOv[FH2_RXOV_MAX];
static volatile LONG g_FH2RxOvNext = 0;
struct FH2_RXDONE { DWORD tick, age, ovl, low, high, ip, port; BYTE data[16]; DWORD dlen; };
static volatile LONG g_FH2DumpBudget = 700;   // max packet dumps per run (keeps the file small)
static volatile LONG g_FH2BigMin = 40;        // v1.0.27: smallest datagram kept by the payload capture (netdiag lowers it to 18 so the 18-byte CLOSE messages show up)
static BOOL g_FH2NoSnap = FALSE;              // v1.0.32: FH2Synth.txt word 'nosnap' = no stunt-start object snapshots (A/B test)
static BOOL g_FH2KeepAll = FALSE;             // v1.0.30: FH2Synth.txt word 'keepall' = capture every 101-byte frame too (old behaviour)
static BOOL g_FH2NetDiag = FALSE;             // v1.0.27: FH2Synth.txt word 'netdiag' = refill the payload budget every second + log peers that go silent
#define FH2_RXDONE_MAX 32
static FH2_RXDONE g_FH2RxDone[FH2_RXDONE_MAX];
static volatile LONG g_FH2RxDoneW = 0;
static LONG g_FH2RxDoneR = 0;
static volatile LONG g_FH2RxOvPosted = 0, g_FH2RxOvDone = 0, g_FH2RxOvExpired = 0;

static VOID FH2_BigPush(DWORD dir, DWORD total, DWORD ip, DWORD port, const BYTE* data, DWORD dlen);
static VOID FH2_RxDonePush(FH2_RXOV& r, DWORD low, DWORD high)
{
    DWORD ip = 0, port = 0;
    if (r.from && MmIsAddressValid((PVOID)r.from) && MmIsAddressValid((PVOID)(r.from + 7)))
    {
        const SOCKADDR_IN* in = (const SOCKADDR_IN*)r.from;
        ip = (DWORD)in->sin_addr.S_un.S_addr; port = (DWORD)in->sin_port;
    }
    LONG k = (InterlockedIncrement(&g_FH2RxDoneW) - 1) % FH2_RXDONE_MAX;
    FH2_RXDONE& d = g_FH2RxDone[k];
    d.tick = GetTickCount(); d.age = d.tick - r.tick; d.ovl = r.ovl; d.low = low; d.high = high; d.ip = ip; d.port = port;
    d.dlen = 0;
    if (r.buf && high > 0 && high < 0x10000)
    {
        DWORD n = high < 16 ? high : 16;
        if (MmIsAddressValid((PVOID)r.buf) && MmIsAddressValid((PVOID)(r.buf + n - 1))) { memcpy(d.data, (const void*)r.buf, n); d.dlen = n; }
        if ((LONG)high >= g_FH2BigMin)
        {
            DWORD m = high < FH2_BIGBYTES ? high : FH2_BIGBYTES;
            if (MmIsAddressValid((PVOID)r.buf) && MmIsAddressValid((PVOID)(r.buf + m - 1)))
                FH2_BigPush(1, high, ip, port, (const BYTE*)r.buf, m);
        }
    }
    InterlockedIncrement(&g_FH2RxOvDone);
    r.active = 0;
}

static VOID FH2_RxOvCheck(FH2_RXOV& r)
{
    if (!r.active) return;
    volatile DWORD* p = (volatile DWORD*)r.ovl;
    if (!p || !MmIsAddressValid((PVOID)p) || !MmIsAddressValid((PVOID)(p + 1))) { r.active = 0; return; }
    DWORD v0 = p[0], v1 = p[1];
    if (v0 == 0 && v1 == 0 && (r.init0 || r.init1)) { r.active = 0; return; }   // game cleared the OVERLAPPED to re-post it: not a completion
    if (v0 != r.init0 || v1 != r.init1) { FH2_RxDonePush(r, v0, v1); return; }
    if ((DWORD)(GetTickCount() - r.tick) > 60000) { InterlockedIncrement(&g_FH2RxOvExpired); r.active = 0; }
}

// call BEFORE the real WSARecvFrom for this OVERLAPPED: if the previous receive on it finished, record it now
static VOID FH2_RxOvBefore(LPOVERLAPPED ov)
{
    if (!ov) return;
    for (int i = 0; i < FH2_RXOV_MAX; ++i)
        if (g_FH2RxOv[i].active && g_FH2RxOv[i].ovl == (DWORD)ov) { FH2_RxOvCheck(g_FH2RxOv[i]); g_FH2RxOv[i].active = 0; }
}

// call AFTER a WSARecvFrom that returned "pending"
static VOID FH2_RxOvAfter(LPOVERLAPPED ov, const VOID* from, DWORD buf, DWORD buflen)
{
    if (!ov || !MmIsAddressValid((PVOID)ov) || !MmIsAddressValid((PVOID)((BYTE*)ov + 7))) return;
    LONG k = (InterlockedIncrement(&g_FH2RxOvNext) - 1) % FH2_RXOV_MAX;
    FH2_RXOV& r = g_FH2RxOv[k];
    r.active = 0;
    r.ovl = (DWORD)ov; r.from = (DWORD)from; r.buf = buf; r.buflen = buflen;
    volatile DWORD* p = (volatile DWORD*)ov;
    r.init0 = p[0]; r.init1 = p[1]; r.tick = GetTickCount();
    r.active = 1;
    InterlockedIncrement(&g_FH2RxOvPosted);
}

// v0.9.17: payload capture of the larger peer messages (lobby state, launch messages).  Hooks only memcpy into this ring;
// the worker (FH2_P2PFlush) writes the lines.  dir 0 = sent, 1 = received.  Total length is the sum over all WSABufs.
struct FH2_BIG { DWORD tick, dir, total, ip, port, dlen; BYTE data[FH2_BIGBYTES]; };
#define FH2_BIG_MAX 48
#define FH2_BIG_MINLEN 40
static FH2_BIG g_FH2Big[FH2_BIG_MAX];
static volatile LONG g_FH2BigW = 0;
static LONG g_FH2BigR = 0;
static volatile LONG g_FH2BigBudget = 220;
static VOID FH2_BigPush(DWORD dir, DWORD total, DWORD ip, DWORD port, const BYTE* data, DWORD dlen)
{
    if (g_FH2BigBudget <= 0 || (LONG)total < g_FH2BigMin) return;
    // v1.0.30: the regular 101-byte in-session frames (about 30/s per peer) used the whole capture budget, so the one-off messages
    // at a stunt start / car switch (522, 432, 424, 81, 40, 48, 70 bytes) came out in pieces.  Keep only one 101-byte frame per
    // second per direction; every other message size is kept in full.
    if (total == 101 && !g_FH2KeepAll)
    {
        static DWORD lastReg[2];
        DWORD nowB = GetTickCount();
        DWORD& lr = lastReg[dir ? 1 : 0];
        if (lr && (DWORD)(nowB - lr) < 1000) return;
        lr = nowB;
    }
    LONG k = (InterlockedIncrement(&g_FH2BigW) - 1) % FH2_BIG_MAX;
    FH2_BIG& b = g_FH2Big[k];
    b.tick = GetTickCount(); b.dir = dir; b.total = total; b.ip = ip; b.port = port;
    b.dlen = dlen > FH2_BIGBYTES ? FH2_BIGBYTES : dlen;
    if (b.dlen) memcpy(b.data, data, b.dlen);
}
// gather the first FH2_BIGBYTES bytes of a WSABUF chain (bounded, validated)
static DWORD FH2_BigGather(LPWSABUF bufs, DWORD count, BYTE* out, DWORD* totalOut)
{
    DWORD have = 0, total = 0;
    if (!bufs || !count || !MmIsAddressValid(bufs)) { *totalOut = 0; return 0; }
    if (count > 4) count = 4;
    for (DWORD i = 0; i < count; ++i)
    {
        if (!MmIsAddressValid(&bufs[i])) break;
        DWORD l = bufs[i].len; const BYTE* b = (const BYTE*)bufs[i].buf;
        total += l;
        if (have < FH2_BIGBYTES && b && l)
        {
            DWORD n = l; if (n > FH2_BIGBYTES - have) n = FH2_BIGBYTES - have;
            if (MmIsAddressValid((PVOID)b) && MmIsAddressValid((PVOID)(b + n - 1))) { memcpy(out + have, b, n); have += n; }
        }
    }
    *totalOut = total;
    return have;
}

struct FH2_TX { DWORD tick, len, ip, port; BYTE data[16]; DWORD dlen; };
#define FH2_TX_MAX 64
static FH2_TX g_FH2Tx[FH2_TX_MAX];
static volatile LONG g_FH2TxW = 0;
static LONG g_FH2TxR = 0;
static VOID FH2_TxNote(const VOID* buf, DWORD len, const VOID* to)
{
    if (g_FH2DumpBudget <= 0) return;
    LONG k = (InterlockedIncrement(&g_FH2TxW) - 1) % FH2_TX_MAX;
    FH2_TX& t = g_FH2Tx[k];
    t.tick = GetTickCount(); t.len = len; t.ip = 0; t.port = 0; t.dlen = 0;
    if (to && MmIsAddressValid((PVOID)to) && MmIsAddressValid((PVOID)((const BYTE*)to + 7)))
    { const SOCKADDR_IN* in = (const SOCKADDR_IN*)to; t.ip = (DWORD)in->sin_addr.S_un.S_addr; t.port = (DWORD)in->sin_port; }
    if (buf && len > 0 && len < 0x10000)
    {
        DWORD n = len < 16 ? len : 16;
        if (MmIsAddressValid((PVOID)buf) && MmIsAddressValid((PVOID)((const BYTE*)buf + n - 1))) { memcpy(t.data, buf, n); t.dlen = n; }
    }
}

// v0.9.20: when the game sends its own connection CLOSE (18-byte control message 0x80 / sub 0x04) keep the code addresses
// found on the sending thread's stack (return addresses only: the word before the address must be a bl / bctrl / blrl),
// one snapshot per 5 s.  The 50 ms main loop logs it (FH2_XgiPoll).  Read-only; nothing is changed.
#define FH2_CLOSE_STK_MAX 40
static volatile LONG g_FH2CloseStkReady = 0;
static DWORD g_FH2CloseStkLastTick = 0, g_FH2CloseStkTick = 0, g_FH2CloseStkIp = 0, g_FH2CloseStkN = 0;
static DWORD g_FH2CloseStkOff[FH2_CLOSE_STK_MAX], g_FH2CloseStkAddr[FH2_CLOSE_STK_MAX];
static VOID FH2_CloseStackNote(const VOID* buf, DWORD len, const VOID* to)
{
    if (len != 18 || !buf || g_FH2CloseStkReady) return;
    if (!MmIsAddressValid((PVOID)buf) || !MmIsAddressValid((PVOID)((const BYTE*)buf + 17))) return;
    const BYTE* b = (const BYTE*)buf;
    if (b[2] != 0x80 || b[3] != 0x04) return;
    DWORD now = GetTickCount();
    if (g_FH2CloseStkLastTick != 0 && (now - g_FH2CloseStkLastTick) < 5000) return;
    g_FH2CloseStkLastTick = now;
    DWORD ip = 0;
    if (to && MmIsAddressValid((PVOID)to) && MmIsAddressValid((PVOID)((const BYTE*)to + 7)))
        ip = (DWORD)((const SOCKADDR_IN*)to)->sin_addr.S_un.S_addr;
    DWORD marker = 0;
    DWORD sp = (DWORD)&marker;
    DWORD n = 0;
    for (DWORD off = 0; off < 0x2000 && n < FH2_CLOSE_STK_MAX; off += 4)
    {
        DWORD a = sp + off;
        if (off == 0 || (a & 0xFFF) == 0) { if (!MmIsAddressValid((PVOID)a)) break; }
        DWORD v = *(volatile DWORD*)a;
        if ((v & 3) || v < 0x82000100 || v >= 0x83400000) continue;
        if (!MmIsAddressValid((PVOID)(v - 4))) continue;
        DWORD prev = *(volatile DWORD*)(v - 4);
        if ((prev & 0xFC000003) != 0x48000001 && prev != 0x4E800421 && prev != 0x4E800021) continue;
        g_FH2CloseStkOff[n] = off; g_FH2CloseStkAddr[n] = v; ++n;
    }
    g_FH2CloseStkTick = now; g_FH2CloseStkIp = ip; g_FH2CloseStkN = n;
    InterlockedExchange(&g_FH2CloseStkReady, 1);
}

// v1.0.34: sender call chain.  The stuck console of a 3-player co-op start sends only the 48-byte message and never its own 522 / 424 / 81 / 40
// (both v1.0.33 logs and the 8:44 log show it).  For these message sizes, once per size per 1.5 s, keep the code addresses found on the sending
// thread's stack (return addresses only: the word before must be a bl / bctrl / blrl) and let the P2P flush log them.  Read-only.
static BOOL g_FH2SendStk = FALSE;   // v1.0.35: FH2Synth.txt word 'sendstk' = capture the sender call chain (off by default: a host console crashed right after v1.0.34 first used it)
#define FH2_SS_MAX     12
#define FH2_SS_FRAMES  26
struct FH2_SS { DWORD tick, total, ip, n; DWORD addr[FH2_SS_FRAMES]; };
static FH2_SS g_FH2Ss[FH2_SS_MAX];
static volatile LONG g_FH2SsW = 0;
static LONG g_FH2SsR = 0;
static DWORD g_FH2SsLast[8] = { 0 };
static VOID FH2_SendStackNote(DWORD total, const VOID* to)
{
    if (!g_FH2SendStk) return;
    static const DWORD sizes[8] = { 48, 522, 424, 81, 40, 95, 120, 70 };
    int slot = -1;
    for (int i = 0; i < 8; ++i) if (sizes[i] == total) { slot = i; break; }
    if (slot < 0) return;
    DWORD now = GetTickCount();
    if (g_FH2SsLast[slot] != 0 && (DWORD)(now - g_FH2SsLast[slot]) < 1500) return;
    g_FH2SsLast[slot] = now;
    DWORD ip = 0;
    if (to && MmIsAddressValid((PVOID)to) && MmIsAddressValid((PVOID)((const BYTE*)to + 7)))
        ip = (DWORD)((const SOCKADDR_IN*)to)->sin_addr.S_un.S_addr;
    LONG k = (InterlockedIncrement(&g_FH2SsW) - 1) % FH2_SS_MAX;
    FH2_SS& e = g_FH2Ss[k];
    e.tick = now; e.total = total; e.ip = ip; e.n = 0;
    DWORD marker = 0;
    DWORD sp = (DWORD)&marker;
    for (DWORD off = 0; off < 0x3000 && e.n < FH2_SS_FRAMES; off += 4)
    {
        DWORD a = sp + off;
        if (off == 0 || (a & 0xFFF) == 0) { if (!MmIsAddressValid((PVOID)a)) break; }
        DWORD v = *(volatile DWORD*)a;
        if ((v & 3) || v < 0x82000100 || v >= 0x83400000) continue;
        if (!MmIsAddressValid((PVOID)(v - 4))) continue;
        DWORD prev = *(volatile DWORD*)(v - 4);
        if ((prev & 0xFC000003) != 0x48000001 && prev != 0x4E800421 && prev != 0x4E800021) continue;
        e.addr[e.n++] = v;
    }
}
static VOID FH2_SendStackFlush()
{
    LONG w = g_FH2SsW;
    if (w - g_FH2SsR > FH2_SS_MAX) g_FH2SsR = w - FH2_SS_MAX;
    while (g_FH2SsR < w)
    {
        FH2_SS e = g_FH2Ss[g_FH2SsR % FH2_SS_MAX];
        ++g_FH2SsR;
        CHAR line[400]; int pos = 0;
        pos += sprintf_s(line, sizeof(line), "v1.0.34 SENDSTK tick=%u total=%u to=%u.%u.%u.%u frames=%u:", e.tick, e.total, (e.ip >> 24) & 255, (e.ip >> 16) & 255, (e.ip >> 8) & 255, e.ip & 255, e.n);
        for (DWORD q = 0; q < e.n && pos < (int)sizeof(line) - 12; ++q)
            pos += sprintf_s(line + pos, sizeof(line) - pos, " %08X", e.addr[q]);
        FH2_Log("%s", line);
    }
}

extern BOOL g_FH2GuestLog;   // v1.0.33 (defined further down)
// v1.0.33: guest mode - while logging is still off the ring buffers are left alone (the drain would spend the payload budget on lines that
// are not written); when the guest log starts the read positions jump to the write positions and the budgets are full again.
VOID FH2_GuestNetResync()
{
    g_FH2TxR = g_FH2TxW;
    g_FH2BigR = g_FH2BigW;
    g_FH2RxDoneR = g_FH2RxDoneW;
    g_FH2DumpBudget = 700;
    g_FH2BigBudget = g_FH2NetDiag ? 300 : 220;
}

VOID FH2_P2PFlush()
{
    if (g_FH2GuestLog && !g_FH2LogEnabled) return;   // v1.0.33
    FH2_SendStackFlush();   // v1.0.34
    {
        LONG w = g_FH2TxW;
        if (w - g_FH2TxR > FH2_TX_MAX) g_FH2TxR = w - FH2_TX_MAX;
        while (g_FH2TxR < w)
        {
            FH2_TX t = g_FH2Tx[g_FH2TxR % FH2_TX_MAX];
            ++g_FH2TxR;
            CHAR hex[40] = { 0 };
            for (DWORD h = 0; h < t.dlen && h < 16; ++h) sprintf_s(hex + h * 2, sizeof(hex) - h * 2, "%02X", t.data[h]);
            if (g_FH2DumpBudget > 0) --g_FH2DumpBudget;
            FH2_Log("v0.9.15 P2P TX: tick=%u len=%u to=%u.%u.%u.%u:%u first=%s", t.tick, t.len,
                (t.ip >> 24) & 255, (t.ip >> 16) & 255, (t.ip >> 8) & 255, t.ip & 255, t.port, hex);
        }
    }
    for (int i = 0; i < FH2_RXOV_MAX; ++i) FH2_RxOvCheck(g_FH2RxOv[i]);
    if (g_FH2NetDiag)
    {
        // v1.0.27: the 220-line payload budget is spent in the first minutes; give back 20 lines per second (cap 40) so the
        // larger peer messages are still captured minutes later, when the car switch happens.
        static DWORD lastRefill = 0;
        DWORD nowR = GetTickCount();
        if ((DWORD)(nowR - lastRefill) >= 1000) { lastRefill = nowR; if (g_FH2BigBudget < 40) g_FH2BigBudget += 20; }
    }
    {
        LONG w = g_FH2BigW;
        if (w - g_FH2BigR > FH2_BIG_MAX) g_FH2BigR = w - FH2_BIG_MAX;
        while (g_FH2BigR < w)
        {
            FH2_BIG b = g_FH2Big[g_FH2BigR % FH2_BIG_MAX];
            ++g_FH2BigR;
            if (g_FH2BigBudget <= 0) continue;
            --g_FH2BigBudget;
            CHAR hex[FH2_BIGBYTES * 2 + 8] = { 0 };
            for (DWORD h = 0; h < b.dlen && h < FH2_BIGBYTES; ++h) sprintf_s(hex + h * 2, sizeof(hex) - h * 2, "%02X", b.data[h]);
            FH2_Log("v0.9.15 P2P PAYLOAD %s: tick=%u total=%u %s=%u.%u.%u.%u:%u first%u=%s", b.dir ? "RX" : "TX", b.tick, b.total,
                b.dir ? "from" : "to", (b.ip >> 24) & 255, (b.ip >> 16) & 255, (b.ip >> 8) & 255, b.ip & 255, b.port, b.dlen, hex);
        }
    }
    {
        LONG w = g_FH2RxDoneW;
        if (w - g_FH2RxDoneR > FH2_RXDONE_MAX) g_FH2RxDoneR = w - FH2_RXDONE_MAX;
        while (g_FH2RxDoneR < w)
        {
            FH2_RXDONE d = g_FH2RxDone[g_FH2RxDoneR % FH2_RXDONE_MAX];
            ++g_FH2RxDoneR;
            if (g_FH2DumpBudget <= 0) continue;
            --g_FH2DumpBudget;
            CHAR hex[40] = { 0 };
            for (DWORD h = 0; h < d.dlen && h < 16; ++h) sprintf_s(hex + h * 2, sizeof(hex) - h * 2, "%02X", d.data[h]);
            FH2_Log("v0.9.15 P2P RX: tick=%u waited=%ums len=%u from=%u.%u.%u.%u:%u first=%s",
                d.tick, d.age, d.high,
                (d.ip >> 24) & 255, (d.ip >> 16) & 255, (d.ip >> 8) & 255, d.ip & 255, d.port, hex);
        }
    }
    DWORD now = GetTickCount();
    for (int t = 0; t < 2; ++t)
    {
        FH2_P2P_DST* tab = t ? g_FH2P2PRecv : g_FH2P2PSend;
        LONG n = t ? g_FH2P2PRecvN : g_FH2P2PSendN; if (n > FH2_P2P_MAX) n = FH2_P2P_MAX;
        for (int i = 0; i < n; ++i)
        {
            FH2_P2P_DST& d = tab[i];
            if (g_FH2NetDiag && t == 1 && d.count > 0 && i < FH2_P2P_MAX)
            {
                // v1.0.27: a peer we receive from that goes quiet for 15 s (and when it comes back)
                static BYTE silent[FH2_P2P_MAX];
                DWORD gap = (DWORD)(now - d.lastTick);
                if (!silent[i] && gap >= 15000)
                {
                    silent[i] = 1;
                    FH2_Log("v1.0.27 NET: RECV SILENT peer=%u.%u.%u.%u:%u gap=%ums count=%d", (d.ip >> 24) & 255, (d.ip >> 16) & 255, (d.ip >> 8) & 255, d.ip & 255, (unsigned)d.port, gap, (int)d.count);
                }
                else if (silent[i] && gap < 3000)
                {
                    silent[i] = 0;
                    FH2_Log("v1.0.27 NET: RECV RESUMED peer=%u.%u.%u.%u:%u count=%d", (d.ip >> 24) & 255, (d.ip >> 16) & 255, (d.ip >> 8) & 255, d.ip & 255, (unsigned)d.port, (int)d.count);
                }
            }
            if (d.dirty && (d.lastLogTick == 0 || (DWORD)(now - d.lastLogTick) >= 1000))
            {
                d.dirty = 0; d.lastLogTick = now;
                FH2_Log("v0.9.15 P2P %s: peer=%u.%u.%u.%u:%u count=%d bytes=%d firstTick=%u lastTick=%u lastResult=%d lastErr=%d",
                    t ? "RECV from" : "SEND to",
                    (d.ip >> 24) & 255, (d.ip >> 16) & 255, (d.ip >> 8) & 255, d.ip & 255, (unsigned)d.port,
                    (int)d.count, (int)d.bytes, d.firstTick, d.lastTick, (int)d.lastRes, (int)d.lastErr);
            }
        }
    }
    LONG calls = g_FH2P2PRecvCalls;
    if (calls != g_FH2P2PRecvLogged && (calls - g_FH2P2PRecvLogged) >= 1)
    {
        static DWORD lastStat = 0;
        if (lastStat == 0 || (DWORD)(now - lastStat) >= 2000)
        {
            lastStat = now; g_FH2P2PRecvLogged = calls;
            FH2_Log("v0.9.15 P2P RECV stats: calls=%d ok=%d pending=%d wouldblock=%d other=%d lastOtherErr=%d ovlPosted=%d ovlDone=%d ovlExpired=%d tick=%u",
                (int)calls, (int)g_FH2P2PRecvOk, (int)g_FH2P2PRecvPending, (int)g_FH2P2PRecvWouldBlock, (int)g_FH2P2PRecvOther, (int)g_FH2P2PRecvLastErr, (int)g_FH2RxOvPosted, (int)g_FH2RxOvDone, (int)g_FH2RxOvExpired, now);
        }
    }
}

// v0.8.13: remember TCP sockets the title creates so select/getsockopt/send/recv/close
// on them can be traced (ring events only; hooks never call FH2_Log for these).
#define FH2_TRACK_MAX 32
static volatile LONG g_FH2TrackSock[FH2_TRACK_MAX];
static volatile LONG g_FH2TrackNext = 0;
static VOID FH2_TrackAdd(int sock)
{
    LONG i = (InterlockedIncrement(&g_FH2TrackNext) - 1) % FH2_TRACK_MAX;
    g_FH2TrackSock[i] = sock + 1;      // +1 so 0 means empty
}
static BOOL FH2_TrackHas(int sock)
{
    for (int i = 0; i < FH2_TRACK_MAX; ++i)
        if (g_FH2TrackSock[i] == sock + 1) return TRUE;
    return FALSE;
}
static VOID FH2_TrackDel(int sock)
{
    for (int i = 0; i < FH2_TRACK_MAX; ++i)
        if (g_FH2TrackSock[i] == sock + 1) g_FH2TrackSock[i] = 0;
}
struct FH2_FDSET { DWORD count; DWORD fds[64]; };
struct FH2_TV { LONG sec; LONG usec; };
typedef int (NTAPI* pFH2_select)(XNCALLER_TYPE, int, FH2_FDSET*, FH2_FDSET*, FH2_FDSET*, const FH2_TV*);
typedef int (NTAPI* pFH2_getsockopt)(XNCALLER_TYPE, SOCKET, int, int, char*, int*);
typedef int (NTAPI* pFH2_closesocket)(XNCALLER_TYPE, SOCKET);
typedef int (NTAPI* pFH2_ioctlsocket)(XNCALLER_TYPE, SOCKET, long, u_long*);
static pFH2_select g_FH2_real_select = NULL;
static pFH2_getsockopt g_FH2_real_getsockopt = NULL;
static pFH2_closesocket g_FH2_real_closesocket = NULL;
static pFH2_ioctlsocket g_FH2_real_ioctlsocket = NULL;
typedef int (NTAPI* pFH2_recv)(XNCALLER_TYPE, SOCKET, char*, int, int);
static pFH2_recv g_FH2_real_recv = NULL;
BOOL g_FH2SkipFiles = TRUE /* v1.0.48 default */, g_FH2SkipPopup = FALSE, g_FH2SkipAvail = FALSE;   // v1.0.2: FH2Synth.txt words skipfiles / skippopup / skipavail
int g_FH2Stage = 99;   // v1.0.1: FH2Synth.txt word stage0..stage3 = install only part of the plugin (crash bisecting); 99 = everything
BOOL g_FH2NoSess = FALSE;      // v0.9.10: FH2Synth.txt word 'nosess' = do not hook XamSessionCreateHandle/RefObjByHandle (790/791)
BOOL g_FH2NoFrStats = FALSE;   // v1.0.7: word 'nofrstats' = do not fail the free-roam stats read
BOOL g_FH2NoKeepOk = FALSE;
extern BOOL g_FH2NoCancel;
extern BOOL g_FH2Pad;    // v1.0.11: word 'nokeepok' = let the real (late) Live result of a plugin-completed modify/end reach the game
BOOL g_FH2NoDiag = FALSE;   // v1.0.22: FH2Synth.txt word 'nodiag' = do not install the log-only observation hooks (popup/lobby/message/dialog/screen)
BOOL g_FH2Legacy = FALSE;   // v1.0.26: FH2Synth.txt word 'legacy' = behave like v1.0.21 (no log hold, B0015 put-back, old E42 handling)
BOOL g_FH2NoHold = FALSE;   // v1.0.23: FH2Synth.txt word 'nohold' = keep writing log files during an invite join
BOOL g_FH2NoWatch = FALSE;  // v1.0.29: FH2Synth.txt word 'nowatch' = no stuck-loading watchdog
BOOL g_FH2LateLog = FALSE;  // v1.0.28: FH2Synth.txt word 'latelog' (or 'latelog180' = seconds) = no log/heartbeat file is opened until that long after every title start
DWORD g_FH2LateMs = 120000; // v1.0.28
BOOL g_FH2LockDiag = FALSE;    // v1.0.43: FH2Synth.txt word 'lockdiag' = critical-section (lock) wait profiler (patches the game's RtlEnterCriticalSection import thunk; opt-in)
BOOL g_FH2WaitDiag = FALSE;    // v1.0.41: FH2Synth.txt word 'waitdiag' = wait-site profiler (patches 4 kernel wait/sleep import thunks of the game; opt-in)
BOOL g_FH2GridDiag = FALSE;    // v1.0.36: FH2Synth.txt word 'griddiag' = log the console flags / game-arbiter / starting-grid state (read-only poll, no code hooks)
BOOL g_FH2GuestLog = FALSE;    // v1.0.33: FH2Synth.txt word 'guest' (or 'guest90' = seconds) = NO logging, NO log-only hooks, until that long after every title start; then everything starts at once
DWORD g_FH2GuestMs = 120000;   // v1.0.33
BOOL g_FH2GuestArmed = FALSE;  // v1.0.33: set at every title start, cleared when the guest log has been started for that instance
BOOL g_FH2NoTimeoutPatch = FALSE;   // v1.0.4: FH2Synth.txt word 'notimeout' = leave the game's 40 s session timeout alone
BOOL g_FH2FrSwap = FALSE; // v1.0.3: free-roam create (flags 0x823, 0 public / N private) is sent as N public / 0 private; word 'nofrswap' disables
BOOL g_FH2Xgi = TRUE; /* v1.0: built-in default */          // v0.9.16: FH2Synth.txt word 'xgi' = with noprobe, still trace the XMsg session calls (500/502/503/508) and title launch/terminate (420-422/425), compact lines
BOOL g_FH2NoProbe = TRUE; /* v1.0: built-in default */     // v0.9.10: FH2Synth.txt word 'noprobe' = do not install the diagnostic XAM probe wrappers (keeps the 590/592 server enumeration)
BOOL g_FH2NoBypass = FALSE;     // v0.9.9: FH2Synth.txt word 'nobypass' = do NOT add XNET_STARTUP_BYPASS_SECURITY to the game's XNetStartup
BOOL g_FH2NoInsecure = FALSE;   // v0.8.11: FH2Synth.txt line 'noinsecure' = do NOT set socket option 0x5801

// -----------------------------------------------------------------------------
// FH2 v0.3.3 diagnostics: trace/probe XAM UI paths and the internal server-down routine.
//
// We deliberately hook the game's imports rather than patching XAM itself. That
// keeps the trace scoped to FH2 and lets the original XAM implementation run
// normally after we record the parameters.
// -----------------------------------------------------------------------------
static VOID FH2_WideToAscii(LPCWSTR input, CHAR* output, DWORD outputSize)
{
	if (!output || outputSize == 0)
		return;

	output[0] = '\0';
	if (!input)
		return;

	DWORD i = 0;
	for (; i + 1 < outputSize && input[i] != L'\0'; ++i)
	{
		WCHAR ch = input[i];
		output[i] = (ch >= 0x20 && ch <= 0x7E) ? (CHAR)ch : '?';
	}
	output[i] = '\0';
}

HRESULT NTAPI FH2_XamShowMessageBoxUIHook(
	DWORD dwUserIndex,
	LPCWSTR wszTitle,
	LPCWSTR wszText,
	DWORD cButtons,
	LPCWSTR* pwszButtons,
	DWORD dwFocusButton,
	DWORD dwFlags,
	PMESSAGEBOX_RESULT pResult,
	PXOVERLAPPED pOverlapped)
{
	CHAR title[192];
	CHAR text[512];
	FH2_WideToAscii(wszTitle, title, sizeof(title));
	FH2_WideToAscii(wszText, text, sizeof(text));

	FH2_Log("MESSAGEBOX TRACE: XamShowMessageBoxUI(ordinal 714) user=%u buttons=%u focus=%u flags=0x%08X overlapped=0x%08X",
		dwUserIndex, cButtons, dwFocusButton, dwFlags, (DWORD)pOverlapped);
	FH2_Log("MESSAGEBOX TRACE: title=\"%s\"", title[0] ? title : "<empty>");
	FH2_Log("MESSAGEBOX TRACE: text=\"%s\"", text[0] ? text : "<empty>");

	if (pwszButtons && cButtons)
	{
		DWORD maxButtons = cButtons < 4 ? cButtons : 4;
		for (DWORD i = 0; i < maxButtons; ++i)
		{
			CHAR button[96];
			FH2_WideToAscii(pwszButtons[i], button, sizeof(button));
			FH2_Log("MESSAGEBOX TRACE: button[%u]=\"%s\"", i, button[0] ? button : "<empty>");
		}
	}

	HRESULT hr = XamShowMessageBoxUI(dwUserIndex, wszTitle, wszText, cButtons,
		pwszButtons, dwFocusButton, dwFlags, pResult, pOverlapped);
	FH2_Log("MESSAGEBOX TRACE: XamShowMessageBoxUI returned 0x%08X", hr);
	return hr;
}

HRESULT NTAPI FH2_XamShowMessageBoxHook(
	DWORD unk,
	LPCWSTR wszTitle,
	LPCWSTR wszText,
	DWORD cButtons,
	LPCWSTR* pwszButtons,
	DWORD dwFocusButton,
	MBOXRESULT resFun,
	DWORD dwFlags)
{
	CHAR title[192];
	CHAR text[512];
	FH2_WideToAscii(wszTitle, title, sizeof(title));
	FH2_WideToAscii(wszText, text, sizeof(text));

	FH2_Log("MESSAGEBOX TRACE: XamShowMessageBox(ordinal 745) unk=%u buttons=%u focus=%u flags=0x%08X callback=0x%08X",
		unk, cButtons, dwFocusButton, dwFlags, (DWORD)resFun);
	FH2_Log("MESSAGEBOX TRACE: title=\"%s\"", title[0] ? title : "<empty>");
	FH2_Log("MESSAGEBOX TRACE: text=\"%s\"", text[0] ? text : "<empty>");

	if (pwszButtons && cButtons)
	{
		DWORD maxButtons = cButtons < 4 ? cButtons : 4;
		for (DWORD i = 0; i < maxButtons; ++i)
		{
			CHAR button[96];
			FH2_WideToAscii(pwszButtons[i], button, sizeof(button));
			FH2_Log("MESSAGEBOX TRACE: button[%u]=\"%s\"", i, button[0] ? button : "<empty>");
		}
	}

	HRESULT hr = XamShowMessageBox(unk, wszTitle, wszText, cButtons, pwszButtons,
		dwFocusButton, resFun, dwFlags);
	FH2_Log("MESSAGEBOX TRACE: XamShowMessageBox returned 0x%08X", hr);
	return hr;
}

static DWORD FH2_CountModuleImport(PLDR_DATA_TABLE_ENTRY module, CHAR* importedModuleName, DWORD ordinal)
{
	DWORD address = (DWORD)ResolveFunction(importedModuleName, ordinal);
	if (address == NULL || module == NULL)
		return 0;

	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(module->XexHeaderBase, 0x000103FF);
	if (importDesc == NULL)
		return 0;

	DWORD count = 0;
	CHAR* stringTable = (CHAR*)(importDesc + 1);
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	for (DWORD x = 0; x < importDesc->ModuleCount; ++x)
	{
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for (DWORD y = 0; y < importTable->ImportTable.ImportCount; ++y)
		{
			DWORD thunkAddress = importAdd[y];
			if (thunkAddress != 0 && *((DWORD*)thunkAddress) == address)
				++count;
		}
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}

	return count;
}

static VOID FH2_ScanDirectBranchesToTarget(PLDR_DATA_TABLE_ENTRY module, DWORD target)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
	{
		FH2_Log("INTERNAL UI TRACE: cannot scan direct branches (invalid module image).");
		return;
	}

	DWORD start = (DWORD)module->ImageBase;
	DWORD end = start + module->SizeOfNtImage;
	DWORD matches = 0;

	for (DWORD address = start; address + 4 <= end; address += 4)
	{
		DWORD instruction = *((DWORD*)address);
		if ((instruction & 0xFC000000) != 0x48000000)
			continue;

		LONG displacement = (LONG)(instruction & 0x03FFFFFC);
		if (displacement & 0x02000000)
			displacement |= (LONG)0xFC000000;

		DWORD branchTarget;
		if (instruction & 0x00000002) // AA: absolute branch
			branchTarget = (DWORD)displacement;
		else
			branchTarget = address + displacement;

		if (branchTarget == target)
		{
			FH2_Log("INTERNAL UI TRACE: direct %s to 0x%08X from 0x%08X instruction=0x%08X",
				(instruction & 1) ? "BL" : "B", target, address, instruction);
			++matches;
		}
	}

	FH2_Log("INTERNAL UI TRACE: scan complete for target 0x%08X; %u direct branch reference(s) found.", target, matches);
}

static VOID FH2_ScanServerNotAvailableString(PLDR_DATA_TABLE_ENTRY module)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage == 0)
		return;

	const CHAR asciiNeedle[] = "Server not available";
	const WCHAR wideNeedle[] = L"Server not available";
	const DWORD asciiLen = sizeof(asciiNeedle) - 1;
	const DWORD wideLen = sizeof(wideNeedle) - sizeof(WCHAR);
	BYTE* base = (BYTE*)module->ImageBase;
	DWORD size = module->SizeOfNtImage;
	DWORD asciiMatches = 0;
	DWORD wideMatches = 0;

	if (size >= asciiLen)
	{
		for (DWORD i = 0; i + asciiLen <= size && asciiMatches < 16; ++i)
		{
			if (memcmp(base + i, asciiNeedle, asciiLen) == 0)
			{
				FH2_Log("INTERNAL UI TRACE: ASCII \"Server not available\" found at 0x%08X.", (DWORD)(base + i));
				++asciiMatches;
			}
		}
	}

	if (size >= wideLen)
	{
		for (DWORD i = 0; i + wideLen <= size && wideMatches < 16; i += 2)
		{
			if (memcmp(base + i, wideNeedle, wideLen) == 0)
			{
				FH2_Log("INTERNAL UI TRACE: UTF-16 \"Server not available\" found at 0x%08X.", (DWORD)(base + i));
				++wideMatches;
			}
		}
	}

	FH2_Log("INTERNAL UI TRACE: literal-text scan complete; ASCII=%u UTF16=%u.", asciiMatches, wideMatches);
}


static DWORD FH2_CollectModuleImportThunks(
	PLDR_DATA_TABLE_ENTRY module,
	CHAR* importedModuleName,
	DWORD ordinal,
	DWORD* outThunks,
	DWORD maxThunks)
{
	DWORD address = (DWORD)ResolveFunction(importedModuleName, ordinal);
	if (address == NULL || module == NULL)
		return 0;

	PXEX_IMPORT_DESCRIPTOR importDesc = (PXEX_IMPORT_DESCRIPTOR)RtlImageXexHeaderField(module->XexHeaderBase, 0x000103FF);
	if (importDesc == NULL)
		return 0;

	DWORD found = 0;
	CHAR* stringTable = (CHAR*)(importDesc + 1);
	XEX_IMPORT_TABLE_ORG* importTable = (XEX_IMPORT_TABLE_ORG*)(stringTable + importDesc->NameTableSize);

	for (DWORD x = 0; x < importDesc->ModuleCount; ++x)
	{
		DWORD* importAdd = (DWORD*)(importTable + 1);
		for (DWORD y = 0; y < importTable->ImportTable.ImportCount; ++y)
		{
			DWORD slotAddress = importAdd[y];
			if (slotAddress == 0 || *((DWORD*)slotAddress) != address)
				continue;

			DWORD thunkAddress = 0;
			if (y + 1 < importTable->ImportTable.ImportCount)
				thunkAddress = importAdd[y + 1];

			FH2_Log("UIEX IMPORT MAP: ordinal %u resolved=0x%08X slot=0x%08X thunk=0x%08X table=%u index=%u.",
				ordinal, address, slotAddress, thunkAddress, x, y);

			if (thunkAddress && outThunks && found < maxThunks)
				outThunks[found] = thunkAddress;
			++found;
		}
		importTable = (XEX_IMPORT_TABLE_ORG*)(((BYTE*)importTable) + importTable->TableSize);
	}

	return found;
}

static VOID FH2_DumpInstructionWindow(PLDR_DATA_TABLE_ENTRY module, DWORD center, DWORD beforeInstructions, DWORD afterInstructions)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
		return;

	DWORD imageStart = (DWORD)module->ImageBase;
	DWORD imageEnd = imageStart + module->SizeOfNtImage;
	DWORD start = center;
	DWORD beforeBytes = beforeInstructions * 4;
	if (center >= imageStart + beforeBytes)
		start = center - beforeBytes;
	else
		start = imageStart;

	DWORD end = center + (afterInstructions * 4);
	if (end + 4 > imageEnd)
		end = imageEnd - 4;

	FH2_Log("UIEX CALLSITE CODE: window around 0x%08X", center);
	for (DWORD address = start; address <= end; address += 4)
	{
		FH2_Log("UIEX CALLSITE CODE: %s0x%08X = 0x%08X",
			(address == center) ? "> " : "  ", address, *((DWORD*)address));
	}
}

static DWORD FH2_ScanDirectBranchesToTargetDetailed(PLDR_DATA_TABLE_ENTRY module, DWORD target, const CHAR* label)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage < 4 || target == 0)
		return 0;

	DWORD start = (DWORD)module->ImageBase;
	DWORD end = start + module->SizeOfNtImage;
	DWORD matches = 0;

	for (DWORD address = start; address + 4 <= end; address += 4)
	{
		DWORD instruction = *((DWORD*)address);
		if ((instruction & 0xFC000000) != 0x48000000)
			continue;

		LONG displacement = (LONG)(instruction & 0x03FFFFFC);
		if (displacement & 0x02000000)
			displacement |= (LONG)0xFC000000;

		DWORD branchTarget = (instruction & 0x00000002)
			? (DWORD)displacement
			: address + displacement;

		if (branchTarget != target)
			continue;

		FH2_Log("UIEX CALLSITE: %s direct %s from 0x%08X -> 0x%08X instruction=0x%08X",
			label ? label : "target",
			(instruction & 1) ? "BL" : "B",
			address, target, instruction);
		FH2_DumpInstructionWindow(module, address, 12, 4);
		++matches;
	}

	FH2_Log("UIEX CALLSITE: %s scan complete for 0x%08X; %u direct branch reference(s) found.",
		label ? label : "target", target, matches);
	return matches;
}

static VOID FH2_ScanDWORDReferences(PLDR_DATA_TABLE_ENTRY module, DWORD target, const CHAR* label)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage < 4)
		return;

	DWORD start = (DWORD)module->ImageBase;
	DWORD end = start + module->SizeOfNtImage;
	DWORD matches = 0;

	for (DWORD address = start; address + 4 <= end && matches < 32; address += 4)
	{
		if (*((DWORD*)address) == target)
		{
			FH2_Log("INDIRECT TARGET TRACE: %s pointer value 0x%08X stored at 0x%08X.",
				label ? label : "target", target, address);
			++matches;
		}
	}
	FH2_Log("INDIRECT TARGET TRACE: %s DWORD-reference scan complete; %u match(es).",
		label ? label : "target", matches);
}

static VOID FH2_ScanAddressMaterialization(PLDR_DATA_TABLE_ENTRY module, DWORD target, const CHAR* label)
{
	if (!module || !module->ImageBase || module->SizeOfNtImage < 8)
		return;

	DWORD start = (DWORD)module->ImageBase;
	DWORD end = start + module->SizeOfNtImage;
	DWORD matches = 0;

	for (DWORD address = start; address + 8 <= end && matches < 32; address += 4)
	{
		DWORD first = *((DWORD*)address);
		// lis rD, imm16 is addis rD,r0,imm16.
		if ((first & 0xFC1F0000) != 0x3C000000)
			continue;

		DWORD reg = (first >> 21) & 0x1F;
		DWORD hi = first & 0xFFFF;

		for (DWORD step = 1; step <= 4 && address + step * 4 < end; ++step)
		{
			DWORD secondAddress = address + step * 4;
			DWORD second = *((DWORD*)secondAddress);
			DWORD value = 0;
			BOOL formed = FALSE;

			// addi rD,rD,simm16
			if ((second & 0xFC000000) == 0x38000000 &&
				((second >> 21) & 0x1F) == reg && ((second >> 16) & 0x1F) == reg)
			{
				SHORT low = (SHORT)(second & 0xFFFF);
				value = (hi << 16) + (LONG)low;
				formed = TRUE;
			}
			// ori rD,rD,uimm16 (RS and RA must both be the same register).
			else if ((second & 0xFC000000) == 0x60000000 &&
				((second >> 21) & 0x1F) == reg && ((second >> 16) & 0x1F) == reg)
			{
				value = (hi << 16) | (second & 0xFFFF);
				formed = TRUE;
			}

			if (formed && value == target)
			{
				FH2_Log("INDIRECT TARGET TRACE: %s address 0x%08X materialized at 0x%08X/0x%08X using r%u.",
					label ? label : "target", target, address, secondAddress, reg);
				FH2_DumpInstructionWindow(module, address, 4, 8);
				++matches;
				break;
			}
		}
	}

	FH2_Log("INDIRECT TARGET TRACE: %s address-materialization scan complete; %u match(es).",
		label ? label : "target", matches);
}


// -----------------------------------------------------------------------------
// FH2 v0.3.5: runtime trace for the private XamShowMessageBoxUIEx import.
//
// TU09 has one direct callsite at 0x82BF2D48.  The code immediately before it
// loads all eight volatile integer argument registers (r3-r10), then compares
// the return value with 0x3E5 (ERROR_IO_PENDING).  That gives us a safe, narrow
// ABI for THIS reached callsite: record eight raw DWORD arguments and forward
// them unchanged to XAM.  We still deliberately do not claim names/types for
// the private UIEx arguments.
// -----------------------------------------------------------------------------
typedef DWORD (NTAPI* pFH2_XamShowMessageBoxUIExRaw)(
    DWORD r3, DWORD r4, DWORD r5, DWORD r6,
    DWORD r7, DWORD r8, DWORD r9, DWORD r10);

static pFH2_XamShowMessageBoxUIExRaw g_FH2_XamShowMessageBoxUIExRaw = NULL;
static volatile DWORD g_FH2_UIExTraceSequence = 0;

static BOOL FH2_IsReadableRange(DWORD address, DWORD bytes)
{
    if (address < 0x10000 || bytes == 0 || address > (0xFFFFFFFF - bytes))
        return FALSE;

    for (DWORD offset = 0; offset < bytes; offset += 4)
    {
        if (!MmIsAddressValid((PVOID)(address + offset)))
            return FALSE;
    }
    return MmIsAddressValid((PVOID)(address + bytes - 1));
}

static VOID FH2_ProbePossiblePointer(const CHAR* name, DWORD value)
{
    if (value < 0x10000 || !MmIsAddressValid((PVOID)value))
        return;

    FH2_Log("UIEX RUNTIME PTR: %s=0x%08X is readable.", name, value);

    if (FH2_IsReadableRange(value, 32))
    {
        DWORD* d = (DWORD*)value;
        FH2_Log("UIEX RUNTIME PTR: %s dwords +00: %08X %08X %08X %08X",
            name, d[0], d[1], d[2], d[3]);
        FH2_Log("UIEX RUNTIME PTR: %s dwords +10: %08X %08X %08X %08X",
            name, d[4], d[5], d[6], d[7]);
    }

    // Best-effort ASCII preview. Only emit it if the prefix looks mostly like
    // printable text; this avoids turning arbitrary structures into noise.
    CHAR ascii[97] = { 0 };
    DWORD asciiLen = 0;
    DWORD asciiPrintable = 0;
    for (; asciiLen < 96; ++asciiLen)
    {
        DWORD a = value + asciiLen;
        if (!MmIsAddressValid((PVOID)a))
            break;
        CHAR ch = *((CHAR*)a);
        if (ch == '\0')
            break;
        if (ch >= 0x20 && ch <= 0x7E)
        {
            ascii[asciiLen] = ch;
            ++asciiPrintable;
        }
        else
        {
            ascii[asciiLen] = '.';
        }
    }
    ascii[asciiLen] = '\0';
    if (asciiLen >= 4 && asciiPrintable * 4 >= asciiLen * 3)
        FH2_Log("UIEX RUNTIME PTR: %s ASCII=\"%s\"", name, ascii);

    // Best-effort UTF-16 preview for localized strings/resource-expanded text.
    CHAR wide[97] = { 0 };
    DWORD wideLen = 0;
    DWORD widePrintable = 0;
    for (; wideLen < 96; ++wideLen)
    {
        DWORD a = value + wideLen * sizeof(WCHAR);
        if (!FH2_IsReadableRange(a, sizeof(WCHAR)))
            break;
        WCHAR ch = *((WCHAR*)a);
        if (ch == L'\0')
            break;
        if (ch >= 0x20 && ch <= 0x7E)
        {
            wide[wideLen] = (CHAR)ch;
            ++widePrintable;
        }
        else
        {
            wide[wideLen] = '?';
        }
    }
    wide[wideLen] = '\0';
    if (wideLen >= 4 && widePrintable * 4 >= wideLen * 3)
        FH2_Log("UIEX RUNTIME PTR: %s UTF16=\"%s\"", name, wide);
}

DWORD NTAPI FH2_XamShowMessageBoxUIExRawHook(
    DWORD a3, DWORD a4, DWORD a5, DWORD a6,
    DWORD a7, DWORD a8, DWORD a9, DWORD a10)
{
    DWORD sequence = ++g_FH2_UIExTraceSequence;

    FH2_Log("UIEX RUNTIME TRACE #%u: r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r9=%08X r10=%08X",
        sequence, a3, a4, a5, a6, a7, a8, a9, a10);

    FH2_ProbePossiblePointer("r3", a3);
    FH2_ProbePossiblePointer("r4", a4);
    FH2_ProbePossiblePointer("r5", a5);
    FH2_ProbePossiblePointer("r6", a6);
    FH2_ProbePossiblePointer("r7", a7);
    FH2_ProbePossiblePointer("r8", a8);
    FH2_ProbePossiblePointer("r9", a9);
    FH2_ProbePossiblePointer("r10", a10);

    if (!g_FH2_XamShowMessageBoxUIExRaw)
    {
        FH2_Log("UIEX RUNTIME TRACE #%u: ERROR original ordinal 732 pointer is NULL.", sequence);
        return ERROR_PROC_NOT_FOUND;
    }

    DWORD result = g_FH2_XamShowMessageBoxUIExRaw(a3, a4, a5, a6, a7, a8, a9, a10);
    FH2_Log("UIEX RUNTIME TRACE #%u: XAM returned 0x%08X%s",
        sequence, result, (result == ERROR_IO_PENDING) ? " (ERROR_IO_PENDING)" : "");
    return result;
}

static DWORD FH2_FindLikelyFunctionStart(DWORD insideAddress, DWORD maxBackBytes)
{
    DWORD imageStart = (DWORD)((PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle)->ImageBase;
    DWORD minAddress = (insideAddress > maxBackBytes) ? insideAddress - maxBackBytes : imageStart;
    if (minAddress < imageStart)
        minAddress = imageStart;

    DWORD address = insideAddress & ~3;
    while (address >= minAddress + 4)
    {
        DWORD instruction = *((DWORD*)address);
        // stwu r1, -N(r1) -- the standard Xbox 360 PPC stack-frame prologue.
        if ((instruction & 0xFFFF0000) == 0x94210000 && (instruction & 0x8000))
            return address;
        address -= 4;
    }
    return 0;
}

static VOID FH2_MapUIExWrapperCallers(PLDR_DATA_TABLE_ENTRY module)
{
    const DWORD uiExCallsite = 0x82BF2D48;
    DWORD functionStart = FH2_FindLikelyFunctionStart(uiExCallsite, 0x800);
    if (!functionStart)
    {
        FH2_Log("UIEX WRAPPER MAP: no likely function prologue found before 0x%08X.", uiExCallsite);
        return;
    }

    FH2_Log("UIEX WRAPPER MAP: likely wrapper start=0x%08X for UIEx callsite 0x%08X.",
        functionStart, uiExCallsite);
    FH2_DumpInstructionWindow(module, functionStart, 0, 20);
    FH2_ScanDirectBranchesToTargetDetailed(module, functionStart, "UIEx wrapper function");
}

VOID SetupFH2MessageBoxTraceHooks()
{
	PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
	DWORD uiResult = PatchModuleImport(module, "xam.xex", 714, (DWORD)FH2_XamShowMessageBoxUIHook);
	DWORD syncResult = PatchModuleImport(module, "xam.xex", 745, (DWORD)FH2_XamShowMessageBoxHook);

	g_FH2_XamShowMessageBoxUIExRaw = (pFH2_XamShowMessageBoxUIExRaw)ResolveFunction("xam.xex", 732);
	DWORD uiExImports = FH2_CountModuleImport(module, "xam.xex", 732);
	DWORD waitExImports = FH2_CountModuleImport(module, "xam.xex", 1337);

	// Map the private UIEx import BEFORE replacing it. PatchModuleImport rewrites
	// both the import slot and its PPC thunk, so collecting the original thunk
	// afterwards would intentionally find nothing.
	// The XEX import table
	// contains both the resolved function slot and the title-side PPC thunk.
	// Direct BLs to that thunk reveal the exact FH2 functions that invoke UIEx
	// without requiring us to guess UIEx's private ABI.
	DWORD uiExThunks[8] = { 0 };
	DWORD thunkCount = FH2_CollectModuleImportThunks(module, "xam.xex", 732, uiExThunks, 8);
	DWORD thunkScanCount = thunkCount < 8 ? thunkCount : 8;
	for (DWORD i = 0; i < thunkScanCount; ++i)
	{
		CHAR label[64];
		sprintf_s(label, sizeof(label), "XamShowMessageBoxUIEx thunk[%u]", i);
		FH2_ScanDirectBranchesToTargetDetailed(module, uiExThunks[i], label);
	}

	FH2_MapUIExWrapperCallers(module);

	DWORD uiExHookResult = g_FH2_XamShowMessageBoxUIExRaw
		? PatchModuleImport(module, "xam.xex", 732, (DWORD)FH2_XamShowMessageBoxUIExRawHook)
		: S_FALSE;

	FH2_Log("v0.3.5 XAM UI diagnostics: ordinal 714 hook=0x%08X, ordinal 745 hook=0x%08X, ordinal 732 imports=%u hook=0x%08X original=0x%08X, ordinal 1337 imports=%u.",
		uiResult, syncResult, uiExImports, uiExHookResult, (DWORD)g_FH2_XamShowMessageBoxUIExRaw, waitExImports);

	if (uiResult != S_OK && syncResult != S_OK)
		FH2_Log("v0.3.5 NOTE: normal XAM message-box imports were not hooked; UIEx raw tracing remains active if ordinal 732 hook succeeded.");

	// Keep the older probes for comparison, and additionally look for indirect
	// references/materialization of the known server-down helper address.
	FH2_ScanDirectBranchesToTarget(module, 0x8284AD60);
	FH2_ScanDWORDReferences(module, 0x8284AD60, "server-down helper");
	FH2_ScanAddressMaterialization(module, 0x8284AD60, "server-down helper");
	FH2_ScanServerNotAvailableString(module);
}


// -----------------------------------------------------------------------------
// FH2 v0.3.6: pass-through network diagnostics.
//
// These hooks intentionally DO NOT redirect traffic, spoof title-server results,
// bypass XNet security, or change return codes. They only log the calls/results
// FH2 makes while entering Online Road Trip so we can identify the real failure
// that leads to the internal "Server not available" UI.
// -----------------------------------------------------------------------------

struct FH2_ENUM_TRACE_ENTRY
{
    HANDLE handle;
    DWORD openMessage;
    DWORD closeMessage;
};

struct FH2_OVERLAPPED_TRACE_ENTRY
{
    PXOVERLAPPED overlapped;
    HANDLE handle;
    DWORD openMessage;
    PVOID buffer;
    DWORD bufferBytes;
    PDWORD itemsReturned;
};

static FH2_ENUM_TRACE_ENTRY g_FH2_EnumTrace[16] = { 0 };
static FH2_OVERLAPPED_TRACE_ENTRY g_FH2_OverlappedTrace[16] = { 0 };
static DWORD g_FH2_EnumTraceNext = 0;
static DWORD g_FH2_OverlappedTraceNext = 0;

static VOID FH2_RememberEnum(HANDLE handle, DWORD openMessage, DWORD closeMessage)
{
    if (!handle)
        return;

    DWORD slot = g_FH2_EnumTraceNext++ % 16;
    g_FH2_EnumTrace[slot].handle = handle;
    g_FH2_EnumTrace[slot].openMessage = openMessage;
    g_FH2_EnumTrace[slot].closeMessage = closeMessage;
}

static DWORD FH2_FindEnumOpenMessage(HANDLE handle)
{
    for (DWORD i = 0; i < 16; ++i)
    {
        if (g_FH2_EnumTrace[i].handle == handle)
            return g_FH2_EnumTrace[i].openMessage;
    }
    return 0;
}

static VOID FH2_RememberOverlapped(
    PXOVERLAPPED overlapped,
    HANDLE handle,
    DWORD openMessage,
    PVOID buffer,
    DWORD bufferBytes,
    PDWORD itemsReturned)
{
    if (!overlapped)
        return;

    DWORD slot = g_FH2_OverlappedTraceNext++ % 16;
    g_FH2_OverlappedTrace[slot].overlapped = overlapped;
    g_FH2_OverlappedTrace[slot].handle = handle;
    g_FH2_OverlappedTrace[slot].openMessage = openMessage;
    g_FH2_OverlappedTrace[slot].buffer = buffer;
    g_FH2_OverlappedTrace[slot].bufferBytes = bufferBytes;
    g_FH2_OverlappedTrace[slot].itemsReturned = itemsReturned;
}

static FH2_OVERLAPPED_TRACE_ENTRY* FH2_FindOverlapped(PXOVERLAPPED overlapped)
{
    for (DWORD i = 0; i < 16; ++i)
    {
        if (g_FH2_OverlappedTrace[i].overlapped == overlapped)
            return &g_FH2_OverlappedTrace[i];
    }
    return NULL;
}

static VOID FH2_NetDumpBuffer(const CHAR* label, PVOID buffer, DWORD bufferBytes)
{
    if (!buffer || bufferBytes == 0)
        return;

    DWORD address = (DWORD)buffer;
    DWORD dumpBytes = bufferBytes < 64 ? bufferBytes : 64;

    if (!FH2_IsReadableRange(address, dumpBytes))
        return;

    BYTE* b = (BYTE*)buffer;
    CHAR line[3 * 16 + 1] = { 0 };

    for (DWORD base = 0; base < dumpBytes; base += 16)
    {
        DWORD count = (dumpBytes - base) < 16 ? (dumpBytes - base) : 16;
        CHAR* out = line;
        DWORD remain = sizeof(line);

        line[0] = '\0';
        for (DWORD i = 0; i < count; ++i)
        {
            int written = sprintf_s(out, remain, "%02X%s", b[base + i], (i + 1 == count) ? "" : " ");
            if (written <= 0)
                break;
            out += written;
            remain -= written;
        }

        FH2_Log("NET TRACE BUFFER: %s +0x%02X: %s",
            label ? label : "buffer", base, line);
    }
}

int NTAPI FH2_NetDll_socketTrace(XNCALLER_TYPE xnc, int af, int type, int protocol)
{
    int result = NetDll_socket(xnc, af, type, protocol);
    if (xnc == 1 && type == 1 && result != (int)INVALID_SOCKET)
        FH2_TrackAdd(result);
    if (xnc == 1 && type == 1 && result != (int)INVALID_SOCKET && !g_FH2NoInsecure)
    {
        // v0.8.8: allow TCP to a non-secure (LAN) address (any SOCK_STREAM, Sunrise option 0x5801).
        BOOL b = TRUE;
        int so = NetDll_setsockopt(xnc, result, SOL_SOCKET, 0x5801, (char*)&b, sizeof(BOOL));
        FH2_SynthEvt(8, (DWORD)((af << 16) | (type << 8) | (protocol & 255)), (DWORD)result, (DWORD)so, 0);
    }
    FH2_Log("NET TRACE: socket xnc=%u af=%d type=%d protocol=%d -> %d",
        (DWORD)xnc, af, type, protocol, result);
    return result;
}

int NTAPI FH2_NetDll_connectTrace(XNCALLER_TYPE xnc, SOCKET s, const sockaddr* name, int namelen)
{
    DWORD family = 0;
    DWORD addr = 0;
    DWORD portRaw = 0;

    if (name && namelen >= (int)sizeof(SOCKADDR_IN) && MmIsAddressValid((PVOID)name))
    {
        const SOCKADDR_IN* in = (const SOCKADDR_IN*)name;
        family = (DWORD)in->sin_family;
        portRaw = (DWORD)in->sin_port;
        addr = in->sin_addr.S_un.S_addr;
    }

    FH2_Log("NET TRACE: connect BEGIN xnc=%u socket=%d family=%u addr=0x%08X portRaw=0x%04X len=%d",
        (DWORD)xnc, (int)s, family, addr, portRaw, namelen);

    int result;
    if (addr == g_FH2SynthIp && g_FH2RealIp != 0 && namelen == (int)sizeof(SOCKADDR_IN) && MmIsAddressValid((PVOID)name))
    {
        // v0.8.20: the game believes the server is the LAN synth IP; connect to the real (VPS) address instead.
        SOCKADDR_IN redirected = *(const SOCKADDR_IN*)name;
        redirected.sin_addr.S_un.S_addr = g_FH2RealIp;
        FH2_Log("v0.8.20 connect redirect: 0x%08X -> 0x%08X", g_FH2SynthIp, g_FH2RealIp);
        if (!g_FH2HttpTick) { DWORD tk = GetTickCount(); g_FH2HttpTick = tk ? tk : 1; }   // v1.0.46
        result = NetDll_connect(xnc, s, (const sockaddr*)&redirected, namelen);
    }
    else
        result = NetDll_connect(xnc, s, name, namelen);
    int wsaError = (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0;
    if (addr == g_FH2SynthIp)
        FH2_SynthEvt(9, (DWORD)s, (DWORD)result, (DWORD)wsaError, portRaw);

    FH2_Log("NET TRACE: connect END socket=%d result=%d wsaError=%d",
        (int)s, result, wsaError);
    return result;
}


static DWORD FH2_FdFlag(const FH2_FDSET* f, int sock)
{
    if (!f || !MmIsAddressValid((PVOID)f)) return 0;
    DWORD n = f->count; if (n > 64) n = 64;
    for (DWORD i = 0; i < n; ++i) if ((int)f->fds[i] == sock) return 1;
    return 0;
}
// returns bitmask: 1=tracked in read set, 2=write set, 4=except set
static DWORD FH2_FdTracked(const FH2_FDSET* r, const FH2_FDSET* w, const FH2_FDSET* e)
{
    DWORD m = 0;
    for (int i = 0; i < FH2_TRACK_MAX; ++i)
    {
        int sk = (int)g_FH2TrackSock[i] - 1;
        if (g_FH2TrackSock[i] == 0) continue;
        if (FH2_FdFlag(r, sk)) m |= 1;
        if (FH2_FdFlag(w, sk)) m |= 2;
        if (FH2_FdFlag(e, sk)) m |= 4;
    }
    return m;
}

int NTAPI FH2_NetDll_selectTrace(XNCALLER_TYPE xnc, int nfds, FH2_FDSET* r, FH2_FDSET* w, FH2_FDSET* e, const FH2_TV* t)
{
    DWORD before = FH2_FdTracked(r, w, e);
    DWORD tmo = 0xFFFFFFFF;
    if (t && MmIsAddressValid((PVOID)t)) tmo = (DWORD)(t->sec * 1000 + t->usec / 1000);
    int result = g_FH2_real_select ? g_FH2_real_select(xnc, nfds, r, w, e, t) : -1;
    if (before)
    {
        static DWORD lastSig = 0; static LONG cnt = 0;
        DWORD after = FH2_FdTracked(r, w, e);
        DWORD sig = (before << 24) | (after << 16) | (DWORD)(result & 0xFFFF);
        if (sig != lastSig && cnt < 400)
        {
            lastSig = sig; ++cnt;
            // a=result, b=tracked-before mask, c=tracked-after mask (1=read 2=write 4=except), d=timeout ms
            FH2_SynthEvt(10, (DWORD)result, before, after, tmo);
        }
    }
    return result;
}

int NTAPI FH2_NetDll_getsockoptTrace(XNCALLER_TYPE xnc, SOCKET s, int level, int optname, char* optval, int* optlen)
{
    int result = g_FH2_real_getsockopt ? g_FH2_real_getsockopt(xnc, s, level, optname, optval, optlen) : -1;
    if (FH2_TrackHas((int)s))
    {
        DWORD v = 0xFFFFFFFF;
        if (optval && optlen && MmIsAddressValid(optlen) && *optlen >= 4 && MmIsAddressValid(optval)) memcpy(&v, optval, 4);
        static LONG cnt = 0;
        if (cnt < 200) { ++cnt; FH2_SynthEvt(11, (DWORD)s, (DWORD)((level << 16) | (optname & 0xFFFF)), (DWORD)result, v); }
    }
    return result;
}

int NTAPI FH2_NetDll_closesocketTrace(XNCALLER_TYPE xnc, SOCKET s)
{
    BOOL tr = FH2_TrackHas((int)s);
    int result = g_FH2_real_closesocket ? g_FH2_real_closesocket(xnc, s) : -1;
    if (tr) { FH2_SynthEvt(12, (DWORD)s, (DWORD)result, 0, 0); FH2_TrackDel((int)s); }
    return result;
}

int NTAPI FH2_NetDll_ioctlsocketTrace(XNCALLER_TYPE xnc, SOCKET s, long cmd, u_long* argp)
{
    DWORD arg = 0xFFFFFFFF;
    if (argp && MmIsAddressValid(argp)) arg = (DWORD)*argp;
    int result = g_FH2_real_ioctlsocket ? g_FH2_real_ioctlsocket(xnc, s, cmd, argp) : -1;
    if (FH2_TrackHas((int)s)) FH2_SynthEvt(13, (DWORD)s, (DWORD)cmd, arg, (DWORD)result);
    return result;
}

static VOID FH2_TrackPayload(DWORD code, const char* buf, int len);
int NTAPI FH2_NetDll_recvDiag(XNCALLER_TYPE xnc, SOCKET s, char* buf, int len, int flags)
{
    int result = g_FH2_real_recv ? g_FH2_real_recv(xnc, s, buf, len, flags) : -1;
    if (FH2_TrackHas((int)s))
    {
        int werr = (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0;
        static DWORD lastSig = 0; static LONG cnt = 0;
        DWORD sig = ((DWORD)result << 8) ^ (DWORD)werr ^ (DWORD)s;
        // EWOULDBLOCK polling is noisy: log changes only, cap at 400.
        if ((result > 0 || sig != lastSig) && cnt < 400)
        {
            lastSig = sig; ++cnt;
            FH2_SynthEvt(16, (DWORD)s, (DWORD)len, (DWORD)result, (DWORD)werr);
            if (result > 0) FH2_TrackPayload(17, buf, result);
        }
    }
    return result;
}

static VOID FH2_TrackPayload(DWORD code, const char* buf, int len)
{
    if (!buf || len <= 0 || !MmIsAddressValid((PVOID)buf)) return;
    DWORD w[4] = { 0, 0, 0, 0 };
    int n = len < 16 ? len : 16;
    memcpy(w, buf, n);
    FH2_SynthEvt(code, w[0], w[1], w[2], w[3]);   // raw bytes, big-endian words
}

int NTAPI FH2_NetDll_XNetServerToInAddrTrace(
    XNCALLER_TYPE xnc,
    const IN_ADDR ina,
    DWORD serviceId,
    PIN_ADDR outAddress)
{
    FH2_Log("NET TRACE: XNetServerToInAddr BEGIN xnc=%u server=0x%08X serviceId=0x%08X out=%08X",
        (DWORD)xnc, ina.S_un.S_addr, serviceId, (DWORD)outAddress);

    if (ina.S_un.S_addr == g_FH2SynthIp && outAddress && MmIsAddressValid(outAddress))
    {
        // v0.8.5: the synthetic server is a plain LAN IP; skip secure-address translation.
        outAddress->S_un.S_addr = ina.S_un.S_addr;
        FH2_SynthEvt(5, ina.S_un.S_addr, serviceId, 0, 0);
        FH2_Log("NET TRACE: XNetServerToInAddr synthetic server -> passthrough");
        return 0;
    }

    int result = NetDll_XNetServerToInAddr(xnc, ina, serviceId, outAddress);

    FH2_Log("NET TRACE: XNetServerToInAddr END result=%d translated=0x%08X",
        result, (outAddress && MmIsAddressValid(outAddress)) ? outAddress->S_un.S_addr : 0);
    return result;
}

int NTAPI FH2_NetDll_XNetConnectTrace(XNCALLER_TYPE xnc, const IN_ADDR ina)
{
    if (ina.S_un.S_addr == g_FH2SynthIp)
    {
        // v0.8.7: plain LAN server, no secure association exists or is needed.
        FH2_SynthEvt(3, ina.S_un.S_addr, 0, 0, 0);
        return 0;
    }
    int result = NetDll_XNetConnect(xnc, ina);
    FH2_SynthEvt(32, ina.S_un.S_addr, (DWORD)result, 0, 0);
    FH2_Log("NET TRACE: XNetConnect xnc=%u addr=0x%08X -> %d",
        (DWORD)xnc, ina.S_un.S_addr, result);
    return result;
}

DWORD NTAPI FH2_NetDll_XNetGetConnectStatusTrace(XNCALLER_TYPE xnc, const IN_ADDR ina)
{
    if (ina.S_un.S_addr == g_FH2SynthIp)
    {
        DWORD real = NetDll_XNetGetConnectStatus(xnc, ina);   // v0.8.13: diagnostic only
        FH2_SynthEvt(4, ina.S_un.S_addr, 2, real, 0);
        return 2;   // XNET_CONNECT_STATUS_CONNECTED
    }
    DWORD result = NetDll_XNetGetConnectStatus(xnc, ina);
    {
        // v0.9.13: record status changes per address (ring event, logged by the worker).
        static volatile DWORD stAddr[8]; static volatile DWORD stVal[8]; static volatile LONG stN = 0;
        LONG cnt = stN; if (cnt > 8) cnt = 8;
        int idx = -1;
        for (int q = 0; q < cnt; ++q) if (stAddr[q] == ina.S_un.S_addr) { idx = q; break; }
        if (idx < 0 && cnt < 8) { LONG k = InterlockedIncrement(&stN) - 1; if (k < 8) { stAddr[k] = ina.S_un.S_addr; stVal[k] = 0xFFFFFFFE; idx = (int)k; } }
        if (idx >= 0 && stVal[idx] != result) { DWORD prev = stVal[idx]; stVal[idx] = result; FH2_SynthEvt(33, ina.S_un.S_addr, result, prev, 0); }
    }
    FH2_Log("NET TRACE: XNetGetConnectStatus xnc=%u addr=0x%08X -> 0x%08X",
        (DWORD)xnc, ina.S_un.S_addr, result);
    return result;
}

int NTAPI FH2_NetDll_XNetDnsLookupTrace(
    XNCALLER_TYPE xnc,
    LPCSTR host,
    WSAEVENT eventHandle,
    XNDNS** ppDns)
{
    FH2_Log("NET TRACE: XNetDnsLookup BEGIN xnc=%u host=\"%s\" event=%08X ppDns=%08X",
        (DWORD)xnc, host ? host : "<null>", (DWORD)eventHandle, (DWORD)ppDns);

    int result = NetDll_XNetDnsLookup(xnc, host, eventHandle, ppDns);

    DWORD dnsPtr = 0;
    if (ppDns && MmIsAddressValid(ppDns))
        dnsPtr = (DWORD)(*ppDns);

    FH2_Log("NET TRACE: XNetDnsLookup END host=\"%s\" result=%d dns=%08X",
        host ? host : "<null>", result, dnsPtr);

    if (dnsPtr && MmIsAddressValid((PVOID)dnsPtr))
        FH2_NetDumpBuffer("XNDNS initial", (PVOID)dnsPtr, 64);

    return result;
}

int NTAPI FH2_NetDll_XNetDnsReleaseTrace(XNCALLER_TYPE xnc, XNDNS* dns)
{
    FH2_Log("NET TRACE: XNetDnsRelease xnc=%u dns=%08X",
        (DWORD)xnc, (DWORD)dns);

    if (dns && MmIsAddressValid(dns))
        FH2_NetDumpBuffer("XNDNS final", dns, 64);

    return NetDll_XNetDnsRelease(xnc, dns);
}

DWORD NTAPI FH2_XamCreateEnumeratorHandleTrace(
    DWORD userIndex,
    HXAMAPP appId,
    DWORD openMessage,
    DWORD closeMessage,
    DWORD extraSize,
    DWORD itemCount,
    DWORD flags,
    PHANDLE outHandle)
{
    FH2_Log("NET TRACE: XamCreateEnumeratorHandle BEGIN user=%u app=%08X open=0x%08X close=0x%08X extra=%u items=%u flags=0x%08X",
        userIndex, (DWORD)appId, openMessage, closeMessage, extraSize, itemCount, flags);

    DWORD result = XamCreateEnumeratorHandle(
        userIndex, appId, openMessage, closeMessage,
        extraSize, itemCount, flags, outHandle);

    HANDLE handle = (outHandle && MmIsAddressValid(outHandle)) ? *outHandle : NULL;
    FH2_Log("NET TRACE: XamCreateEnumeratorHandle END result=0x%08X handle=%08X open=0x%08X",
        result, (DWORD)handle, openMessage);

    if (result == ERROR_SUCCESS && handle)
        FH2_RememberEnum(handle, openMessage, closeMessage);

    return result;
}

DWORD NTAPI FH2_XamEnumerateTrace(
    HANDLE hEnum,
    DWORD flags,
    PVOID buffer,
    DWORD bufferBytes,
    PDWORD itemsReturned,
    PXOVERLAPPED overlapped)
{
    DWORD openMessage = FH2_FindEnumOpenMessage(hEnum);

    FH2_Log("NET TRACE: XamEnumerate BEGIN handle=%08X open=0x%08X flags=0x%08X buffer=%08X bytes=%u itemsPtr=%08X ov=%08X",
        (DWORD)hEnum, openMessage, flags, (DWORD)buffer, bufferBytes,
        (DWORD)itemsReturned, (DWORD)overlapped);

    if (overlapped)
        FH2_RememberOverlapped(overlapped, hEnum, openMessage, buffer, bufferBytes, itemsReturned);

    DWORD result = XamEnumerate(
        hEnum, flags, buffer, bufferBytes, itemsReturned, overlapped);

    DWORD items = 0xFFFFFFFF;
    if (itemsReturned && MmIsAddressValid(itemsReturned))
        items = *itemsReturned;

    FH2_Log("NET TRACE: XamEnumerate END handle=%08X open=0x%08X result=0x%08X items=%u ovLow=0x%08X ovHigh=0x%08X ovExt=0x%08X",
        (DWORD)hEnum, openMessage, result, items,
        overlapped ? (DWORD)overlapped->InternalLow : 0,
        overlapped ? (DWORD)overlapped->InternalHigh : 0,
        overlapped ? (DWORD)overlapped->dwExtendedError : 0);

    if (result != ERROR_IO_PENDING && buffer && bufferBytes)
        FH2_NetDumpBuffer("XamEnumerate sync result", buffer, bufferBytes);

    return result;
}

typedef DWORD (NTAPI* pFH2_XGetOverlappedResult)(
    PXOVERLAPPED overlapped,
    LPDWORD resultValue,
    BOOL wait);

static pFH2_XGetOverlappedResult g_FH2_XGetOverlappedResult = NULL;

DWORD NTAPI FH2_XGetOverlappedResultTrace(
    PXOVERLAPPED overlapped,
    LPDWORD resultValue,
    BOOL wait)
{
    FH2_OVERLAPPED_TRACE_ENTRY* tracked = FH2_FindOverlapped(overlapped);

    DWORD result = g_FH2_XGetOverlappedResult
        ? g_FH2_XGetOverlappedResult(overlapped, resultValue, wait)
        : ERROR_PROC_NOT_FOUND;

    DWORD value = 0xFFFFFFFF;
    if (resultValue && MmIsAddressValid(resultValue))
        value = *resultValue;

    FH2_Log("NET TRACE: XGetOverlappedResult ov=%08X wait=%u -> 0x%08X value=%u trackedHandle=%08X open=0x%08X ovLow=0x%08X ovHigh=0x%08X ovExt=0x%08X",
        (DWORD)overlapped, (DWORD)wait, result, value,
        tracked ? (DWORD)tracked->handle : 0,
        tracked ? tracked->openMessage : 0,
        overlapped ? (DWORD)overlapped->InternalLow : 0,
        overlapped ? (DWORD)overlapped->InternalHigh : 0,
        overlapped ? (DWORD)overlapped->dwExtendedError : 0);

    if (tracked && result == ERROR_SUCCESS && tracked->buffer && tracked->bufferBytes)
    {
        DWORD items = 0xFFFFFFFF;
        if (tracked->itemsReturned && MmIsAddressValid(tracked->itemsReturned))
            items = *tracked->itemsReturned;

        FH2_Log("NET TRACE: async enumeration completed handle=%08X open=0x%08X items=%u",
            (DWORD)tracked->handle, tracked->openMessage, items);
        FH2_NetDumpBuffer("XamEnumerate async result", tracked->buffer, tracked->bufferBytes);
    }

    return result;
}

VOID SetupFH2NetworkTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD rSocket = PatchModuleImport(module, "xam.xex", 3, (DWORD)FH2_NetDll_socketTrace);
    DWORD rConnect = PatchModuleImport(module, "xam.xex", 12, (DWORD)FH2_NetDll_connectTrace);
    DWORD rServerToInAddr = PatchModuleImport(module, "xam.xex", 58, (DWORD)FH2_NetDll_XNetServerToInAddrTrace);
    DWORD rXNetConnect = PatchModuleImport(module, "xam.xex", 65, (DWORD)FH2_NetDll_XNetConnectTrace);
    DWORD rXNetStatus = PatchModuleImport(module, "xam.xex", 66, (DWORD)FH2_NetDll_XNetGetConnectStatusTrace);
    DWORD rDnsLookup = PatchModuleImport(module, "xam.xex", 67, (DWORD)FH2_NetDll_XNetDnsLookupTrace);
    DWORD rDnsRelease = PatchModuleImport(module, "xam.xex", 68, (DWORD)FH2_NetDll_XNetDnsReleaseTrace);
    DWORD rCreateEnum = PatchModuleImport(module, "xam.xex", 590, (DWORD)FH2_XamCreateEnumeratorHandleTrace);
    DWORD rEnumerate = PatchModuleImport(module, "xam.xex", 592, (DWORD)FH2_XamEnumerateTrace);

    g_FH2_XGetOverlappedResult =
        (pFH2_XGetOverlappedResult)ResolveFunction("xam.xex", 1083);
    DWORD rOverlapped = g_FH2_XGetOverlappedResult
        ? PatchModuleImport(module, "xam.xex", 1083, (DWORD)FH2_XGetOverlappedResultTrace)
        : S_FALSE;

    FH2_Log("v0.3.6 NET TRACE hooks: socket=%08X connect=%08X serverToInAddr=%08X xnetConnect=%08X xnetStatus=%08X dnsLookup=%08X dnsRelease=%08X createEnum=%08X enumerate=%08X overlapped=%08X.",
        rSocket, rConnect, rServerToInAddr, rXNetConnect, rXNetStatus,
        rDnsLookup, rDnsRelease, rCreateEnum, rEnumerate, rOverlapped);
}


// -----------------------------------------------------------------------------
// FH2 v0.3.7: pre-network eligibility / Live-state diagnostics.
//
// v0.3.6 proved that pressing Online Road Trip can produce the server-down UI
// without touching the title's imported socket/XNet/enumerator functions. This
// trace therefore watches the user/Live eligibility checks that can reject the
// action before networking begins. All hooks are pass-through: no result is
// changed.
// -----------------------------------------------------------------------------

typedef DWORD (NTAPI* pFH2_XamUserGetSigninState)(DWORD userIndex);
typedef DWORD (NTAPI* pFH2_XamUserCheckPrivilege)(DWORD userIndex, DWORD privilegeType, PBOOL result);
typedef BOOL  (NTAPI* pFH2_XamUserIsOnlineEnabled)(DWORD userIndex);
typedef NTSTATUS (NTAPI* pFH2_XamUserGetSigninInfo)(DWORD userIndex, DWORD flags, PVOID info);
typedef DWORD (NTAPI* pFH2_XGetOverlappedExtendedError)(PXOVERLAPPED overlapped);

static pFH2_XamUserGetSigninState g_FH2_XamUserGetSigninState = NULL;
static pFH2_XamUserCheckPrivilege g_FH2_XamUserCheckPrivilege = NULL;
static pFH2_XamUserIsOnlineEnabled g_FH2_XamUserIsOnlineEnabled = NULL;
static pFH2_XamUserGetSigninInfo g_FH2_XamUserGetSigninInfo = NULL;
static pFH2_XGetOverlappedExtendedError g_FH2_XGetOverlappedExtendedError = NULL;

// v0.9.5: these traces are now hooked in the active build (they were defined but never installed
// before). The game polls sign-in state constantly, so they log only when a value CHANGES, and
// every v0.9.5 trace shares one per-game-instance cap so the log cannot flood.
static volatile LONG g_FH2_V095_TraceCount = 0;
static volatile LONG g_FH2_V095_SigninInfoCalls = 0;
static volatile DWORD g_FH2_V095_LastSigninState[4] = { 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE };
static volatile DWORD g_FH2_V095_LastOnline[4] = { 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE, 0xFFFFFFFE };
static volatile DWORD g_FH2_V095_LastPriv[256];
#define FH2_V095_TRACE_CAP 600
static BOOL FH2_V095_TraceOk()
{
    LONG n = InterlockedIncrement(&g_FH2_V095_TraceCount);
    if (n == FH2_V095_TRACE_CAP + 1)
        FH2_Log("v0.9.5 TRACE: per-instance trace cap (%d lines) reached; further hook traces are suppressed.", FH2_V095_TRACE_CAP);
    return n <= FH2_V095_TRACE_CAP;
}

VOID FH2_V095_ResetTraceCounters()
{
    g_FH2_V095_TraceCount = 0;
    g_FH2_V095_SigninInfoCalls = 0;
    for (int i = 0; i < 4; ++i)
    {
        g_FH2_V095_LastSigninState[i] = 0xFFFFFFFE;
        g_FH2_V095_LastOnline[i] = 0xFFFFFFFE;
    }
    for (int i = 0; i < 256; ++i)
        g_FH2_V095_LastPriv[i] = 0xFFFFFFFE;
}

DWORD NTAPI FH2_XamUserGetSigninStateTrace(DWORD userIndex)
{
    DWORD result = g_FH2_XamUserGetSigninState
        ? g_FH2_XamUserGetSigninState(userIndex)
        : 0xFFFFFFFF;
    if (userIndex < 4)
    {
        if (g_FH2_V095_LastSigninState[userIndex] != result)
        {
            g_FH2_V095_LastSigninState[userIndex] = result;
            if (FH2_V095_TraceOk())
                FH2_Log("v0.9.5 SIGNIN: XamUserGetSigninState user=%u -> %u (0=none 1=local 2=live) tick=%u",
                    userIndex, result, GetTickCount());
        }
    }
    else if (FH2_V095_TraceOk())
        FH2_Log("v0.9.5 SIGNIN: XamUserGetSigninState user=0x%08X -> 0x%08X", userIndex, result);
    return result;
}

DWORD NTAPI FH2_XamUserCheckPrivilegeTrace(DWORD userIndex, DWORD privilegeType, PBOOL resultOut)
{
    DWORD result = g_FH2_XamUserCheckPrivilege
        ? g_FH2_XamUserCheckPrivilege(userIndex, privilegeType, resultOut)
        : ERROR_PROC_NOT_FOUND;

    DWORD allowed = 0xFFFFFFFF;
    if (resultOut && MmIsAddressValid(resultOut))
        allowed = *resultOut ? 1 : 0;

    DWORD key = (result << 8) ^ (allowed & 0xFF) ^ (userIndex << 28);
    if (privilegeType < 256)
    {
        if (g_FH2_V095_LastPriv[privilegeType] == key)
            return result;
        g_FH2_V095_LastPriv[privilegeType] = key;
    }
    if (FH2_V095_TraceOk())
        FH2_Log("v0.9.5 PRIVILEGE: XamUserCheckPrivilege user=0x%08X privilege=%u (254=multiplayer) -> hr=0x%08X allowed=%u tick=%u",
            userIndex, privilegeType, result, allowed, GetTickCount());
    return result;
}

BOOL NTAPI FH2_XamUserIsOnlineEnabledTrace(DWORD userIndex)
{
    BOOL result = g_FH2_XamUserIsOnlineEnabled
        ? g_FH2_XamUserIsOnlineEnabled(userIndex)
        : FALSE;
    DWORD r = result ? 1 : 0;
    if (userIndex < 4)
    {
        if (g_FH2_V095_LastOnline[userIndex] != r)
        {
            g_FH2_V095_LastOnline[userIndex] = r;
            if (FH2_V095_TraceOk())
                FH2_Log("v0.9.5 SIGNIN: XamUserIsOnlineEnabled user=%u -> %u tick=%u", userIndex, r, GetTickCount());
        }
    }
    return result;
}

NTSTATUS NTAPI FH2_XamUserGetSigninInfoTrace(DWORD userIndex, DWORD flags, PVOID info)
{
    NTSTATUS result = g_FH2_XamUserGetSigninInfo
        ? g_FH2_XamUserGetSigninInfo(userIndex, flags, info)
        : (NTSTATUS)0xC000007A;

    LONG n = InterlockedIncrement(&g_FH2_V095_SigninInfoCalls);
    if (n <= 40 && FH2_V095_TraceOk())
    {
        FH2_Log("v0.9.5 SIGNIN: XamUserGetSigninInfo user=%u flags=0x%08X info=%08X -> status=0x%08X tick=%u",
            userIndex, flags, (DWORD)info, (DWORD)result, GetTickCount());
        if (info && FH2_IsReadableRange((DWORD)info, 64))
            FH2_NetDumpBuffer("XamUserGetSigninInfo", info, 64);
    }
    return result;
}

DWORD NTAPI FH2_XGetOverlappedExtendedErrorTrace(PXOVERLAPPED overlapped)
{
    DWORD result = g_FH2_XGetOverlappedExtendedError
        ? g_FH2_XGetOverlappedExtendedError(overlapped)
        : ERROR_PROC_NOT_FOUND;

    // v0.9.5: only log failures (0x48F = ERROR_DEVICE_NOT_CONNECTED is the one we care about).
    if (result != 0 && FH2_V095_TraceOk())
        FH2_Log("v0.9.5 OVERLAPPED: XGetOverlappedExtendedError ov=%08X -> 0x%08X low=0x%08X high=0x%08X ext=0x%08X",
            (DWORD)overlapped, result,
            (overlapped && MmIsAddressValid(overlapped)) ? (DWORD)overlapped->InternalLow : 0,
            (overlapped && MmIsAddressValid(overlapped)) ? (DWORD)overlapped->InternalHigh : 0,
            (overlapped && MmIsAddressValid(overlapped)) ? (DWORD)overlapped->dwExtendedError : 0);
    return result;
}

VOID SetupFH2EligibilityTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c528 = FH2_CountModuleImport(module, "xam.xex", 528);
    DWORD c530 = FH2_CountModuleImport(module, "xam.xex", 530);
    DWORD c545 = FH2_CountModuleImport(module, "xam.xex", 545);
    DWORD c551 = FH2_CountModuleImport(module, "xam.xex", 551);
    DWORD c1082 = FH2_CountModuleImport(module, "xam.xex", 1082);

    // Presence-only probes for lower-level Live state and alternate transport
    // families. These are intentionally not hooked until we know FH2 imports them.
    DWORD c301 = FH2_CountModuleImport(module, "xam.xex", 301); // XNetLogonGetLoggedOnUsers
    DWORD c307 = FH2_CountModuleImport(module, "xam.xex", 307); // XNetLogonGetUserPrivileges
    DWORD c315 = FH2_CountModuleImport(module, "xam.xex", 315); // XNetLogonGetExtendedStatus
    DWORD c322 = FH2_CountModuleImport(module, "xam.xex", 322); // XNetLogonGetState
    DWORD c69  = FH2_CountModuleImport(module, "xam.xex", 69);  // XNetQosListen
    DWORD c70  = FH2_CountModuleImport(module, "xam.xex", 70);  // XNetQosLookup
    DWORD c71  = FH2_CountModuleImport(module, "xam.xex", 71);  // XNetQosServiceLookup
    DWORD c72  = FH2_CountModuleImport(module, "xam.xex", 72);  // XNetQosRelease
    DWORD c201 = FH2_CountModuleImport(module, "xam.xex", 201); // XHttpStartup
    DWORD c205 = FH2_CountModuleImport(module, "xam.xex", 205); // XHttpConnect
    DWORD c207 = FH2_CountModuleImport(module, "xam.xex", 207); // XHttpOpenRequest
    DWORD c209 = FH2_CountModuleImport(module, "xam.xex", 209); // XHttpSendRequest

    FH2_Log("v0.3.7 ELIG IMPORTS: signinState(528)=%u privilege(530)=%u onlineEnabled(545)=%u signinInfo(551)=%u ovExt(1082)=%u",
        c528, c530, c545, c551, c1082);
    FH2_Log("v0.3.7 ALT IMPORTS: logonUsers301=%u logonPriv307=%u logonExt315=%u logonState322=%u qos69/70/71/72=%u/%u/%u/%u xhttp201/205/207/209=%u/%u/%u/%u",
        c301, c307, c315, c322, c69, c70, c71, c72, c201, c205, c207, c209);

    g_FH2_XamUserGetSigninState = (pFH2_XamUserGetSigninState)ResolveFunction("xam.xex", 528);
    g_FH2_XamUserCheckPrivilege = (pFH2_XamUserCheckPrivilege)ResolveFunction("xam.xex", 530);
    g_FH2_XamUserIsOnlineEnabled = (pFH2_XamUserIsOnlineEnabled)ResolveFunction("xam.xex", 545);
    g_FH2_XamUserGetSigninInfo = (pFH2_XamUserGetSigninInfo)ResolveFunction("xam.xex", 551);
    g_FH2_XGetOverlappedExtendedError = (pFH2_XGetOverlappedExtendedError)ResolveFunction("xam.xex", 1082);

    DWORD r528 = (c528 && g_FH2_XamUserGetSigninState)
        ? PatchModuleImport(module, "xam.xex", 528, (DWORD)FH2_XamUserGetSigninStateTrace) : S_FALSE;
    DWORD r530 = (c530 && g_FH2_XamUserCheckPrivilege)
        ? PatchModuleImport(module, "xam.xex", 530, (DWORD)FH2_XamUserCheckPrivilegeTrace) : S_FALSE;
    DWORD r545 = (c545 && g_FH2_XamUserIsOnlineEnabled)
        ? PatchModuleImport(module, "xam.xex", 545, (DWORD)FH2_XamUserIsOnlineEnabledTrace) : S_FALSE;
    DWORD r551 = (c551 && g_FH2_XamUserGetSigninInfo)
        ? PatchModuleImport(module, "xam.xex", 551, (DWORD)FH2_XamUserGetSigninInfoTrace) : S_FALSE;
    DWORD r1082 = (c1082 && g_FH2_XGetOverlappedExtendedError)
        ? PatchModuleImport(module, "xam.xex", 1082, (DWORD)FH2_XGetOverlappedExtendedErrorTrace) : S_FALSE;

    FH2_Log("v0.3.7 ELIG TRACE hooks: signinState=%08X privilege=%08X onlineEnabled=%08X signinInfo=%08X ovExt=%08X",
        r528, r530, r545, r551, r1082);
}


// -----------------------------------------------------------------------------
// FH2 v0.3.8: XNet pre-connectivity gate diagnostics.
//
// v0.3.7 showed no user/privilege API calls when Online Road Trip was selected.
// v0.3.6 did not cover three important low-cost XNet status probes that titles
// can use before DNS/socket activity:
//   73 - NetDll_XNetGetTitleXnAddr
//   75 - NetDll_XNetGetEthernetLinkStatus
//   78 - NetDll_XNetGetOpt (including XNET_OPTID_ONLINE_PRIVS = 0x138E)
//
// All hooks are pass-through and preserve the original return values/buffers.
// -----------------------------------------------------------------------------

typedef DWORD (NTAPI* pFH2_XNetGetTitleXnAddr)(XNCALLER_TYPE xnc, XNADDR* pxna);
typedef DWORD (NTAPI* pFH2_XNetGetEthernetLinkStatus)(XNCALLER_TYPE xnc);
typedef int (NTAPI* pFH2_XNetGetOpt)(XNCALLER_TYPE xnc, DWORD optId, BYTE* value, DWORD* valueSize);

static pFH2_XNetGetTitleXnAddr g_FH2_XNetGetTitleXnAddr = NULL;
static pFH2_XNetGetEthernetLinkStatus g_FH2_XNetGetEthernetLinkStatus = NULL;
static pFH2_XNetGetOpt g_FH2_XNetGetOpt = NULL;

DWORD NTAPI FH2_XNetGetTitleXnAddrTrace(XNCALLER_TYPE xnc, XNADDR* pxna)
{
    DWORD result = g_FH2_XNetGetTitleXnAddr
        ? g_FH2_XNetGetTitleXnAddr(xnc, pxna)
        : 0xFFFFFFFF;

    FH2_Log("XNET GATE TRACE: XNetGetTitleXnAddr xnc=%u pxna=%08X -> 0x%08X pending=%u ethernet=%u static=%u dhcp=%u pppoe=%u gateway=%u dns=%u online=%u troubleshoot=%u",
        (DWORD)xnc, (DWORD)pxna, result,
        result == 0 ? 1 : 0,
        (result & 0x00000002) ? 1 : 0,
        (result & 0x00000004) ? 1 : 0,
        (result & 0x00000008) ? 1 : 0,
        (result & 0x00000010) ? 1 : 0,
        (result & 0x00000020) ? 1 : 0,
        (result & 0x00000040) ? 1 : 0,
        (result & 0x00000080) ? 1 : 0,
        (result & 0x00008000) ? 1 : 0);

    if (pxna && FH2_IsReadableRange((DWORD)pxna, sizeof(XNADDR)))
        FH2_NetDumpBuffer("XNetGetTitleXnAddr XNADDR", pxna, sizeof(XNADDR));

    return result;
}

DWORD NTAPI FH2_XNetGetEthernetLinkStatusTrace(XNCALLER_TYPE xnc)
{
    DWORD result = g_FH2_XNetGetEthernetLinkStatus
        ? g_FH2_XNetGetEthernetLinkStatus(xnc)
        : 0xFFFFFFFF;

    FH2_Log("XNET GATE TRACE: XNetGetEthernetLinkStatus xnc=%u -> 0x%08X",
        (DWORD)xnc, result);
    return result;
}

int NTAPI FH2_XNetGetOptTrace(XNCALLER_TYPE xnc, DWORD optId, BYTE* value, DWORD* valueSize)
{
    DWORD sizeBefore = 0xFFFFFFFF;
    if (valueSize && MmIsAddressValid(valueSize))
        sizeBefore = *valueSize;

    int result = g_FH2_XNetGetOpt
        ? g_FH2_XNetGetOpt(xnc, optId, value, valueSize)
        : ERROR_PROC_NOT_FOUND;

    DWORD sizeAfter = 0xFFFFFFFF;
    if (valueSize && MmIsAddressValid(valueSize))
        sizeAfter = *valueSize;

    FH2_Log("XNET GATE TRACE: XNetGetOpt xnc=%u opt=0x%08X%s value=%08X sizeBefore=%u sizeAfter=%u -> 0x%08X",
        (DWORD)xnc, optId,
        (optId == 0x0000138E) ? " (ONLINE_PRIVS)" : "",
        (DWORD)value, sizeBefore, sizeAfter, (DWORD)result);

    if (value && sizeAfter != 0xFFFFFFFF && sizeAfter > 0)
    {
        DWORD dumpBytes = sizeAfter;
        if (dumpBytes > 64)
            dumpBytes = 64;
        if (FH2_IsReadableRange((DWORD)value, dumpBytes))
            FH2_NetDumpBuffer((optId == 0x0000138E) ? "XNetGetOpt ONLINE_PRIVS" : "XNetGetOpt value", value, dumpBytes);
    }

    return result;
}


// -----------------------------------------------------------------------------
// FH2 v0.4.0: backend / QoS diagnostics.
//
// v0.3.9 proved that forcing the internal TU09 state getter TRUE can move FH2
// past the immediate online-services rejection.  The remaining failure occurs
// after a 20-30 second wait, which is consistent with matchmaking/backend work.
// FH2 imports XNet QoS APIs (69, 70 and 72), so trace those calls and preserve
// every original return value.  No server redirection or response spoofing is
// performed by this diagnostic.
// -----------------------------------------------------------------------------

typedef int (NTAPI* pFH2_XNetQosListen)(
    XNCALLER_TYPE xnc,
    const XNKID* pxnkid,
    const BYTE* pb,
    DWORD cb,
    DWORD dwBitsPerSec,
    DWORD dwFlags);

typedef int (NTAPI* pFH2_XNetQosLookup)(
    XNCALLER_TYPE xnc,
    DWORD cxna,
    const XNADDR* apxna[],
    const XNKID* apxnkid[],
    const XNKEY* apxnkey[],
    UINT cina,
    const IN_ADDR aina[],
    const DWORD adwServiceId[],
    DWORD dwBitsPerSec,
    DWORD dwFlags,
    WSAEVENT hEvent,
    XNQOS** ppxnqos);

typedef int (NTAPI* pFH2_XNetQosRelease)(
    XNCALLER_TYPE xnc,
    XNQOS* pxnqos);

static pFH2_XNetQosListen  g_FH2_XNetQosListen  = NULL;
static pFH2_XNetQosLookup  g_FH2_XNetQosLookup  = NULL;
static pFH2_XNetQosRelease g_FH2_XNetQosRelease = NULL;

static VOID FH2_LogQosTargets(
    DWORD cxna,
    const XNADDR* apxna[],
    UINT cina,
    const IN_ADDR aina[],
    const DWORD adwServiceId[])
{
    DWORD maxXna = cxna < 4 ? cxna : 4;
    if (apxna && FH2_IsReadableRange((DWORD)apxna, maxXna ? (maxXna * sizeof(PVOID)) : sizeof(PVOID)))
    {
        for (DWORD i = 0; i < maxXna; ++i)
        {
            const XNADDR* xna = apxna[i];
            FH2_Log("QOS TRACE: target XNADDR[%u]=%08X", i, (DWORD)xna);
            if (xna && FH2_IsReadableRange((DWORD)xna, sizeof(XNADDR)))
                FH2_NetDumpBuffer("QOS XNADDR", (PVOID)xna, sizeof(XNADDR));
        }
    }

    DWORD maxIna = cina < 8 ? (DWORD)cina : 8;
    if (aina && maxIna && FH2_IsReadableRange((DWORD)aina, maxIna * sizeof(IN_ADDR)))
    {
        for (DWORD i = 0; i < maxIna; ++i)
        {
            DWORD serviceId = 0xFFFFFFFF;
            if (adwServiceId && FH2_IsReadableRange((DWORD)&adwServiceId[i], sizeof(DWORD)))
                serviceId = adwServiceId[i];

            FH2_Log("QOS TRACE: target IN_ADDR[%u]=0x%08X serviceId=0x%08X",
                i, aina[i].S_un.S_addr, serviceId);
        }
    }
}

int NTAPI FH2_XNetQosListenTrace(
    XNCALLER_TYPE xnc,
    const XNKID* pxnkid,
    const BYTE* pb,
    DWORD cb,
    DWORD dwBitsPerSec,
    DWORD dwFlags)
{
    FH2_Log("QOS TRACE: XNetQosListen BEGIN xnc=%u xnkid=%08X data=%08X cb=%u bps=%u flags=0x%08X",
        (DWORD)xnc, (DWORD)pxnkid, (DWORD)pb, cb, dwBitsPerSec, dwFlags);

    if (pxnkid && FH2_IsReadableRange((DWORD)pxnkid, sizeof(XNKID)))
        FH2_NetDumpBuffer("QOS LISTEN XNKID", (PVOID)pxnkid, sizeof(XNKID));

    int result = g_FH2_XNetQosListen
        ? g_FH2_XNetQosListen(xnc, pxnkid, pb, cb, dwBitsPerSec, dwFlags)
        : SOCKET_ERROR;

    FH2_Log("QOS TRACE: XNetQosListen END result=%d wsaError=%d",
        result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    return result;
}

int NTAPI FH2_XNetQosLookupTrace(
    XNCALLER_TYPE xnc,
    DWORD cxna,
    const XNADDR* apxna[],
    const XNKID* apxnkid[],
    const XNKEY* apxnkey[],
    UINT cina,
    const IN_ADDR aina[],
    const DWORD adwServiceId[],
    DWORD dwBitsPerSec,
    DWORD dwFlags,
    WSAEVENT hEvent,
    XNQOS** ppxnqos)
{
    FH2_Log("QOS TRACE: XNetQosLookup BEGIN xnc=%u cxna=%u cina=%u bps=%u flags=0x%08X event=%08X out=%08X",
        (DWORD)xnc, cxna, (DWORD)cina, dwBitsPerSec, dwFlags, (DWORD)hEvent, (DWORD)ppxnqos);

    FH2_LogQosTargets(cxna, apxna, cina, aina, adwServiceId);

    int result = g_FH2_XNetQosLookup
        ? g_FH2_XNetQosLookup(xnc, cxna, apxna, apxnkid, apxnkey,
            cina, aina, adwServiceId, dwBitsPerSec, dwFlags, hEvent, ppxnqos)
        : SOCKET_ERROR;

    DWORD qos = 0;
    if (ppxnqos && MmIsAddressValid(ppxnqos))
        qos = (DWORD)(*ppxnqos);

    FH2_Log("QOS TRACE: XNetQosLookup END result=%d wsaError=%d qos=%08X",
        result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0, qos);

    if (qos && FH2_IsReadableRange(qos, 64))
        FH2_NetDumpBuffer("QOS RESULT INITIAL", (PVOID)qos, 64);

    return result;
}

int NTAPI FH2_XNetQosReleaseTrace(XNCALLER_TYPE xnc, XNQOS* pxnqos)
{
    FH2_Log("QOS TRACE: XNetQosRelease BEGIN xnc=%u qos=%08X", (DWORD)xnc, (DWORD)pxnqos);

    if (pxnqos && FH2_IsReadableRange((DWORD)pxnqos, 96))
        FH2_NetDumpBuffer("QOS RESULT FINAL", (PVOID)pxnqos, 96);

    int result = g_FH2_XNetQosRelease
        ? g_FH2_XNetQosRelease(xnc, pxnqos)
        : SOCKET_ERROR;

    FH2_Log("QOS TRACE: XNetQosRelease END result=%d wsaError=%d",
        result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    return result;
}


// -----------------------------------------------------------------------------
// FH2 v0.4.1: raw socket I/O diagnostics.
//
// v0.4.0 proved that the delayed Online Road Trip / Message Center failures do
// not pass through the QoS APIs we hooked.  The earlier network trace only
// covered socket creation/connect and XNet helpers; a title can still exchange
// traffic through an already-created UDP/TCP socket via send/recv/sendto/
// recvfrom (or the WSA variants) without ever calling connect during the user
// action.  Trace those I/O paths without changing buffers, destinations,
// return values, or errors.
// -----------------------------------------------------------------------------

static volatile LONG g_FH2_SocketIoTraceEvents = 0;

static BOOL FH2_SocketIoMayLog()
{
    // Keep a generous ceiling so a runaway background socket cannot grow the
    // log forever or stall the console.  The counter is per title launch.
    LONG n = ++g_FH2_SocketIoTraceEvents;
    if (n <= 2048)
        return TRUE;

    if (n == 2049)
        FH2_Log("SOCKET IO TRACE: event limit reached (2048); further socket I/O events suppressed.");
    return FALSE;
}

static VOID FH2_LogSockaddr(const CHAR* label, const sockaddr* sa, int saLen)
{
    if (!label)
        label = "endpoint";

    if (!sa || saLen < (int)sizeof(SOCKADDR_IN) || !MmIsAddressValid((PVOID)sa))
    {
        FH2_Log("SOCKET IO TRACE: %s ptr=%08X len=%d", label, (DWORD)sa, saLen);
        return;
    }

    const SOCKADDR_IN* in = (const SOCKADDR_IN*)sa;
    FH2_Log("SOCKET IO TRACE: %s family=%u addr=0x%08X portRaw=0x%04X len=%d",
        label, (DWORD)in->sin_family, in->sin_addr.S_un.S_addr,
        (DWORD)in->sin_port, saLen);
}

int NTAPI FH2_NetDll_sendTrace(XNCALLER_TYPE xnc, SOCKET s, const char* buf, int len, int flags)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
    {
        FH2_Log("SOCKET IO TRACE: send BEGIN xnc=%u socket=%d len=%d flags=0x%X",
            (DWORD)xnc, (int)s, len, flags);
        if (buf && len > 0)
            FH2_NetDumpBuffer("send payload", (PVOID)buf, (DWORD)len);
    }

    int result = NetDll_send(xnc, s, buf, len, flags);
    if (FH2_TrackHas((int)s))
    {
        FH2_SynthEvt(14, (DWORD)s, (DWORD)len, (DWORD)result, (DWORD)((result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0));
        FH2_TrackPayload(15, buf, len);
    }
    if (logIt)
        FH2_Log("SOCKET IO TRACE: send END socket=%d result=%d wsaError=%d",
            (int)s, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    return result;
}

int NTAPI FH2_NetDll_recvTrace(XNCALLER_TYPE xnc, SOCKET s, const char* buf, int len, int flags)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
        FH2_Log("SOCKET IO TRACE: recv BEGIN xnc=%u socket=%d len=%d flags=0x%X",
            (DWORD)xnc, (int)s, len, flags);

    int result = NetDll_recv(xnc, s, buf, len, flags);
    if (FH2_TrackHas((int)s))
    {
        FH2_SynthEvt(16, (DWORD)s, (DWORD)len, (DWORD)result, (DWORD)((result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0));
        if (result > 0) FH2_TrackPayload(17, buf, result);
    }

    if (logIt)
    {
        FH2_Log("SOCKET IO TRACE: recv END socket=%d result=%d wsaError=%d",
            (int)s, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
        if (result > 0 && buf)
            FH2_NetDumpBuffer("recv payload", (PVOID)buf, (DWORD)result);
    }
    return result;
}

int NTAPI FH2_NetDll_sendtoTrace(
    XNCALLER_TYPE xnc, SOCKET s, const VOID* buf, int len, int flags, VOID* to, int tolen)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
    {
        FH2_Log("SOCKET IO TRACE: sendto BEGIN xnc=%u socket=%d len=%d flags=0x%X",
            (DWORD)xnc, (int)s, len, flags);
        FH2_LogSockaddr("sendto destination", (const sockaddr*)to, tolen);
        if (buf && len > 0)
            FH2_NetDumpBuffer("sendto payload", (PVOID)buf, (DWORD)len);
    }

    int result = NetDll_sendto(xnc, s, buf, len, flags, to, tolen);
    FH2_TxNote(buf, (DWORD)len, to);
    FH2_CloseStackNote(buf, (DWORD)len, to);
    if (g_FH2LogEnabled) FH2_SendStackNote((DWORD)len, to);   // v1.0.34
    if ((LONG)len >= g_FH2BigMin && len < 0x10000 && buf && to && MmIsAddressValid((PVOID)to) && MmIsAddressValid((PVOID)((const BYTE*)to + 7)))
    {
        DWORD m = (DWORD)len < FH2_BIGBYTES ? (DWORD)len : FH2_BIGBYTES;
        if (MmIsAddressValid((PVOID)buf) && MmIsAddressValid((PVOID)((const BYTE*)buf + m - 1)))
        {
            const SOCKADDR_IN* in = (const SOCKADDR_IN*)to;
            FH2_BigPush(0, (DWORD)len, (DWORD)in->sin_addr.S_un.S_addr, (DWORD)in->sin_port, (const BYTE*)buf, m);
        }
    }
    FH2_P2PNote(g_FH2P2PSend, &g_FH2P2PSendN, to, len, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    if (logIt)
        FH2_Log("SOCKET IO TRACE: sendto END socket=%d result=%d wsaError=%d",
            (int)s, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    return result;
}

int NTAPI FH2_NetDll_recvfromTrace(
    XNCALLER_TYPE xnc, SOCKET s, const char* buf, int len, int flags, void* from, int fromlen)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
        FH2_Log("SOCKET IO TRACE: recvfrom BEGIN xnc=%u socket=%d len=%d flags=0x%X from=%08X fromlen=%d",
            (DWORD)xnc, (int)s, len, flags, (DWORD)from, fromlen);

    int result = NetDll_recvfrom(xnc, s, buf, len, flags, from, fromlen);
    {
        int rerr = (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0;
        FH2_P2PRecvOutcome(result, rerr, FALSE);
        if (result > 0) FH2_P2PNote(g_FH2P2PRecv, &g_FH2P2PRecvN, from, result, result, 0);
    }

    if (logIt)
    {
        FH2_Log("SOCKET IO TRACE: recvfrom END socket=%d result=%d wsaError=%d",
            (int)s, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
        if (from && fromlen >= (int)sizeof(SOCKADDR_IN))
            FH2_LogSockaddr("recvfrom source", (const sockaddr*)from, fromlen);
        if (result > 0 && buf)
            FH2_NetDumpBuffer("recvfrom payload", (PVOID)buf, (DWORD)result);
    }
    return result;
}

int NTAPI FH2_NetDll_WSASendTrace(
    XNCALLER_TYPE xnc, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
    {
        DWORD firstLen = 0;
        PVOID firstBuf = NULL;
        if (lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers))
        {
            firstLen = lpBuffers[0].len;
            firstBuf = lpBuffers[0].buf;
        }
        FH2_Log("SOCKET IO TRACE: WSASend BEGIN xnc=%u socket=%d buffers=%u firstLen=%u ov=%08X",
            (DWORD)xnc, (int)s, dwBufferCount, firstLen, (DWORD)lpOverlapped);
        if (firstBuf && firstLen)
            FH2_NetDumpBuffer("WSASend first buffer", firstBuf, firstLen);
    }

    int result = NetDll_WSASend(xnc, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpOverlapped, lpCompletionRoutine);
    if (FH2_TrackHas((int)s) && lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers))
    {
        FH2_SynthEvt(14, (DWORD)s, lpBuffers[0].len, (DWORD)result, 0x57534153);   // d='WSAS'
        FH2_TrackPayload(15, (const char*)lpBuffers[0].buf, (int)lpBuffers[0].len);
    }

    if (logIt)
    {
        DWORD sent = (lpNumberOfBytesSent && MmIsAddressValid(lpNumberOfBytesSent))
            ? *lpNumberOfBytesSent : 0xFFFFFFFF;
        FH2_Log("SOCKET IO TRACE: WSASend END socket=%d result=%d bytes=%u wsaError=%d",
            (int)s, result, sent, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    }
    return result;
}

int NTAPI FH2_NetDll_WSARecvTrace(
    XNCALLER_TYPE xnc, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
        FH2_Log("SOCKET IO TRACE: WSARecv BEGIN xnc=%u socket=%d buffers=%u ov=%08X",
            (DWORD)xnc, (int)s, dwBufferCount, (DWORD)lpOverlapped);

    int result = NetDll_WSARecv(xnc, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpOverlapped, lpCompletionRoutine);

    if (logIt)
    {
        DWORD recvd = (lpNumberOfBytesRecvd && MmIsAddressValid(lpNumberOfBytesRecvd))
            ? *lpNumberOfBytesRecvd : 0xFFFFFFFF;
        FH2_Log("SOCKET IO TRACE: WSARecv END socket=%d result=%d bytes=%u wsaError=%d",
            (int)s, result, recvd, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);

        if (result == 0 && recvd > 0 && recvd != 0xFFFFFFFF &&
            lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers) && lpBuffers[0].buf)
        {
            DWORD dumpLen = recvd < lpBuffers[0].len ? recvd : lpBuffers[0].len;
            FH2_NetDumpBuffer("WSARecv first buffer", lpBuffers[0].buf, dumpLen);
        }
    }
    return result;
}

int NTAPI FH2_NetDll_WSASendToTrace(
    XNCALLER_TYPE xnc, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iTolen,
    LPOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
    {
        DWORD firstLen = 0;
        PVOID firstBuf = NULL;
        if (lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers))
        {
            firstLen = lpBuffers[0].len;
            firstBuf = lpBuffers[0].buf;
        }
        FH2_Log("SOCKET IO TRACE: WSASendTo BEGIN xnc=%u socket=%d buffers=%u firstLen=%u ov=%08X",
            (DWORD)xnc, (int)s, dwBufferCount, firstLen, (DWORD)lpOverlapped);
        FH2_LogSockaddr("WSASendTo destination", lpTo, iTolen);
        if (firstBuf && firstLen)
            FH2_NetDumpBuffer("WSASendTo first buffer", firstBuf, firstLen);
    }

    int result = NetDll_WSASendTo(xnc, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent,
        dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
    {
        int wlen = 0;
        if (lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers)) wlen = (int)lpBuffers[0].len;
        FH2_P2PNote(g_FH2P2PSend, &g_FH2P2PSendN, lpTo, wlen, result, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
        FH2_TxNote((lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers)) ? (const VOID*)lpBuffers[0].buf : NULL, (DWORD)wlen, lpTo);
        FH2_CloseStackNote((lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers)) ? (const VOID*)lpBuffers[0].buf : NULL, (DWORD)wlen, lpTo);
        // v0.9.17: whole datagram (all WSABufs), first 96 bytes
        BYTE gb[FH2_BIGBYTES]; DWORD gtotal = 0;
        DWORD ghave = FH2_BigGather(lpBuffers, dwBufferCount, gb, &gtotal);
        if (g_FH2LogEnabled && ghave) FH2_SendStackNote(gtotal, lpTo);   // v1.0.34
        if (ghave && (LONG)gtotal >= g_FH2BigMin && lpTo && MmIsAddressValid((PVOID)lpTo) && MmIsAddressValid((PVOID)((const BYTE*)lpTo + 7)))
        {
            const SOCKADDR_IN* in = (const SOCKADDR_IN*)lpTo;
            FH2_BigPush(0, gtotal, (DWORD)in->sin_addr.S_un.S_addr, (DWORD)in->sin_port, gb, ghave);
        }
    }

    if (logIt)
    {
        DWORD sent = (lpNumberOfBytesSent && MmIsAddressValid(lpNumberOfBytesSent))
            ? *lpNumberOfBytesSent : 0xFFFFFFFF;
        FH2_Log("SOCKET IO TRACE: WSASendTo END socket=%d result=%d bytes=%u wsaError=%d",
            (int)s, result, sent, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
    }
    return result;
}

int NTAPI FH2_NetDll_WSARecvFromTrace(
    XNCALLER_TYPE xnc, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, sockaddr* lpFrom,
    LPINT lpFromlen, LPOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
    BOOL logIt = FH2_SocketIoMayLog();
    if (logIt)
        FH2_Log("SOCKET IO TRACE: WSARecvFrom BEGIN xnc=%u socket=%d buffers=%u ov=%08X",
            (DWORD)xnc, (int)s, dwBufferCount, (DWORD)lpOverlapped);

    FH2_RxOvBefore(lpOverlapped);   // v0.9.14: did the previous receive on this OVERLAPPED finish?
    int result = NetDll_WSARecvFrom(xnc, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd,
        lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    {
        int rerr = (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0;
        FH2_P2PRecvOutcome(result, rerr, TRUE);
        if (result == SOCKET_ERROR && rerr == 997) FH2_RxOvAfter(lpOverlapped, lpFrom, (lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers)) ? (DWORD)lpBuffers[0].buf : 0, (lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers)) ? (DWORD)lpBuffers[0].len : 0);
        if (result == 0 && lpNumberOfBytesRecvd && MmIsAddressValid(lpNumberOfBytesRecvd) && *lpNumberOfBytesRecvd > 0)
            FH2_P2PNote(g_FH2P2PRecv, &g_FH2P2PRecvN, lpFrom, (int)*lpNumberOfBytesRecvd, 0, 0);
    }

    if (logIt)
    {
        DWORD recvd = (lpNumberOfBytesRecvd && MmIsAddressValid(lpNumberOfBytesRecvd))
            ? *lpNumberOfBytesRecvd : 0xFFFFFFFF;
        int fromLen = (lpFromlen && MmIsAddressValid(lpFromlen)) ? *lpFromlen : 0;
        FH2_Log("SOCKET IO TRACE: WSARecvFrom END socket=%d result=%d bytes=%u wsaError=%d",
            (int)s, result, recvd, (result == SOCKET_ERROR) ? NetDll_WSAGetLastError() : 0);
        if (lpFrom && fromLen > 0)
            FH2_LogSockaddr("WSARecvFrom source", lpFrom, fromLen);

        if (result == 0 && recvd > 0 && recvd != 0xFFFFFFFF &&
            lpBuffers && dwBufferCount && MmIsAddressValid(lpBuffers) && lpBuffers[0].buf)
        {
            DWORD dumpLen = recvd < lpBuffers[0].len ? recvd : lpBuffers[0].len;
            FH2_NetDumpBuffer("WSARecvFrom first buffer", lpBuffers[0].buf, dumpLen);
        }
    }
    return result;
}


// -----------------------------------------------------------------------------
// FH2 v0.4.2: trace the XAM inter-app message path used by Xbox Live services.
//
// The v0.4.1 raw socket hooks were fully installed but stayed silent during the
// delayed Online Road Trip failure and Message Center hang.  Xbox 360 titles can
// hand high-level service work to XAM/XLiveBase/XGI through XMsg* instead of
// issuing socket calls directly from the title.  These hooks are observation
// only: the original XAM exports are always called and their results preserved.
// -----------------------------------------------------------------------------
typedef DWORD (WINAPI* pFH2_XMsgInProcessCall)(DWORD app, DWORD message, DWORD arg1, DWORD arg2);
typedef DWORD (WINAPI* pFH2_XMsgSystemProcessCall)(DWORD app, DWORD message, DWORD buffer, DWORD bufferLength);
typedef DWORD (WINAPI* pFH2_XMsgStartIORequest)(DWORD app, DWORD message, PXOVERLAPPED overlapped, DWORD buffer, DWORD bufferLength);
typedef DWORD (WINAPI* pFH2_XMsgCancelIORequest)(PXOVERLAPPED overlapped, DWORD wait);
typedef DWORD (WINAPI* pFH2_XamGetOverlappedResultMsg)(PXOVERLAPPED overlapped, PDWORD length, DWORD unknown);
typedef DWORD (WINAPI* pFH2_XMsgStartIORequestEx)(DWORD app, DWORD message, PXOVERLAPPED overlapped, DWORD buffer, DWORD bufferLength, DWORD unknown);

static pFH2_XMsgInProcessCall g_FH2_XMsgInProcessCall = NULL;
static pFH2_XMsgSystemProcessCall g_FH2_XMsgSystemProcessCall = NULL;
static pFH2_XMsgStartIORequest g_FH2_XMsgStartIORequest = NULL;
static pFH2_XMsgCancelIORequest g_FH2_XMsgCancelIORequest = NULL;
static pFH2_XamGetOverlappedResultMsg g_FH2_XamGetOverlappedResultMsg = NULL;
static pFH2_XMsgStartIORequestEx g_FH2_XMsgStartIORequestEx = NULL;

struct FH2_XMSG_TRACKED
{
    PXOVERLAPPED overlapped;
    DWORD app;
    DWORD message;
};

static FH2_XMSG_TRACKED g_FH2_XMsgTracked[32] = { 0 };
static volatile LONG g_FH2_XMsgTrackIndex = 0;
static volatile LONG g_FH2_XMsgTraceEvents = 0;

static BOOL FH2_XMsgAllowLog()
{
    LONG n = InterlockedIncrement(&g_FH2_XMsgTraceEvents);
    if (n <= 1024)
        return TRUE;
    if (n == 1025)
        FH2_Log("XMSG TRACE: event limit reached (1024); further XMsg events suppressed.");
    return FALSE;
}

static VOID FH2_XMsgTrack(PXOVERLAPPED overlapped, DWORD app, DWORD message)
{
    if (!overlapped)
        return;
    LONG i = InterlockedIncrement(&g_FH2_XMsgTrackIndex) - 1;
    DWORD slot = ((DWORD)i) & 31;
    g_FH2_XMsgTracked[slot].overlapped = overlapped;
    g_FH2_XMsgTracked[slot].app = app;
    g_FH2_XMsgTracked[slot].message = message;
}

static BOOL FH2_XMsgFind(PXOVERLAPPED overlapped, DWORD* app, DWORD* message)
{
    if (!overlapped)
        return FALSE;
    for (DWORD i = 0; i < 32; ++i)
    {
        if (g_FH2_XMsgTracked[i].overlapped == overlapped)
        {
            if (app) *app = g_FH2_XMsgTracked[i].app;
            if (message) *message = g_FH2_XMsgTracked[i].message;
            return TRUE;
        }
    }
    return FALSE;
}

DWORD WINAPI FH2_XMsgInProcessCallTrace(DWORD app, DWORD message, DWORD arg1, DWORD arg2)
{
    BOOL logIt = FH2_XMsgAllowLog();
    if (logIt)
        FH2_Log("XMSG TRACE: InProcess BEGIN app=0x%08X message=0x%08X arg1=0x%08X arg2=0x%08X", app, message, arg1, arg2);
    DWORD result = g_FH2_XMsgInProcessCall ? g_FH2_XMsgInProcessCall(app, message, arg1, arg2) : ERROR_INVALID_FUNCTION;
    if (logIt)
        FH2_Log("XMSG TRACE: InProcess END app=0x%08X message=0x%08X result=0x%08X", app, message, result);
    return result;
}

DWORD WINAPI FH2_XMsgSystemProcessCallTrace(DWORD app, DWORD message, DWORD buffer, DWORD bufferLength)
{
    BOOL logIt = FH2_XMsgAllowLog();
    if (logIt)
        FH2_Log("XMSG TRACE: SystemProcess BEGIN app=0x%08X message=0x%08X buffer=0x%08X len=%u", app, message, buffer, bufferLength);
    DWORD result = g_FH2_XMsgSystemProcessCall ? g_FH2_XMsgSystemProcessCall(app, message, buffer, bufferLength) : ERROR_INVALID_FUNCTION;
    if (logIt)
        FH2_Log("XMSG TRACE: SystemProcess END app=0x%08X message=0x%08X result=0x%08X", app, message, result);
    return result;
}

DWORD WINAPI FH2_XMsgStartIORequestTrace(DWORD app, DWORD message, PXOVERLAPPED overlapped, DWORD buffer, DWORD bufferLength)
{
    FH2_XMsgTrack(overlapped, app, message);
    BOOL logIt = FH2_XMsgAllowLog();
    if (logIt)
        FH2_Log("XMSG TRACE: StartIO BEGIN app=0x%08X message=0x%08X ov=0x%08X buffer=0x%08X len=%u", app, message, (DWORD)overlapped, buffer, bufferLength);
    DWORD result = g_FH2_XMsgStartIORequest ? g_FH2_XMsgStartIORequest(app, message, overlapped, buffer, bufferLength) : ERROR_INVALID_FUNCTION;
    if (logIt)
    {
        if (overlapped)
            FH2_Log("XMSG TRACE: StartIO END app=0x%08X message=0x%08X result=0x%08X ovLow=0x%08X ovHigh=0x%08X ext=0x%08X", app, message, result, (DWORD)overlapped->InternalLow, (DWORD)overlapped->InternalHigh, overlapped->dwExtendedError);
        else
            FH2_Log("XMSG TRACE: StartIO END app=0x%08X message=0x%08X result=0x%08X ov=<null>", app, message, result);
    }
    return result;
}

DWORD WINAPI FH2_XMsgStartIORequestExTrace(DWORD app, DWORD message, PXOVERLAPPED overlapped, DWORD buffer, DWORD bufferLength, DWORD unknown)
{
    FH2_XMsgTrack(overlapped, app, message);
    BOOL logIt = FH2_XMsgAllowLog();
    if (logIt)
        FH2_Log("XMSG TRACE: StartIOEx BEGIN app=0x%08X message=0x%08X ov=0x%08X buffer=0x%08X len=%u unknown=0x%08X", app, message, (DWORD)overlapped, buffer, bufferLength, unknown);
    DWORD result = g_FH2_XMsgStartIORequestEx ? g_FH2_XMsgStartIORequestEx(app, message, overlapped, buffer, bufferLength, unknown) : ERROR_INVALID_FUNCTION;
    if (logIt)
    {
        if (overlapped)
            FH2_Log("XMSG TRACE: StartIOEx END app=0x%08X message=0x%08X result=0x%08X ovLow=0x%08X ovHigh=0x%08X ext=0x%08X", app, message, result, (DWORD)overlapped->InternalLow, (DWORD)overlapped->InternalHigh, overlapped->dwExtendedError);
        else
            FH2_Log("XMSG TRACE: StartIOEx END app=0x%08X message=0x%08X result=0x%08X ov=<null>", app, message, result);
    }
    return result;
}

DWORD WINAPI FH2_XMsgCancelIORequestTrace(PXOVERLAPPED overlapped, DWORD wait)
{
    DWORD app = 0, message = 0;
    BOOL tracked = FH2_XMsgFind(overlapped, &app, &message);
    BOOL logIt = tracked && FH2_XMsgAllowLog();
    if (logIt)
        FH2_Log("XMSG TRACE: CancelIO BEGIN app=0x%08X message=0x%08X ov=0x%08X wait=%u", app, message, (DWORD)overlapped, wait);
    DWORD result = g_FH2_XMsgCancelIORequest ? g_FH2_XMsgCancelIORequest(overlapped, wait) : ERROR_INVALID_FUNCTION;
    if (logIt)
        FH2_Log("XMSG TRACE: CancelIO END app=0x%08X message=0x%08X result=0x%08X", app, message, result);
    return result;
}

DWORD WINAPI FH2_XamGetOverlappedResultMsgTrace(PXOVERLAPPED overlapped, PDWORD length, DWORD unknown)
{
    DWORD app = 0, message = 0;
    BOOL tracked = FH2_XMsgFind(overlapped, &app, &message);
    DWORD beforeLow = overlapped ? (DWORD)overlapped->InternalLow : 0;
    DWORD beforeHigh = overlapped ? (DWORD)overlapped->InternalHigh : 0;
    DWORD beforeExt = overlapped ? overlapped->dwExtendedError : 0;
    DWORD result = g_FH2_XamGetOverlappedResultMsg ? g_FH2_XamGetOverlappedResultMsg(overlapped, length, unknown) : ERROR_INVALID_FUNCTION;
    if (tracked && FH2_XMsgAllowLog())
    {
        FH2_Log("XMSG TRACE: GetOverlapped app=0x%08X message=0x%08X ov=0x%08X result=0x%08X len=%u beforeLow=0x%08X beforeHigh=0x%08X beforeExt=0x%08X afterLow=0x%08X afterHigh=0x%08X afterExt=0x%08X",
            app, message, (DWORD)overlapped, result, length ? *length : 0,
            beforeLow, beforeHigh, beforeExt,
            overlapped ? (DWORD)overlapped->InternalLow : 0,
            overlapped ? (DWORD)overlapped->InternalHigh : 0,
            overlapped ? overlapped->dwExtendedError : 0);
    }
    return result;
}

VOID SetupFH2XMsgTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c500 = FH2_CountModuleImport(module, "xam.xex", 500); // XMsgInProcessCall
    DWORD c501 = FH2_CountModuleImport(module, "xam.xex", 501); // XMsgCompleteIORequest
    DWORD c502 = FH2_CountModuleImport(module, "xam.xex", 502); // XMsgSystemProcessCall
    DWORD c503 = FH2_CountModuleImport(module, "xam.xex", 503); // XMsgStartIORequest
    DWORD c504 = FH2_CountModuleImport(module, "xam.xex", 504); // XMsgCancelIORequest
    DWORD c505 = FH2_CountModuleImport(module, "xam.xex", 505); // XMsgAcquireAsyncMessageFromOverlapped
    DWORD c506 = FH2_CountModuleImport(module, "xam.xex", 506); // XMsgReleaseAsyncMessageToOverlapped
    DWORD c507 = FH2_CountModuleImport(module, "xam.xex", 507); // XamGetOverlappedResult
    DWORD c508 = FH2_CountModuleImport(module, "xam.xex", 508); // XMsgStartIORequestEx

    FH2_Log("v0.4.2 XMSG IMPORTS: in500=%u complete501=%u system502=%u start503=%u cancel504=%u acquire505=%u release506=%u getOv507=%u startEx508=%u",
        c500, c501, c502, c503, c504, c505, c506, c507, c508);

    g_FH2_XMsgInProcessCall = (pFH2_XMsgInProcessCall)ResolveFunction("xam.xex", 500);
    g_FH2_XMsgSystemProcessCall = (pFH2_XMsgSystemProcessCall)ResolveFunction("xam.xex", 502);
    g_FH2_XMsgStartIORequest = (pFH2_XMsgStartIORequest)ResolveFunction("xam.xex", 503);
    g_FH2_XMsgCancelIORequest = (pFH2_XMsgCancelIORequest)ResolveFunction("xam.xex", 504);
    g_FH2_XamGetOverlappedResultMsg = (pFH2_XamGetOverlappedResultMsg)ResolveFunction("xam.xex", 507);
    g_FH2_XMsgStartIORequestEx = (pFH2_XMsgStartIORequestEx)ResolveFunction("xam.xex", 508);

    DWORD r500 = (c500 && g_FH2_XMsgInProcessCall) ? PatchModuleImport(module, "xam.xex", 500, (DWORD)FH2_XMsgInProcessCallTrace) : S_FALSE;
    DWORD r502 = (c502 && g_FH2_XMsgSystemProcessCall) ? PatchModuleImport(module, "xam.xex", 502, (DWORD)FH2_XMsgSystemProcessCallTrace) : S_FALSE;
    DWORD r503 = (c503 && g_FH2_XMsgStartIORequest) ? PatchModuleImport(module, "xam.xex", 503, (DWORD)FH2_XMsgStartIORequestTrace) : S_FALSE;
    DWORD r504 = (c504 && g_FH2_XMsgCancelIORequest) ? PatchModuleImport(module, "xam.xex", 504, (DWORD)FH2_XMsgCancelIORequestTrace) : S_FALSE;
    DWORD r507 = (c507 && g_FH2_XamGetOverlappedResultMsg) ? PatchModuleImport(module, "xam.xex", 507, (DWORD)FH2_XamGetOverlappedResultMsgTrace) : S_FALSE;
    DWORD r508 = (c508 && g_FH2_XMsgStartIORequestEx) ? PatchModuleImport(module, "xam.xex", 508, (DWORD)FH2_XMsgStartIORequestExTrace) : S_FALSE;

    FH2_Log("v0.4.2 XMSG hooks: in500=%08X system502=%08X start503=%08X cancel504=%08X getOv507=%08X startEx508=%08X",
        r500, r502, r503, r504, r507, r508);

    // Also map direct title-side callsites for the two asynchronous entry points.
    // If they are imported but still silent at runtime, these addresses give us
    // safe places to inspect in EmDbg without guessing at another network API.
    DWORD thunks[8] = { 0 };
    DWORD n503 = FH2_CollectModuleImportThunks(module, "xam.xex", 503, thunks, 8);
    for (DWORD i = 0; i < n503 && i < 8; ++i)
        FH2_ScanDirectBranchesToTargetDetailed(module, thunks[i], "XMsgStartIORequest");

    ZeroMemory(thunks, sizeof(thunks));
    DWORD n508 = FH2_CollectModuleImportThunks(module, "xam.xex", 508, thunks, 8);
    for (DWORD i = 0; i < n508 && i < 8; ++i)
        FH2_ScanDirectBranchesToTargetDetailed(module, thunks[i], "XMsgStartIORequestEx");
}


// -----------------------------------------------------------------------------
// FH2 v0.4.3: runtime session-object tracing.
//
// v0.4.2 proved that Online Road Trip and Message Center can enter their
// asynchronous "Please wait" states without hitting the title's imported raw
// socket, QoS, or XMsg entry points.  FH2 *does* import XamSessionCreateHandle
// and XamSessionRefObjByHandle and has concrete title-side callsites for them.
// The ABIs below are well-established: CreateHandle takes an output handle
// pointer, and RefObjByHandle takes a handle plus an output object pointer.
// These hooks are observation-only and always preserve the original result.
// -----------------------------------------------------------------------------
typedef DWORD (WINAPI* pFH2_XamSessionCreateHandle)(DWORD* handleOut);
typedef DWORD (WINAPI* pFH2_XamSessionRefObjByHandle)(DWORD handle, DWORD* objectOut);

static pFH2_XamSessionCreateHandle g_FH2_XamSessionCreateHandle = NULL;
static pFH2_XamSessionRefObjByHandle g_FH2_XamSessionRefObjByHandle = NULL;
static volatile LONG g_FH2_SessionTraceEvents = 0;
static BOOL g_FH2_SessionTraceLimitLogged = FALSE;

static BOOL FH2_SessionTraceMayLog()
{
    LONG n = InterlockedIncrement(&g_FH2_SessionTraceEvents);
    if (n <= 512)
        return TRUE;

    if (!g_FH2_SessionTraceLimitLogged)
    {
        g_FH2_SessionTraceLimitLogged = TRUE;
        FH2_Log("SESSION TRACE: event limit reached (512); further session events suppressed.");
    }
    return FALSE;
}

DWORD WINAPI FH2_XamSessionCreateHandleTrace(DWORD* handleOut)
{
    BOOL logIt = FH2_SessionTraceMayLog();
    DWORD before = 0xFFFFFFFF;
    if (handleOut && MmIsAddressValid(handleOut))
        before = *handleOut;

    if (logIt)
        FH2_Log("SESSION TRACE: CreateHandle BEGIN out=%08X before=%08X", (DWORD)handleOut, before);

    DWORD result = g_FH2_XamSessionCreateHandle
        ? g_FH2_XamSessionCreateHandle(handleOut)
        : ERROR_PROC_NOT_FOUND;

    DWORD after = 0xFFFFFFFF;
    if (handleOut && MmIsAddressValid(handleOut))
        after = *handleOut;

    if (logIt)
        FH2_Log("SESSION TRACE: CreateHandle END result=%08X out=%08X handle=%08X", result, (DWORD)handleOut, after);

    return result;
}

DWORD WINAPI FH2_XamSessionRefObjByHandleTrace(DWORD handle, DWORD* objectOut)
{
    BOOL logIt = FH2_SessionTraceMayLog();
    DWORD before = 0xFFFFFFFF;
    if (objectOut && MmIsAddressValid(objectOut))
        before = *objectOut;

    if (logIt)
        FH2_Log("SESSION TRACE: RefObj BEGIN handle=%08X out=%08X before=%08X", handle, (DWORD)objectOut, before);

    DWORD result = g_FH2_XamSessionRefObjByHandle
        ? g_FH2_XamSessionRefObjByHandle(handle, objectOut)
        : ERROR_PROC_NOT_FOUND;

    DWORD objectValue = 0xFFFFFFFF;
    if (objectOut && MmIsAddressValid(objectOut))
        objectValue = *objectOut;

    if (logIt)
        FH2_Log("SESSION TRACE: RefObj END handle=%08X result=%08X object=%08X", handle, result, objectValue);

    return result;
}

VOID SetupFH2SessionRuntimeTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c790 = FH2_CountModuleImport(module, "xam.xex", 790);
    DWORD c791 = FH2_CountModuleImport(module, "xam.xex", 791);

    g_FH2_XamSessionCreateHandle = (pFH2_XamSessionCreateHandle)ResolveFunction("xam.xex", 790);
    g_FH2_XamSessionRefObjByHandle = (pFH2_XamSessionRefObjByHandle)ResolveFunction("xam.xex", 791);

    DWORD r790 = (c790 && g_FH2_XamSessionCreateHandle)
        ? PatchModuleImport(module, "xam.xex", 790, (DWORD)FH2_XamSessionCreateHandleTrace) : S_FALSE;
    DWORD r791 = (c791 && g_FH2_XamSessionRefObjByHandle)
        ? PatchModuleImport(module, "xam.xex", 791, (DWORD)FH2_XamSessionRefObjByHandleTrace) : S_FALSE;

    FH2_Log("v0.4.3 SESSION IMPORTS: create790=%u ref791=%u", c790, c791);
    FH2_Log("v0.4.3 SESSION hooks: create790=%08X ref791=%08X", r790, r791);

    // Map every direct caller of the internal availability getter that v0.3.9
    // forces TRUE.  This tells us whether it is one isolated gate or shared by
    // several FH2 online flows without changing additional game code.
    FH2_Log("v0.4.3 INTERNAL GETTER CALLER MAP: scanning direct branches to 0x823F2870.");
    FH2_ScanDirectBranchesToTargetDetailed(module, 0x823F2870, "InternalAvailabilityGetter_823F2870");

    // XMsgCompleteIORequest (501) is imported, but its private ABI is not hooked
    // here.  Map title-side direct callsites only so we have concrete addresses
    // for EmDbg if session tracing is also silent.
    DWORD thunks[8] = { 0 };
    DWORD n501 = FH2_CollectModuleImportThunks(module, "xam.xex", 501, thunks, 8);
    FH2_Log("v0.4.3 XMSG COMPLETE MAP: ordinal501 thunks=%u", n501);
    for (DWORD i = 0; i < n501 && i < 8; ++i)
        FH2_ScanDirectBranchesToTargetDetailed(module, thunks[i], "XMsgCompleteIORequest");
}


// -----------------------------------------------------------------------------
// FH2 v0.8.2: narrow outbound/XAM provenance trace.
//
// Every wrapper captures the LR left by FH2's import call, logs it as the
// actual title-side caller, restores the original argument registers/stack,
// and tail-branches to the real pass-through implementation.
// -----------------------------------------------------------------------------

enum FH2_PROV_API
{
    FH2_PROV_SOCKET = 1,
    FH2_PROV_CONNECT,
    FH2_PROV_SEND,
    FH2_PROV_SENDTO,
    FH2_PROV_WSASEND,
    FH2_PROV_WSASENDTO,
    FH2_PROV_XNETCONNECT,
    FH2_PROV_XNETSERVERTOINADDR,
    FH2_PROV_XNETDNSLOOKUP,
    FH2_PROV_XAM_SESSION_CREATE,
    FH2_PROV_XAM_SESSION_REFOBJ,
    FH2_PROV_XAM_SEND_LOADED_APPS,
    FH2_PROV_XAM_APP_REQUEST_LOAD
};

static DWORD g_FH2_ProvXam583 = 0;
static DWORD g_FH2_ProvXam584 = 0;
static volatile LONG g_FH2_ProvEvents = 0;
struct FH2_PROV_RING { LONG seq; DWORD tick, api, caller; };
static FH2_PROV_RING g_FH2_ProvRing[128];
static volatile LONG g_FH2_ProvRingWrite = 0;
static LONG g_FH2_ProvRingRead = 0;

static const CHAR* FH2_ProvApiName(DWORD api)
{
    switch (api)
    {
    case FH2_PROV_SOCKET: return "socket";
    case FH2_PROV_CONNECT: return "connect";
    case FH2_PROV_SEND: return "send";
    case FH2_PROV_SENDTO: return "sendto";
    case FH2_PROV_WSASEND: return "WSASend";
    case FH2_PROV_WSASENDTO: return "WSASendTo";
    case FH2_PROV_XNETCONNECT: return "XNetConnect";
    case FH2_PROV_XNETSERVERTOINADDR: return "XNetServerToInAddr";
    case FH2_PROV_XNETDNSLOOKUP: return "XNetDnsLookup";
    case FH2_PROV_XAM_SESSION_CREATE: return "XamSessionCreateHandle";
    case FH2_PROV_XAM_SESSION_REFOBJ: return "XamSessionRefObjByHandle";
    case FH2_PROV_XAM_SEND_LOADED_APPS: return "XamSendMessageToLoadedApps";
    case FH2_PROV_XAM_APP_REQUEST_LOAD: return "XamAppRequestLoad";
    default: return "unknown";
    }
}

static DWORD FH2_ProvRecordAndGetForward(DWORD api, DWORD caller)
{
    LONG seq = InterlockedIncrement(&g_FH2_ProvEvents);
    // v0.8.4c: no file I/O on game threads (it silently lost lines); snapshot to a
    // ring that FH2_ProbeTick() flushes from the worker thread.
    {
        LONG w = InterlockedIncrement(&g_FH2_ProvRingWrite) - 1;
        FH2_PROV_RING& q = g_FH2_ProvRing[w & 127];
        q.seq = seq; q.tick = GetTickCount(); q.api = api; q.caller = caller;
    }

    switch (api)
    {
    case FH2_PROV_SOCKET:               return (DWORD)&FH2_NetDll_socketTrace;
    case FH2_PROV_CONNECT:              return (DWORD)&FH2_NetDll_connectTrace;
    case FH2_PROV_SEND:                 return (DWORD)&FH2_NetDll_sendTrace;
    case FH2_PROV_SENDTO:               return (DWORD)&FH2_NetDll_sendtoTrace;
    case FH2_PROV_WSASEND:              return (DWORD)&FH2_NetDll_WSASendTrace;
    case FH2_PROV_WSASENDTO:            return (DWORD)&FH2_NetDll_WSASendToTrace;
    case FH2_PROV_XNETCONNECT:          return (DWORD)&FH2_NetDll_XNetConnectTrace;
    case FH2_PROV_XNETSERVERTOINADDR:   return (DWORD)&FH2_NetDll_XNetServerToInAddrTrace;
    case FH2_PROV_XNETDNSLOOKUP:        return (DWORD)&FH2_NetDll_XNetDnsLookupTrace;
    case FH2_PROV_XAM_SESSION_CREATE:   return (DWORD)&FH2_XamSessionCreateHandleTrace;
    case FH2_PROV_XAM_SESSION_REFOBJ:   return (DWORD)&FH2_XamSessionRefObjByHandleTrace;
    case FH2_PROV_XAM_SEND_LOADED_APPS: return g_FH2_ProvXam583;
    case FH2_PROV_XAM_APP_REQUEST_LOAD: return g_FH2_ProvXam584;
    default:                            return 0;
    }
}

__declspec(naked) VOID FH2_ProvSocket()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 1
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvConnect()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 2
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvSend()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 3
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvSendTo()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 4
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvWSASend()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 5
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvWSASendTo()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 6
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXNetConnect()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 7
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXNetServerToInAddr()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 8
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXNetDnsLookup()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 9
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXamSessionCreate()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 10
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXamSessionRefObj()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 11
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXamSendLoadedApps()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 12
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProvXamAppRequestLoad()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 13
        mr      r4, r12
        bl      FH2_ProvRecordAndGetForward
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

BOOL SetupFH2ProvenanceTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
    if (!module)
        return FALSE;

    g_FH2_ProvEvents = 0;

    g_FH2_XamSessionCreateHandle =
        (pFH2_XamSessionCreateHandle)ResolveFunction("xam.xex", 790);
    g_FH2_XamSessionRefObjByHandle =
        (pFH2_XamSessionRefObjByHandle)ResolveFunction("xam.xex", 791);

    // Private ABI: wrappers only snapshot caller LR, then tail-forward untouched.
    g_FH2_ProvXam583 = (DWORD)ResolveFunction("xam.xex", 583);
    g_FH2_ProvXam584 = (DWORD)ResolveFunction("xam.xex", 584);

    struct FH2_PROV_IMPORT
    {
        DWORD ordinal;
        DWORD wrapper;
        const CHAR* name;
        DWORD forward;
    };

    FH2_PROV_IMPORT imports[] =
    {
        { 3,   (DWORD)&FH2_ProvSocket,             "socket",                     (DWORD)&FH2_NetDll_socketTrace },
        { 12,  (DWORD)&FH2_ProvConnect,            "connect",                    (DWORD)&FH2_NetDll_connectTrace },
        { 22,  (DWORD)&FH2_ProvSend,               "send",                       (DWORD)&FH2_NetDll_sendTrace },
        { 23,  (DWORD)&FH2_ProvWSASend,            "WSASend",                    (DWORD)&FH2_NetDll_WSASendTrace },
        { 24,  (DWORD)&FH2_ProvSendTo,             "sendto",                     (DWORD)&FH2_NetDll_sendtoTrace },
        { 25,  (DWORD)&FH2_ProvWSASendTo,          "WSASendTo",                  (DWORD)&FH2_NetDll_WSASendToTrace },
        { 58,  (DWORD)&FH2_ProvXNetServerToInAddr, "XNetServerToInAddr",         (DWORD)&FH2_NetDll_XNetServerToInAddrTrace },
        { 65,  (DWORD)&FH2_ProvXNetConnect,        "XNetConnect",                (DWORD)&FH2_NetDll_XNetConnectTrace },
        { 67,  (DWORD)&FH2_ProvXNetDnsLookup,      "XNetDnsLookup",              (DWORD)&FH2_NetDll_XNetDnsLookupTrace },
        { 583, (DWORD)&FH2_ProvXamSendLoadedApps,  "XamSendMessageToLoadedApps", g_FH2_ProvXam583 },
        { 584, (DWORD)&FH2_ProvXamAppRequestLoad,  "XamAppRequestLoad",          g_FH2_ProvXam584 },
        { 790, (DWORD)&FH2_ProvXamSessionCreate,   "XamSessionCreateHandle",     (DWORD)g_FH2_XamSessionCreateHandle },
        { 791, (DWORD)&FH2_ProvXamSessionRefObj,   "XamSessionRefObjByHandle",   (DWORD)g_FH2_XamSessionRefObjByHandle },
    };

    DWORD present = 0;
    DWORD installed = 0;

    for (DWORD i = 0; i < sizeof(imports) / sizeof(imports[0]); ++i)
    {
        if (g_FH2NoSess && (imports[i].ordinal == 790 || imports[i].ordinal == 791))
        {
            FH2_Log("PROVENANCE SETUP: api=%s ordinal=%u skipped (nosess)", imports[i].name, imports[i].ordinal);
            continue;
        }
        DWORD count = FH2_CountModuleImport(module, "xam.xex", imports[i].ordinal);
        if (!count)
        {
            FH2_Log("PROVENANCE SETUP: api=%s ordinal=%u imports=0",
                imports[i].name, imports[i].ordinal);
            continue;
        }

        ++present;
        if (!imports[i].forward)
        {
            FH2_Log("PROVENANCE SETUP: api=%s ordinal=%u imports=%u original=NULL; skipped",
                imports[i].name, imports[i].ordinal, count);
            continue;
        }

        DWORD result = PatchModuleImport(module, "xam.xex",
            imports[i].ordinal, imports[i].wrapper);

        FH2_Log("PROVENANCE SETUP: api=%s ordinal=%u imports=%u hook=0x%08X result=0x%08X",
            imports[i].name, imports[i].ordinal, count, imports[i].wrapper, result);

        if (result == S_OK)
            ++installed;
    }

    FH2_Log("v0.8.2 PROVENANCE hooks ready: present=%u installed=%u",
        present, installed);
    return installed != 0;
}


DWORD FH2_ProbeRecord(DWORD idx, DWORD caller, DWORD sp);

__declspec(naked) VOID FH2_ProbeWrap0()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 0
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap1()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 1
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap2()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 2
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap3()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 3
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap4()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 4
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap5()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 5
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap6()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 6
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap7()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 7
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap8()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 8
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap9()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 9
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap10()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 10
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap11()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 11
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap12()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 12
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap13()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 13
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap14()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 14
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap15()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 15
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

__declspec(naked) VOID FH2_ProbeWrap16()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        li      r3, 16
        mr      r4, r12
        mr      r5, r1
        bl      FH2_ProbeRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}


// -----------------------------------------------------------------------------
// FH2 v0.8.4: XAM message / enumerator probe.
// The v0.8.3 import census shows FH2 reaches Xbox Live services (title server
// enumeration, sessions, matchmaking) through XMsg*/XamEnumerate, not sockets.
// Each wrapper logs args + caller while a probe window is open, then tail-forwards.
// Window opens from the Road Trip tick when a playlist is selected.
// -----------------------------------------------------------------------------
volatile DWORD g_FH2ProbeUntilTick = 0;
volatile DWORD g_FH2ProbeOpenTick = 0;

struct FH2_PROBE_RING
{
    DWORD tick, idx, caller, a[6];
};
#define FH2_PROBE_RING_SIZE 1024
static FH2_PROBE_RING g_FH2ProbeRing[FH2_PROBE_RING_SIZE];
static volatile LONG g_FH2ProbeRingPos = 0;
static volatile LONG g_FH2EnumLogBudget = 60;

// v0.8.4c: FH2_Log() from game threads was silently losing lines, so hooks now
// only snapshot into this ring and the 500 ms worker (FH2_ProbeTick) logs it.
struct FH2_PROBE_RARE
{
    DWORD tick, idx, caller, a[6];
    DWORD dumpArg;          // which arg (index) was snapshotted, or 0xFFFFFFFF
    DWORD dumpAddr;
    DWORD dump[24];         // 96 bytes snapshot
    // v0.9.19: tracked XGI session calls (app 0xFB): sequence number and up to 4 pointer arguments with their 64-byte contents at call time.
    DWORD xseq, nptr;
    DWORD xptr[4];
    BYTE  xpre[4][64];
    // v1.0.10: return addresses of the calling game functions (stack walk) for tracked session calls.
    DWORD nchain;
    DWORD chain[8];
};
#define FH2_PROBE_RARE_SIZE 256
static FH2_PROBE_RARE g_FH2ProbeRare[FH2_PROBE_RARE_SIZE];
static volatile LONG g_FH2ProbeRareWrite = 0;   // next slot to write (monotonic)
static LONG g_FH2ProbeRareRead = 0;             // worker-only

// -----------------------------------------------------------------------------
// v0.8.5: synthetic title server.  The v0.8.4 probe showed FH2's title-server
// enumeration (XamCreateEnumeratorHandle msg 0x58039 + XamEnumerate) completes
// with no servers, so the game never has anything to connect to.  Like Sunrise
// does for Halo, hand the game one XTITLE_SERVER_INFO entry (g_FH2SynthIp).
// Hooks only write to g_FH2SynthEvt; FH2_ProbeTick() logs it from the worker.
// -----------------------------------------------------------------------------
typedef DWORD (NTAPI *pFH2_RealCreateEnum)(DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, PHANDLE);
typedef DWORD (NTAPI *pFH2_RealEnumerate)(HANDLE, DWORD, PVOID, DWORD, PDWORD, PXOVERLAPPED);
static pFH2_RealCreateEnum g_FH2RealCreateEnum = NULL;
static pFH2_RealEnumerate  g_FH2RealEnumerate = NULL;

#define FH2_SYNTH_HANDLES 8
static volatile DWORD g_FH2SynthHandle[FH2_SYNTH_HANDLES];
static volatile DWORD g_FH2SynthDone[FH2_SYNTH_HANDLES];
static volatile LONG  g_FH2SynthNext = 0;
static DWORD g_FH2SetupTick = 0;          // v0.8.9: when probe hooks were installed
static BOOL  g_FH2NetRestartDone = FALSE; // v0.8.9: one-shot XNet restart with security bypass
#define FH2_NET_RESTART_DELAY_MS 20000

struct FH2_SYNTH_EVT { DWORD tick, code, a, b, c, d; };
#define FH2_SYNTH_EVT_SIZE 512
static FH2_SYNTH_EVT g_FH2SynthEvt[FH2_SYNTH_EVT_SIZE];
static volatile LONG g_FH2SynthEvtWrite = 0;
static LONG g_FH2SynthEvtRead = 0;

static VOID FH2_SynthEvt(DWORD code, DWORD a, DWORD b, DWORD c, DWORD d)
{
    LONG w = InterlockedIncrement(&g_FH2SynthEvtWrite) - 1;
    FH2_SYNTH_EVT& e = g_FH2SynthEvt[w & (FH2_SYNTH_EVT_SIZE - 1)];
    e.tick = GetTickCount(); e.code = code; e.a = a; e.b = b; e.c = c; e.d = d;
}

// v0.8.10: optional FH2Revival.ini, next to the plugin.  Line 1: server IPv4
// (default 192.168.137.1).  Line 2 (optional): "norestart" to skip the v0.8.9 XNet restart.
// v0.8.17: app 0xFC msg 0x58042 enumeration (created around hopper selection, never completes:
// the console cannot reach real Live).  Complete it as an EMPTY result (ERROR_NO_MORE_FILES).
// Disable with the word 'noenum42' in FH2Revival.ini.
#define FH2_E42_HANDLES 8
static volatile DWORD g_FH2E42Handle[FH2_E42_HANDLES];
static volatile LONG  g_FH2E42Next = 0;
static BOOL g_FH2Enum42Enabled = TRUE;
static BOOL g_FH2SkipNetRestart = TRUE;   // v0.8.16: restart is now opt-in (line 2 'restart'); it killed the live socket
// v0.8.19: lobby state trace for all party-lobby transition classes.  Each class's Update() is a tiny state
// dispatcher (state word at this+OFF).  Retail addresses were derived from the beta symbols.  The vtable slots
// holding them are wrapped; a line is logged synchronously (so it survives a crash) whenever the state
// word of a transition object changes.  Class tags: HF=HostFindingPublicHopper (state@+1C), HS=HopperSelect
// (+10), HC=HostCreatingGameLobby (+1C), HO=Hosting (+10), CF=ClientFindingPublicHopper (+10),
// CN=Connecting (+14), CP=ConnectingToPublicHostedMatch (+10).
// Disable with the word 'notrace' in FH2Revival.ini.
typedef VOID (*FH2_Upd_t)(DWORD self);
static VOID FH2_TraceState(const char* tag, DWORD self, DWORD off, volatile DWORD* lastState, volatile DWORD* lastObj)
{
    if (self < 0x10000000 || !MmIsAddressValid((PVOID)self) || !MmIsAddressValid((PVOID)(self + 0x40)))
        return;
    volatile DWORD* w = (volatile DWORD*)self;
    DWORD st = w[off / 4];
    if (st == *lastState && self == *lastObj)
        return;
    *lastState = st;
    *lastObj = self;
    FH2_Log("v0.8.19 TRACE %s state=%u obj=0x%08X tick=%u  w: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
        tag, st, self, GetTickCount(), w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);
}
#define FH2_TRACE_CLASS(TAG, FN, OFF) \
    static volatile DWORD g_FH2Tr##TAG##S = 0xFFFFFFFF; \
    static volatile DWORD g_FH2Tr##TAG##O = 0; \
    static VOID FH2_Wrap##TAG(DWORD self) \
    { \
        FH2_TraceState(#TAG, self, OFF, &g_FH2Tr##TAG##S, &g_FH2Tr##TAG##O); \
        ((FH2_Upd_t)(FN))(self); \
    }
FH2_TRACE_CLASS(HF, 0x829EEF58, 0x1C)
FH2_TRACE_CLASS(HS, 0x82A00D90, 0x10)
FH2_TRACE_CLASS(HC, 0x82A04C00, 0x1C)
FH2_TRACE_CLASS(HO, 0x82A00490, 0x10)
FH2_TRACE_CLASS(CF, 0x82A04DD0, 0x10)
FH2_TRACE_CLASS(CN, 0x82A006C8, 0x14)
FH2_TRACE_CLASS(CP, 0x829EEFC8, 0x10)

static VOID FH2_PatchTraceSlot(const char* tag, DWORD slotAddr, DWORD expected, DWORD wrapper)
{
    volatile DWORD* slot = (volatile DWORD*)slotAddr;
    if (!MmIsAddressValid((PVOID)slot) || *slot != expected)
    {
        FH2_Log("v0.8.19 TRACE %s slot 0x%08X holds 0x%08X, expected 0x%08X: not installed", tag, slotAddr,
            MmIsAddressValid((PVOID)slot) ? *slot : 0, expected);
        return;
    }
    *slot = wrapper;
    FH2_Log("v0.8.19 TRACE %s installed: slot 0x%08X -> 0x%08X (readback 0x%08X)", tag, slotAddr, wrapper, *slot);
}

static VOID FH2_InstallStateTrace(BOOL enabled)
{
    if (!enabled)
    {
        FH2_Log("v0.8.19 config: state trace DISABLED");
        return;
    }
    FH2_PatchTraceSlot("HF", 0x8209C050, 0x829EEF58, (DWORD)FH2_WrapHF);
    FH2_PatchTraceSlot("HS", 0x8209D4A8, 0x82A00D90, (DWORD)FH2_WrapHS);
    FH2_PatchTraceSlot("HC", 0x8209D358, 0x82A04C00, (DWORD)FH2_WrapHC);
    FH2_PatchTraceSlot("HO", 0x8209D2A4, 0x82A00490, (DWORD)FH2_WrapHO);
    FH2_PatchTraceSlot("CF", 0x8209D3C8, 0x82A04DD0, (DWORD)FH2_WrapCF);
    FH2_PatchTraceSlot("CN", 0x8209D2DC, 0x82A006C8, (DWORD)FH2_WrapCN);
    FH2_PatchTraceSlot("CP", 0x8209C094, 0x829EEFC8, (DWORD)FH2_WrapCP);
}


// ---- v0.8.22 crash logger (opt-in: word "crashlog" in FH2Revival.ini) -------------------------------------
// Logs the first instructions of the kernel bugcheck routines (shows whether DashLaunch already patched them),
// and, if installed, replaces KeBugCheck/KeBugCheckEx with a hook that writes a stack scan to FH2Revival.log
// and then parks the thread (power-cycle the console afterwards).
static BOOL g_FH2CrashLogEnabled = FALSE;
static volatile LONG g_FH2CrashLogBusy = 0;

static VOID NTAPI FH2_CrashHook(DWORD code, DWORD p1, DWORD p2, DWORD p3, DWORD p4)
{
    if (InterlockedIncrement(&g_FH2CrashLogBusy) == 1)
    {
        DWORD marker = 0;
        DWORD sp = (DWORD)&marker;
        FH2_Log("v0.8.22 CRASH: bugcheck code=0x%08X p1=0x%08X p2=0x%08X p3=0x%08X p4=0x%08X sp=0x%08X",
            code, p1, p2, p3, p4, sp);
        DWORD found = 0;
        for (DWORD off = 0; off < 0x3000 && found < 80; off += 4)
        {
            DWORD addr = sp + off;
            if (!MmIsAddressValid((PVOID)addr)) break;
            DWORD v = *(DWORD*)addr;
            if (v >= 0x82000000 && v < 0x83700000 && (v & 3) == 0)
            {
                FH2_Log("v0.8.22 CRASH: stack+0x%04X = 0x%08X", off, v);
                ++found;
            }
        }
        FH2_Log("v0.8.22 CRASH: stack scan done (%u candidates); parking thread", found);
    }
    for (;;) { }
}

// v0.8.23: DashLaunch has patched HalReturnToFirmware with a plain jump to its own crash handler (readback in v0.8.22 logs).
// Chain: log + stack scan, then call DashLaunch's handler exactly as before.
static DWORD g_FH2HalOrig = 0;
static volatile LONG g_FH2HalBusy = 0;

static VOID NTAPI FH2_HalHook(DWORD routine)
{
    if (InterlockedIncrement(&g_FH2HalBusy) == 1)
    {
        DWORD marker = 0;
        DWORD sp = (DWORD)&marker;
        FH2_Log("v0.8.23 HAL: HalReturnToFirmware(%u) sp=0x%08X", routine, sp);
        DWORD found = 0;
        for (DWORD off = 0; off < 0x3000 && found < 80; off += 4)
        {
            DWORD addr = sp + off;
            if (!MmIsAddressValid((PVOID)addr)) break;
            DWORD v = *(DWORD*)addr;
            if (v >= 0x82000000 && v < 0x83700000 && (v & 3) == 0)
            {
                FH2_Log("v0.8.23 HAL: stack+0x%04X = 0x%08X", off, v);
                ++found;
            }
        }
        FH2_Log("v0.8.23 HAL: stack scan done (%u candidates); chaining to 0x%08X", found, g_FH2HalOrig);
    }
    InterlockedDecrement(&g_FH2HalBusy);
    typedef VOID (NTAPI *pHal)(DWORD);
    ((pHal)g_FH2HalOrig)(routine);
    for (;;) { }
}

static VOID FH2_InstallHalHook()
{
    DWORD* fn = (DWORD*)ResolveFunction("xboxkrnl.exe", 40);
    if (!fn || !MmIsAddressValid(fn)) { FH2_Log("v0.8.23 halhook: HalReturnToFirmware not resolvable"); return; }
    DWORD w0 = fn[0], w1 = fn[1], w2 = fn[2], w3 = fn[3];
    if ((w0 >> 16) == 0x3D60 && (w1 >> 16) == 0x396B && w2 == 0x7D6903A6 && w3 == 0x4E800420)
    {
        int lo = (short)(w1 & 0xFFFF);
        DWORD target = ((w0 & 0xFFFF) << 16) + (DWORD)lo;
        g_FH2HalOrig = target;
        FH2_Log("v0.8.23 halhook: DashLaunch jump found -> 0x%08X; installing chained hook", target);
        PatchInJump(fn, (DWORD)&FH2_HalHook, FALSE);
        for (DWORD o = 0; o < 16; o += 4) __dcbst(0, (void*)((DWORD)fn + o));
        __sync();
        typedef VOID (NTAPI *pSweep)(PVOID, DWORD);
        pSweep sweep = (pSweep)ResolveFunction("xboxkrnl.exe", 171);
        if (sweep) sweep((PVOID)fn, 16);
        __sync(); __isync();
        FH2_Log("v0.8.23 halhook: installed; readback %08X %08X %08X %08X", fn[0], fn[1], fn[2], fn[3]);
    }
    else
        FH2_Log("v0.8.23 halhook: HalReturnToFirmware not a plain jump (%08X %08X %08X %08X); not hooking", w0, w1, w2, w3);
}

// v0.8.24: HalReturnToFirmware hook never fired in v0.8.23, so the crash does not go through it.
// Register a title-terminate notification (supported kernel API, no patching) to see whether the
// kernel is terminating the title, and scan the stack for game return addresses.
static VOID FH2_DumpProbeTail();
static EX_TITLE_TERMINATE_REGISTRATION g_FH2TermReg;
static volatile LONG g_FH2TermBusy = 0;
static VOID NTAPI FH2_TermNotify()
{
    if (InterlockedIncrement(&g_FH2TermBusy) == 1)
    {
        DWORD local = 0;
        DWORD sp = (DWORD)&local;
        FH2_Log("v0.8.26 TERM: title terminate notification sp=0x%08X tick=%u thread=%u", sp, GetTickCount(), GetCurrentThreadId());
        DWORD found = 0, checked = 0;
        for (DWORD off = 0; off < 0x2000 && found < 120; off += 4)
        {
            DWORD addr = sp + off;
            if ((off & 0xFFF) == 0 && !MmIsAddressValid((PVOID)addr)) { FH2_Log("v0.8.26 TERM: stack+0x%04X not valid, stop", off); break; }
            if ((addr & 0xFFF) == 0 && off != 0 && !MmIsAddressValid((PVOID)addr)) break;
            DWORD v = *(DWORD*)addr;
            ++checked;
            // game code, kernel/xam text, plugin/DashLaunch code
            if ((v >= 0x80000000 && v < 0x83700000) || (v >= 0x90000000 && v < 0x92000000))
            { FH2_Log("v0.8.26 TERM: stack+0x%04X = 0x%08X", off, v); ++found; }
        }
        FH2_Log("v0.8.26 TERM: scan done (checked %u words, %u hits)", checked, found);
        FH2_DumpProbeTail();
    }
    InterlockedDecrement(&g_FH2TermBusy);
}

static VOID FH2_InstallTermNotify()
{
    memset(&g_FH2TermReg, 0, sizeof(g_FH2TermReg));
    g_FH2TermReg.NotificationRoutine = (void*)&FH2_TermNotify;
    g_FH2TermReg.Priority = 0x7C800000;
    ExRegisterTitleTerminateNotification(&g_FH2TermReg, TRUE);
    FH2_Log("v0.8.24 termnotify: registered");
}

static VOID FH2_ProbeCrashPathCandidates()
{
    struct Cand { const CHAR* mod; DWORD ord; const CHAR* name; };
    static const Cand c[] = {
        { "xboxkrnl.exe", 40,  "HalReturnToFirmware" },
        { "xboxkrnl.exe", 21,  "ExRegisterTitleTerminateNotification" },
        { "xam.xex",      425, "XamLoaderTerminateTitle" },
    };
    for (int i = 0; i < 3; ++i)
    {
        DWORD* fn = (DWORD*)ResolveFunction((CHAR*)c[i].mod, c[i].ord);
        if (!fn || !MmIsAddressValid(fn)) { FH2_Log("v0.8.22 cand: %s not resolvable", c[i].name); continue; }
        FH2_Log("v0.8.22 cand: %s @0x%08X first words %08X %08X %08X %08X", c[i].name, (DWORD)fn, fn[0], fn[1], fn[2], fn[3]);
    }
}

// v0.8.27: the "Fatal Crash Intercepted" popup is DashLaunch. Find every place DashLaunch patched the kernel/xam
// with its plain jump (lis r11 / addi r11 / mtctr r11 / bctr) so we can see which hook handles title exceptions.
static VOID FH2_ScanDashLaunchHooks()
{
    static const DWORD ranges[2][2] = { { 0x80000000, 0x80200000 }, { 0x815F0000, 0x81C00000 } };
    DWORD hits = 0;
    for (int r = 0; r < 2; ++r)
    {
        for (DWORD a = ranges[r][0]; a < ranges[r][1] && hits < 80; a += 4)
        {
            if ((a & 0xFFF) == 0 && !MmIsAddressValid((PVOID)a)) { a += 0xFFC; continue; }
            DWORD w0 = *(volatile DWORD*)a;
            if ((w0 >> 16) != 0x3D60) continue;
            DWORD hi = w0 & 0xFFFF;
            if (hi < 0x9000 || hi > 0x92FF) continue;
            if ((a & 0xFFF) > 0xFF0) continue;
            DWORD w1 = *(volatile DWORD*)(a + 4), w2 = *(volatile DWORD*)(a + 8), w3 = *(volatile DWORD*)(a + 12);
            if ((w1 >> 16) != 0x396B || w2 != 0x7D6903A6 || w3 != 0x4E800420) continue;
            DWORD target = (hi << 16) + (DWORD)(int)(short)(w1 & 0xFFFF);
            FH2_Log("v0.8.27 DLHOOK: 0x%08X -> 0x%08X", a, target);
            ++hits;
        }
    }
    FH2_Log("v0.8.27 DLHOOK: scan done, %u hooks", hits);
}

// v0.8.28: find the "Fatal Crash Intercepted" string in memory (ASCII or UTF-16) to learn which module shows it.
static VOID FH2_ScanCrashString()
{
    static const char pat[] = "Crash Intercepted";
    const int plen = 17;
    DWORD found = 0;
    for (DWORD page = 0x90000000; page < 0x92000000 && found < 6; page += 0x1000)
    {
        if (!MmIsAddressValid((PVOID)page)) continue;
        const unsigned char* p = (const unsigned char*)page;
        for (DWORD i = 0; i + 40 < 0x1000 && found < 6; ++i)
        {
            BOOL ascii = TRUE, wide = TRUE;
            for (int k = 0; k < plen && (ascii || wide); ++k)
            {
                if (p[i + k] != (unsigned char)pat[k]) ascii = FALSE;
                if (p[i + 2 * k] != 0 || p[i + 2 * k + 1] != (unsigned char)pat[k]) wide = FALSE;
            }
            if (!ascii && !wide) continue;
            // back up to the start of the surrounding text, then log 0x100 bytes as printable chars
            DWORD at = page + i;
            DWORD from = at - 0x60;
            CHAR line[0x90]; int n = 0;
            for (DWORD q = 0; q < 0x120 && n < 0x8C; ++q)
            {
                if (!MmIsAddressValid((PVOID)(from + q))) break;
                unsigned char c = *(volatile unsigned char*)(from + q);
                if (c >= 0x20 && c < 0x7F) line[n++] = (CHAR)c;
                else if (c == 0 && wide) continue;
                else if (n && line[n - 1] != '|') line[n++] = '|';
            }
            line[n] = 0;
            FH2_Log("v0.8.28 STR: %s at 0x%08X ctx: %s", ascii ? "ascii" : "utf16", at, line);
            ++found;
            i += 40;
        }
    }
    FH2_Log("v0.8.28 STR: scan done (%u)", found);
}

// v0.8.29: "Fatal Crash Intercepted!" lives in DashLaunch at 0x91F1A330 (v0.8.28). Dump DashLaunch's code that uses it
// and the heads of its kernel hook handlers, so the crash trigger can be read offline.
static VOID FH2_DumpWords(const CHAR* tag, DWORD addr, DWORD count)
{
    for (DWORD i = 0; i < count; i += 4)
    {
        DWORD a = addr + i * 4;
        if (!MmIsAddressValid((PVOID)a) || !MmIsAddressValid((PVOID)(a + 15))) return;
        volatile DWORD* w = (volatile DWORD*)a;
        FH2_Log("v0.8.29 DUMP %s %08X: %08X %08X %08X %08X", tag, a, w[0], w[1], w[2], w[3]);
    }
}

static VOID FH2_DumpDashLaunchCrash()
{
    // handlers behind DashLaunch's kernel jumps (v0.8.27 scan)
    static const DWORD heads[] = { 0x91F05C30, 0x91F05D98, 0x91F07F30, 0x91F08030 };
    for (int h = 0; h < 4; ++h) FH2_DumpWords("head", heads[h], 24);

    // find lis rX,0x91F1 followed (within 3 words) by addi/ori giving 0xA330 -> code that uses the popup text
    DWORD refs = 0;
    for (DWORD a = 0x91F00000; a < 0x91F20000 && refs < 4; a += 4)
    {
        if (!MmIsAddressValid((PVOID)a)) { a = (a | 0xFFF); continue; }
        DWORD w = *(volatile DWORD*)a;
        if ((w >> 26) != 15 || (w & 0xFFFF) != 0x91F2) continue;            // lis rX, 0x91F2 (A330 sign-extends negative)
        for (DWORD k = 1; k <= 3; ++k)
        {
            if (!MmIsAddressValid((PVOID)(a + 4 * k))) break;
            DWORD v = *(volatile DWORD*)(a + 4 * k);
            if ((v & 0xFFFF) == 0xA330 && ((v >> 26) == 14 || (v >> 26) == 24))
            {
                FH2_Log("v0.8.29 REF: popup text referenced at 0x%08X", a);
                FH2_DumpWords("ref", a - 0x100, 80);
                ++refs;
                break;
            }
        }
    }
    FH2_Log("v0.8.29 REF: done (%u)", refs);
}

// v0.8.30: DashLaunch hooks the kernel exception path at 0x8015B720 (handler 0x91F05C30): its r4 is an exception record
// (it compares word 0 with 0x80000003). Chain in front of it and log what it is handed, so a fatal exception shows its
// code/address even though DashLaunch swallows it. r3..r6 and the caller LR are passed through untouched.
static DWORD g_FH2ExcOrig = 0;
static volatile LONG g_FH2ExcCount = 0;
static volatile LONG g_FH2ExcBusy = 0;

DWORD FH2_ExcRecord(DWORD a3, DWORD a4, DWORD a5, DWORD a6, DWORD callerLr)
{
    LONG n = InterlockedIncrement(&g_FH2ExcCount);
    if (n <= 60 && InterlockedIncrement(&g_FH2ExcBusy) == 1)
    {
        FH2_Log("v0.8.30 EXC #%d: lr=0x%08X r3=%08X r4=%08X r5=%08X r6=%08X tick=%u", n, callerLr, a3, a4, a5, a6, GetTickCount());
        if (a4 >= 0x10000 && (a4 & 3) == 0 && MmIsAddressValid((PVOID)a4) && MmIsAddressValid((PVOID)(a4 + 0x3F)))
        {
            volatile DWORD* w = (volatile DWORD*)a4;
            FH2_Log("v0.8.30 EXC #%d rec r4: %08X %08X %08X %08X %08X %08X %08X %08X", n, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            FH2_Log("v0.8.30 EXC #%d rec r4+20: %08X %08X %08X %08X %08X %08X %08X %08X", n, w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);
        }
        if (a5 >= 0x10000 && (a5 & 3) == 0 && MmIsAddressValid((PVOID)a5) && MmIsAddressValid((PVOID)(a5 + 0x7F)))
        {
            volatile DWORD* w = (volatile DWORD*)a5;
            for (int r = 0; r < 4; ++r)
                FH2_Log("v0.8.30 EXC #%d ctx r5+%02X: %08X %08X %08X %08X %08X %08X %08X %08X", n, r * 32,
                    w[r*8], w[r*8+1], w[r*8+2], w[r*8+3], w[r*8+4], w[r*8+5], w[r*8+6], w[r*8+7]);
        }
        if (a3 >= 0x10000 && (a3 & 3) == 0 && MmIsAddressValid((PVOID)a3) && MmIsAddressValid((PVOID)(a3 + 0x1F)))
        {
            volatile DWORD* w = (volatile DWORD*)a3;
            FH2_Log("v0.8.30 EXC #%d obj r3: %08X %08X %08X %08X %08X %08X %08X %08X", n, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
        }
    }
    InterlockedDecrement(&g_FH2ExcBusy);
    return g_FH2ExcOrig;
}

__declspec(naked) VOID FH2_ExcWrap()
{
    __asm
    {
        mflr    r12
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
        stw     r12, 0x4C(r1)
        mfctr   r0
        stw     r0,  0x50(r1)
        mfxer   r0
        stw     r0,  0x54(r1)

        mr      r7, r12
        bl      FH2_ExcRecord
        stw     r3,  0x58(r1)

        lwz     r0,  0x54(r1)
        mtxer   r0
        lwz     r0,  0x50(r1)
        mtctr   r0
        lwz     r12, 0x4C(r1)
        mtlr    r12

        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        lwz     r11, 0x44(r1)
        lwz     r0,  0x20(r1)
        lwz     r12, 0x58(r1)
        addi    r1, r1, 0xA0

        mtctr   r12
        bctr
    }
}

static VOID FH2_InstallExcHook()
{
    DWORD* fn = (DWORD*)0x8015B720;
    if (!MmIsAddressValid(fn)) { FH2_Log("v0.8.30 exchook: 0x8015B720 not valid"); return; }
    DWORD w0 = fn[0], w1 = fn[1], w2 = fn[2], w3 = fn[3];
    if ((w0 >> 16) == 0x3D60 && (w1 >> 16) == 0x396B && w2 == 0x7D6903A6 && w3 == 0x4E800420)
    {
        DWORD target = ((w0 & 0xFFFF) << 16) + (DWORD)(int)(short)(w1 & 0xFFFF);
        if (target != 0x91F05C30) { FH2_Log("v0.8.30 exchook: unexpected target 0x%08X; not hooking", target); return; }
        g_FH2ExcOrig = target;
        PatchInJump(fn, (DWORD)&FH2_ExcWrap, FALSE);
        for (DWORD o = 0; o < 16; o += 4) __dcbst(0, (void*)((DWORD)fn + o));
        __sync();
        typedef VOID (NTAPI *pSweep)(PVOID, DWORD);
        pSweep sweep = (pSweep)ResolveFunction("xboxkrnl.exe", 171);
        if (sweep) sweep((PVOID)fn, 16);
        __sync(); __isync();
        FH2_Log("v0.8.30 exchook: installed at 0x8015B720 -> chain 0x%08X; readback %08X %08X %08X %08X", target, fn[0], fn[1], fn[2], fn[3]);
    }
    else
        FH2_Log("v0.8.30 exchook: 0x8015B720 not a DashLaunch jump (%08X %08X %08X %08X); not hooking", w0, w1, w2, w3);
}

static VOID FH2_InstallCrashLog()
{
    FH2_ProbeCrashPathCandidates();
    if (g_FH2CrashLogEnabled) { FH2_InstallExcHook(); FH2_InstallHalHook(); FH2_InstallTermNotify(); }
    static const DWORD ords[2] = { 82, 83 };
    static const CHAR* names[2] = { "KeBugCheck", "KeBugCheckEx" };
    for (int i = 0; i < 2; ++i)
    {
        DWORD* fn = (DWORD*)ResolveFunction("xboxkrnl.exe", ords[i]);
        if (!fn || !MmIsAddressValid(fn))
        {
            FH2_Log("v0.8.22 crashlog: %s (ordinal %u) not resolvable", names[i], ords[i]);
            continue;
        }
        FH2_Log("v0.8.22 crashlog: %s @0x%08X first words %08X %08X %08X %08X %08X %08X",
            names[i], (DWORD)fn, fn[0], fn[1], fn[2], fn[3], fn[4], fn[5]);
        if (g_FH2CrashLogEnabled)
        {
            PatchInJump(fn, (DWORD)&FH2_CrashHook, FALSE);
            // v0.8.22: make the patch visible to instruction fetch (kernel code is hot in the I-cache)
            for (DWORD o = 0; o < 16; o += 4)
                __dcbst(0, (void*)((DWORD)fn + o));
            __sync();
            typedef VOID (NTAPI *pFH2_KeSweepIcacheRange)(PVOID, DWORD);
            pFH2_KeSweepIcacheRange sweep = (pFH2_KeSweepIcacheRange)ResolveFunction("xboxkrnl.exe", 171);
            if (sweep)
            {
                sweep((PVOID)fn, 16);
                FH2_Log("v0.8.22 crashlog: %s I-cache swept", names[i]);
            }
            else
                FH2_Log("v0.8.22 crashlog: KeSweepIcacheRange not resolvable");
            __sync();
            __isync();
            FH2_Log("v0.8.22 crashlog: %s hooked; readback %08X %08X %08X %08X", names[i], fn[0], fn[1], fn[2], fn[3]);
        }
    }
}

static BOOL g_FH2TraceEnabled = TRUE;
// v0.9.0: the revival server address is compiled in (lightly obfuscated), so no FH2Synth.txt is needed.
// FH2Synth.txt, if present, is an optional override/debug file: "real=a.b.c.d" replaces the server (real=0.0.0.0 disables the
// redirect, for a server on the same LAN), "log" enables FH2Revival.log, "crashlog" also installs crash diagnostics.
// The revival server address is not in the public source: Sunrise2/ServerAddress.h ships with no server (0).
// Put your own address in it locally (see readmes/BUILDING.md), or set ServerIp in FH2Revival.ini.
#include "ServerAddress.h"

// ===== v1.0.48: FH2Revival.ini (replaces FH2Synth.txt) =============================================================================
// The plugin keeps its internal "word" switches (strstr on one buffer).  FH2Revival.ini is turned into that same word buffer, so every
// existing switch keeps working exactly as before.  If FH2Revival.ini is missing the plugin falls back to an old FH2Synth.txt (read exactly as
// before, first 127 bytes, no new defaults); if neither exists it writes a default FH2Revival.ini and runs on the defaults.
static const BYTE g_FH2DefaultIni[2870] =
{
    0x3B, 0x20, 0x46, 0x48, 0x32, 0x52, 0x65, 0x76, 0x69, 0x76, 0x61, 0x6C, 0x2E, 0x69, 0x6E, 0x69,
    0x20, 0x2D, 0x20, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x46, 0x48, 0x32, 0x20, 0x52, 0x65, 0x76, 0x69, 0x76, 0x61, 0x6C, 0x20,
    0x70, 0x6C, 0x75, 0x67, 0x69, 0x6E, 0x20, 0x28, 0x72, 0x65, 0x70, 0x6C, 0x61, 0x63, 0x65, 0x73,
    0x20, 0x46, 0x48, 0x32, 0x53, 0x79, 0x6E, 0x74, 0x68, 0x2E, 0x74, 0x78, 0x74, 0x29, 0x2E, 0x0D,
    0x0A, 0x3B, 0x20, 0x4B, 0x65, 0x65, 0x70, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x66, 0x69, 0x6C,
    0x65, 0x20, 0x6E, 0x65, 0x78, 0x74, 0x20, 0x74, 0x6F, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x6C,
    0x75, 0x67, 0x69, 0x6E, 0x20, 0x28, 0x74, 0x68, 0x65, 0x20, 0x73, 0x61, 0x6D, 0x65, 0x20, 0x66,
    0x6F, 0x6C, 0x64, 0x65, 0x72, 0x20, 0x46, 0x48, 0x32, 0x53, 0x79, 0x6E, 0x74, 0x68, 0x2E, 0x74,
    0x78, 0x74, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6C, 0x69, 0x76, 0x65, 0x20,
    0x69, 0x6E, 0x29, 0x2E, 0x0D, 0x0A, 0x3B, 0x20, 0x45, 0x76, 0x65, 0x72, 0x79, 0x20, 0x6B, 0x65,
    0x79, 0x20, 0x69, 0x73, 0x20, 0x6F, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x61, 0x6C, 0x3A, 0x20, 0x61,
    0x20, 0x6D, 0x69, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x6B, 0x65, 0x79, 0x20, 0x75, 0x73, 0x65,
    0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x20, 0x73, 0x68,
    0x6F, 0x77, 0x6E, 0x20, 0x68, 0x65, 0x72, 0x65, 0x2C, 0x20, 0x73, 0x6F, 0x20, 0x79, 0x6F, 0x75,
    0x20, 0x6F, 0x6E, 0x6C, 0x79, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6C,
    0x69, 0x6E, 0x65, 0x73, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20, 0x74, 0x6F,
    0x20, 0x63, 0x68, 0x61, 0x6E, 0x67, 0x65, 0x2E, 0x0D, 0x0A, 0x3B, 0x20, 0x56, 0x61, 0x6C, 0x75,
    0x65, 0x73, 0x3A, 0x20, 0x74, 0x72, 0x75, 0x65, 0x20, 0x2F, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65,
    0x20, 0x28, 0x61, 0x6C, 0x73, 0x6F, 0x20, 0x6F, 0x6E, 0x2F, 0x6F, 0x66, 0x66, 0x2C, 0x20, 0x79,
    0x65, 0x73, 0x2F, 0x6E, 0x6F, 0x2C, 0x20, 0x31, 0x2F, 0x30, 0x29, 0x2E, 0x20, 0x20, 0x4C, 0x69,
    0x6E, 0x65, 0x73, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x77, 0x69, 0x74,
    0x68, 0x20, 0x3B, 0x20, 0x61, 0x72, 0x65, 0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x65, 0x6E, 0x74, 0x73,
    0x2E, 0x0D, 0x0A, 0x3B, 0x20, 0x49, 0x66, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x66, 0x69, 0x6C,
    0x65, 0x20, 0x69, 0x73, 0x20, 0x6D, 0x69, 0x73, 0x73, 0x69, 0x6E, 0x67, 0x20, 0x74, 0x68, 0x65,
    0x20, 0x70, 0x6C, 0x75, 0x67, 0x69, 0x6E, 0x20, 0x77, 0x72, 0x69, 0x74, 0x65, 0x73, 0x20, 0x61,
    0x20, 0x66, 0x72, 0x65, 0x73, 0x68, 0x20, 0x63, 0x6F, 0x70, 0x79, 0x20, 0x77, 0x69, 0x74, 0x68,
    0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x73, 0x20, 0x62, 0x65,
    0x6C, 0x6F, 0x77, 0x2E, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B, 0x4F, 0x50, 0x54, 0x49, 0x4F, 0x4E, 0x53,
    0x5D, 0x0D, 0x0A, 0x3B, 0x20, 0x50, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x73, 0x20, 0x57, 0x49, 0x54,
    0x48, 0x4F, 0x55, 0x54, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x6C, 0x75, 0x67, 0x69, 0x6E, 0x20,
    0x63, 0x61, 0x6E, 0x20, 0x6A, 0x6F, 0x69, 0x6E, 0x20, 0x6C, 0x6F, 0x62, 0x62, 0x69, 0x65, 0x73,
    0x20, 0x79, 0x6F, 0x75, 0x20, 0x68, 0x6F, 0x73, 0x74, 0x20, 0x2D, 0x20, 0x74, 0x68, 0x65, 0x72,
    0x65, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x20, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6E, 0x67, 0x20,
    0x66, 0x6F, 0x72, 0x20, 0x74, 0x68, 0x61, 0x74, 0x2C, 0x20, 0x69, 0x74, 0x20, 0x6A, 0x75, 0x73,
    0x74, 0x20, 0x77, 0x6F, 0x72, 0x6B, 0x73, 0x2E, 0x0D, 0x0A, 0x3B, 0x20, 0x53, 0x68, 0x6F, 0x77,
    0x73, 0x20, 0x61, 0x20, 0x70, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x20, 0x6F, 0x6E, 0x20, 0x74,
    0x68, 0x65, 0x20, 0x46, 0x45, 0x53, 0x54, 0x49, 0x56, 0x41, 0x4C, 0x20, 0x74, 0x69, 0x6C, 0x65,
    0x20, 0x69, 0x6E, 0x20, 0x6F, 0x6E, 0x6C, 0x69, 0x6E, 0x65, 0x20, 0x72, 0x6F, 0x61, 0x64, 0x20,
    0x74, 0x72, 0x69, 0x70, 0x20, 0x6C, 0x6F, 0x62, 0x62, 0x69, 0x65, 0x73, 0x20, 0x2F, 0x20, 0x64,
    0x65, 0x73, 0x74, 0x69, 0x6E, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x76, 0x6F, 0x74, 0x65, 0x20,
    0x28, 0x74, 0x68, 0x65, 0x20, 0x67, 0x61, 0x6D, 0x65, 0x20, 0x73, 0x68, 0x69, 0x70, 0x73, 0x20,
    0x77, 0x69, 0x74, 0x68, 0x6F, 0x75, 0x74, 0x20, 0x6F, 0x6E, 0x65, 0x2C, 0x20, 0x73, 0x6F, 0x20,
    0x69, 0x74, 0x20, 0x77, 0x61, 0x73, 0x20, 0x62, 0x6C, 0x61, 0x63, 0x6B, 0x29, 0x2E, 0x0D, 0x0A,
    0x46, 0x69, 0x78, 0x46, 0x65, 0x73, 0x74, 0x69, 0x76, 0x61, 0x6C, 0x54, 0x69, 0x6C, 0x65, 0x20,
    0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x3B, 0x20, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72,
    0x65, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x46,
    0x65, 0x73, 0x74, 0x69, 0x76, 0x61, 0x6C, 0x20, 0x74, 0x69, 0x6C, 0x65, 0x2E, 0x20, 0x49, 0x74,
    0x20, 0x6D, 0x75, 0x73, 0x74, 0x20, 0x65, 0x78, 0x69, 0x73, 0x74, 0x20, 0x69, 0x6E, 0x20, 0x65,
    0x76, 0x65, 0x72, 0x79, 0x20, 0x44, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x61, 0x74, 0x69, 0x6F, 0x6E,
    0x49, 0x6D, 0x61, 0x67, 0x65, 0x73, 0x20, 0x73, 0x69, 0x7A, 0x65, 0x3B, 0x20, 0x72, 0x65, 0x61,
    0x6C, 0x20, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6E, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x61,
    0x6C, 0x77, 0x61, 0x79, 0x73, 0x20, 0x64, 0x6F, 0x0D, 0x0A, 0x3B, 0x20, 0x28, 0x4E, 0x69, 0x63,
    0x65, 0x4D, 0x61, 0x73, 0x73, 0x65, 0x6E, 0x61, 0x2C, 0x20, 0x53, 0x69, 0x73, 0x74, 0x65, 0x72,
    0x6F, 0x6E, 0x2C, 0x20, 0x53, 0x61, 0x69, 0x6E, 0x74, 0x4D, 0x61, 0x72, 0x74, 0x69, 0x6E, 0x2C,
    0x20, 0x43, 0x61, 0x73, 0x74, 0x65, 0x6C, 0x6C, 0x65, 0x74, 0x74, 0x6F, 0x2C, 0x20, 0x4D, 0x6F,
    0x6E, 0x74, 0x65, 0x6C, 0x6C, 0x69, 0x6E, 0x6F, 0x2C, 0x20, 0x53, 0x61, 0x6E, 0x47, 0x69, 0x6D,
    0x69, 0x67, 0x6E, 0x61, 0x6E, 0x6F, 0x29, 0x2E, 0x0D, 0x0A, 0x46, 0x65, 0x73, 0x74, 0x69, 0x76,
    0x61, 0x6C, 0x50, 0x69, 0x63, 0x74, 0x75, 0x72, 0x65, 0x20, 0x3D, 0x20, 0x4E, 0x69, 0x63, 0x65,
    0x4D, 0x61, 0x73, 0x73, 0x65, 0x6E, 0x61, 0x0D, 0x0A, 0x3B, 0x20, 0x53, 0x65, 0x6E, 0x64, 0x73,
    0x20, 0x79, 0x6F, 0x75, 0x72, 0x20, 0x6C, 0x65, 0x76, 0x65, 0x6C, 0x2C, 0x20, 0x62, 0x61, 0x64,
    0x67, 0x65, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x74, 0x69, 0x74, 0x6C, 0x65, 0x20, 0x74, 0x6F, 0x20,
    0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x68, 0x6F, 0x72, 0x74,
    0x6C, 0x79, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x63, 0x6F, 0x6E,
    0x6E, 0x65, 0x63, 0x74, 0x20, 0x28, 0x6C, 0x65, 0x61, 0x64, 0x65, 0x72, 0x62, 0x6F, 0x61, 0x72,
    0x64, 0x20, 0x2F, 0x20, 0x66, 0x72, 0x69, 0x65, 0x6E, 0x64, 0x73, 0x20, 0x73, 0x68, 0x6F, 0x77,
    0x20, 0x74, 0x68, 0x65, 0x6D, 0x29, 0x2E, 0x0D, 0x0A, 0x50, 0x75, 0x73, 0x68, 0x50, 0x6C, 0x61,
    0x79, 0x65, 0x72, 0x43, 0x61, 0x72, 0x64, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A,
    0x3B, 0x20, 0x47, 0x69, 0x76, 0x65, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x67, 0x61, 0x6D, 0x65,
    0x20, 0x6C, 0x6F, 0x6E, 0x67, 0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x73, 0x65, 0x74, 0x20, 0x75,
    0x70, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x73, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x6A,
    0x6F, 0x69, 0x6E, 0x73, 0x20, 0x28, 0x34, 0x30, 0x20, 0x73, 0x20, 0x2D, 0x3E, 0x20, 0x36, 0x35,
    0x20, 0x73, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x73, 0x69, 0x6D, 0x69, 0x6C, 0x61, 0x72, 0x29, 0x2E,
    0x20, 0x4B, 0x65, 0x65, 0x70, 0x20, 0x6F, 0x6E, 0x2E, 0x0D, 0x0A, 0x53, 0x65, 0x73, 0x73, 0x69,
    0x6F, 0x6E, 0x54, 0x69, 0x6D, 0x65, 0x6F, 0x75, 0x74, 0x50, 0x61, 0x74, 0x63, 0x68, 0x20, 0x3D,
    0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x3B, 0x20, 0x41, 0x64, 0x64, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x58, 0x4E, 0x65, 0x74, 0x20, 0x22, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x73,
    0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x22, 0x20, 0x66, 0x6C, 0x61, 0x67, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x72, 0x65, 0x76, 0x69, 0x76, 0x61, 0x6C, 0x20, 0x6E, 0x65, 0x65, 0x64, 0x73, 0x20,
    0x66, 0x6F, 0x72, 0x20, 0x70, 0x6C, 0x61, 0x79, 0x65, 0x72, 0x2D, 0x74, 0x6F, 0x2D, 0x70, 0x6C,
    0x61, 0x79, 0x65, 0x72, 0x20, 0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x2E, 0x20, 0x4B, 0x65,
    0x65, 0x70, 0x20, 0x6F, 0x6E, 0x2E, 0x0D, 0x0A, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
    0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x3B,
    0x20, 0x42, 0x6C, 0x61, 0x6E, 0x6B, 0x20, 0x3D, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x75, 0x69,
    0x6C, 0x74, 0x2D, 0x69, 0x6E, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2E, 0x20, 0x4F, 0x6E,
    0x6C, 0x79, 0x20, 0x73, 0x65, 0x74, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x74, 0x6F, 0x20, 0x74,
    0x65, 0x73, 0x74, 0x20, 0x61, 0x67, 0x61, 0x69, 0x6E, 0x73, 0x74, 0x20, 0x61, 0x6E, 0x6F, 0x74,
    0x68, 0x65, 0x72, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x2C, 0x20, 0x65, 0x2E, 0x67, 0x2E,
    0x20, 0x31, 0x39, 0x32, 0x2E, 0x31, 0x36, 0x38, 0x2E, 0x31, 0x2E, 0x35, 0x30, 0x0D, 0x0A, 0x53,
    0x65, 0x72, 0x76, 0x65, 0x72, 0x49, 0x70, 0x20, 0x3D, 0x0D, 0x0A, 0x0D, 0x0A, 0x5B, 0x42, 0x45,
    0x54, 0x41, 0x5D, 0x0D, 0x0A, 0x3B, 0x20, 0x42, 0x65, 0x74, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74,
    0x65, 0x72, 0x20, 0x6F, 0x70, 0x74, 0x69, 0x6F, 0x6E, 0x73, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20,
    0x64, 0x65, 0x66, 0x61, 0x75, 0x6C, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x77, 0x68, 0x61,
    0x74, 0x20, 0x65, 0x76, 0x65, 0x72, 0x79, 0x6F, 0x6E, 0x65, 0x20, 0x73, 0x68, 0x6F, 0x75, 0x6C,
    0x64, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x75, 0x6E, 0x6C, 0x65, 0x73, 0x73, 0x20, 0x79, 0x6F, 0x75,
    0x20, 0x61, 0x72, 0x65, 0x20, 0x74, 0x6F, 0x6C, 0x64, 0x20, 0x6F, 0x74, 0x68, 0x65, 0x72, 0x77,
    0x69, 0x73, 0x65, 0x2E, 0x0D, 0x0A, 0x3B, 0x20, 0x53, 0x6B, 0x69, 0x70, 0x73, 0x20, 0x74, 0x68,
    0x65, 0x20, 0x69, 0x6E, 0x2D, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x20, 0x72, 0x65, 0x6E, 0x61,
    0x6D, 0x65, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x72, 0x6F, 0x74, 0x65, 0x63,
    0x74, 0x65, 0x64, 0x20, 0x67, 0x61, 0x6D, 0x65, 0x6D, 0x6F, 0x64, 0x65, 0x73, 0x2E, 0x7A, 0x69,
    0x70, 0x20, 0x2F, 0x20, 0x7A, 0x69, 0x70, 0x6D, 0x61, 0x6E, 0x69, 0x66, 0x65, 0x73, 0x74, 0x2E,
    0x78, 0x6D, 0x6C, 0x20, 0x65, 0x6E, 0x74, 0x72, 0x69, 0x65, 0x73, 0x2E, 0x0D, 0x0A, 0x53, 0x6B,
    0x69, 0x70, 0x46, 0x69, 0x6C, 0x65, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A,
    0x53, 0x6B, 0x69, 0x70, 0x50, 0x6F, 0x70, 0x75, 0x70, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73,
    0x65, 0x0D, 0x0A, 0x53, 0x6B, 0x69, 0x70, 0x41, 0x76, 0x61, 0x69, 0x6C, 0x20, 0x3D, 0x20, 0x66,
    0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x3B, 0x20, 0x42, 0x65, 0x68, 0x61, 0x76, 0x65, 0x20, 0x6C,
    0x69, 0x6B, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6F, 0x6C, 0x64, 0x20, 0x76, 0x31, 0x2E, 0x30,
    0x2E, 0x32, 0x31, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x20, 0x28, 0x66, 0x6F, 0x72, 0x20, 0x63,
    0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x63, 0x72, 0x61,
    0x73, 0x68, 0x20, 0x6F, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6E, 0x65, 0x77, 0x65, 0x72, 0x20,
    0x62, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6F, 0x75, 0x72, 0x2C, 0x20, 0x65, 0x2E, 0x67, 0x2E, 0x20,
    0x61, 0x6E, 0x20, 0x6F, 0x6C, 0x64, 0x65, 0x72, 0x20, 0x67, 0x61, 0x6D, 0x65, 0x20, 0x62, 0x75,
    0x69, 0x6C, 0x64, 0x29, 0x2E, 0x0D, 0x0A, 0x4C, 0x65, 0x67, 0x61, 0x63, 0x79, 0x20, 0x3D, 0x20,
    0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x0D, 0x0A, 0x3B, 0x20, 0x2D, 0x2D, 0x2D, 0x20, 0x4C,
    0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x20, 0x28, 0x6E, 0x65, 0x65, 0x64, 0x65, 0x64, 0x20, 0x77,
    0x68, 0x65, 0x6E, 0x20, 0x79, 0x6F, 0x75, 0x20, 0x73, 0x65, 0x6E, 0x64, 0x20, 0x6C, 0x6F, 0x67,
    0x73, 0x29, 0x20, 0x2D, 0x2D, 0x2D, 0x0D, 0x0A, 0x4C, 0x6F, 0x67, 0x20, 0x3D, 0x20, 0x66, 0x61,
    0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x43, 0x72, 0x61, 0x73, 0x68, 0x4C, 0x6F, 0x67, 0x20, 0x3D, 0x20,
    0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x3B, 0x20, 0x4E, 0x6F, 0x20, 0x6C, 0x6F, 0x67, 0x20,
    0x75, 0x6E, 0x74, 0x69, 0x6C, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x6D, 0x61, 0x6E, 0x79, 0x20,
    0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x20, 0x61, 0x66, 0x74, 0x65, 0x72, 0x20, 0x65, 0x76,
    0x65, 0x72, 0x79, 0x20, 0x67, 0x61, 0x6D, 0x65, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x28,
    0x33, 0x30, 0x2D, 0x39, 0x30, 0x30, 0x29, 0x2E, 0x0D, 0x0A, 0x4C, 0x61, 0x74, 0x65, 0x4C, 0x6F,
    0x67, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x4C, 0x61, 0x74, 0x65, 0x4C,
    0x6F, 0x67, 0x53, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x20, 0x3D, 0x20, 0x31, 0x32, 0x30, 0x0D,
    0x0A, 0x3B, 0x20, 0x4E, 0x6F, 0x20, 0x6C, 0x6F, 0x67, 0x67, 0x69, 0x6E, 0x67, 0x20, 0x61, 0x6E,
    0x64, 0x20, 0x6E, 0x6F, 0x20, 0x6C, 0x6F, 0x67, 0x2D, 0x6F, 0x6E, 0x6C, 0x79, 0x20, 0x68, 0x6F,
    0x6F, 0x6B, 0x73, 0x20, 0x75, 0x6E, 0x74, 0x69, 0x6C, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x6D,
    0x61, 0x6E, 0x79, 0x20, 0x73, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x20, 0x61, 0x66, 0x74, 0x65,
    0x72, 0x20, 0x65, 0x76, 0x65, 0x72, 0x79, 0x20, 0x67, 0x61, 0x6D, 0x65, 0x20, 0x73, 0x74, 0x61,
    0x72, 0x74, 0x20, 0x28, 0x33, 0x30, 0x2D, 0x39, 0x30, 0x30, 0x29, 0x2C, 0x20, 0x74, 0x68, 0x65,
    0x6E, 0x20, 0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x6E, 0x67, 0x20, 0x73, 0x74, 0x61,
    0x72, 0x74, 0x73, 0x20, 0x61, 0x74, 0x20, 0x6F, 0x6E, 0x63, 0x65, 0x2E, 0x0D, 0x0A, 0x47, 0x75,
    0x65, 0x73, 0x74, 0x4C, 0x6F, 0x67, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A,
    0x47, 0x75, 0x65, 0x73, 0x74, 0x4C, 0x6F, 0x67, 0x53, 0x65, 0x63, 0x6F, 0x6E, 0x64, 0x73, 0x20,
    0x3D, 0x20, 0x31, 0x32, 0x30, 0x0D, 0x0A, 0x0D, 0x0A, 0x3B, 0x20, 0x2D, 0x2D, 0x2D, 0x20, 0x44,
    0x69, 0x61, 0x67, 0x6E, 0x6F, 0x73, 0x74, 0x69, 0x63, 0x73, 0x20, 0x28, 0x6F, 0x6E, 0x6C, 0x79,
    0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x4C, 0x6F, 0x67, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65,
    0x29, 0x20, 0x2D, 0x2D, 0x2D, 0x0D, 0x0A, 0x4E, 0x65, 0x74, 0x44, 0x69, 0x61, 0x67, 0x20, 0x3D,
    0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x47, 0x72, 0x69, 0x64, 0x44, 0x69, 0x61, 0x67,
    0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x57, 0x61, 0x69, 0x74, 0x44, 0x69,
    0x61, 0x67, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x4C, 0x6F, 0x63, 0x6B,
    0x44, 0x69, 0x61, 0x67, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x53, 0x65,
    0x6E, 0x64, 0x53, 0x74, 0x6B, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x4B,
    0x65, 0x65, 0x70, 0x41, 0x6C, 0x6C, 0x46, 0x72, 0x61, 0x6D, 0x65, 0x73, 0x20, 0x3D, 0x20, 0x66,
    0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x3B, 0x20, 0x43, 0x6F, 0x6E, 0x74, 0x72, 0x6F, 0x6C, 0x6C,
    0x65, 0x72, 0x20, 0x62, 0x75, 0x74, 0x74, 0x6F, 0x6E, 0x20, 0x63, 0x68, 0x61, 0x6E, 0x67, 0x65,
    0x73, 0x20, 0x69, 0x6E, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6C, 0x6F, 0x67, 0x2E, 0x0D, 0x0A, 0x50,
    0x61, 0x64, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x0D, 0x0A, 0x3B, 0x20,
    0x2D, 0x2D, 0x2D, 0x20, 0x42, 0x65, 0x68, 0x61, 0x76, 0x69, 0x6F, 0x75, 0x72, 0x20, 0x73, 0x77,
    0x69, 0x74, 0x63, 0x68, 0x65, 0x73, 0x20, 0x28, 0x6C, 0x65, 0x61, 0x76, 0x65, 0x20, 0x61, 0x6C,
    0x6F, 0x6E, 0x65, 0x20, 0x75, 0x6E, 0x6C, 0x65, 0x73, 0x73, 0x20, 0x61, 0x73, 0x6B, 0x65, 0x64,
    0x29, 0x20, 0x2D, 0x2D, 0x2D, 0x0D, 0x0A, 0x53, 0x74, 0x75, 0x6E, 0x74, 0x53, 0x6E, 0x61, 0x70,
    0x73, 0x68, 0x6F, 0x74, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x4C, 0x6F,
    0x67, 0x48, 0x6F, 0x6C, 0x64, 0x44, 0x75, 0x72, 0x69, 0x6E, 0x67, 0x4A, 0x6F, 0x69, 0x6E, 0x20,
    0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x53, 0x74, 0x75, 0x63, 0x6B, 0x4C, 0x6F, 0x61,
    0x64, 0x69, 0x6E, 0x67, 0x57, 0x61, 0x74, 0x63, 0x68, 0x64, 0x6F, 0x67, 0x20, 0x3D, 0x20, 0x74,
    0x72, 0x75, 0x65, 0x0D, 0x0A, 0x4F, 0x62, 0x73, 0x65, 0x72, 0x76, 0x61, 0x74, 0x69, 0x6F, 0x6E,
    0x48, 0x6F, 0x6F, 0x6B, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x46, 0x61,
    0x69, 0x6C, 0x46, 0x72, 0x65, 0x65, 0x72, 0x6F, 0x61, 0x6D, 0x53, 0x74, 0x61, 0x74, 0x73, 0x20,
    0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x4B, 0x65, 0x65, 0x70, 0x50, 0x6C, 0x75, 0x67,
    0x69, 0x6E, 0x52, 0x65, 0x73, 0x75, 0x6C, 0x74, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D,
    0x0A, 0x4E, 0x6F, 0x43, 0x61, 0x6E, 0x63, 0x65, 0x6C, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73,
    0x65, 0x0D, 0x0A, 0x49, 0x6E, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65, 0x53, 0x6F, 0x63, 0x6B, 0x65,
    0x74, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x45, 0x6E, 0x75, 0x6D, 0x34, 0x32,
    0x43, 0x6F, 0x6D, 0x70, 0x6C, 0x65, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75,
    0x65, 0x0D, 0x0A, 0x58, 0x4E, 0x65, 0x74, 0x52, 0x65, 0x73, 0x74, 0x61, 0x72, 0x74, 0x20, 0x3D,
    0x20, 0x66, 0x61, 0x6C, 0x73, 0x65, 0x0D, 0x0A, 0x54, 0x72, 0x61, 0x63, 0x65, 0x48, 0x6F, 0x6F,
    0x6B, 0x73, 0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x51, 0x75, 0x69, 0x65, 0x74,
    0x20, 0x3D, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0D, 0x0A, 0x58, 0x67, 0x69, 0x20, 0x3D, 0x20, 0x74,
    0x72, 0x75, 0x65, 0x0D, 0x0A, 0x50, 0x72, 0x6F, 0x62, 0x65, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C,
    0x73, 0x65, 0x0D, 0x0A, 0x4E, 0x6F, 0x53, 0x65, 0x73, 0x73, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C,
    0x73, 0x65, 0x0D, 0x0A, 0x46, 0x72, 0x53, 0x77, 0x61, 0x70, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C,
    0x73, 0x65, 0x0D, 0x0A, 0x42, 0x61, 0x72, 0x65, 0x20, 0x3D, 0x20, 0x66, 0x61, 0x6C, 0x73, 0x65,
    0x0D, 0x0A, 0x3B, 0x20, 0x49, 0x6E, 0x73, 0x74, 0x61, 0x6C, 0x6C, 0x20, 0x6F, 0x6E, 0x6C, 0x79,
    0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x70, 0x6C, 0x75,
    0x67, 0x69, 0x6E, 0x20, 0x28, 0x63, 0x72, 0x61, 0x73, 0x68, 0x20, 0x68, 0x75, 0x6E, 0x74, 0x69,
    0x6E, 0x67, 0x29, 0x3A, 0x20, 0x61, 0x6C, 0x6C, 0x2C, 0x20, 0x30, 0x2C, 0x20, 0x31, 0x2C, 0x20,
    0x32, 0x20, 0x6F, 0x72, 0x20, 0x33, 0x2E, 0x0D, 0x0A, 0x53, 0x74, 0x61, 0x67, 0x65, 0x20, 0x3D,
    0x20, 0x61, 0x6C, 0x6C, 0x0D, 0x0A,
};
struct FH2_INIKEY { const CHAR* key; BOOL def; const CHAR* wTrue; const CHAR* wFalse; };
static const FH2_INIKEY g_FH2IniKeys[] =
{
    // [OPTIONS]
    { "FixFestivalTile",      TRUE,  NULL,        "nofestpic" },
    { "PushPlayerCard",       TRUE,  NULL,        "nocard" },
    { "SessionTimeoutPatch",  TRUE,  NULL,        "notimeout" },
    { "SecurityBypass",       TRUE,  NULL,        "nobypass" },
    // [BETA]
    { "SkipFiles",            TRUE,  "skipfiles", NULL },
    { "SkipPopup",            FALSE, "skippopup", NULL },
    { "SkipAvail",            FALSE, "skipavail", NULL },
    { "Legacy",               FALSE, "legacy",    NULL },
    { "Log",                  FALSE, "log",       NULL },
    { "CrashLog",             FALSE, "crashlog",  NULL },
    { "NetDiag",              FALSE, "netdiag",   NULL },
    { "GridDiag",             FALSE, "griddiag",  NULL },
    { "WaitDiag",             FALSE, "waitdiag",  NULL },
    { "LockDiag",             FALSE, "lockdiag",  NULL },
    { "SendStk",              FALSE, "sendstk",   NULL },
    { "KeepAllFrames",        FALSE, "keepall",   NULL },
    { "Pad",                  FALSE, "pad",       NULL },
    { "StuntSnapshots",       TRUE,  NULL,        "nosnap" },
    { "LogHoldDuringJoin",    TRUE,  NULL,        "nohold" },
    { "StuckLoadingWatchdog", TRUE,  NULL,        "nowatch" },
    { "ObservationHooks",     TRUE,  NULL,        "nodiag" },
    { "FailFreeroamStats",    TRUE,  NULL,        "nofrstats" },
    { "KeepPluginResult",     TRUE,  NULL,        "nokeepok" },
    { "NoCancel",             FALSE, "nocancel",  NULL },
    { "InsecureSocket",       TRUE,  NULL,        "noinsecure" },
    { "Enum42Completion",     TRUE,  NULL,        "noenum42" },
    { "XNetRestart",          FALSE, "restart",   NULL },
    { "TraceHooks",           TRUE,  NULL,        "notrace" },
    { "Quiet",                TRUE,  "quiet",     "loud" },
    { "Xgi",                  TRUE,  "xgi",       "noxgi" },
    { "Probe",                FALSE, "probe",     "noprobe" },
    { "NoSess",               FALSE, "nosess",    NULL },
    { "FrSwap",               FALSE, "frswap",    "nofrswap" },
    { "Bare",                 FALSE, "bare",      NULL },
};
#define FH2_INIKEY_COUNT (sizeof(g_FH2IniKeys) / sizeof(g_FH2IniKeys[0]))

static BOOL g_FH2CfgFromIni = FALSE;   // TRUE: words came from FH2Revival.ini (new defaults apply); FALSE: from an old FH2Synth.txt

static BOOL FH2_IniEq(const CHAR* a, const CHAR* b)   // case-insensitive equality
{
    for (;; ++a, ++b)
    {
        CHAR x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (CHAR)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (CHAR)(y + 32);
        if (x != y) return FALSE;
        if (!x) return TRUE;
    }
}

static BOOL FH2_IniBool(const CHAR* v, BOOL def)   // unrecognised text keeps the default
{
    if (!v || !*v) return def;
    if (FH2_IniEq(v, "1") || FH2_IniEq(v, "true") || FH2_IniEq(v, "t") || FH2_IniEq(v, "yes") || FH2_IniEq(v, "y") || FH2_IniEq(v, "on")) return TRUE;
    if (FH2_IniEq(v, "0") || FH2_IniEq(v, "false") || FH2_IniEq(v, "f") || FH2_IniEq(v, "no") || FH2_IniEq(v, "n") || FH2_IniEq(v, "off")) return FALSE;
    return def;
}

static VOID FH2_AddWord(CHAR* out, int cap, const CHAR* w)
{
    int n = (int)strlen(out), l = (int)strlen(w);
    if (n + l + 2 >= cap) return;
    memcpy(out + n, w, l);
    out[n + l] = ' ';
    out[n + l + 1] = 0;
}

// Turns the text of FH2Revival.ini (raw, may be empty = all defaults) into the word buffer.
static VOID FH2_IniToWords(const CHAR* raw, CHAR* out, int cap)
{
    BOOL val[FH2_INIKEY_COUNT];
    for (int i = 0; i < (int)FH2_INIKEY_COUNT; ++i) val[i] = g_FH2IniKeys[i].def;
    BOOL lateLog = FALSE, guestLog = FALSE;
    CHAR lateSec[8] = { 0 }, guestSec[8] = { 0 }, festPic[40] = { 0 }, serverIp[20] = { 0 }, stage[8] = { 0 };

    const CHAR* p = raw;
    while (*p)
    {
        CHAR line[160];
        int n = 0;
        while (*p && *p != '\n' && *p != '\r') { if (n < (int)sizeof(line) - 1) line[n++] = *p; ++p; }
        while (*p == '\n' || *p == '\r') ++p;
        line[n] = 0;
        // strip an inline comment, then trim
        for (int i = 0; i < n; ++i) if (line[i] == ';' || line[i] == '#') { line[i] = 0; n = i; break; }
        int s = 0; while (s < n && (line[s] == ' ' || line[s] == '\t')) ++s;
        if (s >= n || line[s] == '[') continue;
        CHAR* eq = strchr(line + s, '=');
        if (!eq) continue;
        *eq = 0;
        CHAR* key = line + s;
        CHAR* v = eq + 1;
        int kl = (int)strlen(key); while (kl > 0 && (key[kl - 1] == ' ' || key[kl - 1] == '\t')) key[--kl] = 0;
        while (*v == ' ' || *v == '\t') ++v;
        int vl = (int)strlen(v); while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) v[--vl] = 0;

        BOOL known = FALSE;
        for (int i = 0; i < (int)FH2_INIKEY_COUNT; ++i)
            if (FH2_IniEq(key, g_FH2IniKeys[i].key)) { val[i] = FH2_IniBool(v, g_FH2IniKeys[i].def); known = TRUE; break; }
        if (known) continue;
        if (FH2_IniEq(key, "LateLog"))              lateLog = FH2_IniBool(v, FALSE);
        else if (FH2_IniEq(key, "GuestLog"))        guestLog = FH2_IniBool(v, FALSE);
        else if (FH2_IniEq(key, "LateLogSeconds"))  { int k = 0; for (; k < 4 && v[k] >= '0' && v[k] <= '9'; ++k) lateSec[k] = v[k]; lateSec[k] = 0; }
        else if (FH2_IniEq(key, "GuestLogSeconds")) { int k = 0; for (; k < 4 && v[k] >= '0' && v[k] <= '9'; ++k) guestSec[k] = v[k]; guestSec[k] = 0; }
        else if (FH2_IniEq(key, "FestivalPicture"))
        {
            int k = 0;
            for (; k < 31 && ((v[k] >= 'A' && v[k] <= 'Z') || (v[k] >= 'a' && v[k] <= 'z') || (v[k] >= '0' && v[k] <= '9') || v[k] == '_'); ++k) festPic[k] = v[k];
            festPic[k] = 0;
        }
        else if (FH2_IniEq(key, "ServerIp"))
        {
            int k = 0;
            for (; k < 15 && ((v[k] >= '0' && v[k] <= '9') || v[k] == '.'); ++k) serverIp[k] = v[k];
            serverIp[k] = 0;
        }
        else if (FH2_IniEq(key, "Stage"))
        {
            if (v[0] >= '0' && v[0] <= '3' && v[1] == 0) { stage[0] = v[0]; stage[1] = 0; }
        }
    }

    out[0] = 0;
    for (int i = 0; i < (int)FH2_INIKEY_COUNT; ++i)
    {
        const CHAR* w = val[i] ? g_FH2IniKeys[i].wTrue : g_FH2IniKeys[i].wFalse;
        if (w) FH2_AddWord(out, cap, w);
    }
    CHAR tmp[48];
    if (lateLog)  { strcpy(tmp, "latelog"); strcat(tmp, lateSec);   FH2_AddWord(out, cap, tmp); }
    if (guestLog) { strcpy(tmp, "guest");   strcat(tmp, guestSec);   FH2_AddWord(out, cap, tmp); }
    if (festPic[0])  { strcpy(tmp, "festpic="); strcat(tmp, festPic);   FH2_AddWord(out, cap, tmp); }
    if (serverIp[0]) { strcpy(tmp, "real=");    strcat(tmp, serverIp);  FH2_AddWord(out, cap, tmp); }
    if (stage[0])    { strcpy(tmp, "stage");    strcat(tmp, stage);     FH2_AddWord(out, cap, tmp); }
}

// Fills buf with the config words.  Returns 1 when they came from FH2Revival.ini (or the built-in defaults), 2 when from an old FH2Synth.txt.
static int FH2_LoadConfigWords(CHAR* buf, int cap)
{
    static CHAR raw[4096];
    buf[0] = 0;
    HANDLE h = CreateFile(MOUNT_POINT "\\FH2Revival.ini", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD got = 0;
        ReadFile(h, raw, sizeof(raw) - 1, &got, NULL);
        CloseHandle(h);
        raw[got] = 0;
        FH2_IniToWords(raw, buf, cap);
        g_FH2CfgFromIni = TRUE;
        return 1;
    }
    h = CreateFile(MOUNT_POINT "\\FH2Synth.txt", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD got = 0;
        ReadFile(h, buf, 127, &got, NULL);   // exactly as before: only the first 127 bytes are read
        CloseHandle(h);
        buf[got] = 0;
        g_FH2CfgFromIni = FALSE;
        return 2;
    }
    // neither file: write a default FH2Revival.ini (best effort) and run on the defaults
    h = CreateFile(MOUNT_POINT "\\FH2Revival.ini", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        DWORD wr = 0;
        WriteFile(h, g_FH2DefaultIni, sizeof(g_FH2DefaultIni), &wr, NULL);
        CloseHandle(h);
    }
    raw[0] = 0;
    FH2_IniToWords(raw, buf, cap);
    g_FH2CfgFromIni = TRUE;
    return 1;
}
// ===================================================================================================================================

// v0.9.7: FH2_ReadSynthConfig runs late in the setup path, so g_FH2LogEnabled was still FALSE when the title was detected:
// the "FH2 detected" line and the early v0.9.5 trace hooks were skipped.  This reads just the 'log' word early.
VOID FH2_EarlyLogFlag()
{
    CHAR buf[768] = { 0 };
    FH2_LoadConfigWords(buf, sizeof(buf));   // v1.0.48: FH2Revival.ini (or an old FH2Synth.txt, or the built-in defaults)
    if (strstr(buf, "log")) g_FH2LogEnabled = TRUE;
    if (strstr(buf, "nodiag")) g_FH2NoDiag = TRUE;   // v1.0.22
    if (strstr(buf, "nohold")) g_FH2NoHold = TRUE;   // v1.0.23
    if (strstr(buf, "legacy")) { g_FH2Legacy = TRUE; g_FH2NoHold = TRUE; }   // v1.0.26
    if (strstr(buf, "netdiag")) { g_FH2NetDiag = TRUE; g_FH2BigMin = 18; g_FH2BigBudget = 300; }   // v1.0.27
    {
        // v1.0.28: latelog (implies log).  Optional seconds right after the word: latelog180.  30..900, default 120.
        const CHAR* lp = strstr(buf, "latelog");
        if (lp)
        {
            g_FH2LateLog = TRUE;
            g_FH2LogEnabled = TRUE;
            int sec = 0;
            for (const CHAR* q = lp + 7; *q >= '0' && *q <= '9' && sec < 10000; ++q) sec = sec * 10 + (*q - '0');
            if (sec >= 30 && sec <= 900) g_FH2LateMs = (DWORD)sec * 1000;
        }
    }
    {
        // v1.0.33: guest.  Optional seconds right after the word: guest90.  30..900, default 120.  Logging stays completely off (like a plain
        // 'skipfiles legacy' joiner) until that long after each title start, so the invite-join relaunch runs exactly as it does without 'log'.
        const CHAR* gp = strstr(buf, "guest");
        if (gp)
        {
            g_FH2GuestLog = TRUE;
            int sec = 0;
            for (const CHAR* q = gp + 5; *q >= '0' && *q <= '9' && sec < 10000; ++q) sec = sec * 10 + (*q - '0');
            if (sec >= 30 && sec <= 900) g_FH2GuestMs = (DWORD)sec * 1000;
        }
    }
    // v0.9.10: switches that must be known before the hooks are installed.
    // v1.0: quiet + noprobe + xgi are the built-in defaults (no FH2Synth.txt needed).  Override words: loud, probe, noxgi.
    if (strstr(buf, "quiet"))   g_FH2Quiet = TRUE;
    if (strstr(buf, "loud"))    g_FH2Quiet = FALSE;
    if (strstr(buf, "nosess"))  g_FH2NoSess = TRUE;
    if (strstr(buf, "noprobe")) g_FH2NoProbe = TRUE;
    if (strstr(buf, "probe") && !strstr(buf, "noprobe")) g_FH2NoProbe = FALSE;
    if (strstr(buf, "xgi") && !strstr(buf, "noxgi"))     g_FH2Xgi = TRUE;
    if (strstr(buf, "noxgi"))   g_FH2Xgi = FALSE;
    if (strstr(buf, "frswap") && !strstr(buf, "nofrswap")) g_FH2FrSwap = TRUE;
    if (strstr(buf, "nofrswap")) g_FH2FrSwap = FALSE;
    if (strstr(buf, "notimeout")) g_FH2NoTimeoutPatch = TRUE;
    if (strstr(buf, "nofrstats")) g_FH2NoFrStats = TRUE;
    if (strstr(buf, "nokeepok")) g_FH2NoKeepOk = TRUE;
    if (strstr(buf, "nocancel")) g_FH2NoCancel = TRUE;
    if (strstr(buf, "pad")) g_FH2Pad = TRUE;
    // v0.9.11: 'bare' = nosess + noprobe + quiet (the 590/592 enumeration, ROADTRIP TAP and the connect/XNet redirect stay).
    // v1.0.1 diagnostic stages (default = full).  stage0: do nothing but the XNotify.  stage1: game memory patches only.
    // stage2: + network/session import hooks (provenance).  stage3: everything.
    if (strstr(buf, "nowatch")) g_FH2NoWatch = TRUE;
    if (strstr(buf, "keepall")) g_FH2KeepAll = TRUE;   // v1.0.30
    if (strstr(buf, "nosnap")) g_FH2NoSnap = TRUE;     // v1.0.32
    if (strstr(buf, "nocard")) g_FH2NoCard = TRUE;     // v1.0.46
    if (strstr(buf, "nofestpic")) g_FH2NoFestPic = TRUE;   // v1.0.47
    {
        // v1.0.47: festpic=Name (letters, digits, underscore).  Default NiceMassena.
        const CHAR* fp = strstr(buf, "festpic=");
        if (fp)
        {
            int n = 0;
            for (const CHAR* q = fp + 8; n < 31 && ((*q >= 'A' && *q <= 'Z') || (*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9') || *q == '_'); ++q) g_FH2FestPic[n++] = *q;
            if (n > 0) g_FH2FestPic[n] = 0;
        }
    }
    if (strstr(buf, "sendstk")) g_FH2SendStk = TRUE;   // v1.0.35
    if (strstr(buf, "griddiag")) g_FH2GridDiag = TRUE;   // v1.0.36
    if (strstr(buf, "waitdiag")) g_FH2WaitDiag = TRUE;   // v1.0.41
    if (strstr(buf, "lockdiag")) g_FH2LockDiag = TRUE;   // v1.0.43
    if (!g_FH2CfgFromIni) g_FH2SkipFiles = FALSE;   // v1.0.48: skipfiles is on by default with FH2Revival.ini; an old FH2Synth.txt keeps its old meaning
    if (strstr(buf, "skipfiles")) g_FH2SkipFiles = TRUE;
    if (strstr(buf, "skippopup")) g_FH2SkipPopup = TRUE;
    if (strstr(buf, "skipavail")) g_FH2SkipAvail = TRUE;
    if (strstr(buf, "stage0")) g_FH2Stage = 0;
    else if (strstr(buf, "stage1")) g_FH2Stage = 1;
    else if (strstr(buf, "stage2")) g_FH2Stage = 2;
    else if (strstr(buf, "stage3")) g_FH2Stage = 3;
    if (strstr(buf, "bare"))    { g_FH2NoSess = TRUE; g_FH2NoProbe = TRUE; g_FH2Quiet = TRUE; }
    FH2_Log("v1.0.48 config source: %s  words: %s", g_FH2CfgFromIni ? "FH2Revival.ini" : "FH2Synth.txt (old)", buf);
    FH2_Log("v1.0.43 config: waitdiag=%d lockdiag=%d griddiag=%d sendstk=%d guest=%d/%ums nosnap=%d keepall=%d watch=%d latelog=%d/%ums netdiag=%d legacy=%d hold=%d nodiag=%d pad=%d nocancel=%d quiet=%d nosess=%d noprobe=%d xgi=%d stage=%d skip files/popup/avail=%d/%d/%d frswap=%d", g_FH2WaitDiag ? 1 : 0, g_FH2LockDiag ? 1 : 0, g_FH2GridDiag ? 1 : 0, g_FH2SendStk ? 1 : 0, g_FH2GuestLog ? 1 : 0, (unsigned)g_FH2GuestMs, g_FH2NoSnap ? 1 : 0, g_FH2KeepAll ? 1 : 0, !g_FH2NoWatch, g_FH2LateLog ? 1 : 0, (unsigned)g_FH2LateMs, g_FH2NetDiag ? 1 : 0, g_FH2Legacy ? 1 : 0, g_FH2NoHold ? 0 : 1, g_FH2NoDiag ? 1 : 0, g_FH2Pad ? 1 : 0, g_FH2NoCancel ? 1 : 0, g_FH2Quiet ? 1 : 0, g_FH2NoSess ? 1 : 0, g_FH2NoProbe ? 1 : 0, g_FH2Xgi ? 1 : 0, g_FH2Stage, g_FH2SkipFiles ? 1 : 0, g_FH2SkipPopup ? 1 : 0, g_FH2SkipAvail ? 1 : 0, g_FH2FrSwap ? 1 : 0);
}

static VOID FH2_ReadSynthConfig()
{
    g_FH2RealIp = FH2_BAKED_REAL_IP_ENC ^ FH2_BAKED_REAL_IP_XOR;
    CHAR buf[768] = { 0 };
    FH2_LoadConfigWords(buf, sizeof(buf));   // v1.0.48: FH2Revival.ini (or an old FH2Synth.txt, or the built-in defaults)

    if (!g_FH2CfgFromIni)
    {
        DWORD a = 0, b = 0, c = 0, d = 0;
        if (sscanf_s(buf, "%u.%u.%u.%u", &a, &b, &c, &d) == 4 && a < 256 && b < 256 && c < 256 && d < 256)
        {
            g_FH2SynthIp = (a << 24) | (b << 16) | (c << 8) | d;
            FH2_Log("v0.8.10 config: server IP set to %u.%u.%u.%u", a, b, c, d);
        }
        else
            FH2_Log("v0.8.10 config: could not parse an IPv4 from FH2Synth.txt, using default");
    }

    {
        const CHAR* r = strstr(buf, "real=");
        DWORD ra = 0, rb = 0, rc = 0, rd = 0;
        if (r && sscanf_s(r + 5, "%u.%u.%u.%u", &ra, &rb, &rc, &rd) == 4 && ra < 256 && rb < 256 && rc < 256 && rd < 256)
        {
            g_FH2RealIp = (ra << 24) | (rb << 16) | (rc << 8) | rd;
            FH2_Log("v0.8.20 config: real server %u.%u.%u.%u (game sees the first IP)", ra, rb, rc, rd);
        }
    }
    if (strstr(buf, "log"))
        g_FH2LogEnabled = TRUE;   // also matches "crashlog"
    if (strstr(buf, "crashlog"))
        g_FH2CrashLogEnabled = TRUE;
    if (strstr(buf, "notrace"))
        g_FH2TraceEnabled = FALSE;
    if (strstr(buf, "noenum42"))
    {
        g_FH2Enum42Enabled = FALSE;
        FH2_Log("v0.8.17 config: 0x58042 enumerator completion DISABLED");
    }
    if (strstr(buf, "nobypass"))
    {
        g_FH2NoBypass = TRUE;
        FH2_Log("v0.9.9 config: XNET_STARTUP_BYPASS_SECURITY will NOT be added to XNetStartup");
    }
    if (strstr(buf, "noinsecure"))
    {
        g_FH2NoInsecure = TRUE;
        FH2_Log("v0.8.11 config: socket option 0x5801 (insecure) will NOT be set");
    }
    if (strstr(buf, "restart") && !strstr(buf, "norestart"))
    {
        g_FH2SkipNetRestart = FALSE;
        FH2_Log("v0.8.16 config: XNet restart ENABLED (opt-in)");
    }
    else
        FH2_Log("v0.8.16 config: XNet restart disabled (default)");
}

static DWORD NTAPI FH2_XamCreateEnumeratorSynth(DWORD user, DWORD app, DWORD openMsg,
    DWORD closeMsg, DWORD extra, DWORD count, DWORD flags, PHANDLE outHandle)
{
    DWORD r = g_FH2RealCreateEnum(user, app, openMsg, closeMsg, extra, count, flags, outHandle);
    if (openMsg == 0x58042 && outHandle && MmIsAddressValid(outHandle))
    {
        DWORD h = (DWORD)*outHandle;
        for (int i = 0; i < FH2_E42_HANDLES; ++i)
            if (!g_FH2Legacy && g_FH2E42Handle[i] == h) g_FH2E42Handle[i] = 0;   // v1.0.25: drop stale duplicates of a recycled handle
        LONG slot = (InterlockedIncrement(&g_FH2E42Next) - 1) & (FH2_E42_HANDLES - 1);
        g_FH2E42Handle[slot] = h;
        FH2_SynthEvt(20, h, r, count, extra);
    }
    if (openMsg == 0x58039 && outHandle && MmIsAddressValid(outHandle))
    {
        DWORD h = (DWORD)*outHandle;
        LONG slot = (InterlockedIncrement(&g_FH2SynthNext) - 1) & (FH2_SYNTH_HANDLES - 1);
        // reuse the slot if this handle value is already tracked
        for (int i = 0; i < FH2_SYNTH_HANDLES; ++i)
            if (g_FH2SynthHandle[i] == h) slot = i;
        g_FH2SynthHandle[slot] = h;
        g_FH2SynthDone[slot] = 0;
        FH2_SynthEvt(1, h, r, count, extra);
    }
    return r;
}

static DWORD NTAPI FH2_XamEnumerateSynth(HANDLE hEnum, DWORD flags, PVOID buf,
    DWORD cb, PDWORD pItems, PXOVERLAPPED ov)
{
    if (g_FH2Enum42Enabled && hEnum)
    {
        for (int i = 0; i < FH2_E42_HANDLES; ++i)
        {
            // v1.0.25: handle values are recycled by the kernel after the game closes an enumerator, and this table was never
            // cleared.  A later REAL enumerator (the friends list, cb=19600) that got the same handle value was answered EMPTY
            // -> "There are no friends available".  Only the first 304-byte read of the 0x58042 enumerator is ours, one-shot.
            if (g_FH2E42Handle[i] == (DWORD)hEnum && (cb == 304 || g_FH2Legacy))
            {
                if (!g_FH2Legacy) g_FH2E42Handle[i] = 0;
                DWORD err = ERROR_NO_MORE_FILES;
                FH2_SynthEvt(21, (DWORD)hEnum, cb, err, (DWORD)ov);
                if (ov)
                {
                    ov->InternalLow = err;
                    ov->InternalHigh = 0;
                    ov->InternalContext = (ULONG_PTR)GetCurrentThread();
                    ov->dwExtendedError = 0;
                    if (ov->hEvent)
                    {
                        ResetEvent(ov->hEvent);
                        SetEvent(ov->hEvent);
                    }
                    return ERROR_IO_PENDING;
                }
                if (pItems) *pItems = 0;
                return err;
            }
        }
    }

    int slot = -1;
    for (int i = 0; i < FH2_SYNTH_HANDLES; ++i)
        if (g_FH2SynthHandle[i] == (DWORD)hEnum && hEnum) { slot = i; break; }

    if (slot < 0 || !buf || cb < sizeof(XTITLE_SERVER_INFO))
        return g_FH2RealEnumerate(hEnum, flags, buf, cb, pItems, ov);

    DWORD err = 0, items = 1;
    if (g_FH2SynthDone[slot]) { err = ERROR_NO_MORE_FILES; items = 0; }
    else g_FH2SynthDone[slot] = 1;

    DWORD fill = cb < 0x1000 ? cb : 0x1000;
    memset(buf, 0, fill);
    if (items)
    {
        XTITLE_SERVER_INFO* s = (XTITLE_SERVER_INFO*)buf;
        s->inaServer.S_un.S_addr = g_FH2SynthIp;
        memcpy(s->szServerInfo, "Turn10.Anthem360", 17);   // game filters SGs with mask "Turn10.*"
    }

    FH2_SynthEvt(2, (DWORD)hEnum, items, err, (DWORD)ov);

    if (ov)
    {
        ov->InternalLow = err;
        ov->InternalHigh = items;
        ov->InternalContext = (ULONG_PTR)GetCurrentThread();
        ov->dwExtendedError = 0;
        if (ov->hEvent)
        {
            ResetEvent(ov->hEvent);
            SetEvent(ov->hEvent);
        }
        return ERROR_IO_PENDING;
    }
    if (pItems) *pItems = items;
    return err;
}

struct FH2_PROBE_API
{
    DWORD ordinal;
    const CHAR* name;
    DWORD wrapper;
    DWORD forward;
};

#define FH2_PROBE_COUNT 17
static FH2_PROBE_API g_FH2ProbeApis[FH2_PROBE_COUNT] =
{
    { 500, "XMsgInProcessCall", (DWORD)&FH2_ProbeWrap0, 0 },
    { 502, "XMsgSystemProcessCall", (DWORD)&FH2_ProbeWrap1, 0 },
    { 503, "XMsgStartIORequest", (DWORD)&FH2_ProbeWrap2, 0 },
    { 508, "XMsgStartIORequestEx", (DWORD)&FH2_ProbeWrap3, 0 },
    { 590, "XamCreateEnumeratorHandle", (DWORD)&FH2_ProbeWrap4, 0 },
    { 592, "XamEnumerate", (DWORD)&FH2_ProbeWrap5, 0 },
    { 1311, "XamLrcSetTitlePort", (DWORD)&FH2_ProbeWrap6, 0 },
    { 1312, "XamLrcVerifyClientId", (DWORD)&FH2_ProbeWrap7, 0 },
    { 1313, "XamLrcEncryptDecryptTitleMessage", (DWORD)&FH2_ProbeWrap8, 0 },
    { 1531, "XamLrcLogSessionSummary", (DWORD)&FH2_ProbeWrap9, 0 },
    { 1532, "XamLrcLogError", (DWORD)&FH2_ProbeWrap10, 0 },
    { 425, "XamLoaderTerminateTitle", (DWORD)&FH2_ProbeWrap11, 0 },
    { 420, "XamLoaderLaunchTitle", (DWORD)&FH2_ProbeWrap12, 0 },
    { 421, "XamLoaderLaunchTitleEx", (DWORD)&FH2_ProbeWrap13, 0 },
    { 422, "XamLoaderSetLaunchData", (DWORD)&FH2_ProbeWrap14, 0 },
    { 423, "XamLoaderGetLaunchDataSize", (DWORD)&FH2_ProbeWrap15, 0 },
    { 424, "XamLoaderGetLaunchData", (DWORD)&FH2_ProbeWrap16, 0 }
};
static volatile LONG g_FH2ProbeCounts[FH2_PROBE_COUNT];

// v0.8.26: at title termination, dump the last 40 probe-ring calls (the timer-flushed log can be a second behind).
static VOID FH2_DumpProbeTail()
{
    LONG end = g_FH2ProbeRingPos;
    int shown = 0;
    for (int k = 0; k < 400 && shown < 40; ++k)
    {
        FH2_PROBE_RING r = g_FH2ProbeRing[(end - k) & (FH2_PROBE_RING_SIZE - 1)];
        if (r.tick == 0 || r.idx >= FH2_PROBE_COUNT) continue;
        if (r.idx == 0 && r.a[0] == 0xFA) continue; // hot poll
        ++shown;
        FH2_Log("v0.8.26 TERM tail[-%d]: tick=%u %s caller=0x%08X a0=%08X a1=%08X a2=%08X a3=%08X",
            k, r.tick, g_FH2ProbeApis[r.idx].name, r.caller, r.a[0], r.a[1], r.a[2], r.a[3]);
    }
}
static volatile LONG g_FH2ProbeLogged = 0;

struct FH2_ENUM_PENDING
{
    DWORD buf, cb, pItems, tick, stage, ovl, caller, handle;
};
static FH2_ENUM_PENDING g_FH2EnumPending[8];

static BOOL FH2_ProbeReadable(DWORD addr, DWORD bytes)
{
    if (addr < 0x10000 || addr > 0x9FFFFFFF || (addr & 3))
        return FALSE;
    return MmIsAddressValid((PVOID)addr) && MmIsAddressValid((PVOID)(addr + bytes - 1));
}

static VOID FH2_ProbeHex(const CHAR* tag, DWORD addr, DWORD bytes)
{
    if (!FH2_ProbeReadable(addr, bytes))
        return;
    for (DWORD off = 0; off < bytes; off += 16)
    {
        volatile DWORD* p = (volatile DWORD*)(addr + off);
        FH2_Log("PROBE %s +%03X: %08X %08X %08X %08X", tag, off, p[0], p[1], p[2], p[3]);
    }
}

// -----------------------------------------------------------------------------
// v0.9.19: result tracking for the XGI session calls.  The game starts each call with an OVERLAPPED (a[2]); the 50 ms main loop
// (FH2_XgiPoll) snapshots its 7 dwords (InternalLow = status, ..., dwExtendedError) once the call is >= 120 ms old and again
// whenever they change, and re-reads the call's pointer arguments to show what the call wrote into them (session info etc.).
// Only the calls that matter for joining are tracked (not the very frequent property/context writes).
// -----------------------------------------------------------------------------
#define FH2_XGI_PEND_N 16
struct FH2_XGI_PEND
{
    volatile DWORD used;
    DWORD seq, tick, msg, ovl, nptr, snaps, haveSnap, forced, keep;
    DWORD fEvt, fCr, fCtx;   // v1.0.44: hEvent / completion routine / completion context of the overlapped when the plugin completed it (the real Live completion never changes these)
    DWORD ptr[4];
    DWORD snap[7];
    BYTE  pre[4][64];
};
static FH2_XGI_PEND g_FH2XgiPend[FH2_XGI_PEND_N];
static volatile LONG g_FH2XgiSeq = 0;
static volatile DWORD g_FH2LastEndTick = 0;   // v0.9.24: tick of the last B0015 (end session) call
static volatile LONG g_FH2FrSwapN = 0;
static volatile DWORD g_FH2FreeRoamTick = 0;   // v1.0.7: tick of the last free-roam session create (flags 0x823, 0 public slots)
// v0.9.20: counters for the heartbeat file (read only; no logging from here).
VOID FH2_HbSnap(DWORD* xgiSeq, DWORD* sendN, DWORD* recvCalls)
{
    *xgiSeq = (DWORD)g_FH2XgiSeq; *sendN = (DWORD)g_FH2P2PSendN; *recvCalls = (DWORD)g_FH2P2PRecvCalls;
}

static BOOL FH2_XgiTracked(DWORD msg)
{
    switch (msg)
    {
    case 0x000B0010: case 0x000B0011: case 0x000B0012: case 0x000B0013: case 0x000B0014: case 0x000B0015:
    case 0x000B0018: case 0x000B001C: case 0x000B001F: case 0x000B0021: case 0x000B0025:
        return TRUE;
    }
    return FALSE;
}

static BOOL FH2_XgiPtrOk(DWORD v)
{
    if (v & 1) return FALSE;
    if (!((v >= 0x2E000000 && v < 0x40000000) || (v >= 0x70000000 && v < 0x80000000) || (v >= 0x83000000 && v < 0x84000000)))
        return FALSE;
    return MmIsAddressValid((PVOID)v) && MmIsAddressValid((PVOID)(v + 63));
}

static BOOL FH2_SafeCopy(VOID* dst, DWORD src, DWORD n)
{
    if (src < 0x10000 || src > 0x9FFFFFFF) return FALSE;
    if (!MmIsAddressValid((PVOID)src) || !MmIsAddressValid((PVOID)(src + n - 1))) return FALSE;
    for (DWORD i = 0; i < n; ++i) ((BYTE*)dst)[i] = ((volatile BYTE*)src)[i];
    return TRUE;
}

static VOID FH2_Hex(CHAR* out, const BYTE* p, int n)
{
    static const CHAR hx[] = "0123456789ABCDEF";
    for (int i = 0; i < n; ++i) { out[i * 2] = hx[p[i] >> 4]; out[i * 2 + 1] = hx[p[i] & 15]; }
    out[n * 2] = 0;
}

DWORD FH2_ProbeRecord(DWORD idx, DWORD caller, DWORD sp)
{
    if (idx < FH2_PROBE_COUNT)
    {
        InterlockedIncrement(&g_FH2ProbeCounts[idx]);
        DWORD now = GetTickCount();
        volatile DWORD* a = (volatile DWORD*)(sp + 0x24);
        DWORD ord = g_FH2ProbeApis[idx].ordinal;

        LONG pos = InterlockedIncrement(&g_FH2ProbeRingPos) & (FH2_PROBE_RING_SIZE - 1);
        FH2_PROBE_RING& r = g_FH2ProbeRing[pos];
        r.idx = idx; r.caller = caller;
        for (int k = 0; k < 6; ++k) r.a[k] = a[k];
        r.tick = now;

        // v0.8.4b: these APIs are rare except XMsgInProcessCall, which has one
        // very hot poll (app 0xFA msg 0x7001B). Log every rare call ALWAYS, and
        // log each distinct (app,msg) pair of XMsgInProcessCall once.
        BOOL doLog = TRUE;
        if (ord == 500 || ord == 502)
        {
            doLog = FALSE;
            DWORD key = (a[0] << 16) ^ a[1];
            static DWORD seen[48];
            static volatile LONG nseen = 0;
            LONG n = nseen;
            BOOL found = FALSE;
            for (LONG i = 0; i < n && i < 48; ++i)
                if (seen[i] == key) { found = TRUE; break; }
            if (!found && n < 48)
            {
                LONG slot = InterlockedIncrement(&nseen) - 1;
                if (slot < 48) { seen[slot] = key; doLog = TRUE; }
            }
        }

        if (doLog)
        {
            LONG w = InterlockedIncrement(&g_FH2ProbeRareWrite) - 1;
            FH2_PROBE_RARE& q = g_FH2ProbeRare[w & (FH2_PROBE_RARE_SIZE - 1)];
            q.tick = now; q.idx = idx; q.caller = caller;
            for (int k = 0; k < 6; ++k) q.a[k] = a[k];
            q.dumpArg = 0xFFFFFFFF; q.dumpAddr = 0;
            q.xseq = 0; q.nptr = 0; q.nchain = 0;
            if (ord == 420 || ord == 421 || ord == 422)
            {
                // v0.9.1: the path string is byte-aligned (not 4-aligned); copy it bytewise.
                if (a[0] >= 0x10000 && a[0] < 0x9FFFFF00 &&
                    MmIsAddressValid((PVOID)a[0]) && MmIsAddressValid((PVOID)(a[0] + 95)))
                {
                    q.dumpArg = 0; q.dumpAddr = a[0];
                    for (int j = 0; j < 96; ++j) ((volatile BYTE*)q.dump)[j] = ((volatile BYTE*)a[0])[j];
                }
            }
            else if (ord != 592)
            {
                // v0.9.16: for XMsgStartIORequest(Ex) the interesting data is the request buffer (r6 = a[3]), not the OVERLAPPED (a[2]).
                if (g_FH2Xgi && (ord == 503 || ord == 508) && FH2_ProbeReadable(a[3], 96))
                {
                    if (ord == 503 && a[0] == 0xFB && a[1] == 0x000B0010 && !(a[3] & 3))
                    {
                        volatile DWORD* fb = (volatile DWORD*)a[3];
                        if (fb[1] == 0x00000823 && fb[2] == 0 && fb[3] > 0 && fb[3] <= 16)
                            g_FH2FreeRoamTick = now ? now : 1;
                    }
                    if (g_FH2FrSwap && ord == 503 && a[0] == 0xFB && a[1] == 0x000B0010 && !(a[3] & 3))
                    {
                        volatile DWORD* rb = (volatile DWORD*)a[3];
                        if (rb[1] == 0x00000823 && rb[2] == 0 && rb[3] > 0 && rb[3] <= 16)
                        {
                            rb[2] = rb[3]; rb[3] = 0;
                            InterlockedIncrement(&g_FH2FrSwapN);
                        }
                    }
                    q.dumpArg = 3; q.dumpAddr = a[3];
                    for (int j = 0; j < 24; ++j) q.dump[j] = ((volatile DWORD*)a[3])[j];

                    // v0.9.19: tracked session call -> sequence number, pointer arguments (words 2..11 of the request) and a result slot.
                    if (ord == 503 && a[0] == 0xFB && FH2_XgiTracked(a[1]))
                    {
                        q.xseq = (DWORD)InterlockedIncrement(&g_FH2XgiSeq);
                        if (a[1] == 0x000B0015) g_FH2LastEndTick = now ? now : 1;
                        // v1.0.10: walk the game's stack (back chain at 0(r1), saved LR at -8(prev r1)).
                        if (FH2_ProbeReadable(sp, 4))
                        {
                            DWORD s = *(volatile DWORD*)sp;
                            for (int dpt = 0; dpt < 8; ++dpt)
                            {
                                if (s < 0x70000000 || s >= 0x80000000 || (s & 7) || !FH2_ProbeReadable(s, 4)) break;
                                DWORD prev = *(volatile DWORD*)s;
                                if (prev <= s || prev >= 0x80000000 || (prev & 7) || !FH2_ProbeReadable(prev - 8, 8)) break;
                                DWORD ra = *(volatile DWORD*)(prev - 8);
                                if (ra < 0x82000000 || ra >= 0x84000000) break;
                                q.chain[q.nchain++] = ra;
                                s = prev;
                            }
                        }
                        for (int k = 2; k < 12 && q.nptr < 4; ++k)
                        {
                            DWORD v = q.dump[k];
                            BOOL dup = (v == a[3]);
                            for (DWORD m = 0; m < q.nptr; ++m) if (q.xptr[m] == v) dup = TRUE;
                            if (dup || !FH2_XgiPtrOk(v)) continue;
                            q.xptr[q.nptr] = v;
                            FH2_SafeCopy(q.xpre[q.nptr], v, 64);
                            ++q.nptr;
                        }
                        if (a[2] >= 0x10000 && !(a[2] & 3) && FH2_ProbeReadable(a[2], 28))
                        {
                            for (int s = 0; s < FH2_XGI_PEND_N; ++s)
                            {
                                FH2_XGI_PEND& pe = g_FH2XgiPend[s];
                                if (pe.used) continue;
                                pe.seq = q.xseq; pe.tick = now; pe.msg = a[1]; pe.ovl = a[2];
                                pe.snaps = 0; pe.haveSnap = 0; pe.forced = 0; pe.keep = 0; pe.fEvt = 0; pe.fCr = 0; pe.fCtx = 0; pe.nptr = q.nptr;
                                for (DWORD m = 0; m < q.nptr; ++m) { pe.ptr[m] = q.xptr[m]; memcpy(pe.pre[m], q.xpre[m], 64); }
                                pe.used = 1;
                                break;
                            }
                        }
                    }
                }
                else
                for (int k = 1; k <= 4; ++k)
                {
                    if (FH2_ProbeReadable(a[k], 96))
                    {
                        q.dumpArg = k; q.dumpAddr = a[k];
                        for (int j = 0; j < 24; ++j) q.dump[j] = ((volatile DWORD*)a[k])[j];
                        break;
                    }
                }
            }
            if (ord == 592)
            {
                // XamEnumerate(handle, flags, buffer, cb, pItems, overlapped)
                for (int i = 0; i < 8; ++i)
                {
                    if (g_FH2EnumPending[i].buf == 0 && a[2] != 0)
                    {
                        g_FH2EnumPending[i].pItems = a[4];
                        g_FH2EnumPending[i].ovl = a[5];
                        g_FH2EnumPending[i].caller = caller;
                        g_FH2EnumPending[i].handle = a[0];
                        g_FH2EnumPending[i].cb = a[3];
                        g_FH2EnumPending[i].tick = now;
                        g_FH2EnumPending[i].stage = 0;
                        g_FH2EnumPending[i].buf = a[2];
                        break;
                    }
                }
            }
        }
    }
    return g_FH2ProbeApis[idx].forward;
}


// =============================================================================
// v1.0.29: stuck-loading watchdog (read-only, log only).  The host log of the 6:19 PM car-switch hang and the 7:03 PM co-op stunt
// hang look the same: the host's UDP send rate to its peers falls from ~15-30 packets/s to ~5/s (14-byte keepalives = the game sits
// on a loading screen), no further session calls, screens or dialogs, and it never recovers.  The log shows nothing the game is
// waiting for, so when the rate collapses this writes one snapshot of everything we can read: per-peer send/recv ages, the tracked
// XGI calls, pending enumerators, the online manager / connection objects, every singleton object in the globals around the online
// manager (address, vtable) and, when an object with the session-sequence vtable (0x834656F4, the class with the 60 s limit at
// +0x144) is reachable, its fields.  One 'BASE' snapshot is taken while everything is healthy, to diff against.
static const DWORD FH2_SEQ_VPTR = 0x834656F4;

static BOOL FH2_RdOK(DWORD a, DWORD n)
{
    if (a < 0x10000 || a >= 0x9FFFFF00 || (a & 3)) return FALSE;
    for (DWORD o = 0; o < n; o += 0x400)
        if (!MmIsAddressValid((PVOID)(a + o))) return FALSE;
    return MmIsAddressValid((PVOID)(a + n - 1)) ? TRUE : FALSE;
}

static VOID FH2_StuckWords(const char* tag, DWORD addr, DWORD nWords)
{
    for (DWORD i = 0; i < nWords; i += 8)
    {
        DWORD a = addr + i * 4;
        if (!FH2_RdOK(a, 32)) { FH2_Log("v1.0.29 STUCK %s +%03X unreadable", tag, i * 4); return; }
        const volatile DWORD* p = (const volatile DWORD*)a;
        FH2_Log("v1.0.29 STUCK %s +%03X: %08X %08X %08X %08X %08X %08X %08X %08X", tag, i * 4, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    }
}

static BOOL FH2_IsObj(DWORD v, DWORD* vptr)
{
    if (v < 0x20000000 || v >= 0x9FFFFF00 || (v & 3) || !FH2_RdOK(v, 4)) return FALSE;
    DWORD vp = *(volatile DWORD*)v;
    if (vp < 0x82000000 || vp >= 0x84000000 || (vp & 3)) return FALSE;
    *vptr = vp; return TRUE;
}

// looks for the session-sequence object in nWords words of 'addr': a pointer to an object with that vtable, or the vtable word itself
static VOID FH2_FindSeq(const char* tag, DWORD addr, DWORD nWords, int* found)
{
    for (DWORD i = 0; i < nWords && *found < 3; ++i)
    {
        DWORD a = addr + i * 4;
        if (!FH2_RdOK(a, 4)) return;
        DWORD v = *(volatile DWORD*)a, vp = 0;
        if (v == FH2_SEQ_VPTR)
        {
            ++*found;
            FH2_Log("v1.0.29 STUCK SEQ-OBJECT embedded at %08X (%s+%03X)", a, tag, i * 4);
            FH2_StuckWords("SEQ-OBJ", a + 0x100, 32);
        }
        else if (FH2_IsObj(v, &vp) && vp == FH2_SEQ_VPTR)
        {
            ++*found;
            FH2_Log("v1.0.29 STUCK SEQ-OBJECT %08X referenced from %s+%03X", v, tag, i * 4);
            FH2_StuckWords("SEQ-OBJ", v + 0x100, 32);
        }
    }
}

static VOID FH2_StuckDump(DWORD now, const char* why, int episode, DWORD lowFor, DWORD rate10)
{
    FH2_Log("v1.0.29 STUCK %s: tick=%u lowFor=%us rate=%u.%u/s episode=%d xgiSeq=%d freeRoamAge=%us", why, now, lowFor / 1000, rate10 / 10, rate10 % 10, episode, (int)g_FH2XgiSeq,
        g_FH2FreeRoamTick ? (now - g_FH2FreeRoamTick) / 1000 : 0);
    for (int t = 0; t < 2; ++t)
    {
        FH2_P2P_DST* tab = t ? g_FH2P2PRecv : g_FH2P2PSend;
        LONG n = t ? g_FH2P2PRecvN : g_FH2P2PSendN; if (n > FH2_P2P_MAX) n = FH2_P2P_MAX;
        for (int i = 0; i < n; ++i)
        {
            FH2_P2P_DST& d = tab[i];
            FH2_Log("v1.0.29 STUCK peer %s %u.%u.%u.%u:%u count=%d lastAge=%ums lastRes=%d lastErr=%d", t ? "RX" : "TX",
                (d.ip >> 24) & 255, (d.ip >> 16) & 255, (d.ip >> 8) & 255, d.ip & 255, (unsigned)d.port, (int)d.count, (DWORD)(now - d.lastTick), (int)d.lastRes, (int)d.lastErr);
        }
    }
    for (int s = 0; s < FH2_XGI_PEND_N; ++s)
    {
        FH2_XGI_PEND& p = g_FH2XgiPend[s];
        if (!p.used) continue;
        DWORD o[7] = { 0 };
        if (p.ovl && FH2_RdOK(p.ovl, 28)) for (int k = 0; k < 7; ++k) o[k] = ((volatile DWORD*)p.ovl)[k];
        FH2_Log("v1.0.29 STUCK xgi-pending seq=%u msg=%08X age=%ums forced=%u ovl=%08X: %08X %08X %08X %08X %08X %08X %08X", p.seq, p.msg, (DWORD)(now - p.tick), p.forced, p.ovl, o[0], o[1], o[2], o[3], o[4], o[5], o[6]);
    }
    for (int i = 0; i < 8; ++i)
        if (g_FH2EnumPending[i].buf)
            FH2_Log("v1.0.29 STUCK enum-pending handle=%08X cb=%u age=%ums stage=%u caller=%08X ovl=%08X", g_FH2EnumPending[i].handle, g_FH2EnumPending[i].cb, (DWORD)(now - g_FH2EnumPending[i].tick), g_FH2EnumPending[i].stage, g_FH2EnumPending[i].caller, g_FH2EnumPending[i].ovl);
    FH2_Log("v1.0.29 STUCK e42 handles: %08X %08X %08X %08X %08X %08X %08X %08X", g_FH2E42Handle[0], g_FH2E42Handle[1], g_FH2E42Handle[2], g_FH2E42Handle[3], g_FH2E42Handle[4], g_FH2E42Handle[5], g_FH2E42Handle[6], g_FH2E42Handle[7]);
    DWORD mgr = *(volatile DWORD*)0x8344DB78, con = *(volatile DWORD*)0x8344DA70;
    FH2_Log("v1.0.29 STUCK online mgr=%08X conn=%08X", mgr, con);
    int found = 0;
    if (mgr) { FH2_StuckWords("mgr", mgr, 64); FH2_FindSeq("mgr", mgr, 128, &found); }
    if (con) { FH2_StuckWords("conn", con, 32); FH2_FindSeq("conn", con, 64, &found); }
    // every singleton in the globals around the online manager: global address -> object -> vtable
    CHAR line[200]; int ll = 0; line[0] = 0; int shown = 0;
    for (DWORD g = 0x8344D800; g < 0x8344DE00; g += 4)
    {
        DWORD v = *(volatile DWORD*)g, vp = 0;
        if (!FH2_IsObj(v, &vp)) continue;
        ll += sprintf_s(line + ll, sizeof(line) - ll, "%08X=%08X(%08X) ", g, v, vp);
        if (++shown % 4 == 0) { FH2_Log("v1.0.29 STUCK globals: %s", line); ll = 0; line[0] = 0; }
        if (shown <= 48) FH2_FindSeq("global", v, 160, &found);
    }
    if (ll) FH2_Log("v1.0.29 STUCK globals: %s", line);
    if (!found) FH2_Log("v1.0.29 STUCK SEQ-OBJECT (vtable 834656F4) not reachable from the online manager, connection object or the globals scanned");
}

VOID FH2_StuckWatch()
{
    if (g_FH2NoWatch || !g_FH2LogEnabled) return;
    static DWORD lastSample = 0, prevSend = 0, lowSince = 0, normalSince = 0, lastNormal = 0, ref10 = 0;
    static int episode = 0, dumps = 0, stage = 0; static BOOL baseDone = FALSE, announced = FALSE;
    DWORD now = GetTickCount();
    if (lastSample && (DWORD)(now - lastSample) < 1000) return;
    DWORD dt = lastSample ? (DWORD)(now - lastSample) : 1000; lastSample = now;
    LONG n = g_FH2P2PSendN; if (n > FH2_P2P_MAX) n = FH2_P2P_MAX;
    DWORD sum = 0; int alivePeers = 0;
    for (int i = 0; i < n; ++i) { sum += (DWORD)g_FH2P2PSend[i].count; if ((DWORD)(now - g_FH2P2PSend[i].lastTick) < 5000) ++alivePeers; }
    DWORD delta = sum - prevSend; prevSend = sum;
    DWORD rate10 = (delta * 10000) / (dt ? dt : 1000);     // packets/s x10 (all peers together)
    if (rate10 >= 200)                                     // healthy: >= 20 packets/s
    {
        if (!normalSince) normalSince = now;
        lastNormal = now;
        ref10 = ref10 ? (ref10 * 7 + rate10) / 8 : rate10;   // what "normal" looks like for this group
        if (lowSince) { if (announced) FH2_Log("v1.0.30 STUCK recovered after %us (rate %u.%u/s)", (DWORD)(now - lowSince) / 1000, rate10 / 10, rate10 % 10); lowSince = 0; stage = 0; announced = FALSE; }
        if (!baseDone && (DWORD)(now - normalSince) >= 60000 && dumps < 10)
        {
            baseDone = TRUE; ++dumps;
            __try { FH2_StuckDump(now, "BASE (healthy, for comparison)", 0, 0, rate10); } __except (EXCEPTION_EXECUTE_HANDLER) { FH2_Log("v1.0.29 STUCK BASE dump faulted"); }
        }
    }
    else if (ref10 && rate10 * 5 < ref10 * 2 && alivePeers > 0)   // under 40% of normal, and we are still sending to somebody
    {
        normalSince = 0;
        if (!lastNormal || (DWORD)(now - lastNormal) > 300000) return;
        if (!lowSince) { lowSince = now; stage = 0; announced = FALSE; }
        DWORD low = (DWORD)(now - lowSince);
        // v1.0.30: a 1-3 s dip is normal (loading, menus); only a collapse that lasts >= 4 s is announced and dumped.
        if (!announced && low >= 4000) { announced = TRUE; ++episode; FH2_Log("v1.0.30 STUCK send rate collapsed to %u.%u/s (normal %u.%u/s, episode %d)", rate10 / 10, rate10 % 10, ref10 / 10, ref10 % 10, episode); }
        static const DWORD at[4] = { 6000, 25000, 90000, 240000 };
        if (announced && stage < 4 && low >= at[stage] && dumps < 12)
        {
            ++stage; ++dumps;
            __try { FH2_StuckDump(now, "DUMP", episode, low, rate10); } __except (EXCEPTION_EXECUTE_HANDLER) { FH2_Log("v1.0.29 STUCK dump faulted"); }
        }
    }
    else
    {
        normalSince = 0;
        if (lowSince && rate10 * 5 >= ref10 * 2) { lowSince = 0; stage = 0; announced = FALSE; }
    }
}

// v1.0.31: dump a game object (screen / dialog data) so a hung stunt start can be compared with a good one.  Called from the main loop.
VOID FH2_SnapObj(const char* tag, DWORD addr, DWORD nWords)
{
    if (!g_FH2LogEnabled || g_FH2NoSnap) return;
    __try
    {
        if (!FH2_RdOK(addr, nWords * 4)) { FH2_Log("v1.0.31 SNAP %s obj=%08X not readable", tag, addr); return; }
        DWORD vp = *(volatile DWORD*)addr;
        FH2_Log("v1.0.31 SNAP %s obj=%08X vtable=%08X words=%u", tag, addr, vp, nWords);
        FH2_StuckWords(tag, addr, nWords);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { FH2_Log("v1.0.31 SNAP %s faulted", tag); }
}

// v0.9.19: called every 50 ms from the main loop (same thread as the worker, so FH2_Log is safe here).  For every tracked XGI call:
// once it is >= 120 ms old, log the 7 dwords of its OVERLAPPED (InternalLow, InternalHigh, InternalContext, hEvent, completion
// routine, completion context, dwExtendedError) and log again whenever they change (at most 4 lines); at each snapshot re-read the
// heap/static pointer arguments and log the ones whose first 64 bytes changed since the call started (= what the call wrote).
// The slot is freed after 8 s.
VOID FH2_XgiPoll()
{
    // v0.9.27: the B001F / B0015 / B0021 completions below must also run with logging OFF (FH2_Log is a no-op then), so a
    // no-log join test still behaves like the normal build.
    if (!g_FH2Xgi) return;
    if (g_FH2CloseStkReady)
    {
        // v0.9.20: code addresses on the stack when the game sent its CLOSE (see FH2_CloseStackNote).
        DWORD ip = g_FH2CloseStkIp, n = g_FH2CloseStkN;
        FH2_Log("v0.9.20 CLOSE stack: tick=%u to=%u.%u.%u.%u frames=%u", g_FH2CloseStkTick,
            (ip >> 24) & 255, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, n);
        for (DWORD k = 0; k < n; k += 8)
        {
            CHAR line[200]; line[0] = 0;
            int pos = 0;
            for (DWORD q = k; q < n && q < k + 8; ++q)
            {
                int w = sprintf_s(line + pos, sizeof(line) - pos, " %X:%08X", g_FH2CloseStkOff[q], g_FH2CloseStkAddr[q]);
                if (w > 0) pos += w;
            }
            FH2_Log("v0.9.20 CLOSE stack:%s", line);
        }
        InterlockedExchange(&g_FH2CloseStkReady, 0);
    }
    DWORD now = GetTickCount();
    {
        static LONG s_frLogged = 0;
        LONG fn = g_FH2FrSwapN;
        if (fn != s_frLogged) { s_frLogged = fn; FH2_Log("v1.0.3 XGI: free-roam session create re-shaped (0 public/N private -> N public/0 private), count=%d", fn); }
    }
    for (int s = 0; s < FH2_XGI_PEND_N; ++s)
    {
        FH2_XGI_PEND& p = g_FH2XgiPend[s];
        if (!p.used) continue;
        DWORD age = now - p.tick;
        // v0.9.21-23: the B001F (session modify), the B0015 (session end) and the B0021 (XUserReadStats, result buffer stays all zero = no stats) never complete on their own, which keeps the game's XSession operation queue busy and
        // (suspected) stops the joiner from processing the host's Welcome.  After 300 ms report it as finished OK, once.
        if (age >= 300 && !p.forced && (p.msg == 0x000B001F || p.msg == 0x000B0015 || (p.msg == 0x000B0021 && ((g_FH2LastEndTick && (p.tick - g_FH2LastEndTick) < 8000) || (!g_FH2NoFrStats && g_FH2FreeRoamTick && (p.tick - g_FH2FreeRoamTick) < 120000)))))
        {
            DWORD o[7];
            if (FH2_SafeCopy(o, p.ovl, 28) && o[0] == 0x000003E5 && !(p.ovl & 3))
            {
                volatile DWORD* ov = (volatile DWORD*)p.ovl;
                // v0.9.25: B0021 (stats read) is reported as FAILED (0x65B / 0x80004004, the pair the system itself returns for
                // failed Live calls); reporting success with an all-zero result buffer crashed the game in v0.9.23/24.
                BOOL fail = (p.msg == 0x000B0021);
                ov[6] = fail ? 0x80004004 : 0;          // dwExtendedError
                ov[1] = 0;                              // InternalHigh
                ov[0] = fail ? 0x0000065B : 0;          // InternalLow (written last)
                if (o[3] > 0x10000) SetEvent((HANDLE)o[3]);
                p.forced = 1;
                p.fEvt = o[3]; p.fCr = o[4]; p.fCtx = o[5];
                FH2_Log("v0.9.26 XGI: seq=%u %08X completed by plugin as %s at age=%ums", p.seq, p.msg, fail ? "FAILED" : "OK", age);
            }
            else if (age >= 1000) p.forced = 1;
        }
        // v1.0.11: after the plugin has reported a B001F / B0015 as OK, the real Live completion still arrives (~450 ms) and
        // overwrites the game's overlapped with its own result (low=8 for the modify).  In a Road Trip lobby the game reads the
        // result before that happens; in free roam the join takes 3-5 s and the game evaluates the modify afterwards, sees the
        // failure and tears the session down.  Put OK back (only inside the first 1.2 s, while the game's operation object is
        // certainly still alive).
        // v1.0.24: B0015 (end session) is no longer put back.  22:15:02 quit log: the game had dropped the B0015 request block within 283 ms
        // (it then held floats 1.0/4.0/5.0/0.1 and a pointer), this code zeroed three of its words at 1050 ms, and the game crashed 12 s
        // later ("Fatal Crash Intercepted").  Only the B001F modify (the case v1.0.11 was written for) is put back.
        if (p.forced && !g_FH2NoKeepOk && p.keep < 4 && age >= 300 && age < 1200 && (p.msg == 0x000B001F || (g_FH2Legacy && p.msg == 0x000B0015)))
        {
            DWORD o2[7];
            if (!(p.ovl & 3) && FH2_SafeCopy(o2, p.ovl, 28) && o2[0] != 0 && o2[0] != 0x000003E5)
            {
                // v1.0.44: only overwrite what really is the late Live completion.  Logs from every free-roam join since v1.0.11 show that
                // within ~0.5 s the game often has already freed the overlapped and reused the memory (UTF-16 text such as "3] {f", a
                // gamertag / "User" record, stack pointers).  The old test (low != 0) then zeroed three words of the game's live data;
                // both host crashes at the moment a player joined the free-roam lobby (23:14 and 20:20) had such a write ~0.1-0.7 s
                // earlier.  The real completion leaves hEvent / completion routine / context untouched and only produces one of the two
                // known pairs below; anything else is somebody else's memory: leave it alone and stop for this call.
                BOOL same = (o2[3] == p.fEvt && o2[4] == p.fCr && o2[5] == p.fCtx);
                BOOL known = (o2[0] == 0x00000008 && o2[6] == 0) || (o2[0] == 0x0000065B && o2[6] == 0x80004004);
                if (same && known)
                {
                    volatile DWORD* ov2 = (volatile DWORD*)p.ovl;
                    ov2[6] = 0; ov2[1] = 0; ov2[0] = 0;
                    ++p.keep;
                    FH2_Log("v1.0.11 XGI: seq=%u %08X late result low=%08X ext=%08X put back to OK at age=%ums", p.seq, p.msg, o2[0], o2[6], age);
                }
                else if (!same)
                {
                    p.keep = 4;
                    static LONG s_skipLogged = 0;
                    if (s_skipLogged < 40) { ++s_skipLogged; FH2_Log("v1.0.44 XGI: seq=%u %08X overlapped memory was reused by the game (low=%08X ext=%08X evt=%08X): put-back skipped at age=%ums", p.seq, p.msg, o2[0], o2[6], o2[3], age); }
                }
            }
        }
        if (age >= 120 && p.snaps < 4)
        {
            DWORD o[7];
            if (FH2_SafeCopy(o, p.ovl, 28) && (!p.haveSnap || memcmp(o, p.snap, 28) != 0))
            {
                memcpy(p.snap, o, 28);
                p.haveSnap = 1;
                ++p.snaps;
                FH2_Log("v0.9.16 XGI: seq=%u RESULT msg=%08X age=%ums low=%08X high=%08X ctx=%08X evt=%08X cr=%08X crctx=%08X ext=%08X",
                    p.seq, p.msg, age, o[0], o[1], o[2], o[3], o[4], o[5], o[6]);
                if (p.snaps == 1 && (p.msg == 0x000B0014 || p.msg == 0x000B0015))
                {
                    // v0.9.26: free memory at every event start / end (the host console leaves the game while loading event 4).
                    MEMORYSTATUS ms; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
                    FH2_Log("v0.9.26 MEM: seq=%u msg=%08X freePhys=%uMB freeVirt=%uMB totalPhys=%uMB", p.seq, p.msg,
                        (DWORD)(ms.dwAvailPhys >> 20), (DWORD)(ms.dwAvailVirtual >> 20), (DWORD)(ms.dwTotalPhys >> 20));
                }
                for (DWORD m = 0; m < p.nptr; ++m)
                {
                    if (p.ptr[m] >= 0x70000000 && p.ptr[m] < 0x80000000) continue;   // stack buffers are reused at once
                    BYTE cur[64];
                    if (!FH2_SafeCopy(cur, p.ptr[m], 64)) continue;
                    if (memcmp(cur, p.pre[m], 64) == 0) continue;
                    memcpy(p.pre[m], cur, 64);
                    CHAR hx[129];
                    FH2_Hex(hx, cur, 64);
                    FH2_Log("v0.9.16 XGI: seq=%u OUT ptr%u=%08X: %s", p.seq, m, p.ptr[m], hx);
                }
            }
        }
        if (age >= ((p.msg == 0x000B0010) ? 45000u : 8000u)) p.used = 0;
    }
}

// Open the probe window (worker thread): replay the last 1.5 s of buffered
// calls, then log live for 45 s.
VOID FH2_ProbeOpenWindow()
{
    DWORD now = GetTickCount();
    g_FH2ProbeLogged = 0;
    g_FH2ProbeOpenTick = now;
    g_FH2ProbeUntilTick = now + 45000;
    FH2_Log("PROBE WINDOW OPEN: tick=%u (replaying calls from the previous 1500 ms)", now);

    int replayed = 0;
    for (int i = 0; i < FH2_PROBE_RING_SIZE && replayed < 300; ++i)
    {
        FH2_PROBE_RING r = g_FH2ProbeRing[i];
        if (r.tick == 0 || r.idx >= FH2_PROBE_COUNT) continue;
        if ((LONG)(now - r.tick) <= 0 || (LONG)(now - r.tick) > 1500) continue;
        FH2_Log("PROBE REPLAY: tick=%u api=%s(%u) caller=0x%08X r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X",
            r.tick, g_FH2ProbeApis[r.idx].name, g_FH2ProbeApis[r.idx].ordinal, r.caller,
            r.a[0], r.a[1], r.a[2], r.a[3], r.a[4], r.a[5]);
        ++replayed;
    }
    FH2_Log("PROBE REPLAY: %d entries (unsorted ring order)", replayed);
}

// Called from the 500 ms worker (never from a hook): summarise counters and
// dump the buffers handed to XamEnumerate a few times after the call.
VOID FH2_ProbeTick()
{
    // Flush network-API provenance snapshots (socket/connect/send/XNet/XamSession).
    {
        LONG w = g_FH2_ProvRingWrite;
        if (w - g_FH2_ProvRingRead > 128) g_FH2_ProvRingRead = w - 128;
        while (g_FH2_ProvRingRead < w)
        {
            FH2_PROV_RING q = g_FH2_ProvRing[g_FH2_ProvRingRead & 127];
            ++g_FH2_ProvRingRead;
            // v0.9.12: when quiet, drop only the TCP send/WSASend calls (server traffic, one per request); keep every
            // socket / connect / sendto / WSASendTo / XNet call so the peer connection steps are recorded.
            if (g_FH2Quiet && (q.api == FH2_PROV_SEND || q.api == FH2_PROV_WSASEND || q.api == FH2_PROV_SENDTO || q.api == FH2_PROV_WSASENDTO))
                continue;
            // v0.9.19: with 'xgi' the socket / XamSession lines only duplicate the XGI lines; keep connect / XNetConnect / XNetServerToInAddr.
            if (g_FH2Xgi && (q.api == FH2_PROV_SOCKET || q.api == FH2_PROV_XAM_SESSION_CREATE || q.api == FH2_PROV_XAM_SESSION_REFOBJ))
                continue;
            FH2_Log("PROVENANCE CALL: seq=%d tick=%u api=%s caller=0x%08X",
                q.seq, q.tick, FH2_ProvApiName(q.api), q.caller);
        }
    }

    // Flush rare-call snapshots recorded by hook threads.
    {
        LONG w = g_FH2ProbeRareWrite;
        if (w - g_FH2ProbeRareRead > FH2_PROBE_RARE_SIZE)
        {
            FH2_Log("PROBE RARE: ring overflow, lost %d entries", w - g_FH2ProbeRareRead - FH2_PROBE_RARE_SIZE);
            g_FH2ProbeRareRead = w - FH2_PROBE_RARE_SIZE;
        }
        while (g_FH2ProbeRareRead < w && g_FH2ProbeLogged < (g_FH2Xgi ? 4000 : 900))
        {
            FH2_PROBE_RARE q = g_FH2ProbeRare[g_FH2ProbeRareRead & (FH2_PROBE_RARE_SIZE - 1)];
            ++g_FH2ProbeRareRead;
            InterlockedIncrement(&g_FH2ProbeLogged);
            if (q.idx >= FH2_PROBE_COUNT) continue;
            if (g_FH2Xgi)
            {
                DWORD ordX = g_FH2ProbeApis[q.idx].ordinal;
                if (ordX == 500 || ordX == 502 || ordX == 503 || ordX == 508)
                {
                    // compact: one line per XMsg call, first 12 dwords of the request buffer when it was readable.
                    // 503/508 args: app, message, overlapped, buffer, length[, extra].  500/502: app, message, p1, p2, ...
                    if (q.dumpArg != 0xFFFFFFFF)
                        FH2_Log("v0.9.16 XGI: tick=%u seq=%u %u app=%08X msg=%08X a2=%08X a3=%08X a4=%08X a5=%08X caller=%08X arg%u: %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X %08X",
                            q.tick, q.xseq, ordX, q.a[0], q.a[1], q.a[2], q.a[3], q.a[4], q.a[5], q.caller, q.dumpArg + 3,
                            q.dump[0], q.dump[1], q.dump[2], q.dump[3], q.dump[4], q.dump[5], q.dump[6], q.dump[7], q.dump[8], q.dump[9], q.dump[10], q.dump[11]);
                    else
                        FH2_Log("v0.9.16 XGI: tick=%u seq=%u %u app=%08X msg=%08X a2=%08X a3=%08X a4=%08X a5=%08X caller=%08X",
                            q.tick, q.xseq, ordX, q.a[0], q.a[1], q.a[2], q.a[3], q.a[4], q.a[5], q.caller);
                    if (q.xseq && q.nchain)
                        FH2_Log("v1.0.10 XGI: seq=%u msg=%08X stack: %08X %08X %08X %08X %08X %08X %08X %08X",
                            q.xseq, q.a[1], q.chain[0], q.nchain > 1 ? q.chain[1] : 0, q.nchain > 2 ? q.chain[2] : 0,
                            q.nchain > 3 ? q.chain[3] : 0, q.nchain > 4 ? q.chain[4] : 0, q.nchain > 5 ? q.chain[5] : 0,
                            q.nchain > 6 ? q.chain[6] : 0, q.nchain > 7 ? q.chain[7] : 0);
                    // v0.9.19: contents (first 32 bytes) of the pointer arguments of tracked session calls, as they were when the call started.
                    for (DWORD pi = 0; pi < q.nptr && pi < 3; ++pi)
                    {
                        CHAR hx[65];
                        FH2_Hex(hx, q.xpre[pi], 32);
                        FH2_Log("v0.9.16 XGI: seq=%u ptr%u=%08X: %s", q.xseq, pi, q.xptr[pi], hx);
                    }
                    continue;
                }
            }
            FH2_Log("PROBE CALL: tick=%u api=%s(%u) caller=0x%08X r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X",
                q.tick, g_FH2ProbeApis[q.idx].name, g_FH2ProbeApis[q.idx].ordinal, q.caller,
                q.a[0], q.a[1], q.a[2], q.a[3], q.a[4], q.a[5]);
            if (q.dumpArg != 0xFFFFFFFF)
            {
                for (int j = 0; j < 24; j += 4)
                    FH2_Log("PROBE ARG r%u(0x%08X) +%03X: %08X %08X %08X %08X",
                        q.dumpArg + 3, q.dumpAddr, j * 4, q.dump[j], q.dump[j+1], q.dump[j+2], q.dump[j+3]);
            }            if (q.dumpArg == 0 && g_FH2ProbeApis[q.idx].ordinal >= 420 && g_FH2ProbeApis[q.idx].ordinal <= 422)
            {
                CHAR path[97];
                const BYTE* src = (const BYTE*)q.dump;
                for (int j = 0; j < 96; ++j) path[j] = (src[j] >= 32 && src[j] < 127) ? (CHAR)src[j] : (src[j] ? '?' : 0);
                path[96] = 0;
                FH2_Log("v0.9.3 LAUNCH PATH: \"%s\" flags=%08X", path, q.a[1]);
            }
        }
    }
    static LONG lastSum = -1;
    static DWORD lastSummary = 0;
    DWORD now = GetTickCount();

    LONG sum = 0;
    for (int i = 0; i < FH2_PROBE_COUNT; ++i) sum += g_FH2ProbeCounts[i];
    if (sum != lastSum && (now - lastSummary) > 5000)
    {
        CHAR line[400]; int n = 0;
        for (int i = 0; i < FH2_PROBE_COUNT; ++i)
            n += sprintf_s(line + n, sizeof(line) - n, "%s=%d ", g_FH2ProbeApis[i].name, g_FH2ProbeCounts[i]);
        FH2_Log("PROBE COUNTS: %s", line);
        lastSum = sum;
        lastSummary = now;
    }

    // v0.8.9: the game calls XNetStartup before the plugin can hook it, so the
    // security-bypass flag never applied and the console drops replies from the
    // LAN server.  Restart the title's XNet stack once with the flag set.
    if (!g_FH2NetRestartDone && !g_FH2SkipNetRestart && g_FH2SetupTick &&
        (DWORD)(GetTickCount() - g_FH2SetupTick) >= FH2_NET_RESTART_DELAY_MS)
    {
        g_FH2NetRestartDone = TRUE;
        int rc = NetDll_XNetCleanup(XNCALLER_TITLE);
        XNetStartupParams sp;
        ZeroMemory(&sp, sizeof(sp));
        sp.cfgSizeOfStruct = sizeof(sp);
        sp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
        int rs = NetDll_XNetStartup(XNCALLER_TITLE, &sp);
        FH2_Log("v0.8.9 XNET RESTART: XNetCleanup=%d XNetStartup(bypass)=%d flags=0x%02X", rc, rs, (DWORD)sp.cfgFlags);
    }

    // v0.8.13: poll the console's own title address (XNetGetTitleXnAddr) once a second,
    // log when it changes, so we can see if/when the stack gets its IP (ctx.ip).
    {
        static DWORD lastAddr = 0;
        static DWORD prevFlags = 0xDEADBEEF, prevIna = 0xDEADBEEF;
        if (g_FH2SetupTick && (DWORD)(now - lastAddr) >= 1000)
        {
            lastAddr = now;
            pFH2_XNetGetTitleXnAddr fa = g_FH2_XNetGetTitleXnAddr;
            if (!fa) fa = (pFH2_XNetGetTitleXnAddr)ResolveFunction("xam.xex", 73);
            if (fa)
            {
                XNADDR xa;
                ZeroMemory(&xa, sizeof(xa));
                DWORD fl = fa(XNCALLER_TITLE, &xa);
                DWORD ina = xa.ina.S_un.S_addr;
                if (fl != prevFlags || ina != prevIna)
                {
                    DWORD inaOn = xa.inaOnline.S_un.S_addr;
                    FH2_Log("v0.8.13 TITLEADDR: tick=%u flags=0x%08X ina=%u.%u.%u.%u mac=%02X:%02X:%02X:%02X:%02X:%02X online=%u.%u.%u.%u port=%u",
                        now, fl, (ina >> 24) & 255, (ina >> 16) & 255, (ina >> 8) & 255, ina & 255,
                        xa.abEnet[0], xa.abEnet[1], xa.abEnet[2], xa.abEnet[3], xa.abEnet[4], xa.abEnet[5],
                        (inaOn >> 24) & 255, (inaOn >> 16) & 255, (inaOn >> 8) & 255, inaOn & 255, (unsigned)xa.wPortOnline);
                    prevFlags = fl; prevIna = ina;
                }
            }
        }
    }

    // v0.8.12: poll the XNet packet counters (XNetGetOpt ids 2..9) once a second and
    // log only when something changes.  NIC counters are console-wide; CALLER counters
    // are for the title since XNetStartup.  Comparing NIC rx vs CALLER rx while the
    // PC answers our SYN tells us where inbound frames are being dropped.
    {
        static DWORD lastStats = 0;
        static ULONGLONG prevV[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        static BOOL statsFirst = TRUE;
        if (g_FH2SetupTick && (DWORD)(now - lastStats) >= 1000)
        {
            lastStats = now;
            pFH2_XNetGetOpt fn = g_FH2_XNetGetOpt;
            if (!fn) fn = (pFH2_XNetGetOpt)ResolveFunction("xam.xex", 78);
            if (fn)
            {
                ULONGLONG v[8];
                int rc[8];
                BOOL changed = statsFirst;
                for (int k = 0; k < 8; ++k)
                {
                    DWORD id = 2 + k;                 // 2..9
                    BYTE buf[16];
                    ZeroMemory(buf, sizeof(buf));
                    DWORD sz = (id & 1) ? 4 : 8;      // odd ids are DWORD frame counts, even ids ULONGLONG byte counts
                    rc[k] = fn(XNCALLER_TITLE, id, buf, &sz);
                    v[k] = 0;
                    if (rc[k] == 0)
                    {
                        if (id & 1) { DWORD d32 = 0; memcpy(&d32, buf, 4); v[k] = d32; }
                        else { ULONGLONG d64 = 0; memcpy(&d64, buf, 8); v[k] = d64; }
                    }
                    if (v[k] != prevV[k]) changed = TRUE;
                }
                if (changed)
                {
                    FH2_Log("v0.8.12 NETSTATS tick=%u nicTx=%u/%ufr nicRx=%u/%ufr callerTx=%u/%ufr callerRx=%u/%ufr rc=%d,%d,%d,%d,%d,%d,%d,%d",
                        now, (DWORD)v[0], (DWORD)v[1], (DWORD)v[2], (DWORD)v[3],
                        (DWORD)v[4], (DWORD)v[5], (DWORD)v[6], (DWORD)v[7],
                        rc[0], rc[1], rc[2], rc[3], rc[4], rc[5], rc[6], rc[7]);
                    for (int k = 0; k < 8; ++k) prevV[k] = v[k];
                    statsFirst = FALSE;
                }
            }
        }
    }

    FH2_P2PFlush();   // v0.9.13: peer UDP send/recv summary lines

    // v0.8.5: flush synthetic title-server events.
    {
        LONG w = g_FH2SynthEvtWrite;
        if (w - g_FH2SynthEvtRead > FH2_SYNTH_EVT_SIZE) g_FH2SynthEvtRead = w - FH2_SYNTH_EVT_SIZE;
        while (g_FH2SynthEvtRead < w)
        {
            FH2_SYNTH_EVT e = g_FH2SynthEvt[g_FH2SynthEvtRead & (FH2_SYNTH_EVT_SIZE - 1)];
            ++g_FH2SynthEvtRead;
            if (e.code == 1)
                FH2_Log("SYNTH CREATE: tick=%u handle=%08X result=%08X count=%u extra=%u", e.tick, e.a, e.b, e.c, e.d);
            else if (e.code == 2)
                FH2_Log("SYNTH ENUM: tick=%u handle=%08X items=%u err=%08X ovl=%08X", e.tick, e.a, e.b, e.c, e.d);
            else if (e.code == 20)
                FH2_Log("v0.8.17 E42 CREATE: tick=%u handle=%08X result=%08X count=%u extra=%u", e.tick, e.a, e.b, e.c, e.d);
            else if (e.code == 21)
                FH2_Log("v0.8.17 E42 ENUM completed EMPTY: tick=%u handle=%08X cb=%u err=%08X ovl=%08X", e.tick, e.a, e.b, e.c, e.d);
            else if (e.code == 30)
                FH2_Log("v0.9.15 P2P XnAddrToInAddr: tick=%u peerPublic=%u.%u.%u.%u:%u peerLan=%u.%u.%u.%u result=%d resultInAddr=%u.%u.%u.%u",
                    e.tick, (e.a >> 24) & 255, (e.a >> 16) & 255, (e.a >> 8) & 255, e.a & 255, (e.b >> 16) & 0xFFFF,
                    (e.c >> 24) & 255, (e.c >> 16) & 255, (e.c >> 8) & 255, e.c & 255, (int)(short)(e.b & 0xFFFF),
                    (e.d >> 24) & 255, (e.d >> 16) & 255, (e.d >> 8) & 255, e.d & 255);
            else if (e.code == 31)
                FH2_Log("v0.9.15 P2P XNKID: tick=%u %08X%08X", e.tick, e.a, e.b);
            else if (e.code == 32)
                FH2_Log("v0.9.15 P2P XNetConnect: tick=%u inaddr=%u.%u.%u.%u result=%d",
                    e.tick, (e.a >> 24) & 255, (e.a >> 16) & 255, (e.a >> 8) & 255, e.a & 255, (int)e.b);
            else if (e.code == 34)
                FH2_Log("v0.9.20 P2P XNetUnregisterInAddr: tick=%u inaddr=%u.%u.%u.%u result=%d",
                    e.tick, (e.a >> 24) & 255, (e.a >> 16) & 255, (e.a >> 8) & 255, e.a & 255, (int)e.b);
            else if (e.code == 33)
                FH2_Log("v0.9.15 P2P XNetGetConnectStatus: tick=%u inaddr=%u.%u.%u.%u status=0x%08X (was 0x%08X; 0=idle 1=pending 2=connected 3=incomplete 4=lost)",
                    e.tick, (e.a >> 24) & 255, (e.a >> 16) & 255, (e.a >> 8) & 255, e.a & 255, e.b, e.c);
            else if (e.code == 4)
                FH2_Log("v0.8.13 XNET STATUS: tick=%u inaddr=%08X returnedStatus=%u realStatus=0x%08X", e.tick, e.a, e.b, e.c);
            else if (e.code == 10)
                FH2_Log("v0.8.13 SOCK select: tick=%u ret=%d trackedBefore=0x%X trackedAfter=0x%X (1=read 2=write 4=except) timeoutMs=%u", e.tick, (int)e.a, e.b, e.c, e.d);
            else if (e.code == 11)
                FH2_Log("v0.8.13 SOCK getsockopt: tick=%u sock=%d level=%u opt=0x%04X result=%d value=0x%08X%s", e.tick, (int)e.a, e.b >> 16, e.b & 0xFFFF, (int)e.c, e.d, ((e.b & 0xFFFF) == 0x1007) ? " (SO_ERROR)" : "");
            else if (e.code == 12)
                FH2_Log("v0.8.13 SOCK close: tick=%u sock=%d result=%d", e.tick, (int)e.a, (int)e.b);
            else if (e.code == 13)
                FH2_Log("v0.8.13 SOCK ioctl: tick=%u sock=%d cmd=0x%08X arg=%u result=%d", e.tick, (int)e.a, e.b, e.c, (int)e.d);
            else if (e.code == 14)
                FH2_Log("v0.8.13 SOCK send: tick=%u sock=%d len=%u result=%d wsaErr=%d", e.tick, (int)e.a, e.b, (int)e.c, (int)e.d);
            else if (e.code == 15 || e.code == 17)
                FH2_Log("v0.8.13 SOCK %s payload[0..15]: tick=%u %08X %08X %08X %08X", e.code == 15 ? "send" : "recv", e.tick, e.a, e.b, e.c, e.d);
            else if (e.code == 16)
                FH2_Log("v0.8.13 SOCK recv: tick=%u sock=%d bufLen=%u result=%d wsaErr=%d", e.tick, (int)e.a, e.b, (int)e.c, (int)e.d);
            else
                FH2_Log("SYNTH NET: tick=%u code=%u(3=XNetConnect 4=Status 5=ServerToInAddr 6=Unreg 7=XNetStartup[xnc,flagsBefore,flagsAfter,ret] 8=socket[af|type|proto,sock,setsockopt] 9=connect[sock,result,wsaerr,portRaw]) a=%08X b=%08X c=%08X d=%08X", e.tick, e.code, e.a, e.b, e.c, e.d);
        }
    }

    static const DWORD stageAges[4] = { 1000, 5000, 15000, 30000 };
    for (int i = 0; i < 8; ++i)
    {
        FH2_ENUM_PENDING& e = g_FH2EnumPending[i];
        if (!e.buf) continue;
        if (g_FH2EnumLogBudget <= 0) { e.buf = 0; continue; }
        if (e.stage < 4 && (now - e.tick) >= stageAges[e.stage])
        {
            DWORD items = FH2_ProbeReadable(e.pItems, 4) ? *((volatile DWORD*)e.pItems) : 0xFFFFFFFF;
            InterlockedDecrement(&g_FH2EnumLogBudget);
            FH2_Log("PROBE ENUM RESULT: slot=%d age=%ums caller=0x%08X handle=%08X buf=0x%08X cb=%u items=%u",
                i, now - e.tick, e.caller, e.handle, e.buf, e.cb, items);
            if (FH2_ProbeReadable(e.ovl, 32))
            {
                volatile DWORD* o = (volatile DWORD*)e.ovl;
                FH2_Log("PROBE ENUM OVL: slot=%d ovl=0x%08X InternalLow=%08X InternalHigh=%08X w2=%08X w3=%08X w4=%08X w5=%08X w6=%08X w7=%08X",
                    i, e.ovl, o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]);
            }
            DWORD dump = e.cb < 192 ? e.cb : 192;
            if (dump >= 16 && e.stage == 0) FH2_ProbeHex("ENUMBUF", e.buf, dump & ~15);
            ++e.stage;
            if (e.stage >= 4) e.buf = 0;
        }
    }
}

static int NTAPI FH2_XNetStartupSynth(XNCALLER_TYPE xnc, XNetStartupParams* p)
{
    static XNetStartupParams own;
    DWORD before = 0xFFFFFFFF;
    if (p && MmIsAddressValid(p))
    {
        before = (DWORD)p->cfgFlags;
        if (!g_FH2NoBypass) p->cfgFlags |= XNET_STARTUP_BYPASS_SECURITY;
    }
    else
    {
        ZeroMemory(&own, sizeof(own));
        own.cfgSizeOfStruct = sizeof(own);
        own.cfgFlags = g_FH2NoBypass ? 0 : XNET_STARTUP_BYPASS_SECURITY;
        p = &own;
    }
    int r = NetDll_XNetStartup(xnc, p);
    FH2_Log("v0.9.9 XNetStartup seen: flagsBefore=0x%02X flagsAfter=0x%02X nobypass=%d ret=%d", before, (DWORD)p->cfgFlags, g_FH2NoBypass ? 1 : 0, r);
    FH2_SynthEvt(7, (DWORD)xnc, before, (DWORD)p->cfgFlags, (DWORD)r);
    return r;
}

static int NTAPI FH2_NetDll_XNetUnregisterInAddrSynth(XNCALLER_TYPE xnc, const IN_ADDR ina)
{
    if (ina.S_un.S_addr == g_FH2SynthIp)
    {
        FH2_SynthEvt(6, ina.S_un.S_addr, 0, 0, 0);
        return 0;
    }
    // v0.9.20: peer addresses only record that the game released the connection (ring event, logged by the worker).
    int ur = NetDll_XNetUnregisterInAddr(xnc, ina);
    FH2_SynthEvt(34, ina.S_un.S_addr, (DWORD)ur, 0, 0);
    return ur;
}

static VOID FH2_InstallSockDiag(PLDR_DATA_TABLE_ENTRY module)
{
    // v0.8.13: select(15), getsockopt(8), closesocket(4), ioctlsocket(6) tracing for TCP sockets.
    {
        g_FH2_real_select = (pFH2_select)ResolveFunction("xam.xex", 15);
        g_FH2_real_getsockopt = (pFH2_getsockopt)ResolveFunction("xam.xex", 8);
        g_FH2_real_closesocket = (pFH2_closesocket)ResolveFunction("xam.xex", 4);
        g_FH2_real_ioctlsocket = (pFH2_ioctlsocket)ResolveFunction("xam.xex", 6);
        DWORD c15 = FH2_CountModuleImport(module, "xam.xex", 15);
        DWORD c8 = FH2_CountModuleImport(module, "xam.xex", 8);
        DWORD c4 = FH2_CountModuleImport(module, "xam.xex", 4);
        DWORD c6 = FH2_CountModuleImport(module, "xam.xex", 6);
        DWORD r15 = (c15 && g_FH2_real_select) ? PatchModuleImport(module, "xam.xex", 15, (DWORD)FH2_NetDll_selectTrace) : S_FALSE;
        DWORD r8 = (c8 && g_FH2_real_getsockopt) ? PatchModuleImport(module, "xam.xex", 8, (DWORD)FH2_NetDll_getsockoptTrace) : S_FALSE;
        DWORD r4 = (c4 && g_FH2_real_closesocket) ? PatchModuleImport(module, "xam.xex", 4, (DWORD)FH2_NetDll_closesocketTrace) : S_FALSE;
        DWORD r6 = (c6 && g_FH2_real_ioctlsocket) ? PatchModuleImport(module, "xam.xex", 6, (DWORD)FH2_NetDll_ioctlsocketTrace) : S_FALSE;
        FH2_Log("v0.8.14 SOCK hooks: select imports=%u res=%08X getsockopt imports=%u res=%08X closesocket imports=%u res=%08X ioctlsocket imports=%u res=%08X",
            c15, r15, c8, r8, c4, r4, c6, r6);
        g_FH2_real_recv = (pFH2_recv)ResolveFunction("xam.xex", 18);
        DWORD c18 = FH2_CountModuleImport(module, "xam.xex", 18);
        DWORD r18 = (c18 && g_FH2_real_recv) ? PatchModuleImport(module, "xam.xex", 18, (DWORD)FH2_NetDll_recvDiag) : S_FALSE;
        FH2_Log("v0.8.16 SOCK recv hook: imports=%u res=%08X", c18, r18);
    }
}

BOOL SetupFH2XamProbeHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
    if (!module)
        return FALSE;

    DWORD installed = 0;
    for (int i = 0; i < FH2_PROBE_COUNT; ++i)
    {
        DWORD ordI = g_FH2ProbeApis[i].ordinal;
        BOOL xgiKeep = g_FH2Xgi && (ordI == 500 || ordI == 502 || ordI == 503 || ordI == 508 || ordI == 420 || ordI == 421 || ordI == 422 || ordI == 425);
        if (g_FH2NoProbe && ordI != 590 && ordI != 592 && !xgiKeep)
        {
            FH2_Log("PROBE SETUP: api=%s ordinal=%u skipped (noprobe)", g_FH2ProbeApis[i].name, g_FH2ProbeApis[i].ordinal);
            continue;
        }
        DWORD count = FH2_CountModuleImport(module, "xam.xex", g_FH2ProbeApis[i].ordinal);
        g_FH2ProbeApis[i].forward = (DWORD)ResolveFunction("xam.xex", g_FH2ProbeApis[i].ordinal);
        if (g_FH2ProbeApis[i].forward && g_FH2ProbeApis[i].ordinal == 590)
        {
            g_FH2RealCreateEnum = (pFH2_RealCreateEnum)g_FH2ProbeApis[i].forward;
            g_FH2ProbeApis[i].forward = (DWORD)&FH2_XamCreateEnumeratorSynth;
        }
        else if (g_FH2ProbeApis[i].forward && g_FH2ProbeApis[i].ordinal == 592)
        {
            g_FH2RealEnumerate = (pFH2_RealEnumerate)g_FH2ProbeApis[i].forward;
            g_FH2ProbeApis[i].forward = (DWORD)&FH2_XamEnumerateSynth;
        }
        if (!count || !g_FH2ProbeApis[i].forward)
        {
            FH2_Log("PROBE SETUP: api=%s ordinal=%u imports=%u original=0x%08X; skipped",
                g_FH2ProbeApis[i].name, g_FH2ProbeApis[i].ordinal, count, g_FH2ProbeApis[i].forward);
            continue;
        }
        DWORD result = PatchModuleImport(module, "xam.xex", g_FH2ProbeApis[i].ordinal, g_FH2ProbeApis[i].wrapper);
        FH2_Log("PROBE SETUP: api=%s ordinal=%u imports=%u original=0x%08X hook=0x%08X result=0x%08X",
            g_FH2ProbeApis[i].name, g_FH2ProbeApis[i].ordinal, count,
            g_FH2ProbeApis[i].forward, g_FH2ProbeApis[i].wrapper, result);
        if (result == S_OK) ++installed;
    }
    g_FH2SetupTick = GetTickCount();
    FH2_ReadSynthConfig();
    FH2_InstallStateTrace(g_FH2TraceEnabled);
    FH2_InstallCrashLog();
    FH2_Log("v0.8.5 SYNTH: title-server entry %u.%u.%u.%u, real create=0x%08X real enumerate=0x%08X",
        (g_FH2SynthIp >> 24) & 255, (g_FH2SynthIp >> 16) & 255, (g_FH2SynthIp >> 8) & 255, g_FH2SynthIp & 255,
        (DWORD)g_FH2RealCreateEnum, (DWORD)g_FH2RealEnumerate);
    if (FH2_CountModuleImport(module, "xam.xex", 51))
    {
        DWORD r51 = PatchModuleImport(module, "xam.xex", 51, (DWORD)FH2_XNetStartupSynth);
        FH2_Log("v0.8.5 XNetStartup security-bypass hook result=0x%08X", r51);
    }
    if (FH2_CountModuleImport(module, "xam.xex", 66))
    {
        DWORD r66 = PatchModuleImport(module, "xam.xex", 66, (DWORD)FH2_NetDll_XNetGetConnectStatusTrace);
        FH2_Log("v0.8.7 XNetGetConnectStatus hook result=0x%08X", r66);
    }
    if (FH2_CountModuleImport(module, "xam.xex", 63))
    {
        DWORD r63 = PatchModuleImport(module, "xam.xex", 63, (DWORD)FH2_NetDll_XNetUnregisterInAddrSynth);
        FH2_Log("v0.8.7 XNetUnregisterInAddr hook result=0x%08X", r63);
    }
    FH2_InstallSockDiag(module);
    FH2_Log("v0.8.4 XAM PROBE hooks installed=%u of %d", installed, FH2_PROBE_COUNT);
    return installed != 0;
}


VOID SetupFH2SocketIOTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c18 = FH2_CountModuleImport(module, "xam.xex", 18);
    DWORD c19 = FH2_CountModuleImport(module, "xam.xex", 19);
    DWORD c20 = FH2_CountModuleImport(module, "xam.xex", 20);
    DWORD c21 = FH2_CountModuleImport(module, "xam.xex", 21);
    DWORD c22 = FH2_CountModuleImport(module, "xam.xex", 22);
    DWORD c23 = FH2_CountModuleImport(module, "xam.xex", 23);
    DWORD c24 = FH2_CountModuleImport(module, "xam.xex", 24);
    DWORD c25 = FH2_CountModuleImport(module, "xam.xex", 25);

    FH2_Log("v0.4.1 SOCKET IO IMPORTS: recv18=%u WSARecv19=%u recvfrom20=%u WSARecvFrom21=%u send22=%u WSASend23=%u sendto24=%u WSASendTo25=%u",
        c18, c19, c20, c21, c22, c23, c24, c25);

    DWORD r18 = c18 ? PatchModuleImport(module, "xam.xex", 18, (DWORD)FH2_NetDll_recvTrace) : S_FALSE;
    DWORD r19 = c19 ? PatchModuleImport(module, "xam.xex", 19, (DWORD)FH2_NetDll_WSARecvTrace) : S_FALSE;
    DWORD r20 = c20 ? PatchModuleImport(module, "xam.xex", 20, (DWORD)FH2_NetDll_recvfromTrace) : S_FALSE;
    DWORD r21 = c21 ? PatchModuleImport(module, "xam.xex", 21, (DWORD)FH2_NetDll_WSARecvFromTrace) : S_FALSE;
    DWORD r22 = c22 ? PatchModuleImport(module, "xam.xex", 22, (DWORD)FH2_NetDll_sendTrace) : S_FALSE;
    DWORD r23 = c23 ? PatchModuleImport(module, "xam.xex", 23, (DWORD)FH2_NetDll_WSASendTrace) : S_FALSE;
    DWORD r24 = c24 ? PatchModuleImport(module, "xam.xex", 24, (DWORD)FH2_NetDll_sendtoTrace) : S_FALSE;
    DWORD r25 = c25 ? PatchModuleImport(module, "xam.xex", 25, (DWORD)FH2_NetDll_WSASendToTrace) : S_FALSE;

    FH2_Log("v0.4.1 SOCKET IO hooks: recv18=%08X WSARecv19=%08X recvfrom20=%08X WSARecvFrom21=%08X send22=%08X WSASend23=%08X sendto24=%08X WSASendTo25=%08X",
        r18, r19, r20, r21, r22, r23, r24, r25);

    // Map the two session-object imports FH2 definitely has.  We do not hook
    // their private ABIs; instead, record title-side callsites so they can be
    // inspected safely in EmDbg/X360DebuggerWV if the socket trace is silent.
    DWORD thunks[8] = { 0 };
    DWORD n790 = FH2_CollectModuleImportThunks(module, "xam.xex", 790, thunks, 8);
    for (DWORD i = 0; i < n790 && i < 8; ++i)
        FH2_ScanDirectBranchesToTargetDetailed(module, thunks[i], "XamSessionCreateHandle");

    ZeroMemory(thunks, sizeof(thunks));
    DWORD n791 = FH2_CollectModuleImportThunks(module, "xam.xex", 791, thunks, 8);
    for (DWORD i = 0; i < n791 && i < 8; ++i)
        FH2_ScanDirectBranchesToTargetDetailed(module, thunks[i], "XamSessionRefObjByHandle");
}


VOID SetupFH2BackendQoSTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c69 = FH2_CountModuleImport(module, "xam.xex", 69);
    DWORD c70 = FH2_CountModuleImport(module, "xam.xex", 70);
    DWORD c71 = FH2_CountModuleImport(module, "xam.xex", 71);
    DWORD c72 = FH2_CountModuleImport(module, "xam.xex", 72);

    // Presence-only census for several higher-level session/app paths.  These
    // are deliberately not hooked until we have evidence FH2 actually uses one
    // during the delayed failure.
    DWORD c583  = FH2_CountModuleImport(module, "xam.xex", 583);  // XamSendMessageToLoadedApps
    DWORD c584  = FH2_CountModuleImport(module, "xam.xex", 584);  // XamAppRequestLoad
    DWORD c769  = FH2_CountModuleImport(module, "xam.xex", 769);  // XamShowJoinSessionInProgressUI
    DWORD c779  = FH2_CountModuleImport(module, "xam.xex", 779);  // XamShowCommunitySessionsUI
    DWORD c790  = FH2_CountModuleImport(module, "xam.xex", 790);  // XamSessionCreateHandle
    DWORD c791  = FH2_CountModuleImport(module, "xam.xex", 791);  // XamSessionRefObjByHandle
    DWORD c1904 = FH2_CountModuleImport(module, "xam.xex", 1904); // XamAppGetSessionId

    FH2_Log("v0.4.0 BACKEND IMPORTS: qos69/70/71/72=%u/%u/%u/%u app583/584=%u/%u session769/779/790/791/1904=%u/%u/%u/%u/%u",
        c69, c70, c71, c72, c583, c584, c769, c779, c790, c791, c1904);

    g_FH2_XNetQosListen  = (pFH2_XNetQosListen)ResolveFunction("xam.xex", 69);
    g_FH2_XNetQosLookup  = (pFH2_XNetQosLookup)ResolveFunction("xam.xex", 70);
    g_FH2_XNetQosRelease = (pFH2_XNetQosRelease)ResolveFunction("xam.xex", 72);

    DWORD r69 = (c69 && g_FH2_XNetQosListen)
        ? PatchModuleImport(module, "xam.xex", 69, (DWORD)FH2_XNetQosListenTrace) : S_FALSE;
    DWORD r70 = (c70 && g_FH2_XNetQosLookup)
        ? PatchModuleImport(module, "xam.xex", 70, (DWORD)FH2_XNetQosLookupTrace) : S_FALSE;
    DWORD r72 = (c72 && g_FH2_XNetQosRelease)
        ? PatchModuleImport(module, "xam.xex", 72, (DWORD)FH2_XNetQosReleaseTrace) : S_FALSE;

    FH2_Log("v0.4.0 QOS TRACE hooks: listen69=%08X lookup70=%08X release72=%08X",
        r69, r70, r72);
}

// -----------------------------------------------------------------------------
// FH2 v0.9.4: peer-connection visibility (pass-through traces only).
//
// After the join "soft reboot" we have no evidence of what the restarted game
// does with the host's address.  Trace the XNet address translation calls, the
// QoS calls and recvfrom, so FH2Revival.log shows whether (and how) it tries to
// reach the host.  Nothing here changes behaviour.
//   57 = NetDll_XNetXnAddrToInAddr(xnc, XNADDR*, XNKID*, IN_ADDR*)
//   60 = NetDll_XNetInAddrToXnAddr(xnc, IN_ADDR, XNADDR*, XNKID*)
// -----------------------------------------------------------------------------
typedef int (NTAPI* pFH2_XNetXnAddrToInAddr)(XNCALLER_TYPE xnc, const XNADDR* pxna, const XNKID* pxnkid, IN_ADDR* pina);
typedef int (NTAPI* pFH2_XNetInAddrToXnAddr)(XNCALLER_TYPE xnc, const IN_ADDR ina, XNADDR* pxna, XNKID* pxnkid);
static pFH2_XNetXnAddrToInAddr g_FH2_XnAddrToInAddr = NULL;
static pFH2_XNetInAddrToXnAddr g_FH2_InAddrToXnAddr = NULL;
static volatile LONG g_FH2_PeerTraceCount = 0;

int NTAPI FH2_XNetXnAddrToInAddrTrace(XNCALLER_TYPE xnc, const XNADDR* pxna, const XNKID* pxnkid, IN_ADDR* pina)
{
    if (!g_FH2_XnAddrToInAddr)
        return SOCKET_ERROR;
    BOOL doLog = (g_FH2LogEnabled && InterlockedIncrement(&g_FH2_PeerTraceCount) <= 200);
    if (doLog)
    {
        FH2_Log("v0.9.4 PEER: XNetXnAddrToInAddr BEGIN");
        if (pxna && FH2_IsReadableRange((DWORD)pxna, sizeof(XNADDR)))
            FH2_NetDumpBuffer("PEER XNADDR", (PVOID)pxna, sizeof(XNADDR));
        if (pxnkid && FH2_IsReadableRange((DWORD)pxnkid, sizeof(XNKID)))
            FH2_NetDumpBuffer("PEER XNKID", (PVOID)pxnkid, sizeof(XNKID));
    }
    int result = g_FH2_XnAddrToInAddr(xnc, pxna, pxnkid, pina);
    {
        // v0.9.13: ring events (worker logs them): peer XNADDR, XNKID and the resulting IN_ADDR.
        DWORD pIna = 0, pOn = 0, pPort = 0, kA = 0, kB = 0, oIna = 0;
        if (pxna && FH2_IsReadableRange((DWORD)pxna, sizeof(XNADDR))) { pIna = pxna->ina.S_un.S_addr; pOn = pxna->inaOnline.S_un.S_addr; pPort = pxna->wPortOnline; }
        if (pxnkid && FH2_IsReadableRange((DWORD)pxnkid, 8)) { const DWORD* kp = (const DWORD*)pxnkid; kA = kp[0]; kB = kp[1]; }
        if (pina && FH2_IsReadableRange((DWORD)pina, 4)) oIna = pina->S_un.S_addr;
        FH2_SynthEvt(30, pOn, (pPort << 16) | ((DWORD)result & 0xFFFF), pIna, oIna);
        FH2_SynthEvt(31, kA, kB, 0, 0);
    }
    if (doLog)
    {
        DWORD ina = 0;
        if (pina && FH2_IsReadableRange((DWORD)pina, 4)) ina = pina->S_un.S_addr;
        FH2_Log("v0.9.4 PEER: XNetXnAddrToInAddr END result=%d ina=0x%08X", result, ina);
    }
    return result;
}

int NTAPI FH2_XNetInAddrToXnAddrTrace(XNCALLER_TYPE xnc, const IN_ADDR ina, XNADDR* pxna, XNKID* pxnkid)
{
    if (!g_FH2_InAddrToXnAddr)
        return SOCKET_ERROR;
    int result = g_FH2_InAddrToXnAddr(xnc, ina, pxna, pxnkid);
    if (g_FH2LogEnabled && InterlockedIncrement(&g_FH2_PeerTraceCount) <= 200)
    {
        FH2_Log("v0.9.4 PEER: XNetInAddrToXnAddr ina=0x%08X result=%d", ina.S_un.S_addr, result);
        if (result == 0 && pxna && FH2_IsReadableRange((DWORD)pxna, sizeof(XNADDR)))
            FH2_NetDumpBuffer("PEER XNADDR(out)", (PVOID)pxna, sizeof(XNADDR));
    }
    return result;
}

VOID SetupFH2PeerTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    g_FH2_XnAddrToInAddr = (pFH2_XNetXnAddrToInAddr)ResolveFunction("xam.xex", 57);
    g_FH2_InAddrToXnAddr = (pFH2_XNetInAddrToXnAddr)ResolveFunction("xam.xex", 60);

    DWORD c57 = FH2_CountModuleImport(module, "xam.xex", 57);
    DWORD c60 = FH2_CountModuleImport(module, "xam.xex", 60);
    DWORD c20 = FH2_CountModuleImport(module, "xam.xex", 20);
    DWORD c21 = FH2_CountModuleImport(module, "xam.xex", 21);

    DWORD r57 = (c57 && g_FH2_XnAddrToInAddr) ? PatchModuleImport(module, "xam.xex", 57, (DWORD)FH2_XNetXnAddrToInAddrTrace) : S_FALSE;
    DWORD r60 = (c60 && g_FH2_InAddrToXnAddr) ? PatchModuleImport(module, "xam.xex", 60, (DWORD)FH2_XNetInAddrToXnAddrTrace) : S_FALSE;
    DWORD r20 = c20 ? PatchModuleImport(module, "xam.xex", 20, (DWORD)FH2_NetDll_recvfromTrace) : S_FALSE;
    DWORD r21 = c21 ? PatchModuleImport(module, "xam.xex", 21, (DWORD)FH2_NetDll_WSARecvFromTrace) : S_FALSE;

    FH2_Log("v0.9.4 PEER TRACE: imports 57/60/20/21=%u/%u/%u/%u hooks=%08X/%08X/%08X/%08X", c57, c60, c20, c21, r57, r60, r20, r21);

    SetupFH2BackendQoSTraceHooks();
}

VOID SetupFH2ConnectivityGateTraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    DWORD c73 = FH2_CountModuleImport(module, "xam.xex", 73);
    DWORD c75 = FH2_CountModuleImport(module, "xam.xex", 75);
    DWORD c78 = FH2_CountModuleImport(module, "xam.xex", 78);

    // Presence-only probes for additional status helpers. We deliberately do
    // not hook these private/uncertain ABIs in this build.
    DWORD c1269 = FH2_CountModuleImport(module, "xam.xex", 1269); // XamNetworkStatusGetInformation
    DWORD c1290 = FH2_CountModuleImport(module, "xam.xex", 1290); // XTestOnlineIsConnectedToLive
    DWORD c1318 = FH2_CountModuleImport(module, "xam.xex", 1318); // XamInputGetFailedConnectionOrBind
    DWORD c1320 = FH2_CountModuleImport(module, "xam.xex", 1320); // XamIsOnPrivateNetwork

    FH2_Log("v0.3.8 XNET GATE IMPORTS: titleXnAddr(73)=%u ethernet(75)=%u getOpt(78)=%u netStatus(1269)=%u connectedLive(1290)=%u failedConn(1318)=%u privateNet(1320)=%u",
        c73, c75, c78, c1269, c1290, c1318, c1320);

    g_FH2_XNetGetTitleXnAddr = (pFH2_XNetGetTitleXnAddr)ResolveFunction("xam.xex", 73);
    g_FH2_XNetGetEthernetLinkStatus = (pFH2_XNetGetEthernetLinkStatus)ResolveFunction("xam.xex", 75);
    g_FH2_XNetGetOpt = (pFH2_XNetGetOpt)ResolveFunction("xam.xex", 78);

    DWORD r73 = (c73 && g_FH2_XNetGetTitleXnAddr)
        ? PatchModuleImport(module, "xam.xex", 73, (DWORD)FH2_XNetGetTitleXnAddrTrace) : S_FALSE;
    DWORD r75 = (c75 && g_FH2_XNetGetEthernetLinkStatus)
        ? PatchModuleImport(module, "xam.xex", 75, (DWORD)FH2_XNetGetEthernetLinkStatusTrace) : S_FALSE;
    DWORD r78 = (c78 && g_FH2_XNetGetOpt)
        ? PatchModuleImport(module, "xam.xex", 78, (DWORD)FH2_XNetGetOptTrace) : S_FALSE;

    FH2_Log("v0.3.8 XNET GATE hooks: titleXnAddr=%08X ethernet=%08X getOpt=%08X",
        r73, r75, r78);
}


// -----------------------------------------------------------------------------
// FH2 v0.4.5 - low-impact availability caller counter profiler
//
// The 0x823F2870 getter is too hot for debugger breakpoints. v0.4.4 also tried
// to perform disk logging from the hot hook itself, which produced no runtime
// records on hardware. v0.4.5 keeps the hook minimal: it only updates RAM
// counters. A separate worker thread writes one-second snapshots to the log.
// -----------------------------------------------------------------------------

struct FH2_AVAIL_CALLER_SLOT
{
    volatile DWORD caller;
    volatile LONG count;
    DWORD reportedCount;
    BOOL announced;
};

static FH2_AVAIL_CALLER_SLOT g_FH2AvailSlots[4096] = { 0 };
static volatile LONG g_FH2AvailTotalCalls = 0;
static volatile BOOL g_FH2AvailProfilerRunning = FALSE;

static VOID FH2_RecordAvailabilityCallerFast(DWORD returnAddress)
{
    DWORD caller = returnAddress >= 4 ? (returnAddress - 4) : returnAddress;
    if (caller < 0x82000000 || caller >= 0x84000000)
        return;

    InterlockedIncrement(&g_FH2AvailTotalCalls);

    DWORD base = (caller >> 2) & 0xFFF;
    for (DWORD probe = 0; probe < 4; ++probe)
    {
        FH2_AVAIL_CALLER_SLOT* slot = &g_FH2AvailSlots[(base + probe) & 0xFFF];
        DWORD existing = slot->caller;
        if (existing == caller)
        {
            InterlockedIncrement(&slot->count);
            return;
        }
        if (existing == 0)
        {
            slot->caller = caller;
            InterlockedIncrement(&slot->count);
            return;
        }
    }
}

static DWORD FH2_AvailabilityProfilerWorker(LPVOID)
{
    DWORD second = 0;
    LONG lastTotal = 0;
    FH2_Log("v0.4.5 AVAIL COUNTER worker started (1s snapshots; no file I/O in getter hook).");

    while (bRunContinuous && g_FH2AvailProfilerRunning)
    {
        Sleep(1000);
        ++second;

        LONG total = g_FH2AvailTotalCalls;
        LONG totalDelta = total - lastTotal;
        lastTotal = total;
        FH2_Log("AVAIL SNAP: sec=%u total=%ld delta=%ld", second, total, totalDelta);

        for (DWORD i = 0; i < 4096; ++i)
        {
            FH2_AVAIL_CALLER_SLOT* slot = &g_FH2AvailSlots[i];
            DWORD caller = slot->caller;
            if (!caller)
                continue;

            DWORD count = (DWORD)slot->count;
            DWORD delta = count - slot->reportedCount;
            if (!slot->announced)
            {
                slot->announced = TRUE;
                FH2_Log("AVAIL CALLER: NEW caller=0x%08X count=%u", caller, count);
            }
            if (delta)
            {
                FH2_Log("AVAIL CALLER: ACTIVE caller=0x%08X delta=%u total=%u sec=%u",
                    caller, delta, count, second);
                slot->reportedCount = count;
            }
        }
    }

    FH2_Log("v0.4.5 AVAIL COUNTER worker stopped.");
    return 0;
}

__declspec(naked) DWORD FH2_InternalAvailabilityCounterHook()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0x70(r1)
        stw     r12, 0x68(r1)
        mr      r3, r12
        bl      FH2_RecordAvailabilityCallerFast
        lwz     r12, 0x68(r1)
        addi    r1, r1, 0x70
        mtlr    r12
        li      r3, 1
        blr
    }
}

VOID SetupFH2AvailabilityCallerProfiler()
{
    DWORD* target = (DWORD*)0x823F2870;
    const DWORD expected0 = 0x81632334;
    const DWORD expected1 = 0x2F0B0002;
    const DWORD expected2 = 0x419A0010;
    const DWORD expected3 = 0x896333DC;

    if (target[0] == expected0 && target[1] == expected1 &&
        target[2] == expected2 && target[3] == expected3)
    {
        memset(g_FH2AvailSlots, 0, sizeof(g_FH2AvailSlots));
        g_FH2AvailTotalCalls = 0;
        g_FH2AvailProfilerRunning = TRUE;
        PatchInJump(target, (DWORD)&FH2_InternalAvailabilityCounterHook, FALSE);
        FH2_Log("v0.4.5 AVAIL COUNTER installed at 0x823F2870 -> hook 0x%08X (always TRUE).",
            (DWORD)&FH2_InternalAvailabilityCounterHook);
        ThreadMe((LPTHREAD_START_ROUTINE)FH2_AvailabilityProfilerWorker);
    }
    else
    {
        FH2_Log("v0.4.5 AVAIL COUNTER FAILED at 0x823F2870. Found %08X %08X %08X %08X; expected %08X %08X %08X %08X.",
            target[0], target[1], target[2], target[3],
            expected0, expected1, expected2, expected3);
    }
}


// -----------------------------------------------------------------------------
// FH2 v0.9.5: join-after-relaunch visibility (pass-through traces only).
//
// v0.9.4 proved the invite block is correct and that the relaunched game never reaches
// peer networking. v0.9.5 therefore watches the pieces the SDK says matter for an invite
// that arrives at launch: notification listeners (XN_LIVE_INVITE_ACCEPTED /
// XN_SYS_SIGNINCHANGED are queued until the first listener exists), the storage-device
// check behind the "STORAGE DEVICE NOT CONNECTED" popup (ERROR_DEVICE_NOT_CONNECTED =
// 0x48F), and the Live sign-in / multiplayer-privilege answers (privilege 254).
//
// Every hook forwards the original arguments and return value untouched.
// -----------------------------------------------------------------------------
typedef DWORD (NTAPI* pFH2_V095_NotifyCreateListener)(ULONGLONG qwAreas, DWORD dwArea);
typedef BOOL  (NTAPI* pFH2_V095_NotifyGetNext)(HANDLE hNotification, DWORD dwMsgFilter, PDWORD pdwId, PDWORD pParam);
typedef DWORD (NTAPI* pFH2_V095_ContentGetDeviceState)(DWORD deviceId, PVOID pOverlapped);
typedef DWORD (NTAPI* pFH2_V095_ShowDeviceSelectorUI)(DWORD r3, DWORD r4, DWORD r5, DWORD r6, DWORD r7, DWORD r8, DWORD r9, DWORD r10);

static pFH2_V095_NotifyCreateListener g_FH2_V095_NotifyCreateListener = NULL;
static pFH2_V095_NotifyGetNext g_FH2_V095_NotifyGetNext = NULL;
static pFH2_V095_ContentGetDeviceState g_FH2_V095_ContentGetDeviceState = NULL;
static pFH2_V095_ShowDeviceSelectorUI g_FH2_V095_ShowDeviceSelectorUI = NULL;

DWORD NTAPI FH2_V095_NotifyCreateListenerTrace(ULONGLONG qwAreas, DWORD dwArea)
{
    DWORD result = g_FH2_V095_NotifyCreateListener
        ? g_FH2_V095_NotifyCreateListener(qwAreas, dwArea)
        : 0;
    if (FH2_V095_TraceOk())
        FH2_Log("v0.9.5 NOTIFY: XNotifyCreateListener areas=0x%08X%08X area=%u -> handle=0x%08X tick=%u",
            (DWORD)(qwAreas >> 32), (DWORD)(qwAreas & 0xFFFFFFFF), dwArea, result, GetTickCount());
    return result;
}

BOOL NTAPI FH2_V095_NotifyGetNextTrace(HANDLE hNotification, DWORD dwMsgFilter, PDWORD pdwId, PDWORD pParam)
{
    BOOL result = g_FH2_V095_NotifyGetNext
        ? g_FH2_V095_NotifyGetNext(hNotification, dwMsgFilter, pdwId, pParam)
        : FALSE;

    // The game polls this every frame. Only a notification that was actually delivered is interesting.
    if (result && FH2_V095_TraceOk())
    {
        DWORD id = 0xFFFFFFFF, param = 0xFFFFFFFF;
        if (pdwId && MmIsAddressValid(pdwId)) id = *pdwId;
        if (pParam && MmIsAddressValid(pParam)) param = *pParam;
        FH2_Log("v0.9.5 NOTIFY: XNotifyGetNext DELIVERED id=0x%08X param=0x%08X handle=0x%08X filter=0x%08X tick=%u",
            id, param, (DWORD)hNotification, dwMsgFilter, GetTickCount());
    }
    return result;
}

DWORD NTAPI FH2_V095_ContentGetDeviceStateTrace(DWORD deviceId, PVOID pOverlapped)
{
    DWORD result = g_FH2_V095_ContentGetDeviceState
        ? g_FH2_V095_ContentGetDeviceState(deviceId, pOverlapped)
        : ERROR_PROC_NOT_FOUND;
    if (FH2_V095_TraceOk())
        FH2_Log("v0.9.5 STORAGE: XContentGetDeviceState device=0x%08X ovl=0x%08X -> 0x%08X (0x48F=not connected) tick=%u",
            deviceId, (DWORD)pOverlapped, result, GetTickCount());
    return result;
}

DWORD NTAPI FH2_V095_ShowDeviceSelectorUITrace(DWORD r3, DWORD r4, DWORD r5, DWORD r6, DWORD r7, DWORD r8, DWORD r9, DWORD r10)
{
    // XShowDeviceSelectorUI(user r3, contentType r4, flags r5, ULARGE_INTEGER bytes r6, PXCONTENTDEVICEID pDevice r7, PXOVERLAPPED r8)
    DWORD result = g_FH2_V095_ShowDeviceSelectorUI
        ? g_FH2_V095_ShowDeviceSelectorUI(r3, r4, r5, r6, r7, r8, r9, r10)
        : ERROR_PROC_NOT_FOUND;
    if (FH2_V095_TraceOk())
    {
        DWORD dev = 0xFFFFFFFF;
        if (r7 >= 0x10000 && MmIsAddressValid((PVOID)r7)) dev = *(DWORD*)r7;
        FH2_Log("v0.9.5 STORAGE: XShowDeviceSelectorUI user=%u type=0x%08X flags=0x%08X bytes=0x%08X pDevice=0x%08X(now 0x%08X) ovl=0x%08X -> 0x%08X tick=%u",
            r3, r4, r5, r6, r7, dev, r8, result, GetTickCount());
    }
    return result;
}

// v1.0.13: log every notification the game receives (XNotifyGetNext returning TRUE), uncapped and without any trace window.  The ring is
// filled by the game thread and drained by the poll thread (FH2_NtfDrain).
struct FH2_NTF_ENTRY { DWORD tick, id, param; };
static FH2_NTF_ENTRY g_FH2NtfRing[64];
static volatile DWORD g_FH2NtfN = 0;
static DWORD g_FH2NtfDrained = 0;
static pFH2_V095_NotifyGetNext g_FH2NtfReal = NULL;

BOOL NTAPI FH2_NtfGetNext(HANDLE hNotification, DWORD dwMsgFilter, PDWORD pdwId, PDWORD pParam)
{
    BOOL result = g_FH2NtfReal ? g_FH2NtfReal(hNotification, dwMsgFilter, pdwId, pParam) : FALSE;
    if (result)
    {
        DWORD id = 0xFFFFFFFF, param = 0xFFFFFFFF;
        if (pdwId && MmIsAddressValid(pdwId)) id = *pdwId;
        if (pParam && MmIsAddressValid(pParam)) param = *pParam;
        DWORD n = g_FH2NtfN;
        FH2_NTF_ENTRY& e = g_FH2NtfRing[n & 63];
        e.tick = GetTickCount(); e.id = id; e.param = param;
        g_FH2NtfN = n + 1;
    }
    return result;
}

VOID FH2_NtfInstall()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
    DWORD c651 = FH2_CountModuleImport(module, "xam.xex", 651);
    g_FH2NtfReal = (pFH2_V095_NotifyGetNext)ResolveFunction("xam.xex", 651);
    DWORD r = (c651 && g_FH2NtfReal) ? PatchModuleImport(module, "xam.xex", 651, (DWORD)FH2_NtfGetNext) : S_FALSE;
    FH2_Log("v1.0.13 notification log: XNotifyGetNext imports=%u result=%08X", c651, r);
}

VOID FH2_NtfDrain()
{
    DWORD n = g_FH2NtfN;
    if (n - g_FH2NtfDrained > 64) g_FH2NtfDrained = n - 64;
    while (g_FH2NtfDrained != n)
    {
        FH2_NTF_ENTRY e = g_FH2NtfRing[g_FH2NtfDrained & 63];
        FH2_Log("v1.0.13 NOTIFY: tick=%u id=0x%08X param=0x%08X", e.tick, e.id, e.param);
        ++g_FH2NtfDrained;
    }
}

VOID SetupFH2V095TraceHooks()
{
    PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;

    // Fresh per-instance counters (the title can be relaunched without unloading this plugin).
    FH2_V095_ResetTraceCounters();

    // Sign-in state / privilege / online-enabled / signin-info / overlapped-error traces.
    SetupFH2EligibilityTraceHooks();

    DWORD c650 = FH2_CountModuleImport(module, "xam.xex", 650); // XNotifyCreateListener
    DWORD c651 = FH2_CountModuleImport(module, "xam.xex", 651); // XNotifyGetNext
    DWORD c613 = FH2_CountModuleImport(module, "xam.xex", 613); // XContentGetDeviceState
    DWORD c715 = FH2_CountModuleImport(module, "xam.xex", 715); // XShowDeviceSelectorUI

    g_FH2_V095_NotifyCreateListener = (pFH2_V095_NotifyCreateListener)ResolveFunction("xam.xex", 650);
    g_FH2_V095_NotifyGetNext = (pFH2_V095_NotifyGetNext)ResolveFunction("xam.xex", 651);
    g_FH2_V095_ContentGetDeviceState = (pFH2_V095_ContentGetDeviceState)ResolveFunction("xam.xex", 613);
    g_FH2_V095_ShowDeviceSelectorUI = (pFH2_V095_ShowDeviceSelectorUI)ResolveFunction("xam.xex", 715);

    DWORD r650 = (c650 && g_FH2_V095_NotifyCreateListener)
        ? PatchModuleImport(module, "xam.xex", 650, (DWORD)FH2_V095_NotifyCreateListenerTrace) : S_FALSE;
    DWORD r651 = (c651 && g_FH2_V095_NotifyGetNext)
        ? PatchModuleImport(module, "xam.xex", 651, (DWORD)FH2_V095_NotifyGetNextTrace) : S_FALSE;
    DWORD r613 = (c613 && g_FH2_V095_ContentGetDeviceState)
        ? PatchModuleImport(module, "xam.xex", 613, (DWORD)FH2_V095_ContentGetDeviceStateTrace) : S_FALSE;
    DWORD r715 = (c715 && g_FH2_V095_ShowDeviceSelectorUI)
        ? PatchModuleImport(module, "xam.xex", 715, (DWORD)FH2_V095_ShowDeviceSelectorUITrace) : S_FALSE;

    FH2_Log("v0.9.5 TRACE hooks: imports listener650=%u getnext651=%u devstate613=%u devsel715=%u results=%08X/%08X/%08X/%08X tick=%u",
        c650, c651, c613, c715, r650, r651, r613, r715, GetTickCount());
}


// ======================================================================================================================================
// v1.0.41: wait-site profiler.  Opt-in synth word 'waitdiag' (nothing below runs, and nothing is patched, without it).
//
// Question it answers: when a console is stuck on the co-op loading screen, which kernel wait is the game blocked in (or is it not blocked
// in any wait at all, i.e. spinning)?
//
// How: the game calls the kernel through small import thunks (lis r11 / addi r11 / mtctr r11 / bctr).  For the four wait/sleep imports the
// thunk is replaced with a jump to a wrapper.  The wrapper records the call (thread id, caller address, two return addresses up the
// stack, wait object, timeout, start tick) in a small table, calls the real kernel function with the registers unchanged, and clears the
// record when the wait returns.  Nothing is ever logged from inside the wrapper.  The existing 20 ms poll thread reads the table and
// writes the log lines: one line when a wait passes 5 s (and again at 10 s, 20 s, 40 s ...), one line when a wait that lasted 5 s or more
// ends, and a summary every 10 s (how many waits, which call sites call them most often - a tight Sleep(1) spin shows up there).
//
// Safety: each thunk is only patched after its four instruction words match the expected retail build exactly; any mismatch means that
// thunk is left alone and the words found are logged.  Remaining risk: it is a code patch in the game image.
// ======================================================================================================================================
#define FH2_WD_SLOTS    64
#define FH2_WD_DONE     16
#define FH2_WD_BUCKETS  32
#define FH2_WD_LONG_MS  5000

struct FH2_WD_SLOT
{
    volatile LONG state;     // 0 = free, 1 = being filled, 2 = wait in progress
    DWORD sp, kind, tid, start;
    DWORD a0, a1;            // a0 = object / handle / objects array, a1 = object count (multi)
    DWORD tmoHi, tmoLo, haveTmo;
    DWORD caller, ret1, ret2;
    DWORD nextLog;
};

struct FH2_WD_DONE_ENT
{
    volatile LONG seq;
    DWORD kind, tid, dur, caller, ret1, ret2, a0, result;
};

struct FH2_WD_BUCKET
{
    volatile DWORD key;
    volatile LONG count;
    volatile DWORD kind;
};

struct FH2_WD_SITE
{
    DWORD thunk;             // import thunk in the game image
    DWORD target;            // kernel function the thunk is expected to jump to
    DWORD wrapper;
    const CHAR* name;
};

static FH2_WD_SLOT       g_wdSlot[FH2_WD_SLOTS];
static FH2_WD_DONE_ENT   g_wdDone[FH2_WD_DONE];
static FH2_WD_BUCKET     g_wdBucket[FH2_WD_BUCKETS];
static volatile LONG     g_wdDoneHead = 0;
static LONG              g_wdDoneTail = 0;
static volatile LONG     g_wdEnters[4] = { 0, 0, 0, 0 };
static volatile LONG     g_wdDropped = 0;
static DWORD             g_wdOrig[4] = { 0, 0, 0, 0 };
static volatile LONG     g_wdActive = 0;
static BOOL              g_wdInstalled = FALSE;
static BOOL              g_wdGaveUp = FALSE;
static DWORD             g_wdTries = 0;
static DWORD             g_wdLastTry = 0;
static DWORD             g_wdLastStat = 0;
static DWORD             g_wdLines = 0;

static const CHAR* g_wdKindName[4] = { "KeWaitForSingleObject", "KeWaitForMultipleObjects", "NtWaitForSingleObjectEx", "KeDelayExecutionThread" };

DWORD FH2_WaitEnter(DWORD idx, DWORD caller, DWORD sp, DWORD* regs);
VOID  FH2_WaitLeave(DWORD sp, DWORD result);

// Wrappers.  Same frame discipline as FH2_ProbeWrap*: r3..r10 are saved at 0x24..0x40, the original LR at 0x4C.
// Only 32-bit halves of r3..r10 are saved (all four functions take 32-bit values or pointers); the return value is kept as a full 64-bit register.
__declspec(naked) VOID FH2_WaitWrap0()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0xB0(r1)
        stw     r12, 0x4C(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        li      r3, 0
        mr      r4, r12
        mr      r5, r1
        addi    r6, r1, 0x24
        bl      FH2_WaitEnter
        mtctr   r3
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        bctrl
        std     r3,  0x68(r1)
        mr      r4, r3
        mr      r3, r1
        bl      FH2_WaitLeave
        ld      r3,  0x68(r1)
        lwz     r12, 0x4C(r1)
        mtlr    r12
        addi    r1, r1, 0xB0
        blr
    }
}

__declspec(naked) VOID FH2_WaitWrap1()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0xB0(r1)
        stw     r12, 0x4C(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        li      r3, 1
        mr      r4, r12
        mr      r5, r1
        addi    r6, r1, 0x24
        bl      FH2_WaitEnter
        mtctr   r3
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        bctrl
        std     r3,  0x68(r1)
        mr      r4, r3
        mr      r3, r1
        bl      FH2_WaitLeave
        ld      r3,  0x68(r1)
        lwz     r12, 0x4C(r1)
        mtlr    r12
        addi    r1, r1, 0xB0
        blr
    }
}

__declspec(naked) VOID FH2_WaitWrap2()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0xB0(r1)
        stw     r12, 0x4C(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        li      r3, 2
        mr      r4, r12
        mr      r5, r1
        addi    r6, r1, 0x24
        bl      FH2_WaitEnter
        mtctr   r3
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        bctrl
        std     r3,  0x68(r1)
        mr      r4, r3
        mr      r3, r1
        bl      FH2_WaitLeave
        ld      r3,  0x68(r1)
        lwz     r12, 0x4C(r1)
        mtlr    r12
        addi    r1, r1, 0xB0
        blr
    }
}

__declspec(naked) VOID FH2_WaitWrap3()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0xB0(r1)
        stw     r12, 0x4C(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        li      r3, 3
        mr      r4, r12
        mr      r5, r1
        addi    r6, r1, 0x24
        bl      FH2_WaitEnter
        mtctr   r3
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        bctrl
        std     r3,  0x68(r1)
        mr      r4, r3
        mr      r3, r1
        bl      FH2_WaitLeave
        ld      r3,  0x68(r1)
        lwz     r12, 0x4C(r1)
        mtlr    r12
        addi    r1, r1, 0xB0
        blr
    }
}

// Walks two frames up from the wrapper's frame.  *(r1) is the back chain, the saved return address of a frame lives at (its caller's r1) - 8.
// Every pointer is range-checked and MmIsAddressValid-checked before it is read; on anything odd the values stay 0.
static VOID FH2_WdWalk(DWORD sp, DWORD* ret1, DWORD* ret2)
{
    *ret1 = 0; *ret2 = 0;
    DWORD f = *(volatile DWORD*)sp;                       // frame of the function that called the wait import
    if (f <= sp || (f & 7) || (f - sp) > 0x4000) return;
    if (!MmIsAddressValid((PVOID)f)) return;
    DWORD p = *(volatile DWORD*)f;                        // frame of that function's caller
    if (p <= f || (p & 7) || (p - f) > 0x20000) return;
    if (!MmIsAddressValid((PVOID)(p - 8))) return;
    *ret1 = *(volatile DWORD*)(p - 8);                    // return address of the function that called the wait import
    if (!MmIsAddressValid((PVOID)p)) return;
    DWORD q = *(volatile DWORD*)p;
    if (q <= p || (q & 7) || (q - p) > 0x20000) return;
    if (!MmIsAddressValid((PVOID)(q - 8))) return;
    *ret2 = *(volatile DWORD*)(q - 8);
}

DWORD FH2_WaitEnter(DWORD idx, DWORD caller, DWORD sp, DWORD* regs)
{
    idx &= 3;
    DWORD orig = g_wdOrig[idx];
    if (!g_wdActive) return orig;
    InterlockedIncrement(&g_wdEnters[idx]);

    DWORD a0 = 0, a1 = 0, tp = 0;
    switch (idx)
    {
    case 0: a0 = regs[0]; tp = regs[4]; break;                    // KeWaitForSingleObject(obj, reason, mode, alertable, timeout)
    case 1: a0 = regs[1]; a1 = regs[0]; tp = regs[6]; break;      // KeWaitForMultipleObjects(count, objs, type, reason, mode, alertable, timeout, blocks)
    case 2: a0 = regs[0]; tp = regs[3]; break;                    // NtWaitForSingleObjectEx(handle, mode, alertable, timeout)
    default: tp = regs[2]; break;                                 // KeDelayExecutionThread(mode, alertable, interval)
    }

    DWORD ret1 = 0, ret2 = 0;
    FH2_WdWalk(sp, &ret1, &ret2);

    // call-site histogram (a tight Sleep(1) / wait spin shows up here even though no single wait is long)
    {
        DWORD key = ret1 ? ret1 : caller;
        FH2_WD_BUCKET* b = &g_wdBucket[(key >> 2) & (FH2_WD_BUCKETS - 1)];
        if (b->key != key) { b->key = key; b->kind = idx; }
        InterlockedIncrement(&b->count);
    }

    DWORD haveTmo = 0, hi = 0, lo = 0;
    if (tp >= 0x10000 && !(tp & 3) && MmIsAddressValid((PVOID)tp) && MmIsAddressValid((PVOID)(tp + 7)))
    {
        haveTmo = 1;
        hi = *(volatile DWORD*)tp;
        lo = *(volatile DWORD*)(tp + 4);
        // relative timeouts are negative 100 ns units; a wait that can't reach 4 s is not worth a slot
        if (hi == 0xFFFFFFFF && lo > (DWORD)(-(LONG)40000000)) return orig;
    }

    for (int i = 0; i < FH2_WD_SLOTS; ++i)
    {
        FH2_WD_SLOT* s = &g_wdSlot[i];
        if (s->state != 0) continue;
        if (InterlockedCompareExchange(&s->state, 1, 0) != 0) continue;
        s->sp = sp; s->kind = idx; s->tid = GetCurrentThreadId(); s->start = GetTickCount();
        s->a0 = a0; s->a1 = a1; s->haveTmo = haveTmo; s->tmoHi = hi; s->tmoLo = lo;
        s->caller = caller; s->ret1 = ret1; s->ret2 = ret2; s->nextLog = FH2_WD_LONG_MS;
        __sync();
        s->state = 2;
        return orig;
    }
    InterlockedIncrement(&g_wdDropped);
    return orig;
}

VOID FH2_WaitLeave(DWORD sp, DWORD result)
{
    for (int i = 0; i < FH2_WD_SLOTS; ++i)
    {
        FH2_WD_SLOT* s = &g_wdSlot[i];
        if (s->state != 2 || s->sp != sp) continue;
        DWORD dur = GetTickCount() - s->start;
        if (dur >= FH2_WD_LONG_MS)
        {
            LONG n = InterlockedIncrement(&g_wdDoneHead) - 1;
            FH2_WD_DONE_ENT* d = &g_wdDone[n & (FH2_WD_DONE - 1)];
            d->seq = 0;
            d->kind = s->kind; d->tid = s->tid; d->dur = dur; d->caller = s->caller; d->ret1 = s->ret1; d->ret2 = s->ret2;
            d->a0 = s->a0; d->result = result;
            __sync();
            d->seq = n + 1;
        }
        InterlockedExchange(&s->state, 0);
        return;
    }
}

static VOID FH2_WdFlushCode(DWORD* fn, DWORD bytes)
{
    for (DWORD o = 0; o < bytes; o += 4) __dcbst(0, (void*)((DWORD)fn + o));
    __sync();
    typedef VOID (NTAPI *pSweep)(PVOID, DWORD);
    pSweep sweep = (pSweep)ResolveFunction("xboxkrnl.exe", 171);   // KeSweepIcacheRange, same as the other code hooks
    if (sweep) sweep((PVOID)fn, bytes);
    __sync();
    __isync();
}

// --------------------------------------------------------------------------------------------------------------------------------------
// v1.0.43: lock profiler.  Opt-in synth word 'lockdiag'.  The game's RtlEnterCriticalSection import thunk (0x832F2034) is replaced by a wrapper.
// Every call is recorded in a table (thread, lock address, call site, start tick) and the record is removed when the call returns; the
// lock itself is never touched on the way in, so the lock's internal layout does not matter for correctness.  A call that has not returned
// after 2 s shows up as a LOCK WAIT line (written by the poll thread) with the raw lock words, the apparent owner, and what the owner is
// doing (waiting on another lock = deadlock chain, waiting in a kernel wait, or running).
// --------------------------------------------------------------------------------------------------------------------------------------
#define FH2_LK_SLOTS 256

struct FH2_LK_SLOT
{
    volatile LONG sp;          // wrapper frame address of the calling thread, 0 = free
    volatile DWORD start;      // tick | 1 when the call started, 0 = not published yet
    DWORD cs, caller, tid;
    DWORD seenStart, nextLog;  // poll thread only
};

struct FH2_LK_ID { DWORD tid, id; };

static FH2_LK_SLOT       g_lkSlot[FH2_LK_SLOTS];
static FH2_LK_ID         g_lkId[128];
static DWORD             g_lkOrig = 0;
static volatile LONG     g_lkActive = 0;
static volatile LONG     g_lkEnters = 0;
static volatile LONG     g_lkDropped = 0;
static DWORD             g_lkLines = 0;
static DWORD             g_lkLinesStat = 0;
static DWORD             g_lkLastStat = 0;

DWORD FH2_LockEnter(DWORD cs, DWORD caller, DWORD sp);
VOID  FH2_LockDone(DWORD cs, DWORD sp);

// r3 = critical section.  Same frame discipline as the wait wrappers.  RtlEnterCriticalSection returns nothing meaningful; r3 is still kept intact.
__declspec(naked) VOID FH2_LockWrap()
{
    __asm
    {
        mflr    r12
        stwu    r1, -0xB0(r1)
        stw     r12, 0x4C(r1)
        stw     r3,  0x24(r1)
        stw     r4,  0x28(r1)
        stw     r5,  0x2C(r1)
        stw     r6,  0x30(r1)
        stw     r7,  0x34(r1)
        stw     r8,  0x38(r1)
        stw     r9,  0x3C(r1)
        stw     r10, 0x40(r1)
        mr      r4, r12
        mr      r5, r1
        bl      FH2_LockEnter
        mtctr   r3
        lwz     r3,  0x24(r1)
        lwz     r4,  0x28(r1)
        lwz     r5,  0x2C(r1)
        lwz     r6,  0x30(r1)
        lwz     r7,  0x34(r1)
        lwz     r8,  0x38(r1)
        lwz     r9,  0x3C(r1)
        lwz     r10, 0x40(r1)
        bctrl
        std     r3,  0x68(r1)
        lwz     r3,  0x24(r1)
        mr      r4, r1
        bl      FH2_LockDone
        ld      r3,  0x68(r1)
        lwz     r12, 0x4C(r1)
        mtlr    r12
        addi    r1, r1, 0xB0
        blr
    }
}

DWORD FH2_LockEnter(DWORD cs, DWORD caller, DWORD sp)
{
    if (g_lkActive)
    {
        DWORD h = (sp >> 4) & (FH2_LK_SLOTS - 1);
        int k;
        for (k = 0; k < 8; ++k)
        {
            FH2_LK_SLOT* s = &g_lkSlot[(h + k) & (FH2_LK_SLOTS - 1)];
            if (s->sp == 0 && InterlockedCompareExchange(&s->sp, (LONG)sp, 0) == 0)
            {
                s->cs = cs; s->caller = caller; s->tid = GetCurrentThreadId();
                __sync();
                s->start = GetTickCount() | 1;
                break;
            }
        }
        if (k == 8) ++g_lkDropped;
        ++g_lkEnters;
    }
    return g_lkOrig;
}

VOID FH2_LockDone(DWORD cs, DWORD sp)
{
    DWORD h = (sp >> 4) & (FH2_LK_SLOTS - 1);
    for (int k = 0; k < 8; ++k)
    {
        FH2_LK_SLOT* s = &g_lkSlot[(h + k) & (FH2_LK_SLOTS - 1)];
        if ((DWORD)s->sp != sp) continue;
        s->start = 0;
        __sync();
        s->sp = 0;
        // The lock is ours now: its owner field is this thread's identity.  Remember it (once per thread) so a lock's owner can be
        // translated back to a thread id later.  Guarded read; if the layout is not what I think the value is just garbage in the log.
        DWORD tid = GetCurrentThreadId();
        FH2_LK_ID* e = &g_lkId[(tid >> 2) & 127];
        if (e->tid != tid && cs >= 0x10000 && !(cs & 3) && MmIsAddressValid((PVOID)(cs + 0x18)) && MmIsAddressValid((PVOID)(cs + 0x1B)))
        {
            DWORD id = *(volatile DWORD*)(cs + 0x18);
            if (id) { e->id = id; e->tid = tid; }
        }
        return;
    }
}

// up to four return addresses above the wrapper frame (same walk as FH2_WdWalk, all reads range- and MmIsAddressValid-checked)
static VOID FH2_WdWalk4(DWORD sp, DWORD* out)
{
    out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0;
    if (sp < 0x10000 || (sp & 7) || !MmIsAddressValid((PVOID)sp)) return;
    DWORD f = *(volatile DWORD*)sp;
    for (int i = 0; i < 4; ++i)
    {
        if (f <= sp || (f & 7) || (f - sp) > 0x20000) return;
        if (!MmIsAddressValid((PVOID)f)) return;
        DWORD p = *(volatile DWORD*)f;
        if (p <= f || (p & 7) || (p - f) > 0x20000) return;
        if (!MmIsAddressValid((PVOID)(p - 8))) return;
        out[i] = *(volatile DWORD*)(p - 8);
        sp = f; f = p;
    }
}

static DWORD FH2_WdAge(DWORD start);   // defined below

static VOID FH2_LkDescribeTid(DWORD tid, CHAR* out, int cap)
{
    for (int i = 0; i < FH2_WD_SLOTS; ++i)
    {
        FH2_WD_SLOT* s = &g_wdSlot[i];
        if (s->state == 2 && s->tid == tid)
        {
            sprintf_s(out, cap, "owner is in a %c-wait caller=%08X ret1=%08X age=%ums", "SMND"[s->kind & 3], s->caller, s->ret1, (unsigned)FH2_WdAge(s->start));
            return;
        }
    }
    for (int j = 0; j < FH2_LK_SLOTS; ++j)
    {
        FH2_LK_SLOT* s = &g_lkSlot[j];
        if (s->sp != 0 && s->start != 0 && s->tid == tid)
        {
            sprintf_s(out, cap, "owner is waiting for lock cs=%08X caller=%08X age=%ums", s->cs, s->caller, (unsigned)FH2_WdAge(s->start));
            return;
        }
    }
    sprintf_s(out, cap, "owner is in no tracked wait or lock");
}

static VOID FH2_LockPoll(DWORD now)
{
    if (!g_lkActive) return;
    LONG stuck = 0;
    DWORD maxAge = 0;
    for (int i = 0; i < FH2_LK_SLOTS; ++i)
    {
        FH2_LK_SLOT* s = &g_lkSlot[i];
        DWORD sp = (DWORD)s->sp, st = s->start;
        if (!sp || !st) continue;
        DWORD el = FH2_WdAge(st);
        if (st != s->seenStart) { s->seenStart = st; s->nextLog = 2000; }
        if (el < 500) continue;
        ++stuck;
        if (el > maxAge) maxAge = el;
        if (el < s->nextLog) continue;
        s->nextLog = (el < 2000) ? 4000 : el * 2;
        if (g_lkLines >= 120) continue;
        DWORD cs = s->cs, caller = s->caller, tid = s->tid;
        DWORD rets[4];
        FH2_WdWalk4(sp, rets);
        DWORD w0 = 0xFFFFFFFF, w10 = 0xFFFFFFFF, w14 = 0xFFFFFFFF, w18 = 0xFFFFFFFF;
        if (cs >= 0x10000 && !(cs & 3) && MmIsAddressValid((PVOID)cs) && MmIsAddressValid((PVOID)(cs + 0x1B)))
        {
            w0 = *(volatile DWORD*)cs; w10 = *(volatile DWORD*)(cs + 0x10); w14 = *(volatile DWORD*)(cs + 0x14); w18 = *(volatile DWORD*)(cs + 0x18);
        }
        DWORD ownTid = 0;
        if (w18 != 0 && w18 != 0xFFFFFFFF)
            for (int j = 0; j < 128; ++j)
                if (g_lkId[j].id == w18 && g_lkId[j].tid != 0) { ownTid = g_lkId[j].tid; break; }
        CHAR own[140];
        if (ownTid) FH2_LkDescribeTid(ownTid, own, sizeof(own));
        else sprintf_s(own, sizeof(own), "owner thread unknown");
        FH2_Log("v1.0.43 LOCK WAIT tid=%08X waited=%ums cs=%08X hdr=%08X count=%08X rec=%08X owner=%08X ownerTid=%08X caller=%08X ret=%08X/%08X/%08X/%08X | %s",
            tid, (unsigned)el, cs, w0, w10, w14, w18, ownTid, caller, rets[0], rets[1], rets[2], rets[3], own);
        ++g_lkLines;
    }
    if ((now - g_lkLastStat) >= 30000)
    {
        g_lkLastStat = now;
        LONG e = InterlockedExchange(&g_lkEnters, 0);
        if (g_lkLinesStat < 400)
        {
            FH2_Log("v1.0.43 LOCK STAT 30s: enters=%d | blocked>0.5s now=%d maxAge=%ums dropped=%d", (int)e, (int)stuck, (unsigned)maxAge, (int)g_lkDropped);
            ++g_lkLinesStat;
        }
    }
}

// two back-to-back word stores (the last two words of the thunk are identical before and after), instruction cache flushed by the caller
static VOID FH2_WdPatchFast(DWORD* t, const DWORD* w)
{
    volatile DWORD* v = (volatile DWORD*)t;
    v[0] = w[0];
    v[1] = w[1];
    v[2] = w[2];
    v[3] = w[3];
}


// Returns TRUE when the attempt is finished (installed, or given up for good), FALSE to retry later.
static BOOL FH2_WdTryInstall(BOOL lastTry)
{
    PLDR_DATA_TABLE_ENTRY mod = (PLDR_DATA_TABLE_ENTRY)*XexExecutableModuleHandle;
    if (!mod || mod->TimeDateStamp != 0x542E797E)
    {
        FH2_Log("v1.0.43 WAITDIAG: game build is 0x%08X (expected 0x542E797E); not installing", mod ? (unsigned)mod->TimeDateStamp : 0u);
        return TRUE;
    }

    FH2_WD_SITE sites[5] =
    {
        { 0x832F2204, 0x80073120, (DWORD)&FH2_WaitWrap0, g_wdKindName[0] },
        { 0x832F2124, 0x80072D48, (DWORD)&FH2_WaitWrap1, g_wdKindName[1] },
        { 0x832F20C4, 0x8008B188, (DWORD)&FH2_WaitWrap2, g_wdKindName[2] },
        { 0x832F2E94, 0x80072B58, (DWORD)&FH2_WaitWrap3, g_wdKindName[3] },
        { 0x832F2034, 0x80088FA0, (DWORD)&FH2_LockWrap,  "RtlEnterCriticalSection" },
    };

    DWORD ok = 0, bad = 0, already = 0;
    for (int i = 0; i < 5; ++i)
    {
        if (i < 4 ? !g_FH2WaitDiag : !g_FH2LockDiag) continue;
        DWORD* t = (DWORD*)sites[i].thunk;
        if (!MmIsAddressValid(t) || !MmIsAddressValid(t + 3))
        {
            if (lastTry) FH2_Log("v1.0.43 WAITDIAG: %s thunk 0x%08X not readable", sites[i].name, sites[i].thunk);
            ++bad;
            continue;
        }
        DWORD expect[4], mine[4];
        PatchInJump(expect, sites[i].target, FALSE);
        PatchInJump(mine, sites[i].wrapper, FALSE);
        DWORD w0 = t[0], w1 = t[1], w2 = t[2], w3 = t[3];
        if (w0 == mine[0] && w1 == mine[1] && w2 == mine[2] && w3 == mine[3])
        {
            if (i < 4) { g_wdOrig[i] = sites[i].target; g_wdActive = 1; } else { g_lkOrig = sites[i].target; g_lkActive = 1; }
            ++already;
            continue;
        }
        if (w0 != expect[0] || w1 != expect[1] || w2 != expect[2] || w3 != expect[3])
        {
            if (lastTry) FH2_Log("v1.0.43 WAITDIAG: %s thunk 0x%08X has %08X %08X %08X %08X (expected jump to 0x%08X); NOT patched",
                sites[i].name, sites[i].thunk, w0, w1, w2, w3, sites[i].target);
            ++bad;
            continue;
        }
        if (i < 4) { g_wdOrig[i] = sites[i].target; g_wdActive = 1; } else { g_lkOrig = sites[i].target; g_lkActive = 1; }
        __sync();
        FH2_WdPatchFast(t, mine);
        FH2_WdFlushCode(t, 16);
        if (t[0] == mine[0] && t[1] == mine[1] && t[2] == mine[2] && t[3] == mine[3])
        {
            ++ok;
            FH2_Log("v1.0.43 WAITDIAG: %s thunk 0x%08X -> wrapper 0x%08X (kernel 0x%08X); readback ok", sites[i].name, sites[i].thunk, sites[i].wrapper, sites[i].target);
        }
        else
        {
            ++bad;
            FH2_Log("v1.0.43 WAITDIAG: %s thunk 0x%08X readback %08X %08X %08X %08X differs from the jump written", sites[i].name, sites[i].thunk, t[0], t[1], t[2], t[3]);
        }
    }

    if (ok + already > 0)
    {
        FH2_Log("v1.0.43 WAITDIAG: installed=%u already=%u skipped=%u tick=%u (waits >%u ms are logged by the poll thread)", ok, already, bad, GetTickCount(), FH2_WD_LONG_MS);
        return TRUE;
    }
    if (lastTry)
    {
        FH2_Log("v1.0.43 WAITDIAG: no thunk matched; nothing installed");
        return TRUE;
    }
    return FALSE;
}

static DWORD g_wdLastSnapLog = 0;
static DWORD g_wdSigN = 0, g_wdLastSnap = 0, g_wdLastSnapSum = 0, g_wdLinesEv = 0, g_wdLinesSnap = 0;   // see the v1.0.43 block below
VOID FH2_WaitDiagReset()
{
    if (!g_FH2WaitDiag && !g_FH2LockDiag) return;
    // a new title start: the game image is fresh, so the thunks are unpatched again
    g_wdActive = 0;
    g_lkActive = 0;
    for (int q = 0; q < FH2_LK_SLOTS; ++q) { g_lkSlot[q].start = 0; g_lkSlot[q].sp = 0; g_lkSlot[q].seenStart = 0; }
    g_lkLines = 0; g_lkLinesStat = 0; g_lkLastStat = 0; g_lkEnters = 0; g_lkDropped = 0;
    g_wdInstalled = FALSE;
    g_wdGaveUp = FALSE;
    g_wdTries = 0;
    g_wdLastTry = 0;
    g_wdLastStat = 0;
    for (int i = 0; i < FH2_WD_SLOTS; ++i) g_wdSlot[i].state = 0;
    g_wdDoneTail = g_wdDoneHead;
    for (int b = 0; b < FH2_WD_BUCKETS; ++b) { g_wdBucket[b].count = 0; g_wdBucket[b].key = 0; }
    for (int k = 0; k < 4; ++k) g_wdEnters[k] = 0;
    g_wdDropped = 0;
    g_wdSigN = 0; g_wdLastSnap = 0; g_wdLastSnapSum = 0; g_wdLinesEv = 0; g_wdLinesSnap = 0; g_wdLastSnapLog = 0;
}

static VOID FH2_WdTimeoutText(const FH2_WD_SLOT* s, CHAR* out, DWORD cap)
{
    if (!s->haveTmo) { sprintf_s(out, cap, "INF"); return; }
    __int64 v = ((__int64)(LONG)s->tmoHi << 32) | (unsigned __int64)s->tmoLo;
    if (v < 0) sprintf_s(out, cap, "%ums", (unsigned)((-v) / 10000));
    else if (v == 0) sprintf_s(out, cap, "poll");
    else sprintf_s(out, cap, "abs");
}

static VOID FH2_WdObjInfo(DWORD kind, DWORD a0, DWORD* hdr, DWORD* sig)
{
    *hdr = 0xFFFFFFFF; *sig = 0xFFFFFFFF;
    DWORD obj = 0;
    if (kind == 0) obj = a0;
    else if (kind == 1 && a0 >= 0x10000 && !(a0 & 3) && MmIsAddressValid((PVOID)a0)) obj = *(volatile DWORD*)a0;   // first object of the array
    else return;
    if (obj >= 0x10000 && !(obj & 3) && MmIsAddressValid((PVOID)obj) && MmIsAddressValid((PVOID)(obj + 7)))
    {
        *hdr = *(volatile DWORD*)obj;          // dispatcher header: type / flags / size
        *sig = *(volatile DWORD*)(obj + 4);    // signal state (0 = not signalled)
    }
}

// v1.0.42: waits are grouped by signature (function + call site + the two return addresses above it).  Idle worker threads all share a few
// signatures, so each signature is described in full once; what matters on a stuck console is a NEW signature, or one whose threads change.
struct FH2_WD_SIG
{
    DWORD kind, caller, ret1, ret2;
    DWORD nLong, nEnd;      // how many WAIT LONG / WAIT END lines were written for this signature
};
#define FH2_WD_SIGS 96
static FH2_WD_SIG g_wdSig[FH2_WD_SIGS];

static FH2_WD_SIG* FH2_WdSigFind(DWORD kind, DWORD caller, DWORD r1, DWORD r2)
{
    for (DWORD i = 0; i < g_wdSigN; ++i)
    {
        FH2_WD_SIG* g = &g_wdSig[i];
        if (g->kind == kind && g->caller == caller && g->ret1 == r1 && g->ret2 == r2) return g;
    }
    if (g_wdSigN >= FH2_WD_SIGS) return NULL;
    FH2_WD_SIG* g = &g_wdSig[g_wdSigN++];
    g->kind = kind; g->caller = caller; g->ret1 = r1; g->ret2 = r2; g->nLong = 0; g->nEnd = 0;
    return g;
}

// one wait's age, never negative (the slot can be filled by another thread after the caller read its clock)
static DWORD FH2_WdAge(DWORD start)
{
    DWORD t = GetTickCount();
    DWORD d = t - start;
    return (d > 0x80000000) ? 0 : d;
}

// Called from FH2_V105_StateSample (the 20 ms poll thread) when g_FH2WaitDiag is set.  The only place that writes log lines.
VOID FH2_WaitDiagPoll(DWORD now)
{
    if ((!g_FH2WaitDiag && !g_FH2LockDiag) || g_wdGaveUp) return;

    if (!g_wdInstalled)
    {
        if (g_wdLastTry != 0 && (now - g_wdLastTry) < 1000) return;
        g_wdLastTry = now;
        if (g_wdLastTry == 0) g_wdLastTry = 1;
        ++g_wdTries;
        BOOL last = (g_wdTries >= 20);
        if (FH2_WdTryInstall(last)) { g_wdInstalled = TRUE; g_wdLastStat = now; g_wdLastSnap = now; g_wdLastSnapLog = now; g_lkLastStat = now; if (!g_wdActive && !g_lkActive) g_wdGaveUp = TRUE; }
        else if (last) g_wdGaveUp = TRUE;
        return;
    }

    FH2_LockPoll(now);
    if (!g_wdActive) return;

    // waits still in progress: a signature is described in full the first 2 times one of its waits passes 5 s
    LONG active = 0, longNow = 0;
    for (int i = 0; i < FH2_WD_SLOTS; ++i)
    {
        FH2_WD_SLOT* s = &g_wdSlot[i];
        if (s->state != 2) continue;
        ++active;
        DWORD el = FH2_WdAge(s->start);
        if (el >= FH2_WD_LONG_MS) ++longNow;
        if (el < s->nextLog) continue;
        s->nextLog = (el < 5000) ? 10000 : el * 2;
        DWORD kind = s->kind & 3, tid = s->tid, a0 = s->a0, a1 = s->a1, caller = s->caller, r1 = s->ret1, r2 = s->ret2;
        FH2_WD_SIG* g = FH2_WdSigFind(kind, caller, r1, r2);
        if (g) { if (g->nLong >= 2) continue; ++g->nLong; }
        if (g_wdLinesEv >= 160) continue;
        CHAR tmo[24];
        FH2_WdTimeoutText(s, tmo, sizeof(tmo));
        DWORD hdr, sig;
        FH2_WdObjInfo(kind, a0, &hdr, &sig);
        FH2_Log("v1.0.43 WAIT LONG %s tid=%08X waited=%ums timeout=%s obj=%08X n=%u hdr=%08X sig=%08X caller=%08X ret1=%08X ret2=%08X",
            g_wdKindName[kind], tid, el, tmo, a0, a1, hdr, sig, caller, r1, r2);
        ++g_wdLinesEv;
    }

    // long waits that ended (first 2 per signature)
    while (g_wdDoneTail < g_wdDoneHead)
    {
        FH2_WD_DONE_ENT* d = &g_wdDone[g_wdDoneTail & (FH2_WD_DONE - 1)];
        if (d->seq != g_wdDoneTail + 1)
        {
            if (g_wdDoneHead - g_wdDoneTail > FH2_WD_DONE) { ++g_wdDoneTail; continue; }
            break;
        }
        FH2_WD_SIG* g = FH2_WdSigFind(d->kind & 3, d->caller, d->ret1, d->ret2);
        if ((!g || g->nEnd < 2) && g_wdLinesEv < 160)
        {
            if (g) ++g->nEnd;
            FH2_Log("v1.0.43 WAIT END %s tid=%08X waited=%ums result=%08X obj=%08X caller=%08X ret1=%08X ret2=%08X",
                g_wdKindName[d->kind & 3], d->tid, d->dur, d->result, d->a0, d->caller, d->ret1, d->ret2);
            ++g_wdLinesEv;
        }
        ++g_wdDoneTail;
    }

    // snapshot: every 15 s (only when it changed, or at least once a minute) the groups of threads sitting in a wait of 5 s or more,
    // youngest first, so a wait that is NEW since the load started is at the front.
    if ((now - g_wdLastSnap) >= 15000)
    {
        struct GRP { DWORD kind, caller, ret1, cnt, minAge, maxAge; } grp[40];
        DWORD gn = 0, sum = 0;
        for (int i = 0; i < FH2_WD_SLOTS; ++i)
        {
            FH2_WD_SLOT* s = &g_wdSlot[i];
            if (s->state != 2) continue;
            DWORD el = FH2_WdAge(s->start);
            if (el < FH2_WD_LONG_MS) continue;
            DWORD kind = s->kind & 3, caller = s->caller, r1 = s->ret1;
            DWORD j;
            for (j = 0; j < gn; ++j) if (grp[j].kind == kind && grp[j].caller == caller && grp[j].ret1 == r1) break;
            if (j == gn)
            {
                if (gn >= 40) continue;
                grp[gn].kind = kind; grp[gn].caller = caller; grp[gn].ret1 = r1; grp[gn].cnt = 0; grp[gn].minAge = el; grp[gn].maxAge = el; ++gn;
            }
            ++grp[j].cnt;
            if (el < grp[j].minAge) grp[j].minAge = el;
            if (el > grp[j].maxAge) grp[j].maxAge = el;
            sum += (kind + 1) * 0x9E3779B1u + caller + r1 * 3 + grp[j].cnt;
        }
        g_wdLastSnap = now;   // next look in 15 s
        BOOL changed = (sum != g_wdLastSnapSum);
        if ((changed || (now - g_wdLastSnapLog) >= 60000) && g_wdLinesSnap < 400)
        {
            g_wdLastSnapSum = sum;
            g_wdLastSnapLog = now;
            // order: youngest group first
            for (DWORD a = 0; a + 1 < gn; ++a)
                for (DWORD b = a + 1; b < gn; ++b)
                    if (grp[b].minAge < grp[a].minAge) { GRP t = grp[a]; grp[a] = grp[b]; grp[b] = t; }
            CHAR line[440]; int p = 0;
            p += sprintf_s(line + p, sizeof(line) - p, "v1.0.43 WAIT SNAP groups=%u threads>5s=%d active=%d | ", (unsigned)gn, (int)longNow, (int)active);
            for (DWORD j = 0; j < gn && j < 10 && p < (int)sizeof(line) - 60; ++j)
                p += sprintf_s(line + p, sizeof(line) - p, "%c:%08X/%08X x%u age%u-%us; ", "SMND"[grp[j].kind & 3], grp[j].caller, grp[j].ret1,
                    (unsigned)grp[j].cnt, (unsigned)(grp[j].minAge / 1000), (unsigned)(grp[j].maxAge / 1000));
            FH2_Log("%s", line);
            ++g_wdLinesSnap;
        }
    }

    // every 30 s: totals and call sites that wait/sleep more than 1000 times per 30 s (a polling loop)
    if ((now - g_wdLastStat) >= 30000)
    {
        g_wdLastStat = now;
        LONG e0 = InterlockedExchange(&g_wdEnters[0], 0), e1 = InterlockedExchange(&g_wdEnters[1], 0);
        LONG e2 = InterlockedExchange(&g_wdEnters[2], 0), e3 = InterlockedExchange(&g_wdEnters[3], 0);
        if (g_wdLinesSnap < 400)
        {
            FH2_Log("v1.0.43 WAIT STAT 30s: single=%d multi=%d nt=%d delay=%d | in a tracked wait now=%d (of those >5s=%d) dropped=%d",
                (int)e0, (int)e1, (int)e2, (int)e3, (int)active, (int)longNow, (int)g_wdDropped);
            ++g_wdLinesSnap;
            for (int n = 0; n < 3 && g_wdLinesSnap < 400; ++n)
            {
                int best = -1; LONG bc = 999;
                for (int b = 0; b < FH2_WD_BUCKETS; ++b)
                    if (g_wdBucket[b].count > bc) { bc = g_wdBucket[b].count; best = b; }
                if (best < 0) break;
                FH2_Log("v1.0.43 WAIT BUSY site=%08X %s calls=%d in 30s", g_wdBucket[best].key, g_wdKindName[g_wdBucket[best].kind & 3], (int)bc);
                ++g_wdLinesSnap;
                InterlockedExchange(&g_wdBucket[best].count, 0);
            }
        }
        for (int b = 0; b < FH2_WD_BUCKETS; ++b) InterlockedExchange(&g_wdBucket[b].count, 0);
    }
}
