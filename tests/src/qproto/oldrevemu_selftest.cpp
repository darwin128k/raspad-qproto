#include "qproto/precompiled.h"
#include "qproto/qproto_authorizers.h"
#include <cstdio>
#include <cstring>
#include <cstdint>

#pragma pack(push, 1)
struct OldRevTicket_t { uint32_t Header; uint32_t SteamIdEnc; uint16_t Reserved; };
#pragma pack(pop)

int main() {
    int failures = 0;
    uint32_t wantId = 424242;

    OldRevTicket_t t = {};
    t.Header = 0xFFFF;
    t.SteamIdEnc = (wantId ^ 0xC9710266) << 1;
    t.Reserved = 0;

    printf("sizeof(OldRevTicket_t) = %zu (expect 10)\n", sizeof(t));

    authdata_t authdata = {};
    authdata.authTicket = (const uint8_t*)&t;
    authdata.ticketLen = sizeof(t);

    client_auth_kind kind = OldRevEmuAuthorize(&authdata);
    bool ok = kind == CA_OLD_REVEMU && authdata.steamId == wantId;
    printf("[%s] OldRevEmuAuthorize kind=%d steamId=%u (want %u)\n", ok?"OK":"FAIL", (int)kind, authdata.steamId, wantId);
    failures += !ok;

    unsigned char junk[10] = {1,2,3,4,5,6,7,8,9,10};
    authdata_t garbage = {};
    garbage.authTicket = junk;
    garbage.ticketLen = sizeof(junk);
    bool rejectOk = OldRevEmuAuthorize(&garbage) == CA_UNKNOWN;
    printf("[%s] garbage rejected\n", rejectOk?"OK":"FAIL");
    failures += !rejectOk;

    printf(failures==0 ? "ALL TESTS PASSED\n" : "%d FAILED\n", failures);
    return failures;
}
