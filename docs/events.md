# qproto on the Authum event bus

qproto answers one question: **how did this client get in?** (Steam, RevEmu,
SC2009, sXe, Vellum, no-Steam 47/48, …). It lets clients in or refuses them
according to `qproto.cfg`. That is all.

It does **not** keep bans, connection history, name history or statistics.
Those are separate modules on the same bus — each module solves one problem:

| Need | Who | How |
|------|-----|-----|
| How a client authenticated | qproto | `qproto.client.authorized`, `qproto.client.query` |
| Refuse a connection (ban) | a ban module | `authum.client.connect` → `allow = false`, or `authum_host_kick` after `qproto.client.authorized` |
| Who entered / left when, renames | a logger / MySQL module | `authum.client.connect` / `info_changed` / `disconnect` (+ qproto's info) |

Why no bans in qproto: a ban decision is policy (what storage, what duration,
admin tools, appeals) and has nothing to do with decoding auth tickets. Mixing
them tied a protocol backend to one particular ban storage (`qproto_bans.cfg`).
Now a ban module can key on `long_authid` and use whatever backend it likes.

General bus docs: [`lib/authum/docs/events.md`](../lib/authum/docs/events.md).

---

## Public contract

Header: `<qproto/event.h>` (types only — include it, never link qproto).

### `qproto.client.authorized` (forward)

Published once per connect, right after Authum's `authum.client.connect`,
when qproto has bound the auth result to the slot. Payload:
`qproto_client_info_t` (`<qproto/client/info.h>`):

| Field | Meaning |
|-------|---------|
| `index`, `userid` | Entity index (1…maxClients) and engine userid |
| `auth_kind` | Protocol / emulator the client used (`qproto_client_auth_kind_*`, frozen values) |
| `protocol` | Net protocol 47 / 48 |
| `id_kind`, `steam_id` | What qproto told the engine (cid_* outcome) |
| `auth_key_kind`, `auth_key[_len]` | Raw hardware key (0 length for native Steam) |
| `long_authid` | 16 bytes of SHA-256(key) — stable id for ban / stats modules |
| `auth_id` | Engine auth id string at connect |
| `name` | Name at connect (renames: `authum.client.info_changed`) |
| `connected_at` | Unix time of the connect |

### `qproto.client.query` (query)

```c
#include <qproto/event.h>

qproto_client_query_t q = { .size = sizeof q, .index = id };  /* or .userid, or .name */
if (authum_host_publish(host, QPROTO_EVENT_CLIENT_QUERY, &q) != authum_event_result_continue
    && q.found) {
    /* q.info.auth_kind, q.info.long_authid, … */
}
```

Lookup order: `index` (> 0), else `userid` (> 0), else `name` (connect name,
case-insensitive). Result `continue` → qproto not loaded or no such client.

---

## Console / RCON

Through Authum's one engine command (qproto registers nothing in the engine,
so it cannot clash with AMX Mod X or others —
[`lib/authum/docs/commands.md`](../lib/authum/docs/commands.md)):

```
authum qproto info                     every client: slot, userid, protocol, net protocol, auth id, name
authum qproto info #12                 by userid
authum qproto info 3                   by slot
authum qproto info "Some Player"       by connect name (case-insensitive)
```

The single-client form adds key kind / length, `long_authid`, IP, and connect
time (UTC). The raw key is never printed.

---

## Inside qproto

| File | Role |
|------|------|
| `src/qproto/hook.c` | Engine hook on `Steam_NotifyClientConnect`; stages a pending record |
| `src/qproto/events.c` | Binds it on `authum.client.connect`, clears on `disconnect`, answers queries, publishes `authorized` |
| `src/qproto/client/state.c` | Client table (allocated in qproto's Authum sandbox — nothing to free on stop) |
| `src/qproto/client/long_authid.c` | `long_authid` via Authum crypto |
| `src/qproto/client/auth/kind.c` | Protocol display names |
| `src/qproto/command.c` | `authum qproto info` |

Tests: `tests/client.c` (registry binding / lookup, long authid, `info`
command output) — `ctest` in the build directory.
