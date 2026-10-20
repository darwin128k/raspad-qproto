# qproto configuration

Runtime settings live on `g_qproto_config` (`include/qproto/config.h`).
Defaults are set by static initialization in `src/qproto/config.c`. On module
start, `qproto_config_load()` overlays `qproto.cfg` from the module directory
using Authum’s flat cfg API.

Authum docs for the general mechanism: [`lib/authum/docs/cfg.md`](../lib/authum/docs/cfg.md)
(or the same file upstream in [raspad-authum](https://github.com/darwin128k/raspad-authum)).

---

## File location

```
cstrike/addons/authum/modules/qproto/
  qproto.so
  qproto.cfg          ← loaded here
  qproto.log          ← when LoggingMode has the file bit
```

There is no bans file: bans are not qproto's job (see [events.md](events.md)).

If `qproto.cfg` is missing, defaults stay as compiled; a log line notes that.
Build ships a sample `qproto.cfg` at the repo root — copy it next to the `.so`.

---

## How load works

1. Open `qproto.cfg` under the module env path (`authum_host_env_module` + join).
2. `authum_cfg_apply_items` with `qproto_config_items[]` — bools, cids, sink
   flags, reject messages.
3. **Custom keys** that are not plain table fields:
   - `EngineLayout` — string → `qproto_engine_layout_t` (`auto` / `classic` /
     `8684` / `2018` / `10211` / …)
   - `cid_Steam` — integer, accepted only for a small allow-list; garbage keeps
     the default
4. `authum_cfg_close`.

That split is intentional: the table covers everything that maps 1:1 to a
scalar/cstr field; layout parsing and cid validation stay in `qproto_config_load`
so they remain easy to step through in a debugger.

---

## Keys (summary)

See comments / examples in `qproto.cfg`. Groups:

| Group | Examples | Kind |
|-------|----------|------|
| Emulator toggles | `EnableRevEmu`, `EnableVellum`, … | bool |
| Client-id policy | `cid_RevEmu`, `cid_NoSteam47`, … | i32 (enum values) |
| Logging | `LoggingMode` | u32 bit mask → `authum_logger_sink_t` |
| Reject messages | `RejMsgRevEmu`, … | cstr (fixed buffers) |
| Engine | `EngineLayout` | custom string parse |
| Steam cid | `cid_Steam` | custom validated i32 |

`LoggingMode`: `2` = file only, `4` = authum.log (host) only, `6` = both
(default in code is file-only).

---

## Extending qproto’s own config

**Plain new setting** (bool / i32 / u32 / string buffer):

1. Add a field on `qproto_config_t` with a default in `g_qproto_config = { … }`.
2. Add one row to `qproto_config_items[]`.
3. Document the key in `qproto.cfg`.

**Setting that needs parse or validation** (enum-from-string, allow-list, …):

1. Still default the field on `g_qproto_config`.
2. Do **not** force it into the items table.
3. After `authum_cfg_apply_items`, call `authum_cfg_apply_cstr` /
   `authum_cfg_apply_i32` (or `get_*`) and map/validate in
   `qproto_config_load` (same pattern as `EngineLayout` / `cid_Steam`).

---

## Building against Authum

Authum is the `lib/authum` submodule. CMake:

```cmake
add_subdirectory(lib/authum/client)
target_link_libraries(qproto PRIVATE authum_client …)
```

```bash
git submodule update --init --recursive
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --target qproto
```

Do not pass `AUTHUM_SRC_DIR` or compile `cfg.c` into qproto.
