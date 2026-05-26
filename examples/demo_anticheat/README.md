# demo_anticheat

Reference heartbeat producer for the LOTA end-to-end demo. 

The process opens an `lota_ac_session` in direct mode against the local LOTA agent, mints LACH heartbeats via `lota_ac_heartbeat()`, and POSTs them to the demo server with `libcurl`. It is the smallest possible C reference for an EAC- or BattlEye-style integrator: every production-relevant decision (provider id, game id, socket path, heartbeat interval) is a flag.

Build with `make examples` from the repository root. 
The binary lands at `build/examples/demo_anticheat` and links against the gaming + anticheat + server SDKs that `make all` already produces under `build/`.

## Flags

| Flag             | Default                            | Meaning                                                       |
| ---------------- | ---------------------------------- | ------------------------------------------------------------- |
| `--server URL`   | `http://127.0.0.1:7443/heartbeat`  | demo server `/heartbeat` endpoint                             |
| `--game-id ID`   | `trust-pong`                       | game id stamped into the LACH header                          |
| `--socket PATH`  | (default agent socket)             | override the agent UNIX socket path                           |
| `--provider eac|battleye` | `eac`                     | anti-cheat provider id stamped into the LACH header           |
| `--interval SEC` | `5`                                | seconds between heartbeats; also `$LOTA_DEMO_INTERVAL_SEC`    |
| `--once`         | off                                | fire a single heartbeat, exit with the server-reported state  |
| `--tamper-marker PATH` | (none)                       | flip a token byte when PATH exists; also `$LOTA_DEMO_TAMPER_MARKER` |
| `--help`         | n/a                                | print usage and exit                                          |

## Exit codes

In `--once` mode the process return code mirrors the server verdict so `setup.sh` can use the call as a liveness check without parsing stderr:

| Code | Meaning                                    |
| ---- | ------------------------------------------ |
| 0    | `TRUSTED`                                  |
| 1    | `UNTRUSTED`                                |
| 2    | `REJECT`                                   |
| 3    | transport-level failure (no agent, no server, libcurl error) |
| 64   | usage / CLI error                          |

In continuous mode the process loops forever and exits cleanly on SIGINT or SIGTERM, propagating the last verdict as the exit code.

## Logging

Each tick writes one line to stderr:

```
demo_anticheat: seq=<n> state=<verdict> latency=<ms> http=<status> [reason="..."]
```

The format is intentionally pipe-friendly so the operator can `| awk` it during the live demo without an extra parser.

## Integration notes vs EAC / BattlEye

- **Process model.** Real anti-cheat clients ship a long-lived helper next to the game.
  `demo_anticheat` reproduces that model: the process is independent of the SDL2 client, and the two communicate only through the demo server's verdict state.
- **Provider id.** EAC and BattlEye allocate different provider identifiers (`1` and `2` here). 
  The LACH wire stamps the value into byte 5 of the header so a verifier that bridges both vendors can route per-provider without re-deriving from the socket path.
- **Session id.** The `lota_ac_session` mints its own 16-byte session id at init time. 
  That id is independent from the game-server session id served by `POST /nonce` -- the two are bridged on the server side through `game_id_hash`, which lets multiple producers per game converge on the same verdict without sharing state.
- **Replay defence.** The producer's monotonic sequence is the primary replay defence on the wire. The demo server keeps a per-session high-water mark and rejects any heartbeat at or below it.

## Tamper hook

`--tamper-marker PATH` (or `LOTA_DEMO_TAMPER_MARKER=PATH`) arms a per-tick poll: when the file at `PATH` exists at heartbeat time, the producer XORs `0xFF` into the first byte of the signed token blob before POSTing.
The LACH header stays well-formed, so the server takes the verification branch rather than the wire-format reject branch and answers `UNTRUSTED` with the signature-verify error string surfaced from `sdk/server.VerifyToken`.
This is the integration point that `examples/demo/demo_tamper.sh` uses to flip the live demo's banner from green TRUSTED to red INTEGRITY LOSS without touching the agent process or the swtpm sandbox.
