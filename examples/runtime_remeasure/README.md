# Runtime re-measurement demo

`runtime_remeasure` is a TPM-free reference for the runtime measurement
that the LOTA anti-cheat heartbeat binds into every beat. The
session-start game-binding hash only pins the main executable **on disk**;
nothing in it reflects the code pages that are actually mapped and
running, and it says nothing about the shared libraries the process
loads. This closes that gap by re-measuring the live image - the main
executable plus every loaded shared object - and binding the digest into
the TPM-signed heartbeat nonce, so a verifier can tell when the running
code of any module no longer matches the registered binaries.

The canonical digest (see `include/lota_anticheat.h`) measures every
file-backed object, excluding the kernel vDSO. Each object yields a
content-only digest over its executable segments:

```
object_digest =
  SHA-256("lota-ac-runtime-object:v1\0" || seg_count_LE32 ||
          for each executable (PF_X) PT_LOAD segment, ascending p_vaddr:
              p_vaddr_LE64 || p_offset_LE64 || p_filesz_LE64 ||
              segment_bytes)
```

and the combined image digest folds the objects, keyed by soname (file
basename) and sorted, so neither load order nor library search path
matters:

```
SHA-256("lota-ac-runtime-measure:v2\0" || object_count_LE32 ||
        for each object: soname_len_LE32 || soname_bytes || object_digest)
```

For position-independent x86-64 code with full RELRO the executable
segments carry no load-time relocations (the GOT/PLT data, not code, is
what the loader mutates), so each live object mapping is byte-identical to
its on-disk segment content. This demo needs no agent, no verifier and no
TPM, so it runs unmodified inside a plain VM.

## Build

```sh
make BUILD_DIR=/var/tmp/lota-build all
make BUILD_DIR=/var/tmp/lota-build examples
```

The binary lands at `/var/tmp/lota-build/examples/runtime_remeasure`.

## Modes

| Invocation                          | What it shows                                                       |
|-------------------------------------|--------------------------------------------------------------------|
| `runtime_remeasure`                 | the live mapped image (all loaded objects) equals the set measure of its on-disk files |
| `runtime_remeasure --list-objects`  | the trusted runtime manifest: one object path per line             |
| `runtime_remeasure --manifest FILE` | reproduce the set measure from a manifest and compare to the live image (verifier side) |
| `runtime_remeasure --patch-demo`    | a 1-byte code patch flips an object digest (the closed TOCTOU)     |
| `runtime_remeasure --watch SEC`     | repeated re-measurements of a steady process stay stable           |
| `runtime_remeasure --count N`       | number of `--watch` ticks (default 5)                              |
| `runtime_remeasure --exe PATH`      | ELF copied for `--patch-demo` (default `/proc/self/exe`)           |

The default and `--manifest` modes print the digests they computed and a
final `RESULT:` line, and exit non-zero on a mismatch (or on drift during
`--watch`), so they are safe to wire into a script.

A quick round-trip - capture the manifest, then verify against it:

```sh
runtime_remeasure --list-objects > manifest.txt
runtime_remeasure --manifest manifest.txt   # RESULT: MATCH
```

## Relationship to the heartbeat

`runtime_remeasure` (no flags) is the producer side of runtime re-measurement in
isolation: `lota_ac_compute_runtime_measure()` is exactly what
`lota_ac_heartbeat()` calls every beat. `--manifest` shows the verifier
side, `lota_ac_compute_expected_runtime_measure_set()`, which the demo
server runs over the trusted runtime manifest (captured with
`demo_anticheat --print-runtime-objects`) to obtain the value an honest
producer must report.
