# Runtime re-measurement demo

`runtime_remeasure` is a TPM-free reference for the runtime measurement
that the LOTA anti-cheat heartbeat binds into every beat.
The session-start game-binding hash only pins the executable **on disk**;
nothing in it reflects the code pages that are actually mapped and
running. Runtime re-measure closes that gap by re-measuring the live executable
image and binding the digest into the TPM-signed heartbeat nonce, so a verifier
can tell when the running code no longer matches the registered binary.

The canonical digest (see `include/lota_anticheat.h`) is:

```
SHA-256("lota-ac-runtime-measure:v1\0" || seg_count_LE32 ||
        for each executable (PF_X) PT_LOAD segment, ascending p_vaddr:
            p_vaddr_LE64 || p_offset_LE64 || p_filesz_LE64 ||
            segment_bytes)
```

For position-independent x86-64 code the executable segments carry no
load-time relocations, so the live mapping is byte-identical to the
on-disk segment content. This demo needs no agent, no verifier and no
TPM, so it runs unmodified inside a plain VM.

## Build

```sh
make BUILD_DIR=/var/tmp/lota-build all
make BUILD_DIR=/var/tmp/lota-build examples
```

The binary lands at `/var/tmp/lota-build/examples/runtime_remeasure`.

## Modes

| Invocation                         | What it shows                                              |
|------------------------------------|-----------------------------------------------------------|
| `runtime_remeasure`                | live mapped image measures identically to its ELF file    |
| `runtime_remeasure --compare PATH` | whether another ELF measures the same as this image       |
| `runtime_remeasure --patch-demo`   | a 1-byte code patch flips the digest (the closed TOCTOU)  |
| `runtime_remeasure --watch SEC`    | repeated re-measurements of a steady process stay stable  |
| `runtime_remeasure --count N`      | number of `--watch` ticks (default 5)                     |
| `runtime_remeasure --exe PATH`     | ELF used for the file side (default `/proc/self/exe`)     |

Each mode prints the digests it computed and a final `RESULT:` line. The
process exits non-zero when the live image fails to match (mismatch,
undetected patch, or drift during `--watch`), so it is safe to wire into
a script.

## Relationship to the heartbeat

`runtime_remeasure` (no flags) is the producer side of runtime
re-measurement in isolation: `lota_ac_compute_runtime_measure()`
is exactly what `lota_ac_heartbeat()` calls every beat.

`--compare`/`--exe` show the verifier side,
`lota_ac_compute_expected_runtime_measure()`, which the demo server
runs over its `--anticheat-binary` to obtain the value an honest producer
must report.
