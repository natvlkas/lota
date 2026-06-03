# Sealed keys - offline local attestation

Remote attestation proves a host's state to a verifier over the network.
**Sealing** is the local counterpart: the TPM releases a secret only when
the host booted into the expected state, with no verifier round-trip. It
is the building block for single-player / offline DRM and for hardening
key storage at rest.

A sealed blob is inert: it is useless on a different machine, and useless
on the same machine booted into a different (tampered) state. The TPM
enforces this - it is a local boundary, **not** a replacement for remote
attestation in competitive multiplayer, where the attacker owns the box
and can simply read the unsealed secret out of the running game.

## How it works

`lota-agent --seal` wraps a secret (≤ 128 bytes, read from stdin) as a
TPM keyed-hash object whose authorization policy is a PolicyPCR digest
over the selected PCRs. `lota-agent --unseal` recreates the same
deterministic storage primary, loads the object, and unseals it over a
salted, response-encrypted policy session. If the current PCRs differ
from the seal-time values, the policy no longer matches and the unseal
fails closed.

The default PCR set is the firmware/kernel boot PCRs 0–7 plus LOTA's
PCR14 boot-commitment, so a firmware, kernel, or agent change invalidates
the seal. Override it with `--seal-pcrs MASK`.

```sh
# Seal a per-title key to the current boot state (root; TPM-backed).
printf '%s' "$PER_TITLE_KEY" | sudo lota-agent --seal > title.sealed

# Later, in the same boot state, recover it:
sudo lota-agent --unseal < title.sealed
```

## Run the demo

`seal-demo.sh` runs the full round-trip and proves the fail-closed
property by sealing to a PCR it then extends. It needs a working TPM,
`tpm2-tools`, and root. Point `AGENT` at your built binary:

```sh
sudo AGENT=/var/tmp/lota-build/lota-agent examples/sealed-key/seal-demo.sh
```

Expected output ends with:

```
==> 2. Unseal it back (same boot state -> succeeds)
    RESULT: OK - recovered the key
==> 3. Bind to a single PCR, then change it -> unseal must fail
    RESULT: SEALED SHUT - unseal failed closed after the state changed
```

The script seals step 3 to PCR 16 (the resettable debug PCR) only so it
can move the state without a reboot; production seals to the default
0–7 + PCR14 set, where the equivalent "state change" is a firmware,
kernel, or agent update.

## Hardening the agent's AIK auth

The same primitive backs an opt-in at-rest hardening of the agent's own
AIK userAuth. Enabling `seal_aik_auth_strict` in `lota.conf` stores the
auth only sealed to the boot state, so a captured disk no longer yields
it even to an attacker holding the same TPM. See the "Sealed keys"
section of [`docs/PRODUCTION_BRINGUP.md`](../../docs/PRODUCTION_BRINGUP.md).
