# Scenario: BPF LSM blocks an unauthorised library load

This walk-through shows the LOTA agent's runtime enforcement layer
catching an unauthorised shared object before the kernel maps it
into a game process. The block happens at the
`security_mmap_file` LSM hook in
[`src/bpf/lota_lsm.bpf.c`](../../../src/bpf/lota_lsm.bpf.c) and is
emitted as a structured event on the agent's journal and the BPF
ring buffer; nothing inside Counter-Strike 2 has to opt in for the
check to fire.

Unlike the `agent-down.md` scenario this one needs the **full
agent**, not `--test-ipc`. `--test-ipc` is the IPC bridge for the
attestation token; the LSM gates run only when the agent loads its
BPF object and attaches the LSM programs at startup.

## Prerequisites

- Linux kernel with `CONFIG_BPF_LSM=y` and `bpf` listed in
  `/sys/kernel/security/lsm`. Fedora 44's default kernel meets
  this; verify with `cat /sys/kernel/security/lsm`.
- The agent is built with the BPF object available
  (`make all` produces `build/agent/lota_lsm.bpf.o` or
  `/usr/lib/lota/lota_lsm.bpf.o` after `sudo make install`).
- A throwaway "evil" shared object the operator deliberately
  builds outside the trust set. I've used a one-file no-op .so
  whose constructor only prints to stderr so the scenario does
  not actually load anything dangerous.

Build the dummy:

```sh
cat > /tmp/evil.c <<'EOF'
#include <stdio.h>
__attribute__((constructor)) static void evil_init(void)
{
    fprintf(stderr, "evil.so: loaded into pid %d\n", (int)getpid());
}
EOF
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c
```

## Walk-through

### Terminal 1: start the agent in enforce mode

```sh
sudo systemctl stop lota-agent.socket lota-agent.service
sudo env XDG_RUNTIME_DIR=/run/user/"$(id -u)" \
    /usr/bin/lota-agent --mode enforce --block-anon-exec
```

Watch the banner. A healthy startup announces both IPC listeners,
loads the BPF object, and attaches the LSM programs:

```
IPC listening on /run/lota/lota.sock
IPC extra listener on /run/user/1000/lota/lota.sock
BPF programs attached: 11
LSM mode: enforce
```

### Terminal 2: follow the kernel-side block events

```sh
sudo journalctl -fu lota-agent | grep -E "BLOCK|mmap|exec_mmap"
```

This stays quiet until something trips a policy gate.

### Terminal 3: try the unauthorised preload from a CS2 launch

Set CS2's Steam launch options to include the operator's evil
library next to the LOTA hook:

```
PRESSURE_VESSEL_FILESYSTEMS_RW=/run/user/1000/lota:/tmp \
LOTA_HOOK_SOCKET=/run/user/1000/lota/lota.sock \
LOTA_HOOK_LOG_LEVEL=info \
LD_PRELOAD=/tmp/evil.so \
lota-proton-hook %command%
```

The `:` separator in `PRESSURE_VESSEL_FILESYSTEMS_RW` requests
two bind-mounts: the LOTA socket directory and `/tmp` so the
evil library is reachable inside the container.

Launch CS2.

### What the operator observes

- `evil.so: loaded into pid <N>` does **not** appear in Steam's
  `console-linux.txt`. The kernel returned EPERM from
  `mmap(PROT_EXEC)` before the constructor ran.
- Terminal 2 shows a structured event:

   ```
   lota-agent: BLOCK exec_mmap pid=<cs2-pid> comm=cs2
       path=/tmp/evil.so reason=trust-set-miss
   ```

- `verify-attested.sh` in another terminal stays at `TRUSTED`:
  the LOTA hook itself is in the trust set, the agent stays up,
  attestation is unaffected.

### Reproducing the block without launching CS2

The same gate fires for any process under LOTA's enforcement set.
Reproduce out-of-game with a trivial wrapper that asks the dynamic
loader to preload the evil library:

```sh
LD_PRELOAD=/tmp/evil.so /usr/bin/cat /etc/os-release
```

`cat` exits with `error while loading shared libraries` plus an
EPERM trace in the journal. The kernel side of the policy did not
distinguish "CS2" from "cat"; both hit the same
`security_mmap_file` hook.

## What this proves

- The LSM hook is exercised end-to-end by a real PROT_EXEC mmap
  attempt rather than a synthetic unit test.
- The block is operator-visible in two independent places: the
  game's own stderr (the constructor never ran) and the agent
  journal (the BPF program emitted the structured event).
- The attestation surface (`lota-status` / `lota-token.bin`) is
  orthogonal to the runtime block. A game that crashed on the
  block would still have a valid attested status at the moment
  of the crash; an integrator can record both signals
  independently.

## Tear-down

```sh
rm /tmp/evil.so
# remove LD_PRELOAD=/tmp/evil.so from CS2 launch options
sudo systemctl start lota-agent.socket
```
