/* SPDX-License-Identifier: MIT */
/*
 * LOTA Anti-Cheat Compatibility Layer
 *
 * Adapter that emulates the session interface expected by anti-cheat
 * systems (EAC, BattlEye) for games that require one.
 *
 * Produces heartbeat packets that wrap LOTA attestation tokens with
 * per-session context. Game servers verify heartbeats using
 * lota_ac_verify_heartbeat(), which internally delegates to
 * lota_server_verify_token() for TPM signature validation.
 *
 * Two client modes:
 *   Direct - calls lota_gaming SDK over Unix socket (native games)
 *   File   - reads Wine hook status/token files (Wine/Proton games)
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_ANTICHEAT_H
#define LOTA_ANTICHEAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOTA_AC_MAGIC 0x4C414348 /* "LACH" little-endian */
#define LOTA_AC_VERSION 3
#define LOTA_AC_HEADER_SIZE 110
#define LOTA_AC_MAX_TOKEN 1608
#define LOTA_AC_MAX_HEARTBEAT (LOTA_AC_HEADER_SIZE + LOTA_AC_MAX_TOKEN)
#define LOTA_AC_MAX_GAME_ID 64
#define LOTA_AC_SESSION_ID_SIZE 16
#define LOTA_AC_GAME_HASH_SIZE 32
#define LOTA_AC_RUNTIME_MEASURE_SIZE 32

/*
 * Domain-version negotiation.
 *
 * Each value names a frozen pair of hash domain strings used to derive the
 * game-binding hash and the heartbeat nonce. Producer stamps the value into the
 * wire; verifier rejects anything outside its accepted set. New string variants
 * must allocate the next integer instead of silently replacing an existing one.
 *
 * V1: "lota-ac-game-binding:v2\\0" + "lota-ac-heartbeat:v1\\0"
 * V2: "lota-ac-game-binding:v2\\0" + "lota-ac-heartbeat:v2\\0"
 *
 */
#define LOTA_AC_DOMAIN_VERSION_V1 1u
#define LOTA_AC_DOMAIN_VERSION_V2 2u
#define LOTA_AC_DOMAIN_VERSION_CURRENT LOTA_AC_DOMAIN_VERSION_V2

/* default heartbeat interval in seconds */
#define LOTA_AC_DEFAULT_HEARTBEAT_SEC 30

/* heartbeat output filenames */
#define LOTA_AC_FILE_EAC "lota-ac-eac.bin"
#define LOTA_AC_FILE_BATTLEYE "lota-ac-battleye.bin"

enum lota_ac_provider {
	LOTA_AC_PROVIDER_EAC = 1,
	LOTA_AC_PROVIDER_BATTLEYE = 2,
};

enum lota_ac_state {
	LOTA_AC_STATE_IDLE = 0,	     /* not initialised */
	LOTA_AC_STATE_RUNNING = 1,   /* active, agent reachable */
	LOTA_AC_STATE_TRUSTED = 2,   /* attested: all required flags set */
	LOTA_AC_STATE_UNTRUSTED = 3, /* agent reachable but not attested */
	LOTA_AC_STATE_ERROR = 4,     /* cannot reach agent / internal fault */
};

/* error codes */
enum {
	LOTA_AC_ERR_OK = 0,
	LOTA_AC_ERR_INVALID_ARG = -1,
	LOTA_AC_ERR_MALFORMED = -2,
	LOTA_AC_ERR_VERSION = -3,
	LOTA_AC_ERR_SIG_FAIL = -4,
	LOTA_AC_ERR_NONCE_FAIL = -5,
	LOTA_AC_ERR_EXPIRED = -6,
	LOTA_AC_ERR_CRYPTO = -7,
};

struct lota_ac_config {
	enum lota_ac_provider provider;
	const char *game_id; /* NUL-terminated, max LOTA_AC_MAX_GAME_ID */
	uint32_t heartbeat_interval_sec; /* 0 -> default (30 s) */

	/*
	 * Required attestation flags. Heartbeat state is TRUSTED only if
	 * (lota_flags & required_flags) == required_flags.
	 * Use 0 to accept any non-zero flags.
	 */
	uint32_t required_flags;

	/*
	 * Client mode:
	 *   direct = 1 -> use lota_gaming SDK (native games)
	 *   direct = 0 -> read Wine hook files
	 */
	int direct;

	/*
	 * For file mode: directory containing lota-status and lota-token.bin.
	 * NULL -> auto-detect ($LOTA_HOOK_TOKEN_DIR / $XDG_RUNTIME_DIR/lota).
	 */
	const char *token_dir;

	/*
	 * For direct mode: custom socket path.
	 * NULL -> default (/run/lota/lota.sock).
	 */
	const char *socket_path;
};

/*
 * heartbeat wire format (little-endian, packed):
 *
 *   offset  size   field
 *   0       4      magic           0x4C414348
 *   4       1      version         0x03
 *   5       1      provider        EAC=1, BE=2
 *   6       2      total_size      full packet size
 *   8       16     session_id      random per-session
 *   24      4      sequence        monotonic counter (nonce-bound)
 *   28      4      lota_flags      mirror of token flags (integrity-checked
 *                                  against embedded token during verify)
 *   32      8      timestamp       Unix epoch (seconds, nonce-bound)
 *   40      32     game_id_hash    SHA-256(<game-binding domain> ||
 *                                  game_id || SHA-256(executable-bytes))
 *   72      2      token_size      embedded LOTA token length
 *   74      4      domain_version  LOTA_AC_DOMAIN_VERSION_*; selects the
 *                                  game-binding/heartbeat domain pair and
 *                                  is itself bound into the heartbeat nonce
 *   78      32     runtime_measure live re-measurement of the executable
 *                                  image; nonce-bound and checked against
 *                                  the verifier's expected value
 *   110     var    lota_token[]    full LOTA token (wire format)
 */
struct lota_ac_heartbeat_wire {
	uint32_t magic;
	uint8_t version;
	uint8_t provider;
	uint16_t total_size;
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint32_t sequence;
	uint32_t lota_flags;
	uint64_t timestamp;
	uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE];
	uint16_t token_size;
	uint32_t domain_version;
	uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE];
} __attribute__((packed));

struct lota_ac_info {
	enum lota_ac_provider provider;
	enum lota_ac_state
	    state; /* authoritative only for verify_heartbeat output */
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint64_t session_start;	 /* epoch */
	uint64_t last_heartbeat; /* epoch */
	uint32_t heartbeat_seq;	 /* current counter */
	uint32_t lota_flags;	 /* last known attestation flags */
	uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE]; /* verified game identity
							 binding */
	int trusted; /* set only by lota_ac_verify_heartbeat(); always 0 from
		      * get_info
		      */
};

struct lota_ac_session;

/*
 * Create and initialise an anti-cheat session.
 *
 * In direct mode, opens a connection to the LOTA agent.
 * In file mode, locates the Wine hook output directory.
 *
 * Returns NULL on error.
 */
struct lota_ac_session *lota_ac_init(const struct lota_ac_config *cfg);

/*
 * Destroy session and release resources.
 * Disconnects from agent if in direct mode. Safe to call with NULL.
 */
void lota_ac_shutdown(struct lota_ac_session *session);

/*
 * Get current session state.
 * Returns LOTA_AC_STATE_IDLE if session is NULL.
 */
enum lota_ac_state lota_ac_get_state(const struct lota_ac_session *session);

/*
 * Get local session telemetry for heartbeat production.
 *
 * Output from this function is NOT authoritative for anti-cheat decisions.
 * Treat it as local diagnostics only. Client-side memory can be hooked; server
 * trust must come from lota_ac_verify_heartbeat() over received heartbeat
 * packets.
 *
 * Returns 0 on success, -EINVAL if session or info is NULL.
 */
int lota_ac_get_info(const struct lota_ac_session *session,
		     struct lota_ac_info *info);

/*
 * Refresh session state from agent (direct) or hook files (file mode).
 * Call periodically or before generating a heartbeat.
 *
 * Returns 0 on success, negative errno on failure.
 */
int lota_ac_tick(struct lota_ac_session *session);

/*
 * Generate a heartbeat packet.
 *
 * Calls lota_ac_tick() internally for a fresh state, then serialises
 * the heartbeat into buf[0..buflen). On success, *written is set to
 * the actual packet size.
 *
 * Security model:
 * - The heartbeat binds sequence/timestamp/session/game context into
 *   token nonce, which is TPM-signature-authenticated by the inner token.
 * - This requires live token issuance with caller-supplied nonce.
 * - Therefore heartbeat generation is supported only in direct mode.
 *
 * Returns 0 on success, -EINVAL for bad arguments, -ENODATA if no
 * token is available, -ENOSPC if buf is too small, -EOPNOTSUPP if
 * replay-safe nonce binding is unavailable (file mode).
 */
int lota_ac_heartbeat(struct lota_ac_session *session, uint8_t *buf,
		      size_t buflen, size_t *written);

/*
 * Compute canonical game-binding hash for a game ID and executable image.
 *
 * Hash format:
 *   SHA-256("lota-ac-game-binding:v2\\0" || game_id ||
 * SHA-256(executable-bytes))
 *
 * Use this to precompute expected_game_id_hash for server-side checks.
 */
int lota_ac_compute_game_binding_hash(const char *game_id, const char *exe_path,
				      uint8_t out[LOTA_AC_GAME_HASH_SIZE]);

/*
 * Runtime re-measurement of the live executable image.
 *
 * Game-binding hash above pins SHA-256 of the on-disk executable at
 * session start. It cannot detect an attacker who patches code pages in
 * memory without touching the file.
 *
 * Runtime measurement closes that TOCTOU window by hashing the executable
 * PT_LOAD segments as they are mapped in the live address space.
 *
 * Canonical digest:
 *   SHA-256("lota-ac-runtime-measure:v1\\0" || seg_count_LE32 ||
 *           for each executable (PF_X) PT_LOAD segment, in ascending
 *           p_vaddr order:
 *               p_vaddr_LE64 || p_offset_LE64 || p_filesz_LE64 ||
 *               segment_bytes[p_filesz])
 *
 * For position-independent x86-64 code the executable segments carry no
 * load-time relocations, so the live mapping is byte-identical to the
 * on-disk segment content.
 *
 * Producer measures its own running image.
 * Verifier precomputes the expected digest from the same ELF file.
 *
 * Divergence means the live code pages no longer match the registered
 * binary.
 */

/*
 * Measure the live, mapped executable image of the calling process.
 *
 * Hashes the in-memory PF_X PT_LOAD segments of the main program object
 * (as reported by dl_iterate_phdr). Returns 0 on success, -EINVAL on a
 * NULL argument, -ENOMEM on allocation failure, -E2BIG if the image has
 * more executable segments than the implementation supports, -EIO on a
 * digest failure, -ENOENT if no executable segment is found.
 */
int lota_ac_compute_runtime_measure(uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE]);

/*
 * Precompute the expected runtime measurement from an ELF file on disk.
 *
 * Parses the ELF program headers and hashes the file-backed bytes of the
 * PF_X PT_LOAD segments using the same canonical layout as
 * lota_ac_compute_runtime_measure(). Use this to derive the value a
 * trustworthy producer must report for exe_path.
 *
 * Returns 0 on success, EINVAL on a NULL argument, negative errno
 * on an I/O or parse failure.
 */
int lota_ac_compute_expected_runtime_measure(
    const char *exe_path, uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE]);

/*
 * Verify a heartbeat packet.
 *
 * Parses the heartbeat header, extracts the embedded LOTA token,
 * and performs full TPM signature verification using aik_pub_der.
 * Also requires expected_game_id_hash and rejects heartbeats that do not match
 * the expected game identity binding.
 * Fills info with session/attestation details.
 *
 * expected_runtime_measure is the runtime measurement a trustworthy
 * producer must report for this image.
 * See lota_ac_compute_expected_runtime_measure()
 *
 * It is mandatory: the heartbeat is rejected unless its runtime_measure
 * field matches, and the value is also bound into the nonce so a fully
 * signed token cannot carry a stale or substituted measurement.
 *
 * SECURITY: aik_pub_der is mandatory. Parse-only operation is rejected
 * because unverified claims are attacker-controlled and must not drive
 * trust decisions.
 *
 * max_age_sec: maximum acceptable token age (0 -> 300 s default).
 *
 * Returns 0 on success, negative error code on failure.
 */
int lota_ac_verify_heartbeat(
    const uint8_t *data, size_t len, const uint8_t *aik_pub_der,
    size_t aik_pub_len,
    const uint8_t expected_game_id_hash[LOTA_AC_GAME_HASH_SIZE],
    const uint8_t expected_runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE],
    struct lota_ac_info *info);

const char *lota_ac_state_str(enum lota_ac_state state);
const char *lota_ac_provider_str(enum lota_ac_provider provider);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_ANTICHEAT_H */
