/* SPDX-License-Identifier: MIT */
#ifndef LOTA_SELFTEST_H
#define LOTA_SELFTEST_H

#include <stddef.h>
#include <stdint.h>

int test_tpm(void);
int test_iommu(void);
void print_hex(const char *label, const uint8_t *data, size_t len);

/*
 * Operator/root one-shots: seal a secret read from stdin to the current
 * PCR state and write the blob to stdout, or unseal a blob from stdin and
 * write the secret to stdout. Never exposed over the agent IPC socket.
 */
int do_seal(const char *pcr_str);
int do_unseal(void);

#endif /* LOTA_SELFTEST_H */
