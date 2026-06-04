# EK manufacturer root trust bundle

The attestation CA accepts an Endorsement Key certificate only if it chains
to a TPM manufacturer root the operator trusts. Production fleets span
several manufacturers, so the trust set is a *bundle* of vendor roots.

What this directory ships is **not** the vendor certificates themselves --
those are published by each manufacturer and fetched out of band -- but the
machinery that turns them into a pin-enforced bundle:

- `sources.example` -- the canonical per-vendor download URLs and the slots
  for the SHA-256 fingerprint you verify against each vendor's published
  value.
- `lota-ek-roots-update.sh` (in `scripts/`) -- fetches each root, refuses
  any download whose fingerprint does not match the pin you recorded, and
  writes the populated bundle directory.

The CA loads the populated bundle with `-ek-root-bundle <dir>` and is
**fail-closed**: every pin in the bundle manifest must resolve to a present
certificate whose SHA-256 matches, and any unpinned certificate dropped
into the directory is rejected. A swapped or injected root therefore cannot
widen the trusted manufacturer set without the change showing up as a pin
edit in version control.

## Vendors

The bundle is meant to cover the manufacturers a LOTA fleet realistically
sees. `sources.example` lists, per vendor, a starting point for the root
distribution:

| Vendor              | Root family                | Distribution                                          |
|---------------------|----------------------------|-------------------------------------------------------|
| Infineon            | OPTIGA TPM RSA/ECC root CA  | Infineon PKI host (documented hint)                   |
| STMicroelectronics  | ST TPM EK root CA          | GlobalSign (ST app note TN1330; documented hint)      |
| Intel               | PTT / EK root CA           | legacy upgrades.intel.com **or** Intel OnDie CA (CSME PTT) -- `UNVERIFIED` |
| AMD fTPM            | AMD fTPM EK root           | no single public root -- `UNVERIFIED`                 |
| Microsoft           | Microsoft TPM Root CA      | covers AMD fTPM / vTPM EK chains -- `UNVERIFIED`       |

Cover only the manufacturers your fleet actually attests; an unused vendor
root only widens the trust set.

**No URL here is authoritative on its own.** The reliable way to find the
right root for a platform is to take an actual EK certificate and walk its
issuer chain to the self-signed root:

```sh
# discrete TPM / Intel PTT: the EK cert lives in TPM NV
sudo tpm2_nvreadpublic                    # find the 0x01c0xxxx EK cert index
sudo tpm2_nvread 0x01c00002 -o ek.der     # RSA EK (0x01c0000a = ECC)
openssl x509 -in ek.der -inform DER -noout -issuer -ext authorityInfoAccess
# follow each "CA Issuers" URL up until issuer == subject (the root),
# then: openssl x509 -in root.der -inform DER -outform DER | sha256sum  # the pin
```

On a Windows host the chain comes from PowerShell (admin):
`Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256` exposes
`ManufacturerCertificates` and `AdditionalCertificates`; export each
(`[IO.File]::WriteAllBytes(...,$c.RawData)`) and walk the same way.

`sources.example` only ships a documented URL where the vendor itself
publishes one (Infineon, STM via GlobalSign). Where I could not confirm a
source it ships `UNVERIFIED`, so the tool stops until you supply the root
your own platforms chain to:

- **Intel** runs two PKIs -- legacy discrete / early-PTT roots at
  `upgrades.intel.com`, and the Intel OnDie CA
  (`tsci.intel.com/content/OnDieCA`) used by modern CSME firmware TPM (PTT)
  on Tiger Lake and later. A CSME PTT EK cert (issuer `CSME <SoC> PTT`)
  chains through OnDie CA, not the legacy root, so the legacy URL is not a
  safe default.
- **AMD fTPM** and AMD-based **vTPM** EK certificates chain under Microsoft's
  TPM PKI on most platforms, and many AMD fTPMs ship with no EK certificate
  in NV at all (`tpm2_nvreadpublic` shows no `0x01c0xxxx` cert) -- there is
  nothing to pin until you have an EK cert whose chain you can walk.

## Provisioning a bundle

1. Copy the template and fill each `pin` with the SHA-256 fingerprint the
   vendor publishes for that root (verify it out of band -- a vendor
   advisory, a signed release note -- never trust the value the download
   itself hands you):

   ```sh
   cp sources.example sources
   $EDITOR sources
   ```

2. Materialize the bundle. The tool downloads each root, re-checks its
   fingerprint against your pin, and fails closed on any mismatch:

   ```sh
   scripts/lota-ek-roots-update.sh sources /var/lib/lota/ek-roots
   ```

3. Point the CA at it:

   ```sh
   lota-attest-ca -ek-root-bundle /var/lib/lota/ek-roots ...
   ```

## Updating

Adding, removing, or rotating a vendor root is a manifest edit: change the
relevant line in `sources`, re-run `lota-ek-roots-update.sh`, and commit the
resulting fingerprint change. Because the CA pins every root, the diff in
the manifest is the audit trail for any change to the trusted set.

A vendor that rotates its root publishes the new fingerprint; record it as a
new line (keep the old one until every host with the older EK is retired so
both chains keep verifying through the overlap).
