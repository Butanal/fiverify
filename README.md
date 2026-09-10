# fiverify

Offline validation of France Identité attestation PDFs — the PAdES-T qualified
electronic seal issued by the French Ministry of the Interior.

Offline by default: nothing opens a socket unless you ask for it. Trust anchors,
validation time and revocation data are inputs.

## Install

    pip install fiverify

Or from a clone, to work on it: `pip install -e .` (`pip install --user -e .`
outside a virtualenv).

Python 3.11+. Pulls in `asn1crypto` and `cryptography`; nothing else.

## Quick start

    fi-verify attestation.pdf --fetch-revocation
    fi-verify attestation.pdf --accept-unchecked-revocation

```python
from fiverify import Status, verify_file

# Fetch the CRLs the certificates name — the only network access in the project.
report = verify_file("attestation.pdf", fetch_revocation=True, extract_attributes=True)

# Or stay fully offline, accepting that revocation status is unknown.
report = verify_file("attestation.pdf", accept_unchecked_revocation=True, extract_attributes=True)

if report.status is Status.PASSED:
    print(report.attributes)          # identity fields, only ever from verified bytes
else:
    print(report.status.value, [c.summary for c in report.failures()])
```

That is the complete check: signature, coverage, timestamp, chain to the eIDAS
anchor, and revocation. `examples/` holds a signed document and two forgeries
of it, to try without a real attestation.

## Revocation

The default (`verify_pdf(...)` with no revocation argument) returns
`INDETERMINATE`, never `PASSED` — with no revocation data the tool cannot
honestly say a certificate was good. Your options, least to most trusting:

| | CLI | API |
|---|---|---|
| Fetch CRLs now | `--fetch-revocation` | `fetch_revocation=True` |
| Use CRLs you already have | `--crl ./crls/` | `revocation=RevocationStore.from_paths([...])` |
| Accept that it is unknown | `--accept-unchecked-revocation` | `accept_unchecked_revocation=True` |
| Demand post-dated CRLs | `--strict-revocation` | `strict_revocation=True` |

Revocation is evaluated **at the signing timestamp**, not now, so a
certificate revoked afterward doesn't invalidate the seal — and only if that
timestamp came from a TSA that chains to an anchor, since an untrusted one
would be free to back-date the seal past the revocation. `--strict-revocation`
requires a CRL issued after that timestamp rather than one merely in force
over it — the stronger guarantee needed for archival validation.

`--fetch-revocation` downloads only what an *anchored* certificate names, and
only over HTTP(S): a distribution point is a URL chosen by whoever wrote the
document, so fetching one before its certificate reaches a trust anchor would
make verification a fetch primitive. To pin the hosts as well, fetch separately
with `fetch_for_pdf(data, allowed_hosts=[...])` and pass the store in.

## Identity attributes

Fields like `familyName`, `givenName`, `birthdate` are not extracted unless
you ask (`--attributes` / `extract_attributes=True`), and **are only ever
returned from bytes covered by a signature that reaches a trust anchor** — a
document can be forged so the seal still verifies while content changed
underneath it (see `examples/forged-append.pdf`), or simply signed by its
author's own certificate, and `report.attributes` stays `None` rather than
trusting that content.

## Reading the report

```python
report.status                            # PASSED | FAILED | INDETERMINATE
report.caveats                           # what was not checked, e.g. revocation
report.attributes                        # identity fields, if asked and verified
report.failures()                        # [Check(...), ...]
report.signatures[0].details             # signer, chain, gen_time, algorithms, …
report.to_dict()                         # JSON-safe
```

Results are three-valued, per ETSI EN 319 102-1. Every `Check` carries an `id`,
a `severity`, an ETSI `sub_indication`, and the evidence behind it.
`strict=True` makes profile expectations fatal rather than indeterminate.

Exit codes: `0` passed, `1` failed, `2` indeterminate, `3` usage or I/O error.
Add `--json` for the full report, `-v` to include passing informational checks.

## Profiles and trust anchors

Everything document-specific — policy OIDs, algorithm allow-lists, trust
anchors and their SHA-256 pins — lives in
`src/fiverify/profiles/france-identite.toml`, not in code. Chains terminate at
`AC SERVEUR CACHET EIDAS 2025`, the eIDAS trust anchor itself (listed in the
French Trusted List), pinned by fingerprint in the profile.

    fi-verify doc.pdf --profile my.toml --anchor extra-ca.pem --at 2027-01-01

`tools/tsl-anchors.py --verify` reproduces the bundled anchor from the live
EU/FR trusted lists rather than asking you to take it on trust; see the tool
for rollover instructions.

## What it does not do

- **OCSP.** CRLs only. A responder URL is reported, not queried.
- **Embedded revocation data (PAdES-LT `/DSS`).** Long-term validation of an
  old document depends on a CRL that still lists it.
- **PDF object-graph parsing.** A revision appended after signing is reported
  as uncovered content, not classified — fine for single-signature documents,
  not yet for counter-signed ones.

## Tests

    pip install pytest && python3 -m pytest

88 tests, offline, no fixtures checked in — generated against a throwaway PKI,
with every signature-arithmetic verdict cross-checked against `openssl`.
