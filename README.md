# fiverify

Offline validation of France Identité attestation PDFs — the PAdES-T qualified
electronic seal issued by the French Ministry of the Interior.

Offline by default: nothing opens a socket unless you ask for it. Trust anchors,
validation time and revocation data are inputs.

## Install

Not on PyPI. Install from a clone or an unpacked copy:

    cd fiverify
    python3 -m venv venv
    ./venv/bin/pip install .          # or: -e . to work on it

That puts `fi-verify` in `venv/bin/`. Run it as `./venv/bin/fi-verify`, or
activate the environment first (`source venv/bin/activate`) and just use
`fi-verify`. Without a virtualenv, `pip install --user .` works too.

Python 3.11+. Pulls in `asn1crypto` and `cryptography`; nothing else.

## Quick start

    ./venv/bin/fi-verify attestation.pdf --fetch-revocation

```python
from fiverify import Status, verify_file

report = verify_file("attestation.pdf", fetch_revocation=True)

if report.status is Status.PASSED:
    print("valid", report.signatures[0].details["gen_time"])
else:
    print(report.status.value, [c.summary for c in report.failures()])
```

That is the complete check: signature, coverage, timestamp, chain to the eIDAS
anchor, and revocation. `--fetch-revocation` downloads the CRLs the certificates
name — the one thing here that uses the network. Drop it and everything else
still runs offline.

`examples/` holds a signed document and two forgeries of it, to try without a
real attestation.

## Choosing how to handle revocation

Revocation is the only check needing data from outside the document, so it is the
only real configuration decision. Four ways, in order of least to most trusting:

| | CLI | API |
|---|---|---|
| Fetch CRLs now | `--fetch-revocation` | `fetch_revocation=True` |
| Use CRLs you already have | `--crl ./crls/` | `revocation=RevocationStore.from_paths([...])` |
| Accept that it is unknown | `--accept-unchecked-revocation` | `accept_unchecked_revocation=True` |
| Demand post-dated CRLs | `--strict-revocation` | `strict_revocation=True` |
| Refuse to guess *(default)* | — | — |

The default returns `INDETERMINATE`, never `PASSED`: with no revocation data the
tool cannot honestly say a certificate was good. The other three all make
`PASSED` reachable — the first two by actually establishing it, the third by
recording that you accepted the gap.

`--crl` takes a file or a directory, repeatably. Certificates say where their
CRLs live, and `details.revocation_urls` in the report repeats those URLs so you
know what to fetch. A CRL is believed only if it matches the issuer, carries a
signature that verifies, is in scope, and is fresh enough to speak to the moment
in question.

Revocation is evaluated **at the timestamp**, not now — a certificate revoked
*after* a document was sealed does not invalidate that seal, and the report says
so rather than failing.

A CRL answers for that moment if it was issued at or after it — CRLs are
cumulative, so a later one still lists an earlier revocation — or if its own
validity window covers it, which is what a CA asserts by publishing a
`nextUpdate`. The second case matters in practice: a document sealed this
afternoon will usually be checked against a CRL published this morning, and no
CRL that post-dates the seal exists yet. Requiring one would make every freshly
signed document `INDETERMINATE` until the CA's next publication.

If you need the stronger guarantee — archival or long-term validation, where you
want revocation data that provably post-dates the signature — ask for it:

    fi-verify doc.pdf --crl ./crls/ --strict-revocation

Then a CRL merely in force over the timestamp is not enough, and the result is
`INDETERMINATE / TRY_LATER` with the message naming what would settle it.

To keep the network out of the process entirely, fetch separately:

```python
from fiverify import verify_pdf
from fiverify.online import fetch_for_pdf     # the only socket in the project

data = open("attestation.pdf", "rb").read()
store, errors = fetch_for_pdf(data)
report = verify_pdf(data, revocation=store)
```

## Identity attributes

The attestation carries the holder's details as named fields in a PDF object —
`familyName`, `givenName`, `birthdate`, `birthplace`, `validityDate` and the
rest. They are not extracted unless you ask:

    fi-verify attestation.pdf --attributes

```python
report = verify_file("attestation.pdf", extract_attributes=True)
report.attributes            # {"familyName": "...", ...} or None
```

**They are only ever returned from bytes a signature covers.** If coverage, the
message digest or the signature itself did not pass, `report.attributes` stays
`None` and the report says why — because a document can be forged so that the
seal still verifies while the content changed underneath it, which is exactly
what `examples/forged-append.pdf` does. Reading fields out of such a file and
believing them is the mistake this refuses to let you make.

Values are decoded properly: UTF-16 with or without a byte-order mark, PDF
literal strings with escaped or nested parentheses, and octal escapes. The
carrying object is found by its contents, not by a fixed object number.

## Reading the report

`verify_pdf(data, *, profile=None, at=None, strict=False, extra_anchors=None,
revocation=None, fetch_revocation=False, accept_unchecked_revocation=False)`
takes bytes; `verify_file(path, **kw)` is the same over a path.

```python
report.status                            # PASSED | FAILED | INDETERMINATE
report.caveats                           # what was not checked
report.attributes                        # identity fields, if asked and verified
report.failures()                        # [Check(...), ...]
report.signatures[0].details             # signer, chain, gen_time, algorithms, …
report.to_dict()                         # JSON-safe
```

Results are three-valued, per ETSI EN 319 102-1. Every `Check` carries an `id`, a
`severity` (`CRITICAL` / `POLICY` / `INFO`), an ETSI `sub_indication`, and the
evidence behind it. `strict=True` makes profile expectations fatal rather than
indeterminate.

Whatever was **not** checked stays in `report.caveats`, and the CLI renders it
inline — so a `PASSED` that skipped revocation says so wherever the report goes:

    result: PASSED  (revocation status not checked)

With revocation actually established, `caveats` is empty.

Exit codes: `0` passed, `1` failed, `2` indeterminate, `3` usage or I/O error.
Add `--json` for the full report, `-v` to include passing informational checks.

## Profiles

Everything document-specific is data, in
`src/fiverify/profiles/france-identite.toml` — policy OIDs, algorithm
allow-lists, `signingTime` handling, qcStatements expectations, and trust anchors
with their SHA-256 pins. A CA rollover is a profile change, not a code change.

    fi-verify doc.pdf --profile my.toml --anchor extra-ca.pem --at 2027-01-01

Two profiles ship. `france-identite` asserts the expectations above. `observe`
asserts none of them and only reports what a document contains — use it to check
the profile against a document of your own, or to work out what changed after a
rollover:

    fi-verify doc.pdf --profile src/fiverify/profiles/observe.toml --json

Values such as the signature-policy and TSA-policy OIDs are recorded in `details`
whether or not a profile constrains them.

## Trust anchors

Chains terminate at `AC SERVEUR CACHET EIDAS 2025`, which issues both the sealing
certificate and the MI-19 timestamping certificate. It is the eIDAS trust anchor
itself — listed as a service in the French Trusted List — so paths stop there
rather than at a root CA.

A copy ships in `src/fiverify/anchors/`, and the profile pins its SHA-256:

    96693ee8a4310e9c21893021b536e28d844a3587789b4c3d6c436e456db71871

An anchor whose fingerprint is not pinned by its profile is refused at load time.

Do not take that copy on trust — reproduce it. `tools/tsl-anchors.py` downloads
the list, matches every bundled anchor by fingerprint, and reports the service
type and status the list gives it:

    $ python3 tools/tsl-anchors.py --verify
    [ok  ] AC SERVEUR CACHET EIDAS 2025
           96693ee8a4310e9c21893021b536e28d844a3587789b4c3d6c436e456db71871
           type=QC status=granted

Exit status is non-zero if an anchor is missing or no longer `granted`. Use
`--tsl-file` to work from a copy you downloaded yourself, `--tsl` for a different
list. The provenance, all public:

    EU LOTL   https://ec.europa.eu/tools/lotl/eu-lotl.xml
    FR TSL    https://messervices.cyber.gouv.fr/visas/tl-fr_v6.xml
      Ministère de l'Intérieur
        AC Serveur Cachet eIDAS 2025                 QC   granted
        Horodatage du Ministère de l'Intérieur MI-19 QTST granted

When the CA rolls over, fetch the new anchor and pin it:

    python3 tools/tsl-anchors.py --list                     # find the service
    python3 tools/tsl-anchors.py --match "CACHET EIDAS" \
        -o src/fiverify/anchors                             # writes PEM, prints sha256

Then add the filename to `[trust].anchors` and the fingerprint to
`[trust].pinned_sha256`. To validate against an anchor without editing a profile,
pass `--anchor path.pem` or `extra_anchors=[...]`.

## What it checks

| | |
|---|---|
| `pdf.*` | `/ByteRange` well-formed, `/Contents` fills the gap exactly, coverage of the whole file, appended revisions, padding |
| `cms.*` | messageDigest over the signed bytes, signature arithmetic, contentType, ESS `signingCertificateV2` binding, algorithm policy, `signingTime`, signature-policy and commitment-type attributes |
| `tsp.*` | timestamp present, imprint over *this* signature, the token's own signature, TSA EKU critical, TSA policy, stated accuracy, TSA chain |
| `chain.*` | path to a trusted eIDAS anchor, every certificate valid **at the timestamp**, not at the wall clock |
| `signer.*` | qcStatements — QcCompliance, QcSSCD, QcType eSeal — and key usage |
| `revocation.*` | CRL status of the signer and each CA, evaluated at the timestamp |

Two rules govern the byte handling:

- `/Contents` padding is split off using the **outer DER length**. A CMS can
  legitimately end in `0x00`, so trailing zeroes must never be stripped.
- The signed bytes are used verbatim. Any canonicalisation — `openssl` without
  `-binary`, for instance — makes a valid signature fail.

## What it does not do

- **OCSP.** CRLs only. A responder URL is reported, not queried.
- **Embedded revocation data.** A PAdES-LT document security store (`/DSS`) is
  not read, so long-term validation of an old document depends on a CRL that
  still lists it — a CA may drop entries once a certificate expires. For recent
  documents this is not a problem; for archival ones it is the reason PAdES-LTA
  exists.
- **PDF object-graph parsing.** Signature discovery works on bytes, so
  incremental-update *difference* analysis is out of scope: a revision appended
  after signing is reported as uncovered content, not classified. For
  single-signature documents that is the right call; for counter-signed ones it
  will need building out.

## Tests

    pip install pytest && python3 -m pytest

75 tests, offline, no fixtures checked in. `tests/fixtures.py` generates the
corpus against a throwaway PKI: tampered content, forged revisions, shifted
`/ByteRange`, non-zero padding, substituted timestamps, expired certificates,
missing attributes, CRLs that are stale, mis-signed or out of scope, and
identity fields that must not be handed over. Every
signature-arithmetic verdict is cross-checked against `openssl` in
`tests/test_oracle.py`.
