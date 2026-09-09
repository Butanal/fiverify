from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

from .profile import Profile, ProfileError
from .report import Report, Severity, Status
from .revocation import RevocationStore
from .verify import verify_pdf
from .x509util import load_pem_certs

EXIT = {Status.PASSED: 0, Status.FAILED: 1, Status.INDETERMINATE: 2, Status.SKIPPED: 2}
MARK = {Status.PASSED: "ok  ", Status.FAILED: "FAIL", Status.INDETERMINATE: "??  ", Status.SKIPPED: "--  "}


def render(report: Report, verbose: bool) -> str:
    out = [f"{report.file_sha256[:16]}…  {report.file_size} bytes  profile {report.profile}", ""]
    for c in report.checks:
        if verbose or c.status is not Status.PASSED or c.severity is not Severity.INFO:
            out.append(f"  [{MARK[c.status]}] {c.id:<34} {c.summary}")
    for sig in report.signatures:
        d = sig.details
        out += ["", f"signature {sig.index + 1} — {sig.status.value.upper()}"
                    + (f" ({sig.sub_indication.value})" if sig.sub_indication else "")]
        if d.get("signer"):
            out.append(f"  signer   {d['signer']}")
            out.append(f"  issuer   {d.get('signer_issuer')}  ({d.get('digest_algorithm')}/"
                       f"{d.get('signature_algorithm')}, {d.get('key_bits')}-bit)")
        if d.get("gen_time"):
            out.append(f"  sealed   {d['gen_time']}  by {d.get('tsa')}")
        if d.get("chain"):
            out.append(f"  chain    {' <- '.join(d['chain'])}")
        out.append("")
        for c in sig.checks:
            if not verbose and c.status is Status.PASSED and c.severity is Severity.INFO:
                continue
            out.append(f"  [{MARK[c.status]}] {c.id:<34} {c.summary}")
    if report.attributes:
        out += ["", "identity attributes (from signed bytes)"]
        out += [f"  {k:<14} {v}" for k, v in report.attributes.items()]
    caveats = f"  ({'; '.join(report.caveats)})" if report.caveats else ""
    out += ["", f"result: {report.status.value.upper()}{caveats}"]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="fi-verify",
        description="Validate a France Identité signed PDF offline.")
    ap.add_argument("pdf", type=Path)
    ap.add_argument("--profile", type=Path, help="TOML profile (default: bundled france-identite)")
    ap.add_argument("--anchor", type=Path, action="append", default=[],
                    metavar="PEM", help="extra trust anchor; repeatable")
    ap.add_argument("--at", help="validation time, ISO 8601 (default: now)")
    ap.add_argument("--crl", type=Path, action="append", default=[], metavar="PATH",
                    help="CRL file or directory of them; repeatable. Offline")
    ap.add_argument("--fetch-revocation", action="store_true",
                    help="download CRLs named by the certificates. THE ONLY NETWORK ACCESS")
    ap.add_argument("--strict-revocation", action="store_true",
                    help="require a CRL issued after the timestamp, not merely one in "
                         "force over it")
    ap.add_argument("--accept-unchecked-revocation", action="store_true",
                    help="accept that revocation status is unknown, allowing PASSED")
    ap.add_argument("--strict", action="store_true",
                    help="treat profile expectations as fatal, not indeterminate")
    ap.add_argument("--attributes", action="store_true",
                    help="print identity attributes; only ever from verified bytes")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    try:
        profile = Profile.from_file(args.profile) if args.profile else Profile.bundled()
        extra = [c for p in args.anchor for c in load_pem_certs(p.read_bytes())]
        at = datetime.fromisoformat(args.at) if args.at else None
        data = args.pdf.read_bytes()
        report = verify_pdf(
            data, profile=profile, at=at, strict=args.strict, extra_anchors=extra,
            revocation=RevocationStore.from_paths(args.crl) if args.crl else None,
            fetch_revocation=args.fetch_revocation,
            accept_unchecked_revocation=args.accept_unchecked_revocation,
            strict_revocation=args.strict_revocation,
            extract_attributes=args.attributes)
    except (ProfileError, OSError, ValueError) as e:
        print(f"fi-verify: {e}", file=sys.stderr)
        return 3

    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) if args.json
          else render(report, args.verbose))
    return EXIT[report.status]


if __name__ == "__main__":
    sys.exit(main())
