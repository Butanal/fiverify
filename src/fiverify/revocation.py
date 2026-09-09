"""CRL-based revocation checking. Offline: the caller supplies the CRLs."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from asn1crypto import crl as acrl
from asn1crypto import pem
from asn1crypto import x509 as ax509
from asn1crypto.core import VOID
from cryptography.x509 import load_der_x509_certificate

from .crypto import InvalidSignature, UnsupportedAlgorithm, verify

GOOD, REVOKED, UNKNOWN = "good", "revoked", "unknown"


@dataclass
class RevocationResult:
    state: str
    summary: str
    evidence: dict = field(default_factory=dict)
    code: str = ""   # ok | revoked | no_crl | stale | suspended


@dataclass
class RevocationStore:
    crls: list[acrl.CertificateList] = field(default_factory=list)

    @classmethod
    def from_paths(cls, paths) -> "RevocationStore":
        store = cls()
        for p in paths:
            p = Path(p)
            for f in sorted(p.rglob("*")) if p.is_dir() else [p]:
                if f.is_file():
                    store.add(f.read_bytes())
        return store

    def add(self, data: bytes) -> None:
        if pem.detect(data):
            for _, _, der in pem.unarmor(data, multiple=True):
                self.crls.append(acrl.CertificateList.load(der))
        else:
            self.crls.append(acrl.CertificateList.load(data))

    def __len__(self) -> int:
        return len(self.crls)

    def status(self, cert: ax509.Certificate, issuer: ax509.Certificate,
               at: datetime, *, strict: bool = False) -> RevocationResult:
        """Status of `cert` at time `at`.

        A CRL answers for `at` if it was issued at or after it - CRLs are
        cumulative, so a later one still lists an earlier revocation - or, unless
        `strict`, if its own validity window covers `at`, which is the assertion
        the CA makes by publishing a nextUpdate (RFC 5280 6.3).
        """
        serial = cert["tbs_certificate"]["serial_number"].native
        skipped: list[str] = []
        usable: list[acrl.CertificateList] = []

        for c in self.crls:
            if c.issuer != cert.issuer:
                continue
            if why := _unusable(c, cert):
                skipped.append(why)
                continue
            if not _signature_ok(c, issuer):
                skipped.append("CRL signature does not verify against the issuer")
                continue
            usable.append(c)

        if not usable:
            return RevocationResult(
                UNKNOWN, "no usable CRL for " + (cert.issuer.native.get("common_name") or "the issuer"),
                {"crls_considered": len(self.crls), "skipped": skipped}, "no_crl")

        for c in usable:
            for entry in c["tbs_cert_list"]["revoked_certificates"] or []:
                if entry["user_certificate"].native != serial:
                    continue
                when = entry["revocation_date"].native
                reason = (entry.crl_reason_value.native if entry.crl_reason_value else None)
                ev = {"revocation_date": when, "reason": reason,
                      "crl_this_update": c["tbs_cert_list"]["this_update"].native}
                if reason == "certificate_hold":
                    return RevocationResult(
                        UNKNOWN, f"certificate was suspended on {when.isoformat()}", ev, "suspended")
                if when <= at:
                    return RevocationResult(
                        REVOKED, f"certificate was revoked on {when.isoformat()}"
                                 + (f" ({reason})" if reason else ""), ev, "revoked")
                return RevocationResult(
                    GOOD, f"certificate was revoked on {when.isoformat()}, after this signature",
                    ev, "ok")

        fresh = [c for c in usable
                 if _answers_for(c, at, strict) and not _partial(c)]
        if not fresh:
            newest = max(usable, key=lambda c: c["tbs_cert_list"]["this_update"].native)
            issued = newest["tbs_cert_list"]["this_update"].native
            due = newest["tbs_cert_list"]["next_update"]
            due = None if due is VOID else due.native
            if strict:
                why = f"was issued {issued.isoformat()}, before this signature was timestamped"
                fix = f"re-check against a CRL issued after {at.isoformat()}"
            elif due is None:
                why = f"was issued {issued.isoformat()} and states no next-update time"
                fix = "re-check against a newer CRL"
            else:
                why = f"was in force only until {due.isoformat()}"
                fix = "re-check against the CRL that superseded it"
            return RevocationResult(
                UNKNOWN,
                f"newest CRL {why}, so it cannot show the status at {at.isoformat()}; {fix}",
                {"crl_this_update": issued, "crl_next_update": due, "needed_after": at},
                "stale")
        best = max(fresh, key=lambda c: c["tbs_cert_list"]["this_update"].native)
        issued = best["tbs_cert_list"]["this_update"].native
        due = best["tbs_cert_list"]["next_update"]
        due = None if due is VOID else due.native
        how = ("issued after this signature" if issued >= at
               else f"in force over it until {due.isoformat()}" if due else "in force")
        return RevocationResult(
            GOOD, f"not listed on the CRL issued {issued.isoformat()}, {how}",
            {"crl_this_update": issued, "crl_next_update": due,
             "post_dated": issued >= at}, "ok")


def _answers_for(c: acrl.CertificateList, at: datetime, strict: bool) -> bool:
    tbs = c["tbs_cert_list"]
    if tbs["this_update"].native >= at:
        return True
    if strict:
        return False
    due = tbs["next_update"]
    return due is not VOID and due.native >= at


def _partial(c: acrl.CertificateList) -> bool:
    idp = c.issuing_distribution_point_value
    return bool(idp and idp["only_some_reasons"] is not VOID)


def _unusable(c: acrl.CertificateList, cert: ax509.Certificate) -> str | None:
    if c.delta_crl_indicator_value is not None:
        return "delta CRL (not supported)"
    idp = c.issuing_distribution_point_value
    if idp is None:
        return None
    if idp["indirect_crl"].native:
        return "indirect CRL (not supported)"
    if idp["only_contains_user_certs"].native and cert.ca:
        return "CRL covers end-entity certificates only"
    if idp["only_contains_ca_certs"].native and not cert.ca:
        return "CRL covers CA certificates only"
    return None


def _signature_ok(c: acrl.CertificateList, issuer: ax509.Certificate) -> bool:
    try:
        verify(load_der_x509_certificate(issuer.dump()), c["signature"].native,
               c["tbs_cert_list"].dump(), c["signature_algorithm"])
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return False
    return True
