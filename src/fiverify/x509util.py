from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from asn1crypto import core, pem
from asn1crypto import x509 as ax509
from cryptography.x509 import load_der_x509_certificate

from .crypto import InvalidSignature, UnsupportedAlgorithm, digest, verify

MAX_CHAIN = 8


class QCStatement(core.Sequence):
    _fields = [("statement_id", core.ObjectIdentifier), ("statement_info", core.Any, {"optional": True})]


class QCStatements(core.SequenceOf):
    _child_spec = QCStatement


class QcTypes(core.SequenceOf):
    _child_spec = core.ObjectIdentifier


ax509.ExtensionId._map["1.3.6.1.5.5.7.1.3"] = "qc_statements"
ax509.Extension._oid_specs["qc_statements"] = QCStatements

QC_COMPLIANCE = "0.4.0.1862.1.1"
QC_SSCD = "0.4.0.1862.1.4"
QC_TYPE = "0.4.0.1862.1.6"
QC_TYPES = {"0.4.0.1862.1.6.1": "eSign", "0.4.0.1862.1.6.2": "eSeal", "0.4.0.1862.1.6.3": "webAuth"}


def load_pem_certs(data: bytes) -> list[ax509.Certificate]:
    return [ax509.Certificate.load(der) for _, _, der in pem.unarmor(data, multiple=True)]


def fingerprint(cert: ax509.Certificate) -> str:
    return digest("sha256", cert.dump()).hex()


def name(cert: ax509.Certificate) -> str:
    return cert.subject.native.get("common_name") or cert.subject.human_friendly


def qc_statements(cert: ax509.Certificate) -> dict[str, object]:
    for ext in cert["tbs_certificate"]["extensions"] or []:
        if ext["extn_id"].native != "qc_statements":
            continue
        out: dict[str, object] = {"ids": []}
        for st in ext["extn_value"].parsed:
            oid = st["statement_id"].dotted
            out["ids"].append(oid)
            if oid == QC_TYPE and st["statement_info"] is not core.VOID:
                types = QcTypes.load(st["statement_info"].dump())
                out["types"] = [QC_TYPES.get(t.dotted, t.dotted) for t in types]
        out["compliant"] = QC_COMPLIANCE in out["ids"]
        out["sscd"] = QC_SSCD in out["ids"]
        return out
    return {}


def revocation_urls(cert: ax509.Certificate) -> dict[str, list[str]]:
    """Every CRL URI, not just the first - a distribution point usually lists
    mirrors, and asn1crypto's DistributionPoint.url exposes only one."""
    crl: list[str] = []
    for ext in cert["tbs_certificate"]["extensions"] or []:
        if ext["extn_id"].native != "crl_distribution_points":
            continue
        for dp in ext["extn_value"].parsed:
            point = dp["distribution_point"]
            if point is core.VOID or point.name != "full_name":
                continue
            for gn in point.chosen:
                if gn.name == "uniform_resource_identifier" and gn.native not in crl:
                    crl.append(gn.native)
    return {"crl": crl, "ocsp": list(cert.ocsp_urls or [])}


def verify_issued_by(child: ax509.Certificate, issuer: ax509.Certificate) -> bool:
    if child.issuer != issuer.subject:
        return False
    try:
        verify(
            load_der_x509_certificate(issuer.dump()),
            child["signature_value"].native,
            child["tbs_certificate"].dump(),
            child["signature_algorithm"],
        )
    except (InvalidSignature, UnsupportedAlgorithm, ValueError):
        return False
    return True


@dataclass
class Chain:
    certs: list[ax509.Certificate] = field(default_factory=list)
    anchor: ax509.Certificate | None = None
    error: str | None = None

    @property
    def complete(self) -> bool:
        return self.anchor is not None and self.error is None

    def names(self) -> list[str]:
        return [name(c) for c in self.certs]


def build_chain(leaf: ax509.Certificate, pool: list[ax509.Certificate],
                anchors: list[ax509.Certificate]) -> Chain:
    """Partial-chain build: any trust-store certificate terminates the path."""
    trusted = {fingerprint(a): a for a in anchors}
    chain = Chain(certs=[leaf])
    current = leaf
    if fingerprint(leaf) in trusted:
        chain.anchor = leaf
        return chain
    candidates = pool + anchors
    for _ in range(MAX_CHAIN):
        issuer = next((c for c in candidates if verify_issued_by(current, c)), None)
        if issuer is None:
            chain.error = f"no issuer found for {name(current)!r}"
            return chain
        chain.certs.append(issuer)
        if fingerprint(issuer) in trusted:
            chain.anchor = issuer
            return chain
        if issuer.subject == issuer.issuer:
            chain.error = f"reached untrusted self-signed root {name(issuer)!r}"
            return chain
        current = issuer
    chain.error = f"chain longer than {MAX_CHAIN} certificates"
    return chain


def validity_errors(chain: Chain, at: datetime) -> list[str]:
    errs = []
    for i, c in enumerate(chain.certs):
        tbs = c["tbs_certificate"]["validity"]
        nb, na = tbs["not_before"].native, tbs["not_after"].native
        if at < nb:
            errs.append(f"{name(c)!r} not valid until {nb.isoformat()}")
        elif at > na:
            errs.append(f"{name(c)!r} expired {na.isoformat()}")
        if i and not c.ca:
            errs.append(f"{name(c)!r} is not a CA certificate")
        if i and c.key_usage_value and "key_cert_sign" not in c.key_usage_value.native:
            errs.append(f"{name(c)!r} lacks keyCertSign")
    return errs
