from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from asn1crypto import cms as acms
from asn1crypto import x509 as ax509
from asn1crypto.core import VOID

from . import cades  # noqa: F401  (registers CAdES attribute specs)
from .crypto import InvalidSignature, digest, verify


class MalformedCMS(ValueError):
    pass


@dataclass
class SignedDataView:
    signed_data: acms.SignedData
    signer_info: acms.SignerInfo
    certificates: list[ax509.Certificate]
    signer_cert: ax509.Certificate

    @classmethod
    def load(cls, der: bytes) -> "SignedDataView":
        try:
            ci = acms.ContentInfo.load(der)
            if ci["content_type"].native != "signed_data":
                raise MalformedCMS(f"content type is {ci['content_type'].native!r}, not signed_data")
            sd = ci["content"]
            signers = sd["signer_infos"]
            if len(signers) != 1:
                raise MalformedCMS(f"{len(signers)} SignerInfos, expected exactly 1")
            certs = [c.chosen for c in sd["certificates"] if c.name == "certificate"] if sd["certificates"] else []
        except MalformedCMS:
            raise
        except Exception as e:
            raise MalformedCMS(f"cannot parse SignedData: {e}") from e
        si = signers[0]
        return cls(sd, si, certs, _find_signer(si, certs))

    @property
    def digest_algo(self) -> str:
        return self.signer_info["digest_algorithm"]["algorithm"].native

    @property
    def signature_algo(self) -> str:
        return self.signer_info["signature_algorithm"].signature_algo

    @property
    def econtent_type(self) -> str:
        return self.signed_data["encap_content_info"]["content_type"].native

    @property
    def econtent(self) -> bytes | None:
        c = self.signed_data["encap_content_info"]["content"]
        return None if c is VOID else c.native

    @property
    def signed_attrs(self) -> acms.CMSAttributes | None:
        a = self.signer_info["signed_attrs"]
        return None if a is VOID else a

    def attr(self, name: str) -> Any:
        if (attrs := self.signed_attrs) is None:
            return None
        for a in attrs:
            if a["type"].native == name:
                values = a["values"]
                return values[0] if len(values) else None
        return None

    def unsigned_attr(self, name: str) -> Any:
        a = self.signer_info["unsigned_attrs"]
        if a is VOID:
            return None
        for at in a:
            if at["type"].native == name:
                values = at["values"]
                return values[0] if len(values) else None
        return None

    def dtbs(self, content: bytes | None) -> bytes:
        """Bytes the signature is computed over."""
        if (attrs := self.signed_attrs) is not None:
            return attrs.untag().dump()
        body = self.econtent if content is None else content
        if body is None:
            raise MalformedCMS("detached signature with neither signed attributes nor content")
        return body

    def content_digest_matches(self, content: bytes | None) -> tuple[bool, bytes | None, bytes | None]:
        md = self.attr("message_digest")
        if md is None:
            return False, None, None
        expected = md.native
        body = self.econtent if content is None else content
        if body is None:
            return False, expected, None
        actual = digest(self.digest_algo, body)
        return actual == expected, expected, actual

    def verify_signature(self, content: bytes | None) -> None:
        verify(
            _cryptography_cert(self.signer_cert),
            self.signer_info["signature"].native,
            self.dtbs(content),
            self.signer_info["signature_algorithm"],
        )

    def signing_time(self) -> datetime | None:
        st = self.attr("signing_time")
        return st.native if st is not None else None

    def signing_cert_binding(self) -> tuple[bool | None, dict[str, Any]]:
        """ESS signingCertificate[V2]: does the attribute bind the signer cert?"""
        for name, default in (("signing_certificate_v2", "sha256"), ("signing_certificate", "sha1")):
            if (v := self.attr(name)) is None:
                continue
            certs = v["certs"]
            if not len(certs):
                return False, {"attribute": name, "reason": "no ESSCertID"}
            first = certs[0]
            algo = default
            if name == "signing_certificate_v2" and first["hash_algorithm"] is not VOID:
                algo = first["hash_algorithm"]["algorithm"].native
            want = first["cert_hash"].native
            got = digest(algo, self.signer_cert.dump())
            return got == want, {"attribute": name, "hash_algorithm": algo,
                                 "expected": want, "actual": got}
        return None, {}


def _find_signer(si: acms.SignerInfo, certs: list[ax509.Certificate]) -> ax509.Certificate:
    sid = si["sid"]
    if sid.name == "issuer_and_serial_number":
        issuer, serial = sid.chosen["issuer"], sid.chosen["serial_number"].native
        for c in certs:
            if c.issuer == issuer and c["tbs_certificate"]["serial_number"].native == serial:
                return c
    else:
        key_id = sid.chosen.native
        for c in certs:
            if c.key_identifier == key_id:
                return c
    raise MalformedCMS("signer certificate is not embedded in the CMS")


def _cryptography_cert(cert: ax509.Certificate):
    from cryptography.x509 import load_der_x509_certificate

    return load_der_x509_certificate(cert.dump())


__all__ = ["SignedDataView", "MalformedCMS", "InvalidSignature"]
