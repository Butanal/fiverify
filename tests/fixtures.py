"""Build signed PDFs with a throwaway PKI. No openssl; every attribute is ours."""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone

from asn1crypto import algos, cms, core, tsp
from asn1crypto import x509 as ax509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID, NameOID

from fiverify.cades import (
    SetOfCommitmentTypeIndication,
    SetOfSignaturePolicyIdentifier,
    SignaturePolicyIdentifier,
)
from fiverify.crypto import digest
from fiverify.x509util import QCStatement, QCStatements, QcTypes

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
POLICY_OID = "1.2.250.1.152.202.1.1.1"
COMMITMENT_OID = "1.2.840.113549.1.9.16.6.1"
TSA_POLICY_OID = "1.2.250.1.152.6.1.3.1"
QC_EXT_OID = cx509.ObjectIdentifier("1.3.6.1.5.5.7.1.3")
CRL_URLS = ["http://crl.example.test/test.crl", "http://crl2.example.test/test.crl"]
OCSP_URL = "http://ocsp.example.test"
PLACEHOLDER = 20000  # hex chars reserved for /Contents


def _name(cn: str) -> cx509.Name:
    return cx509.Name([
        cx509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        cx509.NameAttribute(NameOID.ORGANIZATION_NAME, "FIVERIFY TEST - NOT A REAL CA"),
        cx509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _qc_extension(*, compliant=True, sscd=True, qc_type="0.4.0.1862.1.6.2") -> bytes:
    stmts = []
    if compliant:
        stmts.append(QCStatement({"statement_id": "0.4.0.1862.1.1"}))
    if sscd:
        stmts.append(QCStatement({"statement_id": "0.4.0.1862.1.4"}))
    if qc_type:
        stmts.append(QCStatement({
            "statement_id": "0.4.0.1862.1.6",
            "statement_info": core.Any(QcTypes([qc_type])),
        }))
    return QCStatements(stmts).dump()


@dataclass
class PKI:
    ca_key: rsa.RSAPrivateKey
    ca_cert: cx509.Certificate
    signer_key: rsa.RSAPrivateKey
    signer_cert: cx509.Certificate
    tsa_key: rsa.RSAPrivateKey
    tsa_cert: cx509.Certificate

    def asn1(self, cert: cx509.Certificate) -> ax509.Certificate:
        return ax509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))

    def anchors(self) -> list[ax509.Certificate]:
        return [self.asn1(self.ca_cert)]


def make_pki(*, not_before: datetime | None = None, not_after: datetime | None = None,
             qc: dict | None = None, tsa_eku_critical: bool = True,
             key_bits: int = 2048) -> PKI:
    nb = not_before or datetime(2025, 1, 1, tzinfo=timezone.utc)
    na = not_after or datetime(2030, 1, 1, tzinfo=timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    ca_cert = (
        cx509.CertificateBuilder()
        .subject_name(_name("TEST CACHET CA"))
        .issuer_name(_name("TEST CACHET CA"))
        .public_key(ca_key.public_key())
        .serial_number(cx509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(cx509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def issue(cn, key, *, eku=None, eku_critical=False, ku=None, extra=None, nb_=nb, na_=na):
        b = (cx509.CertificateBuilder()
             .subject_name(_name(cn)).issuer_name(ca_cert.subject)
             .public_key(key.public_key()).serial_number(cx509.random_serial_number())
             .not_valid_before(nb_).not_valid_after(na_)
             .add_extension(cx509.BasicConstraints(ca=False, path_length=None), critical=True))
        if ku:
            b = b.add_extension(ku, critical=True)
        if eku:
            b = b.add_extension(cx509.ExtendedKeyUsage(eku), critical=eku_critical)
        for ext, crit in extra or []:
            b = b.add_extension(ext, critical=crit)
        return b.sign(ca_key, hashes.SHA256())

    qc = {} if qc is None else qc
    signer_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    signer_cert = issue(
        "TEST SIGNATURE CACHET", signer_key,
        ku=cx509.KeyUsage(True, True, False, False, False, False, False, False, False),
        extra=[(cx509.UnrecognizedExtension(QC_EXT_OID, _qc_extension(**qc)), False),
               (cx509.CRLDistributionPoints([cx509.DistributionPoint(
                   full_name=[cx509.UniformResourceIdentifier(u) for u in CRL_URLS],
                   relative_name=None, crl_issuer=None, reasons=None)]), False),
               (cx509.AuthorityInformationAccess([cx509.AccessDescription(
                   AuthorityInformationAccessOID.OCSP,
                   cx509.UniformResourceIdentifier(OCSP_URL))]), False)],
        nb_=not_before or nb, na_=not_after or na,
    )
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
    tsa_cert = issue("TEST HORODATAGE", tsa_key,
                     ku=cx509.KeyUsage(True, False, False, False, False, False, False, False, False),
                     eku=[ExtendedKeyUsageOID.TIME_STAMPING], eku_critical=tsa_eku_critical)
    return PKI(ca_key, ca_cert, signer_key, signer_cert, tsa_key, tsa_cert)


def _sign(key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def _ess_cert_v2(cert: cx509.Certificate) -> tsp.SigningCertificateV2:
    der = cert.public_bytes(serialization.Encoding.DER)
    return tsp.SigningCertificateV2({
        "certs": [tsp.ESSCertIDv2({"cert_hash": digest("sha256", der)})],
    })


def build_tst(pki: PKI, imprint: bytes, *, gen_time: datetime | None = None,
              policy_oid: str = TSA_POLICY_OID, accuracy_seconds: int = 1,
              serial: int = 0x1234, nonce: int = 0xABCD,
              imprint_algo: str = "sha256") -> bytes:
    info = tsp.TSTInfo({
        "version": "v1",
        "policy": policy_oid,
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": imprint_algo}),
            "hashed_message": imprint,
        }),
        "serial_number": serial,
        "gen_time": gen_time or datetime(2026, 9, 9, 18, 27, 23, tzinfo=timezone.utc),
        "accuracy": tsp.Accuracy({"seconds": accuracy_seconds}),
        "nonce": nonce,
    })
    body = info.dump()
    attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [digest("sha256", body)]}),
        cms.CMSAttribute({"type": "signing_certificate_v2",
                          "values": [_ess_cert_v2(pki.tsa_cert)]}),
    ])
    return _content_info(
        econtent_type="tst_info", econtent=core.ParsableOctetString(body),
        certs=[pki.tsa_cert], signer=pki.tsa_cert, attrs=attrs,
        signature=_sign(pki.tsa_key, attrs.dump()), version="v3",
    )


def _content_info(*, econtent_type, econtent, certs, signer, attrs, signature,
                  version="v1", unsigned=None) -> bytes:
    sd = cms.SignedData({
        "version": version,
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": ({"content_type": econtent_type} if econtent is None
                               else {"content_type": econtent_type, "content": econtent}),
        "certificates": [cms.CertificateChoices(
            "certificate", ax509.Certificate.load(c.public_bytes(serialization.Encoding.DER)))
            for c in certs],
        "signer_infos": [cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
                "issuer": ax509.Certificate.load(
                    signer.public_bytes(serialization.Encoding.DER)).issuer,
                "serial_number": signer.serial_number,
            })}),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}),
            "signature": signature,
            **({"unsigned_attrs": unsigned} if unsigned else {}),
        })],
    })
    return cms.ContentInfo({"content_type": "signed_data", "content": sd}).dump()


def build_cms(pki: PKI, signed_bytes: bytes, *, signing_time: datetime | None = EPOCH,
              policy_oid: str | None = POLICY_OID, commitment_oid: str | None = COMMITMENT_OID,
              signing_cert_binding: bool = True, timestamp: bool = True,
              tst_imprint: bytes | None = None, tst_kwargs: dict | None = None,
              corrupt_signature: bool = False) -> bytes:
    items = [
        cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
        cms.CMSAttribute({"type": "message_digest",
                          "values": [digest("sha256", signed_bytes)]}),
    ]
    if signing_time is not None:
        items.append(cms.CMSAttribute({"type": "signing_time",
                                       "values": [cms.Time({"utc_time": signing_time})]}))
    if signing_cert_binding:
        items.append(cms.CMSAttribute({"type": "signing_certificate_v2",
                                       "values": [_ess_cert_v2(pki.signer_cert)]}))
    if policy_oid:
        items.append(cms.CMSAttribute({
            "type": "signature_policy_identifier",
            "values": SetOfSignaturePolicyIdentifier([
                SignaturePolicyIdentifier(name="signature_policy_id", value={
                    "sig_policy_id": policy_oid,
                    "sig_policy_hash": {
                        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                        "hash_value": digest("sha256", b"policy document"),
                    },
                })]),
        }))
    if commitment_oid:
        items.append(cms.CMSAttribute({
            "type": "commitment_type_indication",
            "values": SetOfCommitmentTypeIndication([{"commitment_type_id": commitment_oid}]),
        }))
    attrs = cms.CMSAttributes(items)
    signature = _sign(pki.signer_key, attrs.dump())
    if corrupt_signature:
        signature = signature[:-1] + bytes([signature[-1] ^ 0xFF])

    unsigned = None
    if timestamp:
        token = build_tst(pki, tst_imprint or digest("sha256", signature), **(tst_kwargs or {}))
        unsigned = cms.CMSAttributes([cms.CMSAttribute({
            "type": "signature_time_stamp_token",
            "values": [cms.ContentInfo.load(token)],
        })])
    return _content_info(econtent_type="data", econtent=None, certs=[pki.signer_cert],
                         signer=pki.signer_cert, attrs=attrs, signature=signature,
                         unsigned=unsigned)


def _pdf_string(v: str) -> bytes:
    try:
        raw = v.encode("ascii")
    except UnicodeEncodeError:
        return b"<" + (b"\xfe\xff" + v.encode("utf-16-be")).hex().upper().encode() + b">"
    return b"(" + raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def _attr_object(attrs: dict) -> bytes:
    body = b" ".join(b"/" + k.encode() + b" " + _pdf_string(v) for k, v in attrs.items())
    comp = zlib.compress(body)
    return (b"<< /Type /FIAttributes /Filter /FlateDecode /Length "
            + str(len(comp)).encode() + b" >>\nstream\n" + comp + b"\nendstream")


def _skeleton(subfilter: str = "ETSI.CAdES.detached",
              text: str = "fiverify test fixture",
              attributes: dict | None = None) -> bytearray:
    content = b"BT /F1 13 Tf 60 760 Td (" + text.encode("latin-1") + b") Tj ET\n"
    objs = {
        1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [7 0 R] /SigFlags 3 >> >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 6 0 R >> >> /Contents 4 0 R /Annots [7 0 R] >>",
        4: b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"endstream",
        5: (b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /" + subfilter.encode()
            + b" /Name (FIVERIFY TEST) /Reason (fixture) /M (D:20260909182723Z)"
            b" /ByteRange [0 0000000000 0000000000 0000000000] /Contents <"
            + b"0" * PLACEHOLDER + b"> >>"),
        6: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        7: b"<< /Type /Annot /Subtype /Widget /FT /Sig /Rect [0 0 0 0] /T (Signature1) /V 5 0 R /P 3 0 R /F 4 >>",
    }
    if attributes:
        objs[8] = _attr_object(attributes)
    buf = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offs = {}
    for num in sorted(objs):
        offs[num] = len(buf)
        buf += f"{num} 0 obj\n".encode() + objs[num] + b"\nendobj\n"
    xref = len(buf)
    buf += f"xref\n0 {len(objs)+1}\n".encode() + b"0000000000 65535 f \n"
    for num in sorted(objs):
        buf += f"{offs[num]:010d} 00000 n \n".encode()
    buf += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return buf


def signed_pdf(pki: PKI | None = None, *, subfilter: str = "ETSI.CAdES.detached",
               text: str = "fiverify test fixture", attributes: dict | None = None,
               byte_range_shift: int = 0, pad_byte: int = 0,
               **cms_kwargs) -> tuple[bytes, PKI]:
    pki = pki or make_pki()
    buf = _skeleton(subfilter, text, attributes)
    ci = buf.index(b"<" + b"0" * PLACEHOLDER)
    cj = ci + PLACEHOLDER + 2
    a, b, c, d = 0, ci + byte_range_shift, cj, len(buf) - cj
    old = re.search(rb"/ByteRange \[0 0000000000 0000000000 0000000000\]", bytes(buf))
    buf[old.start():old.end()] = f"/ByteRange [{a} {b:010d} {c:010d} {d:010d}]".encode()

    der = build_cms(pki, bytes(buf[a:a + b]) + bytes(buf[c:c + d]), **cms_kwargs)
    hexed = der.hex().upper().encode()
    if len(hexed) > PLACEHOLDER:
        raise AssertionError(f"CMS needs {len(hexed)} hex chars, placeholder is {PLACEHOLDER}")
    buf[ci + 1:ci + 1 + len(hexed)] = hexed
    if pad_byte:
        buf[ci + 1 + len(hexed):cj - 1] = bytes([pad_byte]) * (PLACEHOLDER - len(hexed))
    return bytes(buf), pki


def append_revision(pdf: bytes) -> bytes:
    return pdf + b"\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\ntrailer\n<< >>\n%%EOF\n"


def rewrite_page_text(pdf: bytes, text: str) -> bytes:
    """Forge by incremental update, the way a PDF editor saves: object 4 is
    redefined in a revision appended after the signed range."""
    prev = int(re.search(rb"startxref\s+(\d+)", pdf).group(1))
    body = b"BT /F1 13 Tf 60 760 Td (" + text.encode("latin-1") + b") Tj ET\n"
    obj = (b"4 0 obj\n<< /Length " + str(len(body)).encode() + b" >>\nstream\n"
           + body + b"endstream\nendobj\n")
    out = bytearray(pdf)
    if not out.endswith(b"\n"):
        out += b"\n"
    off = len(out)
    out += obj
    xref = len(out)
    out += (b"xref\n0 1\n0000000000 65535 f \n4 1\n"
            + f"{off:010d} 00000 n \n".encode()
            + f"trailer\n<< /Size 8 /Root 1 0 R /Prev {prev} >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(out)


def make_crl(pki: PKI, *, revoked=(), this_update: datetime | None = None,
             next_update: datetime | None = None, wrong_key: bool = False) -> bytes:
    """revoked: (serial, revocation_date, reason|None) triples."""
    b = (cx509.CertificateRevocationListBuilder()
         .issuer_name(pki.ca_cert.subject)
         .last_update(this_update or datetime(2026, 9, 10, tzinfo=timezone.utc))
         .next_update(next_update or datetime(2026, 10, 10, tzinfo=timezone.utc)))
    for serial, when, reason in revoked:
        rc = (cx509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when))
        if reason:
            rc = rc.add_extension(cx509.CRLReason(reason), False)
        b = b.add_revoked_certificate(rc.build())
    key = pki.signer_key if wrong_key else pki.ca_key
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


ATTRIBUTES = {
    "id": "FI-2026-000123",
    "recipient": "Service test",
    "familyName": "O'BRIEN (n\u00e9e SMITH)",
    "givenName": "Jean-\u00c9tienne",
    "gender": "M",
    "nationality": "FRA",
    "birthdate": "1981-04-17",
    "birthplace": "PARIS (75)",
    "todayDate": "2026-09-09",
    "validityDate": "2027-09-09",
    "reason": "justificatif d'identit\u00e9",
}
