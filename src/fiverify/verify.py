from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from asn1crypto import x509 as ax509

from . import attributes as attrs
from .cades import COMMITMENT_TYPES
from .cms import MalformedCMS, SignedDataView
from .crypto import InvalidSignature, UnsupportedAlgorithm
from .pdf import MalformedSignature, SignatureField, find_signatures
from .profile import Profile
from .report import Check, Report, Severity, SignatureReport, Status, SubIndication
from .revocation import GOOD, REVOKED, RevocationStore
from .tsp import TimestampToken
from .x509util import (
    build_chain,
    fingerprint,
    name,
    qc_statements,
    revocation_urls,
    validity_errors,
)

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def verify_pdf(data: bytes, *, profile: Profile | None = None,
               at: datetime | None = None, strict: bool = False,
               extra_anchors: list[ax509.Certificate] | None = None,
               revocation: RevocationStore | None = None,
               fetch_revocation: bool = False,
               accept_unchecked_revocation: bool = False,
               strict_revocation: bool = False,
               extract_attributes: bool = False) -> Report:
    profile = profile or Profile.bundled()
    if extra_anchors:
        profile = profile.with_anchors(extra_anchors)
    at = at or datetime.now(timezone.utc)
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    report = Report(
        profile=f"{profile.name}/{profile.version}",
        file_size=len(data),
        file_sha256=hashlib.sha256(data).hexdigest(),
        validated_at=at,
    )
    try:
        fields = find_signatures(data)
    except MalformedSignature as e:
        report.add(Check("pdf.structure", Status.FAILED, str(e),
                         sub_indication=SubIndication.FORMAT_FAILURE))
        return report
    if not fields:
        report.add(Check("pdf.signatures", Status.FAILED,
                         "no signature dictionary — this PDF is not signed",
                         sub_indication=SubIndication.SIGNED_DATA_NOT_FOUND))
        return report
    report.add(Check("pdf.signatures", Status.PASSED,
                     f"{len(fields)} signature field(s)", severity=Severity.INFO,
                     evidence={"count": len(fields)}))
    checkers = []
    for f in fields:
        checker = _SignatureChecker(profile, strict, at, accept_unchecked_revocation,
                                    revocation, strict_revocation)
        report.signatures.append(checker.run(data, f))
        checkers.append(checker)
    if fetch_revocation:
        revocation = _fetch(report, checkers, revocation)
    if not revocation:
        report.caveats.append("revocation status not checked")
    for checker in checkers:
        checker.revocation = revocation
        checker.finish()
        report.caveats.extend(c for c in checker.caveats if c not in report.caveats)
    if extract_attributes:
        _extract(report, data)
    return report


def _fetch(report: Report, checkers: list["_SignatureChecker"],
           store: RevocationStore | None) -> RevocationStore | None:
    """Download the CRLs named by certificates that reached a trust anchor.

    After the chains are built, not before: opening a distribution point on an
    unanchored certificate's say-so lets any PDF aim fiverify at a host it picks.
    """
    from .online import fetch_crls  # the only network path

    store = store or RevocationStore()
    certs = [c for ch in checkers for c in ch.anchored_certs()]
    if not certs:
        report.add(Check("revocation.fetch", Status.INDETERMINATE,
                         "nothing downloaded — no chain reached a trust anchor, and an "
                         "unanchored certificate's distribution point is not fetched",
                         severity=Severity.INFO,
                         evidence={"errors": [], "downloaded": 0}))
        return store
    before = len(store)
    store, errors = fetch_crls(certs, store=store)
    got = len(store) - before
    if not got and not errors:
        summary = "no CRL distribution point in the certificates — nothing to download"
    else:
        summary = (f"downloaded {got} CRL(s)"
                   + (f"; {len(errors)} download(s) failed" if errors else ""))
    report.add(Check("revocation.fetch",
                     Status.PASSED if got and not errors else Status.INDETERMINATE,
                     summary, severity=Severity.INFO,
                     evidence={"errors": errors, "downloaded": got}))
    return store


AUTHENTIC = ("pdf.coverage", "cms.message_digest", "cms.signature", "chain.built")
UNKNOWN_SUB = {"stale": SubIndication.TRY_LATER,
               "suspended": SubIndication.TRY_LATER,
               "no_crl": SubIndication.NO_REVOCATION_DATA}


def _authentic(sig: SignatureReport) -> bool:
    return all((c := sig.get(i)) is not None and c.status is Status.PASSED for i in AUTHENTIC)


def _extract(report: Report, data: bytes) -> None:
    """Attributes live in the PDF, so they are only meaningful if a signature
    covers the bytes they came from and reaches an anchor. Integrity alone is
    self-consistency: a forger signs their own work and it holds together."""
    if not any(_authentic(s) for s in report.signatures):
        report.add(Check("attributes.withheld", Status.SKIPPED,
                         "identity attributes not extracted — no signature both covers "
                         "these bytes and chains to a trust anchor",
                         severity=Severity.INFO))
        return
    report.attributes = attrs.extract(data)
    report.add(Check("attributes.extracted", Status.PASSED,
                     f"{len(report.attributes)} identity attribute(s) from signed bytes",
                     severity=Severity.INFO, evidence={"fields": sorted(report.attributes)}))


def verify_file(path, **kwargs) -> Report:
    with open(path, "rb") as fh:
        return verify_pdf(fh.read(), **kwargs)


class _SignatureChecker:
    def __init__(self, profile: Profile, strict: bool, at: datetime,
                 accept_unchecked_revocation: bool = False,
                 revocation: RevocationStore | None = None,
                 strict_revocation: bool = False):
        self.p = profile
        self.strict = strict
        self.at = at
        self.accept_unchecked_revocation = accept_unchecked_revocation
        self.revocation = revocation
        self.strict_revocation = strict_revocation
        self.chain = None
        self.tsa_chain = None
        self.view: SignedDataView | None = None
        self.caveats: list[str] = []
        self.rep: SignatureReport

    # -- helpers ------------------------------------------------------------
    def add(self, id: str, status: Status, summary: str, *,
            severity: Severity = Severity.CRITICAL,
            sub: SubIndication | None = None, **evidence) -> None:
        if severity is Severity.POLICY and self.strict:
            severity = Severity.CRITICAL
        self.rep.add(Check(id, status, summary, severity, sub, evidence))

    def ok(self, id: str, cond: bool, yes: str, no: str, **kw) -> bool:
        self.add(id, Status.PASSED if cond else Status.FAILED, yes if cond else no, **kw)
        return cond

    # -- entry point --------------------------------------------------------
    def run(self, data: bytes, f: SignatureField) -> SignatureReport:
        """Every stage but revocation, which finish() runs afterwards - leaving
        the caller room to fetch CRLs once the chain has reached an anchor."""
        self.rep = SignatureReport(index=f.index)
        self.rep.details.update(
            byte_range=list(f.byte_range),
            subfilter=f.entries.get("SubFilter"),
            filter=f.entries.get("Filter"),
            cms_bytes=len(f.cms_der),
            padding_bytes=len(f.padding),
        )
        self._pdf(data, f)
        try:
            view = SignedDataView.load(f.cms_der)
        except MalformedCMS as e:
            self.add("cms.structure", Status.FAILED, str(e), sub=SubIndication.FORMAT_FAILURE)
            return self.rep
        self.add("cms.structure", Status.PASSED,
                 f"SignedData, {view.digest_algo}/{view.signature_algo}", severity=Severity.INFO)
        self.view = view
        signed = f.signed_bytes(data)
        self._cms(view, signed)
        token = self._timestamp(view)
        self._chain(view, token)
        self._qualified(view)
        return self.rep

    def finish(self) -> None:
        if self.view is not None:
            self._revocation(self.view)

    def anchored_certs(self) -> list[ax509.Certificate]:
        """The only certificates whose distribution points this will open."""
        return [c for chain in (self.chain, self.tsa_chain)
                if chain is not None and chain.complete
                for c in chain.certs]

    # -- stages -------------------------------------------------------------
    def _pdf(self, data: bytes, f: SignatureField) -> None:
        cov = f.coverage
        allowed = self.p.document.get("allowed_subfilters", [])
        sub = f.entries.get("SubFilter")
        if allowed:
            self.ok("pdf.subfilter", sub in allowed,
                    f"SubFilter {sub}", f"SubFilter {sub!r} is not one of {allowed}",
                    severity=Severity.POLICY, value=sub, allowed=allowed)
        self.ok("pdf.byterange", cov.starts_at_zero and cov.contents_in_gap,
                "/ByteRange covers from byte 0 and brackets /Contents exactly",
                "/ByteRange is malformed: "
                + ", ".join(x for x in [
                    None if cov.starts_at_zero else "does not start at byte 0",
                    None if cov.contents_in_gap else "/Contents does not fill the gap"] if x),
                sub=SubIndication.FORMAT_FAILURE,
                byte_range=list(f.byte_range), contents_span=list(f.contents_span))
        require_full = self.p.document.get("require_full_coverage", True)
        if cov.trailing_bytes:
            self.add("pdf.coverage", Status.FAILED if require_full else Status.INDETERMINATE,
                     f"{cov.trailing_bytes} byte(s) after the signed range"
                     + (f" containing a further revision ({cov.revisions_after} %%EOF)"
                        if cov.trailing_is_revision else " (not a PDF revision)"),
                     sub=SubIndication.FORMAT_FAILURE,
                     trailing_bytes=cov.trailing_bytes,
                     trailing_is_revision=cov.trailing_is_revision,
                     revisions_after=cov.revisions_after)
        else:
            self.add("pdf.coverage", Status.PASSED,
                     "signature covers the whole file except its own /Contents hole",
                     revisions_total=cov.revisions_total)
        if f.padding:
            self.add("pdf.contents_padding",
                     Status.PASSED if not any(f.padding) else Status.FAILED,
                     f"{len(f.padding)} byte(s) of /Contents padding"
                     + ("" if not any(f.padding) else " — NOT all zero"),
                     severity=Severity.POLICY, sub=SubIndication.FORMAT_FAILURE,
                     length=len(f.padding))

    def _cms(self, view: SignedDataView, signed: bytes) -> None:
        self.rep.details.update(
            signer=name(view.signer_cert),
            signer_issuer=view.signer_cert.issuer.native.get("common_name"),
            signer_serial=hex(view.signer_cert["tbs_certificate"]["serial_number"].native),
            signer_sha256=fingerprint(view.signer_cert),
            digest_algorithm=view.digest_algo,
            signature_algorithm=view.signature_algo,
            key_bits=view.signer_cert.public_key.bit_size,
        )
        ct = view.attr("content_type")
        self.ok("cms.content_type", ct is not None and ct.native == view.econtent_type,
                f"contentType attribute matches eContentType ({view.econtent_type})",
                "contentType attribute is absent or disagrees with eContentType",
                sub=SubIndication.FORMAT_FAILURE)

        match, expected, actual = view.content_digest_matches(signed)
        self.ok("cms.message_digest", match,
                f"messageDigest matches the {len(signed)} signed bytes",
                "messageDigest does not match the signed bytes",
                sub=SubIndication.HASH_FAILURE, expected=expected, actual=actual)

        try:
            view.verify_signature(signed)
            self.add("cms.signature", Status.PASSED, "signature is cryptographically valid")
        except InvalidSignature:
            self.add("cms.signature", Status.FAILED, "signature does not verify",
                     sub=SubIndication.SIG_CRYPTO_FAILURE)
        except UnsupportedAlgorithm as e:
            self.add("cms.signature", Status.INDETERMINATE, str(e),
                     sub=SubIndication.CRYPTO_CONSTRAINTS_FAILURE)

        self._algorithms(view)

        bound, ev = view.signing_cert_binding()
        if bound is None:
            self.add("cms.signing_certificate_binding",
                     Status.FAILED if self.p.signature.get("require_signing_certificate_binding") else Status.SKIPPED,
                     "no ESS signingCertificate attribute binding the signer certificate",
                     sub=SubIndication.SIG_CONSTRAINTS_FAILURE)
        else:
            self.ok("cms.signing_certificate_binding", bound,
                    f"{ev['attribute']} binds the signer certificate",
                    f"{ev['attribute']} refers to a different certificate",
                    sub=SubIndication.SIG_CONSTRAINTS_FAILURE, **ev)

        self._signing_time(view)
        self._policy_attrs(view)

    def _algorithms(self, view: SignedDataView) -> None:
        c = self.p.crypto
        bad = []
        if (d := c.get("digest_algorithms")) and view.digest_algo not in d:
            bad.append(f"digest {view.digest_algo}")
        if (s := c.get("signature_algorithms")) and view.signature_algo not in s:
            bad.append(f"signature algorithm {view.signature_algo}")
        bits = view.signer_cert.public_key.bit_size
        floor = c.get("min_rsa_bits" if view.signature_algo.startswith("rsa") else "min_ec_bits")
        if floor and bits < floor:
            bad.append(f"{bits}-bit key below the {floor}-bit floor")
        self.ok("cms.algorithms", not bad,
                f"{view.digest_algo} / {view.signature_algo} / {bits}-bit key",
                "outside the profile's algorithm policy: " + ", ".join(bad),
                severity=Severity.POLICY, sub=SubIndication.CRYPTO_CONSTRAINTS_FAILURE)

    def _signing_time(self, view: SignedDataView) -> None:
        st = view.signing_time()
        mode = self.p.signature.get("signing_time", "any")
        self.rep.details["signing_time"] = st
        if mode == "epoch":
            self.ok("cms.signing_time", st == EPOCH,
                    "signingTime is the Unix epoch, as the signature policy requires "
                    "(only the timestamp is authoritative)",
                    f"signingTime is {st.isoformat() if st else 'absent'}, expected the Unix epoch",
                    severity=Severity.POLICY, sub=SubIndication.SIG_CONSTRAINTS_FAILURE, value=st)
        elif mode == "required":
            self.ok("cms.signing_time", st is not None, f"signingTime {st}", "signingTime is absent",
                    severity=Severity.POLICY, sub=SubIndication.SIG_CONSTRAINTS_FAILURE)

    def _policy_attrs(self, view: SignedDataView) -> None:
        attr = view.attr("signature_policy_identifier")
        got = (attr.chosen["sig_policy_id"].dotted
               if attr is not None and attr.name == "signature_policy_id" else None)
        self.rep.details["signature_policy"] = got
        if want := self.p.signature.get("signature_policy_oid"):
            self.ok("cms.signature_policy", got == want,
                    f"signature policy {got}",
                    f"signature policy is {got or 'absent'}, expected {want}",
                    severity=Severity.POLICY, sub=SubIndication.POLICY_PROCESSING_ERROR,
                    expected=want, actual=got)
        attr = view.attr("commitment_type_indication")
        got = attr["commitment_type_id"].dotted if attr is not None else None
        self.rep.details["commitment_type"] = COMMITMENT_TYPES.get(got, got)
        if want_ct := self.p.signature.get("commitment_type_oid"):
            self.ok("cms.commitment_type", got == want_ct,
                    f"commitment type {COMMITMENT_TYPES.get(got, got)}",
                    f"commitment type is {got or 'absent'}, expected {want_ct}",
                    severity=Severity.POLICY, sub=SubIndication.POLICY_PROCESSING_ERROR)

    def _timestamp(self, view: SignedDataView) -> TimestampToken | None:
        raw = view.unsigned_attr("signature_time_stamp_token")
        required = self.p.timestamp.get("required", True)
        if raw is None:
            self.add("tsp.present", Status.FAILED if required else Status.SKIPPED,
                     "no signature timestamp — this is PAdES-B, not PAdES-T",
                     severity=Severity.POLICY, sub=SubIndication.NO_POE)
            return None
        try:
            token = TimestampToken.load(raw.dump())
        except MalformedCMS as e:
            self.add("tsp.present", Status.FAILED, f"timestamp token is malformed: {e}",
                     sub=SubIndication.FORMAT_FAILURE)
            return None
        self.add("tsp.present", Status.PASSED, "signature timestamp present", severity=Severity.INFO)
        self.rep.details.update(
            tsa=name(token.tsa_cert),
            gen_time=token.gen_time,
            tsa_accuracy_seconds=token.accuracy.total_seconds(),
            tst_policy=token.policy,
            tst_serial=hex(token.serial),
        )
        bound = self.ok("tsp.imprint", token.binds(view.signer_info["signature"].native),
                        f"timestamp imprint ({token.imprint_algo}) is over this exact signature",
                        "timestamp imprint does not match this signature",
                        sub=SubIndication.HASH_FAILURE, algorithm=token.imprint_algo)
        digest_ok, _, _ = token.content_digest_matches()
        self.ok("tsp.message_digest", digest_ok,
                "TSTInfo digest matches the token's signed attributes",
                "TSTInfo digest does not match the token's signed attributes",
                sub=SubIndication.HASH_FAILURE)
        try:
            token.verify_signature()
            self.add("tsp.signature", Status.PASSED,
                     f"timestamp token signature is valid ({name(token.tsa_cert)})")
            valid = True
        except InvalidSignature:
            self.add("tsp.signature", Status.FAILED, "timestamp token signature does not verify",
                     sub=SubIndication.SIG_CRYPTO_FAILURE)
            valid = False
        except UnsupportedAlgorithm as e:
            self.add("tsp.signature", Status.INDETERMINATE, str(e),
                     sub=SubIndication.CRYPTO_CONSTRAINTS_FAILURE)
            valid = False

        has_eku, critical, ekus = token.tsa_eku()
        need_crit = self.p.timestamp.get("require_critical_eku", True)
        self.ok("tsp.tsa_eku", has_eku and (critical or not need_crit),
                "TSA certificate carries a critical id-kp-timeStamping EKU",
                f"TSA EKU is {ekus or 'absent'}, critical={critical}",
                severity=Severity.POLICY, sub=SubIndication.CHAIN_CONSTRAINTS_FAILURE)
        if want := self.p.timestamp.get("policy_oid"):
            self.ok("tsp.policy", token.policy == want, f"TSA policy {token.policy}",
                    f"TSA policy is {token.policy}, expected {want}",
                    severity=Severity.POLICY, sub=SubIndication.POLICY_PROCESSING_ERROR)
        if (cap := self.p.timestamp.get("max_accuracy_seconds")) is not None:
            acc = token.accuracy.total_seconds()
            self.ok("tsp.accuracy", acc <= cap, f"stated accuracy {acc}s",
                    f"stated accuracy {acc}s exceeds the {cap}s the profile allows",
                    severity=Severity.POLICY, sub=SubIndication.POLICY_PROCESSING_ERROR)
        return token if (bound and valid) else None

    def _chain(self, view: SignedDataView, token: TimestampToken | None) -> None:
        trusted_time = self._tsa_chain(token)
        poe = token.gen_time if trusted_time else self.at
        self.rep.details["poe"] = poe
        self.rep.details["poe_source"] = "timestamp" if trusted_time else "wall clock"
        if token is not None and not trusted_time:
            self.caveats.append("timestamp not used as proof of existence — its TSA is "
                                "not trusted, so expiry and revocation are measured "
                                "against the clock")
        pool = list(view.certificates)
        chain = build_chain(view.signer_cert, pool, self.p.anchors)
        self.chain = chain
        self.rep.details["chain"] = chain.names()
        self.ok("chain.built", chain.complete,
                "chain reaches the trust anchor " + (name(chain.anchor) if chain.anchor else ""),
                f"no trusted chain: {chain.error}",
                sub=SubIndication.NO_CERTIFICATE_CHAIN_FOUND, chain=chain.names())
        if chain.complete:
            errs = validity_errors(chain, poe)
            self.ok("chain.validity_at_poe", not errs,
                    f"every certificate was valid at {poe.isoformat()}",
                    "; ".join(errs), sub=SubIndication.EXPIRED, poe=poe)

    def _tsa_chain(self, token: TimestampToken | None) -> bool:
        """Whether this timestamp may stand as proof of existence.

        genTime is a claim until the TSA that made it reaches an anchor; taken on
        trust it back-dates a signature past its certificate's expiry or revocation.
        """
        if token is None:
            return False
        chain = build_chain(token.tsa_cert, list(token.view.certificates), self.p.anchors)
        self.tsa_chain = chain
        self.rep.details["tsa_chain"] = chain.names()
        self.ok("tsp.chain", chain.complete,
                "TSA chain reaches the trust anchor",
                f"TSA has no trusted chain: {chain.error}",
                severity=Severity.POLICY, sub=SubIndication.NO_CERTIFICATE_CHAIN_FOUND)
        if not chain.complete:
            return False
        errs = validity_errors(chain, token.gen_time)
        self.ok("tsp.validity", not errs,
                f"TSA certificate was valid at {token.gen_time.isoformat()}",
                "; ".join(errs), severity=Severity.POLICY, sub=SubIndication.EXPIRED)
        return not errs

    def _revocation(self, view: SignedDataView) -> None:
        urls = revocation_urls(view.signer_cert)
        self.rep.details["revocation_urls"] = urls
        if self.revocation and self.chain and self.chain.complete:
            self._check_crls()
            return
        if self.revocation:
            self.add("revocation.status", Status.INDETERMINATE,
                     "cannot check revocation without a trusted chain",
                     severity=Severity.POLICY, sub=SubIndication.NO_REVOCATION_DATA, **urls)
        elif self.accept_unchecked_revocation:
            self.add("revocation.status", Status.SKIPPED,
                     "not checked — caller accepted the unchecked revocation status",
                     severity=Severity.INFO, **urls)
        else:
            self.add("revocation.status", Status.INDETERMINATE,
                     "not checked — no usable revocation data; supply CRLs (--crl / "
                     "RevocationStore), fetch them, or accept the gap with "
                     "accept_unchecked_revocation=True",
                     severity=Severity.POLICY, sub=SubIndication.NO_REVOCATION_DATA, **urls)

    def _check_crls(self) -> None:
        poe = self.rep.details["poe"]
        certs = self.chain.certs
        unknown = []
        for i, cert in enumerate(certs[:-1]):
            r = self.revocation.status(cert, certs[i + 1], poe, strict=self.strict_revocation)
            cid = "revocation.signer" if i == 0 else f"revocation.ca{i}"
            if r.state == REVOKED:
                self.add(cid, Status.FAILED, f"{name(cert)}: {r.summary}",
                         sub=SubIndication.CHAIN_CONSTRAINTS_FAILURE, **r.evidence)
            elif r.state == GOOD:
                self.add(cid, Status.PASSED, f"{name(cert)}: {r.summary}", **r.evidence)
            else:
                unknown.append(cid)
                self.add(cid, Status.INDETERMINATE, f"{name(cert)}: {r.summary}",
                         severity=Severity.POLICY,
                         sub=UNKNOWN_SUB.get(r.code, SubIndication.NO_REVOCATION_DATA),
                         **r.evidence)
        if unknown:
            self.caveats.append("revocation status unknown for " + ", ".join(unknown))

    def _qualified(self, view: SignedDataView) -> None:
        q = self.p.qualified
        qc = qc_statements(view.signer_cert)
        self.rep.details["qc_statements"] = qc
        problems = []
        if q.get("require_qc_compliance") and not qc.get("compliant"):
            problems.append("no QcCompliance statement (not an EU-qualified certificate)")
        if q.get("require_qc_sscd") and not qc.get("sscd"):
            problems.append("no QcSSCD statement (key not declared in a QSCD)")
        if (want := q.get("qc_type")) and want not in (qc.get("types") or []):
            problems.append(f"QcType is {qc.get('types')}, expected {want}")
        self.ok("signer.qualified", not problems,
                f"qualified electronic seal ({', '.join(qc.get('types') or [])}, key in a QSCD)",
                "; ".join(problems), severity=Severity.POLICY,
                sub=SubIndication.CHAIN_CONSTRAINTS_FAILURE, **qc)
        if want_ku := q.get("key_usage"):
            ku = set(view.signer_cert.key_usage_value.native) if view.signer_cert.key_usage_value else set()
            self.ok("signer.key_usage", set(want_ku) <= ku,
                    f"key usage {sorted(ku)}",
                    f"key usage {sorted(ku)} lacks {sorted(set(want_ku) - ku)}",
                    severity=Severity.POLICY, sub=SubIndication.CHAIN_CONSTRAINTS_FAILURE)
