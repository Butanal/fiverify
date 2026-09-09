from datetime import datetime, timezone

import pytest

import fixtures
from fiverify import Status, verify_pdf
from fiverify.crypto import digest


def check(report, id):
    for sig in report.signatures:
        if c := sig.get(id):
            return c
    return next((c for c in report.checks if c.id == id), None)


def test_valid_document_only_lacks_revocation(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.INDETERMINATE
    assert [c.id for c in r.all_checks() if c.status is Status.INDETERMINATE] == ["revocation.status"]
    assert not r.failures()


def test_unsigned_pdf(trusted):
    r = verify_pdf(b"%PDF-1.7\n%%EOF\n", profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "pdf.signatures").sub_indication.value == "SIGNED_DATA_NOT_FOUND"


def test_corrupt_signature(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, corrupt_signature=True)
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "cms.signature").status is Status.FAILED


def test_content_tampered_after_signing(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    tampered = pdf.replace(b"fiverify test fixture", b"fiverify test FIXTURE")
    assert len(tampered) == len(pdf)
    r = verify_pdf(tampered, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "cms.message_digest").status is Status.FAILED
    assert check(r, "cms.signature").status is Status.PASSED  # the CMS itself is intact


def test_appended_revision_fails_coverage(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(fixtures.append_revision(pdf), profile=trusted)
    assert r.status is Status.FAILED
    cov = check(r, "pdf.coverage")
    assert cov.status is Status.FAILED and cov.evidence["trailing_is_revision"]
    assert check(r, "cms.signature").status is Status.PASSED


def test_non_zero_contents_padding(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, pad_byte=0x41)
    r = verify_pdf(pdf, profile=trusted)
    assert check(r, "pdf.contents_padding").status is Status.FAILED


def test_missing_timestamp_is_pades_b(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, timestamp=False)
    r = verify_pdf(pdf, profile=trusted)
    assert check(r, "tsp.present").status is Status.FAILED
    assert r.status is Status.INDETERMINATE
    assert verify_pdf(pdf, profile=trusted, strict=True).status is Status.FAILED


def test_timestamp_over_a_different_signature(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, tst_imprint=digest("sha256", b"some other signature"))
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "tsp.imprint").status is Status.FAILED


def test_wrong_signature_policy(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, policy_oid="1.2.3.4.5")
    r = verify_pdf(pdf, profile=trusted)
    assert check(r, "cms.signature_policy").status is Status.FAILED
    assert r.status is Status.INDETERMINATE


def test_missing_signing_certificate_binding(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, signing_cert_binding=False)
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "cms.signing_certificate_binding").status is Status.FAILED


def test_signing_time_must_be_epoch(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, signing_time=datetime(2026, 5, 1, tzinfo=timezone.utc))
    r = verify_pdf(pdf, profile=trusted)
    assert check(r, "cms.signing_time").status is Status.FAILED


def test_untrusted_anchor(pki, profile):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=profile)
    assert r.status is Status.FAILED
    assert check(r, "chain.built").sub_indication.value == "NO_CERTIFICATE_CHAIN_FOUND"


def test_poe_comes_from_the_timestamp_not_the_clock(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    later = verify_pdf(pdf, profile=trusted, at=datetime(2040, 1, 1, tzinfo=timezone.utc))
    assert check(later, "chain.validity_at_poe").status is Status.PASSED
    assert later.signatures[0].details["poe_source"] == "timestamp"


def test_without_a_timestamp_expiry_is_measured_against_the_clock(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, timestamp=False)
    r = verify_pdf(pdf, profile=trusted, at=datetime(2040, 1, 1, tzinfo=timezone.utc))
    assert r.status is Status.FAILED
    assert check(r, "chain.validity_at_poe").sub_indication.value == "EXPIRED"
    assert r.signatures[0].details["poe_source"] == "wall clock"


def test_certificate_expired_at_the_timestamp():
    pki = fixtures.make_pki(not_after=datetime(2026, 1, 1, tzinfo=timezone.utc))
    from fiverify.profile import Profile
    trusted = Profile.bundled().with_anchors(pki.anchors())
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "chain.validity_at_poe").status is Status.FAILED


@pytest.mark.parametrize("qc,failing", [
    ({"sscd": False}, "QcSSCD"),
    ({"compliant": False}, "QcCompliance"),
    ({"qc_type": "0.4.0.1862.1.6.1"}, "QcType"),
])
def test_qualified_statements(qc, failing):
    pki = fixtures.make_pki(qc=qc)
    from fiverify.profile import Profile
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=Profile.bundled().with_anchors(pki.anchors()))
    c = check(r, "signer.qualified")
    assert c.status is Status.FAILED and failing in c.summary


def test_tsa_eku_must_be_critical():
    pki = fixtures.make_pki(tsa_eku_critical=False)
    from fiverify.profile import Profile
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=Profile.bundled().with_anchors(pki.anchors()))
    assert check(r, "tsp.tsa_eku").status is Status.FAILED


def test_unexpected_subfilter(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, subfilter="adbe.pkcs7.detached")
    r = verify_pdf(pdf, profile=trusted)
    assert check(r, "pdf.subfilter").status is Status.FAILED


def test_report_is_json_serialisable(pki, trusted):
    import json
    pdf, _ = fixtures.signed_pdf(pki)
    d = verify_pdf(pdf, profile=trusted).to_dict()
    assert json.loads(json.dumps(d))["status"] == "indeterminate"


def test_naive_validation_time_is_treated_as_utc(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, timestamp=False)
    r = verify_pdf(pdf, profile=trusted, at=datetime(2040, 1, 1))
    assert check(r, "chain.validity_at_poe").status is Status.FAILED


def test_name_changed_in_place_breaks_the_digest(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, text="Nom: DUPONT Jean")
    forged = pdf.replace(b"Nom: DUPONT Jean", b"Nom: DURAND Paul")
    assert len(forged) == len(pdf)
    r = verify_pdf(forged, profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "cms.message_digest").sub_indication.value == "HASH_FAILURE"


def test_name_changed_by_incremental_update_breaks_only_coverage(pki, trusted):
    """How an editor actually forges: the seal still verifies over its own range."""
    pdf, _ = fixtures.signed_pdf(pki, text="Nom: DUPONT Jean")
    r = verify_pdf(fixtures.rewrite_page_text(pdf, "Nom: DURAND Paul"), profile=trusted)
    assert r.status is Status.FAILED
    assert check(r, "pdf.coverage").sub_indication.value == "FORMAT_FAILURE"
    assert check(r, "cms.signature").status is Status.PASSED
    assert check(r, "cms.message_digest").status is Status.PASSED


def test_observe_profile_reports_values_it_does_not_assert(pki):
    from fiverify.profile import Profile
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=Profile.bundled("observe").with_anchors(pki.anchors()))
    d = r.signatures[0].details
    assert d["signature_policy"] == fixtures.POLICY_OID
    assert d["commitment_type"] == "proofOfOrigin"
    assert d["tst_policy"] == fixtures.TSA_POLICY_OID
    assert not [c for c in r.all_checks() if c.id.endswith(("signature_policy", "commitment_type"))]
