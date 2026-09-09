from datetime import datetime, timezone

import pytest
from cryptography.x509 import ReasonFlags

import fixtures
from fiverify import Status, verify_pdf
from fiverify.revocation import RevocationStore
from test_verify import check

GEN = datetime(2026, 9, 9, 18, 27, 23, tzinfo=timezone.utc)
BEFORE = datetime(2026, 9, 1, tzinfo=timezone.utc)
AFTER = datetime(2026, 9, 20, tzinfo=timezone.utc)


def store(crl_der: bytes) -> RevocationStore:
    s = RevocationStore()
    s.add(crl_der)
    return s


def run(pki, trusted, crl_der, **kw):
    pdf, _ = fixtures.signed_pdf(pki)
    return verify_pdf(pdf, profile=trusted, revocation=store(crl_der), **kw)


def test_not_listed_on_a_fresh_crl_is_good(pki, trusted):
    r = run(pki, trusted, fixtures.make_crl(pki))
    assert r.status is Status.PASSED
    assert check(r, "revocation.signer").status is Status.PASSED
    assert r.caveats == []


def test_revoked_before_the_timestamp_fails(pki, trusted):
    crl = fixtures.make_crl(pki, revoked=[(pki.signer_cert.serial_number, BEFORE,
                                           ReasonFlags.key_compromise)])
    r = run(pki, trusted, crl)
    assert r.status is Status.FAILED
    c = check(r, "revocation.signer")
    assert c.status is Status.FAILED and c.evidence["reason"] == "key_compromise"


def test_revoked_after_the_timestamp_is_still_good(pki, trusted):
    """The seal was made while the certificate was valid; the timestamp proves it."""
    crl = fixtures.make_crl(pki, revoked=[(pki.signer_cert.serial_number, AFTER, None)])
    r = run(pki, trusted, crl)
    assert check(r, "revocation.signer").status is Status.PASSED
    assert r.status is Status.PASSED


def test_certificate_hold_is_indeterminate(pki, trusted):
    crl = fixtures.make_crl(pki, revoked=[(pki.signer_cert.serial_number, BEFORE,
                                           ReasonFlags.certificate_hold)])
    r = run(pki, trusted, crl)
    assert check(r, "revocation.signer").status is Status.INDETERMINATE
    assert r.status is Status.INDETERMINATE


def test_crl_in_force_over_the_timestamp_is_accepted(pki, trusted):
    """Issued before the seal but still in force over it: the CA asserts this CRL
    is authoritative until nextUpdate, so absence from it answers the question."""
    crl = fixtures.make_crl(pki, this_update=BEFORE, next_update=AFTER)
    c = check(run(pki, trusted, crl), "revocation.signer")
    assert c.status is Status.PASSED
    assert c.evidence["post_dated"] is False
    assert "in force over it" in c.summary


def test_strict_revocation_demands_a_post_dated_crl(pki, trusted):
    crl = fixtures.make_crl(pki, this_update=BEFORE, next_update=AFTER)
    c = check(run(pki, trusted, crl, strict_revocation=True), "revocation.signer")
    assert c.status is Status.INDETERMINATE
    assert c.sub_indication.value == "TRY_LATER"
    assert "before this signature was timestamped" in c.summary
    assert "re-check against a CRL issued after" in c.summary


def test_expired_crl_cannot_answer(pki, trusted):
    """Both endpoints before the seal: nothing asserts anything about that moment."""
    crl = fixtures.make_crl(pki, this_update=datetime(2026, 8, 1, tzinfo=timezone.utc),
                            next_update=BEFORE)
    c = check(run(pki, trusted, crl), "revocation.signer")
    assert c.status is Status.INDETERMINATE
    assert c.sub_indication.value == "TRY_LATER"
    assert "in force only until" in c.summary and "superseded" in c.summary


def test_post_dated_crl_is_marked_as_such(pki, trusted):
    c = check(run(pki, trusted, fixtures.make_crl(pki)), "revocation.signer")
    assert c.status is Status.PASSED and c.evidence["post_dated"] is True
    assert "issued after this signature" in c.summary


def test_crl_signed_by_the_wrong_key_is_rejected(pki, trusted):
    r = run(pki, trusted, fixtures.make_crl(pki, wrong_key=True))
    c = check(r, "revocation.signer")
    assert c.status is Status.INDETERMINATE
    assert "signature does not verify" in c.evidence["skipped"][0]


def test_no_store_stays_indeterminate_and_says_why(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted)
    assert r.status is Status.INDETERMINATE
    assert r.caveats == ["revocation status not checked"]
    assert check(r, "revocation.status").status is Status.INDETERMINATE


def test_accepting_the_gap_reaches_passed(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted, accept_unchecked_revocation=True)
    assert r.status is Status.PASSED
    assert r.caveats == ["revocation status not checked"]
    assert check(r, "revocation.status").status is Status.SKIPPED


@pytest.mark.parametrize("paths_are_dir", [True, False])
def test_store_loads_from_paths(tmp_path, pki, paths_are_dir):
    (tmp_path / "a.crl").write_bytes(fixtures.make_crl(pki))
    s = RevocationStore.from_paths([tmp_path if paths_are_dir else tmp_path / "a.crl"])
    assert len(s) == 1


def test_fetch_revocation_is_opt_in_and_reported(pki, trusted, monkeypatch):
    """verify_pdf fetches only when asked, and says what it got."""
    import fiverify.online as online
    calls = []

    def fake(certs, *, timeout=30, store=None):
        calls.append(len(list(certs)))
        store = store or RevocationStore()
        store.add(fixtures.make_crl(pki))
        return store, ["http://crl.example/x.crl: HTTPError: 404"]

    monkeypatch.setattr(online, "fetch_crls", fake)
    pdf, _ = fixtures.signed_pdf(pki)

    assert not calls
    verify_pdf(pdf, profile=trusted)
    assert not calls, "verify_pdf must never fetch unless asked"

    r = verify_pdf(pdf, profile=trusted, fetch_revocation=True)
    assert calls
    assert check(r, "revocation.signer").status is Status.PASSED
    assert check(r, "revocation.fetch").evidence["errors"]
    assert r.status is Status.PASSED and r.caveats == []


def test_all_crl_mirrors_are_reported_not_just_the_first(pki, trusted):
    """A distribution point usually lists mirrors; losing them loses the fallback."""
    pdf, _ = fixtures.signed_pdf(pki)
    urls = verify_pdf(pdf, profile=trusted).signatures[0].details["revocation_urls"]
    assert urls["crl"] == fixtures.CRL_URLS
    assert urls["ocsp"] == [fixtures.OCSP_URL]


def test_fetch_crls_downloads_every_url(pki, monkeypatch):
    """Exercises the real fetch path against a stubbed opener."""
    import io
    import urllib.request

    from fiverify.online import certificates_in, fetch_crls

    crl = fixtures.make_crl(pki)
    asked = []

    def fake_urlopen(req, timeout=None):
        asked.append(req.full_url)
        if "crl2" in req.full_url:
            raise OSError("mirror down")
        return io.BytesIO(crl)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    pdf, _ = fixtures.signed_pdf(pki)
    store, errors = fetch_crls(certificates_in(pdf))
    assert asked == fixtures.CRL_URLS
    assert len(store) == 1 and len(errors) == 1


def test_fetched_crls_are_used(pki, trusted, monkeypatch):
    import io
    import urllib.request

    crl = fixtures.make_crl(pki)
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: io.BytesIO(crl))
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted, fetch_revocation=True)
    assert r.status is Status.PASSED and r.caveats == []
    assert check(r, "revocation.signer").status is Status.PASSED
