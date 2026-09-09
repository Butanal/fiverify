import pytest

import fixtures
from fiverify.pdf import MalformedSignature, find_signatures


def test_single_signature_found(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf)
    assert f.entries["SubFilter"] == "ETSI.CAdES.detached"
    assert f.entries["Filter"] == "Adobe.PPKLite"
    assert f.entries["Name"] == "FIVERIFY TEST"
    assert f.coverage.whole_file
    assert f.coverage.revisions_after == 0


def test_signed_bytes_exclude_only_the_contents_hole(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf)
    a, b, c, d = f.byte_range
    assert f.signed_bytes(pdf) == pdf[:b] + pdf[c:]
    assert len(f.signed_bytes(pdf)) == len(pdf) - (c - b)


def test_padding_split_uses_der_length_not_rstrip():
    """A CMS may legitimately end in 0x00; only the outer length may split it."""
    from asn1crypto import core

    from fiverify.pdf import _split_der

    der = core.OctetString(b"\x00\x00\x00").dump()
    assert der.endswith(b"\x00")
    cms, pad = _split_der(der + b"\x00" * 100)
    assert cms == der and len(pad) == 100


def test_appended_bytes_break_coverage(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(fixtures.append_revision(pdf))
    assert not f.coverage.whole_file
    assert f.coverage.trailing_is_revision
    assert f.coverage.revisions_after == 1


def test_trailing_whitespace_is_not_a_revision(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf + b"\n\n")
    assert f.coverage.trailing_bytes == 2
    assert not f.coverage.trailing_is_revision


def test_shifted_byterange_is_detected(pki):
    pdf, _ = fixtures.signed_pdf(pki, byte_range_shift=-4)
    (f,) = find_signatures(pdf)
    assert not f.coverage.contents_in_gap


def test_unsigned_pdf_has_no_signatures():
    assert find_signatures(b"%PDF-1.7\nnothing here\n%%EOF\n") == []


def test_non_hex_contents_is_rejected(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf)
    lo, _ = f.contents_span
    broken = bytearray(pdf)
    broken[lo + 1:lo + 5] = b"ZZZZ"
    with pytest.raises(MalformedSignature, match="hex"):
        find_signatures(bytes(broken))


def test_der_longer_than_contents_is_rejected(pki):
    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf)
    lo, _ = f.contents_span
    broken = bytearray(pdf)
    broken[lo + 1:lo + 13] = b"3084FFFFFFFF"
    with pytest.raises(MalformedSignature, match="not DER"):
        find_signatures(bytes(broken))


def test_well_framed_but_meaningless_contents_fails_as_cms(pki, trusted):
    """Framing is all pdf.py promises; the CMS layer rejects the rest."""
    from fiverify import Status, verify_pdf

    pdf, _ = fixtures.signed_pdf(pki)
    (f,) = find_signatures(pdf)
    lo, _ = f.contents_span
    broken = bytearray(pdf)
    broken[lo + 1:lo + 9] = b"30020500"  # a valid, empty SEQUENCE
    r = verify_pdf(bytes(broken), profile=trusted)
    assert r.status is Status.FAILED
    assert r.signatures[0].get("cms.structure").status is Status.FAILED
