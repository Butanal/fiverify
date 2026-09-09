import fixtures
from fiverify import Status, verify_pdf
from fiverify.attributes import decode_pdf_string, extract, parse_fields
from test_verify import check


def test_round_trip_through_flate_utf16_and_escapes(pki):
    pdf, _ = fixtures.signed_pdf(pki, attributes=fixtures.ATTRIBUTES)
    assert extract(pdf) == fixtures.ATTRIBUTES


def test_escaped_and_nested_parens_are_not_truncated():
    got = parse_fields(rb"/familyName (O'BRIEN \(n\351e SMITH\)) /birthplace (PARIS \(75\))")
    assert got == {"familyName": "O'BRIEN (née SMITH)", "birthplace": "PARIS (75)"}


def test_utf16_hex_strings():
    assert parse_fields(b"/givenName <FEFF004A00650061006E>") == {"givenName": "Jean"}
    assert decode_pdf_string(b"\xfe\xff\x00J") == "J"
    assert decode_pdf_string(b"plain") == "plain"


def test_names_are_not_mistaken_for_values():
    assert parse_fields(b"/Type /FIAttributes /gender (M)") == {"gender": "M"}


def test_absent_when_the_document_has_none(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki)
    r = verify_pdf(pdf, profile=trusted, extract_attributes=True)
    assert r.attributes == {}


def test_not_extracted_unless_asked(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, attributes=fixtures.ATTRIBUTES)
    r = verify_pdf(pdf, profile=trusted)
    assert r.attributes is None
    assert "attributes" not in r.to_dict()


def test_extracted_from_a_sound_document(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, attributes=fixtures.ATTRIBUTES)
    r = verify_pdf(pdf, profile=trusted, extract_attributes=True)
    assert r.attributes["familyName"] == "O'BRIEN (née SMITH)"
    assert r.to_dict()["attributes"]["givenName"] == "Jean-Étienne"
    assert check(r, "attributes.extracted").status is Status.PASSED


def test_withheld_when_content_was_tampered(pki, trusted):
    pdf, _ = fixtures.signed_pdf(pki, attributes=fixtures.ATTRIBUTES)
    tampered = pdf.replace(b"fiverify test fixture", b"fiverify test FIXTURE")
    r = verify_pdf(tampered, profile=trusted, extract_attributes=True)
    assert r.attributes is None
    assert check(r, "attributes.withheld").status is Status.SKIPPED


def test_withheld_when_a_revision_was_appended(pki, trusted):
    """The forged-append case: the seal verifies, but not over these bytes."""
    pdf, _ = fixtures.signed_pdf(pki, attributes=fixtures.ATTRIBUTES)
    r = verify_pdf(fixtures.append_revision(pdf), profile=trusted, extract_attributes=True)
    assert check(r, "cms.signature").status is Status.PASSED
    assert r.attributes is None


def test_withheld_from_an_unsigned_document(trusted):
    r = verify_pdf(b"%PDF-1.7\n/familyName (DUPONT) /givenName (Jean) /gender (M)\n%%EOF\n",
                   profile=trusted, extract_attributes=True)
    assert r.attributes is None
