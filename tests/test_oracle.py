"""Every verdict this library reaches about signature arithmetic must match openssl."""
import shutil
import subprocess

import pytest

import fixtures
from fiverify import Status, verify_pdf
from fiverify.pdf import find_signatures

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")


def openssl_verifies(tmp_path, pdf: bytes) -> bool:
    (f,) = find_signatures(pdf)
    p7 = tmp_path / "sig.p7s"
    content = tmp_path / "signed.bin"
    p7.write_bytes(f.cms_der)
    content.write_bytes(f.signed_bytes(pdf))
    # -binary is not optional: without it openssl canonicalises line endings.
    r = subprocess.run(
        ["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(p7),
         "-content", str(content), "-noverify", "-purpose", "any", "-out", "/dev/null"],
        capture_output=True)
    return r.returncode == 0


@pytest.mark.parametrize("mutate", ["none", "corrupt", "tamper", "append"])
def test_agrees_with_openssl(tmp_path, pki, trusted, mutate):
    pdf, _ = fixtures.signed_pdf(pki, corrupt_signature=(mutate == "corrupt"))
    if mutate == "tamper":
        pdf = pdf.replace(b"fiverify test fixture", b"fiverify test FIXTURE")
    if mutate == "append":
        pdf = fixtures.append_revision(pdf)

    ours = verify_pdf(pdf, profile=trusted).signatures[0]
    crypto_ok = all(ours.get(c).status is Status.PASSED
                    for c in ("cms.signature", "cms.message_digest"))
    assert crypto_ok == openssl_verifies(tmp_path, pdf)


def test_openssl_accepts_a_forged_revision_but_we_do_not(tmp_path, pki, trusted):
    """A rendered-name forgery: the seal stays valid over its own range, so the
    CMS alone cannot catch it. Only /ByteRange coverage does."""
    pdf, _ = fixtures.signed_pdf(pki, text="Nom: DUPONT Jean")
    forged = fixtures.rewrite_page_text(pdf, "Nom: DURAND Paul")
    assert openssl_verifies(tmp_path, forged)
    assert verify_pdf(forged, profile=trusted).status is Status.FAILED
