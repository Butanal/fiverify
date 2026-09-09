#!/usr/bin/env python3
"""Rebuild the example documents. Run from the repository root."""
import sys
from pathlib import Path

sys.path[:0] = ["src", "tests"]
import fixtures  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

NAME, FORGED = "Nom: DUPONT Jean", "Nom: DURAND Paul"
out = Path(__file__).parent

pdf, pki = fixtures.signed_pdf(text=NAME, attributes=fixtures.ATTRIBUTES)
(out / "signed.pdf").write_bytes(pdf)
(out / "test-ca.pem").write_bytes(pki.ca_cert.public_bytes(serialization.Encoding.PEM))
(out / "forged-inplace.pdf").write_bytes(pdf.replace(NAME.encode(), FORGED.encode()))
(out / "forged-append.pdf").write_bytes(fixtures.rewrite_page_text(pdf, FORGED))
(out / "test.crl").write_bytes(fixtures.make_crl(pki))
print("wrote signed.pdf, forged-inplace.pdf, forged-append.pdf, test-ca.pem, test.crl")
