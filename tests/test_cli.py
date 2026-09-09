from cryptography.hazmat.primitives import serialization

import fixtures
from fiverify.cli import main


def write(tmp_path, pki, **kw):
    pdf, _ = fixtures.signed_pdf(pki, **kw)
    (tmp_path / "doc.pdf").write_bytes(pdf)
    (tmp_path / "ca.pem").write_bytes(pki.ca_cert.public_bytes(serialization.Encoding.PEM))
    return [str(tmp_path / "doc.pdf"), "--anchor", str(tmp_path / "ca.pem")]


def test_indeterminate_exits_2(tmp_path, pki, capsys):
    assert main(write(tmp_path, pki)) == 2
    assert "result: INDETERMINATE" in capsys.readouterr().out


def test_failure_exits_1(tmp_path, pki, capsys):
    assert main(write(tmp_path, pki, corrupt_signature=True)) == 1
    assert "signature does not verify" in capsys.readouterr().out


def test_json_output(tmp_path, pki, capsys):
    import json
    main(write(tmp_path, pki) + ["--json"])
    d = json.loads(capsys.readouterr().out)
    assert d["signatures"][0]["details"]["signer"] == "TEST SIGNATURE CACHET"
    assert d["status"] == "indeterminate"


def test_missing_file_exits_3(tmp_path, capsys):
    assert main([str(tmp_path / "nope.pdf")]) == 3
