import pytest

from fiverify.profile import Profile, ProfileError
from fiverify.x509util import fingerprint, name


def test_bundled_profile_pins_its_anchor():
    p = Profile.bundled()
    (anchor,) = p.anchors
    assert name(anchor) == "AC SERVEUR CACHET EIDAS 2025"
    assert fingerprint(anchor) in p.trust["pinned_sha256"]


def test_unpinned_anchor_is_refused(tmp_path):
    import shutil
    from importlib import resources
    src = resources.files("fiverify") / "anchors" / "ac-serveur-cachet-eidas-2025.pem"
    shutil.copy(str(src), tmp_path / "anchor.pem")
    (tmp_path / "p.toml").write_text(
        'name = "x"\n[trust]\nanchors = ["anchor.pem"]\npinned_sha256 = ["00"]\n')
    with pytest.raises(ProfileError, match="not pinned"):
        Profile.from_file(tmp_path / "p.toml")


def test_profile_from_file_without_pins(tmp_path):
    (tmp_path / "p.toml").write_text('name = "loose"\n[timestamp]\nrequired = false\n')
    p = Profile.from_file(tmp_path / "p.toml")
    assert p.name == "loose" and p.anchors == [] and p.timestamp["required"] is False


def test_tsl_certificates_are_read_from_the_etsi_namespace():
    """Identity certificates sit in the ETSI namespace, not xmldsig."""
    import base64
    import importlib.util
    import pathlib

    spec = importlib.util.spec_from_file_location(
        "tsl_anchors", pathlib.Path(__file__).parent.parent / "tools" / "tsl-anchors.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    from importlib import resources

    from asn1crypto import pem
    _, _, der = pem.unarmor(
        (resources.files("fiverify") / "anchors" / "ac-serveur-cachet-eidas-2025.pem").read_bytes())
    xml = (
        '<TrustServiceStatusList xmlns="http://uri.etsi.org/02231/v2#">'
        "<TSPService><ServiceInformation>"
        "<ServiceTypeIdentifier>http://x/QC</ServiceTypeIdentifier>"
        "<ServiceStatus>http://x/granted</ServiceStatus>"
        f"<X509Certificate>{base64.b64encode(der).decode()}</X509Certificate>"
        "</ServiceInformation></TSPService></TrustServiceStatusList>"
    ).encode()
    (name, typ, status, got), = mod.services(xml)
    assert (name, typ, status, got) == ("AC SERVEUR CACHET EIDAS 2025", "QC", "granted", der)
