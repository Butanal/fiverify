#!/usr/bin/env python3
"""Fetch trust anchors from an EU Trusted List and check the bundled copies.

The only part of this project that uses the network. Validation itself never does.

    python3 tools/tsl-anchors.py --verify
    python3 tools/tsl-anchors.py --list
    python3 tools/tsl-anchors.py --match "CACHET EIDAS 2025" -o src/fiverify/anchors
"""
import argparse
import base64
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from asn1crypto import pem, x509  # noqa: E402

from fiverify.profile import Profile  # noqa: E402
from fiverify.x509util import fingerprint, name  # noqa: E402

FR_TSL = "https://messervices.cyber.gouv.fr/visas/tl-fr_v6.xml"
# Identity certificates sit in the ETSI namespace here, not xmldsig.
V2 = "{http://uri.etsi.org/02231/v2#}"


def services(xml: bytes):
    for svc in ET.fromstring(xml).iter(V2 + "TSPService"):
        info = svc.find(V2 + "ServiceInformation")
        typ = (info.findtext(V2 + "ServiceTypeIdentifier") or "").rsplit("/", 1)[-1]
        status = (info.findtext(V2 + "ServiceStatus") or "").rsplit("/", 1)[-1]
        for el in info.iter(V2 + "X509Certificate"):
            der = base64.b64decode("".join((el.text or "").split()))
            try:
                cert = x509.Certificate.load(der)
            except ValueError:
                continue
            yield name(cert) or "?", typ, status, der


def slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tsl", default=FR_TSL, help=f"trusted list URL (default: {FR_TSL})")
    ap.add_argument("--tsl-file", type=Path, help="read a local copy instead of fetching")
    ap.add_argument("--match", help="substring of the certificate subject")
    ap.add_argument("--list", action="store_true", help="list every service")
    ap.add_argument("--verify", action="store_true",
                    help="check the profile's anchors against the trusted list")
    ap.add_argument("-o", "--outdir", type=Path, help="write matching certificates as PEM")
    ap.add_argument("--profile", type=Path)
    args = ap.parse_args()

    if args.tsl_file:
        xml = args.tsl_file.read_bytes()
    else:
        print(f"fetching {args.tsl}", file=sys.stderr)
        with urllib.request.urlopen(args.tsl, timeout=60) as r:
            xml = r.read()
    found = list(services(xml))
    print(f"{len(found)} service certificates", file=sys.stderr)

    if args.verify:
        profile = Profile.from_file(args.profile) if args.profile else Profile.bundled()
        listed = {fingerprint(x509.Certificate.load(der)): (n, t, s) for n, t, s, der in found}
        bad = 0
        for anchor in profile.anchors:
            fp = fingerprint(anchor)
            if entry := listed.get(fp):
                print(f"[ok  ] {name(anchor)}\n       {fp}\n       type={entry[1]} status={entry[2]}")
                if entry[2] != "granted":
                    bad += 1
            else:
                print(f"[FAIL] {name(anchor)}\n       {fp}\n       not in this trusted list")
                bad += 1
        return 1 if bad else 0

    for n, typ, status, der in found:
        if args.list or (args.match and args.match.lower() in n.lower()):
            print(f"{n}\n  type={typ} status={status}\n  "
                  f"sha256={fingerprint(x509.Certificate.load(der))}")
            if args.outdir and args.match:
                args.outdir.mkdir(parents=True, exist_ok=True)
                path = args.outdir / f"{slug(n)}.pem"
                path.write_bytes(pem.armor("CERTIFICATE", der))
                print(f"  wrote {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
