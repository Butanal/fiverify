"""Network fetching of revocation data. Nothing else in fiverify opens a socket.

Importing this module changes no behaviour; verification never calls it.

    from fiverify import verify_file
    from fiverify.online import fetch_for_pdf

    data = open("doc.pdf", "rb").read()
    store, errors = fetch_for_pdf(data)
    report = verify_pdf(data, revocation=store)
"""
from __future__ import annotations

import urllib.request
from typing import Iterable

from asn1crypto import x509 as ax509

from .cms import MalformedCMS, SignedDataView
from .pdf import find_signatures
from .revocation import RevocationStore
from .tsp import TimestampToken
from .x509util import revocation_urls

USER_AGENT = "fiverify"


def fetch_crls(certs: Iterable[ax509.Certificate], *, timeout: float = 30,
               store: RevocationStore | None = None) -> tuple[RevocationStore, list[str]]:
    store = store or RevocationStore()
    errors: list[str] = []
    seen: set[str] = set()
    for cert in certs:
        for url in revocation_urls(cert)["crl"]:
            if url in seen:
                continue
            seen.add(url)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    store.add(r.read())
            except Exception as e:
                errors.append(f"{url}: {type(e).__name__}: {e}")
    return store, errors


def certificates_in(data: bytes) -> list[ax509.Certificate]:
    """Every certificate embedded in the PDF's signatures and their timestamps."""
    out: list[ax509.Certificate] = []
    for f in find_signatures(data):
        try:
            view = SignedDataView.load(f.cms_der)
        except MalformedCMS:
            continue
        out.extend(view.certificates)
        raw = view.unsigned_attr("signature_time_stamp_token")
        if raw is not None:
            try:
                out.extend(TimestampToken.load(raw.dump()).view.certificates)
            except MalformedCMS:
                pass
    return out


def fetch_for_pdf(data: bytes, *, timeout: float = 30,
                  extra: Iterable[ax509.Certificate] = ()) -> tuple[RevocationStore, list[str]]:
    return fetch_crls(list(certificates_in(data)) + list(extra), timeout=timeout)
