"""Network fetching of revocation data. Nothing else in fiverify opens a socket.

Importing this module changes no behaviour; verification never calls it unless
asked. A distribution point is a URL read out of a certificate, so fetching one
before that certificate chains to an anchor would make verification a fetch
primitive for whoever wrote the file. anchored_certificates_in() is the gate;
fetch_crls() is only the transport, and trusts what it is handed.

    from fiverify import verify_pdf
    from fiverify.online import fetch_for_pdf

    data = open("doc.pdf", "rb").read()
    store, errors = fetch_for_pdf(data)
    report = verify_pdf(data, revocation=store)
"""
from __future__ import annotations

import urllib.request
from typing import Iterable
from urllib.parse import urlsplit

from asn1crypto import x509 as ax509

from .cms import MalformedCMS, SignedDataView
from .pdf import find_signatures
from .profile import Profile
from .revocation import RevocationStore
from .tsp import TimestampToken
from .x509util import Chain, build_chain, fingerprint, revocation_urls

USER_AGENT = "fiverify"
SCHEMES = ("http", "https")
MAX_BYTES = 8 << 20
MAX_URLS = 16   # per call, across every certificate


class _HTTPOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """A Location header is remote input, and urllib follows one into ftp:// by default."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme not in SCHEMES:
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener() -> urllib.request.OpenerDirector:
    """By hand, not build_opener, which installs the file://, ftp:// and data: handlers."""
    opener = urllib.request.OpenerDirector()
    for handler in (urllib.request.ProxyHandler(),
                    urllib.request.UnknownHandler(),
                    urllib.request.HTTPHandler(),
                    urllib.request.HTTPSHandler(),
                    urllib.request.HTTPDefaultErrorHandler(),
                    urllib.request.HTTPErrorProcessor(),
                    _HTTPOnlyRedirects()):
        opener.add_handler(handler)
    return opener


def _refusal(url: str, hosts: frozenset[str] | None) -> str | None:
    """Why this URL will not be opened, or None if it will be."""
    parts = urlsplit(url)
    if parts.scheme not in SCHEMES:
        return f"scheme {parts.scheme or '(none)'!r} is not http(s)"
    if not parts.hostname:
        return "no host"
    if hosts is not None and parts.hostname.lower() not in hosts:
        return f"host {parts.hostname!r} is not in allowed_hosts"
    return None


def fetch_crls(certs: Iterable[ax509.Certificate], *, timeout: float = 30,
               store: RevocationStore | None = None,
               allowed_hosts: Iterable[str] | None = None,
               max_urls: int = MAX_URLS) -> tuple[RevocationStore, list[str]]:
    """Download the CRLs these certificates name.

    Pass only certificates already chained to an anchor - anchored_certificates_in()
    returns those; this does not re-check. `allowed_hosts` additionally pins the
    distribution points, for deployments unwilling to follow a CA's URL wherever
    it moves.
    """
    store = store or RevocationStore()
    errors: list[str] = []
    hosts = None if allowed_hosts is None else frozenset(h.lower() for h in allowed_hosts)

    urls: list[str] = []
    for cert in certs:
        for url in revocation_urls(cert)["crl"]:
            if url not in urls:
                urls.append(url)
    if len(urls) > max_urls:
        errors.append(f"{len(urls) - max_urls} distribution point(s) beyond the "
                      f"{max_urls}-URL cap were not fetched")
        urls = urls[:max_urls]

    opener = _opener()
    for url in urls:
        if why := _refusal(url, hosts):
            errors.append(f"{url}: refused, {why}")
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with opener.open(req, timeout=timeout) as r:
                body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                errors.append(f"{url}: larger than the {MAX_BYTES}-byte limit")
                continue
            store.add(body)
        except Exception as e:
            errors.append(f"{url}: {type(e).__name__}: {e}")
    return store, errors


def certificates_in(data: bytes) -> list[ax509.Certificate]:
    """Every certificate embedded in the PDF's signatures and their timestamps.

    Unvalidated: whoever wrote the file chose these.
    """
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


def anchored_certificates_in(data: bytes,
                             profile: Profile | None = None) -> list[ax509.Certificate]:
    """Only certificates sitting on a chain that reaches a trust anchor."""
    profile = profile or Profile.bundled()
    out: list[ax509.Certificate] = []
    for f in find_signatures(data):
        try:
            view = SignedDataView.load(f.cms_der)
        except MalformedCMS:
            continue
        _collect(out, build_chain(view.signer_cert, list(view.certificates), profile.anchors))
        raw = view.unsigned_attr("signature_time_stamp_token")
        if raw is None:
            continue
        try:
            token = TimestampToken.load(raw.dump())
        except MalformedCMS:
            continue
        _collect(out, build_chain(token.tsa_cert, list(token.view.certificates), profile.anchors))
    return out


def _collect(out: list[ax509.Certificate], chain: Chain) -> None:
    if not chain.complete:
        return
    have = {fingerprint(c) for c in out}
    for cert in chain.certs:
        if (fp := fingerprint(cert)) not in have:
            have.add(fp)
            out.append(cert)


def fetch_for_pdf(data: bytes, *, profile: Profile | None = None, timeout: float = 30,
                  extra: Iterable[ax509.Certificate] = (),
                  allowed_hosts: Iterable[str] | None = None
                  ) -> tuple[RevocationStore, list[str]]:
    return fetch_crls(anchored_certificates_in(data, profile) + list(extra),
                      timeout=timeout, allowed_hosts=allowed_hosts)
