from __future__ import annotations

import re
from dataclasses import dataclass, field

from asn1crypto.parser import peek

BYTERANGE_RE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
NAME_RE = rb"/%s\s*/([A-Za-z0-9.\-_+]+)"
STR_RE = rb"/%s\s*\(((?:[^()\\]|\\.)*)\)"
DICT_KEYS = ("SubFilter", "Filter", "Type")
STR_KEYS = ("Name", "Reason", "Location", "ContactInfo", "M")


class MalformedSignature(ValueError):
    pass


@dataclass
class Coverage:
    starts_at_zero: bool
    contents_in_gap: bool
    trailing_bytes: int
    trailing_is_revision: bool
    revisions_total: int
    revisions_after: int

    @property
    def whole_file(self) -> bool:
        return self.starts_at_zero and self.contents_in_gap and self.trailing_bytes == 0


@dataclass
class SignatureField:
    index: int
    byte_range: tuple[int, int, int, int]
    contents_span: tuple[int, int]
    cms_der: bytes
    padding: bytes
    entries: dict[str, str] = field(default_factory=dict)
    coverage: Coverage | None = None

    def signed_bytes(self, data: bytes) -> bytes:
        a, b, c, d = self.byte_range
        return data[a : a + b] + data[c : c + d]


def _object_span(data: bytes, pos: int) -> tuple[int, int]:
    start = data.rfind(b"obj", 0, pos)
    if start < 0:
        return max(0, pos - 4096), min(len(data), pos + 4096)
    i = start
    while i > 0 and data[i - 1 : i].isspace():
        i -= 1
    while i > 0 and data[i - 1 : i].isdigit():
        i -= 1
    end = data.find(b"endobj", pos)
    return i, (end + 6 if end >= 0 else min(len(data), pos + 65536))


def _entries(blob: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for k in DICT_KEYS:
        if m := re.search(NAME_RE % k.encode(), blob):
            out[k] = m.group(1).decode("latin-1")
    for k in STR_KEYS:
        if m := re.search(STR_RE % k.encode(), blob):
            out[k] = m.group(1).decode("latin-1", "replace")
    return out


def _split_der(raw: bytes) -> tuple[bytes, bytes]:
    """Split /Contents into the CMS and its zero padding using the outer DER
    length. Never strip trailing 0x00 - a CMS can legitimately end in one."""
    try:
        total = peek(raw)
    except Exception as e:
        raise MalformedSignature(f"/Contents is not DER: {e}") from e
    if total > len(raw):
        raise MalformedSignature(f"DER claims {total} bytes, /Contents holds {len(raw)}")
    return raw[:total], raw[total:]


def _coverage(data: bytes, br: tuple[int, int, int, int], span: tuple[int, int]) -> Coverage:
    a, b, c, d = br
    end = c + d
    eofs = [m.start() for m in re.finditer(rb"%%EOF", data)]
    trailing = data[end:]
    return Coverage(
        starts_at_zero=a == 0,
        contents_in_gap=span == (a + b, c),
        trailing_bytes=len(trailing),
        trailing_is_revision=bool(re.search(rb"\bobj\b|\bxref\b|/Type\s*/XRef", trailing)),
        revisions_total=len(eofs),
        revisions_after=sum(1 for e in eofs if e >= end),
    )


def find_signatures(data: bytes) -> list[SignatureField]:
    fields: list[SignatureField] = []
    for n, m in enumerate(BYTERANGE_RE.finditer(data)):
        a, b, c, d = (int(x) for x in m.groups())
        if not (0 <= a <= a + b <= c <= c + d <= len(data)):
            raise MalformedSignature(f"/ByteRange [{a} {b} {c} {d}] is out of bounds")
        lo = data.find(b"<", a + b - 1 if a + b else 0)
        hi = data.find(b">", lo) + 1 if lo >= 0 else -1
        if lo < 0 or hi <= 0:
            raise MalformedSignature("no /Contents hex string after the signed prefix")
        hexed = re.sub(rb"\s", b"", data[lo + 1 : hi - 1])
        if len(hexed) % 2 or not re.fullmatch(rb"[0-9A-Fa-f]*", hexed):
            raise MalformedSignature("/Contents is not a well-formed hex string")
        cms, pad = _split_der(bytes.fromhex(hexed.decode()))
        o0, o1 = _object_span(data, m.start())
        blob = data[o0:lo] + data[hi:o1]
        fields.append(
            SignatureField(
                index=n,
                byte_range=(a, b, c, d),
                contents_span=(lo, hi),
                cms_der=cms,
                padding=pad,
                entries=_entries(blob),
                coverage=_coverage(data, (a, b, c, d), (lo, hi)),
            )
        )
    return fields
