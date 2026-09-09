"""Identity attributes carried in a PDF object, as name/string pairs.

Trustworthy only if a signature covers the bytes they came from - see verify.py,
which refuses to expose them otherwise.
"""
from __future__ import annotations

import re
import zlib

OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj\b(.*?)\bendobj", re.S)
STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
NAME_RE = re.compile(rb"/([A-Za-z0-9#_.\-]+)\s*")

KNOWN = ("id", "recipient", "familyName", "givenName", "gender", "nationality",
         "birthdate", "birthplace", "todayDate", "validityDate", "reason")
MIN_KNOWN = 3
OCTAL = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}


def _literal(buf: bytes, i: int) -> tuple[bytes, int]:
    """Read a ( ... ) string at buf[i] == '('. Handles nesting and escapes."""
    out, depth, i = bytearray(), 1, i + 1
    while i < len(buf) and depth:
        c = buf[i]
        if c == 0x5C:  # backslash
            i += 1
            if i >= len(buf):
                break
            e = buf[i]
            if e in OCTAL:
                out.append(OCTAL[e])
            elif 0x30 <= e <= 0x37:
                digits = bytes(buf[i:i + 3]).split(b"\\")[0]
                digits = bytes(d for d in digits if 0x30 <= d <= 0x37)[:3]
                out.append(int(digits, 8) & 0xFF)
                i += len(digits) - 1
            elif e in (0x0A, 0x0D):
                if e == 0x0D and buf[i + 1:i + 2] == b"\n":
                    i += 1
            else:
                out.append(e)
        elif c == 0x28:
            depth += 1
            out.append(c)
        elif c == 0x29:
            depth -= 1
            if depth:
                out.append(c)
        else:
            out.append(c)
        i += 1
    return bytes(out), i


def _hex(buf: bytes, i: int) -> tuple[bytes, int]:
    j = buf.index(b">", i)
    digits = re.sub(rb"[^0-9A-Fa-f]", b"", buf[i + 1:j])
    if len(digits) % 2:
        digits += b"0"
    return bytes.fromhex(digits.decode()), j + 1


def decode_pdf_string(raw: bytes) -> str:
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", "replace")
    if b"\x00" in raw:  # unmarked UTF-16BE
        return raw.decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def parse_fields(buf: bytes) -> dict[str, str]:
    """Every /Name (string) or /Name <hex> pair in a PDF dictionary body."""
    fields: dict[str, str] = {}
    for m in NAME_RE.finditer(buf):
        i = m.end()
        if i >= len(buf):
            break
        if buf[i] == 0x28:
            value, _ = _literal(buf, i)
        elif buf[i] == 0x3C and buf[i + 1:i + 2] != b"<":
            try:
                value, _ = _hex(buf, i)
            except ValueError:
                continue
        else:
            continue
        fields[m.group(1).decode("latin-1")] = decode_pdf_string(value)
    return fields


def _bodies(data: bytes):
    for m in OBJ_RE.finditer(data):
        body = m.group(3)
        yield body
        if s := STREAM_RE.search(body):
            raw = s.group(1)
            if b"/FlateDecode" in body:
                try:
                    yield zlib.decompressobj().decompress(raw)
                except zlib.error:
                    continue
            else:
                yield raw


def extract(data: bytes, *, known: tuple[str, ...] = KNOWN,
            min_known: int = MIN_KNOWN) -> dict[str, str]:
    """Identity attributes from whichever object carries them. Empty if none."""
    best: dict[str, str] = {}
    for body in _bodies(data):
        if not any(b"/" + k.encode() in body for k in known):
            continue
        fields = parse_fields(body)
        hits = sum(1 for k in known if k in fields)
        if hits >= min_known and hits > sum(1 for k in known if k in best):
            best = fields
    return best
