from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

from asn1crypto import x509 as ax509

from .x509util import fingerprint, load_pem_certs

BUNDLED = "france-identite"


class ProfileError(ValueError):
    pass


@dataclass
class Profile:
    name: str
    version: str
    description: str
    document: dict[str, Any]
    crypto: dict[str, Any]
    signature: dict[str, Any]
    qualified: dict[str, Any]
    timestamp: dict[str, Any]
    trust: dict[str, Any]
    anchors: list[ax509.Certificate] = field(default_factory=list)

    @classmethod
    def bundled(cls, name: str = BUNDLED) -> "Profile":
        files = resources.files("fiverify")
        data = (files / "profiles" / f"{name}.toml").read_bytes()
        return cls._build(tomllib.loads(data.decode()), lambda f: (files / "anchors" / f).read_bytes())

    @classmethod
    def from_file(cls, path: str | Path) -> "Profile":
        path = Path(path)
        doc = tomllib.loads(path.read_text())
        return cls._build(doc, lambda f: (path.parent / f).read_bytes())

    @classmethod
    def _build(cls, doc: dict[str, Any], read) -> "Profile":
        try:
            p = cls(
                name=doc["name"],
                version=doc.get("version", ""),
                description=doc.get("description", ""),
                document=doc.get("document", {}),
                crypto=doc.get("crypto", {}),
                signature=doc.get("signature", {}),
                qualified=doc.get("qualified", {}),
                timestamp=doc.get("timestamp", {}),
                trust=doc.get("trust", {}),
            )
        except KeyError as e:
            raise ProfileError(f"profile is missing {e}") from e
        for fname in p.trust.get("anchors", []):
            p.anchors.extend(load_pem_certs(read(fname)))
        pinned = set(p.trust.get("pinned_sha256", []))
        if pinned:
            actual = {fingerprint(a) for a in p.anchors}
            if unexpected := actual - pinned:
                raise ProfileError(f"anchor fingerprint not pinned by the profile: {sorted(unexpected)}")
        return p

    def with_anchors(self, extra: list[ax509.Certificate]) -> "Profile":
        clone = Profile(**{**self.__dict__, "anchors": self.anchors + extra})
        return clone
