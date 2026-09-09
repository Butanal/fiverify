from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, Mapping, Sequence


class Status(enum.Enum):
    PASSED = "passed"
    FAILED = "failed"
    INDETERMINATE = "indeterminate"
    SKIPPED = "skipped"


class Severity(enum.Enum):
    CRITICAL = "critical"  # cryptographic or structural
    POLICY = "policy"      # profile expectation
    INFO = "info"          # never decisive


class SubIndication(enum.Enum):
    FORMAT_FAILURE = "FORMAT_FAILURE"
    HASH_FAILURE = "HASH_FAILURE"
    SIG_CRYPTO_FAILURE = "SIG_CRYPTO_FAILURE"
    SIGNED_DATA_NOT_FOUND = "SIGNED_DATA_NOT_FOUND"
    NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND"
    CHAIN_CONSTRAINTS_FAILURE = "CHAIN_CONSTRAINTS_FAILURE"
    EXPIRED = "EXPIRED"
    NOT_YET_VALID = "NOT_YET_VALID"
    CRYPTO_CONSTRAINTS_FAILURE = "CRYPTO_CONSTRAINTS_FAILURE"
    POLICY_PROCESSING_ERROR = "POLICY_PROCESSING_ERROR"
    SIG_CONSTRAINTS_FAILURE = "SIG_CONSTRAINTS_FAILURE"
    NO_POE = "NO_POE"
    NO_REVOCATION_DATA = "NO_REVOCATION_DATA"
    TRY_LATER = "TRY_LATER"
    REVOKED_NO_POE = "REVOKED_NO_POE"


@dataclass(frozen=True)
class Check:
    id: str
    status: Status
    summary: str
    severity: Severity = Severity.CRITICAL
    sub_indication: SubIndication | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
        }
        if self.sub_indication:
            d["sub_indication"] = self.sub_indication.value
        if self.evidence:
            d["evidence"] = jsonable(self.evidence)
        return d


def _worst(checks: Sequence[Check]) -> tuple[Status, SubIndication | None]:
    for c in checks:
        if c.severity is Severity.CRITICAL and c.status is Status.FAILED:
            return Status.FAILED, c.sub_indication
    for c in checks:
        if c.severity is Severity.INFO or c.status in (Status.PASSED, Status.SKIPPED):
            continue
        return Status.INDETERMINATE, c.sub_indication
    return Status.PASSED, None


@dataclass
class SignatureReport:
    index: int
    checks: list[Check] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    def get(self, check_id: str) -> Check | None:
        return next((c for c in self.checks if c.id == check_id), None)

    @property
    def status(self) -> Status:
        return _worst(self.checks)[0]

    @property
    def sub_indication(self) -> SubIndication | None:
        return _worst(self.checks)[1]

    def failures(self) -> list[Check]:
        return [c for c in self.checks if c.status is Status.FAILED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "status": self.status.value,
            "sub_indication": (s.value if (s := self.sub_indication) else None),
            "details": jsonable(self.details),
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class Report:
    profile: str
    file_size: int
    file_sha256: str
    signatures: list[SignatureReport] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)  # document level
    caveats: list[str] = field(default_factory=list)   # what was not checked
    attributes: dict[str, str] | None = None           # only if integrity established
    validated_at: datetime | None = None

    def add(self, check: Check) -> Check:
        self.checks.append(check)
        return check

    @property
    def status(self) -> Status:
        if not self.signatures:
            return _worst(self.checks)[0]
        every = list(self.checks)
        for s in self.signatures:
            every.extend(s.checks)
        return _worst(every)[0]

    def all_checks(self) -> Iterator[Check]:
        yield from self.checks
        for s in self.signatures:
            yield from s.checks

    def failures(self) -> list[Check]:
        return [c for c in self.all_checks() if c.status is Status.FAILED]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "caveats": list(self.caveats),
            "profile": self.profile,
            "validated_at": jsonable(self.validated_at),
            "file": {"size": self.file_size, "sha256": self.file_sha256},
            **({"attributes": dict(self.attributes)} if self.attributes is not None else {}),
            "checks": [c.to_dict() for c in self.checks],
            "signatures": [s.to_dict() for s in self.signatures],
        }


def jsonable(v: Any) -> Any:
    if isinstance(v, (bytes, bytearray)):
        return v.hex()
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, enum.Enum):
        return v.value
    if isinstance(v, Mapping):
        return {str(k): jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [jsonable(x) for x in v]
    return v
