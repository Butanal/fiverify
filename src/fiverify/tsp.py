from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from asn1crypto import tsp as atsp
from asn1crypto import x509 as ax509
from asn1crypto.core import VOID

from .cms import MalformedCMS, SignedDataView
from .crypto import digest

TIMESTAMPING_EKU = "time_stamping"


@dataclass
class TimestampToken:
    view: SignedDataView
    info: atsp.TSTInfo

    @classmethod
    def load(cls, der: bytes) -> "TimestampToken":
        view = SignedDataView.load(der)
        if view.econtent_type != "tst_info":
            raise MalformedCMS(f"eContentType is {view.econtent_type!r}, not id-ct-TSTInfo")
        content = view.signed_data["encap_content_info"]["content"]
        if content is VOID:
            raise MalformedCMS("timestamp token carries no TSTInfo")
        return cls(view, atsp.TSTInfo.load(content.__bytes__()))

    @property
    def tsa_cert(self) -> ax509.Certificate:
        return self.view.signer_cert

    @property
    def gen_time(self) -> datetime:
        return self.info["gen_time"].native

    @property
    def policy(self) -> str:
        return self.info["policy"].native

    @property
    def serial(self) -> int:
        return self.info["serial_number"].native

    @property
    def nonce(self) -> int | None:
        n = self.info["nonce"]
        return None if n is VOID else n.native

    @property
    def imprint_algo(self) -> str:
        return self.info["message_imprint"]["hash_algorithm"]["algorithm"].native

    @property
    def imprint(self) -> bytes:
        return self.info["message_imprint"]["hashed_message"].native

    @property
    def accuracy(self) -> timedelta:
        a = self.info["accuracy"]
        if a is VOID:
            return timedelta(0)
        get = lambda k: (0 if a[k] is VOID else a[k].native)  # noqa: E731
        return timedelta(seconds=get("seconds"), microseconds=get("millis") * 1000 + get("micros"))

    def binds(self, data: bytes) -> bool:
        return digest(self.imprint_algo, data) == self.imprint

    def verify_signature(self) -> None:
        self.view.verify_signature(self._tst_info_bytes())

    def _tst_info_bytes(self) -> bytes:
        return self.view.signed_data["encap_content_info"]["content"].__bytes__()

    def content_digest_matches(self) -> tuple[bool, bytes | None, bytes | None]:
        return self.view.content_digest_matches(self._tst_info_bytes())

    def tsa_eku(self) -> tuple[bool, bool, list[str]]:
        """(has id-kp-timeStamping, extension is critical, all EKU names)."""
        for ext in self.tsa_cert["tbs_certificate"]["extensions"] or []:
            if ext["extn_id"].native == "extended_key_usage":
                names = list(ext["extn_value"].parsed.native)
                return TIMESTAMPING_EKU in names, bool(ext["critical"].native), names
        return False, False, []
