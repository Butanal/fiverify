from __future__ import annotations

import hashlib

from asn1crypto import algos
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509 import Certificate

HASHES = {
    "md5": hashes.MD5,
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3_256": hashes.SHA3_256,
    "sha3_384": hashes.SHA3_384,
    "sha3_512": hashes.SHA3_512,
}


class UnsupportedAlgorithm(ValueError):
    pass


def digest(name: str, data: bytes) -> bytes:
    try:
        return hashlib.new(name.replace("sha3_", "sha3-"), data).digest()
    except ValueError as e:
        raise UnsupportedAlgorithm(f"digest {name!r}: {e}") from e


def _hash(name: str) -> hashes.HashAlgorithm:
    if name not in HASHES:
        raise UnsupportedAlgorithm(f"digest {name!r}")
    return HASHES[name]()


def _pss(params: algos.RSASSAPSSParams, hash_name: str) -> padding.PSS:
    mgf_hash = params["mask_gen_algorithm"]["parameters"]["algorithm"].native
    return padding.PSS(
        mgf=padding.MGF1(_hash(mgf_hash)),
        salt_length=params["salt_length"].native,
    )


def verify(cert: Certificate, signature: bytes, data: bytes,
           algorithm: algos.SignedDigestAlgorithm) -> None:
    """Raise InvalidSignature or UnsupportedAlgorithm; return None on success."""
    key = cert.public_key()
    algo = algorithm.signature_algo
    if algo in ("ed25519", "ed448"):
        if not isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            raise UnsupportedAlgorithm("EdDSA signature with a non-EdDSA key")
        key.verify(signature, data)
        return

    hash_name = algorithm.hash_algo
    if algo == "rsassa_pkcs1v15":
        if not isinstance(key, rsa.RSAPublicKey):
            raise UnsupportedAlgorithm("RSA signature with a non-RSA key")
        key.verify(signature, data, padding.PKCS1v15(), _hash(hash_name))
    elif algo == "rsassa_pss":
        if not isinstance(key, rsa.RSAPublicKey):
            raise UnsupportedAlgorithm("RSA-PSS signature with a non-RSA key")
        key.verify(signature, data, _pss(algorithm["parameters"], hash_name), _hash(hash_name))
    elif algo == "ecdsa":
        if not isinstance(key, ec.EllipticCurvePublicKey):
            raise UnsupportedAlgorithm("ECDSA signature with a non-EC key")
        key.verify(signature, data, ec.ECDSA(_hash(hash_name)))
    else:
        raise UnsupportedAlgorithm(f"signature algorithm {algo!r}")


__all__ = ["InvalidSignature", "UnsupportedAlgorithm", "digest", "verify", "HASHES"]
