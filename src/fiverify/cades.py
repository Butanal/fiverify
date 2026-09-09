"""CAdES signed attributes asn1crypto does not model (ETSI EN 319 122)."""
from __future__ import annotations

from asn1crypto import algos, cms, core, tsp  # noqa: F401  (tsp registers ESS attrs)


class OtherHashAlgAndValue(core.Sequence):
    _fields = [("hash_algorithm", algos.DigestAlgorithm), ("hash_value", core.OctetString)]


class SigPolicyQualifierInfo(core.Sequence):
    _fields = [("sig_policy_qualifier_id", core.ObjectIdentifier), ("sig_qualifier", core.Any)]


class SigPolicyQualifierInfos(core.SequenceOf):
    _child_spec = SigPolicyQualifierInfo


class SignaturePolicyId(core.Sequence):
    _fields = [
        ("sig_policy_id", core.ObjectIdentifier),
        ("sig_policy_hash", OtherHashAlgAndValue),
        ("sig_policy_qualifiers", SigPolicyQualifierInfos, {"optional": True}),
    ]


class SignaturePolicyIdentifier(core.Choice):
    _alternatives = [("signature_policy_id", SignaturePolicyId), ("signature_policy_implied", core.Null)]


class SetOfSignaturePolicyIdentifier(core.SetOf):
    _child_spec = SignaturePolicyIdentifier


class CommitmentTypeQualifier(core.Sequence):
    _fields = [("commitment_type_identifier", core.ObjectIdentifier), ("qualifier", core.Any, {"optional": True})]


class CommitmentTypeQualifiers(core.SequenceOf):
    _child_spec = CommitmentTypeQualifier


class CommitmentTypeIndication(core.Sequence):
    _fields = [
        ("commitment_type_id", core.ObjectIdentifier),
        ("commitment_type_qualifier", CommitmentTypeQualifiers, {"optional": True}),
    ]


class SetOfCommitmentTypeIndication(core.SetOf):
    _child_spec = CommitmentTypeIndication


COMMITMENT_TYPES = {
    "1.2.840.113549.1.9.16.6.1": "proofOfOrigin",
    "1.2.840.113549.1.9.16.6.2": "proofOfReceipt",
    "1.2.840.113549.1.9.16.6.3": "proofOfDelivery",
    "1.2.840.113549.1.9.16.6.4": "proofOfSender",
    "1.2.840.113549.1.9.16.6.5": "proofOfApproval",
    "1.2.840.113549.1.9.16.6.6": "proofOfCreation",
}

cms.CMSAttributeType._map["1.2.840.113549.1.9.16.2.15"] = "signature_policy_identifier"
cms.CMSAttributeType._map["1.2.840.113549.1.9.16.2.16"] = "commitment_type_indication"
cms.CMSAttribute._oid_specs["signature_policy_identifier"] = SetOfSignaturePolicyIdentifier
cms.CMSAttribute._oid_specs["commitment_type_indication"] = SetOfCommitmentTypeIndication
