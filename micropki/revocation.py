from enum import IntEnum
from cryptography import x509


class RevocationReason(IntEnum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


REASON_STRING_TO_ENUM = {
    'unspecified': RevocationReason.UNSPECIFIED,
    'keycompromise': RevocationReason.KEY_COMPROMISE,
    'key_compromise': RevocationReason.KEY_COMPROMISE,
    'cacompromise': RevocationReason.CA_COMPROMISE,
    'ca_compromise': RevocationReason.CA_COMPROMISE,
    'affiliationchanged': RevocationReason.AFFILIATION_CHANGED,
    'affiliation_changed': RevocationReason.AFFILIATION_CHANGED,
    'superseded': RevocationReason.SUPERSEDED,
    'cessationofoperation': RevocationReason.CESSATION_OF_OPERATION,
    'cessation_of_operation': RevocationReason.CESSATION_OF_OPERATION,
    'certificatehold': RevocationReason.CERTIFICATE_HOLD,
    'certificate_hold': RevocationReason.CERTIFICATE_HOLD,
    'removefromcrl': RevocationReason.REMOVE_FROM_CRL,
    'remove_from_crl': RevocationReason.REMOVE_FROM_CRL,
    'privilegewithdrawn': RevocationReason.PRIVILEGE_WITHDRAWN,
    'privilege_withdrawn': RevocationReason.PRIVILEGE_WITHDRAWN,
    'aacompromise': RevocationReason.AA_COMPROMISE,
    'aa_compromise': RevocationReason.AA_COMPROMISE,
}

REASON_ENUM_TO_X509 = {
    RevocationReason.UNSPECIFIED: x509.ReasonFlags.unspecified,
    RevocationReason.KEY_COMPROMISE: x509.ReasonFlags.key_compromise,
    RevocationReason.CA_COMPROMISE: x509.ReasonFlags.ca_compromise,
    RevocationReason.AFFILIATION_CHANGED: x509.ReasonFlags.affiliation_changed,
    RevocationReason.SUPERSEDED: x509.ReasonFlags.superseded,
    RevocationReason.CESSATION_OF_OPERATION: x509.ReasonFlags.cessation_of_operation,
    RevocationReason.CERTIFICATE_HOLD: x509.ReasonFlags.certificate_hold,
    RevocationReason.REMOVE_FROM_CRL: x509.ReasonFlags.remove_from_crl,
    RevocationReason.PRIVILEGE_WITHDRAWN: x509.ReasonFlags.privilege_withdrawn,
    RevocationReason.AA_COMPROMISE: x509.ReasonFlags.aa_compromise,
}


def parse_revocation_reason(reason_str: str) -> RevocationReason:
    normalized = reason_str.lower().replace(' ', '_').replace('-', '_')
    if normalized not in REASON_STRING_TO_ENUM:
        valid = ', '.join(sorted(set(REASON_STRING_TO_ENUM.keys())))
        raise ValueError(f"Unsupported revocation reason: '{reason_str}'. Valid: {valid}")
    return REASON_STRING_TO_ENUM[normalized]


def reason_to_x509_flag(reason: RevocationReason) -> x509.ReasonFlags:
    return REASON_ENUM_TO_X509[reason]


def get_reason_name(reason: RevocationReason) -> str:
    names = {
        RevocationReason.UNSPECIFIED: 'Unspecified',
        RevocationReason.KEY_COMPROMISE: 'Key Compromise',
        RevocationReason.CA_COMPROMISE: 'CA Compromise',
        RevocationReason.AFFILIATION_CHANGED: 'Affiliation Changed',
        RevocationReason.SUPERSEDED: 'Superseded',
        RevocationReason.CESSATION_OF_OPERATION: 'Cessation of Operation',
        RevocationReason.CERTIFICATE_HOLD: 'Certificate Hold',
        RevocationReason.REMOVE_FROM_CRL: 'Remove from CRL',
        RevocationReason.PRIVILEGE_WITHDRAWN: 'Privilege Withdrawn',
        RevocationReason.AA_COMPROMISE: 'AA Compromise',
    }
    return names.get(reason, 'Unknown')


def validate_reason(reason_str: str) -> bool:
    try:
        parse_revocation_reason(reason_str)
        return True
    except ValueError:
        return False