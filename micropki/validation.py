from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.exceptions import InvalidSignature


@dataclass
class ValidationStep:
    name: str
    passed: bool
    message: str = ""


@dataclass
class ValidationResult:
    success: bool
    chain: List[x509.Certificate] = field(default_factory=list)
    steps: List[ValidationStep] = field(default_factory=list)
    error: Optional[str] = None

    def add_step(self, name: str, passed: bool, message: str = ""):
        self.steps.append(ValidationStep(name, passed, message))
        if not passed and self.error is None:
            self.error = f"{name}: {message}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "error": self.error,
            "chain_length": len(self.chain),
            "chain": [c.subject.rfc4514_string() for c in self.chain],
            "steps": [
                {"name": s.name, "passed": s.passed, "message": s.message}
                for s in self.steps
            ]
        }


def _verify_signature(cert: x509.Certificate, issuer_cert: x509.Certificate) -> bool:
    issuer_pub = issuer_cert.public_key()
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            issuer_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except InvalidSignature:
        return False


def _is_issued_by(cert: x509.Certificate, candidate_issuer: x509.Certificate) -> bool:
    if cert.issuer != candidate_issuer.subject:
        return False
    return _verify_signature(cert, candidate_issuer)


def build_chain(
    leaf_cert: x509.Certificate,
    untrusted_certs: List[x509.Certificate],
    trusted_certs: List[x509.Certificate]
) -> Optional[List[x509.Certificate]]:
    chain = [leaf_cert]
    current = leaf_cert

    max_depth = 10  # защита от циклов
    for _ in range(max_depth):
        # Проверяем, выпущен ли текущий доверенным корнем
        for trusted in trusted_certs:
            if _is_issued_by(current, trusted):
                chain.append(trusted)
                return chain

        # Иначе ищем среди непроверенных
        found_issuer = None
        for candidate in untrusted_certs:
            if candidate in chain:
                continue
            if _is_issued_by(current, candidate):
                found_issuer = candidate
                break

        if found_issuer is None:
            return None

        chain.append(found_issuer)
        current = found_issuer

    return None


def validate_chain(
    leaf_cert: x509.Certificate,
    untrusted_certs: Optional[List[x509.Certificate]] = None,
    trusted_certs: Optional[List[x509.Certificate]] = None,
    validation_time: Optional[datetime] = None,
    check_eku: Optional[str] = None
) -> ValidationResult:
    result = ValidationResult(success=False)

    if untrusted_certs is None:
        untrusted_certs = []
    if trusted_certs is None:
        trusted_certs = []

    if validation_time is None:
        validation_time = datetime.now(timezone.utc)
    if validation_time.tzinfo is None:
        validation_time = validation_time.replace(tzinfo=timezone.utc)

    # Шаг 1: построение цепочки
    chain = build_chain(leaf_cert, untrusted_certs, trusted_certs)
    if chain is None:
        result.add_step("build_chain", False, "Cannot build certificate chain to a trusted root")
        return result

    result.chain = chain
    result.add_step("build_chain", True, f"Chain length: {len(chain)}")

    # Шаг 2: проверка каждого сертификата (кроме корневого)
    # chain = [leaf, intermediate(s)..., root]
    for i, cert in enumerate(chain):
        cn = cert.subject.rfc4514_string()
        is_root = (i == len(chain) - 1)

        # Срок действия
        if cert.not_valid_before_utc <= validation_time <= cert.not_valid_after_utc:
            result.add_step(f"validity[{cn}]", True, "Within validity period")
        else:
            result.add_step(
                f"validity[{cn}]",
                False,
                f"Expired or not yet valid (valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc})"
            )
            return result

        # Подпись (кроме корня — корень самоподписан, проверяем отдельно)
        if not is_root:
            issuer = chain[i + 1]
            if _verify_signature(cert, issuer):
                result.add_step(f"signature[{cn}]", True, "Valid signature")
            else:
                result.add_step(f"signature[{cn}]", False, "Invalid signature")
                return result
        else:
            # Самоподпись корня
            if _verify_signature(cert, cert):
                result.add_step(f"signature[{cn}]", True, "Valid self-signature")
            else:
                result.add_step(f"signature[{cn}]", False, "Invalid self-signature")
                return result

        # BasicConstraints
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            expected_ca = (i > 0)  # leaf = i=0, должен быть CA=False; intermediate/root = CA=True

            if bc.ca != expected_ca:
                result.add_step(
                    f"basic_constraints[{cn}]",
                    False,
                    f"CA flag is {bc.ca}, expected {expected_ca}"
                )
                return result
            result.add_step(f"basic_constraints[{cn}]", True, f"CA={bc.ca}")

            # pathLenConstraint
            if bc.ca and bc.path_length is not None:
                # количество CA-сертификатов между этим и leaf
                ca_below = i  # сколько CA ниже по цепочке (intermediate + leaf)
                # Точнее: количество подчинённых CA = i - 1 (вычитаем leaf)
                subordinate_cas = i - 1 if i > 0 else 0
                if subordinate_cas > bc.path_length:
                    result.add_step(
                        f"path_length[{cn}]",
                        False,
                        f"Subordinate CAs ({subordinate_cas}) exceed pathLenConstraint ({bc.path_length})"
                    )
                    return result
                result.add_step(f"path_length[{cn}]", True, f"pathLen={bc.path_length}")

        except x509.ExtensionNotFound:
            if i > 0:  # CA должен иметь BasicConstraints
                result.add_step(
                    f"basic_constraints[{cn}]",
                    False,
                    "CA certificate missing BasicConstraints extension"
                )
                return result

        # KeyUsage для CA
        if i > 0:  # все CA в цепочке
            try:
                ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
                if not ku.key_cert_sign:
                    result.add_step(
                        f"key_usage[{cn}]",
                        False,
                        "CA certificate missing keyCertSign flag"
                    )
                    return result
                result.add_step(f"key_usage[{cn}]", True, "keyCertSign present")
            except x509.ExtensionNotFound:
                pass

        # Issuer == Subject следующего в цепочке
        if not is_root:
            next_cert = chain[i + 1]
            if cert.issuer != next_cert.subject:
                result.add_step(
                    f"issuer_match[{cn}]",
                    False,
                    "Issuer DN does not match next cert's subject"
                )
                return result
            result.add_step(f"issuer_match[{cn}]", True, "Issuer matches")

    # Шаг 3: проверка EKU для leaf-сертификата
    if check_eku is not None:
        eku_map = {
            "serverAuth": ExtendedKeyUsageOID.SERVER_AUTH,
            "clientAuth": ExtendedKeyUsageOID.CLIENT_AUTH,
            "codeSigning": ExtendedKeyUsageOID.CODE_SIGNING,
            "ocspSigning": ExtendedKeyUsageOID.OCSP_SIGNING,
        }
        if check_eku in eku_map:
            try:
                eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
                if eku_map[check_eku] in eku:
                    result.add_step("eku_check", True, f"EKU '{check_eku}' present")
                else:
                    result.add_step("eku_check", False, f"EKU '{check_eku}' missing")
                    return result
            except x509.ExtensionNotFound:
                result.add_step("eku_check", False, "ExtendedKeyUsage extension missing")
                return result

    result.success = True
    return result