
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class CertTemplate:
    """Шаблон сертификата."""
    name: str
    # Key Usage флаги
    digital_signature: bool = False
    key_encipherment: bool = False
    key_agreement: bool = False
    # Extended Key Usage OID-ы
    extended_key_usages: List[str] = field(default_factory=list)
    # Какие типы SAN разрешены
    allowed_san_types: Set[str] = field(default_factory=set)
    # Обязателен ли хотя бы один SAN
    san_required: bool = False


# Три шаблона

SERVER_TEMPLATE = CertTemplate(
    name="server",
    digital_signature=True,
    key_encipherment=True,  # для RSA key exchange в TLS
    extended_key_usages=["serverAuth"],
    allowed_san_types={"dns", "ip"},
    san_required=True,  # серверный сертификат ОБЯЗАН иметь SAN
)

CLIENT_TEMPLATE = CertTemplate(
    name="client",
    digital_signature=True,
    key_agreement=False,
    extended_key_usages=["clientAuth"],
    allowed_san_types={"dns", "email", "uri"},
    san_required=False,
)

CODE_SIGNING_TEMPLATE = CertTemplate(
    name="code_signing",
    digital_signature=True,
    extended_key_usages=["codeSigning"],
    allowed_san_types={"dns", "uri"},
    san_required=False,
)

# Словарь для быстрого доступа по имени
TEMPLATES = {
    "server": SERVER_TEMPLATE,
    "client": CLIENT_TEMPLATE,
    "code_signing": CODE_SIGNING_TEMPLATE,
}


def get_template(name: str) -> CertTemplate:

    if name not in TEMPLATES:
        raise ValueError(
            f"Unknown template '{name}'. "
            f"Available: {', '.join(TEMPLATES.keys())}"
        )
    return TEMPLATES[name]


def validate_san_for_template(template: CertTemplate, san_entries: list) -> None:

    if template.san_required and not san_entries:
        raise ValueError(
            f"Template '{template.name}' requires at least one SAN entry"
        )

    for entry in san_entries:
        if ':' not in entry:
            raise ValueError(
                f"Invalid SAN format: '{entry}'. Expected 'type:value' "
                f"(e.g., dns:example.com)"
            )

        san_type, san_value = entry.split(':', 1)
        san_type = san_type.lower().strip()
        san_value = san_value.strip()

        if not san_value:
            raise ValueError(f"Empty SAN value for type '{san_type}'")

        if san_type not in template.allowed_san_types:
            raise ValueError(
                f"SAN type '{san_type}' is not allowed for template "
                f"'{template.name}'. Allowed types: "
                f"{', '.join(sorted(template.allowed_san_types))}"
            )