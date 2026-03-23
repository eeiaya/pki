
import sys
import argparse
from pathlib import Path

from .logger import setup_logger
from .crypto_utils import read_passphrase_file
from .ca import initialize_root_ca, issue_intermediate_ca, issue_certificate


def validate_ca_init_args(args):
    """Валидация аргументов для ca init."""
    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")

    passphrase_path = Path(args.passphrase_file)
    if not passphrase_path.exists():
        raise ValueError(f"Passphrase file not found: {passphrase_path}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def validate_issue_intermediate_args(args):
    """Валидация аргументов для ca issue-intermediate."""
    for name, path_str in [('root-cert', args.root_cert), ('root-key', args.root_key)]:
        if not Path(path_str).exists():
            raise ValueError(f"File not found: {path_str} (--{name})")

    if not Path(args.root_pass_file).exists():
        raise ValueError(f"Root passphrase file not found: {args.root_pass_file}")
    if not Path(args.passphrase_file).exists():
        raise ValueError(f"Intermediate passphrase file not found: {args.passphrase_file}")

    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")
    if args.pathlen < 0:
        raise ValueError("Path length must be >= 0")


def validate_issue_cert_args(args):
    """Валидация аргументов для ca issue-cert."""
    if not Path(args.ca_cert).exists():
        raise ValueError(f"CA certificate not found: {args.ca_cert}")
    if not Path(args.ca_key).exists():
        raise ValueError(f"CA key not found: {args.ca_key}")
    if not Path(args.ca_pass_file).exists():
        raise ValueError(f"CA passphrase file not found: {args.ca_pass_file}")

    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
    if args.template not in ('server', 'client', 'code_signing'):
        raise ValueError(f"Unknown template: {args.template}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def ca_init_command(args):
    """Обработка команды ca init."""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_ca_init_args(args)
        passphrase = read_passphrase_file(Path(args.passphrase_file))
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")

        initialize_root_ca(
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=Path(args.out_dir),
            validity_days=args.validity_days,
            logger=logger
        )
        print("\n✓ Root CA initialized successfully!", file=sys.stderr)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def ca_issue_intermediate_command(args):
    """Обработка команды ca issue-intermediate."""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_issue_intermediate_args(args)

        root_passphrase = read_passphrase_file(Path(args.root_pass_file))
        intermediate_passphrase = read_passphrase_file(Path(args.passphrase_file))

        if not root_passphrase:
            raise ValueError("Root passphrase cannot be empty")
        if not intermediate_passphrase:
            raise ValueError("Intermediate passphrase cannot be empty")

        issue_intermediate_ca(
            root_cert_path=Path(args.root_cert),
            root_key_path=Path(args.root_key),
            root_passphrase=root_passphrase,
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=intermediate_passphrase,
            out_dir=Path(args.out_dir),
            validity_days=args.validity_days,
            path_length=args.pathlen,
            logger=logger
        )
        print("\n✓ Intermediate CA created successfully!", file=sys.stderr)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def ca_issue_cert_command(args):
    """Обработка команды ca issue-cert."""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_issue_cert_args(args)

        ca_passphrase = read_passphrase_file(Path(args.ca_pass_file))
        if not ca_passphrase:
            raise ValueError("CA passphrase cannot be empty")

        san_entries = args.san if args.san else []

        issue_certificate(
            ca_cert_path=Path(args.ca_cert),
            ca_key_path=Path(args.ca_key),
            ca_passphrase=ca_passphrase,
            template_name=args.template,
            subject_dn=args.subject,
            san_entries=san_entries,
            out_dir=Path(args.out_dir),
            validity_days=args.validity_days,
            logger=logger
        )
        print(f"\n✓ {args.template} certificate issued successfully!", file=sys.stderr)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)


def main():
    """Точка входа CLI."""
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - Minimal PKI implementation'
    )

    subparsers = parser.add_subparsers(dest='command')

    # === ca command group ===
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command')

    # --- ca init ---
    init_parser = ca_subparsers.add_parser('init', help='Initialize root CA')
    init_parser.add_argument('--subject', required=True)
    init_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    init_parser.add_argument('--key-size', type=int, default=4096)
    init_parser.add_argument('--passphrase-file', required=True)
    init_parser.add_argument('--out-dir', default='./pki/pki1')  # ← ИЗМЕНЕНО
    init_parser.add_argument('--validity-days', type=int, default=3650)
    init_parser.add_argument('--log-file', default=None)

    # --- ca issue-intermediate ---
    inter_parser = ca_subparsers.add_parser(
        'issue-intermediate', help='Create intermediate CA signed by root'
    )
    inter_parser.add_argument('--root-cert', required=True)
    inter_parser.add_argument('--root-key', required=True)
    inter_parser.add_argument('--root-pass-file', required=True)
    inter_parser.add_argument('--subject', required=True)
    inter_parser.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    inter_parser.add_argument('--key-size', type=int, default=4096)
    inter_parser.add_argument('--passphrase-file', required=True)
    inter_parser.add_argument('--out-dir', default='./pki/pki1')  # ← ИЗМЕНЕНО
    inter_parser.add_argument('--validity-days', type=int, default=1825)
    inter_parser.add_argument('--pathlen', type=int, default=0)
    inter_parser.add_argument('--log-file', default=None)

    # --- ca issue-cert ---
    cert_parser = ca_subparsers.add_parser(
        'issue-cert', help='Issue end-entity certificate'
    )
    cert_parser.add_argument('--ca-cert', required=True)
    cert_parser.add_argument('--ca-key', required=True)
    cert_parser.add_argument('--ca-pass-file', required=True)
    cert_parser.add_argument('--template', required=True,
                             choices=['server', 'client', 'code_signing'])
    cert_parser.add_argument('--subject', required=True)
    cert_parser.add_argument('--san', action='append', default=None)
    cert_parser.add_argument('--out-dir', default='./pki/pki1/certs')  # ← ИЗМЕНЕНО
    cert_parser.add_argument('--validity-days', type=int, default=365)
    cert_parser.add_argument('--log-file', default=None)


    args = parser.parse_args()

    if args.command == 'ca':
        if args.ca_command == 'init':
            ca_init_command(args)
        elif args.ca_command == 'issue-intermediate':
            ca_issue_intermediate_command(args)
        elif args.ca_command == 'issue-cert':
            ca_issue_cert_command(args)
        else:
            ca_parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()