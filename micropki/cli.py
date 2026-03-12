"""
Command-line interface for MicroPKI
"""

import sys
import argparse
from pathlib import Path
import logging

from .logger import setup_logger
from .crypto_utils import read_passphrase_file
from .ca import initialize_root_ca


def validate_args(args):
    """
    Validate command-line arguments.

    Args:
        args: Parsed arguments from argparse

    Raises:
        ValueError: If validation fails
    """
    # Validate subject
    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")

    # Validate key type and size
    if args.key_type not in ('rsa', 'ecc'):
        raise ValueError(f"Invalid key type: {args.key_type}. Must be 'rsa' or 'ecc'")

    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096 bits")

    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384 bits for P-384 curve")

    # Validate passphrase file
    passphrase_path = Path(args.passphrase_file)
    if not passphrase_path.exists():
        raise ValueError(f"Passphrase file not found: {passphrase_path}")

    if not passphrase_path.is_file():
        raise ValueError(f"Passphrase path is not a file: {passphrase_path}")

    # Validate output directory
    out_dir = Path(args.out_dir)

    # Check if directory exists and is writable
    if out_dir.exists():
        if not out_dir.is_dir():
            raise ValueError(f"Output path exists but is not a directory: {out_dir}")

        # Check if we can write to it
        test_file = out_dir / '.write_test'
        try:
            test_file.touch()
            test_file.unlink()
        except Exception as e:
            raise ValueError(f"Output directory is not writable: {out_dir}") from e

    # Validate validity days
    if args.validity_days <= 0:
        raise ValueError("Validity days must be a positive integer")


def ca_init_command(args):
    """
    Handle the 'ca init' command.

    Args:
        args: Parsed command-line arguments
    """
    # Setup logger first
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        # Validate arguments
        logger.info("Validating command-line arguments")
        validate_args(args)

        # Read passphrase
        logger.info(f"Reading passphrase from file: {args.passphrase_file}")
        passphrase = read_passphrase_file(Path(args.passphrase_file))

        if len(passphrase) == 0:
            raise ValueError("Passphrase cannot be empty")

        logger.info("Passphrase loaded successfully")

        # Initialize Root CA
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
        print(f"✓ PKI files created in: {args.out_dir}", file=sys.stderr)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - A minimal PKI implementation for educational purposes'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # CA command group
    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_subparsers = ca_parser.add_subparsers(dest='ca_command', help='CA commands')

    # CA init command
    init_parser = ca_subparsers.add_parser('init', help='Initialize a root CA')

    init_parser.add_argument(
        '--subject',
        required=True,
        help='Distinguished Name (DN) for the CA, e.g., "/CN=My Root CA" or "CN=My Root CA,O=Demo,C=US"'
    )

    init_parser.add_argument(
        '--key-type',
        choices=['rsa', 'ecc'],
        default='rsa',
        help='Key type: rsa or ecc (default: rsa)'
    )

    init_parser.add_argument(
        '--key-size',
        type=int,
        default=4096,
        help='Key size in bits: 4096 for RSA, 384 for ECC P-384 (default: 4096)'
    )

    init_parser.add_argument(
        '--passphrase-file',
        required=True,
        help='Path to file containing passphrase for private key encryption'
    )

    init_parser.add_argument(
        '--out-dir',
        default='./pki1',
        help='Output directory for PKI files (default: ./pki1)'
    )

    init_parser.add_argument(
        '--validity-days',
        type=int,
        default=3650,
        help='Certificate validity period in days (default: 3650 ≈ 10 years)'
    )

    init_parser.add_argument(
        '--log-file',
        help='Path to log file (if omitted, logs to stderr)'
    )

    # Parse arguments
    args = parser.parse_args()

    # Handle commands
    if args.command == 'ca':
        if args.ca_command == 'init':
            ca_init_command(args)
        else:
            ca_parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()