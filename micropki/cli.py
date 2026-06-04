import json
import sys
import argparse
from pathlib import Path
from typing import Optional

from .logger import setup_logger
from .crypto_utils import read_passphrase_file
from .ca import initialize_root_ca, issue_intermediate_ca, issue_certificate
from .database import CertificateDatabase
from datetime import datetime, timedelta, timezone

def get_default_db_path(out_dir: Path) -> Path:
    """Получить путь к БД по умолчанию."""
    return out_dir / 'certificates.db'

def validate_ca_init_args(args):
    """Валидация для ca init."""
    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")
    if not Path(args.passphrase_file).exists():
        raise ValueError(f"Passphrase file not found: {args.passphrase_file}")
    if args.validity_days <= 0:
        raise ValueError("Validity days must be positive")


def validate_issue_intermediate_args(args):
    """Валидация для ca issue-intermediate."""
    for name, path_str in [('root-cert', args.root_cert), ('root-key', args.root_key)]:
        if not Path(path_str).exists():
            raise ValueError(f"File not found: {path_str}")
    if not Path(args.root_pass_file).exists():
        raise ValueError(f"Passphrase file not found: {args.root_pass_file}")
    if not Path(args.passphrase_file).exists():
        raise ValueError(f"Passphrase file not found: {args.passphrase_file}")
    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
    if args.key_type == 'rsa' and args.key_size != 4096:
        raise ValueError("RSA key size must be 4096")
    if args.key_type == 'ecc' and args.key_size != 384:
        raise ValueError("ECC key size must be 384")


def validate_issue_cert_args(args):
    """Валидация для ca issue-cert."""
    if not Path(args.ca_cert).exists():
        raise ValueError(f"CA certificate not found: {args.ca_cert}")
    if not Path(args.ca_key).exists():
        raise ValueError(f"CA key not found: {args.ca_key}")
    if not Path(args.ca_pass_file).exists():
        raise ValueError(f"Passphrase file not found: {args.ca_pass_file}")
    # Subject обязателен только если не передан CSR
    csr_provided = getattr(args, 'csr', None)
    if not csr_provided:
        if not args.subject or not args.subject.strip():
            raise ValueError("Subject DN cannot be empty (or provide --csr)")
    if args.template not in ('server', 'client', 'code_signing'):
        raise ValueError(f"Unknown template: {args.template}")

def ca_init_command(args):
    """ca init"""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_ca_init_args(args)
        passphrase = read_passphrase_file(Path(args.passphrase_file))
        if not passphrase:
            raise ValueError("Passphrase cannot be empty")

        out_dir = Path(args.out_dir)
        db_path = get_default_db_path(out_dir)

        initialize_root_ca(
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=passphrase,
            out_dir=out_dir,
            validity_days=args.validity_days,
            logger=logger,
            db_path=db_path
        )

        print("\n✓ Root CA initialized successfully!", file=sys.stderr)
        print(f"✓ Certificate saved to database: {db_path}", file=sys.stderr)

    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ca_issue_intermediate_command(args):
    """ca issue-intermediate"""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_issue_intermediate_args(args)
        root_pass = read_passphrase_file(Path(args.root_pass_file))
        inter_pass = read_passphrase_file(Path(args.passphrase_file))

        out_dir = Path(args.out_dir)
        db_path = get_default_db_path(out_dir)

        issue_intermediate_ca(
            root_cert_path=Path(args.root_cert),
            root_key_path=Path(args.root_key),
            root_passphrase=root_pass,
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            passphrase=inter_pass,
            out_dir=out_dir,
            validity_days=args.validity_days,
            path_length=args.pathlen,
            logger=logger,
            db_path=db_path
        )

        print("\n✓ Intermediate CA created successfully!", file=sys.stderr)
        print(f"✓ Certificate saved to database: {db_path}", file=sys.stderr)

    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ca_issue_cert_command(args):
    """ca issue-cert"""
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        validate_issue_cert_args(args)
        ca_pass = read_passphrase_file(Path(args.ca_pass_file))
        san_entries = args.san if args.san else []
        out_dir = Path(args.out_dir)

        # Определяем путь к БД
        if out_dir.name == 'certs':
            db_path = out_dir.parent / 'certificates.db'
        else:
            db_path = out_dir / 'certificates.db'

        issue_certificate(
            ca_cert_path=Path(args.ca_cert),
            ca_key_path=Path(args.ca_key),
            ca_passphrase=ca_pass,
            template_name=args.template,
            subject_dn=args.subject,
            san_entries=san_entries,
            out_dir=out_dir,
            validity_days=args.validity_days,
            logger=logger,
            db_path=db_path,
            csr_path = Path(args.csr) if args.csr else None
        )

        print(f"\n✓ {args.template} certificate issued successfully!", file=sys.stderr)
        print(f"✓ Certificate saved to database: {db_path}", file=sys.stderr)

    except Exception as e:
        logger.error(f"Error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ca_revoke_command(args):
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        from .revocation import parse_revocation_reason, get_reason_name
        from .serial import is_valid_hex_serial

        serial = args.serial.upper()
        if not is_valid_hex_serial(serial):
            raise ValueError(f"Invalid serial number format: '{serial}'")

        reason = args.reason.lower()
        reason_enum = parse_revocation_reason(reason)
        reason_name = get_reason_name(reason_enum)

        out_dir = Path(args.out_dir)
        db_path = get_default_db_path(out_dir)

        if not db_path.exists():
            raise ValueError(f"Database not found: {db_path}")

        db = CertificateDatabase(db_path)
        cert_data = db.get_certificate(serial)

        if cert_data is None:
            raise ValueError(f"Certificate with serial {serial} not found")

        if cert_data['status'] == 'revoked':
            logger.warning(f"Certificate already revoked: {serial}")
            print(f"\n⚠ Certificate {serial} is already revoked.", file=sys.stderr)
            sys.exit(0)

        if not args.force:
            print(f"\nRevoke certificate {serial}?", file=sys.stderr)
            print(f"  Subject: {cert_data['subject']}", file=sys.stderr)
            print(f"  Reason:  {reason_name}", file=sys.stderr)
            confirm = input("Confirm [y/N]: ")
            if confirm.lower() not in ('y', 'yes'):
                print("Cancelled.", file=sys.stderr)
                sys.exit(0)

        db.revoke_certificate(serial, reason)
        logger.info(f"Certificate revoked: serial={serial}, reason={reason_name}")
        print(f"\n✓ Certificate {serial} revoked ({reason_name})", file=sys.stderr)

    except Exception as e:
        logger.error(f"Revocation error: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ca_gen_crl_command(args):
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        from .crl import CRLManager
        from .crypto_utils import load_certificate

        out_dir = Path(args.out_dir)
        db_path = get_default_db_path(out_dir)

        if not db_path.exists():
            raise ValueError(f"Database not found: {db_path}")

        ca_name = args.ca.lower()
        if ca_name not in ('root', 'intermediate'):
            raise ValueError(f"Invalid CA: '{args.ca}'. Use 'root' or 'intermediate'.")

        certs_dir = out_dir / 'certs'
        private_dir = out_dir / 'private'

        if ca_name == 'root':
            ca_cert_path = certs_dir / 'ca.cert.pem'
            ca_key_path = private_dir / 'ca.key.pem'
            pass_default = './secrets/root_ca.pass'
        else:
            ca_cert_path = certs_dir / 'intermediate.cert.pem'
            ca_key_path = private_dir / 'intermediate.key.pem'
            pass_default = './secrets/intermediate_ca.pass'

        if not ca_cert_path.exists():
            raise ValueError(f"CA certificate not found: {ca_cert_path}")
        if not ca_key_path.exists():
            raise ValueError(f"CA key not found: {ca_key_path}")

        pass_file = Path(args.ca_pass_file) if args.ca_pass_file else Path(pass_default)
        if not pass_file.exists():
            raise ValueError(f"Passphrase file not found: {pass_file}")

        ca_passphrase = read_passphrase_file(pass_file)
        ca_cert = load_certificate(ca_cert_path)
        ca_subject_dn = ca_cert.subject.rfc4514_string()

        db = CertificateDatabase(db_path)
        revoked_certs = db.get_revoked_by_issuer(ca_subject_dn)

        crl_manager = CRLManager(out_dir, logger)
        out_file = Path(args.out_file) if args.out_file else None

        crl_path = crl_manager.generate_and_save_crl(
            ca_cert_path, ca_key_path, ca_passphrase,
            revoked_certs, ca_name, args.next_update, out_file
        )

        next_update = (datetime.now(timezone.utc) + timedelta(days=args.next_update)).isoformat()
        crl_number = crl_manager._read_crl_number(ca_name) - 1
        db.update_crl_metadata(ca_subject_dn, crl_number, next_update, str(crl_path))

        print(f"\n✓ CRL generated: {crl_path}", file=sys.stderr)
        print(f"  Revoked: {len(revoked_certs)}, CRL#: {crl_number}", file=sys.stderr)

    except Exception as e:
        logger.error(f"CRL generation failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ca_check_revoked_command(args):
    from .serial import is_valid_hex_serial

    serial = args.serial.upper()
    if not is_valid_hex_serial(serial):
        print(f"Invalid serial: {serial}", file=sys.stderr)
        sys.exit(1)

    db_path = get_default_db_path(Path(args.out_dir))
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db = CertificateDatabase(db_path)
    cert = db.get_certificate(serial)

    if cert is None:
        print(f"Certificate {serial}: NOT FOUND")
        sys.exit(1)

    if cert['status'] == 'revoked':
        print(f"Certificate {serial}: REVOKED")
        print(f"  Date:   {cert['revocation_date']}")
        print(f"  Reason: {cert['revocation_reason']}")
    else:
        print(f"Certificate {serial}: {cert['status'].upper()}")

# ============================================================
# SPRINT 6: Client commands
# ============================================================

def client_gen_csr_command(args):
    from .client import client_gen_csr, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        san_entries = args.san if args.san else []

        client_gen_csr(
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            san_entries=san_entries,
            out_key=Path(args.out_key),
            out_csr=Path(args.out_csr),
            logger=logger
        )

        print(f"\n✓ CSR generated successfully!", file=sys.stderr)
        print(f"  Key: {args.out_key}", file=sys.stderr)
        print(f"  CSR: {args.out_csr}", file=sys.stderr)

    except Exception as e:
        logger.error(f"CSR generation failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


def client_request_cert_command(args):
    from .client import client_request_cert, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        client_request_cert(
            csr_path=Path(args.csr),
            template=args.template,
            ca_url=args.ca_url,
            out_cert=Path(args.out_cert),
            api_key=args.api_key,
            logger=logger
        )

        print(f"\n✓ Certificate received from CA!", file=sys.stderr)
        print(f"  Saved to: {args.out_cert}", file=sys.stderr)

    except Exception as e:
        logger.error(f"Request-cert failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


def client_validate_command(args):
    from .client import client_validate, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        untrusted = args.untrusted if args.untrusted else []
        trusted = [args.trusted] if args.trusted else []

        validation_time = None
        if args.validation_time:
            from datetime import datetime
            validation_time = datetime.fromisoformat(args.validation_time)

        result = client_validate(
            cert_path=Path(args.cert),
            trusted_paths=trusted,
            untrusted_paths=untrusted,
            crl_source=args.crl,
            use_ocsp=args.ocsp,
            mode=args.mode,
            validation_time=validation_time,
            check_eku=args.check_eku,
            logger=logger
        )

        if args.format == 'json':
            import json as _json
            print(_json.dumps(result, indent=2, default=str))
        else:
            print("\n" + "=" * 70)
            print("CERTIFICATE VALIDATION RESULT")
            print("=" * 70)
            print(f"Overall: {'✓ SUCCESS' if result['success'] else '✗ FAILED'}")
            if result.get('error'):
                print(f"Error:   {result['error']}")
            print(f"Chain length: {result['chain_length']}")

            print("\nChain:")
            for i, subject in enumerate(result['chain']):
                print(f"  [{i}] {subject}")

            print("\nValidation steps:")
            for step in result['steps']:
                mark = '✓' if step['passed'] else '✗'
                print(f"  {mark} {step['name']}: {step['message']}")

            if result.get('revocation'):
                rev = result['revocation']
                print(f"\nRevocation check:")
                print(f"  Status:  {rev['status']}")
                print(f"  Method:  {rev['method']}")
                print(f"  Message: {rev['message']}")
                if rev.get('revocation_time'):
                    print(f"  Revoked: {rev['revocation_time']}")
                if rev.get('revocation_reason'):
                    print(f"  Reason:  {rev['revocation_reason']}")
            print("=" * 70)

        if not result['success']:
            sys.exit(1)

    except Exception as e:
        logger.error(f"Validation failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


def client_check_status_command(args):
    from .client import client_check_status, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        result = client_check_status(
            cert_path=Path(args.cert),
            ca_cert_path=Path(args.ca_cert),
            crl_source=args.crl,
            ocsp_url=args.ocsp_url,
            logger=logger
        )

        print("\n" + "=" * 60)
        print("REVOCATION STATUS CHECK")
        print("=" * 60)
        print(f"Status:  {result.status.upper()}")
        print(f"Method:  {result.method}")
        print(f"Message: {result.message}")
        if result.revocation_time:
            print(f"Revoked: {result.revocation_time}")
        if result.revocation_reason:
            print(f"Reason:  {result.revocation_reason}")
        print("=" * 60)

        if result.status == 'revoked':
            sys.exit(2)
        elif result.status == 'unknown':
            sys.exit(3)

    except Exception as e:
        logger.error(f"Status check failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

def client_sign_command(args):
    from .client import client_sign_file, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        client_sign_file(
            file_path=Path(args.file),
            key_path=Path(args.key),
            out_sig=Path(args.out_sig),
            logger=logger
        )
        print(f"\n✓ File signed", file=sys.stderr)
        print(f"  File:      {args.file}", file=sys.stderr)
        print(f"  Signature: {args.out_sig}", file=sys.stderr)
    except Exception as e:
        logger.error(f"Sign failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


def client_verify_command(args):
    from .client import client_verify_file, setup_client_logger

    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_client_logger(log_file=log_file)

    try:
        valid = client_verify_file(
            file_path=Path(args.file),
            cert_path=Path(args.cert),
            sig_path=Path(args.sig),
            logger=logger
        )

        if valid:
            print(f"\n✓ Signature VALID", file=sys.stderr)
            print(f"  File:      {args.file}", file=sys.stderr)
            print(f"  Signer:    {args.cert}", file=sys.stderr)
            sys.exit(0)
        else:
            print(f"\n✗ Signature INVALID", file=sys.stderr)
            sys.exit(2)

    except Exception as e:
        logger.error(f"Verify failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)


# ============================================================
# SPRINT 7: Audit + Compromise commands
# ============================================================

def audit_query_command(args):
    from .audit import query_audit_entries, format_audit_entries_table, format_audit_entries_csv, verify_audit_log

    log_file = Path(args.log_file)

    if not log_file.exists():
        print(f"Audit log not found: {log_file}", file=sys.stderr)
        sys.exit(1)

    try:
        entries = query_audit_entries(
            log_file=log_file,
            from_ts=args.from_ts,
            to_ts=args.to_ts,
            level=args.level,
            operation=args.operation,
            serial=args.serial,
        )
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.format == 'json':
        print(json.dumps(entries, indent=2, ensure_ascii=False))
    elif args.format == 'csv':
        print(format_audit_entries_csv(entries))
    else:
        print(format_audit_entries_table(entries))

    if args.verify:
        chain_file = log_file.parent / 'chain.dat'
        result = verify_audit_log(log_file, chain_file if chain_file.exists() else None)
        if result.ok:
            print("\n✓ Integrity verified", file=sys.stderr)
        else:
            print(f"\n✗ Integrity check FAILED: {result.message}", file=sys.stderr)
            sys.exit(2)


def audit_verify_command(args):
    from .audit import verify_audit_log

    log_file = Path(args.log_file)
    chain_file = Path(args.chain_file)

    if not log_file.exists():
        print(f"Audit log not found: {log_file}", file=sys.stderr)
        sys.exit(1)

    result = verify_audit_log(log_file, chain_file if chain_file.exists() else None)

    if result.ok:
        print(f"✓ Audit log integrity OK: {log_file}")
        print(f"  Chain file: {chain_file if chain_file.exists() else '(not used)'}")
        sys.exit(0)
    else:
        print(f"✗ Audit log integrity FAILED", file=sys.stderr)
        if result.first_bad_line is not None:
            print(f"  First bad line: {result.first_bad_line}", file=sys.stderr)
        print(f"  Reason: {result.message}", file=sys.stderr)
        sys.exit(2)


def audit_ct_verify_command(args):
    from .transparency import CTLog

    out_dir = Path(args.out_dir)
    serial = args.serial.upper()

    ct = CTLog(out_dir)
    if ct.contains_serial(serial):
        print(f"✓ Certificate {serial} found in CT log")
        sys.exit(0)
    else:
        print(f"✗ Certificate {serial} NOT found in CT log", file=sys.stderr)
        sys.exit(1)


def ca_compromise_command(args):
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        from .ca import compromise_certificate
        from .crypto_utils import load_certificate

        cert_path = Path(args.cert)
        if not cert_path.exists():
            raise ValueError(f"Certificate not found: {cert_path}")

        out_dir = Path(args.out_dir)
        db_path = get_default_db_path(out_dir)

        if not db_path.exists():
            raise ValueError(f"Database not found: {db_path}")

        cert = load_certificate(cert_path)
        serial_hex = format(cert.serial_number, 'X')

        if not args.force:
            print(f"\n{'='*60}", file=sys.stderr)
            print("KEY COMPROMISE SIMULATION", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)
            print(f"Serial:  {serial_hex}", file=sys.stderr)
            print(f"Subject: {cert.subject.rfc4514_string()}", file=sys.stderr)
            print(f"Reason:  {args.reason}", file=sys.stderr)
            print(f"{'='*60}", file=sys.stderr)
            confirm = input("Mark this certificate as compromised? [y/N]: ")
            if confirm.lower() not in ('y', 'yes'):
                print("Cancelled.", file=sys.stderr)
                sys.exit(0)

        # Определяем пути CA для экстренного CRL
        certs_dir = out_dir / 'certs'
        private_dir = out_dir / 'private'

        issuer_dn = cert.issuer.rfc4514_string().lower()
        if 'intermediate' in issuer_dn:
            ca_cert_path = certs_dir / 'intermediate.cert.pem'
            ca_key_path = private_dir / 'intermediate.key.pem'
        else:
            ca_cert_path = certs_dir / 'ca.cert.pem'
            ca_key_path = private_dir / 'ca.key.pem'

        ca_passphrase = None
        if args.ca_pass_file and Path(args.ca_pass_file).exists():
            ca_passphrase = read_passphrase_file(Path(args.ca_pass_file))

        result = compromise_certificate(
            cert_path=cert_path,
            out_dir=out_dir,
            db_path=db_path,
            ca_passphrase=ca_passphrase,
            ca_cert_path=ca_cert_path if ca_passphrase else None,
            ca_key_path=ca_key_path if ca_passphrase else None,
            reason=args.reason,
            logger=logger,
        )

        print(f"\n✓ Certificate marked as compromised", file=sys.stderr)
        print(f"  Serial:           {result['serial']}", file=sys.stderr)
        print(f"  Public key hash:  {result['public_key_hash'][:32]}...", file=sys.stderr)
        if result.get('emergency_crl'):
            print(f"  Emergency CRL:    {result['emergency_crl']}", file=sys.stderr)
        else:
            print(f"  Emergency CRL:    skipped (no --ca-pass-file)", file=sys.stderr)

    except Exception as e:
        logger.error(f"Compromise failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)

def ca_issue_ocsp_cert_command(args):
    log_file = Path(args.log_file) if args.log_file else None
    logger = setup_logger(log_file=log_file)

    try:
        from .ca import issue_ocsp_certificate

        if not Path(args.ca_cert).exists():
            raise ValueError(f"CA certificate not found: {args.ca_cert}")
        if not Path(args.ca_key).exists():
            raise ValueError(f"CA key not found: {args.ca_key}")
        if not Path(args.ca_pass_file).exists():
            raise ValueError(f"Passphrase file not found: {args.ca_pass_file}")

        ca_pass = read_passphrase_file(Path(args.ca_pass_file))
        san_entries = args.san if args.san else []
        out_dir = Path(args.out_dir)

        if out_dir.name == 'certs':
            db_path = out_dir.parent / 'certificates.db'
        else:
            db_path = out_dir / 'certificates.db'

        issue_ocsp_certificate(
            ca_cert_path=Path(args.ca_cert),
            ca_key_path=Path(args.ca_key),
            ca_passphrase=ca_pass,
            subject_dn=args.subject,
            key_type=args.key_type,
            key_size=args.key_size,
            san_entries=san_entries,
            out_dir=out_dir,
            validity_days=args.validity_days,
            logger=logger,
            db_path=db_path,
            ocsp_url=args.ocsp_url
        )

        print("\n✓ OCSP responder certificate issued!", file=sys.stderr)
        print(f"  Cert: {out_dir}/ocsp.cert.pem", file=sys.stderr)
        print(f"  Key:  {out_dir}/ocsp.key.pem", file=sys.stderr)

    except Exception as e:
        logger.error(f"OCSP cert issuance failed: {e}")
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def ocsp_serve_command(args):
    try:
        import uvicorn
        from .ocsp_responder import create_ocsp_app
        from .logger import setup_logger as _setup

        log_file = Path(args.log_file) if args.log_file else None
        logger = _setup(log_file=log_file)

        for f in [args.responder_cert, args.responder_key, args.ca_cert]:
            if not Path(f).exists():
                raise ValueError(f"File not found: {f}")

        app = create_ocsp_app(
            db_path=Path(args.db_path),
            responder_cert_path=Path(args.responder_cert),
            responder_key_path=Path(args.responder_key),
            ca_cert_path=Path(args.ca_cert),
            cache_ttl=args.cache_ttl,
            logger=logger
        )

        print("=" * 60)
        print("MicroPKI OCSP Responder")
        print("=" * 60)
        print(f"Host:      {args.host}")
        print(f"Port:      {args.port}")
        print(f"Endpoint:  http://{args.host}:{args.port}/ocsp")
        print(f"Cache TTL: {args.cache_ttl}s")
        print("-" * 60)
        print("Press Ctrl+C to stop.")
        print("=" * 60 + "\n")

        uvicorn.run(app, host=args.host, port=args.port, log_level="warning")

    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

def ca_list_certs_command(args):
    """ca list-certs (алиас для db list)"""
    db_list_command(args)


def ca_show_cert_command(args):
    """ca show-cert (алиас для db show)"""
    # Преобразуем аргументы
    args.show_pem = getattr(args, 'format', 'table') == 'pem'
    db_show_command(args)

def db_init_command(args):
    """db init"""
    db_path = Path(args.db_path)

    if db_path.exists():
        print(f"Database already exists: {db_path}")
        print("Schema is up to date.")
        return

    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = CertificateDatabase(db_path)

    print(f"✓ Database initialized: {db_path}")


def db_list_command(args):
    """db list / ca list-certs"""
    db_path = Path(args.db_path)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db = CertificateDatabase(db_path)
    status = getattr(args, 'status', None)
    template = getattr(args, 'template', None)
    limit = getattr(args, 'limit', 100)
    output_format = getattr(args, 'format', 'table')

    certs = db.list_certificates(status=status, template=template, limit=limit)

    if not certs:
        print("\nNo certificates found.")
        return

    if output_format == 'json':
        import json
        # Убираем PEM для краткости
        for c in certs:
            c.pop('cert_pem', None)
        print(json.dumps(certs, indent=2))

    elif output_format == 'csv':
        print("serial_hex,subject,issuer,status,template,not_after")
        for c in certs:
            print(f"{c['serial_hex']},{c['subject']},{c['issuer']},{c['status']},{c.get('template','')},{c['not_after'][:10]}")

    else:  # table
        print(f"\n{'='*115}")
        print(f"CERTIFICATES ({len(certs)} found)")
        print(f"{'='*115}")
        print(f"{'Serial':<42} {'Subject':<35} {'Status':<10} {'Template':<15} {'Expires':<12}")
        print(f"{'-'*115}")

        for c in certs:
            serial = c['serial_hex'][:40] + '..' if len(c['serial_hex']) > 40 else c['serial_hex']
            subject = c['subject'][:33] + '..' if len(c['subject']) > 33 else c['subject']
            print(f"{serial:<42} {subject:<35} {c['status']:<10} {c.get('template','N/A'):<15} {c['not_after'][:10]:<12}")

        print(f"{'='*115}\n")


def db_show_command(args):
    """db show / ca show-cert"""
    db_path = Path(args.db_path)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db = CertificateDatabase(db_path)
    cert = db.get_certificate(args.serial)

    if cert is None:
        print(f"\n✗ Certificate with serial '{args.serial}' not found.", file=sys.stderr)
        sys.exit(1)

    show_pem = getattr(args, 'show_pem', False) or getattr(args, 'format', '') == 'pem'

    if show_pem:
        print(cert['cert_pem'])
    else:
        print("\n" + "=" * 70)
        print("CERTIFICATE DETAILS")
        print("=" * 70)
        print(f"Serial Number:   {cert['serial_hex']}")
        print(f"Subject:         {cert['subject']}")
        print(f"Issuer:          {cert['issuer']}")
        print(f"Not Before:      {cert['not_before']}")
        print(f"Not After:       {cert['not_after']}")
        print(f"Status:          {cert['status']}")
        print(f"Template:        {cert.get('template') or 'N/A'}")
        if cert.get('san_entries'):
            print(f"SAN Entries:     {', '.join(cert['san_entries'])}")
        if cert.get('revocation_reason'):
            print(f"Revoked:         {cert['revocation_reason']} on {cert['revocation_date']}")
        print(f"Created At:      {cert['created_at']}")
        print("=" * 70)


def db_export_command(args):
    """db export"""
    db_path = Path(args.db_path)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db = CertificateDatabase(db_path)
    cert = db.get_certificate(args.serial)

    if cert is None:
        print(f"\n✗ Certificate not found.", file=sys.stderr)
        sys.exit(1)

    output = Path(args.output) if args.output else Path(f"{args.serial}.pem")
    output.write_text(cert['cert_pem'])
    print(f"✓ Certificate exported to: {output}")


def db_stats_command(args):
    """db stats"""
    db_path = Path(args.db_path)

    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    db = CertificateDatabase(db_path)
    stats = db.get_statistics()

    print("\n" + "=" * 50)
    print("DATABASE STATISTICS")
    print("=" * 50)
    print(f"Total Certificates: {stats['total']}")

    if stats['by_status']:
        print("\nBy Status:")
        for k, v in stats['by_status'].items():
            print(f"  {k:<15} {v}")

    if stats['by_template']:
        print("\nBy Template:")
        for k, v in stats['by_template'].items():
            print(f"  {k:<15} {v}")

    print("=" * 50 + "\n")

def repo_serve_command(args):
    """repo serve / server start"""
    try:
        import uvicorn
        from .server import create_app
    except ImportError as e:
        print(f"Missing dependency: {e}", file=sys.stderr)
        print("Run: pip install fastapi uvicorn", file=sys.stderr)
        sys.exit(1)

    db_path = Path(args.db_path)
    ca_certs_dir = Path(args.cert_dir)

    print("=" * 60)
    print("Starting MicroPKI Certificate Repository Server")
    print("=" * 60)
    print(f"Host:            {args.host}")
    print(f"Port:            {args.port}")
    print(f"Database:        {db_path}")
    print(f"CA Certificates: {ca_certs_dir}")
    print("-" * 60)
    print(f"API Base URL:    http://{args.host}:{args.port}")
    print(f"API Docs:        http://{args.host}:{args.port}/docs")
    print("-" * 60)
    print("Press Ctrl+C to stop.")
    print("=" * 60 + "\n")

    app = create_app(db_path=db_path, ca_certs_dir=ca_certs_dir)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

def main():
    """Точка входа CLI."""
    parser = argparse.ArgumentParser(
        prog='micropki',
        description='MicroPKI - Minimal PKI implementation'
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    ca_parser = subparsers.add_parser('ca', help='Certificate Authority operations')
    ca_sub = ca_parser.add_subparsers(dest='ca_command')

    # ca init
    p = ca_sub.add_parser('init', help='Initialize root CA')
    p.add_argument('--subject', required=True)
    p.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    p.add_argument('--key-size', type=int, default=4096)
    p.add_argument('--passphrase-file', required=True)
    p.add_argument('--out-dir', default='./pki/pki1')
    p.add_argument('--validity-days', type=int, default=3650)
    p.add_argument('--log-file')

    # ca issue-intermediate
    p = ca_sub.add_parser('issue-intermediate', help='Create intermediate CA')
    p.add_argument('--root-cert', required=True)
    p.add_argument('--root-key', required=True)
    p.add_argument('--root-pass-file', required=True)
    p.add_argument('--subject', required=True)
    p.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    p.add_argument('--key-size', type=int, default=4096)
    p.add_argument('--passphrase-file', required=True)
    p.add_argument('--out-dir', default='./pki/pki1')
    p.add_argument('--validity-days', type=int, default=1825)
    p.add_argument('--pathlen', type=int, default=0)
    p.add_argument('--log-file')

    # ca issue-cert
    p = ca_sub.add_parser('issue-cert', help='Issue end-entity certificate')
    p.add_argument('--ca-cert', required=True)
    p.add_argument('--ca-key', required=True)
    p.add_argument('--ca-pass-file', required=True)
    p.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    p.add_argument('--subject', default='')
    p.add_argument('--san', action='append')
    p.add_argument('--out-dir', default='./pki/pki1/certs')
    p.add_argument('--validity-days', type=int, default=365)
    p.add_argument('--csr', help='Optional CSR file to sign (overrides --subject and --san)')
    p.add_argument('--log-file')

    # ca revoke
    p = ca_sub.add_parser('revoke', help='Revoke certificate')
    p.add_argument('serial', help='Serial number (hex)')
    p.add_argument('--reason', default='unspecified')
    p.add_argument('--force', action='store_true')
    p.add_argument('--out-dir', default='./pki/pki1')
    p.add_argument('--log-file')

    # ca gen-crl
    p = ca_sub.add_parser('gen-crl', help='Generate CRL')
    p.add_argument('--ca', required=True, help='root or intermediate')
    p.add_argument('--next-update', type=int, default=7)
    p.add_argument('--out-file')
    p.add_argument('--ca-pass-file')
    p.add_argument('--out-dir', default='./pki/pki1')
    p.add_argument('--log-file')

    # ca check-revoked
    p = ca_sub.add_parser('check-revoked', help='Check revocation status')
    p.add_argument('serial')
    p.add_argument('--out-dir', default='./pki/pki1')

    # ca compromise (Sprint 7)
    p = ca_sub.add_parser('compromise', help='Simulate private key compromise')
    p.add_argument('--cert', required=True, help='Path to compromised certificate (PEM)')
    p.add_argument('--reason', default='keyCompromise')
    p.add_argument('--force', action='store_true')
    p.add_argument('--ca-pass-file', help='CA passphrase file for emergency CRL')
    p.add_argument('--out-dir', default='./pki/pki1')
    p.add_argument('--log-file')

    # ca issue-ocsp-cert
    p = ca_sub.add_parser('issue-ocsp-cert', help='Issue OCSP responder certificate')
    p.add_argument('--ca-cert', required=True)
    p.add_argument('--ca-key', required=True)
    p.add_argument('--ca-pass-file', required=True)
    p.add_argument('--subject', required=True)
    p.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    p.add_argument('--key-size', type=int, default=2048)
    p.add_argument('--san', action='append')
    p.add_argument('--out-dir', default='./pki/pki1/certs')
    p.add_argument('--validity-days', type=int, default=365)
    p.add_argument('--ocsp-url')
    p.add_argument('--log-file')

    # ca list-certs (CLI-13)
    p = ca_sub.add_parser('list-certs', help='List all certificates')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--status', choices=['valid', 'revoked', 'expired'])
    p.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    p.add_argument('--limit', type=int, default=100)

    # ca show-cert (CLI-14)
    p = ca_sub.add_parser('show-cert', help='Show certificate by serial')
    p.add_argument('serial', help='Serial number (hex)')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--format', choices=['table', 'pem'], default='table')

    # OCSP команды
    ocsp_parser = subparsers.add_parser('ocsp', help='OCSP responder operations')
    ocsp_sub = ocsp_parser.add_subparsers(dest='ocsp_command')

    p = ocsp_sub.add_parser('serve', help='Start OCSP responder')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8081)
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--responder-cert', required=True)
    p.add_argument('--responder-key', required=True)
    p.add_argument('--ca-cert', required=True)
    p.add_argument('--cache-ttl', type=int, default=60)
    p.add_argument('--log-file')

    # ============================================================
    # SPRINT 6: client commands
    # ============================================================
    client_parser = subparsers.add_parser('client', help='Client-side operations')
    client_sub = client_parser.add_subparsers(dest='client_command')

    # client gen-csr
    p = client_sub.add_parser('gen-csr', help='Generate private key and CSR')
    p.add_argument('--subject', required=True)
    p.add_argument('--key-type', choices=['rsa', 'ecc'], default='rsa')
    p.add_argument('--key-size', type=int, default=2048)
    p.add_argument('--san', action='append')
    p.add_argument('--out-key', default='./key.pem')
    p.add_argument('--out-csr', default='./request.csr.pem')
    p.add_argument('--log-file')

    # client request-cert
    p = client_sub.add_parser('request-cert', help='Send CSR to CA and get certificate')
    p.add_argument('--csr', required=True)
    p.add_argument('--template', required=True, choices=['server', 'client', 'code_signing'])
    p.add_argument('--ca-url', default='http://localhost:8080')
    p.add_argument('--out-cert', default='./cert.pem')
    p.add_argument('--api-key', default='changeme')
    p.add_argument('--log-file')

    # client validate
    p = client_sub.add_parser('validate', help='Validate certificate chain')
    p.add_argument('--cert', required=True)
    p.add_argument('--untrusted', action='append', help='Intermediate certificates (can repeat)')
    p.add_argument('--trusted', default='./pki/pki1/certs/ca.cert.pem')
    p.add_argument('--crl', help='CRL file path or URL')
    p.add_argument('--ocsp', action='store_true', help='Use OCSP for revocation check')
    p.add_argument('--mode', choices=['chain', 'full'], default='full')
    p.add_argument('--validation-time', help='ISO 8601 datetime to use instead of now')
    p.add_argument('--check-eku', choices=['serverAuth', 'clientAuth', 'codeSigning', 'ocspSigning'])
    p.add_argument('--format', choices=['text', 'json'], default='text')
    p.add_argument('--log-file')

    # client check-status
    p = client_sub.add_parser('check-status', help='Check revocation status (OCSP→CRL)')
    p.add_argument('--cert', required=True)
    p.add_argument('--ca-cert', required=True)
    p.add_argument('--crl', help='CRL file path or URL')
    p.add_argument('--ocsp-url', help='Override OCSP responder URL')
    p.add_argument('--log-file')

    # client sign
    p = client_sub.add_parser('sign', help='Sign a file with code-signing private key')
    p.add_argument('--file', required=True, help='File to sign')
    p.add_argument('--key', required=True, help='Private key (PEM, unencrypted)')
    p.add_argument('--out-sig', default='./signature.sig', help='Output signature file')
    p.add_argument('--log-file')

    # client verify
    p = client_sub.add_parser('verify', help='Verify file signature')
    p.add_argument('--file', required=True, help='File to verify')
    p.add_argument('--cert', required=True, help='Signer certificate (PEM)')
    p.add_argument('--sig', required=True, help='Signature file')
    p.add_argument('--log-file')

    # ============================================================
    # SPRINT 7: audit commands
    # ============================================================
    audit_parser = subparsers.add_parser('audit', help='Audit log operations')
    audit_sub = audit_parser.add_subparsers(dest='audit_command')

    # audit query
    p = audit_sub.add_parser('query', help='Query audit log entries')
    p.add_argument('--log-file', default='./pki/pki1/audit/audit.log')
    p.add_argument('--from', dest='from_ts', help='ISO 8601 start timestamp')
    p.add_argument('--to', dest='to_ts', help='ISO 8601 end timestamp')
    p.add_argument('--level', choices=['INFO', 'WARNING', 'ERROR', 'AUDIT'])
    p.add_argument('--operation', help='Filter by operation name')
    p.add_argument('--serial', help='Filter by certificate serial (hex)')
    p.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    p.add_argument('--verify', action='store_true', help='Verify integrity after query')

    # audit verify
    p = audit_sub.add_parser('verify', help='Verify audit log integrity')
    p.add_argument('--log-file', default='./pki/pki1/audit/audit.log')
    p.add_argument('--chain-file', default='./pki/pki1/audit/chain.dat')

    # audit ct-verify
    p = audit_sub.add_parser('ct-verify', help='Check if cert serial is in CT log')
    p.add_argument('serial', help='Certificate serial (hex)')
    p.add_argument('--out-dir', default='./pki/pki1')

    db_parser = subparsers.add_parser('db', help='Database operations')
    db_sub = db_parser.add_subparsers(dest='db_command')

    # db init (CLI-12)
    p = db_sub.add_parser('init', help='Initialize certificate database')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')

    # db list
    p = db_sub.add_parser('list', help='List certificates')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--status', choices=['valid', 'revoked', 'expired'])
    p.add_argument('--template')
    p.add_argument('--format', choices=['table', 'json', 'csv'], default='table')
    p.add_argument('--limit', type=int, default=100)

    # db show
    p = db_sub.add_parser('show', help='Show certificate details')
    p.add_argument('serial')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--show-pem', action='store_true')

    # db export
    p = db_sub.add_parser('export', help='Export certificate to file')
    p.add_argument('serial')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--output', '-o')

    # db stats
    p = db_sub.add_parser('stats', help='Show statistics')
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')

    repo_parser = subparsers.add_parser('repo', help='Repository server operations')
    repo_sub = repo_parser.add_subparsers(dest='repo_command')

    # repo serve
    p = repo_sub.add_parser('serve', help='Start HTTP repository server')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8080)
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--cert-dir', default='./pki/pki1/certs')

    server_parser = subparsers.add_parser('server', help='HTTP server (alias for repo)')
    server_sub = server_parser.add_subparsers(dest='server_command')

    p = server_sub.add_parser('start', help='Start server')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=8080)
    p.add_argument('--db-path', default='./pki/pki1/certificates.db')
    p.add_argument('--cert-dir', default='./pki/pki1/certs')

    args = parser.parse_args()

    if args.command == 'ca':
        if args.ca_command == 'init':
            ca_init_command(args)
        elif args.ca_command == 'issue-intermediate':
            ca_issue_intermediate_command(args)
        elif args.ca_command == 'issue-cert':
            ca_issue_cert_command(args)
        elif args.ca_command == 'list-certs':
            ca_list_certs_command(args)
        elif args.ca_command == 'show-cert':
            ca_show_cert_command(args)
        elif args.ca_command == 'revoke':
            ca_revoke_command(args)
        elif args.ca_command == 'gen-crl':
            ca_gen_crl_command(args)
        elif args.ca_command == 'check-revoked':
            ca_check_revoked_command(args)
        elif args.ca_command == 'issue-ocsp-cert':
            ca_issue_ocsp_cert_command(args)
        elif args.ca_command == 'compromise':
            ca_compromise_command(args)
        else:
            ca_parser.print_help()
            sys.exit(1)

    elif args.command == 'db':
        if args.db_command == 'init':
            db_init_command(args)
        elif args.db_command == 'list':
            db_list_command(args)
        elif args.db_command == 'show':
            db_show_command(args)
        elif args.db_command == 'export':
            db_export_command(args)
        elif args.db_command == 'stats':
            db_stats_command(args)
        else:
            db_parser.print_help()
            sys.exit(1)

    elif args.command == 'repo':
        if args.repo_command == 'serve':
            repo_serve_command(args)
        else:
            repo_parser.print_help()
            sys.exit(1)

    elif args.command == 'server':
        if args.server_command == 'start':
            repo_serve_command(args)
        else:
            server_parser.print_help()
            sys.exit(1)

    elif args.command == 'ocsp':
        if args.ocsp_command == 'serve':
            ocsp_serve_command(args)
        else:
            ocsp_parser.print_help()
            sys.exit(1)

    elif args.command == 'client':
        if args.client_command == 'gen-csr':
            client_gen_csr_command(args)
        elif args.client_command == 'request-cert':
            client_request_cert_command(args)
        elif args.client_command == 'validate':
            client_validate_command(args)
        elif args.client_command == 'check-status':
            client_check_status_command(args)
        elif args.client_command == 'sign':
            client_sign_command(args)
        elif args.client_command == 'verify':
            client_verify_command(args)
        else:
            client_parser.print_help()
            sys.exit(1)

    elif args.command == 'audit':
        if args.audit_command == 'query':
            audit_query_command(args)
        elif args.audit_command == 'verify':
            audit_verify_command(args)
        elif args.audit_command == 'ct-verify':
            audit_ct_verify_command(args)
        else:
            audit_parser.print_help()
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()