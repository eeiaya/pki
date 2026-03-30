
import sys
import argparse
from pathlib import Path
from typing import Optional

from .logger import setup_logger
from .crypto_utils import read_passphrase_file
from .ca import initialize_root_ca, issue_intermediate_ca, issue_certificate
from .database import CertificateDatabase

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
    if not args.subject or not args.subject.strip():
        raise ValueError("Subject DN cannot be empty")
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
            db_path=db_path
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
    p.add_argument('--subject', required=True)
    p.add_argument('--san', action='append')
    p.add_argument('--out-dir', default='./pki/pki1/certs')
    p.add_argument('--validity-days', type=int, default=365)
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

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()