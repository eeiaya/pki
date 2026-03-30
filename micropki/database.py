
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import json

from cryptography import x509


class CertificateDatabase:


    def __init__(self, db_path: Path):

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_database()

    def _init_database(self):

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Таблица сертификатов (схема по ТЗ PKI-15)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                serial_hex TEXT UNIQUE NOT NULL,
                subject TEXT NOT NULL,
                issuer TEXT NOT NULL,
                not_before TEXT NOT NULL,
                not_after TEXT NOT NULL,
                cert_pem TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'valid',
                template TEXT,
                san_entries TEXT,
                revocation_reason TEXT,
                revocation_date TEXT,
                created_at TEXT NOT NULL
            )
        ''')

        # Индексы для производительности
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_serial_hex 
            ON certificates(serial_hex)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_status 
            ON certificates(status)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_subject 
            ON certificates(subject)
        ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_issuer 
            ON certificates(issuer)
        ''')

        conn.commit()
        conn.close()

    def add_certificate(
            self,
            certificate: x509.Certificate,
            certificate_pem: str,
            template: Optional[str] = None,
            san_entries: Optional[List[str]] = None
    ) -> str:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        serial_hex = format(certificate.serial_number, 'X')
        subject = certificate.subject.rfc4514_string()
        issuer = certificate.issuer.rfc4514_string()
        not_before = certificate.not_valid_before_utc.isoformat()
        not_after = certificate.not_valid_after_utc.isoformat()
        created_at = datetime.now(timezone.utc).isoformat()
        san_json = json.dumps(san_entries) if san_entries else None

        try:
            cursor.execute('''
                INSERT INTO certificates (
                    serial_hex, subject, issuer, not_before, not_after,
                    cert_pem, status, template, san_entries, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                serial_hex, subject, issuer, not_before, not_after,
                certificate_pem, 'valid', template, san_json, created_at
            ))

            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.close()
            raise ValueError(f"Certificate with serial {serial_hex} already exists: {e}")
        finally:
            conn.close()

        return serial_hex

    def get_certificate(self, serial_hex: str) -> Optional[Dict[str, Any]]:

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Регистронезависимый поиск
        cursor.execute('''
            SELECT * FROM certificates WHERE serial_hex = ? COLLATE NOCASE
        ''', (serial_hex,))

        row = cursor.fetchone()
        conn.close()

        if row is None:
            return None

        result = dict(row)
        if result['san_entries']:
            result['san_entries'] = json.loads(result['san_entries'])

        return result

    def list_certificates(
            self,
            status: Optional[str] = None,
            template: Optional[str] = None,
            issuer: Optional[str] = None,
            limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM certificates WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if template:
            query += " AND template = ?"
            params.append(template)

        if issuer:
            query += " AND issuer LIKE ?"
            params.append(f"%{issuer}%")

        query += " ORDER BY created_at DESC"

        if limit:
            query += f" LIMIT {int(limit)}"

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            result = dict(row)
            if result['san_entries']:
                result['san_entries'] = json.loads(result['san_entries'])
            results.append(result)

        return results

    def update_status(
            self,
            serial_hex: str,
            status: str,
            revocation_reason: Optional[str] = None
    ) -> bool:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        revocation_date = None
        if status == 'revoked':
            revocation_date = datetime.now(timezone.utc).isoformat()

        cursor.execute('''
            UPDATE certificates
            SET status = ?, revocation_reason = ?, revocation_date = ?
            WHERE serial_hex = ? COLLATE NOCASE
        ''', (status, revocation_reason, revocation_date, serial_hex))

        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()

        return rows_affected > 0

    def get_revoked_certificates(self) -> List[Dict[str, Any]]:

        return self.list_certificates(status='revoked')

    def get_statistics(self) -> Dict[str, Any]:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM certificates")
        total = cursor.fetchone()[0]

        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM certificates
            GROUP BY status
        ''')
        by_status = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute('''
            SELECT template, COUNT(*) as count
            FROM certificates
            WHERE template IS NOT NULL
            GROUP BY template
        ''')
        by_template = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        return {
            'total': total,
            'by_status': by_status,
            'by_template': by_template
        }

    def search_by_subject(self, subject_pattern: str) -> List[Dict[str, Any]]:

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM certificates
            WHERE subject LIKE ?
            ORDER BY created_at DESC
        ''', (subject_pattern,))

        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            result = dict(row)
            if result['san_entries']:
                result['san_entries'] = json.loads(result['san_entries'])
            results.append(result)

        return results

    def certificate_exists(self, serial_hex: str) -> bool:

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT COUNT(*) FROM certificates WHERE serial_hex = ? COLLATE NOCASE
        ''', (serial_hex,))

        count = cursor.fetchone()[0]
        conn.close()

        return count > 0