
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

    def _init_database(self):
        """Инициализация базы данных с обеими таблицами."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Таблица сертификатов (существующая)
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

        # === НОВОЕ: Таблица метаданных CRL (DB-6) ===
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crl_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ca_subject TEXT NOT NULL UNIQUE,
                crl_number INTEGER NOT NULL,
                last_generated TEXT NOT NULL,
                next_update TEXT NOT NULL,
                crl_path TEXT NOT NULL
            )
        ''')

        # Индексы
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

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ca_subject 
            ON crl_metadata(ca_subject)
        ''')
        cursor.execute('''
             CREATE TABLE IF NOT EXISTS crl_metadata (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       ca_subject TEXT NOT NULL UNIQUE,
                       crl_number INTEGER NOT NULL,
                       last_generated TEXT NOT NULL,
                       next_update TEXT NOT NULL,
                       crl_path TEXT NOT NULL
                   )
               ''')

        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_ca_subject 
                   ON crl_metadata(ca_subject)
               ''')

        conn.commit()
        conn.close()

    # === НОВЫЕ МЕТОДЫ ДЛЯ РАБОТЫ С ОТЗЫВОМ ===

    def revoke_certificate(
            self,
            serial_hex: str,
            reason: str = 'unspecified'
    ) -> bool:
        """
        Отзывает сертификат (CRL-3).

        Args:
            serial_hex: Серийный номер сертификата
            reason: Причина отзыва (строка)

        Returns:
            True если сертификат был отозван, False если уже был отозван

        Raises:
            ValueError: Если сертификат не найден
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Проверяем существование сертификата
        cursor.execute('''
            SELECT status FROM certificates 
            WHERE serial_hex = ? COLLATE NOCASE
        ''', (serial_hex,))

        row = cursor.fetchone()

        if row is None:
            conn.close()
            raise ValueError(f"Certificate with serial {serial_hex} not found")

        current_status = row[0]

        # Если уже отозван - возвращаем False
        if current_status == 'revoked':
            conn.close()
            return False

        # Отзываем сертификат
        revocation_date = datetime.now(timezone.utc).isoformat()

        cursor.execute('''
            UPDATE certificates
            SET status = 'revoked',
                revocation_reason = ?,
                revocation_date = ?
            WHERE serial_hex = ? COLLATE NOCASE
        ''', (reason, revocation_date, serial_hex))

        conn.commit()
        conn.close()

        return True

    def get_revoked_by_issuer(self, issuer_dn: str) -> List[Dict[str, Any]]:
        """
        Получает все отозванные сертификаты для указанного издателя (CA).

        Args:
            issuer_dn: DN издателя (CA)

        Returns:
            Список словарей с данными отозванных сертификатов
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM certificates
            WHERE issuer = ? AND status = 'revoked'
            ORDER BY revocation_date ASC
        ''', (issuer_dn,))

        rows = cursor.fetchall()
        conn.close()

        results = []
        for row in rows:
            result = dict(row)
            if result['san_entries']:
                result['san_entries'] = json.loads(result['san_entries'])
            results.append(result)

        return results

    def get_crl_metadata(self, ca_subject: str) -> Optional[Dict[str, Any]]:
        """
        Получает метаданные CRL для указанного CA.

        Args:
            ca_subject: DN CA

        Returns:
            Словарь с метаданными или None
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM crl_metadata WHERE ca_subject = ?
        ''', (ca_subject,))

        row = cursor.fetchone()
        conn.close()

        return dict(row) if row else None

    def update_crl_metadata(
            self,
            ca_subject: str,
            crl_number: int,
            next_update: str,
            crl_path: str
    ) -> None:
        """
        Обновляет или создаёт метаданные CRL для CA.

        Args:
            ca_subject: DN CA
            crl_number: Номер CRL
            next_update: ISO 8601 дата следующего обновления
            crl_path: Путь к файлу CRL
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        last_generated = datetime.now(timezone.utc).isoformat()

        cursor.execute('''
            INSERT INTO crl_metadata (ca_subject, crl_number, last_generated, next_update, crl_path)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(ca_subject) DO UPDATE SET
                crl_number = excluded.crl_number,
                last_generated = excluded.last_generated,
                next_update = excluded.next_update,
                crl_path = excluded.crl_path
        ''', (ca_subject, crl_number, last_generated, next_update, crl_path))

        conn.commit()
        conn.close()