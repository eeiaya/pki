
import pytest
import tempfile
import time
from pathlib import Path

from micropki.serial import (
    generate_serial_number,
    generate_serial_with_db_check,
    serial_to_hex,
    hex_to_serial,
    is_valid_hex_serial
)
from micropki.database import CertificateDatabase
from micropki.crypto_utils import generate_rsa_key_pair
from micropki.certificates import (
    parse_subject_dn,
    create_self_signed_certificate
)


class TestSerialNumber:
    """Тесты генератора серийных номеров."""

    def test_generate_serial_positive(self):
        """Серийный номер должен быть положительным."""
        for _ in range(100):
            serial = generate_serial_number()
            assert serial > 0

    def test_generate_serial_unique(self):
        """100 серийников должны быть уникальны."""
        serials = set()
        for _ in range(100):
            serial = generate_serial_number()
            assert serial not in serials, "Duplicate serial!"
            serials.add(serial)

        assert len(serials) == 100

    def test_generate_serial_contains_timestamp(self):
        """Серийник должен содержать timestamp в старших битах."""
        serial = generate_serial_number()
        timestamp_part = serial >> 32
        current_time = int(time.time())

        # Timestamp должен быть близок к текущему времени (±2 сек)
        assert abs(timestamp_part - current_time) < 2

    def test_serial_to_hex(self):
        """Конвертация serial -> hex."""
        assert serial_to_hex(255) == "FF"
        assert serial_to_hex(4096) == "1000"

    def test_hex_to_serial(self):
        """Конвертация hex -> serial."""
        assert hex_to_serial("FF") == 255
        assert hex_to_serial("ff") == 255
        assert hex_to_serial("1000") == 4096

    def test_is_valid_hex_serial(self):
        """Валидация hex строки."""
        assert is_valid_hex_serial("ABC123") is True
        assert is_valid_hex_serial("abc123def") is True
        assert is_valid_hex_serial("0") is True

        assert is_valid_hex_serial("") is False
        assert is_valid_hex_serial("XYZ") is False
        assert is_valid_hex_serial("12G45") is False
        assert is_valid_hex_serial(None) is False


class TestDatabaseCRUD:
    """Тесты CRUD операций базы данных."""

    @pytest.fixture
    def db(self):
        """Создаёт временную БД для тестов."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            yield CertificateDatabase(db_path)

    @pytest.fixture
    def sample_cert(self):
        """Создаёт тестовый сертификат."""
        key = generate_rsa_key_pair(4096)
        subject = parse_subject_dn("CN=Test Cert")
        cert = create_self_signed_certificate(key, subject, 365)

        from cryptography.hazmat.primitives import serialization
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()

        return cert, pem

    def test_add_and_get_certificate(self, db, sample_cert):
        """Добавление и получение сертификата."""
        cert, pem = sample_cert

        serial = db.add_certificate(cert, pem, template='server', san_entries=['dns:test.com'])

        assert serial is not None

        retrieved = db.get_certificate(serial)
        assert retrieved is not None
        assert retrieved['subject'] == "CN=Test Cert"
        assert retrieved['status'] == 'valid'
        assert retrieved['template'] == 'server'
        assert 'dns:test.com' in retrieved['san_entries']

    def test_get_nonexistent(self, db):
        """Получение несуществующего сертификата."""
        result = db.get_certificate("NONEXISTENT")
        assert result is None

    def test_list_certificates(self, db, sample_cert):
        """Список сертификатов."""
        cert, pem = sample_cert
        db.add_certificate(cert, pem, template='server')

        certs = db.list_certificates()
        assert len(certs) == 1

    def test_list_with_status_filter(self, db, sample_cert):
        """Фильтрация по статусу."""
        cert, pem = sample_cert
        serial = db.add_certificate(cert, pem)

        valid_certs = db.list_certificates(status='valid')
        assert len(valid_certs) == 1

        revoked_certs = db.list_certificates(status='revoked')
        assert len(revoked_certs) == 0

    def test_update_status(self, db, sample_cert):
        """Обновление статуса сертификата."""
        cert, pem = sample_cert
        serial = db.add_certificate(cert, pem)

        result = db.update_status(serial, 'revoked', 'keyCompromise')
        assert result is True

        updated = db.get_certificate(serial)
        assert updated['status'] == 'revoked'
        assert updated['revocation_reason'] == 'keyCompromise'
        assert updated['revocation_date'] is not None

    def test_get_revoked(self, db, sample_cert):
        """Получение отозванных сертификатов."""
        cert, pem = sample_cert
        serial = db.add_certificate(cert, pem)
        db.update_status(serial, 'revoked', 'test')

        revoked = db.get_revoked_certificates()
        assert len(revoked) == 1

    def test_statistics(self, db, sample_cert):
        """Статистика."""
        cert, pem = sample_cert
        db.add_certificate(cert, pem, template='server')

        stats = db.get_statistics()
        assert stats['total'] == 1
        assert stats['by_status'].get('valid', 0) == 1
        assert stats['by_template'].get('server', 0) == 1

    def test_duplicate_serial_rejected(self, db, sample_cert):
        """Дубликат серийника отклоняется."""
        cert, pem = sample_cert
        db.add_certificate(cert, pem)

        with pytest.raises(ValueError, match="already exists"):
            db.add_certificate(cert, pem)

    def test_case_insensitive_lookup(self, db, sample_cert):
        """Регистронезависимый поиск."""
        cert, pem = sample_cert
        serial = db.add_certificate(cert, pem)

        # Ищем в нижнем регистре
        result = db.get_certificate(serial.lower())
        assert result is not None

        # Ищем в верхнем
        result = db.get_certificate(serial.upper())
        assert result is not None


class TestLoadSerialUniqueness:
    """Нагрузочный тест уникальности серийников (TEST-17)."""

    def test_100_unique_serials(self):
        """Генерация 100 уникальных серийников."""
        serials = set()

        for i in range(100):
            serial = generate_serial_number()
            hex_serial = serial_to_hex(serial)

            assert hex_serial not in serials, f"Duplicate at iteration {i}: {hex_serial}"
            serials.add(hex_serial)

        assert len(serials) == 100


class TestAPIValidation:
    """Тесты валидации для API."""

    def test_invalid_hex_formats(self):
        """Невалидные hex строки."""
        invalid = ["XYZ", "12G45", "hello", "123!", " ", ""]

        for s in invalid:
            assert is_valid_hex_serial(s) is False, f"{s} should be invalid"

    def test_valid_hex_formats(self):
        """Валидные hex строки."""
        valid = ["0", "A", "abc", "ABC123", "deadbeef", "DEADBEEF"]

        for s in valid:
            assert is_valid_hex_serial(s) is True, f"{s} should be valid"