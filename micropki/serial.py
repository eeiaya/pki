
import time
import secrets
from pathlib import Path
from typing import Optional
import sqlite3


def generate_serial_number() -> int:

    timestamp = int(time.time()) & 0xFFFFFFFF
    random_part = secrets.randbits(32)

    serial = (timestamp << 32) | random_part

    serial = serial & ((1 << 63) - 1)

    if serial == 0:
        serial = secrets.randbits(63)

    return serial


def generate_serial_with_db_check(db_path: Optional[Path] = None, max_attempts: int = 10) -> int:

    for attempt in range(max_attempts):
        serial = generate_serial_number()

        # Если БД не указана, просто возвращаем
        if db_path is None or not db_path.exists():
            return serial

        # Проверяем уникальность в БД
        serial_hex = format(serial, 'X')

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT COUNT(*) FROM certificates WHERE serial_hex = ?",
            (serial_hex,)
        )
        count = cursor.fetchone()[0]
        conn.close()

        if count == 0:
            return serial

    raise RuntimeError(
        f"Failed to generate unique serial number after {max_attempts} attempts"
    )


def serial_to_hex(serial: int) -> str:
    return format(serial, 'X')


def hex_to_serial(hex_str: str) -> int:
    return int(hex_str, 16)


def is_valid_hex_serial(hex_str: str) -> bool:
    if not hex_str:
        return False

    try:
        int(hex_str, 16)
        return True
    except ValueError:
        return False