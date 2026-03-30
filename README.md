# MicroPKI
Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

## Зависимости
- Python 3.10+
- OpenSSL
- cryptography >= 41.0.0
- fastapi >= 0.104.0
- uvicorn >= 0.24.0
- pydantic >= 2.0.0
## Установка
```bash
# Клонируйте репозиторий
git clone https://github.com/your-username/pki.git
cd pki

# Создайте виртуальное окружение
python -m venv .venv

# Активируйте (Windows PowerShell)
.venv\Scripts\Activate.ps1

# Активируйте (Linux/macOS)
source .venv/bin/activate

# Установите зависимости
pip install -r requirements.txt

# Установите проект в режиме разработки
pip install -e .
```

## Использование
### Спринт 1: Корневой CA
#### Инициализация корневого CA (RSA-4096)
```
micropki ca init \
    --subject "CN=Demo Root CA,O=MicroPKI,C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki/pki1 \
    --validity-days 3650
```
#### Инициализация корневого CA (ECC P-384)

```
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki/pki1
```
### Спринт 2: Промежуточный CA и сертификаты
#### Создание промежуточного CA
```
micropki ca issue-intermediate \
    --root-cert pki/pki1/certs/ca.cert.pem \
    --root-key pki/pki1/private/ca.key.pem \
    --root-pass-file secrets/ca.pass \
    --subject "CN=Demo Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki/pki1 \
    --validity-days 1825 \
    --pathlen 0
```
#### Выпуск серверного сертификата
```

micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template server \
    --subject "CN=example.com" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir pki/pki1/certs
```
#### Выпуск клиентского сертификата
```
micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir pki/pki1/certs
```
#### Выпуск сертификата подписи кода
```

micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir pki/pki1/certs
```
## Спринт 3: База данных и репозиторий
### Инициализация базы данных

```
micropki db init --db-path pki/pki1/certificates.db
```
При выпуске сертификатов они автоматически сохраняются в базу данных.
Дополнительные флаги не требуются.
### Просмотр списка сертификатов
```
# Таблица (по умолчанию)
micropki ca list-certs

# Фильтр по статусу
micropki ca list-certs --status valid

# Вывод в JSON
micropki ca list-certs --format json

# Вывод в CSV
micropki ca list-certs --format csv
```
Пример вывода:
```
===============================================================================================================
CERTIFICATES (5 found)
===============================================================================================================
Serial                                     Subject                             Status     Template        Expires
---------------------------------------------------------------------------------------------------------------
69C3CA912F77F1EB                           CN=code signer                      valid      code_signing    2027-03-25
69C3CA8B88E3AB72                           CN=alice                            valid      client          2027-03-25
69C3CA85206B8F4A                           CN=example.com                      valid      server          2027-03-25
69C3CA7C2A4E5D91                           CN=intermediate ca                  valid      intermediate_ca 2031-03-24
69C3CA6E4B1A3F28                           CN=root ca                          valid      root_ca         2036-03-23
===============================================================================================================
```
### Просмотр конкретного сертификата 
```
# По серийному номеру (таблица)
micropki ca show-cert 69C3CA912F77F1EB

# Вывод PEM
micropki ca show-cert 69C3CA912F77F1EB --format pem
```
Пример вывода:
```
======================================================================
CERTIFICATE DETAILS
======================================================================
Serial Number:   69C3CA912F77F1EB
Subject:         CN=code signer
Issuer:          CN=intermediate ca
Not Before:      2026-03-25T11:44:17+00:00
Not After:       2027-03-25T11:44:17+00:00
Status:          valid
Template:        code_signing
Created At:      2026-03-25T11:44:17.310524+00:00
======================================================================
```
### Экспорт сертификата из базы данных
```
micropki db export 69C3CA912F77F1EB -o exported_cert.pem
```
### Статистика базы данных
```
micropki db stats
```
Пример вывода:
```
==================================================
DATABASE STATISTICS
==================================================
Total Certificates: 5

By Status:
  valid           5

By Template:
  root_ca         1
  intermediate_ca 1
  server          1
  client          1
  code_signing    1
==================================================
```
### Запуск HTTP-сервера репозитория
```
micropki repo serve --host 127.0.0.1 --port 8080
```
Пример вывода:
```
============================================================
Starting MicroPKI Certificate Repository Server
============================================================
Host:            127.0.0.1
Port:            8080
Database:        pki/pki1/certificates.db
CA Certificates: pki/pki1/certs
------------------------------------------------------------
API Base URL:    http://127.0.0.1:8080
API Docs:        http://127.0.0.1:8080/docs
------------------------------------------------------------
Press Ctrl+C to stop.
============================================================
```
### Примеры API-запросов (curl)
```
# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/69C3CA912F77F1EB

# Скачать сертификат в PEM
curl http://localhost:8080/certificate/69C3CA912F77F1EB/pem --output cert.pem

# Список всех сертификатов
curl http://localhost:8080/certificates

# Фильтрация по статусу
curl "http://localhost:8080/certificates?status=valid"

# Фильтрация по шаблону
curl "http://localhost:8080/certificates?template=server"

# Получить корневой сертификат CA
curl http://localhost:8080/ca/root --output root-ca.pem

# Получить промежуточный сертификат CA
curl http://localhost:8080/ca/intermediate --output intermediate-ca.pem

# Статистика
curl http://localhost:8080/statistics

# Поиск по субъекту
curl "http://localhost:8080/search?q=example.com"

# Точка распространения CRL (заглушка)
curl http://localhost:8080/crl
# Ответ: 501 Not Implemented
```
### Интерактивная документация API (Swagger UI)
После запуска сервера откройте в браузере:
```
http://127.0.0.1:8080/docs
```
Swagger UI позволяет:

- Просматривать все эндпоинты API
- Тестировать запросы прямо в браузере
- Скачивать сертификаты

## Тестирование
### Модульные тесты
```

pytest tests/ -v

# Результат: 39 passed in 8.16s
```
### TEST-1: Просмотр сертификата
```
openssl x509 -in pki/pki1/certs/ca.cert.pem -text -noout

# Вывод:
# Certificate:
#     Data:
#         Version: 3 (0x2)
#         Serial Number: 529f09b6aebbea2e1f1fe180819784191d62df23
#         Signature Algorithm: sha256WithRSAEncryption
#         Issuer: CN = Demo Root CA, O = MicroPKI, C = RU
#         Validity
#             Not Before: Mar 16 14:27:57 2026 GMT
#             Not After : Mar 14 14:27:57 2036 GMT
#         Subject: CN = Demo Root CA, O = MicroPKI, C = RU
#         ...
#         X509v3 extensions:
#             X509v3 Basic Constraints: critical
#                 CA:TRUE
#             X509v3 Key Usage: critical
#                 Digital Signature, Certificate Sign, CRL Sign
#             X509v3 Subject Key Identifier:
#                 ...

openssl verify -CAfile pki/pki1/certs/ca.cert.pem pki/pki1/certs/ca.cert.pem

# Вывод: pki/pki1/certs/ca.cert.pem: OK
```
### TEST-2: Проверка соответствия ключа и сертификата
```
# Подписать тестовые данные закрытым ключом
echo -n "test message" | openssl dgst -sha256 \
    -sign pki/pki1/private/ca.key.pem \
    -out /tmp/test_signature.bin
# (Вводим парольную фразу)

# Извлечь открытый ключ из сертификата
openssl x509 -in pki/pki1/certs/ca.cert.pem -pubkey -noout > /tmp/ca_pub.pem

# Проверить подпись
echo -n "test message" | openssl dgst -sha256 \
    -verify /tmp/ca_pub.pem \
    -signature /tmp/test_signature.bin

# Ожидаемый вывод: Verified OK
```
### TEST-3: Проверка зашифрованного ключа
```

# Расшифровка ключа с правильным паролем
openssl pkey -in pki/pki1/private/ca.key.pem -noout
# Ожидаемый вывод: команда завершается без ошибок

# Расшифровка с неправильным паролем
openssl pkey -in pki/pki1/private/ca.key.pem -noout -passin pass:wrong_password
# Ожидаемый вывод: ошибка расшифровки
```
### TEST-4: Негативные тесты
```

# 4A: Отсутствует --subject
micropki ca init --passphrase-file secrets/ca.pass
# Результат: error: the following arguments are required: --subject

# 4B: Неправильный --key-size для ECC
micropki ca init --subject "CN=Test" --key-type ecc --key-size 4096 --passphrase-file secrets/ca.pass
# Результат: Error: ECC key size must be 384 bits (P-384)

# 4C: Несуществующий --passphrase-file
micropki ca init --subject "CN=Test" --passphrase-file nonexistent/file.pass
# Результат: Error: Passphrase file not found

# 4D: Некорректный DN
micropki ca init --subject "invalid-dn" --passphrase-file secrets/ca.pass
# Результат: Error: Invalid DN component: invalid-dn
```
### TEST-5: Проверка цепочки сертификатов (Спринт 2)
```
# Проверка промежуточного CA
openssl verify -CAfile pki/pki1/certs/ca.cert.pem pki/pki1/certs/intermediate.cert.pem
# Вывод: pki/pki1/certs/intermediate.cert.pem: OK

# Проверка конечного сертификата через полную цепочку
openssl verify \
    -CAfile pki/pki1/certs/ca.cert.pem \
    -untrusted pki/pki1/certs/intermediate.cert.pem \
    pki/pki1/certs/example.com.cert.pem
# Вывод: pki/pki1/certs/example.com.cert.pem: OK
```
### TEST-6: Проверка расширений серверного сертификата
```
openssl x509 -in pki/pki1/certs/example.com.cert.pem -text -noout | grep -A 20 "X509v3 extensions"

# Ожидаемый вывод:
#     X509v3 extensions:
#         X509v3 Basic Constraints: critical
#             CA:FALSE
#         X509v3 Key Usage: critical
#             Digital Signature, Key Encipherment
#         X509v3 Extended Key Usage:
#             TLS Web Server Authentication
#         X509v3 Subject Alternative Name:
#             DNS:example.com, DNS:www.example.com, IP Address:192.168.1.10
```
### TEST-7: Негативные тесты шаблонов (Спринт 2)
```

# Серверный сертификат без SAN — должен быть отклонён
micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template server \
    --subject "CN=test.com"
# Результат: Error: Template 'server' requires at least one SAN entry

# Email SAN для серверного сертификата — должен быть отклонён
micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template server \
    --subject "CN=test.com" \
    --san email:test@test.com
# Результат: Error: SAN type 'email' is not allowed for template 'server'
```
### TEST-8: Вставка в базу данных и получение через CLI
```
# Выпуск 5 сертификатов (автоматически сохраняются в БД)
micropki ca init --subject "CN=Root CA" --passphrase-file secrets/ca.pass
micropki ca issue-intermediate --root-cert pki/pki1/certs/ca.cert.pem \
    --root-key pki/pki1/private/ca.key.pem --root-pass-file secrets/ca.pass \
    --subject "CN=Intermediate CA" --passphrase-file secrets/ca.pass
micropki ca issue-cert --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem --ca-pass-file secrets/ca.pass \
    --template server --subject "CN=example.com" --san dns:example.com
micropki ca issue-cert --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem --ca-pass-file secrets/ca.pass \
    --template client --subject "CN=Alice" --san email:alice@example.com
micropki ca issue-cert --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem --ca-pass-file secrets/ca.pass \
    --template code_signing --subject "CN=Code Signer"

# Проверка: в БД должно быть 5 сертификатов
micropki db stats
# Total Certificates: 5

# Получение через CLI
micropki ca list-certs --status valid
micropki ca show-cert <serial>
```
### TEST-9: API репозитория — получение сертификата
```
# Запустить сервер (в отдельном терминале)
micropki repo serve --port 8080

# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/69C3CA912F77F1EB

# Скачать PEM и сравнить с файлом
curl http://localhost:8080/certificate/69C3CA912F77F1EB/pem --output api_cert.pem
diff api_cert.pem pki/pki1/certs/code_signer.cert.pem
# Ожидаемый результат: файлы идентичны
```
### TEST-10: API репозитория — получение CA сертификатов
```
curl http://localhost:8080/ca/root --output api_root.pem
diff api_root.pem pki/pki1/certs/ca.cert.pem
# Ожидаемый результат: файлы идентичны

curl http://localhost:8080/ca/intermediate --output api_intermediate.pem
diff api_intermediate.pem pki/pki1/certs/intermediate.cert.pem
# Ожидаемый результат: файлы идентичны
```
### TEST-11: Невалидный серийный номер — 400 Bad Request
```
curl http://localhost:8080/certificate/INVALID_XYZ
# Ожидаемый результат: 400 Bad Request

curl http://localhost:8080/certificate/12G45
# Ожидаемый результат: 400 Bad Request
```
### TEST-12: CRL заглушка — 501 Not Implemented
```
curl http://localhost:8080/crl
# Ожидаемый результат: 501 Not Implemented
# Тело ответа: "CRL generation not yet implemented. See Sprint 4."
```
## Структура выходных файлов
```text

pki/pki1/
├── private/
│   ├── ca.key.pem                  # зашифрованный ключ корневого CA
│   └── intermediate.key.pem        # зашифрованный ключ промежуточного CA
├── certs/
│   ├── ca.cert.pem                 # сертификат корневого CA
│   ├── intermediate.cert.pem       # сертификат промежуточного CA
│   ├── example.com.cert.pem        # серверный сертификат
│   ├── example.com.key.pem         # ключ сервера (незашифрованный)
│   ├── alice.cert.pem              # клиентский сертификат
│   ├── alice.key.pem               # ключ клиента
│   ├── code_signer.cert.pem        # сертификат подписи кода
│   └── code_signer.key.pem         # ключ подписи кода
├── csrs/
│   └── intermediate.csr.pem        # CSR промежуточного CA
├── certificates.db                  # база данных SQLite
└── policy.txt                 # документ политики УЦ
```
## Структура проекта
```text

pki/
├── micropki/
│   ├── __init__.py               # пакет
│   ├── cli.py                    # парсер аргументов CLI
│   ├── ca.py                     # логика CA (init, issue-intermediate, issue-cert)
│   ├── certificates.py           # работа с X.509 сертификатами
│   ├── chain.py                  # проверка цепочки сертификатов
│   ├── csr.py                    # генерация и обработка CSR
│   ├── crypto_utils.py           # генерация ключей, PEM, шифрование
│   ├── logger.py                 # настройка логирования
│   ├── templates.py              # шаблоны сертификатов (server/client/code_signing)
│   ├── serial.py                 # генератор уникальных серийных номеров
│   ├── database.py               # работа с SQLite (CRUD операции)
│   └── server.py                 # REST API сервер (FastAPI)
├── tests/
│   ├── test_ca.py                # тесты спринтов 1-2 (39 тестов)
│   └── test_sprint3.py           # тесты спринта 3 (18 тестов)
├── pki/pki1/                     # выходные файлы PKI (в .gitignore)
├── secrets/                      # пароли (в .gitignore)
├── logs/                         # логи (в .gitignore)
├── .gitignore
├── requirements.txt
├── setup.py
└── README.md
```
## Схема базы данных (SQLite)
```
CREATE TABLE certificates (
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
);

-- Индексы
CREATE INDEX idx_serial_hex ON certificates(serial_hex);
CREATE INDEX idx_status ON certificates(status);
CREATE INDEX idx_subject ON certificates(subject);
CREATE INDEX idx_issuer ON certificates(issuer);

```