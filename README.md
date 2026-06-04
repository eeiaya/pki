# MicroPKI
#### Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

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
## Дополнительная документация
* demo/DEMO.md — пошаговое описание автоматизированной демонстрации
* docs/ARCHITECTURE.md — схема архитектуры (Mermaid) и описание компонентов
* docs/SECURITY.md — аспекты безопасности, threat model, ограничения
* docs/API.md — полный справочник по HTTP API
## Быстрая демонстрация
```Bash
python demo/demo.py
````
Скрипт развернёт полную PKI во временной директории и проведёт все 25 шагов: создание CA → выпуск сертификатов → запуск серверов → валидация → отзыв → подпись кода → проверка аудита.
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
### Спринт 3: База данных и репозиторий
#### Инициализация базы данных

```
micropki db init --db-path pki/pki1/certificates.db
```
При выпуске сертификатов они автоматически сохраняются в базу данных.
Дополнительные флаги не требуются.
#### Просмотр списка сертификатов
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
#### Просмотр конкретного сертификата 
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
#### Экспорт сертификата из базы данных
```
micropki db export 69C3CA912F77F1EB -o exported_cert.pem
```
#### Статистика базы данных
```
micropki db stats
```
##### Пример вывода:
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
#### Запуск HTTP-сервера репозитория
```
micropki repo serve --host 127.0.0.1 --port 8080
```
##### Пример вывода:
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
#### Примеры API-запросов (curl)
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
#### Интерактивная документация API (Swagger UI)
После запуска сервера откройте в браузере:
```
http://127.0.0.1:8080/docs
```
Swagger UI позволяет:

- Просматривать все эндпоинты API
- Тестировать запросы прямо в браузере
- Скачивать сертификаты

### Спринт 4: Отзыв сертификатов и CRL

#### Отзыв сертификата

```bash
# Посмотреть список сертификатов
micropki ca list-certs

# Отозвать с подтверждением
micropki ca revoke 69C3CA5D7A53717F --reason keyCompromise

# Отозвать без подтверждения
micropki ca revoke 69C3CA5D7A53717F --reason superseded --force

# Проверить статус
micropki ca check-revoked 69C3CA5D7A53717F
```
#### Поддерживаемые причины отзыва (RFC 5280):

| Код | 	Причина	   | Описание | 
|-|-------------|---|
|0| unspecified |Не указана (по умолчанию)|
|1|	keyCompromise|	Компрометация ключа|
|2|	cACompromise|	Компрометация CA|
|3|	affiliationChanged|	Изменение принадлежности|
|4|	superseded|	Заменён новым сертификатом|
|5|	cessationOfOperation|	Прекращение деятельности|
|6|	certificateHold|	Временная приостановка|
|8|	removeFromCRL|	Удаление из CRL|
|9|	privilegeWithdrawn|	Отзыв привилегий|
|10|	aACompromise|	Компрометация AA|

#### Генерация CRL
```
# CRL для корневого CA
micropki ca gen-crl --ca root --ca-pass-file secrets/ca.pass

# CRL для промежуточного CA
micropki ca gen-crl --ca intermediate --ca-pass-file secrets/ca.pass

# С указанием срока (дней до следующего обновления)
micropki ca gen-crl --ca intermediate --ca-pass-file secrets/ca.pass --next-update 14

# Сохранить в произвольный файл
micropki ca gen-crl --ca root --ca-pass-file secrets/ca.pass --out-file ./backup/root.crl.pem
```
#### Получение CRL через API
```
# CRL промежуточного CA (по умолчанию)
curl http://localhost:8080/crl

# CRL корневого CA
curl http://localhost:8080/crl?ca=root

# Альтернативный путь
curl http://localhost:8080/crl/intermediate.crl
curl http://localhost:8080/crl/root.crl
```
 
### Спринт 5: OCSP-ответчик

#### Выпуск сертификата OCSP-ответчика

 Сертификат OCSP-ответчика выпускается промежуточным CA и имеет специальное расширение Extended Key Usage = OCSPSigning.

```bash
micropki ca issue-ocsp-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir pki/pki1/certs \
    --validity-days 365
````
 В каталоге pki/pki1/certs/ появятся два файла:

* ocsp.cert.pem — сертификат OCSP-ответчика
* ocsp.key.pem — приватный ключ без шифрования (нужно для автозагрузки сервером)

Важно: приватный ключ OCSP-ответчика хранится без пароля. Защищайте его правами доступа файловой системы.
#### Запуск OCSP-ответчика
OCSP-ответчик работает как отдельный HTTP-сервер на порту 8081:
```bash
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path pki/pki1/certificates.db \
    --responder-cert pki/pki1/certs/ocsp.cert.pem \
    --responder-key pki/pki1/certs/ocsp.key.pem \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --cache-ttl 60
```
Пример вывода:
```text
============================================================
MicroPKI OCSP Responder
============================================================
Host:      127.0.0.1
Port:      8081
Endpoint:  http://127.0.0.1:8081/ocsp
Cache TTL: 60s
------------------------------------------------------------
Press Ctrl+C to stop.
============================================================
```
#### Эндпоинт OCSP
| Параметр             | Значение |
|----------------------|----------|
| Метод                | POST     |
| URL                  | http://127.0.0.1:8081/ocsp |
| Content-Type запроса | application/ocsp-request   |
| Content-Type ответа  | application/ocsp-response  |
| Тело запроса         | DER-кодированный OCSPRequest (RFC 6960)|
| Тело ответа          | DER-кодированный OCSPResponse (RFC 6960)|

#### Что такое nonce
nonce — это случайное значение, которое клиент включает в OCSP-запрос. OCSP-ответчик обязан вернуть точно тот же nonce в ответе.
Зачем это нужно:

* защита от replay-атак (нельзя подсунуть старый кэшированный ответ)
* подтверждение, что ответ свежий и относится к конкретному запросу

Если в запросе nonce есть — он должен быть в ответе.
Если в запросе nonce нет — ответчик НЕ добавляет его в ответ.

#### Проверка работы OCSP
После запуска ответчика проверки можно делать через Python.
##### Проверка статуса GOOD
```PowerShell
@'
from urllib.request import Request, urlopen
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization

def load_cert(p):
    with open(p, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

issuer = load_cert("pki/pki1/certs/intermediate.cert.pem")
cert = load_cert("pki/pki1/certs/alice.cert.pem")

req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
data = req.public_bytes(serialization.Encoding.DER)

r = Request("http://127.0.0.1:8081/ocsp", data=data,
            headers={"Content-Type": "application/ocsp-request"}, method="POST")
with urlopen(r) as resp:
    body = resp.read()

result = ocsp.load_der_ocsp_response(body)
print("Cert status:", result.certificate_status)
'@ | python -
```
Ожидаемый вывод:
```text
Cert status: OCSPCertStatus.GOOD
```
#### Проверка статуса REVOKED
```PowerShell
@'
from urllib.request import Request, urlopen
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization

def load_cert(p):
    with open(p, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

issuer = load_cert("pki/pki1/certs/intermediate.cert.pem")
cert = load_cert("pki/pki1/certs/example.com.cert.pem")

req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
data = req.public_bytes(serialization.Encoding.DER)

r = Request("http://127.0.0.1:8081/ocsp", data=data,
            headers={"Content-Type": "application/ocsp-request"}, method="POST")
with urlopen(r) as resp:
    body = resp.read()

result = ocsp.load_der_ocsp_response(body)
print("Cert status:    ", result.certificate_status)
print("Revocation time:", result.revocation_time_utc)
print("Reason:         ", result.revocation_reason)
'@ | python -
```
##### Ожидаемый вывод:
```text
Cert status:     OCSPCertStatus.REVOKED
Revocation time: 2026-...
Reason:          ReasonFlags.key_compromise
```
#### Проверка nonce
```PowerShell
@'
import os
from urllib.request import Request, urlopen
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import hashes, serialization

def load_cert(p):
    with open(p, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

issuer = load_cert("pki/pki1/certs/intermediate.cert.pem")
cert = load_cert("pki/pki1/certs/alice.cert.pem")

nonce = os.urandom(16)
builder = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1())
builder = builder.add_extension(x509.OCSPNonce(nonce), critical=False)
req = builder.build()

data = req.public_bytes(serialization.Encoding.DER)
r = Request("http://127.0.0.1:8081/ocsp", data=data,
            headers={"Content-Type": "application/ocsp-request"}, method="POST")
with urlopen(r) as resp:
    body = resp.read()

result = ocsp.load_der_ocsp_response(body)
resp_nonce = result.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
print("Match:", nonce == resp_nonce)
'@ | python -
```
##### Ожидаемый вывод:
```text
Match: True
```
#### Проверка через OpenSSL
Если установлен OpenSSL, можно использовать стандартный клиент:
```bash
# Запрос статуса сертификата
openssl ocsp \
    -issuer pki/pki1/certs/intermediate.cert.pem \
    -cert pki/pki1/certs/alice.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -resp_text \
    -noverify

# Проверка подписи ответа
openssl ocsp \
    -issuer pki/pki1/certs/intermediate.cert.pem \
    -cert pki/pki1/certs/alice.cert.pem \
    -url http://127.0.0.1:8081/ocsp \
    -CAfile pki/pki1/certs/ca.cert.pem \
    -VAfile pki/pki1/certs/ocsp.cert.pem
```
### Спринт 6: Клиентские инструменты и проверка цепочки

#### Генерация CSR

```bash
micropki client gen-csr \
    --subject "CN=app.example.com,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:app.example.com \
    --san dns:api.example.com \
    --out-key ./app.key.pem \
    --out-csr ./app.csr.pem
```
#### Создаёт:

* app.key.pem — приватный ключ (без шифрования, 0o600)
* app.csr.pem — запрос на подпись сертификата (PKCS#10)
#### Запрос сертификата через API
```bash
micropki client request-cert \
    --csr ./app.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./app.cert.pem \
    --api-key changeme
```
#### Требоания:
* Сервер репозитория должен быть запущен (micropki repo serve)
* API-ключ передаётся в заголовке X-API-Key (по умолчанию changeme)

#### Проверка цепочки сертификатов
```bash
# Базовая проверка (подписи + сроки)
micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/pki1/certs/intermediate.cert.pem \
    --trusted ./pki/pki1/certs/ca.cert.pem \
    --mode chain

# Полная проверка (с отзывом через CRL)
micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/pki1/certs/intermediate.cert.pem \
    --trusted ./pki/pki1/certs/ca.cert.pem \
    --crl ./pki/pki1/crl/intermediate.crl.pem \
    --mode full

# С проверкой через OCSP
micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/pki1/certs/intermediate.cert.pem \
    --trusted ./pki/pki1/certs/ca.cert.pem \
    --ocsp \
    --mode full

# JSON-вывод для автоматизации
micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/pki1/certs/intermediate.cert.pem \
    --trusted ./pki/pki1/certs/ca.cert.pem \
    --format json
```
#### Проверяется:
* Построение цепочки до доверенного корня
* Подписи всех сертификатов
* Сроки действия (notBefore/notAfter)
* BasicConstraints (CA flag, pathLen)
* KeyUsage (keyCertSign для CA)
* ExtendedKeyUsage (опционально через --check-eku)
* Статус отзыва (CRL и/или OCSP)

#### Проверка статуса отзыва
```bash
# Автоматически (OCSP из AIA → fallback на CRL из CDP)
micropki client check-status \
    --cert ./app.cert.pem \
    --ca-cert ./pki/pki1/certs/intermediate.cert.pem

# Принудительно через OCSP
micropki client check-status \
    --cert ./app.cert.pem \
    --ca-cert ./pki/pki1/certs/intermediate.cert.pem \
    --ocsp-url http://127.0.0.1:8081/ocsp

# Принудительно через CRL
micropki client check-status \
    --cert ./app.cert.pem \
    --ca-cert ./pki/pki1/certs/intermediate.cert.pem \
    --crl ./pki/pki1/crl/intermediate.crl.pem
```
#### Логика проверки отзыва:
* Сначала пробуем OCSP (если URL доступен)
* Если OCSP недоступен → fallback на CRL
* Если оба недоступны → статус unknown

#### Вывод:
* GOOD — сертификат действителен
* REVOKED — отозван (с датой и причиной)
* UNKNOWN — не удалось определить

#### Подпись внешнего CSR через CA
```bash
micropki ca issue-cert \
    --ca-cert ./pki/pki1/certs/intermediate.cert.pem \
    --ca-key ./pki/pki1/private/intermediate.key.pem \
    --ca-pass-file ./secrets/ca.pass \
    --template server \
    --csr ./app.csr.pem \
    --out-dir ./pki/pki1/certs
```
#### Особенности:

* Subject и SAN берутся из CSR (игнорируются --subject и --san)
* Проверяется подпись CSR
* Отклоняются CSR с CA=TRUE
* Ключ не генерируется (используется из CSR)

## Спринт 7: Аудит, политики безопасности и средства защиты

### Система аудита

Все критичные операции (выпуск, отзыв, компрометация, инициализация CA) автоматически логируются в:
- `pki/pki1/audit/audit.log` — NDJSON формат с хеш-цепочкой SHA-256
- `pki/pki1/audit/chain.dat` — последний хеш цепочки для быстрой верификации
- `pki/pki1/audit/ct.log` — симуляция Certificate Transparency

Каждая запись содержит хеш предыдущей записи (`prev_hash`) и собственный хеш (`hash`), что обеспечивает криптографическую целостность.

#### Просмотр журнала аудита

```bash
# Все записи (таблица)
micropki audit query

# Фильтр по операции
micropki audit query --operation issue_certificate

# Фильтр по уровню
micropki audit query --level AUDIT

# Фильтр по серийному номеру
micropki audit query --serial 6A1C2FB87A3E4172

# Фильтр по времени
micropki audit query --from 2026-05-31T00:00:00Z --to 2026-05-31T23:59:59Z

# JSON-формат
micropki audit query --format json

# CSV-формат
micropki audit query --format csv

# С проверкой целостности
micropki audit query --verify
```
#### Проверка целостности аудита
```Bash
micropki audit verify
```
#### Вывод:

```text
✓ Audit log integrity OK: pki\pki1\audit\audit.log
```
#### Если файл был подделан:

```text
✗ Audit log integrity FAILED
  First bad line: 2
  Reason: Entry hash mismatch at line 2: expected ..., got ...
```
### Certificate Transparency (CT) log
#### При каждом выпуске сертификата запись добавляется в ct.log в формате:

```text

<timestamp>  <serial>  <subject>  <sha256-fingerprint>  <issuer>
```
#### Проверка наличия сертификата:

```Bash
micropki audit ct-verify 6A1C2FB87A3E4172
```
### Политики безопасности
##### Все операции выпуска сертификатов проверяются на соответствие политикам. При нарушении выпуск блокируется и фиксируется в аудите.

#### Размер ключа (POL-3)

| Тип             | RSA | ECC |
|-----------------|-----|-----|
| Root CA         | ≥ 4096 бит | ≥ P-384 |
| Intermediate CA | ≥ 3072 бит | ≥ P-384 |
| End-entity      | ≥ 2048 бит | ≥ P-256 |

#### Срок действия (POL-4)
| Тип     | Максимум |
|---------|----------|
| Root CA | 3650 дней (10 лет) |
| Intermediate CA | 1825 дней (5 лет) |
|  End-entity  | 365 дней (1 год) |

#### SAN (POL-5)
| Шаблон | Разрешенные типы | Запрещено |
|-------|----------|---------|
| server|  dns, ip | email, uri, wildcard (*.example.com) |
| client|  email, dns (требуется email)| ip, uri |
| code_signing | dns, uri | ip, email|

#### Алгоритм подписи (POL-6)
* SHA-1 отклоняется
* RSA: только SHA-256/384/512
* ECC P-256: только SHA-256
* ECC P-384: только SHA-384

#### Длина пути CA (POL-7)
* Root CA: без ограничения
* Intermediate CA: pathLen = 0 (не может выпускать другие CA)

### Примеры нарушений политик
```bash
# Слишком длинный срок (max 365)
micropki ca issue-cert --validity-days 400 ... 
# ✗ Error: End-entity certificate validity cannot exceed 365 days

# Wildcard SAN
micropki ca issue-cert --template server --san "dns:*.example.com" ...
# ✗ Error: Wildcard SAN entries are forbidden by default

# Email SAN для server
micropki ca issue-cert --template server --san "email:admin@example.com" ...
# ✗ Error: SAN type 'email' is not allowed for template 'server'
```
### Симуляция компрометации ключа
##### При компрометации закрытого ключа:

* Сертификат немедленно отзывается с причиной keyCompromise
* Публичный ключ заносится в таблицу compromised_keys
* Генерируется экстренный CRL
* Будущие CSR с этим ключом блокируются
```bash
micropki ca compromise \
    --cert pki/pki1/certs/audit-test.com.cert.pem \
    --reason keyCompromise \
    --force \
    --ca-pass-file secrets/ca.pass
```
##### Вывод:
```text
✓ Certificate marked as compromised
  Serial:           6A1C2FB87A3E4172
  Public key hash:  af3c8d9e1b2f...
  Emergency CRL:    pki\pki1\crl\intermediate.crl.pem
```
##### После этого попытка использовать тот же ключ в новом CSR будет отклонена:
```text
✗ Error: Public key is marked as compromised; refusing to issue
```
### База данных: таблица compromised_keys
```sql
CREATE TABLE compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);
```
## Спринт 8: Подпись кода, демо и финальная интеграция
### Подпись и проверка файлов
```Bash
# Подпись файла приватным ключом code-signing сертификата
micropki client sign \
    --file ./script.sh \
    --key pki/pki1/certs/Demo_Code_Signer.key.pem \
    --out-sig ./script.sh.sig

# Проверка подписи
micropki client verify \
    --file ./script.sh \
    --cert pki/pki1/certs/Demo_Code_Signer.cert.pem \
    --sig ./script.sh.sig
```
Вывод при валидной подписи:
```text
✓ Signature VALID
  File:      ./script.sh
  Signer:    pki/pki1/certs/Demo_Code_Signer.cert.pem
```
При модификации файла:
```text
✗ Signature INVALID
```
Альтернативно с OpenSSL:

```Bash
openssl dgst -sha256 -sign code_signing.key.pem -out script.sh.sig script.sh
openssl dgst -sha256 -verify <(openssl x509 -in code_signing.cert.pem -pubkey -noout) \
    -signature script.sh.sig script.sh
````
### TLS-демонстрация
Сертификат, выпущенный MicroPKI, можно использовать для реального TLS-соединения:

```Bash
# Запуск HTTPS-сервера с выпущенным сертификатом
openssl s_server \
    -accept 8443 \
    -cert pki/pki1/certs/example.com.cert.pem \
    -key pki/pki1/certs/example.com.key.pem \
    -CAfile pki/pki1/certs/intermediate.cert.pem

# Клиент подключается с доверием к корневому CA
openssl s_client \
    -connect localhost:8443 \
    -CAfile pki/pki1/certs/ca.cert.pem \
    -showcerts
```
После отзыва сертификата и регенерации CRL клиент с проверкой отзыва (-crl_check) должен получить ошибку.

### Демонстрационный скрипт
Автоматизированный сценарий из 25 шагов, охватывающий все возможности PKI:

```Bash
python demo/demo.py
````
Подробное описание шагов: demo/DEMO.md

## Тестирование
### Модульные тесты
```
pytest tests/ -v

# Результат: 211 passed
```
С покрытием
```Bash
pytest tests/ --cov=micropki --cov-report=term-missing
# Coverage: 80%
```
### Производительность
```Bash
pytest tests/test_sprint8.py -v -s -m perf
```
### Тесты по спринтам
|Файл|	Описание|	Тестов|
|------------------|-----------|--------|
|test_ca.py|	Спринты 1-2 (Root + Intermediate CA, выпуск)|	39|
|test_sprint3.py|	БД и репозиторий|	18|
|test_sprint4.py|	Отзыв и CRL|	18|
|test_sprint5.py|	OCSP|	30|
|test_sprint6.py|	Клиент и валидация|	32|
|test_sprint7.py|	Аудит и политики|	54|
|test_sprint8.py|	Edge cases + perf + code signing|	20|


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
### TEST-12: Получение CRL через API

```
curl http://localhost:8080/crl
# Ожидаемый результат: 200 OK, Content-Type: application/pkix-crl

curl http://localhost:8080/crl?ca=root
# Ожидаемый результат: 200 OK (CRL корневого CA)
```
### TEST-13: Полный цикл отзыва
```
# 1. Выпустить сертификат
micropki ca issue-cert \
    --ca-cert pki/pki1/certs/intermediate.cert.pem \
    --ca-key pki/pki1/private/intermediate.key.pem \
    --ca-pass-file secrets/ca.pass \
    --template server \
    --subject "CN=revoke-test.com" \
    --san dns:revoke-test.com

# 2. Проверить статус — должен быть valid
micropki ca list-certs --status valid

# 3. Отозвать
micropki ca revoke <SERIAL> --reason keyCompromise --force

# 4. Проверить статус — должен быть revoked
micropki ca check-revoked <SERIAL>
# Вывод: Certificate <SERIAL>: REVOKED

# 5. Сгенерировать CRL
micropki ca gen-crl --ca intermediate --ca-pass-file secrets/ca.pass

# 6. Проверить что сертификат в CRL
python -c "
from micropki.crl import load_crl
crl = load_crl('pki/pki1/crl/intermediate.crl.pem')
print(f'Revoked certificates: {len(list(crl))}')
"
```
### TEST-14: Увеличение номера CRL
```
# Генерируем CRL дважды
micropki ca gen-crl --ca root --ca-pass-file secrets/ca.pass
# Вывод: CRL#: 1

micropki ca gen-crl --ca root --ca-pass-file secrets/ca.pass
# Вывод: CRL#: 2
```
### TEST-15: Негативные тесты отзыва
```
# Несуществующий сертификат
micropki ca revoke DEADBEEF --reason keyCompromise
# Результат: Error: Certificate with serial DEADBEEF not found

# Повторный отзыв
micropki ca revoke <SERIAL> --reason superseded
# Результат: Certificate <SERIAL> is already revoked (код возврата 0)

# Невалидная причина
micropki ca revoke <SERIAL> --reason invalidReason
# Результат: Error: Unsupported revocation reason
```
### TEST-16: CRL через HTTP API
```
# Запустить сервер
micropki repo serve --port 8080

# Получить CRL
curl http://localhost:8080/crl --output intermediate.crl.pem

# Проверить Content-Type
curl -I http://localhost:8080/crl
# Content-Type: application/pkix-crl
```
### Тесты спринта 5
```bash
pytest tests/test_sprint5.py -v
# Результат: 30 passed
```
#### Тесты покрывают:

* профиль OCSP-сертификата (BasicConstraints, KeyUsage, EKU = OCSPSigning)
* статус GOOD для valid сертификатов
* статус REVOKED с датой и причиной отзыва
* статус UNKNOWN для несуществующих серийных номеров
* echo nonce в ответе
* malformed-request обработка
* интеграционный тест полного жизненного цикла
### Тесты спринта 6
```bash
pytest tests/test_sprint6.py -v
# Результат: 32 passed
```
#### Тесты покрывают:

* Генерацию CSR (RSA/ECC, subject, SAN, подпись)
* Подпись CSR через CA
* Построение и валидацию цепочки
* Проверку сроков действия
* Проверку EKU
* Проверку отзыва через CRL и OCSP
* Fallback логику OCSP → CRL
* Интеграционный полный цикл (CSR → cert → validate → revoke)

### Тесты спринта 7
```Bash
pytest tests/test_sprint7.py -v
# Результат: 54 passed
````
##### Тесты покрывают:

* Хеш-цепочку аудита (создание, связывание, верификация)
* Обнаружение подделки и пропущенных записей
* Все политики (key size, validity, SAN, signature algorithm, pathLen)
* Симуляцию компрометации ключа
* Блокировку CSR со скомпрометированным ключом
* Запись в CT log при выпуске
* Целостность аудита после полного workflow

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
│   ├── code_signer.key.pem         # ключ подписи кода
│   ├── ocsp.cert.pem               # сертификат OCSP-ответчика
│   └── ocsp.key.pem                # ключ OCSP-ответчика, без шифрования
├── crl/                             
│   ├── root.crl.pem                
│   └── intermediate.crl.pem
├── audit/                          
│   ├── audit.log                   # NDJSON журнал с хеш-цепочкой
│   ├── chain.dat                   # последний хеш
│   └── ct.log   
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
│   ├── crl.py                    # генерация CRL
│   ├── revocation.py             # коды причин отзыва
│   ├── logger.py                 # настройка логирования
│   ├── ocsp.py                   # OCSP handler
│   ├── ocsp_responder.py         # OCSP HTTP сервер
│   ├── templates.py              # шаблоны сертификатов (server/client/code_signing)
│   ├── serial.py                 # генератор уникальных серийных номеров
│   ├── database.py               # работа с SQLite (CRUD операции)
│   ├── client.py                 # клиентские функции 
│   ├── validation.py             # проверка цепочки 
│   ├── revocation_check.py       # проверка отзыва CRL/OCSP 
│   ├── audit.py                  # система аудита 
│   ├── policy.py                 # политики безопасности 
│   ├── ratelimit.py              # rate limiting 
│   ├── transparency.py           # CT log 
│   ├── compromise.py             # компрометация ключей 
│   └── server.py                 # REST API сервер (FastAPI)
├── tests/
│   ├── test_ca.py                # тесты спринтов 1-2 (39 тестов)
│   ├── test_sprint3.py           # тесты спринта 3 (18 тестов)
│   ├── test_sprint4.py           # тесты спринта 4 (18 тестов)
│   ├── test_sprint5.py 
│   ├── test_sprint6.py           # тесты спринта 6 (32 теста)
│   └── test_sprint7.py           # тесты спринта 7 (54 теста)
├── demo/
│   ├── demo.py                   # автоматизированный демо-скрипт (25 шагов)
│   └── DEMO.md                   # пошаговое описание демо
├── docs/
│   ├── ARCHITECTURE.md           # компонентная диаграмма (Mermaid)
│   ├── SECURITY.md               # аспекты безопасности
│   └── API.md                    # справочник HTTP API
├── pki/pki1/                     # выходные файлы PKI (в .gitignore)
├── secrets/                      # пароли (в .gitignore)
├── logs/                         # логи (в .gitignore)
├── .gitignore
├── .coveragerc
├── requirements.txt
├── pytest.ini
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

CREATE TABLE crl_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_subject TEXT NOT NULL UNIQUE,
    crl_number INTEGER NOT NULL,
    last_generated TEXT NOT NULL,
    next_update TEXT NOT NULL,
    crl_path TEXT NOT NULL
);

CREATE INDEX idx_ca_subject ON crl_metadata(ca_subject);

CREATE TABLE compromised_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    public_key_hash TEXT UNIQUE NOT NULL,
    certificate_serial TEXT NOT NULL,
    compromise_date TEXT NOT NULL,
    compromise_reason TEXT NOT NULL,
    FOREIGN KEY (certificate_serial) REFERENCES certificates(serial_hex)
);

CREATE INDEX idx_compromised_pubkey ON compromised_keys(public_key_hash);
```
## Аспекты безопасности
MicroPKI — учебный проект. Не использовать в production без существенных доработок.

##### Основные ограничения:

* Закрытые ключи конечных сертификатов хранятся незашифрованными
* Парольные фразы CA читаются из файлов
* OCSP-ответчик работает по HTTP без TLS
* Rate limiting базовый, не защищает от DDoS
* Аудит-журнал не подписан, только хеш-цепочка
* Certificate Transparency только симулируется
* Нет интеграции с HSM
* Аутентификация API через единый shared secret

Полное обсуждение, threat model и рекомендации: docs/SECURITY.md.

# Сводная таблица команд MicroPKI

## Сводная таблица команд

### Управление CA

| Команда                     | Описание                       | Спринт |
|-----------------------------|--------------------------------|--------|
| `ca init`                   | Инициализация Root CA          | 1 |
| `ca issue-intermediate`     | Создание Intermediate CA       | 2 |
| `ca issue-cert`             | Выпуск конечного сертификата   | 2 |
| `ca issue-cert --csr`       | Подпись внешнего CSR           | 6 |
| `ca issue-ocsp-cert`        | Выпуск OCSP-сертификата        | 5 |
| `ca revoke <serial>`        | Отзыв сертификата              | 4 |
| `ca gen-crl`                | Генерация CRL                  | 4 |
| `ca check-revoked <serial>` | Проверка статуса отзыва        | 4 |
| ca compromise --cert <path> | 	Симуляция компрометации ключа | 	7                           |
| `ca list-certs`             | Список сертификатов            | 3 |
| `ca show-cert <serial>`     | Показать сертификат            | 3 |

### Работа с базой данных

| Команда | Описание | Спринт |
|---------|----------|--------|
| `db init` | Инициализация БД | 3 |
| `db list` | Список сертификатов в БД | 3 |
| `db show <serial>` | Детали сертификата | 3 |
| `db export <serial>` | Экспорт сертификата в файл | 3 |
| `db stats` | Статистика БД | 3 |

### HTTP-сервер репозитория

| Команда | Описание | Спринт |
|---------|----------|--------|
| `repo serve` | Запуск HTTP-репозитория | 3 |
| `server start` | Алиас для `repo serve` | 3 |

### OCSP-ответчик

| Команда | Описание | Спринт |
|---------|----------|--------|
| `ocsp serve` | Запуск OCSP-ответчика | 5 |

### Клиентские инструменты

| Команда | Описание | Спринт |
|---------|----------|--------|
| `client gen-csr` | Генерация ключа и CSR | 6 |
| `client request-cert` | Запрос сертификата у CA | 6 |
| `client validate` | Проверка цепочки сертификатов | 6 |
| `client check-status` | Проверка статуса отзыва (OCSP→CRL) | 6 |
|client sign|	Подпись файла|	8|
|client verify|	Проверка подписи файла|	8|
### Аудит и безопасность

| Команда | Описание | Спринт |
|---------|----------|--------|
| `ca compromise --cert <path>` | Симуляция компрометации ключа | 7 |
| `audit query` | Поиск записей аудита (с фильтрами) | 7 |
| `audit verify` | Проверка целостности хеш-цепочки | 7 |
| `audit ct-verify <serial>` | Проверка наличия в CT-логе | 7 |

### HTTP API эндпоинты

| Метод | URL | Описание | Спринт |
|-------|-----|----------|--------|
| `GET` | `/` | Информация о сервисе | 3 |
| `GET` | `/certificate/{serial}` | Получить сертификат (JSON) | 3 |
| `GET` | `/certificate/{serial}/pem` | Получить сертификат (PEM) | 3 |
| `GET` | `/certificates` | Список сертификатов | 3 |
| `GET` | `/ca/root` | Сертификат корневого CA | 3 |
| `GET` | `/ca/intermediate` | Сертификат промежуточного CA | 3 |
| `GET` | `/statistics` | Статистика | 3 |
| `GET` | `/search?q=...` | Поиск по subject | 3 |
| `GET` | `/crl?ca=root\|intermediate` | Получить CRL | 4 |
| `GET` | `/crl/{ca_name}.crl` | Альтернативный путь CRL | 4 |
| `POST` | `/ocsp` | OCSP-запрос | 5 |
| `POST` | `/request-cert?template=...` | Подпись CSR (требует `X-API-Key`) | 6 |

## Источники
* RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile
* RFC 6960 — X.509 Internet Public Key Infrastructure Online Certificate Status Protocol (OCSP)
* RFC 2986 — PKCS #10: Certification Request Syntax
* pyca/cryptography — Python cryptographic library
* FastAPI — HTTP framework
* CA/Browser Forum Baseline Requirements