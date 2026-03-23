# MicroPKI
Минималистичный инструмент для создания инфраструктуры открытых ключей (PKI) в учебных целях.

## Зависимости
Python 3.10+
OpenSSL
cryptography >= 41.0.0
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
## Структура выходных файлов
```text

pki/pki1/
├── private/
│   ├── ca.key.pem              # зашифрованный ключ корневого CA (PKCS#8)
│   └── intermediate.key.pem    # зашифрованный ключ промежуточного CA
├── certs/
│   ├── ca.cert.pem             # сертификат корневого CA
│   ├── intermediate.cert.pem  # сертификат промежуточного CA
│   ├── example.com.cert.pem   # серверный сертификат
│   └── example.com.key.pem    # ключ сервера (незашифрованный)
├── csrs/
│   └── intermediate.csr.pem   # CSR промежуточного CA
└── policy.txt                  # документ политики УЦ
```
## Структура проекта
```text

pki/
├── micropki/
│   ├── __init__.py           # пакет
│   ├── cli.py                # парсер аргументов CLI
│   ├── ca.py                 # логика CA (init, issue-intermediate, issue-cert)
│   ├── certificates.py       # работа с X.509 сертификатами
│   ├── chain.py              # проверка цепочки сертификатов
│   ├── csr.py                # генерация и обработка CSR
│   ├── crypto_utils.py       # генерация ключей, PEM, шифрование
│   ├── logger.py             # настройка логирования
│   └── templates.py          # шаблоны сертификатов (server/client/code_signing)
├── tests/
│   └── test_ca.py            # 39 тестов
├── pki/pki1/                  # выходные файлы PKI (в .gitignore)
├── secrets/                   # пароли (в .gitignore)
├── logs/                      # логи (в .gitignore)
├── .gitignore
├── requirements.txt
├── setup.py
└── README.md
```