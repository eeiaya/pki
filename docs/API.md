# MicroPKI HTTP API Reference

## Repository Server

Default: `http://127.0.0.1:8080`

### `GET /`
Service info and endpoint list.

```bash
curl http://localhost:8080/
````
### GET /certificate/{serial}

 Get certificate metadata by serial (hex).

 **Response:** JSON with subject, issuer, validity, status, PEM.

```Bash
curl http://localhost:8080/certificate/6A1AF8867BEC69EC
```
### GET /certificate/{serial}/pem

Download certificate in PEM format.

```Bash
curl http://localhost:8080/certificate/6A1AF8867BEC69EC/pem --output cert.pem
```
### GET /certificates
List certificates with optional filters.

**Query parameters:**

* status — valid, revoked, expired
* template — server, client, code_signing, ocsp
* limit — max results (default 100)
```Bash
curl "http://localhost:8080/certificates?status=valid&template=server"
```
### GET /ca/{level}
Download CA certificate.

* level=root → root CA cert
* level=intermediate → intermediate CA cert
```Bash
curl http://localhost:8080/ca/root --output root-ca.pem
```
### GET /crl?ca=intermediate
Download CRL (default: intermediate).

**Response:** application/pkix-crl

```Bash
curl http://localhost:8080/crl?ca=intermediate --output crl.pem
curl http://localhost:8080/crl/root.crl --output root-crl.pem  # alternative path
```
### GET /statistics
Database statistics.

```Bash
curl http://localhost:8080/statistics
```
Response:

```JSON
{
  "total": 10,
  "by_status": {"valid": 8, "revoked": 2},
  "by_template": {"server": 4, "client": 3, "code_signing": 2, "ocsp": 1}
}
```
### GET /search?q=<pattern>
Search certificates by subject substring.

```Bash
curl "http://localhost:8080/search?q=example.com"
```
### POST /ocsp (OCSP via Repository)
OCSP request endpoint (also available standalone on port 8081).

**Content-Type:** application/ocsp-request
**Response Content-Type:** application/ocsp-response

```Bash
# Build OCSP request manually via openssl
openssl ocsp -issuer intermediate.cert.pem -cert server.cert.pem \
    -url http://localhost:8080/ocsp -resp_text -noverify
```
### POST /request-cert?template=<template> Authentication required
Submit CSR for signing.

**Headers:**

* Content-Type: application/x-pem-file
* X-API-Key: <api_key> (default changeme, configurable via MICROPKI_API_KEY env var)
**Query parameters:**

* template — server, client, code_signing
**Request body:** PEM-encoded CSR
**Response:** PEM-encoded certificate (HTTP 201)

```Bash
curl -X POST \
    -H "Content-Type: application/x-pem-file" \
    -H "X-API-Key: changeme" \
    --data-binary @app.csr.pem \
    "http://localhost:8080/request-cert?template=server" \
    --output app.cert.pem
```
**Response codes:**

* 201 — certificate issued
* 400 — invalid CSR or policy violation
* 401 — missing/invalid API key
* 503 — CA unavailable
## OCSP Responder (standalone)
Default: http://127.0.0.1:8081

### POST /ocsp
Standard OCSP request per RFC 6960.

**Content-Type:** application/ocsp-request
**Response Content-Type:** application/ocsp-response

```Bash
openssl ocsp -issuer intermediate.cert.pem -cert server.cert.pem \
    -url http://localhost:8081/ocsp -resp_text -noverify
```
***Returns:***

* GOOD — certificate is valid
* REVOKED — with revocation time and reason
* UNKNOWN — serial not found or wrong issuer
#### GET /
Service info.

## Environment Variables
| Variable         |	Default|	Purpose|
|------------------|-----------|--------|
| MICROPKI_API_KEY |	changeme|	API key for /request-cert|
|MICROPKI_CA_PASS_FILE|	./secrets/ca.pass|	CA passphrase file for API signing|
```PowerShell
$env:MICROPKI_API_KEY = "mysecretkey"
$env:MICROPKI_CA_PASS_FILE = "./secrets/ca.pass"
micropki repo serve
```
