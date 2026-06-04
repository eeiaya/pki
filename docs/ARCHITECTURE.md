
# MicroPKI Architecture

## Component Diagram

```mermaid
graph TB
    subgraph CLI["CLI (micropki)"]
        CA_CMD[ca commands]
        CLIENT_CMD[client commands]
        DB_CMD[db commands]
        AUDIT_CMD[audit commands]
        REPO_CMD[repo serve]
        OCSP_CMD[ocsp serve]
    end

    subgraph CORE["Core PKI Logic"]
        CA_MOD[ca.py<br/>CA operations]
        CERT_MOD[certificates.py<br/>X.509 builders]
        CSR_MOD[csr.py<br/>CSR handling]
        CRL_MOD[crl.py<br/>CRL generation]
        OCSP_MOD[ocsp.py<br/>OCSP responder]
        VAL_MOD[validation.py<br/>Chain validator]
        REV_MOD[revocation_check.py<br/>CRL+OCSP fallback]
    end

    subgraph SECURITY["Security Layer"]
        POL[policy.py<br/>Policy enforcement]
        AUD[audit.py<br/>NDJSON + SHA-256 chain]
        CT[transparency.py<br/>CT log]
        COMP[compromise.py<br/>Key compromise]
    end

    subgraph STORAGE["Storage"]
        DB[(SQLite<br/>certificates.db)]
        CERTS[certs/]
        KEYS[private/]
        CRL_FILES[crl/]
        AUDIT_LOG[audit/audit.log<br/>+ chain.dat]
        CT_LOG[audit/ct.log]
    end

    subgraph HTTP["HTTP Services"]
        REPO[Repository Server<br/>:8080]
        OCSP_SRV[OCSP Responder<br/>:8081]
    end

    subgraph CLIENT["Client Tools"]
        GEN_CSR[gen-csr]
        REQ_CERT[request-cert]
        VALIDATE[validate]
        CHECK[check-status]
        SIGN[sign / verify]
    end

    CA_CMD --> CA_MOD
    CLIENT_CMD --> CLIENT
    AUDIT_CMD --> AUD
    REPO_CMD --> REPO
    OCSP_CMD --> OCSP_SRV

    CA_MOD --> POL
    CA_MOD --> AUD
    CA_MOD --> CT
    CA_MOD --> CERT_MOD
    CA_MOD --> CSR_MOD
    CA_MOD --> CRL_MOD
    CA_MOD --> DB
    CA_MOD --> COMP

    REPO --> CA_MOD
    REPO --> DB
    REPO --> CRL_FILES

    OCSP_SRV --> OCSP_MOD
    OCSP_MOD --> DB

    VALIDATE --> VAL_MOD
    CHECK --> REV_MOD
    REQ_CERT -->|HTTPS POST /request-cert| REPO

    AUD --> AUDIT_LOG
    CT --> CT_LOG
    CA_MOD --> CERTS
    CA_MOD --> KEYS
```
## Component Description
### CLI Layer
#### Single entry point micropki with command groups: ca, client, db, audit, repo, ocsp.

### Core PKI Logic
#### Implements RFC 5280 X.509 certificates, RFC 5280 CRL, RFC 6960 OCSP.

### Security Layer
* Policy — enforces key sizes, validity periods, SAN restrictions
* Audit — NDJSON log with SHA-256 hash chain for tamper detection
* Transparency — CT-log simulation (append-only public log)
* Compromise — blocks reuse of compromised public keys
### Storage
* SQLite — certificate metadata, CRL metadata, compromised keys
* Filesystem — PEM certificates, encrypted private keys, CRLs, audit logs
### HTTP Services
* Repository (port 8080) — public distribution + CSR signing endpoint
* OCSP Responder (port 8081) — real-time revocation status
### Client Tools
#### End-user tools for CSR generation, certificate validation, revocation checking, code signing.

## Data Flow Examples
### Certificate Issuance via API
1. Client generates key pair + CSR (client gen-csr)
2. Client sends CSR to repository (POST /request-cert)
3. Repository validates CSR (signature, policy)
4. Repository invokes ca.issue_certificate()
5. Certificate stored in DB + audit log + CT log
6. Certificate returned to client (PEM)
### Revocation Check (OCSP→CRL fallback)
1. Client requests status (client check-status)
2. Client extracts OCSP URL from cert's AIA extension
3. Client sends OCSP request
4. If OCSP succeeds → return result
5. If OCSP fails → fallback to CRL (from CDP or --crl)
6. CRL signature verified, serial searched in revocation list
### Audit Integrity
1. Every critical operation writes entry to audit.log
2. Entry includes SHA-256 hash linking to previous entry
3. chain.dat stores latest hash for fast verification
4. audit verify recomputes full chain and detects tampering