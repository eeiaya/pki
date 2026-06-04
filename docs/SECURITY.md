# MicroPKI Security Considerations

 **MicroPKI is an educational project. Do not use in production without significant hardening.**

## Known Limitations

### 1. End-entity private keys stored unencrypted
End-entity certificates (server, client, code-signing) have their private keys stored as plain PEM files with permissions 0o600 (effective on Unix). On Windows, file permissions are not enforced — protect via NTFS ACLs manually.

**Mitigation:** restrict directory access; consider hardware-backed key storage for production.

### 2. CA passphrases read from files
Root and Intermediate CA private keys are encrypted (AES-256 via PKCS#8), but their passphrases must be readable by the CA process — stored in `secrets/*.pass` files.

**Mitigation:** restrict `secrets/` directory; use environment variables (`MICROPKI_CA_PASS_FILE`) pointing to ramfs/tmpfs in production.

### 3. OCSP responder uses HTTP (no TLS)
The OCSP responder serves over plain HTTP on port 8081. While OCSP responses are themselves cryptographically signed (so tampering is detectable), the lack of transport encryption may leak query metadata.

**Mitigation:** front with a reverse proxy (nginx) with TLS termination.

### 4. Rate limiting is basic
The included rate limiter (`ratelimit.py`) uses a token bucket per source IP. It does **not** protect against:
- Distributed attacks from multiple IPs
- Resource exhaustion via slow loris
- Application-layer abuse

**Mitigation:** use external WAF / reverse proxy with proper DDoS protection.

### 5. Audit log integrity, but no signing
The audit log uses SHA-256 hash chains to detect tampering. However:
- The log file itself is not digitally signed
- An attacker with file write access can replay the entire chain from scratch
- There is no external timestamping authority

**Mitigation:** ship audit logs to a write-once-read-many (WORM) storage; use trusted timestamping (RFC 3161) for periodic anchoring.

### 6. Certificate Transparency is simulated
The CT log is a plain text file, not a Merkle tree. There are:
- No SCTs (Signed Certificate Timestamps)
- No gossip protocol with other CT logs
- No public auditability

**Mitigation:** for production, use real CT logs (e.g., Google Argon, Let's Encrypt Oak).

### 7. API key authentication (single shared secret)
The `/request-cert` endpoint accepts a static `X-API-Key` header. There is:
- No per-client authentication
- No rotation mechanism
- No rate limiting per key

**Mitigation:** use mTLS for client authentication; integrate with OAuth/OIDC.

### 8. No HSM integration
All cryptographic operations use software keys. There is no support for hardware security modules (HSMs) or smart cards.

**Mitigation:** integrate with PKCS#11 modules (e.g., SoftHSM, YubiHSM) for CA key protection.

### 9. Policy violations are logged but not alerted
Failed policy checks are recorded in the audit log, but there is no real-time alerting mechanism (email, syslog, SIEM integration).

**Mitigation:** parse audit log with external SIEM (Splunk, ELK); set up alerts.

### 10. Database is SQLite (single-writer)
The certificate database uses SQLite, which limits concurrent writes. For high-volume CAs:
- Switch to PostgreSQL or MySQL
- Add proper connection pooling

## Compliance Notes

MicroPKI **does not** comply with:
- CA/Browser Forum Baseline Requirements
- WebTrust for CAs
- ETSI EN 319 411
- FIPS 140-2/3 (no HSM)

It implements **subset of RFC 5280, RFC 6960** sufficient for educational purposes.

## Threat Model Summary

| Threat | Mitigation | Status |
|--------|-----------|--------|
| Stolen end-entity key | Revocation via CRL/OCSP |  Implemented |
| Stolen CA key | Re-key entire PKI; revoke intermediate |  Manual |
| Audit log tampering | SHA-256 hash chain |  Detected |
| Replay of full audit log | Not detected |  Out of scope |
| Wildcard cert abuse | Blocked by default policy |  Implemented |
| Weak keys (< 2048 RSA) | Policy enforcement |  Implemented |
| Excessive validity | Policy enforcement |  Implemented |
| SHA-1 signatures | Rejected |  Implemented |
| CSR with CA=TRUE | Rejected |  Implemented |
| Reuse of compromised key | Blocked via `compromised_keys` table |  Implemented |

## Recommendations for Educational Use

1. **Always use temporary directories** for demo runs
2. **Never commit** `secrets/`, `pki/pki1/`, or `*.key.pem` files to git
3. **Rotate API keys** if shared between users
4. **Verify audit log** (`audit verify`) periodically
5. **Review policy violations** in audit log regularly