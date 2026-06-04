"""
MicroPKI Full Lifecycle Demo

Демонстрирует все возможности MicroPKI:
- Инициализация Root + Intermediate CA
- Выпуск server/client/code-signing/OCSP сертификатов
- Запуск HTTP-репозитория и OCSP-ответчика
- Проверка цепочки и статуса отзыва
- Отзыв сертификата и обнаружение
- Подпись и проверка файлов (code-signing)
- Целостность аудита
- Применение политик безопасности
"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
import signal
from pathlib import Path


# ============================================================
# Цветной вывод
# ============================================================

class C:
    R = "\033[91m"   # red
    G = "\033[92m"   # green
    Y = "\033[93m"   # yellow
    B = "\033[94m"   # blue
    M = "\033[95m"   # magenta
    C = "\033[96m"   # cyan
    BOLD = "\033[1m"
    END = "\033[0m"

    @staticmethod
    def disable():
        for attr in ("R", "G", "Y", "B", "M", "C", "BOLD", "END"):
            setattr(C, attr, "")


if os.name == "nt":
    try:
        import colorama
        colorama.init()
    except ImportError:
        C.disable()


def step(msg: str):
    print(f"\n{C.BOLD}{C.B}=== {msg} ==={C.END}")


def ok(msg: str):
    print(f"{C.G}[OK]{C.END} {msg}")


def fail(msg: str):
    print(f"{C.R}[FAIL]{C.END} {msg}")


def info(msg: str):
    print(f"{C.C}[INFO]{C.END} {msg}")


def warn(msg: str):
    print(f"{C.Y}[WARN]{C.END} {msg}")


# ============================================================
# Запуск micropki
# ============================================================

def run(cmd: list, check: bool = True, capture: bool = False, expect_fail: bool = False) -> subprocess.CompletedProcess:
    info(" ".join(str(c) for c in cmd))
    result = subprocess.run(
        cmd,
        capture_output=capture,
        text=True,
    )

    if expect_fail:
        if result.returncode != 0:
            ok(f"Command failed as expected (exit={result.returncode})")
            return result
        else:
            fail("Command succeeded but failure was expected")
            sys.exit(1)

    if check and result.returncode != 0:
        fail(f"Command failed (exit={result.returncode})")
        if capture:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result


def start_background(cmd: list, log_file: Path) -> subprocess.Popen:
    info("Background: " + " ".join(str(c) for c in cmd))
    f = open(log_file, "w", encoding="utf-8")
    if os.name == "nt":
        proc = subprocess.Popen(
            cmd, stdout=f, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        proc = subprocess.Popen(
            cmd, stdout=f, stderr=subprocess.STDOUT, preexec_fn=os.setsid
        )
    return proc


def stop_background(proc: subprocess.Popen, name: str):
    if proc is None or proc.poll() is not None:
        return
    info(f"Stopping {name}...")
    try:
        if os.name == "nt":
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        proc.kill()
    ok(f"{name} stopped")


# ============================================================
# Main
# ============================================================

def main():
    # Изолированная директория
    base_dir = Path(tempfile.mkdtemp(prefix="micropki_demo_"))
    out_dir = base_dir / "pki"
    secrets_dir = base_dir / "secrets"
    work_dir = base_dir / "work"

    out_dir.mkdir(parents=True, exist_ok=True)
    secrets_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    pass_file = secrets_dir / "ca.pass"
    pass_file.write_text("DemoPass123", encoding="utf-8")

    server_log = work_dir / "repo_server.log"
    ocsp_log = work_dir / "ocsp_server.log"

    server_proc = None
    ocsp_proc = None

    print(f"{C.BOLD}{C.M}")
    print("=" * 70)
    print("    MICROPKI FULL LIFECYCLE DEMO")
    print("=" * 70)
    print(f"{C.END}")
    print(f"Demo directory: {base_dir}\n")

    try:
        # ============================================================
        step("1. Initialize Root CA")
        run([
            "micropki", "ca", "init",
            "--subject", "CN=Demo Root CA,O=MicroPKI Demo",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", str(pass_file),
            "--out-dir", str(out_dir),
            "--validity-days", "3650",
        ])
        ok("Root CA initialized")

        # ============================================================
        step("2. Issue Intermediate CA")
        run([
            "micropki", "ca", "issue-intermediate",
            "--root-cert", str(out_dir / "certs" / "ca.cert.pem"),
            "--root-key", str(out_dir / "private" / "ca.key.pem"),
            "--root-pass-file", str(pass_file),
            "--subject", "CN=Demo Intermediate CA,O=MicroPKI Demo",
            "--key-type", "rsa", "--key-size", "4096",
            "--passphrase-file", str(pass_file),
            "--out-dir", str(out_dir),
            "--validity-days", "1825",
        ])
        ok("Intermediate CA issued")

        # ============================================================
        step("3. Issue Server Certificate")
        run([
            "micropki", "ca", "issue-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--template", "server",
            "--subject", "CN=demo.example.com,O=MicroPKI Demo",
            "--san", "dns:demo.example.com",
            "--out-dir", str(out_dir / "certs"),
        ])
        ok("Server certificate issued")

        # ============================================================
        step("4. Issue Client Certificate")
        run([
            "micropki", "ca", "issue-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--template", "client",
            "--subject", "CN=alice,O=MicroPKI Demo",
            "--san", "email:alice@example.com",
            "--out-dir", str(out_dir / "certs"),
        ])
        ok("Client certificate issued")

        # ============================================================
        step("5. Issue Code-Signing Certificate")
        run([
            "micropki", "ca", "issue-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--template", "code_signing",
            "--subject", "CN=Demo Code Signer,O=MicroPKI Demo",
            "--out-dir", str(out_dir / "certs"),
        ])
        ok("Code-signing certificate issued")

        # ============================================================
        step("6. Issue OCSP Responder Certificate")
        run([
            "micropki", "ca", "issue-ocsp-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--subject", "CN=Demo OCSP Responder,O=MicroPKI Demo",
            "--out-dir", str(out_dir / "certs"),
        ])
        ok("OCSP responder certificate issued")

        # ============================================================
        step("7. Generate initial CRL")
        run([
            "micropki", "ca", "gen-crl",
            "--ca", "intermediate",
            "--ca-pass-file", str(pass_file),
            "--out-dir", str(out_dir),
        ])
        ok("CRL generated")

        # ============================================================
        step("8. Start Repository Server (background)")
        env = os.environ.copy()
        env["MICROPKI_CA_PASS_FILE"] = str(pass_file)
        env["MICROPKI_API_KEY"] = "demo-api-key"

        server_proc = subprocess.Popen(
            [
                "micropki", "repo", "serve",
                "--host", "127.0.0.1",
                "--port", "8090",
                "--db-path", str(out_dir / "certificates.db"),
                "--cert-dir", str(out_dir / "certs"),
            ],
            stdout=open(server_log, "w", encoding="utf-8"),
            stderr=subprocess.STDOUT,
            env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            preexec_fn=os.setsid if os.name != "nt" else None,
        )
        time.sleep(3)
        ok(f"Repository server running on http://127.0.0.1:8090 (log: {server_log})")

        # ============================================================
        step("9. Start OCSP Responder (background)")
        ocsp_proc = start_background([
            "micropki", "ocsp", "serve",
            "--host", "127.0.0.1",
            "--port", "8091",
            "--db-path", str(out_dir / "certificates.db"),
            "--responder-cert", str(out_dir / "certs" / "ocsp.cert.pem"),
            "--responder-key", str(out_dir / "certs" / "ocsp.key.pem"),
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
        ], ocsp_log)
        time.sleep(3)
        ok(f"OCSP responder running on http://127.0.0.1:8091 (log: {ocsp_log})")

        # ============================================================
        step("10. Generate CSR and request certificate via API")
        csr_path = work_dir / "app.csr.pem"
        csr_key = work_dir / "app.key.pem"
        cert_path = work_dir / "app.cert.pem"

        run([
            "micropki", "client", "gen-csr",
            "--subject", "CN=app.demo.com,O=MicroPKI Demo",
            "--san", "dns:app.demo.com",
            "--out-key", str(csr_key),
            "--out-csr", str(csr_path),
        ])
        ok(f"CSR generated: {csr_path}")

        run([
            "micropki", "client", "request-cert",
            "--csr", str(csr_path),
            "--template", "server",
            "--ca-url", "http://127.0.0.1:8090",
            "--out-cert", str(cert_path),
            "--api-key", "demo-api-key",
        ])
        ok(f"Certificate issued via API: {cert_path}")

        # ============================================================
        step("11. Validate certificate chain (full)")
        run([
            "micropki", "client", "validate",
            "--cert", str(cert_path),
            "--untrusted", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--trusted", str(out_dir / "certs" / "ca.cert.pem"),
            "--crl", str(out_dir / "crl" / "intermediate.crl.pem"),
            "--mode", "full",
        ])
        ok("Chain validation PASSED")

        # ============================================================
        step("12. Check status via OCSP (should be GOOD)")
        run([
            "micropki", "client", "check-status",
            "--cert", str(cert_path),
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ocsp-url", "http://127.0.0.1:8091/ocsp",
        ])
        ok("OCSP status: GOOD")

        # ============================================================
        step("13. Code Signing: sign a file")
        test_file = work_dir / "important.txt"
        test_file.write_text("Important data to sign\n", encoding="utf-8")
        sig_file = work_dir / "important.txt.sig"

        run([
            "micropki", "client", "sign",
            "--file", str(test_file),
            "--key", str(out_dir / "certs" / "Demo_Code_Signer.key.pem"),
            "--out-sig", str(sig_file),
        ])
        ok("File signed")

        # ============================================================
        step("14. Code Signing: verify signature")
        run([
            "micropki", "client", "verify",
            "--file", str(test_file),
            "--cert", str(out_dir / "certs" / "Demo_Code_Signer.cert.pem"),
            "--sig", str(sig_file),
        ])
        ok("Signature verified")

        # ============================================================
        step("15. Code Signing: detect file tampering")
        test_file.write_text("TAMPERED data\n", encoding="utf-8")
        run([
            "micropki", "client", "verify",
            "--file", str(test_file),
            "--cert", str(out_dir / "certs" / "Demo_Code_Signer.cert.pem"),
            "--sig", str(sig_file),
        ], expect_fail=True)
        ok("Tampering detected")
        test_file.write_text("Important data to sign\n", encoding="utf-8")

        # ============================================================
        step("16. Policy enforcement: try wildcard SAN (should fail)")
        run([
            "micropki", "ca", "issue-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--template", "server",
            "--subject", "CN=wild.example.com",
            "--san", "dns:*.example.com",
            "--out-dir", str(out_dir / "certs"),
        ], expect_fail=True)
        ok("Wildcard SAN rejected by policy")

        # ============================================================
        step("17. Policy enforcement: try validity > 365 days (should fail)")
        run([
            "micropki", "ca", "issue-cert",
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ca-key", str(out_dir / "private" / "intermediate.key.pem"),
            "--ca-pass-file", str(pass_file),
            "--template", "server",
            "--subject", "CN=longlife.example.com",
            "--san", "dns:longlife.example.com",
            "--validity-days", "999",
            "--out-dir", str(out_dir / "certs"),
        ], expect_fail=True)
        ok("Excessive validity rejected by policy")

        # ============================================================
        step("18. Revoke certificate")
        # Получаем serial
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        serial_hex = format(cert.serial_number, "X")
        info(f"Revoking serial: {serial_hex}")

        run([
            "micropki", "ca", "revoke",
            serial_hex, "--reason", "keyCompromise", "--force",
            "--out-dir", str(out_dir),
        ])
        ok(f"Certificate {serial_hex} revoked")

        # ============================================================
        step("19. Regenerate CRL after revocation")
        run([
            "micropki", "ca", "gen-crl",
            "--ca", "intermediate",
            "--ca-pass-file", str(pass_file),
            "--out-dir", str(out_dir),
        ])
        ok("CRL regenerated")

        # ============================================================
        step("20. Check status via OCSP (should now be REVOKED)")
        result = subprocess.run([
            "micropki", "client", "check-status",
            "--cert", str(cert_path),
            "--ca-cert", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--ocsp-url", "http://127.0.0.1:8091/ocsp",
        ], capture_output=True, text=True)

        if "REVOKED" in (result.stdout + result.stderr):
            ok("OCSP detected REVOKED status")
        else:
            fail("OCSP did not detect revocation")
            sys.exit(1)

        # ============================================================
        step("21. Full validation should now FAIL (revoked)")
        result = subprocess.run([
            "micropki", "client", "validate",
            "--cert", str(cert_path),
            "--untrusted", str(out_dir / "certs" / "intermediate.cert.pem"),
            "--trusted", str(out_dir / "certs" / "ca.cert.pem"),
            "--crl", str(out_dir / "crl" / "intermediate.crl.pem"),
            "--mode", "full",
        ], capture_output=True, text=True)

        combined = result.stdout + result.stderr
        if result.returncode != 0 and "revoked" in combined.lower():
            ok("Validation correctly FAILED for revoked certificate")
        else:
            fail("Validation should have failed")
            sys.exit(1)

        # ============================================================
        step("22. Compromise simulation")
        comp_cert = out_dir / "certs" / "alice.cert.pem"
        run([
            "micropki", "ca", "compromise",
            "--cert", str(comp_cert),
            "--reason", "keyCompromise",
            "--force",
            "--ca-pass-file", str(pass_file),
            "--out-dir", str(out_dir),
        ])
        ok("Key compromise simulated")

        # ============================================================
        step("23. Audit log integrity check")
        run([
            "micropki", "audit", "verify",
            "--log-file", str(out_dir / "audit" / "audit.log"),
            "--chain-file", str(out_dir / "audit" / "chain.dat"),
        ])
        ok("Audit log integrity verified")

        # ============================================================
        step("24. Query AUDIT entries")
        run([
            "micropki", "audit", "query",
            "--log-file", str(out_dir / "audit" / "audit.log"),
            "--level", "AUDIT",
        ])
        ok("Audit query completed")


        # ============================================================
        step("25. CT-log verification")
        # Берём серийник server-сертификата (был выпущен локально через CLI)
        from cryptography import x509 as _x509
        srv = _x509.load_pem_x509_certificate(
            (out_dir / "certs" / "demo.example.com.cert.pem").read_bytes()
        )
        srv_serial = format(srv.serial_number, "X")
        run([
            "micropki", "audit", "ct-verify",
            srv_serial,
            "--out-dir", str(out_dir),
        ])
        ok(f"CT log contains {srv_serial}")

        # ============================================================
        print(f"\n{C.BOLD}{C.G}")
        print("=" * 70)
        print("    DEMO COMPLETED SUCCESSFULLY")
        print("=" * 70)
        print(f"{C.END}")
        print(f"All artifacts in: {base_dir}")
        print(f"Repository log:   {server_log}")
        print(f"OCSP log:         {ocsp_log}\n")

    finally:
        if ocsp_proc:
            stop_background(ocsp_proc, "OCSP responder")
        if server_proc:
            stop_background(server_proc, "Repository server")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
        sys.exit(130)