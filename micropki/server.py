import os
import logging
import re
from pathlib import Path
from typing import Optional, List

from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import CertificateDatabase
from .serial import is_valid_hex_serial
from fastapi import Body, Header
import tempfile

class CertificateInfo(BaseModel):
    serial_hex: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    status: str
    template: Optional[str] = None
    san_entries: Optional[List[str]] = None
    created_at: str


class CertificateDetail(CertificateInfo):
    cert_pem: str
    revocation_reason: Optional[str] = None
    revocation_date: Optional[str] = None


class CertificateList(BaseModel):
    total: int
    certificates: List[CertificateInfo]


class Statistics(BaseModel):
    total: int
    by_status: dict
    by_template: dict

class HTTPLogger:

    def __init__(self):
        self.logger = logging.getLogger('micropki.http')
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [HTTP] %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_request(self, request: Request, status_code: int):
        client_ip = request.client.host if request.client else "unknown"
        self.logger.info(
            f'{client_ip} - "{request.method} {request.url.path}" {status_code}'
        )


http_logger = HTTPLogger()

def create_app(db_path: Path, ca_certs_dir: Path) -> FastAPI:
    """Создаёт FastAPI приложение."""

    app = FastAPI(
        title="MicroPKI Certificate Repository",
        description="REST API for certificate management and distribution",
        version="1.0.0"
    )

    # CORS middleware (REPO-7)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Инициализируем БД
    db = CertificateDatabase(db_path)

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        response = await call_next(request)
        http_logger.log_request(request, response.status_code)
        return response


    @app.get("/", tags=["General"])
    def root():

        return {
            "service": "MicroPKI Certificate Repository",
            "version": "1.0.0",
            "endpoints": {
                "certificate": "/certificate/{serial}",
                "certificates": "/certificates",
                "ca_root": "/ca/root",
                "ca_intermediate": "/ca/intermediate",
                "crl": "/crl",
                "statistics": "/statistics",
                "search": "/search?q=..."
            }
        }

    @app.get("/certificate/{serial}", tags=["Certificates"])
    def get_certificate(serial: str):

        # Валидация серийного номера (REPO-8)
        if not is_valid_hex_serial(serial):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid serial number format: '{serial}'. Expected hexadecimal string."
            )

        cert_data = db.get_certificate(serial)

        if cert_data is None:
            raise HTTPException(
                status_code=404,
                detail=f"Certificate with serial {serial} not found"
            )


        return cert_data

    @app.get("/certificate/{serial}/pem", response_class=PlainTextResponse, tags=["Certificates"])
    def get_certificate_pem(serial: str):

        if not is_valid_hex_serial(serial):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid serial number format: '{serial}'"
            )

        cert_data = db.get_certificate(serial)

        if cert_data is None:
            raise HTTPException(
                status_code=404,
                detail=f"Certificate with serial {serial} not found"
            )

        return PlainTextResponse(
            content=cert_data['cert_pem'],
            media_type="application/x-pem-file",
            headers={
                'Content-Disposition': f'attachment; filename="{serial}.pem"'
            }
        )

    @app.get("/certificates", response_model=CertificateList, tags=["Certificates"])
    def list_certificates(
            status: Optional[str] = Query(None, description="Filter: valid, revoked, expired"),
            template: Optional[str] = Query(None, description="Filter: server, client, code_signing"),
            limit: Optional[int] = Query(100, description="Max results")
    ):

        certs = db.list_certificates(status=status, template=template, limit=limit)

        # Убираем PEM из списка
        certs_info = [
            {k: v for k, v in cert.items() if k != 'cert_pem'}
            for cert in certs
        ]

        return {
            'total': len(certs_info),
            'certificates': certs_info
        }

    @app.get("/ca/{level}", response_class=PlainTextResponse, tags=["CA"])
    def get_ca_certificate(level: str):

        if level not in ('root', 'intermediate'):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid CA level: '{level}'. Use 'root' or 'intermediate'."
            )

        if level == 'root':
            cert_path = ca_certs_dir / 'ca.cert.pem'
        else:
            cert_path = ca_certs_dir / 'intermediate.cert.pem'

        if not cert_path.exists():
            raise HTTPException(
                status_code=404,
                detail=f"{level.capitalize()} CA certificate not found"
            )

        with open(cert_path, 'r') as f:
            pem_content = f.read()

        return PlainTextResponse(
            content=pem_content,
            media_type="application/x-pem-file",
            headers={
                'Content-Disposition': f'attachment; filename="{level}-ca.pem"'
            }
        )

    @app.get("/crl", tags=["CRL"])
    def get_crl(ca: Optional[str] = Query("intermediate")):
        if ca not in ('root', 'intermediate'):
            raise HTTPException(400, f"Invalid CA: {ca}")

        # Определяем crl_dir
        if ca_certs_dir.name == 'certs':
            crl_dir = ca_certs_dir.parent / 'crl'
        else:
            crl_dir = ca_certs_dir / 'crl'

        crl_path = crl_dir / f'{ca}.crl.pem'

        if not crl_path.exists():
            raise HTTPException(404, f"CRL not found for {ca} CA")

        import os
        from datetime import datetime, timezone
        from fastapi.responses import Response

        crl_content = crl_path.read_bytes()
        mtime = os.path.getmtime(crl_path)
        last_mod = datetime.fromtimestamp(mtime, tz=timezone.utc)

        return Response(
            content=crl_content,
            media_type="application/pkix-crl",
            headers={
                'Content-Disposition': f'attachment; filename="{ca}.crl"',
                'Last-Modified': last_mod.strftime('%a, %d %b %Y %H:%M:%S GMT'),
                'Cache-Control': 'max-age=604800',
            }
        )

    @app.get("/crl/{ca_name}.crl", tags=["CRL"])
    def get_crl_by_path(ca_name: str):
        if ca_name not in ('root', 'intermediate'):
            raise HTTPException(400, f"Invalid CA: {ca_name}")

        if ca_certs_dir.name == 'certs':
            crl_dir = ca_certs_dir.parent / 'crl'
        else:
            crl_dir = ca_certs_dir / 'crl'

        crl_path = crl_dir / f'{ca_name}.crl.pem'

        if not crl_path.exists():
            raise HTTPException(404, f"CRL not found")

        from fastapi.responses import Response
        return Response(
            content=crl_path.read_bytes(),
            media_type="application/pkix-crl",
        )

    @app.post("/ocsp", tags=["OCSP"])
    async def ocsp_endpoint(request: Request):
        content_type = request.headers.get("content-type", "")
        if "application/ocsp-request" not in content_type:
            raise HTTPException(status_code=400, detail="Expected application/ocsp-request")

        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Empty body")

        # Ищем файлы ответчика
        ocsp_cert_path = ca_certs_dir / 'ocsp.cert.pem'
        ocsp_key_path = ca_certs_dir / 'ocsp.key.pem'
        ca_cert_path = ca_certs_dir / 'intermediate.cert.pem'

        if not ocsp_cert_path.exists() or not ocsp_key_path.exists():
            raise HTTPException(
                status_code=501,
                detail="OCSP responder certificate not found. Run: micropki ca issue-ocsp-cert"
            )

        from .ocsp import OCSPHandler
        from .ocsp_responder import load_unencrypted_private_key
        from .crypto_utils import load_certificate

        ca_cert = load_certificate(ca_cert_path)
        responder_cert = load_certificate(ocsp_cert_path)
        responder_key = load_unencrypted_private_key(ocsp_key_path)

        handler = OCSPHandler(
            db=db,
            ca_cert=ca_cert,
            responder_cert=responder_cert,
            responder_key=responder_key
        )

        client_ip = request.client.host if request.client else "unknown"
        response_der = handler.handle_request(body, client_ip)

        return Response(content=response_der, media_type="application/ocsp-response")

    # ============================================================
    # SPRINT 6: /request-cert endpoint
    # ============================================================

    @app.post("/request-cert", tags=["CSR"])
    async def request_cert(
            request: Request,
            template: str = Query("server", description="Template: server, client, code_signing"),
            x_api_key: Optional[str] = Header(None, alias="X-API-Key")
    ):
        client_ip = request.client.host if request.client else "unknown"

        # Простая проверка API-ключа
        EXPECTED_API_KEY = os.environ.get("MICROPKI_API_KEY", "changeme")
        if x_api_key != EXPECTED_API_KEY:
            http_logger.logger.warning(
                f"Unauthorized /request-cert attempt from {client_ip}"
            )
            raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")

        if template not in ('server', 'client', 'code_signing'):
            raise HTTPException(status_code=400, detail=f"Invalid template: {template}")

        # Читаем тело запроса (PEM CSR)
        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Empty request body")

        # Определяем CA-файлы
        if ca_certs_dir.name == 'certs':
            base_dir = ca_certs_dir.parent
        else:
            base_dir = ca_certs_dir

        ca_cert_path = ca_certs_dir / 'intermediate.cert.pem'
        ca_key_path = base_dir / 'private' / 'intermediate.key.pem'

        if not ca_cert_path.exists() or not ca_key_path.exists():
            raise HTTPException(
                status_code=503,
                detail="Intermediate CA not available"
            )

        # Читаем пароль CA из переменной окружения или файла
        ca_pass_file = os.environ.get('MICROPKI_CA_PASS_FILE', './secrets/ca.pass')
        if not Path(ca_pass_file).exists():
            raise HTTPException(
                status_code=503,
                detail=f"CA passphrase file not found: {ca_pass_file}"
            )

        with open(ca_pass_file, 'rb') as f:
            ca_passphrase = f.read().rstrip(b'\r\n')

        # Выпускаем сертификат
        try:
            import logging as _logging
            from .ca import issue_certificate
            from fastapi.responses import Response as _Response

            ca_logger = _logging.getLogger('micropki.api')

            serial_hex = issue_certificate(
                ca_cert_path=ca_cert_path,
                ca_key_path=ca_key_path,
                ca_passphrase=ca_passphrase,
                template_name=template,
                subject_dn="",
                san_entries=[],
                out_dir=ca_certs_dir,
                validity_days=365,
                logger=ca_logger,
                db_path=db_path,
                csr_pem=body
            )

            cert_data = db.get_certificate(serial_hex)
            if not cert_data:
                raise HTTPException(status_code=500, detail="Certificate not saved to DB")

            http_logger.logger.info(
                f"CSR signed: client={client_ip} serial={serial_hex} template={template}"
            )

            return _Response(
                content=cert_data['cert_pem'],
                media_type="application/x-pem-file",
                status_code=201,
                headers={
                    'X-Certificate-Serial': serial_hex,
                    'Content-Disposition': 'attachment; filename="cert.pem"'
                }
            )

        except ValueError as e:
            http_logger.logger.error(f"CSR rejected from {client_ip}: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except HTTPException:
            raise
        except Exception as e:
            http_logger.logger.error(f"CSR signing failed from {client_ip}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to issue certificate: {e}")


            from fastapi.responses import Response as _Response
            return _Response(
                    content=cert_data['cert_pem'],
                    media_type="application/x-pem-file",
                    status_code=201,
                    headers={
                        'X-Certificate-Serial': serial_hex,
                        'Content-Disposition': f'attachment; filename="cert.pem"'
                    }
                )

        except ValueError as e:
            http_logger.logger.error(f"CSR rejected: {e}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            http_logger.logger.error(f"CSR signing failed: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to issue certificate: {e}")


    @app.get("/statistics", response_model=Statistics, tags=["General"])
    def get_statistics():

        return db.get_statistics()

    @app.get("/search", response_model=CertificateList, tags=["Certificates"])
    def search_certificates(
            q: str = Query(..., description="Search query (subject pattern)")
    ):

        pattern = f"%{q}%"
        certs = db.search_by_subject(pattern)

        certs_info = [
            {k: v for k, v in cert.items() if k != 'cert_pem'}
            for cert in certs
        ]

        return {
            'total': len(certs_info),
            'certificates': certs_info
        }

    return app