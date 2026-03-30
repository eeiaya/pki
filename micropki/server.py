
import logging
import re
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import CertificateDatabase
from .serial import is_valid_hex_serial

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
    def get_crl():

        return PlainTextResponse(
            content="CRL generation not yet implemented. See Sprint 4.",
            status_code=501,
            media_type="text/plain",
            headers={
                "X-CRL-Status": "not-implemented",
                "Content-Type": "application/pkix-crl"
            }
        )

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