from pathlib import Path
from typing import Optional
import logging

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .database import CertificateDatabase
from .crypto_utils import load_certificate
from .ocsp import OCSPHandler


def load_unencrypted_private_key(path: Path):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.backends import default_backend
    return load_pem_private_key(Path(path).read_bytes(), password=None, backend=default_backend())


def create_ocsp_app(
    db_path: Path,
    responder_cert_path: Path,
    responder_key_path: Path,
    ca_cert_path: Path,
    cache_ttl: int = 60,
    logger: Optional[logging.Logger] = None
) -> FastAPI:

    if logger is None:
        logger = logging.getLogger('micropki.ocsp')

    db = CertificateDatabase(db_path)
    ca_cert = load_certificate(ca_cert_path)
    responder_cert = load_certificate(responder_cert_path)
    responder_key = load_unencrypted_private_key(responder_key_path)

    handler = OCSPHandler(
        db=db,
        ca_cert=ca_cert,
        responder_cert=responder_cert,
        responder_key=responder_key,
        cache_ttl=cache_ttl,
        logger=logger
    )

    app = FastAPI(
        title="MicroPKI OCSP Responder",
        description="OCSP Responder compliant with RFC 6960",
        version="1.0.0"
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["POST", "GET"],
        allow_headers=["*"],
    )

    @app.post("/ocsp")
    async def ocsp_post(request: Request):
        content_type = request.headers.get("content-type", "")
        if "application/ocsp-request" not in content_type:
            logger.warning("OCSP request with wrong Content-Type")
            raise HTTPException(status_code=400, detail="Expected application/ocsp-request")

        body = await request.body()
        if not body:
            raise HTTPException(status_code=400, detail="Empty request body")

        client_ip = request.client.host if request.client else "unknown"
        response_der = handler.handle_request(body, client_ip)

        return Response(
            content=response_der,
            media_type="application/ocsp-response"
        )

    @app.get("/")
    def root():
        return {
            "service": "MicroPKI OCSP Responder",
            "version": "1.0.0",
            "endpoint": "POST /ocsp"
        }

    return app