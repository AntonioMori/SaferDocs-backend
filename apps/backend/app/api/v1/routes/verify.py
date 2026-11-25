"""Verificação pública de documentos (REQ-50 a 54). Não exige autenticação."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.deps import DbSession
from app.core.config import get_settings
from app.core.request_info import client_ip
from app.middlewares.rate_limit import check_rate_limit
from app.pdf.upload import PdfUpload, pdf_upload_with
from app.schemas.documents import VerificationOut
from app.services import verify_service

router = APIRouter(tags=["verify"])

VerifyUpload = Annotated[PdfUpload, Depends(pdf_upload_with())]


def limit_verify_by_ip(request: Request) -> None:
    """REQ-53: limite por IP da rota pública, lido do .env a cada pedido."""
    check_rate_limit("verify", client_ip(request) or "desconhecido", get_settings().rate_limit_verify_per_ip)


# O rate limit é dependência do decorador: roda antes de o upload ser lido.
@router.post("/verify", response_model=VerificationOut, dependencies=[Depends(limit_verify_by_ip)])
def verify_document(upload: VerifyUpload, request: Request, db: DbSession) -> VerificationOut:
    """Confere um PDF assinado (multipart: file).

    Resultado: INTEGRO (com quem assinou, quando e o id da assinatura), ADULTERADO
    ou NAO_ENCONTRADA. O PDF é processado em memória e descartado.
    """
    return verify_service.verify_document(db, upload.pdf, request)
