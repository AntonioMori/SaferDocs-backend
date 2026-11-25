"""Verificação pública de documentos (REQ-50 a 54). Não exige autenticação."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request

from app.api.deps import DbSession
from app.pdf.upload import PdfUpload, pdf_upload_with
from app.schemas.documents import VerificationOut
from app.services import verify_service

router = APIRouter(tags=["verify"])

VerifyUpload = Annotated[PdfUpload, Depends(pdf_upload_with())]


@router.post("/verify", response_model=VerificationOut)
def verify_document(upload: VerifyUpload, request: Request, db: DbSession) -> VerificationOut:
    """Confere um PDF assinado (multipart: file).

    Resultado: INTEGRO (com quem assinou, quando e o id da assinatura), ADULTERADO
    ou NAO_ENCONTRADA. O PDF é processado em memória e descartado.
    """
    return verify_service.verify_document(db, upload.pdf, request)
