"""Assinatura de documentos (REQ-46 a 49). Todas as rotas exigem autenticação.

A autenticação é dependência do router: roda antes de o upload ser lido, então
quem não está autenticado não faz a API ler o PDF.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import CurrentUser, DbSession, get_auth_context
from app.pdf.upload import PdfUpload, pdf_upload_with
from app.schemas.documents import SignatureOut
from app.services import signing_service

router = APIRouter(prefix="/documents", tags=["documents"], dependencies=[Depends(get_auth_context)])

SignUpload = Annotated[PdfUpload, Depends(pdf_upload_with("page", "x", "y"))]


@router.post(
    "/sign",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}, "description": "PDF assinado"}},
)
def sign_document(upload: SignUpload, user: CurrentUser, request: Request, db: DbSession) -> Response:
    """Assina o PDF (multipart: file, page, x, y) e devolve o arquivo assinado.

    O id da assinatura volta no header `X-Signature-Id`. O PDF não é guardado.
    """
    signed = signing_service.sign_document(db, user, upload, request)
    return Response(
        content=signed.pdf,
        media_type="application/pdf",
        headers={
            "X-Signature-Id": str(signed.signature_id),
            "Content-Disposition": 'attachment; filename="documento-assinado.pdf"',
        },
    )


@router.get("/signatures", response_model=list[SignatureOut])
def list_signatures(user: CurrentUser, db: DbSession) -> list[SignatureOut]:
    """Histórico das minhas assinaturas: só metadados e hashes, nunca o PDF."""
    return [
        SignatureOut.model_validate(s, from_attributes=True)
        for s in signing_service.list_signatures(db, user)
    ]
