from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict[str, str]:
    """Indica que a API está no ar."""
    return {"status": "ok"}
