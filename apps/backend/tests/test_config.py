from app.core.config import Settings, get_settings


def test_settings_vem_do_ambiente():
    settings = get_settings()
    assert settings.app_env == "test"
    assert settings.cors_allowed_origins == ["http://localhost:3039"]
    assert settings.access_token_ttl_seconds == 900


def test_origens_separadas_por_virgula(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://a.example, https://b.example")
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.cors_allowed_origins == ["https://a.example", "https://b.example"]


def test_segredos_nao_aparecem_no_repr():
    settings = get_settings()
    texto = repr(settings)
    assert settings.master_key.get_secret_value() not in texto
    assert settings.hash_pepper.get_secret_value() not in texto
