# Script de Inicializacao de Data Science (VENV + DVC + Python)
# Execute este script se voce for trabalhar na pasta data-science/

Write-Host "Configurando ambiente de Data Science..." -ForegroundColor Cyan

# 1. Verifica se o Python esta instalado
python --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "Erro: Python nao encontrado no PATH." -ForegroundColor Red
    exit
}

# 2. Cria o Ambiente Virtual (.venv) se nao existir
if (-not (Test-Path ".venv")) {
    Write-Host "Criando ambiente virtual (.venv)..." -ForegroundColor Yellow
    python -m venv .venv
    if (-not (Test-Path ".venv")) {
        Write-Host "Erro: Falha ao criar a pasta .venv. Verifique suas permissoes." -ForegroundColor Red
        exit
    }
    Write-Host "Ambiente virtual criado com sucesso." -ForegroundColor Green
} else {
    Write-Host "Ambiente virtual (.venv) ja existe." -ForegroundColor Green
}

# Definindo caminhos dos executaveis
$venvPython = ".\.venv\Scripts\python.exe"
$venvPip = ".\.venv\Scripts\pip.exe"
$venvDvc = ".\.venv\Scripts\dvc.exe"

# Verifica se o Python do venv existe
if (-not (Test-Path $venvPython)) {
    Write-Host "Erro critico: O executavel do Python nao foi encontrado em $venvPython" -ForegroundColor Red
    exit
}

# 3. Instala dependencias dentro do .venv
Write-Host "Instalando dependencias no .venv..." -ForegroundColor Yellow
& $venvPython -m pip install --upgrade pip
& $venvPip install -r data-science/requirements.txt

# 4. Inicializa o DVC (Data Version Control)
if (-not (Test-Path ".dvc")) {
    Write-Host "Inicializando DVC..." -ForegroundColor Yellow
    
    # Verifica se o DVC foi instalado corretamente
    if (Test-Path $venvDvc) {
        & $venvDvc init
        git add .dvc .dvcignore
        git commit -m "chore: inicializa DVC para versionamento de modelos"
        Write-Host "DVC inicializado." -ForegroundColor Green
    } else {
        Write-Host "Erro: O DVC nao foi encontrado apos a instalacao. Verifique o arquivo requirements.txt." -ForegroundColor Red
    }
} else {
    Write-Host "DVC ja configurado." -ForegroundColor Green
}

Write-Host "Ambiente de DS pronto!" -ForegroundColor Green
Write-Host "IMPORTANTE: Para ativar o ambiente, use: .\.venv\Scripts\Activate.ps1" -ForegroundColor Cyan