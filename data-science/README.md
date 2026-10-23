# 🧪 Data Science Workspace

Bem-vindo à área de Ciência de Dados e IA. Aqui desenvolvemos modelos, rodamos experimentos e analisamos dados para os projetos de bateria e energia.

## 📂 Estrutura

*   **`experiments/`**: Notebooks Jupyter e logs de experimentos.
    *   *Convenção:* Use nomes descritivos, ex: `01_analise_exploratoria.ipynb`.
*   **`models/`**: Artefatos binários (`.pkl`, `.h5`, `.onnx`).
    *   **⚠️ Atenção:** Estes arquivos são versionados pelo DVC, não pelo Git.
*   **`src/`**: Código fonte Python estruturado (scripts de treino, processamento, inferência).

## 🚀 Configuração do Ambiente

Para garantir que todos usem as mesmas versões de bibliotecas e o DVC configurado corretamente, utilizamos um script de automação.

### Passo Único (Windows/PowerShell)
Na raiz do repositório, execute:

```powershell
./scripts/setup-ds.ps1
```

**O que esse script faz?**
1.  Cria o ambiente virtual Python (`.venv`).
2.  Instala as bibliotecas (`requirements.txt`).
3.  Inicializa o **DVC**.

---

## 🤖 Guia Prático do DVC (Data Version Control)

Arquivos pesados (>10MB) não sobem para o GitHub. Eles ficam guardados no **AWS S3** e o DVC gerencia os links.

### 1. Preparação (Primeira vez)
Sempre ative seu ambiente virtual antes de usar o DVC:
```powershell
.\.venv\Scripts\Activate.ps1
```

Se for sua primeira vez no projeto, configure suas chaves AWS (peça ao Líder Técnico):
```powershell
dvc remote modify --local s3-storage access_key_id SUA_CHAVE
dvc remote modify --local s3-storage secret_access_key SUA_SENHA
```

### 2. Fluxo de Trabalho Diário

**Para quem cria um modelo/dado novo:**
```powershell
# 1. Adicione o arquivo ao DVC
dvc add models/meu_modelo.pkl

# 2. Registre o "ticket" (.dvc) no Git
git add models/meu_modelo.pkl.dvc models/.gitignore
git commit -m "exp: treina modelo v1"

# 3. Suba o arquivo pesado para a nuvem (S3)
dvc push
```

**Para quem quer baixar o modelo de um colega:**
```powershell
# 1. Pegue as atualizações do Git
git pull

# 2. Baixe os arquivos pesados do S3
dvc pull
```

### 3. "Viagem no Tempo" (Trocar Versões)
Se você precisar voltar para uma versão antiga do modelo que estava em outro commit:
```powershell
# 1. Volte o arquivo .dvc para o estado antigo
git checkout <hash-do-commit> models/meu_modelo.pkl.dvc

# 2. Peça ao DVC para restaurar o arquivo real correspondente
dvc checkout
```

### 4. Comandos Essenciais

*   `dvc status`: Vê se algum arquivo pesado foi alterado.
*   `dvc pull`: Baixa dados da nuvem.
*   `dvc push`: Sobe dados para a nuvem.
*   `dvc checkout`: Restaura arquivos baseados nos arquivos `.dvc` atuais.