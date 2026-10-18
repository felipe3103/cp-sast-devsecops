# 🛡️ SentinelaSAST — Plataforma SAST & DevSecOps

Projeto Integrador · Engenharia de Software (3º ano) · FIAP 2026 · Prof. M.Sc. Oerton Fernandes

**Integrantes**

| Nome | RM |
|---|---|
| Felipe Braunstein e Silva | RM554483 |
| Felipe do Nascimento Fernandes | RM554598 |
| Henrique Ignacio Bartalo | RM555274 |
| Gustavo Henrique Martins | RM556956 |

O SentinelaSAST é uma plataforma de **Static Application Security Testing** que analisa código-fonte sem executá-lo, encontra vulnerabilidades (OWASP Top 10 / CWE), usa um **LLM local (Ollama + Llama 3)** para triagem e sugestão de correção e bloqueia Pull Requests inseguros por meio de **Security Gates** no GitHub Actions.

**Linguagem alvo escolhida: Python** (AST + taint analysis interprocedural). O motor é multilinguagem: **JavaScript via Tree-sitter**, também com regras e taint analysis.

📋 **[Matriz de conformidade](docs/conformidade.md)**: cada exigência do enunciado e do PDF ligada à sua evidência.

---

## Destaques

| Requisito do enunciado | Como foi atendido | Onde |
|---|---|---|
| Motor SAST com parser | AST do Python (`ast`) percorrida **uma única vez**, com despacho de nós por regra e resolução de aliases de import | `sast_engine/languages/python_ast.py`, `sast_engine/scanner.py` |
| Parsing multilinguagem | Tree-sitter para JavaScript (regras + taint de Express/navegador) | `sast_engine/languages/javascript_ts.py` |
| Regras determinísticas e heurísticas | 18 regras Python + 5 JS, mapeadas para CWE e OWASP 2021 | `sast_engine/rules/` |
| **CP1 — 3 violações iniciais** | `PY001` senha/segredo hardcoded, `PY002` `eval`/`exec`, `PY003` execução de comando via shell | `sast_engine/rules/python_rules.py` |
| **CP2 — Taint analysis** | Python: interprocedural (inclusive **entre arquivos**), sensível ao fluxo, com sanitizadores, guardas e trace fonte→sink. JavaScript: intraprocedural | `sast_engine/taint.py`, `javascript_ts.py` |
| **CP2 — IA (LLM local)** | Ollama/Llama 3 classifica severidade, reduz falsos positivos e gera correção **aplicada e re-escaneada no projeto inteiro**, com autocorreção guiada pelo validador | `sast_engine/ai/` |
| **CP2 — Demo de varredura semântica** | LLM procura falhas de **lógica** (IDOR, autenticação ausente) sem comentários/gabarito e sem repetir achados das regras | `samples/vulnerable_app/pedidos.py`, botão no dashboard, `--ai-semantic` |
| LangChain + Hugging Face | Chain LangChain sobre o Ollama + **RAG** com base CWE/OWASP/CVE e embeddings do Hugging Face Hub | `sast_engine/ai/rag.py`, `ollama_client.py` |
| Integração com Bandit/Semgrep | Resultados normalizados e deduplicados com o motor próprio | `sast_engine/integrations.py`, `rules/semgrep/` |
| Microsserviços + processamento assíncrono | FastAPI + Celery (filas `scans` e `ai`) + Redis + PostgreSQL + Ollama, via Docker Compose | `services/api/`, `docker-compose.yml` |
| **CP3 — Security Gates em CI/CD** | GitHub Actions com 7 controles e check único "Security Gate"; baseline para bloquear só achados **novos**; versão GitLab CI com relatório nativo | `.github/workflows/devsecops.yml`, `.gitlab-ci.yml`, `action.yml` |
| **CP3 — Dashboard executivo** | Rosca de severidade, tendência, top 5 arquivos críticos, OWASP, **falhas detectadas (CVEs reais)**, KPIs, drill-down com código, fluxo e IA | `services/api/app/static/` |
| Testes contínuos | 107 testes (regras, taint, IA, gate, API) + benchmark de precisão/recall no CI | `tests/`, `benchmark/` |

![Dashboard executivo: KPIs, severidade em rosca e tendência por varredura](docs/img/dashboard.jpg)

![Painel "Falhas detectadas": CVEs reais da mesma classe das falhas encontradas](docs/img/falhas-detectadas.jpg)

### Resultados medidos

Benchmark (`python benchmark/run_benchmark.py`) sobre as amostras anotadas (`# expect:`): **51 vulnerabilidades** (36 em Python, 15 em JavaScript). A linha do Bandit e do Semgrep compara só as 36 de Python:

| Ferramenta | Precisão | Recall | Observação |
|---|---|---|---|
| **SentinelaSAST** | **100%** | **100%** | ~520 linhas em ~15 ms |
| SentinelaSAST **sem** taint analysis | 73,7% | 54,9% | ablação: o F1 cai de 1,0 para 0,63 |
| Bandit 1.9 | 62% | 69% | não faz taint; marca `import pickle` etc.; não vê SSRF/XSS/path traversal |
| Semgrep (4 regras do grupo) | 80% | 11% | só as regras customizadas; não segue fluxo entre arquivos |

> ⚠️ **Análise crítica:** o corpus foi escrito pelo próprio grupo, então há viés a favor do nosso motor. As regras foram ajustadas contra ele. O número que importa para a defesa é a **ablação** (o taint sobe o F1 de 0,63 para 1,0) e os **casos negativos** em `samples/safe_app` e `tests/test_rules.py`, que medem falso positivo de forma independente das regras. Limitações conhecidas estão em [`docs/motor-sast.md`](docs/motor-sast.md#limitações-conhecidas).

---

## Como executar

### 1) Plataforma completa (Docker)

```bash
cp .env.example .env              # defina POSTGRES_PASSWORD e SAST_API_TOKEN
docker compose up -d --build      # API + workers + PostgreSQL + Redis
docker compose --profile ai up -d # (opcional) + Ollama baixando o llama3 (~4,7 GB)
python scripts/seed_demo.py       # popula o dashboard com 5 varreduras de exemplo
```

> **Máquina com pouca RAM (ex.: Mac com 8 GB)?** Rode o Ollama nativo (usa a GPU) em vez do container:
> `brew install ollama && brew services start ollama && ollama pull llama3.2:3b`, e no `.env` defina
> `OLLAMA_MODEL=llama3.2:3b` e `OLLAMA_URL=http://host.docker.internal:11434`. Para o RAG: `ollama pull hf.co/nomic-ai/nomic-embed-text-v1.5-GGUF:Q8_0`. No macOS sem Docker Desktop:
> `brew install colima docker docker-compose && colima start --memory 3`.

- Dashboard: <http://localhost:8000>
- API / Swagger: <http://localhost:8000/docs>

### 2) Só o motor (sem Docker, sem dependências)

O motor usa apenas a biblioteca padrão do Python (3.11+).

```bash
python -m sast_engine scan samples/vulnerable_app                 # relatório no terminal
python -m sast_engine scan . --fail-on high                       # Security Gate (exit 1 se reprovar)
python -m sast_engine scan . --format sarif -o sast.sarif          # SARIF p/ GitHub Code Scanning
python -m sast_engine scan app/ --ai                              # triagem com Ollama/Llama 3
python -m sast_engine scan . --bandit --semgrep                   # visão consolidada multi-motor
python -m sast_engine scan app/ --ai-semantic                     # falhas de lógica via LLM
python -m sast_engine scan . --format gitlab -o gl-sast-report.json   # relatório GitLab
python -m sast_engine rules                                       # catálogo de regras
```

### 3) Desenvolvimento e testes

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
make test        # 107 testes
make benchmark   # precisão / recall / ablação
make gate        # mesmo Security Gate do CI, no próprio repositório
```

---

## Estrutura

```
sast_engine/              motor SAST (biblioteca padrão; CLI em cli.py)
  languages/              parsers: Python (ast) e JavaScript (Tree-sitter)
  rules/                  catálogo (CWE/OWASP/remediação), regras Python, heurística de segredos
  taint.py                taint analysis interprocedural
  ai/                     cliente Ollama, prompts, triagem com guardrails
  gate.py, reporters.py   Security Gate e relatórios (texto, JSON, SARIF, Markdown)
  integrations.py         Bandit e Semgrep
services/api/app/         FastAPI, Celery, SQLAlchemy e dashboard estático
rules/semgrep/            regras Semgrep customizadas (modo taint)
samples/                  apps de teste escritos pelo grupo (vulnerável, segura, JS)
benchmark/                cálculo de precisão/recall contra o ground truth
tests/                    suíte pytest
docs/                     documentação técnica e roteiro da defesa
.github/workflows/        pipeline DevSecOps
action.yml                GitHub Action reutilizável do Security Gate
```

## Evidências no GitHub

- Pipeline DevSecOps: aba **Actions**. Todos os controles verdes na `main`.
- Proteção da branch `main`: merge exige o check **Security Gate**.
- **PR #1 (demo):** adiciona uma rota com Command Injection. O SentinelaSAST detecta o fluxo `host → os.popen` (CRITICAL), comenta o relatório no PR, publica o alerta no **Code Scanning** e o merge fica **bloqueado**.

## Documentação

- [Arquitetura (C4 + decisões)](docs/arquitetura.md)
- [Motor SAST, regras e taint analysis](docs/motor-sast.md)
- [Módulo de IA](docs/ia.md)
- [DevSecOps e Security Gates](docs/devsecops.md)
- [API e dashboard](docs/api.md)
- [Roteiro da defesa](docs/defesa.md)
- [Matriz de conformidade com o enunciado/PDF](docs/conformidade.md)

## Ética e propriedade intelectual

- Todo código vulnerável em `samples/` foi **escrito pelo grupo** para testes. Nenhum código de terceiros foi copiado.
- A varredura de repositórios Git aceita só **hosts autorizados** (`ALLOWED_GIT_HOSTS`) e clona apenas repositórios públicos (sem credenciais). A plataforma deve ser usada só em código próprio, open source ou com autorização expressa do dono.
- O LLM roda **localmente** (Ollama): o código analisado não sai da máquina/rede da organização.
- As chaves que aparecem nas amostras são exemplos públicos/falsos (ex.: `AKIAIOSFODNN7EXAMPLE`, da documentação da AWS).
