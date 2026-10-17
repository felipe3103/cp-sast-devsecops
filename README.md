# 🛡️ SentinelaSAST — Plataforma SAST & DevSecOps

Projeto Integrador · Engenharia de Software (3º ano) · FIAP 2026 · Prof. M.Sc. Oerton Fernandes

O SentinelaSAST é uma plataforma de **Static Application Security Testing** que analisa código-fonte sem executá-lo, encontra vulnerabilidades (OWASP Top 10 / CWE), usa um **LLM local (Ollama + Llama 3)** para triagem e sugestão de correção e bloqueia Pull Requests inseguros por meio de **Security Gates** no GitHub Actions.

**Linguagem alvo escolhida: Python** (análise completa com AST + taint analysis). Como prova do motor multilinguagem, há também um analisador **JavaScript via Tree-sitter**.

---

## Destaques

| Requisito do enunciado | Como foi atendido | Onde |
|---|---|---|
| Motor SAST com parser | AST do Python (`ast`) percorrida **uma única vez**, com despacho de nós por regra e resolução de aliases de import | `sast_engine/languages/python_ast.py`, `sast_engine/scanner.py` |
| Parsing multilinguagem | Tree-sitter para JavaScript | `sast_engine/languages/javascript_ts.py` |
| Regras determinísticas e heurísticas | 18 regras Python + 5 JS, mapeadas para CWE e OWASP 2021 | `sast_engine/rules/` |
| **CP1 — 3 violações iniciais** | `PY001` senha/segredo hardcoded, `PY002` `eval`/`exec`, `PY003` execução de comando via shell | `sast_engine/rules/python_rules.py` |
| **CP2 — Taint analysis** | Interprocedural (inclusive **entre arquivos**), sensível ao fluxo, com sanitizadores, guardas e trace fonte→sink | `sast_engine/taint.py` |
| **CP2 — IA (LLM local)** | Ollama/Llama 3 classifica severidade, reduz falsos positivos e gera correção **validada em ciclo fechado** | `sast_engine/ai/` |
| Integração com Bandit/Semgrep | Resultados normalizados e deduplicados com o motor próprio | `sast_engine/integrations.py`, `rules/semgrep/` |
| Microsserviços + processamento assíncrono | FastAPI + Celery (filas `scans` e `ai`) + Redis + PostgreSQL + Ollama, via Docker Compose | `services/api/`, `docker-compose.yml` |
| **CP3 — Security Gates em CI/CD** | Pipeline com 7 controles e check único "Security Gate"; baseline para bloquear só achados **novos** | `.github/workflows/devsecops.yml`, `action.yml` |
| **CP3 — Dashboard executivo** | Severidade, tendência, top 5 arquivos críticos, OWASP, KPIs, drill-down com código, fluxo e IA | `services/api/app/static/` |
| Testes contínuos | 75 testes (regras, taint, IA, gate, API) + benchmark de precisão/recall no CI | `tests/`, `benchmark/` |

### Resultados medidos

Benchmark (`python benchmark/run_benchmark.py`) sobre as amostras anotadas (`# expect:`), com 36 vulnerabilidades em Python e 9 em JS:

| Ferramenta | Precisão | Recall | Observação |
|---|---|---|---|
| **SentinelaSAST** | **100%** | **100%** | 445 linhas analisadas em ~13 ms |
| SentinelaSAST **sem** taint analysis | 83,8% | 68,9% | ablação: mostra o ganho do módulo de taint |
| Bandit 1.9 | 62% | 69% | não faz taint; marca `import pickle` etc.; não vê SSRF/XSS/path traversal |
| Semgrep (4 regras do grupo) | 80% | 11% | só as regras customizadas; não segue fluxo entre arquivos |

> ⚠️ **Análise crítica:** o corpus foi escrito pelo próprio grupo, então há viés a favor do nosso motor. As regras foram ajustadas contra ele. O número que importa para a defesa é a **ablação** (o taint sobe o F1 de 0,76 para 1,0) e os **casos negativos** em `samples/safe_app` e `tests/test_rules.py`, que medem falso positivo de forma independente das regras. Limitações conhecidas estão em [`docs/motor-sast.md`](docs/motor-sast.md#limitações-conhecidas).

---

## Como executar

### 1) Plataforma completa (Docker)

```bash
cp .env.example .env              # defina POSTGRES_PASSWORD e SAST_API_TOKEN
docker compose up -d --build      # API + workers + PostgreSQL + Redis
docker compose --profile ai up -d # (opcional) + Ollama baixando o llama3 (~4,7 GB)
python scripts/seed_demo.py       # popula o dashboard com 5 varreduras de exemplo
```

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
python -m sast_engine rules                                       # catálogo de regras
```

### 3) Desenvolvimento e testes

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
make test        # 75 testes
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

## Documentação

- [Arquitetura (C4 + decisões)](docs/arquitetura.md)
- [Motor SAST, regras e taint analysis](docs/motor-sast.md)
- [Módulo de IA](docs/ia.md)
- [DevSecOps e Security Gates](docs/devsecops.md)
- [API e dashboard](docs/api.md)
- [Roteiro da defesa](docs/defesa.md)

## Ética e propriedade intelectual

- Todo código vulnerável em `samples/` foi **escrito pelo grupo** para testes. Nenhum código de terceiros foi copiado.
- A varredura de repositórios Git aceita só **hosts autorizados** (`ALLOWED_GIT_HOSTS`) e clona apenas repositórios públicos (sem credenciais). A plataforma deve ser usada só em código próprio, open source ou com autorização expressa do dono.
- O LLM roda **localmente** (Ollama): o código analisado não sai da máquina/rede da organização.
- As chaves que aparecem nas amostras são exemplos públicos/falsos (ex.: `AKIAIOSFODNN7EXAMPLE`, da documentação da AWS).
