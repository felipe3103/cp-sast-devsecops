# Matriz de conformidade: enunciado e PDF → evidência

Cada exigência do enunciado da atividade e do PDF *"Projeto Integrador: Plataforma SAST & DevSecOps"* (Prof. M.Sc. Oerton Fernandes, 2026), com onde está atendida e como verificar.

## Enunciado: "A solução precisa incluir"

| Exigência | Evidência | Como verificar |
|---|---|---|
| Motor de análise baseado em SAST | `sast_engine/` (analisa o código sem executá-lo) | `python -m sast_engine scan samples/vulnerable_app` |
| Regras determinísticas e heurísticas de segurança | 18 regras Python + 5 JS, com campo `kind` (`deterministic`/`heuristic`/`taint`) em `sast_engine/rules/catalog.py` | `python -m sast_engine rules` |
| Módulo de IA para interpretação semântica e sugestões de correção | `sast_engine/ai/`: triagem, remediação com código, varredura semântica, RAG | `docs/ia.md`; botões "Analisar com IA" e "Varredura semântica (IA)" no dashboard |
| Arquitetura escalável com microsserviços e processamento assíncrono | `docker-compose.yml`: `api`, `worker-scan`, `worker-ai`, `postgres`, `redis`, `ollama`; filas Celery separadas | `docker compose ps`; `docs/arquitetura.md` |
| Integração DevSecOps com pipelines automatizados | `.github/workflows/devsecops.yml` (8 jobs) e `.gitlab-ci.yml` | aba Actions do repositório |
| Dashboard analítico com severidade, tendência de falhas e arquivos críticos | `services/api/app/static/` | <http://localhost:8000> |

## Enunciado: tecnologias recomendadas

| Tecnologia | Uso no projeto |
|---|---|
| Tree-sitter | parser e taint analysis de JavaScript (`sast_engine/languages/javascript_ts.py`) |
| Python AST | parser principal (`sast_engine/languages/python_ast.py`) |
| Bandit | job bloqueante no CI e motor complementar (`--bandit`), deduplicado com o nosso |
| Semgrep | regras customizadas em modo taint (`rules/semgrep/`), job no CI e motor complementar (`--semgrep`) |
| FastAPI | API REST (`services/api/app/main.py`) |
| PostgreSQL | banco da plataforma (`postgres` no compose) |
| Redis / Celery | broker e workers assíncronos (`services/api/app/worker.py`) |
| Docker | `Dockerfile` (usuário sem root) e `docker-compose.yml` |
| GitHub Actions | `.github/workflows/devsecops.yml`, `action.yml` reutilizável |
| Ollama / Llama 3 | LLM local; testado com **Llama 3 8B** e Llama 3.2 3B |

## Enunciado: "O grupo precisará entregar"

| Entregável | Evidência |
|---|---|
| Arquitetura técnica containerizada | `docker-compose.yml`, `Dockerfile`, `docs/arquitetura.md` (C4) |
| Parser funcional com detecção inicial de violações | `python_ast.py` + PY001/PY002/PY003 |
| Módulo de taint analysis | `sast_engine/taint.py` (Python, interprocedural) e `_JSTaint` (JavaScript) |
| Integração com IA para classificação de severidade e remediação | `AITriage` (veredito, severidade com guardrail de ±1 nível, código corrigido validado no projeto) |
| Dashboard executivo com métricas claras | KPIs, rosca de severidade, tendência, top 5 arquivos, OWASP, falhas detectadas (CVEs) |
| Documentação técnica e defesa final | `README.md`, `docs/*.md`, roteiro `docs/defesa.md` e [slides da defesa](https://claude.ai/artifact/3JM6CUphSCjJVh2b44DhVt) |

## Enunciado: considerações

| Consideração | Evidência |
|---|---|
| Escolha da linguagem alvo no início | **Python**, declarado no README; JS como segunda linguagem |
| Ética e propriedade intelectual | amostras escritas pelo grupo; clone só de host autorizado e repositório público; LLM local; PDF do professor fora do repositório público |
| Testes contínuos | 107 testes + benchmark com precisão/recall mínimos no CI |
| Conteinerização funcional | stack testada com `docker compose up` (Colima) e smoke test do container no CI |
| Pipelines com Security Gates | check obrigatório "Security Gate" na `main`; PR #1 bloqueado |

## PDF: o desafio SAST

| Item do PDF | Evidência |
|---|---|
| Parsing multilinguagem com ASTs robustas | Python (`ast`) e JavaScript (Tree-sitter), ambos com regras **e** taint |
| Regras e heurísticas, verificações determinísticas e análise semântica | regras determinísticas/heurísticas + taint + varredura semântica por LLM |
| Remediação com IA: sugestões de correção automáticas e contextuais | `fixed_code` gerado com o contexto da função, RAG com CWE/CVE e validação re-escaneando o projeto |
| Escalabilidade: microsserviços assíncronos e processamento em fila | filas `scans` e `ai` em workers independentes |

## PDF: arquitetura e stack

| Componente | Recomendado | Usado |
|---|---|---|
| Engine de análise | Tree-sitter, Python AST, Bandit, Semgrep | os quatro |
| Módulo de IA | Ollama (Llama 3), Hugging Face, LangChain | os três: chain `ChatPromptTemplate → ChatOllama → JsonOutputParser` (LangChain); RAG com `InMemoryVectorStore` e embeddings `nomic-embed-text` **baixados do Hugging Face Hub** |
| Backend e API | FastAPI, PostgreSQL, Redis/Celery | os três |
| DevSecOps | Docker, GitHub Actions, GitLab CI | os três (`.gitlab-ci.yml` com relatório `gl-sast-report.json` validado no schema oficial 15.0.7) |

## PDF: checkpoints

| Checkpoint | Item | Evidência |
|---|---|---|
| **CP1** | Ambiente conteinerizado com Docker | `docker-compose.yml` |
| | Arquitetura base (C4 Model) | `docs/arquitetura.md`: níveis 1, 2 e 3 + sequência |
| | Motor de parsing / AST | `python_ast.py`, `javascript_ts.py` |
| | Senhas hardcoded e funções perigosas (ex.: `eval`) | PY001, PY002 (+ PY003) |
| | **Entregáveis:** diagrama, repositório com Compose, parser funcional, 3 violações | ✅ |
| **CP2** | Taint analysis: entradas não sanitizadas → sinks | `taint.py`, trace fonte→sink no dashboard e no SARIF |
| | LLMs locais para classificar severidade e reduzir falsos positivos | veredito + supressão com confiança ≥ 0,8 (nunca de fluxo comprovado) |
| | Blocos de código corrigidos (Remediation Advice) | `fixed_code` + ciclo de autocorreção |
| | **Demo de varredura semântica** | `samples/vulnerable_app/pedidos.py` (IDOR, falta de autenticação, desconto controlado pelo cliente); botão no dashboard; `--ai-semantic` na CLI |
| **CP3** | Security Gates em CI/CD (GitHub Actions) bloqueando PRs inseguros | PR #1 com merge **BLOCKED** |
| | Dashboard executivo por arquivo, linha e severidade | tabela + painel de detalhe com código destacado |
| | Refinamento de UX e documentação | tema claro/escuro, tooltips, filtros, drill-down; `docs/` |
| | **Entregáveis:** plataforma 100% funcional, CI/CD com gates, dashboard e relatórios, defesa e documentação | ✅ (relatórios: SARIF, JSON, Markdown, GitLab SAST) |

## PDF: sugestões de dashboard

| Painel do PDF | Implementação |
|---|---|
| Severidade (rosca com %) | gráfico de rosca com percentual por severidade |
| Tendência de falhas | barras empilhadas por varredura, com resultado do gate |
| Top 5 arquivos críticos (nome + nº de falhas) | barras empilhadas por severidade, clicáveis |
| Falhas detectadas (CVE-2014-3704, CVE-2020-11022, CVE-2020-13379, CVE-2021-41773) | painel "Falhas detectadas" com esses quatro CVEs e outros, ligados às CWEs encontradas no código, com contagem e link para o NVD |

## PDF: critérios de avaliação

| Peso | Critério | Onde está a evidência |
|---|---|---|
| 25% | Arquitetura: AST/parsers, serviços, Docker | `docs/arquitetura.md`, ADRs, compose |
| 30% | Robustez SAST: precisão, eficiência, poucos falsos positivos | `benchmark/` (51 vulnerabilidades, ablação), `safe_app`, testes negativos, comparação com Bandit/Semgrep |
| 20% | Inovação IA: LLM local, análise semântica, correções úteis | guardrails, validação no projeto inteiro, autocorreção, RAG, resultados reais em `docs/ia.md` |
| 15% | DevSecOps: gates funcionais e relatórios claros | 8 jobs, baseline, SARIF/Code Scanning, comentário no PR, GitLab CI |
| 10% | Defesa: clareza e análise crítica | `docs/defesa.md`, slides, seção de limitações |

## PDF: ética e próximos passos

| Item | Situação |
|---|---|
| Só repositórios autorizados ou open source | allowlist de hosts + repositório público; amostras próprias |
| Formação de grupos (4–5 integrantes) | **responsabilidade do grupo:** adicionar os colegas como colaboradores no GitHub |
| Escolha da linguagem alvo | Python |
