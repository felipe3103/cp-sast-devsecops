# API REST e dashboard

Swagger interativo em `http://localhost:8000/docs`.

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | Dashboard executivo |
| GET | `/health` | status da API |
| GET | `/api/v1/rules` | catálogo de regras (CWE, OWASP, remediação) |
| GET | `/api/v1/ai/status` | Ollama disponível? qual modelo? |
| GET | `/api/v1/projects` | projetos |
| POST | `/api/v1/scans/upload` | multipart: `file` (.zip/.py/.js) + `project`, retorna **202** e enfileira |
| POST | `/api/v1/scans/git` | `{repo_url, project?, ref?}`, só repositório público de host permitido |
| POST | `/api/v1/scans/snippet` | `{code, filename, project}` para analisar um trecho colado |
| POST | `/api/v1/scans/ci` | relatório JSON da CLI no pipeline (header `X-API-Token`) |
| GET | `/api/v1/scans?project=` | histórico |
| GET | `/api/v1/scans/{id}` | status, contagens, resultado do gate |
| GET | `/api/v1/scans/{id}/findings?severity=HIGH,CRITICAL&status=open&file=` | achados ordenados por severidade e risco |
| GET | `/api/v1/scans/{id}/report.sarif` · `.md` · `.json` | relatórios |
| POST | `/api/v1/scans/{id}/ai?limit=15` | enfileira triagem por IA dos achados de maior risco |
| POST | `/api/v1/scans/{id}/semantic` | varredura semântica por LLM (falhas de lógica) |
| GET | `/api/v1/findings/{id}` | detalhe com contexto de código, trace e análise da IA |
| PATCH | `/api/v1/findings/{id}` | `{status: open|false_positive|accepted_risk|fixed}` |
| POST | `/api/v1/findings/{id}/ai?sync=true` | triagem imediata de um achado |
| GET | `/api/v1/metrics?project=` | KPIs, severidade, tendência, top 5 arquivos, OWASP, CWE, motores |

## Dashboard

- **KPIs:** achados abertos, críticos, altos, risco acumulado, projetos reprovados no gate, achados triados pela IA, falsos positivos descartados e novos × corrigidos em relação à varredura anterior.
- **Severidade:** barras com contagem e percentual (a cor sempre vem acompanhada do rótulo).
- **Tendência:** barras empilhadas por varredura (clique numa barra para abrir aquela varredura); o tooltip mostra o resultado do gate.
- **Top 5 arquivos críticos:** barras empilhadas por severidade (clique filtra a tabela por arquivo).
- **OWASP Top 10:** distribuição por categoria.
- **Tabela de achados:** filtro por varredura, severidade e status. Ao clicar num achado abre um painel com código (linha destacada), fluxo de taint passo a passo, remediação, análise da IA (veredito, cenário de exploração, correção validada) e alteração de status.
- Tema claro/escuro (segue o sistema, com alternância manual), sem dependências externas: os gráficos são SVG gerados pelo próprio `app.js`.

## Modelo de dados

`projects (1) ─ (N) scans (1) ─ (N) findings`, mais `scans (1) ─ (N) scan_files`, que guarda só os arquivos com achados (contexto para a IA e o painel).
