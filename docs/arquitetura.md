# Arquitetura técnica

Diagramas no modelo **C4**, em Mermaid (o GitHub renderiza direto).

## Nível 1 — Contexto

```mermaid
flowchart LR
    dev([👩‍💻 Desenvolvedor]) -- push / Pull Request --> gh[GitHub<br/>repositório + Actions]
    gh -- executa Security Gate<br/>e envia relatório --> sent[[SentinelaSAST<br/>Plataforma SAST]]
    sec([🛡️ Time de Segurança /<br/>Gestão]) -- consulta dashboard,<br/>triagem de achados --> sent
    dev -- upload .zip / URL de repo público --> sent
    sent -- SARIF --> cs[GitHub Code Scanning]
    sent -- comentário com relatório --> gh
```

## Nível 2 — Containers

```mermaid
flowchart TB
    subgraph Docker Compose
        api["<b>api</b><br/>FastAPI + dashboard estático<br/>:8000"]
        ws["<b>worker-scan</b><br/>Celery · fila <i>scans</i><br/>motor SAST + taint"]
        wa["<b>worker-ai</b><br/>Celery · fila <i>ai</i><br/>triagem por LLM"]
        redis[("<b>redis</b><br/>broker + resultados")]
        pg[("<b>postgres</b><br/>projetos, scans,<br/>achados, arquivos")]
        ollama["<b>ollama</b><br/>Llama 3 local<br/>:11434"]
    end
    user([Navegador / CLI / GitHub Actions]) -->|HTTP/JSON| api
    api -->|enfileira| redis
    redis --> ws
    redis --> wa
    ws --> pg
    wa --> pg
    api --> pg
    wa -->|/api/chat JSON schema| ollama
    ci[GitHub Actions<br/>CLI sast_engine] -->|POST /api/v1/scans/ci<br/>X-API-Token| api
```

| Container | Responsabilidade | Escala |
|---|---|---|
| `api` | REST, validação de entrada, ingestão segura (zip/git), métricas, dashboard | horizontal (stateless) |
| `worker-scan` | parsing, regras, taint, gate; CPU-bound e rápido | `-c 4` por réplica |
| `worker-ai` | chamadas ao LLM; lento e limitado pela GPU | `-c 1` (fila própria evita travar varreduras) |
| `postgres` | persistência relacional (histórico para tendência) | — |
| `redis` | broker Celery | — |
| `ollama` | LLM local; o código não sai da rede | GPU opcional |

## Nível 3 — Componentes do motor (`sast_engine`)

```mermaid
flowchart LR
    files[Arquivos] --> col[scanner.collect_files<br/>exclusões, limite de tamanho]
    col --> py[python_ast.parse_python<br/>AST + mapa de imports + pais]
    col --> js[javascript_ts<br/>Tree-sitter]
    py --> rules[Regras PY001..PY018<br/>1 passada na AST]
    py --> taint[TaintEngine<br/>resumos de função · ponto fixo]
    js --> jsr[Regras JS001..JS005]
    ext[Bandit / Semgrep<br/>opcionais] --> dedup
    rules --> dedup[Supressões · deduplicação<br/>taint &gt; heurística]
    taint --> dedup
    jsr --> dedup
    dedup --> ai[AITriage opcional<br/>guardrails + validação da correção]
    ai --> gate[gate.evaluate<br/>severidade · confiança · baseline]
    gate --> rep[reporters<br/>texto · JSON · SARIF · Markdown]
```

## Fluxo de uma varredura assíncrona

```mermaid
sequenceDiagram
    participant U as Usuário
    participant A as API
    participant R as Redis
    participant W as worker-scan
    participant I as worker-ai
    participant DB as PostgreSQL
    U->>A: POST /api/v1/scans/upload (.zip)
    A->>A: valida zip (zip slip, tamanho, extensões)
    A->>DB: cria Scan(status=queued)
    A->>R: run_scan.delay(scan_id, files)
    A-->>U: 202 Accepted {id}
    R->>W: tarefa
    W->>W: scan_sources() + Security Gate
    W->>DB: achados + arquivos com achados, status=completed
    opt AI_AUTO_TRIAGE ou botão "Triagem IA"
        W->>R: triage_finding_task.delay(id) (top N por risco)
        R->>I: tarefa
        I->>I: Ollama → guardrails → re-scan da correção
        I->>DB: finding.ai, severidade ajustada
    end
    U->>A: GET /api/v1/metrics (polling do dashboard)
```

## Decisões de arquitetura (ADRs resumidos)

1. **Python como linguagem alvo.** O `ast` da biblioteca padrão dá uma AST fiel e estável, sem dependências. Python também é a linguagem do Bandit, que usamos como referência de comparação.
2. **Motor sem dependências externas.** A CLI roda em qualquer runner de CI com `python -m sast_engine`, sem `pip install`. Isso reduz o tempo de pipeline e a superfície de supply chain.
3. **Uma única passada na AST.** Cada regra declara os tipos de nó que inspeciona (`@python_rule("PY002", ast.Call)`) e o scanner despacha cada nó só para as regras interessadas. O custo fica em O(nós), e não O(nós × regras).
4. **Taint por resumos de função com ponto fixo**, em vez de inlining. Cada função é analisada uma vez por iteração e as chamadas usam o resumo (parâmetro→retorno, parâmetro→sink). Isso escala para projetos inteiros e suporta recursão.
5. **Duas filas Celery.** O LLM leva segundos por achado. Se dividisse a fila com as varreduras, um PR grande travaria a análise de todos os outros.
6. **IA como assistente, não como juiz.** O LLM não remove sozinho um fluxo de taint comprovado e só ajusta a severidade em ±1 nível, e as correções são re-escaneadas (ver `docs/ia.md`). O resultado continua determinístico e auditável.
7. **Fingerprint independente de linha** (`regra + arquivo + trecho normalizado`). Permite comparar varreduras (novos × corrigidos, baseline do gate) mesmo quando o código é deslocado.
8. **SARIF 2.1.0** como formato de integração: o GitHub Code Scanning mostra os achados inline no PR, com `codeFlows` para o caminho do taint.

## Segurança da própria plataforma

| Ameaça | Controle |
|---|---|
| Zip slip / zip bomb no upload | caminhos absolutos ou com `..` são rejeitados; limite de tamanho descompactado e de nº de arquivos; symlinks ignorados; extração em memória |
| SSRF / injeção via URL de repositório | regex estrita `https://host/dono/repo`, allowlist de hosts, `git clone -- URL` sem shell, `GIT_TERMINAL_PROMPT=0`, timeout |
| Ingestão do CI forjada | `X-API-Token` comparado com `hmac.compare_digest` |
| XSS no dashboard | todo dado da API passa por `esc()` antes de `innerHTML` (exceção documentada em `.sast.toml`) |
| Vazamento de código para terceiros | LLM local (Ollama) |
| Container | usuário sem privilégios (`uid 10001`), imagem slim, Trivy no CI |
| Dogfooding | o pipeline roda o SentinelaSAST, o Bandit e o Semgrep no próprio código da plataforma |
