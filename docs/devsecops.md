# DevSecOps e Security Gates

Workflow: `.github/workflows/devsecops.yml` (executa em `push` na `main`, em todo `pull_request` e manualmente).

## Jobs

| Job | Controle | Bloqueia? |
|---|---|---|
| `tests` | 80 testes pytest + benchmark com **precisão e recall ≥ 90%** | sim |
| `sast` | **SentinelaSAST** no repositório: SARIF no Code Scanning, relatório como comentário no PR e no Job Summary, envio opcional ao dashboard | sim, achado **novo** HIGH+ com confiança ≥ MEDIUM |
| `gate-demo` | prova que o gate **reprova** `samples/vulnerable_app` e **aprova** `samples/safe_app` | sim |
| `bandit` | Bandit em severidade ≥ MEDIUM no código da plataforma | sim |
| `semgrep` | regras customizadas do grupo (bloqueante) + `p/python` e `p/secrets` (informativo, SARIF) | regras do grupo |
| `dependencies` | **SCA** com `pip-audit` nas dependências | sim |
| `container` | build da imagem, **Trivy** (CRITICAL/HIGH corrigíveis) e smoke test do `/health` | sim |
| `security-gate` | consolida todos os jobs num **check único** | sim |

## Política do gate (`sast_engine/gate.py`)

```
reprova se existir achado com:
    severidade ≥ --fail-on (padrão HIGH)
  E confiança ≥ --min-confidence (padrão MEDIUM)
  E não está no baseline (fingerprint já conhecido na branch base)
  E não foi suprimido pela IA (falso positivo com confiança ≥ 0,8)
ou se o total de achados exceder --max-findings (opcional)
```

**Baseline:** em PRs o pipeline varre também a branch base (`git worktree`) e passa o relatório como `--baseline`. Só **vulnerabilidades introduzidas pelo PR** bloqueiam o merge. A dívida técnica existente continua visível no dashboard sem impedir o time de trabalhar. Como o fingerprint não depende do número da linha, mover código não faz achados antigos parecerem novos.

Códigos de saída da CLI: `0` aprovado · `1` reprovado · `2` erro de execução.

## Ativando o bloqueio de PRs

No GitHub: *Settings → Branches → Branch protection rules → `main`*
1. ✅ *Require a pull request before merging*
2. ✅ *Require status checks to pass* e selecione **`Security Gate`**
3. ✅ *Require branches to be up to date*

Com isso, o botão de merge fica desabilitado enquanto o Security Gate estiver vermelho.

## Secrets opcionais

| Secret | Uso |
|---|---|
| `SAST_API_URL` | URL da plataforma (ex.: `https://sentinela.empresa.com`): o resultado de cada pipeline aparece no dashboard |
| `SAST_API_TOKEN` | token aceito por `POST /api/v1/scans/ci` |

## Reuso em outros repositórios

`action.yml` empacota o gate como uma GitHub Action:

```yaml
- uses: <org>/<este-repositorio>@main
  with:
    path: .
    fail-on: high
```

## Dogfooding

A própria plataforma passa nos seus controles: SentinelaSAST (0 achados ≥ MEDIUM fora das exceções documentadas), Bandit (`-ll` limpo) e Semgrep. Dois alertas legítimos do Bandit (`urlopen` aceitando qualquer esquema) foram **corrigidos** com validação http/https (`require_http_url`), em vez de simplesmente silenciados.
