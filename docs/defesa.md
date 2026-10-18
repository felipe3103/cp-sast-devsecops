# Roteiro da defesa técnica (≈ 15 min + perguntas)

**Slides:** https://claude.ai/artifact/3JM6CUphSCjJVh2b44DhVt (12 slides com notas do apresentador; exporta para PDF/PPTX pelo menu Share › Export). O link é privado até ser compartilhado pelo menu Share.

Os pesos da avaliação guiam o tempo: Arquitetura 25% · **Robustez SAST 30%** · Inovação IA 20% · DevSecOps 15% · Defesa 10%.

## Divisão da apresentação (10 slides)

| Quem | Slides | Conteúdo | Demo ao vivo |
|---|---|---|---|
| **Felipe Braunstein e Silva** (RM554483) | 1–3 | Abertura, problema (shift-left), arquitetura | — |
| **Felipe do Nascimento Fernandes** (RM554598) | 4–5 | Motor + taint analysis, precisão medida | terminal: trace do `db.py:18` |
| **Henrique Ignacio Bartalo** (RM555274) | 6–7 | IA local, guardrails, resultados reais com Llama 3 | — |
| **Gustavo Henrique Martins** (RM556956) | 8–10 | Security Gate (PR #1), dashboard, análise crítica e encerramento | PR #1 no GitHub; dashboard |

O texto falado de cada slide está nas notas do apresentador.

## Roteiro de demonstração (ensaiar!)

```bash
# 0. Antes da apresentação
docker compose --profile ai up -d && python scripts/seed_demo.py

# 1. CP1 — parser + 3 violações iniciais
python -m sast_engine scan samples/vulnerable_app/config.py
python -m sast_engine scan samples/vulnerable_app/utils.py

# 2. CP2 — taint analysis entre arquivos (mostrar o "↳ fluxo")
python -m sast_engine scan samples/vulnerable_app | grep -A3 "db.py:18"

# 3. Robustez: mesma app corrigida = 0 achados; benchmark + ablação
python -m sast_engine scan samples/safe_app
python benchmark/run_benchmark.py

# 4. Security Gate (exit code)
python -m sast_engine scan samples/vulnerable_app --fail-on high; echo "exit=$?"
```

5. **Dashboard** (<http://localhost:8000>): KPIs → tendência caindo ao longo das sprints → clicar no top arquivo → abrir `TAINT-SQLI db.py:18` → mostrar o fluxo → **"Analisar com IA"** → mostrar o veredito e a correção validada.
6. **Varredura semântica:** no dashboard, varredura #1 → botão *Varredura semântica (IA)* → achados `AI-SEMANTIC` em `pedidos.py` (IDOR, falta de autenticação), sem nenhuma regra ter disparado ali.
7. **GitHub:** mostrar o **PR #1** (já aberto): o check *Security Gate* vermelho, o comentário do relatório, o alerta `TAINT-CMDI` no Code Scanning e o botão de merge bloqueado.

> Plano B: se o Ollama estiver lento na hora, a triagem cai para a base de conhecimento e o fluxo continua. Vale mostrar isso também, porque é o guardrail 1.

## Mensagens-chave por critério

- **Arquitetura (25%)**
  - Motor sem dependências: roda no CI com `python -m`.
  - API stateless e escalável.
  - Filas separadas para não travar varreduras com o LLM.
  - Container sem root e escaneado por Trivy.
- **Robustez SAST (30%)**
  - Uma passada na AST e aliases de import resolvidos.
  - Taint interprocedural com ponto fixo, sanitizadores e guardas.
  - Precisão e recall medidos, com **ablação**.
  - App segura com 0 falsos positivos.
  - Comparação honesta com Bandit e Semgrep.
- **Inovação IA (20%)**
  - LLM local por privacidade.
  - Saída com JSON Schema.
  - A IA é *assistente, não juiz*: ±1 nível, não apaga fluxo comprovado.
  - **Correção re-escaneada pelo próprio motor.**
  - Varredura semântica para falhas de lógica.
- **DevSecOps (15%)**
  - 7 controles com check único.
  - Baseline: só achado novo bloqueia.
  - SARIF no Code Scanning e comentário no PR.
  - Action reutilizável.
  - Dogfooding: corrigimos alertas reais do Bandit no nosso código.

## Perguntas prováveis e respostas

**Por que não usar só o Bandit/Semgrep?**
O Bandit é baseado em padrões: não segue o dado, então marca todo `pickle.loads` e não vê SSRF, path traversal, XSS ou SQLi entre funções. No nosso corpus ele teve 62% de precisão e 69% de recall. O Semgrep tem taint, mas intraprocedural na versão aberta, e deu falso positivo onde há allowlist (`safe_app:97`). Usamos os dois como **segunda opinião**, deduplicada no relatório.

**Como vocês medem falso positivo?**
De três formas: a `safe_app`, que implementa as mesmas funções de forma correta (qualquer achado é FP); os testes negativos por regra (`test_*_false_positives`); e o benchmark no CI, que falha se a precisão cair abaixo de 90%.

**O benchmark não é enviesado?**
É, porque foi escrito por nós, e assumimos isso. Por isso mostramos a ablação (contribuição do taint) e os casos negativos. Como próximo passo, rodaríamos contra corpora independentes.

**E se o LLM alucinar uma correção?**
Ela é aplicada no arquivo e o projeto inteiro é re-escaneado. Se a vulnerabilidade continuar, ou se surgir outra, a correção é rejeitada e o erro volta para o LLM tentar de novo. No teste real, o Llama 3.2 3B errou a correção do SQLi interprocedural três vezes e o validador barrou todas (ver `docs/ia.md`). O LLM também não pode mudar a severidade em mais de um nível nem suprimir um fluxo de taint comprovado.

**E se o Ollama cair no meio do pipeline?**
O sistema cai para a base de conhecimento do catálogo. A IA nunca é ponto único de falha do gate.

**Como o gate não trava um time com dívida técnica antiga?**
Pelo baseline com fingerprint estável: só achados introduzidos pelo PR bloqueiam. O resto aparece no dashboard como tendência.

**Qual a complexidade do motor?**
As regras rodam em O(n) nós da AST. O taint roda em O(iterações × tamanho do código), com no máximo 8 iterações. Na prática, 4 mil linhas da própria plataforma levam ~150 ms.

**Como garantem que a própria plataforma é segura?**
Ela passa pelos próprios controles. O upload tem proteção contra zip slip e zip bomb; o clone Git tem allowlist de hosts e roda sem shell; o token é comparado em tempo constante; o container roda sem root; e o dashboard escapa todo HTML.

**Ética?**
Só usamos código próprio ou aberto, o clone aceita apenas hosts autorizados e repositórios públicos, e o LLM é local, então o código não sai da organização.

## Análise crítica (fechamento)

- **O que funcionou:** taint interprocedural com trace legível; guardrails da IA; gate com baseline.
- **Limitações:** sem análise de tipos/aliasing de objetos; bibliotecas externas tratadas de forma conservadora; JS sem taint; corpus de avaliação pequeno.
- **Próximos passos:** taint para JS via Tree-sitter; summaries pré-computados para bibliotecas populares (Django ORM, SQLAlchemy); benchmark em corpus independente; *fine-tuning* ou RAG com o catálogo CWE para o LLM.
