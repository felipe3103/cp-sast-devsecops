# Módulo de IA (LLM local)

Código: `sast_engine/ai/` · Modelo padrão: **Llama 3 via Ollama** (`OLLAMA_MODEL`, `OLLAMA_URL`) · Orquestração: **LangChain** · Embeddings do RAG: **Hugging Face Hub**.

## Stack de IA (as três tecnologias recomendadas no PDF)

| Tecnologia | Papel |
|---|---|
| **Ollama + Llama 3** | LLM local (8B testado; 3.2 3B em máquinas com 8 GB). O código não sai da máquina. |
| **LangChain** | chain `ChatPromptTemplate → ChatOllama(format=JSON Schema) → JsonOutputParser` (`LangChainOllamaClient`, padrão `AI_BACKEND=langchain`) e **RAG** com `InMemoryVectorStore` + `OllamaEmbeddings` (`sast_engine/ai/rag.py`) |
| **Hugging Face** | o modelo de embeddings do RAG, `nomic-ai/nomic-embed-text-v1.5`, é baixado do **Hugging Face Hub** (`ollama pull hf.co/nomic-ai/nomic-embed-text-v1.5-GGUF:Q8_0`), com os prefixos `search_document:`/`search_query:` indicados no model card |

### RAG
A base de conhecimento é o próprio catálogo do motor: as 31 regras (descrição, remediação, exemplo seguro, CWE/OWASP) e os CVEs reais por CWE. Na triagem, os 3 documentos mais parecidos com o achado entram no prompt, e os ids usados ficam registrados em `rag_documents`, para auditoria. Exemplo real: para o SQLi interprocedural foram recuperados `TAINT-SQLI`, `CVE-2014-3704` (Drupalgeddon) e `PY005`; para `yaml.load`, `CVE-2017-18342` (PyYAML). Sem LangChain ou sem o modelo de embeddings, a triagem segue sem RAG (`AI_RAG=0` desliga).

## O que a IA faz

| Função | Entrada | Saída |
|---|---|---|
| **Triagem** (`AITriage.analyze`) | achado + 25 linhas de contexto + caminho do taint + descrição da CWE | veredito (verdadeiro/falso positivo/incerto), confiança, severidade real, justificativa, cenário de exploração, remediação e **código corrigido** |
| **Varredura semântica** (`AITriage.semantic_review`) | cada **função de rota** (achada pela AST), sem comentários | falhas de **lógica** que regras não pegam: IDOR (CWE-639), operação sem autenticação (CWE-306), valor sensível decidido pelo cliente (CWE-602) |

Por que LLM **local**? O código-fonte da empresa nunca sai da rede, sem custo por token e sem depender de API externa (requisito de privacidade e propriedade intelectual).

## Prompting

- Prompt de sistema define o papel ("engenheiro AppSec cético"), os critérios de decisão (o dado é controlável? há sanitização? é código de teste?) e exige **somente JSON**, em português.
- **Structured outputs do Ollama:** o campo `format` recebe um **JSON Schema** (`prompts.TRIAGE_SCHEMA`) e o modelo é obrigado a seguir os enums (`verdict`, `severity`).
- `temperature = 0.1` para respostas estáveis e reproduzíveis.
- O contexto marca a linha do achado com `>>` e inclui o **trace de taint**, para o modelo não precisar "adivinhar" o fluxo.

## Guardrails (o diferencial)

LLMs alucinam, por isso a resposta do modelo nunca é aplicada às cegas:

1. **Schema validado:** resposta inválida ou Ollama fora do ar fazem o sistema cair para a **base de conhecimento** (descrição + remediação + exemplo do catálogo), marcada como `source: knowledge_base`. O pipeline nunca quebra por causa da IA.
2. **Ajuste de severidade limitado a ±1 nível:** se a IA sugerir HIGH→INFO, aplicamos HIGH→MEDIUM e registramos a nota.
3. **A IA não suprime sozinha um fluxo de taint comprovado:** se o motor provou o caminho fonte→sink com confiança HIGH e a IA disser "falso positivo", o achado vai para `needs_review` (revisão humana).
4. **Supressão só com confiança ≥ 0,8.** Abaixo disso também vai para revisão humana.
5. **Validação da correção em ciclo fechado:** o `fixed_code` sugerido
   - precisa **compilar** (`ast.parse`);
   - é **aplicado no arquivo real** (substitui a função inteira ou a instrução do achado) e o **projeto inteiro é re-escaneado**. Assim a taint analysis entre arquivos também é verificada: uma "correção" de SQLi que continua concatenando a entrada no SQL é rejeitada mesmo que a fonte (`request.args`) esteja em outro arquivo;
   - não pode **introduzir** um achado novo (≥ MEDIUM) na região alterada.
   Exemplo: se a IA "corrigir" `os.system("ls " + c)` para `os.system("ls " + c.strip())`, o re-scan ainda acusa PY003 e a correção é marcada como **não validada**.
5b. **Autocorreção guiada pelo validador:** quando a correção é rejeitada, o erro exato (ex.: "ainda dispara TAINT-SQLI na linha 18") volta para o LLM, que tem até 2 novas tentativas.
6. **Varredura semântica, desenho anti-alucinação:**
   - **comentários são removidos** antes do envio (o modelo não pode "colar" de anotações como as do benchmark);
   - em vez de uma pergunta aberta ("ache falhas de lógica", que o Llama 3 respondeu com lista vazia no teste real), o motor acha as **rotas pela AST** e faz ao LLM **perguntas objetivas por função**: exige autenticação? busca registro por id? confere o dono? altera dados? confia em valor do cliente? O **código** converte as respostas em achados com CWE;
   - **checagem cruzada com a AST:** "altera dados" só vale com evidência sintática (POST/PUT/DELETE, `save()`/`delete()`, atribuição a atributo). Isso eliminou falsos positivos reais em que o LLM afirmou que um GET de leitura alterava dados;
   - achados que repetem algo que o motor já tem são descartados; os achados entram com **confiança LOW** (indício para revisão humana) e **não bloqueiam o Security Gate** sozinhos.
7. **Cache** por hash (modelo + regra + contexto): o mesmo trecho não é reenviado ao LLM.

Achados suprimidos pela IA ficam visíveis no dashboard (status `false_positive`, com a justificativa) e **não bloqueiam o gate**. Ou seja, a IA reduz o ruído sem apagar evidência.

## Como usar

```bash
# Docker
docker compose --profile ai up -d          # sobe o Ollama e baixa o llama3

# Local
ollama pull llama3 && ollama serve
python -m sast_engine scan samples/vulnerable_app --ai --ai-limit 10 --format json -o r.json
```

No dashboard: abra um achado e clique em **"Analisar com IA"**, ou use **"Triagem IA (top 15)"** para enfileirar os achados de maior risco na fila `ai`. Com `AI_AUTO_TRIAGE=true`, toda varredura dispara a triagem automaticamente.

## Testes

`tests/test_ai.py` usa um cliente Ollama simulado para provar cada guardrail de forma determinística: correção válida aceita, correção ainda vulnerável rejeitada, correção que não compila rejeitada, severidade limitada, supressão por confiança, proteção do fluxo de taint, fallback offline, cache e descarte de linhas alucinadas.

## Resultados com o Llama 3 8B (LangChain + RAG)

Execução real, Mac com 8 GB de RAM (Ollama nativo com GPU Metal). Triagem de 6 achados em ~15 min e varredura semântica de 4 rotas em ~70 s.

**Triagem** (`--ai --ai-limit 6` em `samples/vulnerable_app`):

| Achado | Veredito | Correção | RAG recuperou |
|---|---|---|---|
| `TAINT-SQLI` app.py:30 | verdadeiro positivo (0,9) | consulta parametrizada, **validada** | TAINT-SQLI, CVE-2014-3704, PY005 |
| `TAINT-CODE` app.py:62 | verdadeiro positivo (0,9) | mapa de operações permitidas, **validada** | TAINT-CODE |
| `TAINT-DESER` app.py:102 | verdadeiro positivo (0,9) | `json.loads`, **validada** | TAINT-DESER, PY004 |
| `TAINT-DESER` app.py:108 | verdadeiro positivo (0,9) | `yaml.safe_load`, **validada** | CVE-2017-18342 |
| `TAINT-CMDI` app.py:48 | verdadeiro positivo (0,9) | **rejeitada**: não compilava em nenhuma das 3 tentativas | CVE-2014-6271 (Shellshock) |
| `TAINT-CMDI` app.py:55 | verdadeiro positivo (0,9) | **rejeitada**: `str(destino)` não sanitiza; o re-scan do projeto acusou TAINT-CMDI | CVE-2014-6271 |

Classificação: 6/6 corretos. Correções: 4/6 validadas; as 2 erradas foram barradas pelo validador, nenhuma correção errada foi exibida como válida.

**Varredura semântica** (`--ai-semantic`):

| Arquivo | Resultado |
|---|---|
| `vulnerable_app/pedidos.py` (5 falhas de lógica plantadas, comentários removidos antes do envio) | **4 de 5 encontradas**: IDOR e falta de autenticação em `cancelar_pedido`, desconto definido pelo cliente, exclusão de conta pelo id do corpo. Não encontrou o IDOR de `ver_pedido`. |
| `safe_app/app.py` | 2 alertas, ambos defensáveis: `backup()` aceita do cliente o destino e `importar_config()` aceita POST sem login (a app segura corrigiu as falhas de regra, mas não tem autenticação). A versão sem checagem cruzada dava mais 2 alertas falsos em rotas GET de leitura. |

## Resultados com o Llama 3.2 3B (primeiros testes)

| Achado | Veredito da IA | Correção |
|---|---|---|
| `PY001` `app.secret_key = "..."` | verdadeiro positivo (0,9) | `os.environ['APP_SECRET_KEY']`, **validada** |
| `PY001` chave AWS em `config.py` | verdadeiro positivo (0,9) | `os.environ['AWS_ACCESS_KEY_ID']`, **validada** |
| `TAINT-DESER` `yaml.load(request.data)` | verdadeiro positivo (0,9) | troca por JSON, **validada** |
| `TAINT-SQLI` interprocedural `db.py:18` | verdadeiro positivo (0,9) | **rejeitada** nas 3 tentativas: o modelo continuou concatenando a entrada no SQL, e o re-scan do projeto mostrou `TAINT-SQLI` |

Lições aprendidas com o teste real:
- A primeira versão do validador re-escaneava só o trecho isolado e **aceitou** uma correção de SQLi ainda vulnerável, porque sem a fonte no trecho o taint não tinha o que rastrear. Isso motivou a validação no projeto inteiro.
- O modelo pequeno truncava o código em `sql =`. Com a saída restrita por JSON Schema, uma aspa dupla sem escape fecha a string do JSON. Pedir aspas simples no código resolveu.
- A correção `os.environ.get('APP_SECRET_KEY', 'default_value')` passou na primeira versão. Criamos uma detecção para segredo literal usado como valor padrão de `getenv`.
- Modelos de 3B acertam bem a **classificação**, mas erram correções que exigem refatorar mais de uma função. Com mais memória, use `OLLAMA_MODEL=llama3` (8B). O validador continua impedindo que uma correção errada seja exibida como válida.
