# Módulo de IA (LLM local)

Código: `sast_engine/ai/` · Modelo padrão: **Llama 3 via Ollama** (`OLLAMA_MODEL`, `OLLAMA_URL`).

## O que a IA faz

| Função | Entrada | Saída |
|---|---|---|
| **Triagem** (`AITriage.analyze`) | achado + 25 linhas de contexto + caminho do taint + descrição da CWE | veredito (verdadeiro/falso positivo/incerto), confiança, severidade real, justificativa, cenário de exploração, remediação e **código corrigido** |
| **Varredura semântica** (`AITriage.semantic_review`) | arquivo inteiro numerado | falhas de **lógica** que regras não pegam: IDOR, autorização ausente, vazamento em logs, regra de negócio insegura |

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
6. **Varredura semântica:** linhas inexistentes (alucinação) são descartadas, confiança < 0,6 é ignorada e a severidade fica limitada a HIGH. Esses achados nunca entram como CRITICAL sem um humano.
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

## Resultados com o LLM real (Llama 3.2 3B, Mac com 8 GB de RAM)

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
