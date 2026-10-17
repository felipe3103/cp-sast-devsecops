"""Prompts e schemas de saída para o LLM."""

TRIAGE_SYSTEM = """Você é um engenheiro de segurança de aplicações (AppSec) revisando achados de uma ferramenta SAST.
Analise o código com ceticismo técnico. Decida se o achado é um verdadeiro positivo considerando:
- se o dado realmente pode ser controlado por um atacante;
- se existe sanitização, validação ou parametrização no caminho;
- o contexto (código de teste, valor constante, ambiente de desenvolvimento).
Responda SOMENTE com JSON válido no schema pedido, em português do Brasil.
A correção (fixed_code) deve ser código Python completo e sintaticamente válido que substitui o trecho
vulnerável, mantendo o comportamento original e eliminando a vulnerabilidade. Não invente APIs.
No fixed_code use SEMPRE aspas simples (') nas strings Python, nunca aspas duplas, e não deixe
segredos como valor padrão (use os.environ["NOME"])."""

TRIAGE_USER = """Achado da ferramenta SAST:
- Regra: {rule_id} - {title}
- CWE: {cwe} | OWASP: {owasp}
- Severidade atribuída pela regra: {severity} (confiança {confidence})
- Mensagem: {message}
- Arquivo: {file}, linha {line}
{trace}
Descrição da vulnerabilidade: {description}

Código (a linha marcada com >> é a do achado):
```{language}
{context}
```

Retorne JSON com:
- verdict: "true_positive", "false_positive" ou "uncertain"
- confidence: número de 0 a 1
- severity: "CRITICAL", "HIGH", "MEDIUM", "LOW" ou "INFO" (severidade real neste contexto)
- justification: por que é (ou não é) explorável, em até 3 frases
- exploit_scenario: como um atacante exploraria, em 1-2 frases (vazio se falso positivo)
- remediation: explicação objetiva da correção
- fixed_code: o trecho corrigido (somente código)"""

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "uncertain"]},
        "confidence": {"type": "number"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "justification": {"type": "string"},
        "exploit_scenario": {"type": "string"},
        "remediation": {"type": "string"},
        "fixed_code": {"type": "string"},
    },
    "required": ["verdict", "confidence", "severity", "justification", "remediation", "fixed_code"],
}

SEMANTIC_SYSTEM = """Você é um revisor de segurança. Procure falhas de LÓGICA que regras sintáticas não pegam:
controle de acesso ausente (IDOR), autenticação quebrada, condições de corrida, validação de negócio
incorreta, vazamento de dados sensíveis em logs/respostas, uso inseguro de criptografia.
Não repita achados triviais de injeção já cobertos pela ferramenta. Seja conservador: só reporte
o que tiver evidência no código. Responda SOMENTE JSON válido, em português do Brasil."""

SEMANTIC_USER = """Arquivo: {file}
```{language}
{code}
```
A ferramenta SAST JÁ detectou os problemas abaixo. NÃO os repita; procure apenas falhas de lógica
diferentes (ex.: um recurso acessado por id sem verificar se pertence ao usuário logado):
{known}

Retorne JSON: {{"issues": [{{"line": <int>, "title": <str>, "cwe": "CWE-<n>", "severity": "CRITICAL|HIGH|MEDIUM|LOW",
"confidence": <0-1>, "explanation": <str>, "remediation": <str>}}]}}. Lista vazia se não houver problemas."""

SEMANTIC_SCHEMA = {
    "type": "object",
    "properties": {
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "title": {"type": "string"},
                    "cwe": {"type": "string"},
                    "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                    "confidence": {"type": "number"},
                    "explanation": {"type": "string"},
                    "remediation": {"type": "string"},
                },
                "required": ["line", "title", "severity", "confidence", "explanation"],
            },
        }
    },
    "required": ["issues"],
}

FIX_RETRY_USER = """A correção que você propôs foi REJEITADA pelo validador automático:
{error}

Código vulnerável original:
```{language}
{snippet}
```
Vulnerabilidade: {rule_id} - {title} ({cwe}). Correção esperada: {remediation}

Devolva JSON {{"fixed_code": "<código Python COMPLETO e válido>"}} com a função inteira corrigida,
sem reticências e sem comentários fora do código. Use aspas simples (') nas strings Python."""

FIX_RETRY_SCHEMA = {
    "type": "object",
    "properties": {"fixed_code": {"type": "string"}},
    "required": ["fixed_code"],
}

# Varredura semântica por função: perguntas objetivas que até modelos pequenos respondem bem.
FUNCTION_SYSTEM = """Você é um revisor de segurança de APIs web. Responda sobre UMA função de rota,
olhando só o código dado. Responda SOMENTE com JSON válido, em português do Brasil."""

FUNCTION_USER = """Função de rota (arquivo {file}):
```{language}
{code}
```
Responda cada pergunta com true/false olhando o código:
- requires_authentication: a função verifica se há usuário logado (sessão, token, decorator de login) antes de agir?
- accesses_resource_by_id: busca, altera ou apaga um registro usando um id vindo da URL, da query ou do corpo?
- checks_resource_owner: compara o dono do registro com o usuário logado da sessão (ex.: pedido.usuario_id == session['usuario_id'])?
- modifies_data: altera, cancela, apaga ou salva dados?
- trusts_client_sensitive_value: usa um valor de preço, desconto, papel, permissão ou id de usuário enviado pelo cliente em vez de calcular/obter no servidor?
Também informe sensitive_value (qual valor, se houver) e explanation (1-2 frases)."""

FUNCTION_SCHEMA = {
    "type": "object",
    "properties": {
        "requires_authentication": {"type": "boolean"},
        "accesses_resource_by_id": {"type": "boolean"},
        "checks_resource_owner": {"type": "boolean"},
        "modifies_data": {"type": "boolean"},
        "trusts_client_sensitive_value": {"type": "boolean"},
        "sensitive_value": {"type": "string"},
        "explanation": {"type": "string"},
    },
    "required": ["requires_authentication", "accesses_resource_by_id", "checks_resource_owner",
                 "modifies_data", "trusts_client_sensitive_value", "explanation"],
}
