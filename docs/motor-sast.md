# Motor SAST: parser, regras e taint analysis

## 1. Parsing

### Python (`sast_engine/languages/python_ast.py`)
- `ast.parse` gera a **Árvore de Sintaxe Abstrata**.
- Numa passada extra o parser monta:
  - **mapa de imports/aliases**: `import subprocess as sp` faz `sp.Popen` virar `subprocess.Popen`, e `from pickle import loads` faz `loads` virar `pickle.loads`. Sem isso, renomear um import bastaria para escapar das regras;
  - **mapa de pais**: permite a uma regra subir na árvore (ex.: `PY007` descobre se `random.randint()` está sendo atribuído a uma variável chamada `token`).
- Erros de sintaxe viram `ParseError` no relatório. A varredura continua nos outros arquivos.

### JavaScript (`sast_engine/languages/javascript_ts.py`)
- **Tree-sitter** gera a árvore sintática concreta e as regras JS consultam os tipos de nó (`call_expression`, `assignment_expression`, `template_string`...).
- **Taint analysis JS** (`_JSTaint`):
  - **fontes:** `req.query/body/params/headers/cookies` (Express/Koa), `location.search/hash`, `document.cookie/URL`, `process.argv`;
  - **sinks:** `eval`/`Function`/`setTimeout(string)`, `exec`, `query()` com SQL, `res.send`/`innerHTML`/`document.write`, `fs.readFile`/`res.sendFile`, `fetch`/`axios`/`http.get`, `res.redirect`;
  - **sanitizadores:** `parseInt`, `Number`, `encodeURIComponent`, `DOMPurify.sanitize`, `path.basename`, `validator.escape`;
  - suporta desestruturação (`const { id } = req.query`) e reatribuição limpa. É intraprocedural.
- É opcional: se o Tree-sitter não estiver instalado, o motor segue só com Python.

## 2. Catálogo de regras

`python -m sast_engine rules` lista todas. Metadados (CWE, OWASP, descrição, remediação, exemplo de correção) ficam em `sast_engine/rules/catalog.py`, que é a fonte única para o motor, o dashboard e a IA.

| ID | Tipo | Severidade | CWE | OWASP 2021 | Detecta |
|---|---|---|---|---|---|
| **PY001** | heurística | HIGH/CRITICAL | 798 | A07 | senha, token ou chave hardcoded (atribuição, kwarg, dict, comparação) |
| **PY002** | determinística | MEDIUM (LOW se literal) | 95 | A03 | `eval` / `exec` |
| **PY003** | determinística | HIGH (LOW se literal) | 78 | A03 | `shell=True`, `os.system`, `os.popen` com valor dinâmico |
| PY004 | determinística | HIGH | 502 | A08 | `pickle`, `marshal`, `shelve`, `yaml.load` sem SafeLoader |
| PY005 | heurística | HIGH | 89 | A03 | SQL montado com f-string/`+`/`%`/`.format` passado a `execute` |
| PY006 | determinística | MEDIUM | 328 | A02 | MD5/SHA-1 (exceto `usedforsecurity=False`) |
| PY007 | heurística | MEDIUM | 330 | A02 | `random` gerando token/senha/OTP |
| PY008 | determinística | HIGH | 295 | A02 | `verify=False`, contexto SSL sem verificação |
| PY009 | determinística | MEDIUM | 489 | A05 | `app.run(debug=True)`, `DEBUG = True` |
| PY010 | heurística | LOW | 703 | A04 | `assert` usado para autorização |
| PY011 | determinística | MEDIUM | 377 | A01 | `tempfile.mktemp` |
| PY012 | determinística | HIGH | 327 | A02 | DES, RC4, Blowfish, modo ECB |
| PY013 | determinística | HIGH | 347 | A07 | JWT sem verificar assinatura / alg `none` |
| PY014 | determinística | MEDIUM | 732 | A01 | `chmod` com escrita para todos |
| PY015 | determinística | MEDIUM | 79 | A03 | Jinja2 sem autoescape |
| PY016 | determinística | MEDIUM | 611 | A05 | parsers XML vulneráveis a XXE |
| PY017 | determinística | LOW | 400 | A05 | `requests` sem timeout |
| PY018 | heurística | LOW | 605 | A05 | bind em `0.0.0.0` |
| TAINT-SQLI | taint | CRITICAL | 89 | A03 | entrada → SQL |
| TAINT-CMDI | taint | CRITICAL | 78 | A03 | entrada → comando do SO |
| TAINT-CODE | taint | CRITICAL | 94 | A03 | entrada → `eval`/`exec`/`compile` |
| TAINT-DESER | taint | CRITICAL | 502 | A08 | entrada → `pickle`/`yaml.load` |
| TAINT-PATH | taint | HIGH | 22 | A01 | entrada → `open`, `os.remove`, `send_file`... |
| TAINT-SSRF | taint | HIGH | 918 | A10 | entrada → `requests.*`, `urlopen` |
| TAINT-XSS | taint | HIGH | 79 | A03 | entrada → `render_template_string`, `Markup`, HTML retornado pela rota |
| TAINT-REDIRECT | taint | MEDIUM | 601 | A01 | entrada → `redirect` |
| JS001–JS005 | Tree-sitter | MEDIUM–HIGH | 95/79/798/78/89 | A03/A07 | `eval`, `innerHTML`, segredos, `child_process.exec`, SQL concatenado |
| TAINT-* (JS) | taint/Tree-sitter | igual ao Python | idem | idem | os mesmos 7 tipos de fluxo, em Express e no navegador |

As três **violações iniciais do CP1** são `PY001`, `PY002` e `PY003`.

### Como a heurística de segredos evita falso positivo (`rules/secrets.py`)
1. **Padrão de formato conhecido** (chave AWS `AKIA…`, token GitHub `ghp_…`, chave privada PEM, JWT, URL com senha) gera achado **CRITICAL**, mesmo sem nome sugestivo.
2. **Nome sugere segredo** (`password`, `senha`, `api_key`, `secret`...) **e** o valor parece real:
   - não é placeholder (`changeme`, `<...>`, `${VAR}`, `TODO`, `xxx`...);
   - não é uma frase (mensagem de erro com a palavra "password");
   - entropia de Shannon ≥ 2,5 bits e ≥ 6 caracteres;
   - nomes como `PASSWORD_FIELD`, `TOKEN_URL`, `token_type` são ignorados.

## 3. Taint analysis (`sast_engine/taint.py`)

### Modelo
- **Fontes (sources):** `request.args/form/json/cookies/headers/data/files/...` (Flask, Django, FastAPI/Starlette), `input()`, `sys.argv`, `sys.stdin`, e **parâmetros de rotas** (`@app.route`, `@app.get`, `@router.post`...). Parâmetros FastAPI com `Depends(...)` não contam como fonte.
- **Sinks:** tabela `SINKS` com o argumento relevante de cada um (ex.: em `requests.request(method, url)` o sink é o argumento 1). Para `subprocess.*`, só conta como sink com `shell=True` ou quando o **programa** (1º elemento da lista) vem do usuário.
- **Sanitizadores:** `int`, `float`, `shlex.quote`, `html.escape`, `markupsafe.escape`, `secure_filename`, `os.path.basename`, `urllib.parse.quote`, `re.escape`...

### Propagação
- Atribuições, f-strings, concatenação, `%`, `.format`, métodos de string, contêineres (`list`, `dict`, `append`, `update`), comprehensions, `with ... as`, laços (duas passadas para aproximar o ponto fixo) e `match`.
- **Sensível ao fluxo:** `cmd = request.args["c"]; cmd = "ls"; os.system(cmd)` **não** gera alerta.
- **Ramos:** `if/else` são analisados separadamente e unidos. Se um ramo sempre sai (`return`, `raise`, `abort()`), o estado dele é descartado.
- **Guardas** (reduzem falso positivo):
  - `if x not in PERMITIDOS: abort(400)` limpa `x` depois do `if`;
  - `if urlparse(url).hostname not in HOSTS: return` limpa `url`;
  - `if not caminho.startswith(BASE): abort(403)` limpa `caminho`;
  - `if nome.isalnum():`, `re.fullmatch(...)` e funções `is_valid_*`/`is_safe_*` limpam a variável só dentro do ramo validado.

### Interprocedural (resumos de função)
Cada função recebe um resumo:
- `returns_params`: quais parâmetros chegam ao `return` (ex.: `montar_filtro(campo, valor)` retorna `{0, 1}`);
- `returns_source`: a função devolve dado de fonte (ex.: um helper `get_param()`);
- `sink_params`: quais parâmetros chegam a quais sinks, com o caminho interno.

Os resumos são recalculados para **todas as funções do projeto** até nada mudar (ponto fixo, máx. 8 iterações). Depois uma passada final emite os achados. A resolução de chamadas cobre funções do mesmo módulo, `self.metodo()` e **imports entre arquivos** (`from db import buscar`). Exemplo real das amostras:

```
TAINT-SQLI  db.py:18
↳ app.py:L37 fonte: request.args → app.py:L37 passado para buscar_usuario_por_nome() como 'nome'
  → L17 propagado pelo retorno de montar_filtro() → L17 atribuído a 'sql' → L18 sink: execute()
```

### Confiança
- **HIGH:** o caminho só passou por operações de propagação exata (concatenação, f-string, métodos de string, funções do projeto).
- **MEDIUM:** o dado passou por uma função **desconhecida** (biblioteca externa), em que assumimos propagação conservadora.

O Security Gate usa `--min-confidence` para decidir se achados MEDIUM bloqueiam.

## 4. Pós-processamento

1. **Supressão inline:** `# nosast` ou `# nosast: PY003` (JS: `// nosast`).
2. **Exceções documentadas** em `.sast.toml` (`[[ignore]]` com `path`, `rules` e **`reason` obrigatório**), revisadas no PR.
3. **Deduplicação:** quando o taint confirma o fluxo, o achado heurístico na mesma linha (`PY005`→`TAINT-SQLI`, `PY002`→`TAINT-CODE`...) é descartado. Achados de motores diferentes na mesma linha e CWE são unidos (`extra.also_reported_by`).
4. **Fingerprint** estável (não depende do número da linha) para baseline e tendência.
5. **Risk score** 0–10 = severidade × fator de confiança.

## 5. Avaliação

`benchmark/run_benchmark.py` compara os achados com as anotações `# expect: REGRA` das amostras:
- `samples/vulnerable_app`: 4 arquivos Flask com 36 vulnerabilidades, incluindo fluxos entre arquivos;
- `samples/safe_app`: as **mesmas funcionalidades corrigidas**, onde qualquer achado é falso positivo;
- `samples/js_app`: 15 vulnerabilidades JS (regras + taint), incluindo casos seguros na mesma rota;
- `samples/vulnerable_app/pedidos.py`: falhas de **lógica** sem anotação (nenhuma regra deve disparar; alvo da varredura semântica por IA).

Ele também roda uma **ablação** sem taint, para medir a contribuição desse módulo: F1 cai de 1,0 para 0,63. O CI exige precisão e recall ≥ 90%.

## Limitações conhecidas

- **Sem análise de tipos/objetos:** `obj.atributo` contaminado é rastreado por nome (`self.x`), não por alias de objeto.
- **Funções de bibliotecas externas** são tratadas de forma conservadora (propagam taint), o que pode gerar falso positivo. A IA ajuda na triagem desses casos.
- **Chamadas dinâmicas** (`getattr`, `**kwargs` repassados, decorators que trocam a função) não são resolvidas.
- **Guardas** reconhecem padrões comuns, não condições arbitrárias.
- **Taint em JavaScript** é intraprocedural (não segue o dado entre funções/módulos) e não distingue escopos de variáveis com o mesmo nome.
- O benchmark é pequeno e foi escrito pelo grupo. O próximo passo natural é medir contra um corpus independente, como o **OWASP Benchmark** (Java) ou projetos Python intencionalmente vulneráveis com licença aberta.
