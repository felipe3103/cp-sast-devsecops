"""Cliente HTTP mínimo para o Ollama (LLM local). Usa só a biblioteca padrão."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request


class LLMUnavailable(RuntimeError):
    pass


def require_http_url(url: str) -> str:
    """Aceita só http(s): impede que urlopen leia file:// ou outros esquemas."""
    if urllib.parse.urlparse(url).scheme not in {"http", "https"}:
        raise ValueError(f"URL deve usar http ou https: {url!r}")
    return url


class OllamaClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, timeout: float | None = None):
        self.base_url = require_http_url(base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3")
        self.timeout = timeout or float(os.getenv("OLLAMA_TIMEOUT", "120"))

    def _post(self, path: str, payload: dict, timeout: float | None = None) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # esquema http(s) garantido por require_http_url
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # nosec B310
                return json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            raise LLMUnavailable(str(exc)) from exc

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            # esquema http(s) garantido por require_http_url
            with urllib.request.urlopen(req, timeout=3) as resp:  # nosec B310
                models = json.loads(resp.read().decode()).get("models", [])
            return any(m.get("name", "").split(":")[0] == self.model.split(":")[0] for m in models)
        except Exception:
            return False

    def chat_json(self, system: str, user: str, schema: dict | None = None) -> dict:
        """Pede uma resposta em JSON. Com `schema`, usa structured outputs do Ollama."""
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "format": schema or "json",
            "options": {"temperature": 0.1, "num_ctx": 8192},
        }
        data = self._post("/api/chat", payload)
        content = data.get("message", {}).get("content", "")
        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise LLMUnavailable(f"Resposta não é JSON válido: {content[:200]}") from exc
