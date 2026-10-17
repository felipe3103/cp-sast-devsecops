"""RAG (Retrieval-Augmented Generation) local com LangChain + modelo do Hugging Face.

A base de conhecimento é o próprio catálogo do motor (descrição, remediação e exemplo de
cada regra, mapeamento CWE/OWASP e CVEs reais). Cada entrada vira um documento LangChain,
vetorizado com um modelo de embeddings baixado do **Hugging Face Hub**
(`hf.co/nomic-ai/nomic-embed-text-v1.5-GGUF`, servido localmente pelo Ollama) e guardado num
`InMemoryVectorStore`. Na triagem, os documentos mais parecidos com o achado entram no
prompt: o LLM responde ancorado em conhecimento verificado, e não só na memória do modelo.

Tudo é opcional: sem LangChain ou sem o modelo de embeddings, a triagem segue sem RAG.
"""
from __future__ import annotations

import os
from functools import lru_cache

from ..models import Finding
from ..rules.catalog import CATALOG, REFERENCE_CVES

EMBED_MODEL = os.getenv("EMBED_MODEL", "hf.co/nomic-ai/nomic-embed-text-v1.5-GGUF:Q8_0")
# O nomic-embed-text foi treinado com prefixos de tarefa (ver model card no Hugging Face).
DOC_PREFIX, QUERY_PREFIX = "search_document: ", "search_query: "


def knowledge_documents() -> list[tuple[str, dict]]:
    """(texto, metadados) de cada entrada da base de conhecimento."""
    docs = []
    for meta in CATALOG.values():
        text = (
            f"{meta.id} {meta.title} ({meta.cwe}, {meta.owasp}). {meta.description} "
            f"Como corrigir: {meta.remediation} Exemplo seguro: {meta.fix_example}"
        )
        docs.append((text, {"kind": "regra", "id": meta.id, "cwe": meta.cwe}))
    for cwe, refs in REFERENCE_CVES.items():
        for ref in refs:
            docs.append((f"{ref.cve} {ref.title} ({cwe}): {ref.description}", {"kind": "cve", "id": ref.cve, "cwe": cwe}))
    return docs


class KnowledgeBase:
    def __init__(self, base_url: str | None = None, model: str = EMBED_MODEL):
        from langchain_core.documents import Document
        from langchain_core.vectorstores import InMemoryVectorStore
        from langchain_ollama import OllamaEmbeddings

        self.model = model
        embeddings = OllamaEmbeddings(model=model, base_url=base_url or os.getenv("OLLAMA_URL", "http://localhost:11434"))
        self.store = InMemoryVectorStore(embeddings)
        self.store.add_documents([Document(page_content=DOC_PREFIX + t, metadata=m) for t, m in knowledge_documents()])

    def search(self, finding: Finding, k: int = 3) -> list[tuple[str, dict]]:
        query = f"{QUERY_PREFIX}{finding.title} {finding.cwe} {finding.message} {finding.snippet}"
        docs = self.store.similarity_search(query, k=k)
        return [(d.page_content.removeprefix(DOC_PREFIX), d.metadata) for d in docs]


@lru_cache(maxsize=1)
def get_knowledge_base(base_url: str | None = None) -> KnowledgeBase | None:
    """Base vetorial criada uma vez por processo; None se LangChain/modelo indisponíveis."""
    if os.getenv("AI_RAG", "1") == "0":
        return None
    try:
        return KnowledgeBase(base_url)
    except Exception:
        return None


def rag_context(finding: Finding, base_url: str | None = None, k: int = 3) -> tuple[str, list[str]]:
    """Texto para o prompt e ids dos documentos usados (para auditoria no resultado)."""
    kb = get_knowledge_base(base_url)
    if kb is None:
        return "", []
    try:
        hits = kb.search(finding, k)
    except Exception:
        return "", []
    text = "Base de conhecimento recuperada (RAG):\n" + "\n".join(f"- {t}" for t, _ in hits)
    return text, [m["id"] for _, m in hits]
