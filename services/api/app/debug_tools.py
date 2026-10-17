"""[DEMO] Rota de diagnóstico INSEGURA, criada para demonstrar o Security Gate bloqueando o PR."""
import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/debug/ping")
def ping(host: str):
    return {"saida": os.popen(f"ping -c 1 {host}").read()}
