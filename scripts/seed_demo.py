"""Popula a plataforma com varreduras de demonstração (tendência de correção ao longo do tempo).

Simula um time corrigindo a aplicação vulnerável em 4 sprints e envia cada versão
para a API. Uso:  python scripts/seed_demo.py [http://localhost:8000]
"""
from __future__ import annotations

import io
import json
import sys
import urllib.request
import uuid
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
VULN = ROOT / "samples" / "vulnerable_app"


def files_of(directory: Path) -> dict[str, str]:
    return {p.relative_to(directory).as_posix(): p.read_text() for p in directory.rglob("*.py")}


def zipped(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def upload(project: str, filename: str, data: bytes) -> dict:
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"project\"\r\n\r\n{project}\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
        "Content-Type: application/zip\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(f"{API}/api/v1/scans/upload", data=body, method="POST",
                                 headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # nosec B310
        return json.loads(resp.read())


def main() -> None:
    base = files_of(VULN)
    sprints = [
        ("sprint-1", base),
        ("sprint-2", {k: v for k, v in base.items() if k != "utils.py"}),  # utilitários reescritos
        ("sprint-3", {**{k: v for k, v in base.items() if k not in {"utils.py", "config.py"}},
                      "config.py": "import os\n\ndef get_db_path():\n    return os.environ['DB_PATH']\n"}),
        ("sprint-4", {"app.py": (ROOT / "samples" / "safe_app" / "app.py").read_text(),
                      "db.py": base["db.py"],
                      "config.py": "import os\n\ndef get_db_path():\n    return os.environ['DB_PATH']\n"}),
    ]
    for ref, files in sprints:
        scan = upload("loja-online", f"{ref}.zip", zipped(files))
        print(f"varredura #{scan['id']} ({ref}) enviada")
    js = {"server.js": (ROOT / "samples" / "js_app" / "server.js").read_text()}
    print(f"varredura #{upload('api-node', 'api-node.zip', zipped(js))['id']} (api-node) enviada")


if __name__ == "__main__":
    main()
