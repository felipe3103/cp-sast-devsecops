PY ?= .venv/bin/python

.PHONY: up up-ai down test scan gate benchmark seed

up:            ## sobe API, workers, Postgres e Redis
	docker compose up -d --build
up-ai:         ## idem + Ollama com Llama 3
	docker compose --profile ai up -d --build
down:
	docker compose down
test:
	$(PY) -m pytest
scan:          ## varre a aplicação vulnerável de exemplo
	$(PY) -m sast_engine scan samples/vulnerable_app
gate:          ## Security Gate no próprio repositório (igual ao CI)
	$(PY) -m sast_engine scan . --fail-on high
benchmark:
	$(PY) benchmark/run_benchmark.py
seed:          ## popula o dashboard com varreduras de demonstração
	$(PY) scripts/seed_demo.py http://localhost:8000
