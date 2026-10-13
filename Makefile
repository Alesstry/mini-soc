-include .env
export

.PHONY: env up down attack alerts events logs test clean

env:
	@[ -f .env ] || (echo "INGEST_API_KEY=$$(python3 -c 'import secrets; print(secrets.token_hex(24))')" > .env && echo "[+] .env creado con clave aleatoria")

up: env
	docker compose up -d --build
	@echo "[+] Plataforma en http://127.0.0.1:8000/docs  (los endpoints requieren X-API-Key del .env)"

down:
	docker compose --profile attack down

attack:
	docker compose --profile attack run --rm attacker

alerts:
	@curl -s -H "X-API-Key: $(INGEST_API_KEY)" http://127.0.0.1:8000/alerts | python3 -m json.tool

events:
	@curl -s -H "X-API-Key: $(INGEST_API_KEY)" "http://127.0.0.1:8000/events?limit=20" | python3 -m json.tool

logs:
	docker compose logs -f platform shipper

test:
	cd platform && pip install -q -r requirements-dev.txt && python -m pytest -q

clean:
	docker compose --profile attack down -v
