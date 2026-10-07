# Sysmon AI Analyst

Прототип веб-приложения для загрузки Sysmon-событий, базовой корреляции и LLM-assisted threat hunting.

## Возможности

- множественная загрузка Sysmon XML;
- JSON/NDJSON как дополнительный формат;
- parsing и normalization;
- базовый risk scoring;
- process/parent correlation на уровне событий;
- вкладки Events / Findings / LLM Result;
- подключение любого OpenAI-compatible LLM API;
- structured JSON output от LLM;
- LLM получает только отобранный контекст, а не весь сырой лог;
- API key хранится только на backend;
- ограничения количества и размера файлов;
- Docker-ready и пригоден для публикации на GitHub.

## Быстрый запуск

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt

cp .env.example .env
# отредактируйте .env

uvicorn app.main:app --reload
```

Откройте http://127.0.0.1:8000

## Docker

```bash
cp .env.example .env
docker compose up --build
```

## Конфигурация LLM

Приложение использует OpenAI-compatible endpoint:

- `LLM_API_KEY`
- `LLM_BASE_URL`
- `LLM_MODEL`

Поэтому backend можно подключить к совместимому API без изменения frontend.

## Безопасность прототипа

- не храните `.env` в Git;
- API key не передаётся в браузер;
- сырой Sysmon payload не отправляется в LLM целиком;
- перед LLM формируется минимальный контекст из событий с максимальным risk score;
- действия инфраструктурного response в прототип не выполняются автоматически.

Перед production deployment рекомендуется добавить authentication, TLS, audit logging, persistent storage, RBAC, secret manager, rate limiting и строгую allowlist-политику для LLM-generated queries.

## GitHub

```bash
git init
git add .
git commit -m "Initial Sysmon AI Analyst prototype"
git branch -M main
git remote add origin <YOUR_GITHUB_REPOSITORY>
git push -u origin main
```
