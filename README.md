# BugBounty / Pentest Automation Hub (Skills + Pipeline + Faraday)

Projeto para organizar e orquestrar automacoes de bug bounty/pentest em 4 etapas:
- `recon`: descoberta e enriquecimento de escopo/ativos
- `enum`: enumeracoes (portas/servicos/paths/arquivos)
- `exploit`: validacao controlada (PoCs) e verificacao de impacto
- `report`: consolidacao (sumarios, evidencias, export)

A integracao com Faraday (self-hosted) eh opcional: o pipeline pode apenas emitir JSONL, e quando configurado tambem faz ingestao no Faraday.

## Estrutura

```
.
├─ README.md
├─ AGENTS.md
├─ package.json
├─ pipeline.json
├─ scripts/
│  ├─ new-skill.js
│  └─ sanity.sh
└─ src/
   ├─ bin/
   │  ├─ run-pipeline.js
   │  ├─ faraday-ingest.js
   │  └─ faraday-query.js
   ├─ lib/
   │  └─ faraday.js
   └─ skills/
      ├─ nodejs/{recon,enum,exploit,report}/
      ├─ python/{recon,enum,exploit,report}/
      └─ shell/{recon,enum,exploit,report}/
```

## Quickstart

Sanity check local (nao precisa Faraday):

```bash
bash scripts/sanity.sh
```

How-to para instalar dependencias (inclui Faraday opcional):

```bash
bash scripts/sanity.sh --howto
```

Rodar pipeline em dry-run (gera JSONL no stdout):

```bash
node src/bin/run-pipeline.js --target example.com --dry-run
```

Rodar apenas uma etapa:

```bash
node src/bin/run-pipeline.js --target example.com --stage recon --dry-run
```

## Contrato de Dados (JSONL)

**Todas as skills escrevem JSON Lines** (1 objeto JSON por linha) em stdout.

Campos esperados:
- `type`: `asset` | `finding` | `note`
- `target`: host/ip/dominio
- `data`: objeto livre com informacoes do achado
- `timestamp`: ISO 8601 (se nao vier, o runner/skills adicionam)
- `source`: caminho do script (ex: `src/skills/nodejs/recon/01-passive-recon.js`)
- `workspace` (opcional): pode vir no record, ou ser fornecido via `--workspace` no runner/ingest

Exemplo:

```json
{"type":"finding","target":"example.com","data":{"category":"http-enum","endpoints":["/","/login"]},"timestamp":"2026-02-09T00:00:00Z","source":"src/skills/nodejs/enum/01-http-enum.js"}
```

## Orquestracao (pipeline)

- `pipeline.json` define a ordem das etapas e quais skills executar.
- O runner eh `src/bin/run-pipeline.js`.

Uso:

```bash
node src/bin/run-pipeline.js --target example.com --dry-run
node src/bin/run-pipeline.js --target example.com --workspace myws
```

Observacoes:
- Skills em `nodejs/` sao executadas in-process (import/export) para suportar ambientes onde `node -> child node stdout pipe` eh instavel.
- Skills em `python/` e `shell/` rodam como subprocessos e precisam aceitar `--target`.
- Quando `pipeline.json` tem `options.propagate_assets=true`, o runner acumula novos alvos a partir de records `asset` e usa o conjunto expandido nas proximas etapas (a partir de `record.target`, `record.data.hostnames[]` e `record.data.ip` quando existirem).

## Faraday (opcional)

### Variaveis

- `FARADAY_URL` (ex: `http://127.0.0.1:5985`)
- `FARADAY_WORKSPACE` (workspace existente)
- Auth (1 opcao):
  - `FARADAY_TOKEN` (preferencial)
  - ou `FARADAY_USER` + `FARADAY_PASS`

O runner chama `ingestRecord()` de `src/lib/faraday.js` para `asset` e `finding`.

Notas:
- `note` nao eh importado por padrao. Para importar como `finding` de severidade `info`, usar `FARADAY_IMPORT_NOTES=true`.
- `FARADAY_DEBUG=true` imprime logs de debug no stderr.
- Se seus targets sao dominios/hostnames, `FARADAY_RESOLVE_HOSTNAMES=true` tenta resolver IPv4 (A) para criar hosts com IP real no Faraday.

### Ingest Manual (JSONL)

Quando quiser rodar uma skill isolada e ingerir no Faraday:

```bash
bash src/skills/shell/recon/01-subdomains.sh --target example.com \
  | node src/bin/faraday-ingest.js --workspace myws
```

### Query (minimo)

```bash
node src/bin/faraday-query.js list-hosts --workspace myws
node src/bin/faraday-query.js find-host --workspace myws --target example.com
```

## Criando uma Nova Skill

Gerador (recomendado):

```bash
node scripts/new-skill.js --tech nodejs --stage recon --name "Passive Recon" --order 02
node scripts/new-skill.js --tech python --stage enum --name "Port Scan" --order 02
node scripts/new-skill.js --tech shell --stage report --name "Export" --order 02
```

Regras:
- Local: `src/skills/<tech>/<stage>/`
- `stage`: `recon|enum|exploit|report`
- Prefixo numerico: `01-`, `02-`...
- Sempre emitir JSONL em stdout.

## Executando Skills Individualmente

```bash
node src/skills/nodejs/recon/01-passive-recon.js --target example.com
python3 src/skills/python/enum/01-port-scan.py --target example.com
bash src/skills/shell/enum/01-dir-enum.sh --target example.com
```

## Sobre npm

Se `npm` no seu ambiente apontar para o Windows (ex: WSL1), os scripts do `package.json` podem nao funcionar.
Use os comandos diretos (`node ...`, `bash ...`) acima ou instale `npm` nativo dentro do Linux/WSL.
