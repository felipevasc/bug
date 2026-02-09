# AGENTS.md (regras para LLMs e contribuidores)

Este repo eh uma base de **skills** orquestradas por **pipeline** para bug bounty/pentest.
O objetivo eh manter tudo previsivel, extensivel e facil de automatizar.

## Invariantes (nao quebrar)

- Skills sempre ficam em `src/skills/<tech>/<stage>/`.
- `stage` eh sempre: `recon`, `enum`, `exploit`, `report`.
- Nomes de arquivos com prefixo numerico: `01-...`, `02-...`.
- Todas as skills aceitam pelo menos `--target <valor>`.
- Todas as skills escrevem **JSONL** em stdout (1 JSON por linha).

## Metadados no topo do script

Obrigatorio incluir (em comentario/docstring):

```
@skill: <tech>/<stage>/<nome>
@inputs: target[, ...]
@outputs: asset|finding|note
@tools: <lista>
```

## Contrato de dados (JSONL)

Campos recomendados:
- `type`: `asset` | `finding` | `note`
- `target`: string
- `data`: objeto (sem esquema fixo)
- `timestamp`: ISO 8601
- `source`: caminho do script (ex: `src/skills/python/enum/01-port-scan.py`)
- `workspace` (opcional)

Regras:
- O JSON deve ser parseavel (sem logs misturados em stdout).
- Logs/diagnosticos devem ir para stderr.
- Nao imprimir arquivos gigantes no stdout; prefira resumir em `data`.

## Comunicacao entre skills

- Padrao: skills emitem JSONL e o runner/ingest decide o destino.
- Quando uma skill precisa de informacao anterior, ela deve:
  - Preferir consultar o Faraday via `src/bin/faraday-query.js`, ou
  - Receber dados via argumentos/variaveis de ambiente, ou
  - Receber JSONL via stdin (quando fizer sentido).

## Faraday

- Integracao principal esta em `src/lib/faraday.js`.
- O runner (`src/bin/run-pipeline.js`) e o ingest (`src/bin/faraday-ingest.js`) fazem ingestao quando configurado.
- Variaveis esperadas: `FARADAY_URL`, `FARADAY_WORKSPACE` e auth (`FARADAY_TOKEN` ou `FARADAY_USER`/`FARADAY_PASS`).
- `note` so eh importado se `FARADAY_IMPORT_NOTES=true`.
- Para targets hostname/dominio, `FARADAY_RESOLVE_HOSTNAMES=true` tenta resolver IPv4 antes de criar o host.

## Orquestracao

- `pipeline.json` eh a definicao de orquestracao.
- `src/bin/run-pipeline.js` executa as skills em ordem, por stage.
- Ao adicionar skill nova que deva entrar no fluxo padrao, atualizar `pipeline.json`.

## Padroes por linguagem

- Node.js (`src/skills/nodejs/*`):
  - O arquivo deve exportar `run({ target, emit })`.
  - O CLI deve existir (executar quando `require.main === module`).
  - O `run()` nao deve chamar `process.exit()`.
- Python (`src/skills/python/*`):
  - CLI com `argparse`.
  - `emit()` imprime JSONL compacto.
- Shell (`src/skills/shell/*`):
  - `#!/usr/bin/env bash` + `set -euo pipefail`.
  - Parse de `--target` (aceitar posicional como fallback).

## Como adicionar uma skill

1. Gerar o arquivo:

```bash
node scripts/new-skill.js --tech nodejs --stage recon --name "X" --order 03
```

2. Implementar a logica real usando ferramentas do Kali.
3. Garantir que stdout seja apenas JSONL.
4. Rodar sanity:

```bash
bash scripts/sanity.sh
```

5. Se for parte do fluxo padrao, atualizar `pipeline.json`.

## Seguranca / Escopo

- Nunca rodar acoes destrutivas por padrao.
- Exigir confirmacao/flags explicitas para:
  - brute-force, fuzz pesado, exploracao intrusiva.
- Respeitar escopo (allowlist) e rate limit quando aplicavel.
