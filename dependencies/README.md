# Dependencies / Setup (Kali/WSL)

Esta pasta descreve e automatiza a instalacao das dependencias que o pipeline usa.

> Observacao: varios passos exigem `sudo` e/ou acesso a internet para baixar pacotes.

## O que instala

### Base (recomendado)
- `nmap` (port scan + service detect)
- `httpx` (probe HTTP)
- `whatweb` (fingerprint)
- `sslscan` (TLS)
- `curl`, `jq`, `dnsutils` (dig)

### Recon / Enum (para volume)
- `amass` (subdomain enum)
- `ffuf` (dir/file enum)
- `seclists` (wordlists)

### Vulnerability scanning (opcional, mas muito util)
- `nuclei` + `nuclei-templates`

### Faraday (opcional)
- `faraday` + `postgresql` + `redis-server`

## Instalacao rapida

No Kali/WSL:

```bash
cd /mnt/c/dev/bug
bash dependencies/install_kali.sh
```

Esse script:
- instala pacotes via `apt`
- tenta instalar ferramentas Go (se `go` existir)
- atualiza `nuclei-templates` se nuclei estiver instalado
- inicializa e sobe Faraday se estiver instalado

## Verificacao

Depois rode:

```bash
bash dependencies/check_kali.sh
```

Ele imprime o que esta instalado e o que esta faltando.

## Dicas
- Se `sudo` pedir senha, eh esperado.
- Se voce nao quiser instalar Faraday, exporte `INSTALL_FARADAY=0` ao rodar o script.

Ex:

```bash
INSTALL_FARADAY=0 bash dependencies/install_kali.sh
```
