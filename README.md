# Infra Report

Auditoria local de infraestrutura (portas, firewall, SSH, HTTP/TLS, Docker, hardening) com relatório JSON + HTML — **sem expor** o resultado na internet.

Versão atual: **1.5.2** (`infra-report --version`).

> O relatório contém achados de segurança. Não publique em site público, Caddy/nginx aberto, Portainer ou qualquer URL externa.

## Requisitos

| Obrigatório | Opcional |
|-------------|----------|
| Bash 4+, `python3` (≥3.8), `ss` (iproute2), `curl`, `openssl` | `docker`, `ufw` / `firewalld`, `fail2ban-client` |

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y iproute2 curl openssl python3

# RHEL / Rocky / Alma
sudo dnf install -y iproute curl openssl python3

# Alpine
sudo apk add iproute2 curl openssl python3 bash
```

## Arquivos

| Arquivo | Função |
|---------|--------|
| `infra-report.sh` | Coleta e achados |
| `infra_report_render.py` | Monta JSON + HTML (ao lado do `.sh`) |
| `install.sh` | Instala em `/usr/local` (wrapper + man) |
| `uninstall.sh` | Remove a instalação de `/usr/local` |
| `man/infra-report.1` | Manual (`man infra-report`) |
| `/tmp/infra-report.json` | Dados (padrão) |
| `/tmp/infra-report.html` | Página do relatório (padrão) |

## Instalação no VPS

### Recomendado: `install.sh`

No diretório do projeto (ou após copiar o pacote):

```bash
sudo bash install.sh
sudo bash uninstall.sh
# Prefixo custom: PREFIX=/opt sudo bash install.sh
#                 PREFIX=/opt sudo bash uninstall.sh
# Alternativa:    sudo bash install.sh --uninstall
```

Isso instala:

- `/usr/local/lib/infra-report/` — scripts
- `/usr/local/bin/infra-report` — wrapper (executa o `.sh` em `lib/`)
- `/usr/local/share/man/man1/infra-report.1`

```bash
sudo infra-report --json /tmp/infra-report.json
man infra-report
```

### Manual (qualquer path)

```bash
sudo mkdir -p /opt/infra-report
# copie infra-report.sh + infra_report_render.py para /opt/infra-report/
sudo chmod +x /opt/infra-report/infra-report.sh
sudo bash /opt/infra-report/infra-report.sh --json /tmp/infra-report.json
```

Override do renderizador:

```bash
export INFRA_REPORT_RENDER=/caminho/custom/infra_report_render.py
# ou
sudo infra-report --render-py /caminho/custom/infra_report_render.py
```

## 1. Gerar o relatório

```bash
sudo infra-report --json /tmp/infra-report.json
```

Saídas: `/tmp/infra-report.json` e `/tmp/infra-report.html`.

```bash
sudo infra-report --json /tmp/infra-report.json --html /tmp/meu-relatorio.html
sudo infra-report --json /tmp/infra-report.json --host exemplo.com
infra-report --version
```

## 2. Abrir o HTML (recomendado: túnel SSH)

Servir em `0.0.0.0` expõe dados sensíveis. O túnel acessa **só localhost** na sua máquina.

**Cliente** (deixe aberto):

```bash
ssh -N -L 8765:127.0.0.1:8765 USER@SEU_HOST
```

**Servidor:**

```bash
cd /tmp && python3 -m http.server 8765 --bind 127.0.0.1
```

**Browser:** http://127.0.0.1:8765/infra-report.html

| Flag | Significado |
|------|-------------|
| `-L 8765:127.0.0.1:8765` | Encaminha a porta local para o VPS |
| `-N` | Só túnel (sem shell) |
| `-f` | Background |

```bash
ssh -f -N -L 8765:127.0.0.1:8765 USER@SEU_HOST
```

### Windows (PowerShell / OpenSSH)

```powershell
ssh -N -L 8765:127.0.0.1:8765 USER@SEU_HOST
```

### Windows (PuTTY)

1. Session → Host: `SEU_HOST`
2. Connection → SSH → Tunnels → Source `8765` → Destination `127.0.0.1:8765` → Add
3. No VPS: `python3 -m http.server 8765 --bind 127.0.0.1` em `/tmp`
4. Browser: http://127.0.0.1:8765/infra-report.html

## 3. Alternativa sem HTTP server

```bash
scp USER@SEU_HOST:/tmp/infra-report.html ./infra-report.html
scp USER@SEU_HOST:/tmp/infra-report.json ./infra-report.json
```

Abra o `.html` no browser (JSON embutido; funciona offline — sem CDN de fontes).

## 4. Uso da página

- **Score / contadores** — postura geral
- **Achados** — filtros por severidade
- **Recomendações** — ações priorizadas
- **Portas / SSH / Firewall / HTTP / TLS / Docker** — detalhes
- **Baixar JSON embutido** / **Imprimir / PDF**

## 5. Checklist de segurança

- [ ] Não publicar HTML/JSON em root web público
- [ ] Sempre `--bind 127.0.0.1` no `http.server`
- [ ] Não liberar a porta do relatório no firewall só para ver
- [ ] Encerrar o `http.server` ao terminar
- [ ] Tratar JSON/HTML como confidencial

## 6. Troubleshooting

| Sintoma | Causa provável | Ação |
|---------|----------------|------|
| `ERRO: renderizador não encontrado` | `.py` fora do diretório do `.sh` | Mantenha juntos, `install.sh`, ou `--render-py` |
| `comandos obrigatórios ausentes` | Deps faltando | Seção Requisitos |
| `ERR_CONNECTION_TIMED_OUT` em `http://IP:8765` | Firewall / bind público | Túnel + `127.0.0.1` |
| Página em branco / score "—" | JSON inválido ou antigo | Regenere o relatório |
| `Connection refused` no túnel | HTTP server parado | `ss -tlnp \| grep 8765` |
| Porta em uso | Outro processo em `8765` | Use outra porta nos dois lados |

## 7. Fluxo rápido

**Servidor:**

```bash
sudo infra-report --json /tmp/infra-report.json
cd /tmp && python3 -m http.server 8765 --bind 127.0.0.1
```

**Cliente:**

```bash
ssh -N -L 8765:127.0.0.1:8765 USER@SEU_HOST
```

**Browser:** http://127.0.0.1:8765/infra-report.html
