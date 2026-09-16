#!/usr/bin/env bash
# ============================================================================
# analisar-infra.sh — Auditoria local de infraestrutura, portas e segurança
# Uso:  sudo bash analisar-infra.sh
#       sudo bash analisar-infra.sh --json /tmp/infra-report.json
#       sudo bash analisar-infra.sh --host exemplo.com
# Gera também HTML: mesmo caminho com extensão .html (ex: /tmp/infra-report.html)
# ============================================================================
set -euo pipefail

VERSION="1.2.0"
SCRIPT_NAME="$(basename "$0")"
HOST_TARGET=""
JSON_OUT=""
HTML_OUT=""
TIMEOUT_SEC=5
NOW="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname)"
RENDER_PY="/root/infra_report_render.py"

CRIT=0; WARN=0; INFO=0; OK=0
RECOMMENDATIONS=()
REPORT_TMP="$(mktemp -d /tmp/infra-audit.XXXXXX)"
trap 'rm -rf "$REPORT_TMP"' EXIT

: >"$REPORT_TMP/findings.jsonl"
: >"$REPORT_TMP/recommendations.jsonl"

if [[ -t 1 ]]; then
  R='\033[0;31m'; Y='\033[0;33m'; G='\033[0;32m'
  B='\033[0;34m'; C='\033[0;36m'; BOLD='\033[1m'; N='\033[0m'
else
  R=''; Y=''; G=''; B=''; C=''; BOLD=''; N=''
fi

usage() {
  cat <<EOF
${SCRIPT_NAME} v${VERSION} — análise local de infra / portas / HTTP(S) / segurança

Uso:
  sudo bash ${SCRIPT_NAME} [opções]

Opções:
  --host HOST     Testa HTTP/HTTPS em HOST (além do localhost)
  --json ARQUIVO  Salva relatório JSON (+ HTML irmão .html)
  --html ARQUIVO  Caminho HTML explícito (padrão: troca .json por .html)
  --timeout N     Timeout de probes em segundos (padrão: ${TIMEOUT_SEC})
  -h, --help      Ajuda

Requer: ss, curl, openssl, python3. Opcional: docker, ufw, fail2ban-client.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST_TARGET="${2:-}"; shift 2 ;;
    --json) JSON_OUT="${2:-}"; shift 2 ;;
    --html) HTML_OUT="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT_SEC="${2:-5}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Opção desconhecida: $1"; usage; exit 1 ;;
  esac
done

need_cmd() { command -v "$1" >/dev/null 2>&1; }

json_escape_line() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1], ensure_ascii=False))' "$1"
}

section() {
  echo ""
  echo -e "${BOLD}${C}═══ $* ═══${N}"
}

finding() {
  local level="$1" msg="$2" rec="${3:-}" section_name="${4:-geral}"
  case "$level" in
    CRIT) echo -e "  ${R}[CRÍTICO]${N} $msg"; CRIT=$((CRIT+1)) ;;
    WARN) echo -e "  ${Y}[AVISO]${N}   $msg"; WARN=$((WARN+1)) ;;
    INFO) echo -e "  ${B}[INFO]${N}    $msg"; INFO=$((INFO+1)) ;;
    OK)   echo -e "  ${G}[OK]${N}      $msg"; OK=$((OK+1)) ;;
  esac
  python3 -c '
import json,sys
print(json.dumps({"level":sys.argv[1],"message":sys.argv[2],"recommendation":sys.argv[3] or None,"section":sys.argv[4]}, ensure_ascii=False))
' "$level" "$msg" "$rec" "$section_name" >>"$REPORT_TMP/findings.jsonl"
  if [[ -n "$rec" ]]; then
    RECOMMENDATIONS+=("[$level] $rec")
    python3 -c '
import json,sys
print(json.dumps({"level":sys.argv[1],"text":sys.argv[2]}, ensure_ascii=False))
' "$level" "$rec" >>"$REPORT_TMP/recommendations.jsonl"
  fi
}

kv() { printf "  %-28s %s\n" "$1" "$2"; }

# ─── 1. Sistema ───────────────────────────────────────────────────────────────
analyze_system() {
  section "Sistema"

  python3 - "$HOSTNAME_FQDN" "$NOW" "$REPORT_TMP/system.json" <<'PY'
import json, os, platform, shutil, subprocess, sys
from pathlib import Path

hostname, generated_at, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

def human(n):
    n = float(n or 0)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or u == "TiB":
            return f"{n:.1f} {u}" if u != "B" else f"{int(n)} B"
        n /= 1024

def pct(used, total):
    if not total:
        return 0.0
    return round(100.0 * used / total, 1)

cpu_model = "n/a"
try:
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.lower().startswith("model name"):
            cpu_model = line.split(":", 1)[1].strip()
            break
except Exception:
    pass
cpus_logical = os.cpu_count() or 0
try:
    load1, load5, load15 = os.getloadavg()
except Exception:
    load1 = load5 = load15 = 0.0
load_per_cpu = round(load1 / cpus_logical, 2) if cpus_logical else None

mem = {}
try:
    for line in Path("/proc/meminfo").read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            mem[parts[0].rstrip(":")] = int(parts[1]) * 1024
except Exception:
    pass
mem_total = mem.get("MemTotal", 0)
mem_available = mem.get("MemAvailable", mem.get("MemFree", 0))
mem_used = max(0, mem_total - mem_available)
swap_total = mem.get("SwapTotal", 0)
swap_free = mem.get("SwapFree", 0)
swap_used = max(0, swap_total - swap_free)

disks = []
try:
    out = subprocess.check_output(["df", "-PBk"], text=True, stderr=subprocess.DEVNULL)
    for line in out.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        fs, blocks, used, avail, pcent, mount = cols[0], cols[1], cols[2], cols[3], cols[4], cols[5]
        if mount.startswith(("/proc", "/sys", "/run")):
            continue
        if not (fs.startswith("/") or fs.startswith("/dev")):
            continue
        total_b = int(blocks) * 1024
        used_b = int(used) * 1024
        avail_b = int(avail) * 1024
        disks.append({
            "filesystem": fs,
            "mount": mount,
            "total_bytes": total_b,
            "used_bytes": used_b,
            "available_bytes": avail_b,
            "used_percent": float(pcent.rstrip("%")),
            "total_human": human(total_b),
            "used_human": human(used_b),
            "available_human": human(avail_b),
        })
except Exception:
    pass

root = next((d for d in disks if d["mount"] == "/"), None)
if root is None:
    try:
        u = shutil.disk_usage("/")
        root = {
            "filesystem": "/",
            "mount": "/",
            "total_bytes": u.total,
            "used_bytes": u.used,
            "available_bytes": u.free,
            "used_percent": pct(u.used, u.total),
            "total_human": human(u.total),
            "used_human": human(u.used),
            "available_human": human(u.free),
        }
        disks = [root] + [d for d in disks if d["mount"] != "/"]
    except Exception:
        root = {}

uptime = "n/a"
try:
    uptime = subprocess.check_output(["uptime", "-p"], text=True).strip()
except Exception:
    try:
        uptime = subprocess.check_output(["uptime"], text=True).strip()
    except Exception:
        pass

os_name = platform.platform()
try:
    for line in Path("/etc/os-release").read_text().splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip().strip('"')
            break
except Exception:
    pass

kernel = platform.release()
mem_str = f"{human(mem_used)} / {human(mem_total)} usada ({pct(mem_used, mem_total)}%) · livre {human(mem_available)}"
disk_str = (
    f"{root.get('used_human','?')} / {root.get('total_human','?')} ({root.get('used_percent','?')}%) · livre {root.get('available_human','?')}"
    if root else "n/a"
)
load_str = f"{load1:.2f} {load5:.2f} {load15:.2f}"

resources = {
    "cpu": {
        "model": cpu_model,
        "logical_cpus": cpus_logical,
        "loadavg": {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)},
        "load_per_cpu_1m": load_per_cpu,
    },
    "memory": {
        "total_bytes": mem_total,
        "used_bytes": mem_used,
        "available_bytes": mem_available,
        "used_percent": pct(mem_used, mem_total),
        "total_human": human(mem_total),
        "used_human": human(mem_used),
        "available_human": human(mem_available),
    },
    "swap": {
        "total_bytes": swap_total,
        "used_bytes": swap_used,
        "available_bytes": swap_free,
        "used_percent": pct(swap_used, swap_total) if swap_total else 0.0,
        "total_human": human(swap_total),
        "used_human": human(swap_used),
        "available_human": human(swap_free),
    },
    "disks": disks,
    "disk_root": root or {},
}

Path(out_path).write_text(json.dumps({
    "hostname": hostname,
    "generated_at": generated_at,
    "kernel": kernel,
    "os": os_name,
    "uptime": uptime,
    "load": load_str,
    "memory": mem_str,
    "disk_root": disk_str,
    "resources": resources,
}, ensure_ascii=False, indent=2), encoding="utf-8")
PY

  local cpu_n model mem_h disk_h load_h mem_pct disk_pct swap_pct os kernel uptime
  eval "$(python3 - <<PY
import json
d=json.load(open("$REPORT_TMP/system.json"))
r=d.get("resources",{})
cpu=r.get("cpu",{})
mem=r.get("memory",{})
swap=r.get("swap",{})
root=r.get("disk_root") or {}
def q(s):
    return "'" + str(s).replace("'", "'\\''") + "'"
print("cpu_n="+q(cpu.get("logical_cpus",0)))
print("model="+q(cpu.get("model","")))
print("mem_h="+q(d.get("memory","")))
print("disk_h="+q(d.get("disk_root","")))
print("load_h="+q(d.get("load","")))
print("mem_pct="+q(mem.get("used_percent",0)))
print("disk_pct="+q(root.get("used_percent",0)))
print("swap_pct="+q(swap.get("used_percent",0)))
print("os="+q(d.get("os","")))
print("kernel="+q(d.get("kernel","")))
print("uptime="+q(d.get("uptime","")))
PY
)"

  kv "Hostname" "$HOSTNAME_FQDN"
  kv "Data (UTC)" "$NOW"
  kv "Kernel" "$kernel"
  kv "OS" "$os"
  kv "Uptime" "$uptime"
  kv "CPU" "${cpu_n} vCPU — ${model}"
  kv "Load" "$load_h"
  kv "Memória" "$mem_h"
  kv "Disco /" "$disk_h"

  awk -v p="$mem_pct" 'BEGIN{exit !(p+0>=90)}' && \
    finding CRIT "Memória em ${mem_pct}% de uso" "Libere processos, aumente RAM ou investigue vazamentos." "sistema" || true
  awk -v p="$mem_pct" 'BEGIN{exit !(p+0>=80 && p+0<90)}' && \
    finding WARN "Memória em ${mem_pct}% de uso" "Monitore consumo e planeje capacidade." "sistema" || true
  awk -v p="$disk_pct" 'BEGIN{exit !(p+0>=90)}' && \
    finding CRIT "Disco / em ${disk_pct}% de uso" "Libere espaço (logs, imagens Docker, backups antigos)." "sistema" || true
  awk -v p="$disk_pct" 'BEGIN{exit !(p+0>=80 && p+0<90)}' && \
    finding WARN "Disco / em ${disk_pct}% de uso" "Planeje limpeza ou expansão de volume." "sistema" || true
  awk -v p="$swap_pct" 'BEGIN{exit !(p+0>=50)}' && \
    finding WARN "Swap em ${swap_pct}% de uso" "Alto uso de swap indica pressão de memória." "sistema" || true

  if [[ "$(id -u)" -ne 0 ]]; then
    finding WARN "Não está rodando como root — alguns checks serão limitados" \
      "Execute com sudo para firewall, SSH e processos completos." "sistema"
  else
    finding OK "Executando como root" "" "sistema"
  fi
}

# ─── 2. Portas ────────────────────────────────────────────────────────────────
declare -A SENSITIVE_PORTS=(
  [21]="FTP (não criptografado)"
  [23]="Telnet (não criptografado)"
  [25]="SMTP"
  [110]="POP3"
  [143]="IMAP"
  [3306]="MySQL/MariaDB"
  [5432]="PostgreSQL"
  [6379]="Redis"
  [11211]="Memcached"
  [27017]="MongoDB"
  [9200]="Elasticsearch"
  [5601]="Kibana"
  [2375]="Docker API sem TLS"
  [2376]="Docker API (TLS)"
  [3389]="RDP"
  [5900]="VNC"
  [8080]="HTTP alt"
  [8443]="HTTPS alt"
  [9000]="Portainer HTTP"
  [9443]="Portainer HTTPS"
  [9090]="Monitor/Prometheus-like"
  [5060]="SIP"
  [5038]="Asterisk AMI"
)

analyze_ports() {
  section "Portas em escuta (TCP/UDP)"
  if ! need_cmd ss; then
    finding CRIT "comando 'ss' não encontrado" "" "portas"
    echo '[]' >"$REPORT_TMP/ports.json"
    return
  fi

  local listen_tcp listen_udp
  listen_tcp="$(ss -tlnp 2>/dev/null || true)"
  listen_udp="$(ss -ulnp 2>/dev/null || true)"

  echo -e "  ${BOLD}TCP:${N}"
  echo "$listen_tcp" | awk 'NR==1 || /LISTEN/' | sed 's/^/    /'
  echo ""
  echo -e "  ${BOLD}UDP (amostra):${N}"
  echo "$listen_udp" | head -n 20 | sed 's/^/    /'

  printf '%s\n' "$listen_tcp" >"$REPORT_TMP/ss_tcp.txt"
  python3 -c '
import json, re, sys
out_path, in_path = sys.argv[1], sys.argv[2]
raw = open(in_path).read()
ports, seen = [], set()
for line in raw.splitlines():
    if "LISTEN" not in line:
        continue
    parts = line.split()
    if len(parts) < 4:
        continue
    addr = parts[3]
    m = re.search(r":(\d+)$", addr.replace("]", ""))
    if not m:
        continue
    port = int(m.group(1))
    public = (
        addr.startswith("0.0.0.0:")
        or addr.startswith("*:")
        or addr.startswith("[::]:")
        or addr.startswith(":::")
    )
    process = ""
    pm = re.search(r"\"([^\"]+)\"", line)
    if pm:
        process = pm.group(1)
    key = (port, addr)
    if key in seen:
        continue
    seen.add(key)
    ports.append({"port": port, "address": addr, "public": public, "process": process, "proto": "tcp"})
json.dump(ports, open(out_path, "w"), ensure_ascii=False, indent=2)
' "$REPORT_TMP/ports.json" "$REPORT_TMP/ss_tcp.txt"

  declare -A SEEN_PUBLIC=() SEEN_LOCAL=()
  local line addr port
  while IFS= read -r line; do
    [[ "$line" == *LISTEN* ]] || continue
    addr="$(echo "$line" | awk '{print $4}')"
    port="${addr##*:}"; port="${port%%]*}"
    [[ "$port" =~ ^[0-9]+$ ]] || continue
    local public=0
    if [[ "$addr" == 0.0.0.0:* || "$addr" == \*:? || "$addr" == \[::\]:* || "$addr" == :::?* || "$addr" == \*:* ]]; then
      public=1
    fi
    if [[ -n "${SENSITIVE_PORTS[$port]+x}" ]]; then
      if [[ $public -eq 1 ]]; then
        if [[ -z "${SEEN_PUBLIC[$port]+x}" ]]; then
          SEEN_PUBLIC[$port]=1
          finding CRIT "Porta $port pública (${SENSITIVE_PORTS[$port]}) — bind: $addr" \
            "Restrinja a porta $port a localhost/VPN ou firewall (allowlist)." "portas"
        fi
      else
        if [[ -z "${SEEN_LOCAL[$port]+x}" ]]; then
          SEEN_LOCAL[$port]=1
          finding OK "Porta $port (${SENSITIVE_PORTS[$port]}) apenas local: $addr" "" "portas"
        fi
      fi
    fi
    if [[ "$port" == "22" && $public -eq 1 && -z "${SEEN_PUBLIC[ssh22]+x}" ]]; then
      SEEN_PUBLIC[ssh22]=1
      finding INFO "SSH na porta 22 exposto publicamente" \
        "Considere porta não padrão + fail2ban + chave-only + AllowUsers." "portas"
    fi
    if [[ "$port" == "80" && $public -eq 1 && -z "${SEEN_PUBLIC[http80]+x}" ]]; then
      SEEN_PUBLIC[http80]=1
      finding INFO "HTTP (80) público — verifique redirect para HTTPS" "" "portas"
    fi
  done <<< "$listen_tcp"

  local tcp_count
  tcp_count="$(echo "$listen_tcp" | grep -c LISTEN || true)"
  kv "Total listeners TCP" "$tcp_count"
}

# ─── 3. Firewall ──────────────────────────────────────────────────────────────
analyze_firewall() {
  section "Firewall"
  local ufw_status="n/a" fw_active=false
  local has_fw=0

  if need_cmd ufw; then
    has_fw=1
    ufw_status="$(ufw status 2>/dev/null | head -n 1 || true)"
    kv "UFW" "$ufw_status"
    if echo "$ufw_status" | grep -qi inactive; then
      finding CRIT "UFW instalado mas inativo" \
        "Ative o UFW com política default deny incoming e liberação explícita." "firewall"
    else
      fw_active=true
      finding OK "UFW ativo" "" "firewall"
      ufw status numbered 2>/dev/null | sed 's/^/    /' | head -n 40
    fi
  fi

  if need_cmd firewall-cmd; then
    has_fw=1
    if systemctl is-active --quiet firewalld 2>/dev/null; then
      fw_active=true
      finding OK "firewalld ativo" "" "firewall"
    else
      finding WARN "firewalld instalado mas inativo" "" "firewall"
    fi
  fi

  local ipt_rules=0
  if need_cmd iptables; then
    ipt_rules="$(iptables -L INPUT -n 2>/dev/null | grep -cE 'ACCEPT|DROP|REJECT' || true)"
    kv "Regras iptables INPUT" "$ipt_rules"
    if [[ $has_fw -eq 0 ]]; then
      if iptables -L INPUT -n 2>/dev/null | grep -q 'policy ACCEPT' && [[ "$ipt_rules" -lt 5 ]]; then
        finding WARN "iptables com política ACCEPT e poucas regras" \
          "Configure UFW/firewalld ou regras iptables/nftables restritivas." "firewall"
      fi
    fi
  fi

  if [[ $has_fw -eq 0 ]] && ! need_cmd iptables && ! need_cmd nft; then
    finding WARN "Nenhum firewall detectado (ufw/firewalld/iptables/nft)" \
      "Instale e configure um firewall de host." "firewall"
  fi

  python3 -c '
import json,sys
print(json.dumps({"ufw": sys.argv[1], "active": sys.argv[2]=="true", "iptables_input_rules": int(sys.argv[3])}, ensure_ascii=False))
' "$ufw_status" "$fw_active" "$ipt_rules" >"$REPORT_TMP/firewall.json"
}

# ─── 4. SSH ───────────────────────────────────────────────────────────────────
analyze_ssh() {
  section "SSH"
  local conf="/etc/ssh/sshd_config"
  local permit_root="" pwd_auth="" pubkey="" port="22" fail2ban=false

  if [[ ! -f "$conf" ]]; then
    finding INFO "sshd_config não encontrado" "" "ssh"
    echo '{}' >"$REPORT_TMP/ssh.json"
    return
  fi

  get_ssh() {
    local key="$1"
    grep -Ei "^[[:space:]]*${key}[[:space:]]+" "$conf" 2>/dev/null \
      | grep -v '^[[:space:]]*#' | tail -n1 | awk '{print $2}' | tr -d '"' || true
  }

  permit_root="$(get_ssh PermitRootLogin)"
  pwd_auth="$(get_ssh PasswordAuthentication)"
  pubkey="$(get_ssh PubkeyAuthentication)"
  port="$(get_ssh Port)"; port="${port:-22}"

  kv "Port" "$port"
  kv "PermitRootLogin" "${permit_root:-default}"
  kv "PasswordAuthentication" "${pwd_auth:-default}"
  kv "PubkeyAuthentication" "${pubkey:-default}"

  case "${permit_root,,}" in
    yes) finding CRIT "PermitRootLogin yes" "Defina PermitRootLogin prohibit-password ou no." "ssh" ;;
    prohibit-password|without-password|no) finding OK "PermitRootLogin=${permit_root}" "" "ssh" ;;
    *) finding INFO "PermitRootLogin=${permit_root:-padrão do pacote}" "" "ssh" ;;
  esac

  case "${pwd_auth,,}" in
    yes) finding WARN "PasswordAuthentication yes" "Prefira autenticação só por chave (PasswordAuthentication no)." "ssh" ;;
    no) finding OK "PasswordAuthentication no" "" "ssh" ;;
  esac

  if need_cmd fail2ban-client; then
    if fail2ban-client status 2>/dev/null | grep -qi ssh; then
      fail2ban=true
      finding OK "fail2ban com jail SSH" "" "ssh"
    else
      finding WARN "fail2ban presente, jail SSH não detectado" \
        "Habilite jail sshd no fail2ban." "ssh"
    fi
  else
    finding INFO "fail2ban não instalado" \
      "Instale fail2ban para mitigar brute-force em SSH/HTTP." "ssh"
  fi

  python3 -c '
import json,sys
print(json.dumps({
  "port": sys.argv[1], "permit_root_login": sys.argv[2] or "default",
  "password_authentication": sys.argv[3] or "default",
  "pubkey_authentication": sys.argv[4] or "default",
  "fail2ban_ssh": sys.argv[5]=="true"
}, ensure_ascii=False))
' "$port" "${permit_root}" "${pwd_auth}" "${pubkey}" "$fail2ban" >"$REPORT_TMP/ssh.json"
}

# ─── 5. HTTP / HTTPS ──────────────────────────────────────────────────────────
SECURITY_HEADERS=(
  "Strict-Transport-Security"
  "Content-Security-Policy"
  "X-Content-Type-Options"
  "X-Frame-Options"
  "Referrer-Policy"
  "Permissions-Policy"
)

: >"$REPORT_TMP/http.jsonl"
: >"$REPORT_TMP/tls.jsonl"

probe_http() {
  local url="$1"
  local label="$2"
  echo ""
  echo -e "  ${BOLD}→ ${label}: ${url}${N}"

  if ! need_cmd curl; then
    finding WARN "curl indisponível" "" "http"
    return
  fi

  local headers http_code
  headers="$(curl -sS -k -I -L --max-time "$TIMEOUT_SEC" --connect-timeout "$TIMEOUT_SEC" "$url" 2>/dev/null || true)"
  if [[ -z "$headers" ]]; then
    finding WARN "Sem resposta de $url" "" "http"
    python3 -c 'import json,sys; print(json.dumps({"url":sys.argv[1],"ok":False}, ensure_ascii=False))' "$url" >>"$REPORT_TMP/http.jsonl"
    return
  fi

  http_code="$(echo "$headers" | awk 'BEGIN{c="?"} /^HTTP/{c=$2} END{print c}')"
  kv "Status" "$http_code"

  local redirect_https=false
  if [[ "$url" == http://* ]]; then
    if echo "$headers" | grep -qiE '^location:[[:space:]]*https://'; then
      redirect_https=true
      finding OK "Redirect HTTP → HTTPS presente" "" "http"
    else
      finding WARN "HTTP sem Location para HTTPS" \
        "Configure redirect 301 permanente de HTTP para HTTPS." "http"
    fi
  fi

  local present_headers=() missing=()
  local h
  for h in "${SECURITY_HEADERS[@]}"; do
    if echo "$headers" | grep -qi "^${h}:"; then
      present_headers+=("$h")
      finding OK "Header $h presente" "" "http"
    else
      missing+=("$h")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    finding WARN "Headers ausentes: ${missing[*]}" \
      "Adicione headers de segurança no reverse proxy (nginx/caddy/traefik)." "http"
  fi

  local srv
  srv="$(echo "$headers" | grep -i '^server:' | head -n1 | cut -d: -f2- | tr -d '\r' | xargs || true)"
  if [[ -n "$srv" ]]; then
    kv "Server" "$srv"
    if echo "$srv" | grep -qiE 'Apache/[0-9]|nginx/[0-9]|PHP/'; then
      finding INFO "Banner Server revela versão ($srv)" \
        "Oculte versões com server_tokens off / ServerTokens Prod." "http"
    fi
  fi

  python3 -c '
import json,sys
print(json.dumps({
  "url": sys.argv[1], "status": sys.argv[2], "server": sys.argv[3],
  "redirect_https": sys.argv[4]=="true",
  "headers_present": json.loads(sys.argv[5]),
  "headers_missing": json.loads(sys.argv[6]),
  "ok": True
}, ensure_ascii=False))
' "$url" "$http_code" "$srv" "$redirect_https" \
  "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${present_headers[@]:-}")" \
  "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${missing[@]:-}")" \
  >>"$REPORT_TMP/http.jsonl"
}

probe_tls() {
  local host="$1" port="${2:-443}"
  echo ""
  echo -e "  ${BOLD}→ TLS ${host}:${port}${N}"

  if ! need_cmd openssl; then
    finding WARN "openssl indisponível" "" "tls"
    return
  fi

  local out
  out="$(echo | timeout "$TIMEOUT_SEC" openssl s_client -connect "${host}:${port}" -servername "$host" 2>/dev/null || true)"
  if [[ -z "$out" ]] || ! echo "$out" | grep -q 'BEGIN CERTIFICATE'; then
    finding WARN "Não foi possível obter certificado em ${host}:${port}" "" "tls"
    python3 -c 'import json,sys; print(json.dumps({"host":sys.argv[1],"port":int(sys.argv[2]),"ok":False}, ensure_ascii=False))' \
      "$host" "$port" >>"$REPORT_TMP/tls.jsonl"
    return
  fi

  local subject issuer not_after proto days=""
  subject="$(echo "$out" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')"
  issuer="$(echo "$out" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')"
  not_after="$(echo "$out" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
  proto="$(echo "$out" | grep -E 'Protocol  :' | tail -n1 | awk -F: '{print $2}' | xargs)"

  kv "Subject" "$subject"
  kv "Issuer" "$issuer"
  kv "Validade até" "$not_after"
  kv "Protocolo" "${proto:-n/a}"

  local end_epoch now_epoch
  end_epoch="$(date -d "$not_after" +%s 2>/dev/null || true)"
  now_epoch="$(date +%s)"
  if [[ -n "$end_epoch" ]]; then
    days=$(( (end_epoch - now_epoch) / 86400 ))
    kv "Dias restantes" "$days"
    if [[ $days -lt 0 ]]; then
      finding CRIT "Certificado EXPIRADO" "Renove o certificado TLS imediatamente." "tls"
    elif [[ $days -lt 14 ]]; then
      finding CRIT "Certificado expira em $days dias" "Renove (certbot renew / ACME) e monitore expiração." "tls"
    elif [[ $days -lt 30 ]]; then
      finding WARN "Certificado expira em $days dias" "Agende renovação; configure alerta < 30 dias." "tls"
    else
      finding OK "Certificado válido por mais $days dias" "" "tls"
    fi
  fi

  if echo "$out" | grep -qE 'Protocol  : TLSv1\.0|Protocol  : TLSv1\.1|Protocol  : SSLv'; then
    finding CRIT "Protocolo TLS legado em uso ($proto)" \
      "Desabilite SSLv3/TLS1.0/TLS1.1; use TLS 1.2+." "tls"
  elif [[ "$proto" == *TLSv1.2* || "$proto" == *TLSv1.3* ]]; then
    finding OK "Protocolo moderno: $proto" "" "tls"
  fi

  python3 -c '
import json,sys
days = sys.argv[6]
print(json.dumps({
  "host": sys.argv[1], "port": int(sys.argv[2]), "ok": True,
  "subject": sys.argv[3], "issuer": sys.argv[4], "not_after": sys.argv[5],
  "days_remaining": int(days) if days not in ("", "None") else None,
  "protocol": sys.argv[7] or None
}, ensure_ascii=False))
' "$host" "$port" "$subject" "$issuer" "$not_after" "${days:-}" "${proto:-}" >>"$REPORT_TMP/tls.jsonl"
}

analyze_http() {
  section "HTTP / HTTPS"
  local targets=()
  if ss -tln 2>/dev/null | grep -qE ':80\s'; then targets+=("http://127.0.0.1"); fi
  if ss -tln 2>/dev/null | grep -qE ':443\s'; then targets+=("https://127.0.0.1"); fi
  if ss -tln 2>/dev/null | grep -qE ':8080\s'; then targets+=("http://127.0.0.1:8080"); fi
  if ss -tln 2>/dev/null | grep -qE ':8443\s'; then targets+=("https://127.0.0.1:8443"); fi
  if [[ -n "$HOST_TARGET" ]]; then
    targets+=("http://${HOST_TARGET}" "https://${HOST_TARGET}")
  fi

  if [[ ${#targets[@]} -eq 0 ]]; then
    finding INFO "Nenhuma porta 80/443/8080/8443 detectada localmente" \
      "Use --host SEU_DOMINIO para testar endpoints externos." "http"
  fi

  local t
  for t in "${targets[@]}"; do
    probe_http "$t" "probe"
  done

  if ss -tln 2>/dev/null | grep -qE ':443\s'; then
    probe_tls "127.0.0.1" 443
  fi
  if [[ -n "$HOST_TARGET" ]]; then
    probe_tls "$HOST_TARGET" 443
  fi
}

# ─── 6. Docker ────────────────────────────────────────────────────────────────
analyze_docker() {
  section "Docker"
  if ! need_cmd docker; then
    finding INFO "Docker não instalado / não no PATH" "" "docker"
    echo '{"available":false}' >"$REPORT_TMP/docker.json"
    return
  fi
  if ! docker info >/dev/null 2>&1; then
    finding WARN "Docker presente mas daemon inacessível" "" "docker"
    echo '{"available":true,"daemon":false}' >"$REPORT_TMP/docker.json"
    return
  fi

  finding OK "Docker daemon acessível" "" "docker"
  local running images
  running="$(docker ps -q 2>/dev/null | wc -l)"
  images="$(docker images -q 2>/dev/null | wc -l)"
  kv "Containers rodando" "$running"
  kv "Imagens" "$images"

  echo -e "  ${BOLD}Containers:${N}"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null | sed 's/^/    /'

  docker ps --format '{{json .}}' 2>/dev/null >"$REPORT_TMP/docker_ps.jsonl" || true

  if ss -tln 2>/dev/null | grep -qE ':2375\s'; then
    finding CRIT "Docker API TCP 2375 em escuta (sem TLS)" \
      "Nunca exponha 2375 publicamente; use TLS (2376) ou apenas socket unix." "docker"
  fi

  local priv
  priv="$(docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null | grep ' true$' || true)"
  local privileged_names=""
  if [[ -n "$priv" ]]; then
    privileged_names="$(echo "$priv" | awk '{print $1}' | tr '\n' ' ')"
    finding WARN "Containers privilegiados: $privileged_names" \
      "Evite --privileged; use capabilities mínimas." "docker"
  else
    finding OK "Nenhum container privilegiado detectado" "" "docker"
  fi

  python3 -c '
import json,sys
containers=[]
try:
  with open(sys.argv[4]) as f:
    for line in f:
      line=line.strip()
      if not line: continue
      o=json.loads(line)
      containers.append({"name": o.get("Names"), "status": o.get("Status"), "ports": o.get("Ports")})
except Exception:
  pass
print(json.dumps({
  "available": True, "daemon": True,
  "running": int(sys.argv[1]), "images": int(sys.argv[2]),
  "privileged": [x for x in sys.argv[3].split() if x],
  "containers": containers
}, ensure_ascii=False))
' "$running" "$images" "$privileged_names" "$REPORT_TMP/docker_ps.jsonl" >"$REPORT_TMP/docker.json"
}

# ─── 7. Misc ──────────────────────────────────────────────────────────────────
analyze_misc() {
  section "Hardening geral"
  local upgradable=0 unattended=false cron_jobs=0

  if need_cmd apt-get; then
    upgradable="$(apt list --upgradable 2>/dev/null | grep -vc 'Listing' || true)"
    kv "Pacotes atualizáveis (apt)" "$upgradable"
    if [[ "${upgradable:-0}" -gt 50 ]]; then
      finding WARN "Muitos pacotes pendentes ($upgradable)" \
        "Aplique atualizações de segurança regularmente (unattended-upgrades)." "hardening"
    elif [[ "${upgradable:-0}" -gt 0 ]]; then
      finding INFO "$upgradable pacotes com update disponível" "" "hardening"
    else
      finding OK "Sistema aparentemente atualizado (apt)" "" "hardening"
    fi
  fi

  if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    unattended=true
    finding OK "unattended-upgrades instalado" "" "hardening"
  else
    finding INFO "unattended-upgrades não instalado" \
      "Considere unattended-upgrades para patches de segurança automáticos." "hardening"
  fi

  if [[ -d /etc ]]; then
    local ww
    ww="$(find /etc -type f -perm -0002 2>/dev/null | head -n 5 || true)"
    if [[ -n "$ww" ]]; then
      finding WARN "Arquivos world-writable em /etc" \
        "Remova permissão de escrita para 'others' em arquivos de configuração." "hardening"
    else
      finding OK "Sem world-writable óbvio em /etc" "" "hardening"
    fi
  fi

  if [[ -d /etc/cron.d ]]; then
    cron_jobs="$(ls /etc/cron.d 2>/dev/null | wc -l)"
    kv "Jobs cron.d" "$cron_jobs"
  fi

  if mount | grep -q ' /tmp '; then
    if mount | grep ' /tmp ' | grep -q noexec; then
      finding OK "/tmp com noexec" "" "hardening"
    else
      finding INFO "/tmp sem noexec" "Considere montar /tmp com noexec,nosuid,nodev." "hardening"
    fi
  fi

  if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
    if [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" == "0" ]]; then
      finding INFO "IPv6 habilitado — garanta regras de firewall também em ip6tables/nft" "" "hardening"
    fi
  fi

  python3 -c '
import json,sys
print(json.dumps({
  "apt_upgradable": int(sys.argv[1]),
  "unattended_upgrades": sys.argv[2]=="true",
  "cron_d_jobs": int(sys.argv[3])
}, ensure_ascii=False))
' "$upgradable" "$unattended" "$cron_jobs" >"$REPORT_TMP/hardening.json"
}

print_summary() {
  section "Resumo"
  echo -e "  ${R}Críticos:${N} $CRIT   ${Y}Avisos:${N} $WARN   ${B}Infos:${N} $INFO   ${G}OK:${N} $OK"

  if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
    section "Recomendações priorizadas"
    local i=1 r
    for r in "${RECOMMENDATIONS[@]}"; do
      [[ "$r" == \[CRIT\]* ]] || continue
      echo -e "  ${R}${i}.${N} ${r#\[CRIT\] }"
      i=$((i+1))
    done
    for r in "${RECOMMENDATIONS[@]}"; do
      [[ "$r" == \[WARN\]* ]] || continue
      echo -e "  ${Y}${i}.${N} ${r#\[WARN\] }"
      i=$((i+1))
    done
    for r in "${RECOMMENDATIONS[@]}"; do
      [[ "$r" == \[INFO\]* ]] || continue
      echo -e "  ${B}${i}.${N} ${r#\[INFO\] }"
      i=$((i+1))
    done
  fi
  echo ""
}

write_report() {
  # Sem --json: grava padrão em /tmp
  if [[ -z "$JSON_OUT" ]]; then
    JSON_OUT="/tmp/infra-report.json"
  fi
  if [[ -z "$HTML_OUT" ]]; then
    if [[ "$JSON_OUT" == *.json ]]; then
      HTML_OUT="${JSON_OUT%.json}.html"
    else
      HTML_OUT="${JSON_OUT}.html"
    fi
  fi

  python3 "$RENDER_PY" \
    --tmp "$REPORT_TMP" \
    --json-out "$JSON_OUT" \
    --html-out "$HTML_OUT" \
    --version "$VERSION" \
    --crit "$CRIT" --warn "$WARN" --info "$INFO" --ok "$OK" \
    --host-target "$HOST_TARGET"

  echo -e "  Relatório JSON: ${BOLD}${JSON_OUT}${N}"
  echo -e "  Relatório HTML: ${BOLD}${HTML_OUT}${N}"
}

main() {
  echo -e "${BOLD}Auditoria de infraestrutura v${VERSION}${N}"
  echo "  Alvo local: $HOSTNAME_FQDN"
  [[ -n "$HOST_TARGET" ]] && echo "  Host HTTP(S): $HOST_TARGET"

  if [[ ! -f "$RENDER_PY" ]]; then
    echo "ERRO: renderizador não encontrado: $RENDER_PY" >&2
    exit 1
  fi

  analyze_system
  analyze_ports
  analyze_firewall
  analyze_ssh
  analyze_http
  analyze_docker
  analyze_misc
  print_summary
  write_report
}

main
