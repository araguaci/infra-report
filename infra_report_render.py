#!/usr/bin/env python3
"""Monta infra-report.json + página HTML a partir dos artefatos temporários da auditoria."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except Exception:
            continue
    return rows


def build_report(args: argparse.Namespace) -> Dict[str, Any]:
    tmp = Path(args.tmp)
    findings = load_jsonl(tmp / "findings.jsonl")
    recommendations = load_jsonl(tmp / "recommendations.jsonl")

    # Prioriza recomendações: CRIT → WARN → INFO, sem duplicar texto
    order = {"CRIT": 0, "WARN": 1, "INFO": 2, "OK": 3}
    seen_rec: set = set()
    recs_sorted: List[Dict[str, Any]] = []
    for level in ("CRIT", "WARN", "INFO"):
        for r in recommendations:
            if r.get("level") != level:
                continue
            text = (r.get("text") or "").strip()
            if not text or text in seen_rec:
                continue
            seen_rec.add(text)
            recs_sorted.append({"level": level, "text": text})

    report: Dict[str, Any] = {
        "tool": "infra-report.sh",
        "version": args.version,
        "host_target": args.host_target or None,
        "system": load_json(tmp / "system.json", {}),
        "summary": {
            "critical": int(args.crit),
            "warn": int(args.warn),
            "info": int(args.info),
            "ok": int(args.ok),
            "score": max(
                0,
                100
                - int(args.crit) * 12
                - int(args.warn) * 4
                - int(args.info) * 1,
            ),
        },
        "findings": findings,
        "recommendations": recs_sorted,
        "ports": load_json(tmp / "ports.json", []),
        "firewall": load_json(tmp / "firewall.json", {}),
        "ssh": load_json(tmp / "ssh.json", {}),
        "http": load_jsonl(tmp / "http.jsonl"),
        "tls": load_jsonl(tmp / "tls.jsonl"),
        "docker": load_json(tmp / "docker.json", {}),
        "hardening": load_json(tmp / "hardening.json", {}),
        "checklist": [
            "Firewall default-deny + allowlist de portas",
            "SSH: chave-only, root desabilitado, fail2ban",
            "TLS 1.2+, renovação automática, HSTS",
            "DBs/Redis/AMI só em localhost ou rede privada",
            "Headers de segurança no reverse proxy",
            "Backups testados + monitoramento de expiração de certs",
        ],
    }
    # host no topo para compatibilidade
    report["host"] = report["system"].get("hostname", "")
    report["generated_at"] = report["system"].get("generated_at", "")
    return report


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Infra Report — __HOST__</title>
<style>
  :root {
    --font-display: Georgia, "Iowan Old Style", "Palatino Linotype", "Times New Roman", serif;
    --font-sans: "Segoe UI", "Helvetica Neue", Helvetica, ui-sans-serif, system-ui, sans-serif;
    --font-mono: "Cascadia Mono", "SF Mono", Consolas, "Liberation Mono", ui-monospace, monospace;
    --bg: #e8efe8;
    --bg-deep: #d5e2d6;
    --ink: #14201a;
    --muted: #4a5c52;
    --line: rgba(20, 32, 26, 0.12);
    --panel: rgba(255, 252, 247, 0.72);
    --crit: #b42318;
    --warn: #b54708;
    --info: #175cd3;
    --ok: #027a48;
    --accent: #0f6b4c;
    --accent-2: #1a8f66;
    --radar: rgba(15, 107, 76, 0.08);
  }
  * { box-sizing: border-box; }
  html { scroll-behavior: smooth; }
  body {
    margin: 0;
    color: var(--ink);
    font-family: var(--font-sans);
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, rgba(26, 143, 102, 0.18), transparent 55%),
      radial-gradient(ellipse 60% 40% at 90% 0%, rgba(20, 32, 26, 0.08), transparent 50%),
      linear-gradient(165deg, var(--bg) 0%, var(--bg-deep) 100%);
    min-height: 100vh;
  }
  body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image:
      linear-gradient(var(--line) 1px, transparent 1px),
      linear-gradient(90deg, var(--line) 1px, transparent 1px);
    background-size: 48px 48px;
    mask-image: linear-gradient(180deg, rgba(0,0,0,.35), transparent 70%);
    opacity: .45;
  }
  .wrap {
    position: relative;
    width: min(1120px, calc(100% - 2rem));
    margin: 0 auto;
    padding: 2.5rem 0 4rem;
  }
  .brand {
    font-family: var(--font-display);
    font-size: clamp(2.4rem, 5vw, 3.6rem);
    font-weight: 700;
    letter-spacing: -0.03em;
    line-height: 1.05;
    margin: 0 0 .4rem;
    color: var(--accent);
  }
  .lede {
    margin: 0 0 1.75rem;
    max-width: 38rem;
    color: var(--muted);
    font-size: 1.05rem;
    line-height: 1.5;
  }
  .meta {
    display: flex;
    flex-wrap: wrap;
    gap: .55rem .9rem;
    margin-bottom: 1.75rem;
    font-family: var(--font-mono);
    font-size: .78rem;
    color: var(--muted);
  }
  .meta span {
    background: var(--panel);
    border: 1px solid var(--line);
    padding: .35rem .65rem;
  }
  .score-row {
    display: grid;
    grid-template-columns: 160px 1fr;
    gap: 1.25rem;
    align-items: stretch;
    margin-bottom: 2rem;
  }
  @media (max-width: 720px) {
    .score-row { grid-template-columns: 1fr; }
  }
  .score {
    background: var(--ink);
    color: #f4faf6;
    padding: 1.25rem;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    min-height: 140px;
  }
  .score strong {
    font-family: var(--font-display);
    font-size: 3rem;
    line-height: 1;
    font-weight: 700;
  }
  .score small { opacity: .7; font-size: .75rem; letter-spacing: .04em; text-transform: uppercase; }
  .stats {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: .75rem;
  }
  @media (max-width: 720px) {
    .stats { grid-template-columns: repeat(2, 1fr); }
  }
  .stat {
    background: var(--panel);
    border: 1px solid var(--line);
    padding: 1rem .9rem;
  }
  .stat b {
    display: block;
    font-family: var(--font-display);
    font-size: 1.9rem;
    line-height: 1;
    margin-bottom: .35rem;
  }
  .stat span { font-size: .78rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
  .stat.crit b { color: var(--crit); }
  .stat.warn b { color: var(--warn); }
  .stat.info b { color: var(--info); }
  .stat.ok b { color: var(--ok); }
  section {
    margin: 2.25rem 0 0;
  }
  h2 {
    font-family: var(--font-display);
    font-size: 1.55rem;
    font-weight: 700;
    margin: 0 0 .35rem;
    letter-spacing: -0.02em;
  }
  .section-lede {
    margin: 0 0 1rem;
    color: var(--muted);
    font-size: .95rem;
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--line);
    backdrop-filter: blur(8px);
  }
  .sys-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1px;
    background: var(--line);
    border: 1px solid var(--line);
  }
  .sys-grid div {
    background: rgba(255,252,247,.9);
    padding: .85rem 1rem;
  }
  .sys-grid label {
    display: block;
    font-size: .7rem;
    text-transform: uppercase;
    letter-spacing: .05em;
    color: var(--muted);
    margin-bottom: .25rem;
  }
  .sys-grid strong {
    font-family: var(--font-mono);
    font-size: .86rem;
    font-weight: 500;
    word-break: break-word;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: .88rem;
  }
  th, td {
    text-align: left;
    padding: .7rem .85rem;
    border-bottom: 1px solid var(--line);
    vertical-align: top;
  }
  th {
    font-size: .72rem;
    text-transform: uppercase;
    letter-spacing: .05em;
    color: var(--muted);
    font-weight: 600;
    background: rgba(20,32,26,.03);
  }
  tr:last-child td { border-bottom: 0; }
  .mono { font-family: var(--font-mono); font-size: .82rem; }
  .pill {
    display: inline-block;
    font-family: var(--font-mono);
    font-size: .68rem;
    padding: .15rem .45rem;
    border: 1px solid currentColor;
    letter-spacing: .03em;
  }
  .pill.CRIT { color: var(--crit); }
  .pill.WARN { color: var(--warn); }
  .pill.INFO { color: var(--info); }
  .pill.OK { color: var(--ok); }
  .pill.pub { color: var(--crit); }
  .pill.loc { color: var(--ok); }
  .findings li, .recs li {
    list-style: none;
    margin: 0;
    padding: .85rem 1rem;
    border-bottom: 1px solid var(--line);
    display: grid;
    grid-template-columns: 5.5rem 1fr;
    gap: .75rem;
    align-items: start;
  }
  .findings, .recs { margin: 0; padding: 0; }
  .findings li:last-child, .recs li:last-child { border-bottom: 0; }
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: .4rem;
    margin-bottom: .75rem;
  }
  .filters button {
    font-family: var(--font-sans);
    font-size: .8rem;
    border: 1px solid var(--line);
    background: transparent;
    color: var(--muted);
    padding: .35rem .7rem;
    cursor: pointer;
  }
  .filters button.active, .filters button:hover {
    background: var(--ink);
    color: #f4faf6;
    border-color: var(--ink);
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: .6rem;
    align-items: center;
    margin: 0 0 1.5rem;
  }
  .toolbar label, .toolbar a, .toolbar button {
    font-size: .82rem;
    border: 1px solid var(--line);
    background: var(--panel);
    color: var(--ink);
    padding: .45rem .8rem;
    cursor: pointer;
    text-decoration: none;
  }
  .toolbar input[type=file] { display: none; }
  .check {
    display: grid;
    gap: .55rem;
    padding: 1rem;
  }
  .check div {
    display: flex;
    gap: .65rem;
    align-items: flex-start;
    color: var(--muted);
    font-size: .92rem;
  }
  .check i {
    width: .7rem;
    height: .7rem;
    margin-top: .35rem;
    background: var(--accent-2);
    flex: none;
  }
  footer {
    margin-top: 2.5rem;
    padding-top: 1rem;
    border-top: 1px solid var(--line);
    font-size: .78rem;
    color: var(--muted);
    font-family: var(--font-mono);
  }
  .empty { padding: 1rem; color: var(--muted); }
  .bar {
    height: 6px;
    background: rgba(20,32,26,.1);
    margin-top: .75rem;
    overflow: hidden;
  }
  .bar > i {
    display: block;
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent-2));
  }
  .res-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: .75rem;
    margin-bottom: .75rem;
  }
  .res-card {
    background: var(--panel);
    border: 1px solid var(--line);
    padding: 1rem 1.05rem;
  }
  .res-card h3 {
    margin: 0 0 .55rem;
    font-size: .72rem;
    font-weight: 600;
    letter-spacing: .05em;
    text-transform: uppercase;
    color: var(--muted);
  }
  .res-card .big {
    font-family: var(--font-display);
    font-size: 1.65rem;
    font-weight: 700;
    line-height: 1.1;
    margin: 0 0 .35rem;
  }
  .res-card .sub {
    font-family: var(--font-mono);
    font-size: .78rem;
    color: var(--muted);
    line-height: 1.45;
  }
  .res-meter {
    height: 8px;
    background: rgba(20,32,26,.1);
    margin: .75rem 0 .35rem;
    overflow: hidden;
  }
  .res-meter > i {
    display: block;
    height: 100%;
    background: var(--accent-2);
  }
  .res-meter.warn > i { background: var(--warn); }
  .res-meter.crit > i { background: var(--crit); }
  .res-meter-label {
    display: flex;
    justify-content: space-between;
    font-size: .72rem;
    color: var(--muted);
    font-family: var(--font-mono);
  }
</style>
</head>
<body>
  <div class="wrap">
    <p class="brand">Infra Report</p>
    <p class="lede" id="lede">Auditoria de portas, firewall, SSH, HTTP/HTTPS, Docker e hardening.</p>
    <div class="meta" id="meta"></div>
    <div class="toolbar">
      <label>Carregar JSON<input type="file" id="file" accept="application/json,.json" /></label>
      <a id="dl-json" download="infra-report.json">Baixar JSON embutido</a>
      <button type="button" id="print">Imprimir / PDF</button>
    </div>
    <div class="score-row">
      <div class="score">
        <small>Score de postura</small>
        <strong id="score">—</strong>
        <div class="bar"><i id="score-bar" style="width:0%"></i></div>
      </div>
      <div class="stats" id="stats"></div>
    </div>

    <section>
      <h2>Sistema</h2>
      <p class="section-lede">Snapshot do host no momento da coleta.</p>
      <div class="sys-grid" id="system"></div>
    </section>

    <section>
      <h2>Recursos de hardware</h2>
      <p class="section-lede">CPU, memória, swap e discos — capacidade usada e disponível.</p>
      <div class="res-grid" id="resources"></div>
      <div class="panel" style="overflow:auto">
        <table>
          <thead>
            <tr>
              <th>Montagem</th>
              <th>Filesystem</th>
              <th>Total</th>
              <th>Usado</th>
              <th>Disponível</th>
              <th>Uso</th>
            </tr>
          </thead>
          <tbody id="disks"></tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Achados</h2>
      <p class="section-lede">Resultados classificados por severidade.</p>
      <div class="filters" id="find-filters"></div>
      <div class="panel"><ul class="findings" id="findings"></ul></div>
    </section>

    <section>
      <h2>Recomendações</h2>
      <p class="section-lede">Ações priorizadas a partir dos achados.</p>
      <div class="panel"><ul class="recs" id="recs"></ul></div>
    </section>

    <section>
      <h2>Portas em escuta</h2>
      <p class="section-lede">Listeners TCP detectados e exposição pública.</p>
      <div class="panel" style="overflow:auto">
        <table>
          <thead><tr><th>Porta</th><th>Bind</th><th>Processo</th><th>Exposição</th></tr></thead>
          <tbody id="ports"></tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>SSH &amp; Firewall</h2>
      <p class="section-lede">Controle de acesso ao host.</p>
      <div class="sys-grid" id="access"></div>
    </section>

    <section>
      <h2>HTTP / HTTPS / TLS</h2>
      <p class="section-lede">Probes locais e certificados.</p>
      <div class="panel" style="overflow:auto; margin-bottom: .75rem">
        <table>
          <thead><tr><th>URL</th><th>Status</th><th>Server</th><th>Headers OK</th><th>Ausentes</th></tr></thead>
          <tbody id="http"></tbody>
        </table>
      </div>
      <div class="panel" style="overflow:auto">
        <table>
          <thead><tr><th>Host</th><th>Porta</th><th>Protocolo</th><th>Validade</th><th>Dias</th></tr></thead>
          <tbody id="tls"></tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Docker</h2>
      <p class="section-lede">Containers e superfície de exposição.</p>
      <div class="sys-grid" id="docker-meta" style="margin-bottom:.75rem"></div>
      <div class="panel" style="overflow:auto">
        <table>
          <thead><tr><th>Nome</th><th>Status</th><th>Portas</th></tr></thead>
          <tbody id="docker"></tbody>
        </table>
      </div>
    </section>

    <section>
      <h2>Checklist</h2>
      <p class="section-lede">Baseline contínuo de segurança.</p>
      <div class="panel check" id="checklist"></div>
    </section>

    <footer id="footer"></footer>
  </div>
<script id="report-data" type="application/json">__REPORT_JSON__</script>
<script>
(function () {
  const $ = (id) => document.getElementById(id);
  let report = null;
  let findFilter = "ALL";

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) => ({
      "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
    }[c]));
  }

  function levelLabel(l) {
    return ({CRIT:"CRÍTICO", WARN:"AVISO", INFO:"INFO", OK:"OK"})[l] || l;
  }

  function cell(label, value) {
    return `<div><label>${esc(label)}</label><strong>${esc(value || "—")}</strong></div>`;
  }

  function meterClass(pct) {
    const p = Number(pct) || 0;
    if (p >= 90) return "crit";
    if (p >= 80) return "warn";
    return "";
  }

  function resourceCard(title, percent, primary, lines) {
    const p = Math.max(0, Math.min(100, Number(percent) || 0));
    return `<div class="res-card">
      <h3>${esc(title)}</h3>
      <div class="big">${esc(primary)}</div>
      <div class="res-meter ${meterClass(p)}"><i style="width:${p}%"></i></div>
      <div class="res-meter-label"><span>usado</span><span>${esc(p)}%</span></div>
      <div class="sub" style="margin-top:.55rem">${lines.map(esc).join("<br>")}</div>
    </div>`;
  }

  function renderFindings() {
    const list = report.findings || [];
    const filtered = findFilter === "ALL" ? list : list.filter((f) => f.level === findFilter);
    const root = $("findings");
    if (!filtered.length) {
      root.innerHTML = `<li class="empty" style="display:block">Nenhum achado neste filtro.</li>`;
      return;
    }
    root.innerHTML = filtered.map((f) => `
      <li>
        <span class="pill ${esc(f.level)}">${esc(levelLabel(f.level))}</span>
        <div>
          <div>${esc(f.message)}</div>
          ${f.recommendation ? `<div style="margin-top:.35rem;color:var(--muted);font-size:.86rem">${esc(f.recommendation)}</div>` : ""}
          ${f.section ? `<div class="mono" style="margin-top:.3rem;color:var(--muted);font-size:.72rem">${esc(f.section)}</div>` : ""}
        </div>
      </li>`).join("");
  }

  function render(data) {
    report = data;
    const sys = data.system || {};
    const sum = data.summary || {};
    const score = Number(sum.score ?? 0);

    $("lede").textContent = `Auditoria de ${sys.hostname || data.host || "host"} — portas, firewall, SSH, HTTP/HTTPS, Docker e hardening.`;
    $("meta").innerHTML = [
      `host ${sys.hostname || data.host || "—"}`,
      `gerado ${sys.generated_at || data.generated_at || "—"}`,
      `tool ${data.tool || "infra-report.sh"} v${data.version || "?"}`,
      data.host_target ? `probe ${data.host_target}` : null
    ].filter(Boolean).map((t) => `<span>${esc(t)}</span>`).join("");

    $("score").textContent = String(score);
    $("score-bar").style.width = Math.max(0, Math.min(100, score)) + "%";

    $("stats").innerHTML = [
      ["crit", "Críticos", sum.critical],
      ["warn", "Avisos", sum.warn],
      ["info", "Infos", sum.info],
      ["ok", "OK", sum.ok],
    ].map(([cls, label, n]) => `<div class="stat ${cls}"><b>${esc(n ?? 0)}</b><span>${label}</span></div>`).join("");

    const res = sys.resources || {};

    $("system").innerHTML = [
      cell("Hostname", sys.hostname),
      cell("SO", sys.os),
      cell("Kernel", sys.kernel),
      cell("Uptime", sys.uptime),
      cell("CPU", res.cpu ? `${res.cpu.logical_cpus || "—"} vCPU` : "—"),
      cell("Modelo CPU", res.cpu && res.cpu.model),
      cell("Load (1/5/15)", sys.load),
      cell("Coletado (UTC)", sys.generated_at),
    ].join("");

    const mem = res.memory || {};
    const swap = res.swap || {};
    const cpu = res.cpu || {};
    const rootDisk = res.disk_root || {};
    const loadPct = cpu.logical_cpus
      ? Math.min(100, Math.round(100 * (Number(cpu.loadavg && cpu.loadavg["1m"]) || 0) / Number(cpu.logical_cpus)))
      : 0;

    $("resources").innerHTML = [
      resourceCard(
        "CPU / Load",
        loadPct,
        `${cpu.logical_cpus || "—"} vCPU`,
        [
          `load 1m/5m/15m: ${(cpu.loadavg && cpu.loadavg["1m"]) ?? "—"} / ${(cpu.loadavg && cpu.loadavg["5m"]) ?? "—"} / ${(cpu.loadavg && cpu.loadavg["15m"]) ?? "—"}`,
          `load por vCPU (1m): ${cpu.load_per_cpu_1m ?? "—"}`,
          cpu.model || "modelo n/a",
        ]
      ),
      resourceCard(
        "Memória RAM",
        mem.used_percent,
        `${mem.used_percent ?? "—"}%`,
        [
          `usado: ${mem.used_human || "—"}`,
          `disponível: ${mem.available_human || "—"}`,
          `capacidade: ${mem.total_human || "—"}`,
        ]
      ),
      resourceCard(
        "Swap",
        swap.used_percent,
        swap.total_bytes ? `${swap.used_percent ?? 0}%` : "sem swap",
        [
          `usado: ${swap.used_human || "—"}`,
          `disponível: ${swap.available_human || "—"}`,
          `capacidade: ${swap.total_human || "—"}`,
        ]
      ),
      resourceCard(
        "Disco /",
        rootDisk.used_percent,
        `${rootDisk.used_percent ?? "—"}%`,
        [
          `usado: ${rootDisk.used_human || "—"}`,
          `disponível: ${rootDisk.available_human || "—"}`,
          `capacidade: ${rootDisk.total_human || "—"}`,
        ]
      ),
    ].join("");

    const disks = res.disks || [];
    $("disks").innerHTML = disks.length
      ? disks.map((d) => {
          const p = Number(d.used_percent) || 0;
          return `<tr>
            <td class="mono">${esc(d.mount)}</td>
            <td class="mono">${esc(d.filesystem)}</td>
            <td class="mono">${esc(d.total_human)}</td>
            <td class="mono">${esc(d.used_human)}</td>
            <td class="mono">${esc(d.available_human)}</td>
            <td>
              <div class="res-meter ${meterClass(p)}" style="margin:.15rem 0 .2rem;min-width:7rem"><i style="width:${Math.min(100,p)}%"></i></div>
              <span class="mono">${esc(p)}%</span>
            </td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="6" class="empty">Sem dados de disco.</td></tr>`;

    const levels = ["ALL", "CRIT", "WARN", "INFO", "OK"];
    $("find-filters").innerHTML = levels.map((l) =>
      `<button type="button" data-level="${l}" class="${findFilter===l?"active":""}">${l==="ALL"?"Todos":levelLabel(l)}</button>`
    ).join("");
    $("find-filters").onclick = (e) => {
      const btn = e.target.closest("button[data-level]");
      if (!btn) return;
      findFilter = btn.dataset.level;
      renderFindings();
      [...$("find-filters").querySelectorAll("button")].forEach((b) =>
        b.classList.toggle("active", b.dataset.level === findFilter));
    };
    renderFindings();

    const recs = data.recommendations || [];
    $("recs").innerHTML = recs.length
      ? recs.map((r) => `<li><span class="pill ${esc(r.level)}">${esc(levelLabel(r.level))}</span><div>${esc(r.text)}</div></li>`).join("")
      : `<li class="empty" style="display:block">Sem recomendações.</li>`;

    const ports = data.ports || [];
    $("ports").innerHTML = ports.length
      ? ports.map((p) => `<tr>
          <td class="mono">${esc(p.port)}</td>
          <td class="mono">${esc(p.address)}</td>
          <td class="mono">${esc(p.process || "—")}</td>
          <td><span class="pill ${p.public ? "pub" : "loc"}">${p.public ? "PÚBLICA" : "LOCAL"}</span></td>
        </tr>`).join("")
      : `<tr><td colspan="4" class="empty">Sem dados de portas.</td></tr>`;

    const fw = data.firewall || {};
    const ssh = data.ssh || {};
    const hard = data.hardening || {};
    $("access").innerHTML = [
      cell("UFW", fw.ufw),
      cell("Firewall ativo", fw.active ? "sim" : "não"),
      cell("iptables INPUT", fw.iptables_input_rules),
      cell("SSH port", ssh.port),
      cell("PermitRootLogin", ssh.permit_root_login),
      cell("PasswordAuth", ssh.password_authentication),
      cell("PubkeyAuth", ssh.pubkey_authentication),
      cell("fail2ban SSH", ssh.fail2ban_ssh ? "sim" : "não"),
      cell("Apt upgradable", hard.apt_upgradable),
      cell("unattended-upgrades", hard.unattended_upgrades ? "sim" : "não"),
    ].join("");

    const http = data.http || [];
    $("http").innerHTML = http.length
      ? http.map((h) => `<tr>
          <td class="mono">${esc(h.url)}</td>
          <td class="mono">${esc(h.ok === false ? "sem resposta" : h.status)}</td>
          <td class="mono">${esc(h.server || "—")}</td>
          <td class="mono">${esc((h.headers_present||[]).length)}</td>
          <td class="mono">${esc((h.headers_missing||[]).join(", ") || "—")}</td>
        </tr>`).join("")
      : `<tr><td colspan="5" class="empty">Sem probes HTTP.</td></tr>`;

    const tls = data.tls || [];
    $("tls").innerHTML = tls.length
      ? tls.map((t) => `<tr>
          <td class="mono">${esc(t.host)}</td>
          <td class="mono">${esc(t.port)}</td>
          <td class="mono">${esc(t.ok === false ? "falhou" : (t.protocol || "—"))}</td>
          <td class="mono">${esc(t.not_after || "—")}</td>
          <td class="mono">${esc(t.days_remaining ?? "—")}</td>
        </tr>`).join("")
      : `<tr><td colspan="5" class="empty">Sem probes TLS.</td></tr>`;

    const dock = data.docker || {};
    $("docker-meta").innerHTML = [
      cell("Disponível", dock.available ? "sim" : "não"),
      cell("Daemon", dock.daemon ? "ok" : "n/a"),
      cell("Rodando", dock.running),
      cell("Imagens", dock.images),
      cell("Privileged", (dock.privileged || []).join(" ") || "nenhum"),
    ].join("");
    const containers = dock.containers || [];
    $("docker").innerHTML = containers.length
      ? containers.map((c) => `<tr>
          <td class="mono">${esc(c.name)}</td>
          <td>${esc(c.status)}</td>
          <td class="mono">${esc(c.ports || "—")}</td>
        </tr>`).join("")
      : `<tr><td colspan="3" class="empty">Sem containers.</td></tr>`;

    $("checklist").innerHTML = (data.checklist || []).map((c) =>
      `<div><i></i><span>${esc(c)}</span></div>`).join("");

    $("footer").textContent = `${data.tool || "infra-report.sh"} v${data.version || ""} · gerado para visualização local`;

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    $("dl-json").href = URL.createObjectURL(blob);
  }

  try {
    const embedded = JSON.parse($("report-data").textContent);
    render(embedded);
  } catch (e) {
    $("lede").textContent = "Não foi possível ler o JSON embutido. Carregue um arquivo infra-report.json.";
  }

  $("file").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    try {
      const text = await file.text();
      render(JSON.parse(text));
    } catch (err) {
      alert("JSON inválido: " + err.message);
    }
  });

  $("print").addEventListener("click", () => window.print());
})();
</script>
</body>
</html>
"""


def render_html(report: dict) -> str:
    host = report.get("host") or report.get("system", {}).get("hostname") or "host"
    payload = json.dumps(report, ensure_ascii=False)
    # Evita quebrar o script embutido
    payload = payload.replace("</", "<\\/")
    return (
        HTML_TEMPLATE.replace("__HOST__", host)
        .replace("__REPORT_JSON__", payload)
    )


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--tmp", required=True)
    p.add_argument("--json-out", required=True)
    p.add_argument("--html-out", required=True)
    p.add_argument("--version", default="1.1.0")
    p.add_argument("--crit", default="0")
    p.add_argument("--warn", default="0")
    p.add_argument("--info", default="0")
    p.add_argument("--ok", default="0")
    p.add_argument("--host-target", default="")
    args = p.parse_args()

    report = build_report(args)
    json_path = Path(args.json_out)
    html_path = Path(args.html_out)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")


if __name__ == "__main__":
    main()
