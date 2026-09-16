#!/usr/bin/env bash
# ============================================================================
# install.sh — instala / remove infra-report em PREFIX (padrão: /usr/local)
# Uso:
#   sudo bash install.sh
#   sudo bash install.sh --uninstall
#   PREFIX=/opt sudo bash install.sh
# ============================================================================
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
LIBDIR="${PREFIX}/lib/infra-report"
BINDIR="${PREFIX}/bin"
MANDIR="${PREFIX}/share/man/man1"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ACTION="install"
for arg in "$@"; do
  case "$arg" in
    --uninstall|-u) ACTION="uninstall" ;;
    -h|--help)
      cat <<EOF
Uso: sudo bash install.sh [--uninstall]
  PREFIX=/usr/local  (override via env)
Instala em:
  ${LIBDIR}/infra-report.sh
  ${LIBDIR}/infra_report_render.py
  ${BINDIR}/infra-report  (symlink)
  ${MANDIR}/infra-report.1
EOF
      exit 0
      ;;
  esac
done

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Execute como root (sudo)." >&2
    exit 1
  fi
}

do_install() {
  need_root
  [[ -f "${SRC_DIR}/infra-report.sh" ]] || { echo "Falta infra-report.sh em ${SRC_DIR}" >&2; exit 1; }
  [[ -f "${SRC_DIR}/infra_report_render.py" ]] || { echo "Falta infra_report_render.py em ${SRC_DIR}" >&2; exit 1; }
  [[ -f "${SRC_DIR}/man/infra-report.1" ]] || { echo "Falta man/infra-report.1 em ${SRC_DIR}" >&2; exit 1; }

  mkdir -p "$LIBDIR" "$BINDIR" "$MANDIR"
  install -m 0755 "${SRC_DIR}/infra-report.sh" "${LIBDIR}/infra-report.sh"
  install -m 0644 "${SRC_DIR}/infra_report_render.py" "${LIBDIR}/infra_report_render.py"
  install -m 0644 "${SRC_DIR}/man/infra-report.1" "${MANDIR}/infra-report.1"
  ln -sfn "../lib/infra-report/infra-report.sh" "${BINDIR}/infra-report"

  echo "Instalado:"
  echo "  ${BINDIR}/infra-report"
  echo "  ${LIBDIR}/"
  echo "  ${MANDIR}/infra-report.1"
  echo ""
  echo "Uso: sudo infra-report --json /tmp/infra-report.json"
  echo "Man:  man infra-report"
}

do_uninstall() {
  need_root
  rm -f "${BINDIR}/infra-report"
  rm -f "${MANDIR}/infra-report.1"
  rm -rf "$LIBDIR"
  echo "Removido de ${PREFIX}"
}

case "$ACTION" in
  install) do_install ;;
  uninstall) do_uninstall ;;
esac
