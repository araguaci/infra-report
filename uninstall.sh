#!/usr/bin/env bash
# ============================================================================
# uninstall.sh — remove infra-report de PREFIX (padrão: /usr/local)
# Uso:
#   sudo bash uninstall.sh
#   PREFIX=/opt sudo bash uninstall.sh
# ============================================================================
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
LIBDIR="${PREFIX}/lib/infra-report"
BINDIR="${PREFIX}/bin"
MANDIR="${PREFIX}/share/man/man1"

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      cat <<EOF
Uso: sudo bash uninstall.sh
  PREFIX=/usr/local  (override via env)

Remove:
  ${BINDIR}/infra-report
  ${LIBDIR}/
  ${MANDIR}/infra-report.1
EOF
      exit 0
      ;;
    *)
      echo "Opção desconhecida: $arg (use --help)" >&2
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Execute como root (sudo)." >&2
  exit 1
fi

removed=0
if [[ -e "${BINDIR}/infra-report" || -L "${BINDIR}/infra-report" ]]; then
  rm -f "${BINDIR}/infra-report"
  echo "Removido: ${BINDIR}/infra-report"
  removed=1
fi
if [[ -e "${MANDIR}/infra-report.1" ]]; then
  rm -f "${MANDIR}/infra-report.1"
  echo "Removido: ${MANDIR}/infra-report.1"
  removed=1
fi
if [[ -d "$LIBDIR" ]]; then
  rm -rf "$LIBDIR"
  echo "Removido: ${LIBDIR}/"
  removed=1
fi

if [[ $removed -eq 0 ]]; then
  echo "Nada instalado em ${PREFIX} (já removido?)."
else
  echo "Desinstalação concluída (${PREFIX})."
fi
