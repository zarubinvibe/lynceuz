#!/usr/bin/env bash
# Установка Линкея: проверить среду, доказать, что инструмент работает, и положить
# навыки туда, где их найдет агент. Ни одной внешней зависимости - только Node.
#
#   bash install.sh            # спрашивает перед каждым шагом
#   bash install.sh --yes      # без вопросов
#   bash install.sh --dry-run  # только показать, что будет сделано
set -euo pipefail

DOM="$(cd "$(dirname "$0")" && pwd)"
BEZ_VOPROSOV=0
TOLKO_POKAZAT=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y) BEZ_VOPROSOV=1 ;;
    --dry-run|-n) TOLKO_POKAZAT=1 ;;
    *) echo "неизвестный ключ: $arg" >&2; exit 2 ;;
  esac
done

# Нет терминала - значит ставит машина: чужой компьютер, CI, изолированный прогон.
# Спрашивать некому, а пропускать шаги нельзя: установщик, который в такой среде
# тихо ничего не делает и выходит нулем, доказывает не установку, а вежливость.
if [ ! -t 0 ]; then
  BEZ_VOPROSOV=1
  echo "терминала нет: ставлю без вопросов"
fi

sprosit() {
  [ "$BEZ_VOPROSOV" -eq 1 ] && return 0
  printf '%s [y/N] ' "$1"
  read -r otvet </dev/tty || return 1
  case "$otvet" in y|Y|yes|Yes) return 0 ;; *) return 1 ;; esac
}

command -v node >/dev/null 2>&1 || { echo "нужен node 20 или новее" >&2; exit 1; }
VERSIYA="$(node -p 'process.versions.node.split(".")[0]')"
if [ "$VERSIYA" -lt 20 ]; then
  echo "нужен node 20 или новее, у вас $VERSIYA" >&2
  exit 1
fi
echo "node $VERSIYA: годится"

echo "== инструмент проверяет сам себя"
if [ "$TOLKO_POKAZAT" -eq 1 ]; then
  echo "запустил бы: node scripts/onboard.mjs --selftest"
else
  node "$DOM/scripts/onboard.mjs" --selftest
fi

echo "== навыки в дома агентов"
for imya in lynceuz-setup lynceuz-update; do
  istochnik="$DOM/.claude/skills/$imya"
  [ -d "$istochnik" ] || continue
  for dom_agenta in "$HOME/.claude/skills" "$HOME/.codex/skills"; do
    cel="$dom_agenta/$imya"
    if [ "$TOLKO_POKAZAT" -eq 1 ]; then
      echo "поставил бы $imya в $cel"
      continue
    fi
    if ! sprosit "поставить $imya в $cel?"; then
      echo "пропущено: $cel"
      continue
    fi
    mkdir -p "$cel"
    cp -R "$istochnik/." "$cel/"
    echo "готово: $cel"
  done
done

echo
echo "Первый запуск:"
echo "  node $DOM/src/lynceuz.mjs url 'https://example.org/' --json"
echo
echo "Путь через браузер систему МЕНЯЕТ и ставится отдельно, вашими руками:"
echo "  см. SECURITY.ru.md, раздел «Путь через браузер»"
