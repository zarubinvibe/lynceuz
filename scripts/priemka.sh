#!/usr/bin/env bash
# Приемка дома: собрать витрину из данных, свести ссылки семьи и прогнать весь
# набор проверок. Одной командой, потому что порядок тут значим: страницы
# собираются ДО сведения ссылок, ссылки ДО ворот, ворота ДО пуша.
set -uo pipefail

DOM="$(cd "$(dirname "$0")/.." && pwd)"
cd "$DOM"
# Ворота ищутся, а не задаются: в эталонном доме они лежат в дереве, в остальных
# домах семьи - только в установленной копии. Прибитый путь делал прибор рабочим
# ровно в одном репозитории и молча ломал его во всех прочих.
VOROTA=""
for kandidat in \
  "skills/public-repo-release-gate/scripts/public-repo-gate.mjs" \
  "$HOME/.agents/skills/public-repo-release-gate/scripts/public-repo-gate.mjs" \
  "$HOME/.claude/skills/public-repo-release-gate/scripts/public-repo-gate.mjs"; do
  if [ -f "$kandidat" ]; then VOROTA="$kandidat"; break; fi
done
if [ -z "$VOROTA" ]; then
  echo "ворота не найдены: ни в дереве, ни в ~/.agents, ни в ~/.claude" >&2
  exit 2
fi
echo "ворота: $VOROTA"
otkazy=0

shag() {
  echo
  echo "== $1"
  shift
  "$@" || { echo "ОТКАЗ на шаге выше" >&2; otkazy=$((otkazy + 1)); }
}

shag "витрина из .github/family-page.json" node "$VOROTA" build-readme --repo .
shag "ссылки семьи" node "$VOROTA" sync-pantheon-links --repo .
shag "селфтест ворот" node "$VOROTA" selftest
shag "ворота по этому дому" node "$VOROTA" check --repo .
shag "отслеживание сессий" entire-tracking-gate

echo
if [ "$otkazy" -gt 0 ]; then
  echo "ПРИЕМКА КРАСНАЯ: отказов $otkazy" >&2
  exit 1
fi
echo "ПРИЕМКА ЗЕЛЕНАЯ"
