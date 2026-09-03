#!/usr/bin/env bash
# Снять серию кадров ПО ОДНОМУ, подряд. Драйвер поверх snyat_kadr.sh.
#
#   scripts/snyat_seriyu.sh <имя> [<имя> ...]
#
# Для каждого имени берется .github/pantheon/<имя>-prompt.txt и снимается
# docs/assets/pantheon/<имя>.png. В референсы, кроме двух якорей канона, идут
# оба листа свода: без них каждая сцена придумывает фигуру и предметы заново.
# Уже снятый кадр пропускается, чтобы повтор прогона не стоил еще получаса.
set -uo pipefail

DOM="$(cd "$(dirname "$0")/.." && pwd)"
SVOD_LICO="$DOM/docs/assets/pantheon/bible-character.png"
SVOD_REKVIZIT="$DOM/docs/assets/pantheon/bible-props.png"

for f in "$SVOD_LICO" "$SVOD_REKVIZIT"; do
  [ -f "$f" ] || { echo "свод не снят: $f" >&2; exit 2; }
done

otkazy=0
for imya in "$@"; do
  vyhod="$DOM/docs/assets/pantheon/$imya.png"
  if [ -s "$vyhod" ]; then
    echo "пропуск, кадр уже есть: $imya"
    continue
  fi
  "$DOM/scripts/snyat_kadr.sh" \
    "$DOM/.github/pantheon/$imya-prompt.txt" \
    "$vyhod" \
    "$SVOD_LICO" "$SVOD_REKVIZIT" || otkazy=$((otkazy + 1))
done

if [ "$otkazy" -gt 0 ]; then
  echo "серия закончена с отказами: $otkazy" >&2
  exit 1
fi
echo "серия снята целиком"
