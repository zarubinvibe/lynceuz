#!/usr/bin/env bash
# Снять ОДИН кадр Пантеона через встроенный image_gen Кодекса.
#
# Один кадр за вызов — не пожелание, а измеренный факт: просьба сгенерировать
# несколько изображений одним заданием зависает без вывода (проверено трижды:
# 24, 34 и 20 минут впустую). Один кадр идет 3-4 минуты.
#
#   scripts/snyat_kadr.sh <файл-промпта> <выходной-png> [референс ...]
#
# Якоря канона (стиль + колонна) подставляются сами и идут первыми. Обертка
# ждет появления файла и проверяет, что это настоящий PNG непустого размера:
# отчет модели «готово» без файла на диске — не результат.
set -euo pipefail

DOM="$(cd "$(dirname "$0")/.." && pwd)"
SKILL="${PANTHEON_SKILL_DIR:-$HOME/.agents/skills/public-repo-release-gate}"
YAKOR_STIL="$SKILL/assets/pantheon-style-anchor.png"
YAKOR_KOLONNA="$SKILL/assets/pantheon-column.png"

if [ "$#" -lt 2 ]; then
  echo "использование: $0 <файл-промпта> <выходной-png> [референс ...]" >&2
  exit 2
fi

PROMPT_FILE="$1"; shift
VYHOD="$1"; shift

[ -f "$PROMPT_FILE" ] || { echo "нет файла промпта: $PROMPT_FILE" >&2; exit 2; }
for f in "$YAKOR_STIL" "$YAKOR_KOLONNA"; do
  [ -f "$f" ] || { echo "нет якоря канона: $f" >&2; exit 2; }
done

VYHOD_ABS="$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$VYHOD")"
mkdir -p "$(dirname "$VYHOD_ABS")"
rm -f "$VYHOD_ABS"

REFS=("$YAKOR_STIL" "$YAKOR_KOLONNA")
for r in "$@"; do
  [ -f "$r" ] || { echo "нет референса: $r" >&2; exit 2; }
  REFS+=("$(python3 -c 'import os,sys;print(os.path.abspath(sys.argv[1]))' "$r")")
done

SPISOK=""
i=1
for r in "${REFS[@]}"; do
  SPISOK="${SPISOK}Image ${i}: ${r}"$'\n'
  i=$((i + 1))
done

ZADANIE="$(cat <<EOF
Call the image_gen tool exactly once. Pass these files as referenced_image_paths, in this order:
${SPISOK}
Save the generated image to this exact absolute path, creating no other files:
${VYHOD_ABS}

Use the prompt below verbatim as the image prompt. Do not summarize it, do not rewrite it, do not add to it. Do not write any code, do not run any other tool, do not explain. When the file exists, answer with the single word DONE.

--- PROMPT ---
$(cat "$PROMPT_FILE")
EOF
)"

echo "снимаю кадр: $(basename "$VYHOD_ABS")  (референсов: ${#REFS[@]})"
NACHALO="$(date +%s)"
codex exec \
  --cd "$DOM" \
  --sandbox danger-full-access \
  --skip-git-repo-check \
  "$ZADANIE" >"${VYHOD_ABS}.log" 2>&1 || true
KONETS="$(date +%s)"

# Дважды кадр «готов» по отчету модели, а файла на месте нет: инструмент сохранил
# его мимо пути и отчитался словом DONE. Слово не проверяется, файл проверяется.
# Поэтому перед отказом ищем PNG, появившийся за время прогона в очевидных местах.
if [ ! -s "$VYHOD_ABS" ]; then
  MARKER="$(mktemp "${TMPDIR:-/tmp}/kadr-marker.XXXXXX")"
  touch -t "$(date -r "$NACHALO" +%Y%m%d%H%M.%S)" "$MARKER" 2>/dev/null || true
  # `|| true` тут обязателен: find возвращает ненулевой код, если хоть одного из
  # каталогов нет, и под set -e обертка умирала молча вместо честного отказа.
  NAYDEN="$(find "$DOM" "${TMPDIR:-/tmp}" "$HOME/Downloads" -maxdepth 4 -name '*.png' \
    -newer "$MARKER" -not -path '*/.git/*' 2>/dev/null | head -2 || true)"
  rm -f "$MARKER"
  if [ "$(printf '%s\n' "$NAYDEN" | grep -c .)" = "1" ]; then
    echo "кадр нашелся мимо пути, переношу: $NAYDEN"
    mv "$NAYDEN" "$VYHOD_ABS"
  fi
fi

if [ ! -s "$VYHOD_ABS" ]; then
  echo "ОТКАЗ: файл не появился за $((KONETS - NACHALO)) с — $VYHOD_ABS" >&2
  tail -20 "${VYHOD_ABS}.log" >&2 || true
  exit 1
fi
if ! python3 - "$VYHOD_ABS" <<'PY'
import struct, sys
p = sys.argv[1]
with open(p, 'rb') as f:
    head = f.read(24)
if head[:8] != b'\x89PNG\r\n\x1a\n':
    sys.exit('не PNG')
w, h = struct.unpack('>II', head[16:24])
if w < 512 or h < 512:
    sys.exit(f'слишком мелкий кадр {w}x{h}')
print(f'{w}x{h}')
PY
then
  echo "ОТКАЗ: выход не прошел проверку PNG — $VYHOD_ABS" >&2
  exit 1
fi
echo "готов за $((KONETS - NACHALO)) с: $VYHOD_ABS"
