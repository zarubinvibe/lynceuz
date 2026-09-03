#!/usr/bin/env python3
"""Высечь подписи на плитах кадра такта.

Подписи ставит ПРИБОР, а не модель: модель на схеме пишет выдуманные буквы, и
поймать это можно только глазами, каждый раз заново. Отсюда порядок: кадр
рождается с пустыми плитами (в промпте `No readable text`), а текст приходит
отсюда, детерминированно и одинаково на всех языках.

Резьба, а не печать. Буква имеет ЦВЕТ КАМНЯ: она видна тенью в верхней кромке
реза и бликом в нижней. Серая или черная заливка читается как наклейка поверх
камня и в семействе запрещена.

    scripts/podpisi_takta.py ru en zh

Геометрия плит снимается один раз и лежит в .github/pantheon/takt-plity.json.
"""
import json
import os
import sys

import numpy
from PIL import Image, ImageDraw, ImageFont

DOM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISTOCHNIK = os.path.join(DOM, "docs/assets/pantheon/takt.png")
PLITY = os.path.join(DOM, ".github/pantheon/takt-plity.json")
MANIFEST = os.path.join(DOM, ".github/pantheon.json")
VYHOD = os.path.join(DOM, "docs/assets/pantheon/takt-{}.png")

# Инскрипционная капитель уровня Cinzel, лицензия OFL. Cormorant несет латиницу и
# кириллицу в одном строю; китайский добирается системным серифом того же веса.
# Шрифт в репозиторий не кладется: чужая лицензия в MIT-доме дороже, чем строка
# в CONTRIBUTING о том, где его взять.
SHRIFT_LATINICA = [
    os.path.expanduser("~/Library/Fonts/Cormorant-Variable.ttf"),
    "/Library/Fonts/Cormorant-Variable.ttf",
]
SHRIFT_CJK = ["/System/Library/Fonts/Supplemental/Songti.ttc"]

TREKING = 0.20   # разрядка в долях кегля: римская капитель стоит широко
DOLYA_SHIRINY = 0.86   # какую часть плиты занимает строка письма


def nayti(puti):
    for put in puti:
        if os.path.exists(put):
            return put
    raise SystemExit(
        "не найден шрифт резьбы: " + " | ".join(puti) +
        "\nпоставьте Cormorant (OFL): см. CONTRIBUTING.md"
    )


def shrift(yazyk, kegl):
    if yazyk == "zh":
        return ImageFont.truetype(nayti(SHRIFT_CJK), kegl, index=0)
    f = ImageFont.truetype(nayti(SHRIFT_LATINICA), kegl)
    try:
        f.set_variation_by_axes([700])
    except Exception:
        pass
    return f


def shirina_stroki(text, f, treking):
    if not text:
        return 0
    shirina = sum(f.getlength(ch) for ch in text)
    return shirina + treking * (len(text) - 1)


def napisat(sloy, x, y, text, f, treking):
    d = ImageDraw.Draw(sloy)
    for ch in text:
        d.text((x, y), ch, font=f, fill=255)
        x += f.getlength(ch) + treking


def sdvig(mask, dx, dy):
    novy = Image.new("L", mask.size, 0)
    novy.paste(mask, (dx, dy))
    return novy


def kamen(im, ramka):
    """Средний цвет камня плиты: буква режется в НЕМ, а не в сером."""
    x, y, w, h = ramka
    kusok = im.crop((x + w // 6, y + h // 3, x + w - w // 6, y + 2 * h // 3))
    px = list(kusok.getdata())
    n = len(px)
    return tuple(sum(p[i] for p in px) // n for i in range(3))


def kromka(maska, dy):
    """Кромка реза: то, что остается от буквы после сдвига копии по вертикали."""
    a = numpy.asarray(maska, dtype=int)
    b = numpy.asarray(sdvig(maska, 0, dy), dtype=int)
    return Image.fromarray(numpy.clip(a - b, 0, 255).astype("uint8"))


def vysech(im, ramka, text, f, treking):
    """Высечь одну строку в камне: тень в верхней кромке реза, блик в нижней."""
    x, y, w, h = ramka
    tsvet = kamen(im, ramka)
    shirina = shirina_stroki(text, f, treking)
    verh, niz = f.getbbox("Hg")[1], f.getbbox("Hg")[3]
    vysota = niz - verh
    px = int(x + (w - shirina) / 2)
    py = int(y + (h - vysota) / 2 - verh)

    maska = Image.new("L", im.size, 0)
    napisat(maska, px, py, text, f, treking)

    dno = tuple(max(0, int(c * 0.90)) for c in tsvet)
    ten = tuple(max(0, int(c * 0.52)) for c in tsvet)
    blik = tuple(min(255, int(c * 1.16)) for c in tsvet)

    im.paste(Image.new("RGB", im.size, dno), (0, 0), Image.eval(maska, lambda v: int(v * 0.55)))
    im.paste(Image.new("RGB", im.size, blik), (0, 0), Image.eval(kromka(maska, -2), lambda v: int(v * 0.95)))
    im.paste(Image.new("RGB", im.size, ten), (0, 0), Image.eval(kromka(maska, 2), lambda v: int(v)))


def kegl_dlya(yazyk, podpisi, ramki):
    """Один кегль на все плиты: разный размер букв в ряду читается как ошибка."""
    kegl = 8
    while kegl < 200:
        f = shrift(yazyk, kegl + 1)
        tr = (kegl + 1) * TREKING
        if any(shirina_stroki(t, f, tr) > r[2] * DOLYA_SHIRINY
               for t, r in zip(podpisi, ramki)):
            break
        kegl += 1
    return kegl


def izmerit(polosy):
    """Снять геометрию плит проекцией краев внутри названных рядов.

    Ряды называет человек ОДИН раз, посмотрев на кадр: `--izmerit 230:390 480:650`.
    Дальше все механическое: вертикальные края внутри полосы дают границы плит,
    лицо плиты берется с отступом от карниза сверху и от базы снизу. Результат
    ложится в takt-plity.json и в кадр наложения, который проверяется глазами -
    прибор, чью разметку никто не видел, врет тихо.
    """
    a = numpy.asarray(Image.open(ISTOCHNIK).convert("L"), dtype=float)
    ramki = []
    for polosa in polosy:
        y0, y1 = (int(v) for v in polosa.split(":"))
        band = a[y0:y1, :].mean(axis=0)
        d = numpy.abs(numpy.diff(band))
        idx = numpy.where(d > d.max() * 0.18)[0]
        gruppy = []
        for i in idx:
            if gruppy and i - gruppy[-1][-1] <= 4:
                gruppy[-1].append(i)
            else:
                gruppy.append([i])
        kraya = [int(numpy.mean(g)) for g in gruppy]
        # Четность пар угадывать нельзя: на одном ряду первым краем оказывается
        # начало плиты, на соседнем - начало промежутка, и разметка садится на
        # пустоту. Плита ТЕМНЕЕ слоновой кости, поэтому промежуток от плиты
        # отличается замером яркости, а не порядковым номером края.
        intervaly = [(kraya[i], kraya[i + 1]) for i in range(len(kraya) - 1)]
        if not intervaly:
            continue
        porog = (band.max() + numpy.median(band)) / 2
        pary = [(a_, b) for a_, b in intervaly
                if b - a_ > 10 and band[a_ + 3:b - 3].mean() < porog]
        # Плиты ряда ОДИНАКОВЫ по ширине - это их определение. Медиана тут не
        # помогает: мелкие засечки и тени забивают середину списка. Берется самая
        # многочисленная группа одинаковых ширин, при равенстве - более широкая.
        if not pary:
            continue
        gruppy_shirin = []
        for x0, x1 in sorted(pary, key=lambda t: t[1] - t[0], reverse=True):
            sh = x1 - x0
            for g in gruppy_shirin:
                if abs(sh - g[0]) <= g[0] * 0.10:
                    g[1].append((x0, x1))
                    break
            else:
                gruppy_shirin.append([sh, [(x0, x1)]])
        etalon, plity_ryada = max(gruppy_shirin, key=lambda g: (len(g[1]), g[0]))
        vysota = y1 - y0
        for x0, x1 in sorted(plity_ryada):
            ramki.append({
                "x": int(x0 + (x1 - x0) * 0.06),
                "y": int(y0 + vysota * 0.16),
                "w": int((x1 - x0) * 0.88),
                "h": int(vysota * 0.66),
            })

    json.dump(ramki, open(PLITY, "w"), indent=1)
    print("снято плит: {}".format(len(ramki)))

    proba = Image.open(ISTOCHNIK).convert("RGB")
    d = ImageDraw.Draw(proba)
    for r in ramki:
        d.rectangle([r["x"], r["y"], r["x"] + r["w"], r["y"] + r["h"]],
                    outline=(220, 40, 40), width=3)
    put = os.path.join(DOM, "docs/assets/pantheon/takt-nalozhenie.png")
    proba.save(put)
    print("наложение для проверки глазами:", put)


def main(yazyki):
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    stadii = manifest["visuals"]["stages"]
    plity = json.load(open(PLITY, encoding="utf-8"))
    if len(plity) != len(stadii):
        raise SystemExit(
            "плит {}, стадий {}: геометрия и манифест разошлись".format(len(plity), len(stadii))
        )
    ramki = [(p["x"], p["y"], p["w"], p["h"]) for p in plity]

    for yazyk in yazyki:
        podpisi = [s["diagram_" + yazyk].upper() if yazyk != "zh" else s["diagram_" + yazyk]
                   for s in stadii]
        kegl = kegl_dlya(yazyk, podpisi, ramki)
        f = shrift(yazyk, kegl)
        tr = kegl * TREKING
        im = Image.open(ISTOCHNIK).convert("RGB")
        # Одна линия письма в ряду: плиты одного ряда получают одну середину.
        ryady = {}
        for i, r in enumerate(ramki):
            ryady.setdefault(round(r[1] / 40), []).append(i)
        for indeksy in ryady.values():
            sredniy_y = sum(ramki[i][1] for i in indeksy) // len(indeksy)
            sredniy_h = sum(ramki[i][3] for i in indeksy) // len(indeksy)
            for i in indeksy:
                x, _, w, _ = ramki[i]
                vysech(im, (x, sredniy_y, w, sredniy_h), podpisi[i], f, tr)
        put = VYHOD.format(yazyk)
        im.save(put)
        print("высечено {}: кегль {}".format(put, kegl))


if __name__ == "__main__":
    argi = sys.argv[1:]
    if argi and argi[0] == "--izmerit":
        izmerit(argi[1:])
    else:
        main(argi or ["en", "ru", "zh"])
