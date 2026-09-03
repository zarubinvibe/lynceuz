#!/usr/bin/env python3
"""Поставить снятые кадры Линкея в манифест: пути, свежие хеши, alt.

Хеш, набранный руками, расходится с файлом на первой же пересъемке. Прибор берет
его прямо с диска и пишет три раздела: свод, кадр такта и кадры документов, плюс
список длинных страниц с их кадрами.

Hero и эмблема тут НЕ трогаются: они сняты раньше свода и служили ему референсом,
их квитанции действительны, и переписывать их значило бы соврать о входе.

    scripts/postavit_seriyu.py
"""
import collections
import hashlib
import json
import os

DOM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(DOM, ".github/pantheon.json")
KADRY = "docs/assets/pantheon"


def sha(otnositelny):
    with open(os.path.join(DOM, otnositelny), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def kadr(imya, alt):
    put = "{}/{}.png".format(KADRY, imya)
    return collections.OrderedDict([
        ("published_path", put),
        ("published_sha256", sha(put)),
        ("alt", alt),
    ])


SVOD = [
    ("character_sheet", "bible-character",
     "Карта персонажа: Линкей из белого мрамора в четырех видах, глаза открыты, правая рука у лба "
     "прикрывает взгляд, рядом этюды головы, запечатанного ларца, плитки улики и лестницы"),
    ("prop_sheet", "bible-props",
     "Карта реквизита: мраморный стол, адресный камень, лестница, стеклянная пластина в золотой раме, "
     "дверь на засове, плитка улики, запечатанный ларец, печать и колонна на слоновой кости"),
]

TAKT_ALT = {
    "en": "Five marble plates in one row, each engraved with one step of the run, linked by a blue "
          "stream that ends at the sealed evidence chest",
    "ru": "Пять мраморных плит в ряд, на каждой высечен один шаг прогона, их связывает голубой поток, "
          "который заканчивается у запечатанного ларца улик",
    "zh": "五块大理石板排成一行，每块刻着运行中的一步，一条蓝色水流把它们串起来，最后汇入封好印的证据箱",
}

DOKUMENTY = [
    ("security", "doc-security",
     "Закрытая мраморная дверь на золотом засове, три голубых потока упираются в ее подножие, рядом "
     "стоит запечатанный ларец с уликами",
     {"en": "SECURITY.md", "ru": "SECURITY.ru.md", "zh": "SECURITY.zh.md"}),
    ("contributing", "doc-contributing",
     "Мраморный стол с чистыми плитками улик, голубой поток от них уходит в запечатанный ларец, рядом "
     "со столом стоит лестница бесплатных путей",
     {"en": "CONTRIBUTING.md", "ru": "CONTRIBUTING.ru.md", "zh": "CONTRIBUTING.zh.md"}),
]

STRANICY = [
    ("docs/ONBOARDING.md", ["assets/pantheon/doc-onboarding.png"]),
    ("docs/ONBOARDING.ru.md", ["assets/pantheon/doc-onboarding.png"]),
    ("docs/ONBOARDING.zh.md", ["assets/pantheon/doc-onboarding.png"]),
    ("docs/discovery-ladder.md", ["assets/pantheon/doc-ladder.png"]),
    ("docs/access-policy.md", ["assets/pantheon/doc-door.png"]),
    ("docs/wave2-containment-proof.md", ["assets/pantheon/doc-browser.png"]),
]


def main():
    manifest = json.load(open(MANIFEST, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    v = manifest["visuals"]

    v["bible"] = collections.OrderedDict((rol, kadr(imya, alt)) for rol, imya, alt in SVOD)

    yazyki = collections.OrderedDict()
    for yazyk, alt in TAKT_ALT.items():
        yazyki[yazyk] = kadr("takt-" + yazyk, alt)
    v["takt"] = collections.OrderedDict([
        ("source_path", "{}/takt.png".format(KADRY)),
        ("source_sha256", sha("{}/takt.png".format(KADRY))),
        ("languages", yazyki),
    ])

    ramki = collections.OrderedDict()
    for docid, imya, alt, stranicy in DOKUMENTY:
        zapis = kadr(imya, alt)
        zapis["pages"] = collections.OrderedDict(sorted(stranicy.items()))
        ramki[docid] = zapis
    v["doc_frames"] = ramki

    v["doc_pages"] = [collections.OrderedDict([("path", put), ("frames", kadry)])
                      for put, kadry in STRANICY]

    with open(MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("манифест обновлен: свод, такт, {} документа, {} страниц".format(
        len(ramki), len(v["doc_pages"])))


if __name__ == "__main__":
    main()
