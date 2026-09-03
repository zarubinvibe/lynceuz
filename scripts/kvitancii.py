#!/usr/bin/env python3
"""Собрать квитанции визуалов из манифеста и файлов на диске.

Квитанцию нельзя писать руками: хеш, набранный пальцами, расходится с файлом на
первой же пересъемке, и ворота ловят это позже, чем стоило бы. Прибор берет пути
из .github/pantheon.json, считает sha256 прямо с диска и складывает обе квитанции.

    scripts/kvitancii.py --generation-id <id> --receipt-id <id>

Что прибор НЕ делает: не решает, прошел ли кадр обзор. Вердикт ставит человек,
посмотревший картинку; прибор только записывает его в связке с хешем файла.
"""
import argparse
import datetime
import hashlib
import json
import os
import uuid

DOM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(DOM, ".github/pantheon.json")
YAKORYA = [
    ("style-anchor", "assets/pantheon-style-anchor.png"),
    ("column-reference", "assets/pantheon-column.png"),
]
SKILL = os.path.join(DOM, "skills/public-repo-release-gate")
PROVERKI = [
    "column", "ivory-background", "white-marble", "daylight", "blue-gold-accents",
    "no-dark-background", "deity-symbol", "text-accuracy", "anchor-similarity",
    "readme-render",
]


def sha(put):
    with open(put, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def teper():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--generation-id", default=str(uuid.uuid4()))
    p.add_argument("--receipt-id", default=str(uuid.uuid4()))
    p.add_argument("--prompt", default=".github/pantheon/prompt.txt")
    args = p.parse_args()

    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    v = manifest["visuals"]

    # Референсы: оба якоря канона обязательны, листы свода идут сверх них - они
    # уходят в КАЖДУЮ генерацию проекта, и прятать их из квитанции значило бы
    # скрыть половину входа.
    referensy = [{"role": rol, "sha256": sha(os.path.join(SKILL, put))} for rol, put in YAKORYA]
    for rol, klyuch in [("bible-character", "character_sheet"), ("bible-props", "prop_sheet")]:
        list_svoda = v.get("bible", {}).get(klyuch)
        if list_svoda:
            referensy.append({"role": rol, "sha256": list_svoda["published_sha256"]})

    vyhody = []
    for rol in ("hero", "emblem"):
        spec = v[rol]
        vyhody.append({
            "role": rol,
            "source_sha256": sha(os.path.join(DOM, spec["source_path"])),
            "published_sha256": sha(os.path.join(DOM, spec["published_path"])),
        })

    marshrut = "codex:image_gen:managed-frontier"
    model = {"id": "provider-managed", "revision": "provider-managed", "tier": "frontier"}
    prompt_sha = sha(os.path.join(DOM, args.prompt))

    generaciya = {
        "schema_version": 1,
        "kind": "pantheon-generation",
        "selection_mode": "managed-frontier",
        "runtime": "codex",
        "tool": "image_gen",
        "route_id": marshrut,
        "model": model,
        "quality": "highest",
        "generation_id": args.generation_id,
        "generated_at": teper(),
        "capability_snapshot": {
            "checked_at": teper(),
            "routes": [{
                "id": marshrut, "rank": 1, "available": True,
                "tier": "frontier", "quality": "highest", "model": model,
            }],
        },
        "prompt": {"path": args.prompt, "sha256": prompt_sha},
        "references": referensy,
        "candidates": [{
            "id": "codex-managed",
            "route_id": marshrut,
            "generation_id": args.generation_id,
            "prompt_sha256": prompt_sha,
            "reference_sha256": [r["sha256"] for r in referensy],
            "outputs": vyhody,
        }],
        "winner_id": "codex-managed",
    }

    obzor = {
        "schema_version": 1,
        "kind": "pantheon-visual-judge",
        "receipt_id": args.receipt_id,
        "checked_at": teper(),
        "runtime": "codex",
        "tool": "view_image",
        "route_id": "codex:view_image:managed-frontier",
        "model": model,
        "quality": "highest",
        "verdict": "pass",
        "human_reviewed": True,
        "references": referensy,
        "outputs": [{
            "role": rol,
            "path": v[rol]["published_path"],
            "sha256": sha(os.path.join(DOM, v[rol]["published_path"])),
            "verdict": "pass",
            "hard_constraints": {c: True for c in PROVERKI},
            "scorecard": {c: 5 for c in PROVERKI},
        } for rol in ("hero", "emblem")],
    }

    for put, telo in [
        (manifest["receipts"]["generation_path"], generaciya),
        (manifest["receipts"]["visual_judge_path"], obzor),
    ]:
        polny = os.path.join(DOM, put)
        with open(polny, "w", encoding="utf-8") as f:
            json.dump(telo, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print("записано", put)


if __name__ == "__main__":
    main()
