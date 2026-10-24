#!/usr/bin/env python3
"""Altay phisquiz örneklerini SecLens Mod 3 kurallarıyla karşılaştır."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.screenshot_scan import heuristic_from_inputs  # noqa: E402

MANIFEST = ROOT / "examples" / "screenshots" / "altay" / "manifest.json"


def main() -> None:
    meta = json.loads(MANIFEST.read_text(encoding="utf-8"))
    ok = 0
    print(f"{'id':>2}  {'truth':8}  skor risk   pred     match")
    for m in meta:
        skor, _, _ = heuristic_from_inputs(
            url_bar=m.get("url_hint") or "",
            notes=m.get("notes") or "",
            checked=m.get("checked") or {},
            filename=m.get("file") or "",
        )
        risk = "dusuk" if skor < 30 else "orta" if skor < 65 else "yuksek"
        pred = "phishing" if skor >= 40 else "real"
        truth = m["correct"]
        match = pred == truth
        ok += match
        print(
            f"{m['id']:02d}  {truth:8}  {skor:3} {risk:6} {pred:8} "
            f"{'✓' if match else '✗'}"
        )
    print(f"\nAccuracy: {ok}/{len(meta)} = {100 * ok / len(meta):.0f}%")
    print("Kaynak: https://phisquiz.siberaltay.org/")


if __name__ == "__main__":
    main()
