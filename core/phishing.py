"""
Mod 1 — Türkçe metin phishing / smishing analizi.

Küçük LLM tek başına yetersiz → kamu uyarılarından derlenen kurallar + AI gerekçe.
Sinyal listesi: core/scam_patterns.py
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from core.ollama_client import chat
from core import scam_patterns as P

SYSTEM_PROMPT = """Sen Türkçe SMS/e-posta dolandırıcılık (smishing/phishing) asistanısın.
SADECE tek JSON yaz. Markdown yok.

Şema:
{"risk":"dusuk"|"orta"|"yuksek","skor":0-100,"gerekceler":["..."],"oneriler":["..."]}

Yüksek risk örnekleri: sahte banka/kargo linki, savcılık-uzlaştırma+telefon,
e-Devlet askıya alma, HGS/gümrük ücreti, IBAN'a EFT isteği, kripto "hesabın tehlikede",
istenmeyen hediye/maket.
Düşük risk: arkadaş/toplantı maili, link-telefon-IBAN-tehdit yok.
"gündem/toplantı" şüpheli DEĞİL. Abartma.
"""


@dataclass
class PhishingResult:
    risk: str
    skor: int
    gerekceler: list[str] = field(default_factory=list)
    oneriler: list[str] = field(default_factory=list)
    ham: str = ""
    json_ok: bool = True
    kural_skoru: int = 0


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def _hits(text: str, words: list[str]) -> list[str]:
    return [w for w in words if w in text]


def heuristic_score(text: str) -> tuple[int, list[str]]:
    """0–100 kural skoru + bulunan sinyaller."""
    t = text.lower()
    score = 8
    reasons: list[str] = []

    urls = P.URL_RE.findall(text)
    phones = P.PHONE_RE.findall(text)
    ibans = P.IBAN_RE.findall(text)

    if urls:
        score += 22
        reasons.append(f"Link var: {urls[0][:70]}")
    if P.SUSPICIOUS_TLD.search(text) or P.IP_URL.search(text):
        score += 22
        reasons.append("Şüpheli domain / IP linki")
    if P.SHORT_LINK.search(text):
        score += 12
        reasons.append("Kısaltılmış link (bit.ly vb.)")
    if phones:
        score += 12
        reasons.append(f"Arama numarası: {phones[0]}")
    if ibans:
        score += 28
        reasons.append(f"IBAN paylaşılmış: {ibans[0][:34]}…")

    buckets = [
        ("Aciliyet/korku dili", P.RED_WORDS, 10),  # kelime başına, max 3
        ("Savcılık/uzlaştırma/icra", P.LEGAL_SCAM, 22),
        ("e-Devlet/kamu taklidi", P.EDEVLET_SCAM, 22),
        ("Kargo/PTT/HGS/gümrük kalıbı", P.CARGO_SCAM, 20),
        ("Banka/EFT tuzağı dili", P.BANK_SCAM, 20),
        ("Kripto smishing dili", P.CRYPTO_SCAM, 20),
        ("Hediye/çekiliş bait", P.GIFT_BAIT, 24),
    ]
    found_any_scam_bucket = False
    for label, words, weight in buckets:
        h = _hits(t, words)
        if not h:
            continue
        found_any_scam_bucket = True
        if words is P.RED_WORDS:
            score += weight * min(3, len(h))
        else:
            score += weight + 5 * min(2, len(h) - 1)
        reasons.append(f"{label}: " + ", ".join(h[:3]))

    brand_hits = _hits(t, P.BANK_BRANDS + P.CARGO_BRANDS)
    if brand_hits and urls:
        score += 18
        reasons.append("Marka + link (sık oltalama): " + ", ".join(brand_hits[:3]))
    elif brand_hits and (phones or ibans):
        score += 15
        reasons.append("Marka + telefon/IBAN")

    # Kombo: hukuki + ara/telefon
    legal = _hits(t, P.LEGAL_SCAM)
    if legal and phones:
        score += 25
        reasons.append("Sahte savcılık/uzlaştırma + telefon kalıbı")
    if _hits(t, P.EDEVLET_SCAM) and urls:
        score += 20
        reasons.append("e-Devlet/kamu + dış link (resmi kurum SMS ile login linki göndermez)")
    if ibans and (
        _hits(t, P.BANK_SCAM)
        or "eft" in t
        or "havale" in t
        or "indirim" in t
    ):
        score += 15
        reasons.append("IBAN + ödeme/EFT baskısı")

    forwarded = (
        "forwarded message" in t
        or "iletilen ileti" in t
        or "---------- forwarded" in t
    )
    gift = _hits(t, P.GIFT_BAIT)
    if gift and (forwarded or "no-reply@" in t or "@gmail.com" in t):
        score += 22
        reasons.append("İletilmiş / no-reply hediye spam kalıbı")
        score = max(score, 70)  # bu kalıp tek başına yüksek risk sayılır

    safe = _hits(t, P.SAFE_WORDS)
    if (
        safe
        and not urls
        and not phones
        and not ibans
        and not found_any_scam_bucket
        and not brand_hits
    ):
        score -= 20
        reasons.append("Normal iletişim sinyali: " + ", ".join(safe[:3]))

    if (
        not urls
        and not phones
        and not ibans
        and not found_any_scam_bucket
        and not brand_hits
    ):
        score = min(score, 15)
        if not reasons:
            reasons.append("Belirgin dolandırıcılık sinyali yok")

    return max(0, min(100, score)), reasons


def _risk_from_score(skor: int) -> str:
    if skor < 30:
        return "dusuk"
    if skor < 65:
        return "orta"
    return "yuksek"


def _default_oneriler(risk: str) -> list[str]:
    if risk == "dusuk":
        return [
            "Belirgin tuzak yok; yine de tanımadığın link/IBAN'a güvenme",
            "Emin değilsen göndereni başka kanaldan sor",
        ]
    if risk == "orta":
        return [
            "Linke tıklama; kurumu kendi uygulamasından / sitesinden aç",
            "Şüpheli SMS'i 5010'a bildirebilirsin",
        ]
    return [
        "Linke tıklama, numarayı ARAMA, IBAN'a para yatırma",
        "Banka/kargo/e-Devlet işlemlerini sadece resmi uygulamadan yap",
        "Şüpheli mesajı 5010 (Dolandırıcılıkla Mücadele) hattına ilet",
        "OTP / CVV / şifre asla SMS veya link formuna yazılmaz",
    ]


def analyze_text(text: str, *, model: str) -> PhishingResult:
    text = (text or "").strip()
    if not text:
        return PhishingResult(
            risk="dusuk",
            skor=0,
            gerekceler=["Boş metin"],
            oneriler=["Analiz için SMS veya e-posta yapıştır"],
            ham="",
            json_ok=True,
            kural_skoru=0,
        )

    kural_skor, kural_gerekce = heuristic_score(text)
    user_prompt = (
        f"Kural özeti (doğru kabul et): skor≈{kural_skor}, sinyaller={kural_gerekce}\n"
        f"Metin:\n---\n{text}\n---\n"
        "Sadece JSON döndür. Skoru kural özetine yakın tut."
    )

    ham = ""
    llm_gerekce: list[str] = []
    llm_oneriler: list[str] = []
    llm_skor: int | None = None
    json_ok = True

    try:
        ham = chat(
            user_prompt,
            system=SYSTEM_PROMPT,
            model=model,
            temperature=0.1,
        )
        data = _extract_json(ham)
        if data is None:
            json_ok = False
        else:
            try:
                llm_skor = int(data.get("skor", kural_skor))
            except (TypeError, ValueError):
                llm_skor = None
            g = data.get("gerekceler") or data.get("gerekçeler") or []
            o = data.get("oneriler") or data.get("öneriler") or []
            if isinstance(g, str):
                g = [g]
            if isinstance(o, str):
                o = [o]
            llm_gerekce = [str(x) for x in g if str(x).strip()][:4]
            llm_oneriler = [str(x) for x in o if str(x).strip()][:4]
    except Exception as e:
        json_ok = False
        ham = f"(LLM atlandı: {e})"

    if llm_skor is None:
        skor = kural_skor
    else:
        skor = int(round(0.75 * kural_skor + 0.25 * max(0, min(100, llm_skor))))

    if kural_skor <= 20:
        skor = min(skor, 20)
    if kural_skor >= 75:
        skor = max(skor, 75)

    risk = _risk_from_score(skor)

    gerekceler = kural_gerekce[:]
    for g in llm_gerekce:
        if len(g) < 10:
            continue
        if g.lower() not in {x.lower() for x in gerekceler}:
            gerekceler.append(g)
    gerekceler = gerekceler[:7] or ["Belirgin sinyal yok"]

    oneriler = llm_oneriler if llm_oneriler else _default_oneriler(risk)
    oneriler = [o for o in oneriler if len(o) >= 10][:6] or _default_oneriler(risk)

    return PhishingResult(
        risk=risk,
        skor=skor,
        gerekceler=gerekceler,
        oneriler=oneriler,
        ham=ham,
        json_ok=json_ok,
        kural_skoru=kural_skor,
    )
