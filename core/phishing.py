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

SYSTEM_PROMPT = """Sen Türkçe phishing asistanısın. SADECE tek satır/kısa JSON yaz.
Markdown, açıklama, kod çiti YOK.

Şema (alan adları birebir):
{"risk":"dusuk"|"orta"|"yuksek","skor":0-100,"gerekceler":["kısa","kısa"],"oneriler":["kısa","kısa"]}

KURALLAR:
- gerekceler/oneriler en fazla 3 madde, her madde en fazla 8 kelime
- Orijinal SMS/e-postayı gerekçeye KOPYALAMA
- skor'u kural özetine yakın tut
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
    # skipped_speed | ok | failed | bad_json
    llm_status: str = "ok"


def _repair_json_fragment(fragment: str) -> str:
    """Küçük modelin yarıda kestiği JSON'u kapatmaya çalış."""
    s = fragment.strip()
    # Trailing virgül / yarım string
    s = re.sub(r",\s*$", "", s)
    # Açık string varsa kapat
    if s.count('"') % 2 == 1:
        s += '"'
    # Açık dizi / nesne kapat
    open_sq = s.count("[") - s.count("]")
    open_br = s.count("{") - s.count("}")
    s += "]" * max(0, open_sq)
    s += "}" * max(0, open_br)
    return s


def _extract_json(text: str) -> dict | None:
    text = (text or "").strip()
    # ```json ... ``` temizle
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    candidates: list[str] = [text]
    m = re.search(r"\{[\s\S]*", text)
    if m:
        candidates.append(m.group(0))
        # İlk tam {...} dene
        m2 = re.search(r"\{[\s\S]*\}", text)
        if m2:
            candidates.insert(0, m2.group(0))

    for raw in candidates:
        for variant in (raw, _repair_json_fragment(raw)):
            try:
                data = json.loads(variant)
                if isinstance(data, dict) and ("risk" in data or "skor" in data):
                    return data
            except json.JSONDecodeError:
                continue
    return None


def _hits(text: str, words: list[str]) -> list[str]:
    return [w for w in words if w in text]


def _mask_ibans(text: str) -> tuple[str, list[str]]:
    """IBAN'ları bul; telefon regex'inin IBAN içinden sahte numara çıkarmasını engelle."""
    ibans = P.IBAN_RE.findall(text)
    masked = text
    for iban in ibans:
        masked = masked.replace(iban, " " * len(iban))
    return masked, list(ibans)


def heuristic_score(text: str) -> tuple[int, list[str]]:
    """0–100 kural skoru + bulunan sinyaller."""
    t = text.lower()
    score = 8
    reasons: list[str] = []

    urls = P.URL_RE.findall(text)
    masked, ibans = _mask_ibans(text)
    phones = P.PHONE_RE.findall(masked)  # IBAN maskelendikten sonra
    ig_hits = P.INSTAGRAM_RE.findall(text)

    if urls:
        score += 22
        reasons.append(f"Link var: {urls[0][:70]}")
    if P.SUSPICIOUS_TLD.search(text) or P.IP_URL.search(text):
        score += 22
        reasons.append("Şüpheli domain / IP linki")
    if P.SHORT_LINK.search(text):
        score += 12
        reasons.append("Kısaltılmış link (bit.ly vb.)")
    if getattr(P, "LOOKALIKE_HOST", None) and P.LOOKALIKE_HOST.search(text):
        score += 28
        reasons.append("Kurum/marka taklidi domain (lookalike)")
    if getattr(P, "PHISH_PATH", None) and P.PHISH_PATH.search(text):
        score += 14
        reasons.append("Login/verify/ödeme path'li şüpheli link")
    if getattr(P, "TEL_LINK", None) and P.TEL_LINK.search(text):
        score += 10
        reasons.append("tel: linki (arama tuzağı)")
    if phones:
        score += 12
        reasons.append(f"Arama numarası: {phones[0]}")
    if ibans:
        score += 30
        reasons.append(f"IBAN paylaşılmış: {ibans[0][:34]}")
    if ig_hits:
        score += 12
        reasons.append(f"Instagram / sosyal hesap: {ig_hits[0][:40]}")

    buckets = [
        ("Aciliyet/korku dili", P.RED_WORDS, 10),  # kelime başına, max 3
        ("Savcılık/uzlaştırma/icra", P.LEGAL_SCAM, 22),
        ("e-Devlet/kamu taklidi", P.EDEVLET_SCAM, 22),
        ("Kargo/PTT/HGS/gümrük kalıbı", P.CARGO_SCAM, 20),
        ("Banka/EFT tuzağı dili", P.BANK_SCAM, 20),
        ("Kripto smishing dili", P.CRYPTO_SCAM, 20),
        ("Hediye/çekiliş bait", P.GIFT_BAIT, 24),
        ("Valilik/bağış IBAN tuzağı", P.SOCIAL_IBAN_SCAM, 28),
        ("KYC/kimlik doğrulama tuzağı", P.KYC_SCAM, 22),
        ("WhatsApp/Telegram/uzaktan erişim", P.MESSENGER_SCAM, 24),
        ("Operatör/eSIM/fatura", P.TELCO_SCAM, 18),
        ("Sahte tech support / hesap askı", P.TECH_SUPPORT_SCAM, 22),
        ("Yatırım/forex tuzağı", P.INVEST_SCAM, 24),
        ("İş/romance/gönderi ücreti", P.JOB_ROMANCE_SCAM, 22),
        ("Vergi/SGK/iade bait", P.REFUND_SCAM, 22),
        ("Fatura/QR ödeme tuzağı", P.INVOICE_QR_SCAM, 20),
        ("OTP/şifre paylaşma baskısı", P.OTP_PRESSURE, 30),
        ("CEO/muhasebe fraud dili", P.CEO_FRAUD, 26),
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
    if _hits(t, P.OTP_PRESSURE) and (phones or "whatsapp" in t or "telegram" in t):
        score += 20
        reasons.append("OTP/şifre isteme + iletişim kanalı (asla paylaşma)")
        score = max(score, 80)
    if _hits(t, P.MESSENGER_SCAM) and (
        "anydesk" in t or "teamviewer" in t or "uzaktan" in t
    ):
        score += 18
        reasons.append("Uzaktan erişim + mesajlaşma tuzağı")
        score = max(score, 75)
    if _hits(t, P.INVEST_SCAM) and (urls or phones or "whatsapp" in t):
        score += 15
        reasons.append("Yatırım vaadi + dış kanal")
        score = max(score, 70)
    if _hits(t, P.TECH_SUPPORT_SCAM) and urls:
        score += 15
        reasons.append("Hesap askıya alma iddiası + link")
        score = max(score, 70)
    if _hits(t, P.REFUND_SCAM) and urls:
        score += 15
        reasons.append("İade/ödeme bait + link")
        score = max(score, 68)
    if _hits(t, P.KYC_SCAM) and urls:
        score += 15
        reasons.append("KYC/kimlik + dış link (resmi süreç değil)")
        score = max(score, 70)

    # Klasik IG/sosyal: "Valilik onaylı IBAN" + IBAN (+ Instagram)
    social_iban = _hits(t, P.SOCIAL_IBAN_SCAM)
    if ibans and social_iban:
        score += 25
        reasons.append(
            "Kamu onayı iddiası + kişisel IBAN = sık bağış dolandırıcılığı"
        )
        score = max(score, 85)
    elif ibans and ig_hits:
        score += 20
        reasons.append("Instagram hesabı ile IBAN paylaşımı (yüksek riskli kalıp)")
        score = max(score, 75)
    elif ibans and ("izin no" in t or "valilik" in t):
        score = max(score, 80)
        reasons.append("Valilik/izin no + IBAN kalıbı")

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
            llm_status="skipped_speed",
        )

    kural_skor, kural_gerekce = heuristic_score(text)

    ham = ""
    llm_gerekce: list[str] = []
    llm_oneriler: list[str] = []
    llm_skor: int | None = None
    json_ok = True
    llm_status = "ok"

    # Her analizde LLM çağrılır (kullanıcı isteği: atlama yok).
    user_prompt = (
        f"kural_skor={kural_skor}; sinyaller={kural_gerekce[:4]}\n"
        f"metin:\n{text[:500]}\n"
        'Örnek çıktı: {"risk":"yuksek","skor":90,"gerekceler":["sahte e-devlet linki"],'
        '"oneriler":["linke tiklama"]}\n'
        "Şimdi SADECE JSON:"
    )
    try:
        ham = chat(
            user_prompt,
            system=SYSTEM_PROMPT,
            model=model,
            temperature=0.0,
            timeout=90.0,
            num_predict=256,
        )

        data = _extract_json(ham)
        if data is None:
            json_ok = False
            llm_status = "bad_json"
        else:
            llm_status = "ok"
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
        llm_status = "failed"
        ham = f"LLM çağrısı başarısız; skor yine kurallardan.\nDetay: {e}"

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
        llm_status=llm_status,
    )
