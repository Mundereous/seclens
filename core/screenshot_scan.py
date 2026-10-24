"""
Mod 3 — Login screenshot phishing UI analizi.

Skorun çoğu kullanıcı checklist + URL/not sinyallerinden gelir.
Varsa Ollama vision modeli (moondream / llava / bakllava) görsel ipucu ekler;
yoksa metin LLM checklist özetini Türkçe açıklar.
"""

from __future__ import annotations

import base64
import io
import json
import re
from dataclasses import dataclass, field

from core.ollama_client import OllamaError, chat, chat_vision, list_models

VISION_CANDIDATES = (
    "moondream",
    "llava",
    "llava:7b",
    "llava-phi3",
    "bakllava",
    "minicpm-v",
)

# Checklist maddeleri: (id, etiket, ağırlık high=18 medium=12)
CHECK_ITEMS: list[tuple[str, str, int]] = [
    ("url_lookalike", "Adres çubuğunda marka taklidi / garip domain (xyz, IP, ek kelime)", 22),
    ("no_https", "Kilit / HTTPS yok veya tarayıcı uyarıyor", 18),
    ("urgency", "Ekranda aciliyet / korku dili (bloke, son 24 saat, hemen doğrula)", 16),
    ("odd_logo", "Logo düşük kalite, bulanık veya markaya benzemiyor", 12),
    ("ask_extra", "CVV / OTP / kimlik fotoğrafı / seed phrase istiyor", 22),
    ("popup_download", "Aniden indirme / uzaktan erişim (AnyDesk) istiyor", 20),
    ("spelling", "Yazım hataları, kötü Türkçe / çeviri", 10),
    ("unexpected_channel", "Banka/kargo için beklenmeyen kanal (SMS linkinden açıldı)", 14),
]

SUSPICIOUS_URL = re.compile(
    r"(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}"
    r"|[a-z0-9-]+\.(?:xyz|top|icu|click|loan|gq|tk|ml|cf|zip|buzz|shop)\b"
    r"|(?:garanti|ziraat|akbank|yapikredi|ptt|edevlet|turkiye)[a-z0-9-]*\.(?:com|net|xyz|top)",
    re.I,
)
PHISH_PATH = re.compile(
    r"/(login|signin|verify|secure|update|account|odeme|dogrula|confirm)(/|\?|$)",
    re.I,
)


@dataclass
class ScreenshotFinding:
    id: str
    title: str
    detail: str
    weight: int


@dataclass
class ScreenshotResult:
    risk: str
    skor: int
    kural_skoru: int
    gerekceler: list[str] = field(default_factory=list)
    oneriler: list[str] = field(default_factory=list)
    findings: list[ScreenshotFinding] = field(default_factory=list)
    vision_used: bool = False
    vision_model: str | None = None
    llm_status: str = "ok"
    ham: str = ""


def pick_vision_model(installed: list[str] | None = None) -> str | None:
    try:
        models = installed if installed is not None else list_models()
    except OllamaError:
        return None
    lower_map = {m.lower(): m for m in models}
    for cand in VISION_CANDIDATES:
        for key, original in lower_map.items():
            if cand in key:
                return original
    return None


def _risk_from_score(skor: int) -> str:
    if skor < 30:
        return "dusuk"
    if skor < 65:
        return "orta"
    return "yuksek"


def _default_oneriler(risk: str) -> list[str]:
    if risk == "dusuk":
        return [
            "Belirgin UI tuzağı yok; yine de adresi elle yazarak aç",
            "Şüphede resmi uygulamayı kullan",
        ]
    if risk == "orta":
        return [
            "Bu sekmede giriş yapma; kurum sitesini yer iminden aç",
            "Adres çubuğunu karakter karakter kontrol et",
        ]
    return [
        "Bu sayfada şifre / OTP girme",
        "Sekmeyi kapat; resmi mobil uygulama veya bilinen URL kullan",
        "Şüpheli sayfayı 5010'a bildir",
    ]


def heuristic_from_inputs(
    *,
    url_bar: str,
    notes: str,
    checked: dict[str, bool],
    filename: str = "",
) -> tuple[int, list[ScreenshotFinding], list[str]]:
    score = 10
    findings: list[ScreenshotFinding] = []
    reasons: list[str] = []
    blob = f"{url_bar}\n{notes}\n{filename}".lower()

    for cid, title, weight in CHECK_ITEMS:
        if checked.get(cid):
            findings.append(
                ScreenshotFinding(
                    id=cid,
                    title=title,
                    detail="Kullanıcı checklist'te işaretledi.",
                    weight=weight,
                )
            )
            score += weight
            reasons.append(title)

    if url_bar.strip():
        if SUSPICIOUS_URL.search(url_bar):
            findings.append(
                ScreenshotFinding(
                    id="url_regex",
                    title="URL şüpheli TLD / lookalike / IP",
                    detail=f"Adres: {url_bar[:80]}",
                    weight=20,
                )
            )
            score += 20
            reasons.append("Şüpheli URL kalıbı")
        if PHISH_PATH.search(url_bar):
            score += 8
            reasons.append("Login/verify path")
        if "http://" in url_bar.lower() and "https://" not in url_bar.lower():
            score += 12
            reasons.append("Cleartext http://")

    bait_words = [
        "bloke",
        "askıya",
        "askiya",
        "hemen doğrula",
        "hemen dogrula",
        "son 24",
        "cvv",
        "otp",
        "seed",
        "anydesk",
        "teamviewer",
        "ödeme talep",
        "odeme talep",
        "kargo takip",
        "teslim edilemedi",
        "paypaul",
        "vergiiade",
        "ptt-kargo",
        ".xyz",
    ]
    hits = [w for w in bait_words if w in blob]
    if hits:
        score += 8 * min(3, len(hits))
        reasons.append("Not/URL'de tuzak kelime: " + ", ".join(hits[:3]))

    if any(x in filename.lower() for x in ("phish", "fake", "scam", "sahte")):
        score += 10
        reasons.append("Örnek dosya adı phishing senaryosu")

    if not findings and not reasons:
        reasons.append("Checklist boş / belirgin sinyal yok")
        score = min(score, 18)

    return max(0, min(100, score)), findings, reasons


def _parse_llm_json(text: str) -> dict | None:
    text = (text or "").strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        data = json.loads(m.group(0))
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        return None


def analyze_screenshot(
    image_bytes: bytes,
    *,
    url_bar: str = "",
    notes: str = "",
    checked: dict[str, bool] | None = None,
    filename: str = "",
    model: str = "llama3.2:1b",
    use_vision: bool = True,
) -> ScreenshotResult:
    checked = checked or {}
    kural, findings, reasons = heuristic_from_inputs(
        url_bar=url_bar,
        notes=notes,
        checked=checked,
        filename=filename,
    )

    vision_used = False
    vision_model = None
    vision_notes = ""
    llm_status = "ok"
    ham = ""

    b64 = base64.b64encode(image_bytes).decode("ascii")

    if use_vision:
        vision_model = pick_vision_model()
        if vision_model:
            try:
                vision_notes = chat_vision(
                    "Bu bir login / hesap ekranı ekran görüntüsü olabilir. "
                    "Kısa Türkçe madde işaretleri yaz: (1) adres çubuğu tuhaf mı "
                    "(2) aciliyet dili var mı (3) logo/marka uyumsuz mu "
                    "(4) CVV/OTP/kimlik istiyor mu (5) genel phishing olasılığı düşük/orta/yüksek. "
                    "En fazla 6 kısa satır.",
                    images_b64=[b64],
                    model=vision_model,
                    timeout=90.0,
                    num_predict=180,
                )
                vision_used = True
                # Vision "yüksek" derse hafif skor ekle
                vl = vision_notes.lower()
                if "yüksek" in vl or "yuksek" in vl:
                    kural = min(100, kural + 15)
                    reasons.append("Vision model: yüksek phishing olasılığı")
                elif "orta" in vl:
                    kural = min(100, kural + 8)
                    reasons.append("Vision model: orta şüphe")
            except OllamaError as e:
                vision_notes = str(e)
                llm_status = "vision_failed"

    # Metin LLM: checklist → JSON gerekçe
    system = (
        "Sen phishing UI asistanısın. SADECE kısa JSON yaz. "
        '{"risk":"dusuk"|"orta"|"yuksek","skor":0-100,'
        '"gerekceler":["kısa"],"oneriler":["kısa"]}. '
        "Markdown yok. skor'u verilen kural skoruna yakın tut."
    )
    prompt = (
        f"Kural skoru: {kural}\n"
        f"URL çubuğu: {url_bar or '(yok)'}\n"
        f"Kullanıcı notu: {notes or '(yok)'}\n"
        f"Checklist sinyalleri:\n- " + "\n- ".join(reasons[:8]) + "\n"
    )
    if vision_notes and vision_used:
        prompt += f"\nVision modeli notları:\n{vision_notes[:500]}\n"

    try:
        ham = chat(
            prompt,
            system=system,
            model=model,
            timeout=45.0,
            num_predict=140,
        )
        data = _parse_llm_json(ham)
        if not data:
            llm_status = "bad_json" if llm_status == "ok" else llm_status
            risk = _risk_from_score(kural)
            return ScreenshotResult(
                risk=risk,
                skor=kural,
                kural_skoru=kural,
                gerekceler=reasons[:5] or ["Kural özeti"],
                oneriler=_default_oneriler(risk),
                findings=findings,
                vision_used=vision_used,
                vision_model=vision_model,
                llm_status=llm_status,
                ham=ham or vision_notes,
            )
        try:
            llm_skor = int(data.get("skor", kural))
        except (TypeError, ValueError):
            llm_skor = kural
        skor = max(0, min(100, int(0.55 * llm_skor + 0.45 * kural)))
        # Checklist boş / zayıf sinyalde LLM şişirmesin
        if kural < 25 and not findings:
            skor = min(skor, 22)
        risk = data.get("risk") or _risk_from_score(skor)
        if risk not in ("dusuk", "orta", "yuksek"):
            risk = _risk_from_score(skor)
        if kural < 25 and not findings:
            risk = "dusuk"
        gerek = data.get("gerekceler") or reasons
        oner = data.get("oneriler") or _default_oneriler(risk)
        if isinstance(gerek, str):
            gerek = [gerek]
        if isinstance(oner, str):
            oner = [oner]
        gerek_clean = [
            str(x).strip()
            for x in gerek
            if str(x).strip() and str(x).strip().lower() not in ("kısa", "kisa", "short")
        ] or reasons[:5]
        return ScreenshotResult(
            risk=risk,
            skor=skor,
            kural_skoru=kural,
            gerekceler=gerek_clean[:5],
            oneriler=[str(x) for x in oner][:4],
            findings=findings,
            vision_used=vision_used,
            vision_model=vision_model,
            llm_status=llm_status,
            ham=ham,
        )
    except OllamaError as e:
        risk = _risk_from_score(kural)
        return ScreenshotResult(
            risk=risk,
            skor=kural,
            kural_skoru=kural,
            gerekceler=reasons[:5],
            oneriler=_default_oneriler(risk),
            findings=findings,
            vision_used=vision_used,
            vision_model=vision_model,
            llm_status="failed",
            ham=str(e),
        )


def load_image_bytes(path_or_file) -> bytes:
    if hasattr(path_or_file, "read"):
        data = path_or_file.read()
        if hasattr(path_or_file, "seek"):
            path_or_file.seek(0)
        return data
    with open(path_or_file, "rb") as f:
        return f.read()


def image_to_png_bytes(raw: bytes) -> bytes:
    """Normalize to PNG for consistent preview / vision."""
    try:
        from PIL import Image

        im = Image.open(io.BytesIO(raw))
        if im.mode not in ("RGB", "RGBA"):
            im = im.convert("RGB")
        buf = io.BytesIO()
        im.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return raw
