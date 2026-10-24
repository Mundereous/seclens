"""
Mod 4 — XposedOrNot e-posta sızıntı kontrolü.

Ücretsiz API (anahtar yok): https://api.xposedornot.com
Dokümantasyon: https://xposedornot.com/api_doc

E-posta yalnızca API'ye gider; SecLens tarafında saklanmaz.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote

import requests

BASE = "https://api.xposedornot.com"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class BreachCheckError(Exception):
    """API / ağ hatası."""


@dataclass
class BreachResult:
    email: str
    found: bool
    breaches: list[str] = field(default_factory=list)
    risk_label: str | None = None  # Low / Medium / High / Critical …
    risk_score: int | None = None
    password_hint: dict | None = None  # EasyToCrack / PlainText / …
    xposed_summary: list[str] = field(default_factory=list)
    oneriler: list[str] = field(default_factory=list)
    ham_status: str = "ok"
    error: str | None = None


def _flatten_breaches(raw) -> list[str]:
    """API bazen [['A','B']] bazen ['A','B'] döner."""
    if not raw:
        return []
    out: list[str] = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, list):
                out.extend(str(x) for x in item)
            else:
                out.append(str(item))
    return sorted(set(out), key=str.lower)


def _default_oneriler(found: bool, risk_label: str | None) -> list[str]:
    if not found:
        return [
            "Bu e-posta bilinen sızıntılarda görünmüyor (XposedOrNot indeksi)",
            "Yine de benzersiz parola + 2FA kullan; ücretsiz breach alert açabilirsin",
        ]
    tips = [
        "Bu hesapların parolasını hemen değiştir; başka yerde aynı parolayı kullanma",
        "Mümkün olan her yerde 2FA / passkey aç",
        "Şüpheli oturumları kapat; banka/e-posta önce",
    ]
    if risk_label and risk_label.lower() in ("high", "critical", "yüksek"):
        tips.insert(
            0,
            "Risk yüksek/kritik — parola sızıntısı ihtimali var; tüm kritik hesapları rotate et",
        )
    tips.append("İzleme: xposedornot.com üzerinden ücretsiz breach alert")
    return tips


def check_email(email: str, *, timeout: float = 20.0) -> BreachResult:
    email = (email or "").strip()
    if not email or not EMAIL_RE.match(email):
        return BreachResult(
            email=email,
            found=False,
            ham_status="invalid",
            error="Geçerli bir e-posta gir (ör. isim@ornek.com).",
            oneriler=["Doğru formatta e-posta yazıp tekrar dene"],
        )

    try:
        r = requests.get(
            f"{BASE}/v1/check-email/{quote(email, safe='')}",
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "SecLens/1.0"},
        )
    except requests.Timeout as e:
        raise BreachCheckError("XposedOrNot zaman aşımı — tekrar dene.") from e
    except requests.RequestException as e:
        raise BreachCheckError(f"XposedOrNot'a bağlanılamadı: {e}") from e

    if r.status_code == 429:
        raise BreachCheckError(
            "Rate limit (ücretsiz: ~2/sn, 25/saat). Biraz bekleyip tekrar dene."
        )
    if r.status_code >= 500:
        raise BreachCheckError(f"XposedOrNot sunucu hatası HTTP {r.status_code}.")

    try:
        data = r.json()
    except ValueError as e:
        raise BreachCheckError("XposedOrNot geçersiz JSON döndü.") from e

    # Not found
    if isinstance(data, dict) and data.get("Error"):
        return BreachResult(
            email=email,
            found=False,
            ham_status="not_found",
            oneriler=_default_oneriler(False, None),
        )

    breaches = _flatten_breaches(data.get("breaches"))
    found = bool(breaches) or str(data.get("status", "")).lower() == "success"

    risk_label = None
    risk_score = None
    password_hint = None
    xposed_summary: list[str] = []

    # Detaylı analytics (best-effort)
    try:
        a = requests.get(
            f"{BASE}/v1/breach-analytics",
            params={"email": email},
            timeout=timeout,
            headers={"Accept": "application/json", "User-Agent": "SecLens/1.0"},
        )
        if a.status_code == 200:
            adata = a.json()
            metrics = adata.get("BreachMetrics") or {}
            risk_list = metrics.get("risk") or []
            if risk_list and isinstance(risk_list[0], dict):
                risk_label = risk_list[0].get("risk_label")
                try:
                    risk_score = int(risk_list[0].get("risk_score"))
                except (TypeError, ValueError):
                    risk_score = None
            pw = metrics.get("passwords_strength") or []
            if pw and isinstance(pw[0], dict):
                password_hint = pw[0]
            # xposed_data özeti
            xd = metrics.get("xposed_data") or []
            for block in xd[:1]:
                for child in (block.get("children") or [])[:6]:
                    name = child.get("name")
                    if name:
                        xposed_summary.append(str(name))
    except requests.RequestException:
        pass

    if not breaches and found:
        # status success ama liste boşsa yine "found" sayma
        found = False

    return BreachResult(
        email=email,
        found=found and bool(breaches),
        breaches=breaches,
        risk_label=risk_label,
        risk_score=risk_score,
        password_hint=password_hint,
        xposed_summary=xposed_summary,
        oneriler=_default_oneriler(bool(breaches), risk_label),
        ham_status="ok",
    )
