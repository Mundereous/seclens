"""
Ollama ile konuşan küçük yardımcı.

Ollama bilgisayarında yerel çalışır (genelde http://localhost:11434).
Bu dosya sadece HTTP isteği atar — model eğitmez.
"""

from __future__ import annotations

import requests

OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2:1b"


class OllamaError(Exception):
    """Ollama kapalıysa veya model yoksa bu hatayı fırlatırız."""


def is_ollama_up(timeout: float = 2.0) -> bool:
    """Ollama servisi ayakta mı?"""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=timeout)
        return r.status_code == 200
    except requests.RequestException:
        return False


def list_models(timeout: float = 5.0) -> list[str]:
    """Kurulu model isimlerini döndür."""
    try:
        r = requests.get(f"{OLLAMA_URL}/api/tags", timeout=timeout)
        r.raise_for_status()
        return [m["name"] for m in r.json().get("models", [])]
    except requests.RequestException as e:
        raise OllamaError(
            "Ollama'ya bağlanılamadı. Kurulu mu ve çalışıyor mu kontrol et: "
            "`ollama serve` veya uygulamayı aç."
        ) from e


def chat(
    prompt: str,
    *,
    system: str | None = None,
    model: str = DEFAULT_MODEL,
    timeout: float = 120.0,
    temperature: float = 0.2,
) -> str:
    """
    Modele bir mesaj gönder, düz metin cevap al.

    system: modele 'sen kimsin / nasıl davran' talimatı
    prompt: kullanıcının asıl sorusu / metni
    temperature: düşük = daha tutarlı (phishing için iyi)
    """
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {"temperature": temperature},
            },
            timeout=timeout,
        )
        r.raise_for_status()
    except requests.RequestException as e:
        raise OllamaError(
            f"Ollama chat başarısız ({model}). Model indirdin mi? "
            f"Örnek: `ollama pull {model}`"
        ) from e

    data = r.json()
    return data.get("message", {}).get("content", "").strip()
