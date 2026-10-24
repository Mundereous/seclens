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
    timeout: float = 45.0,
    temperature: float = 0.1,
    num_predict: int = 160,
) -> str:
    """
    Modele bir mesaj gönder, düz metin cevap al.

    system: modele 'sen kimsin / nasıl davran' talimatı
    prompt: kullanıcının asıl sorusu / metni
    temperature: düşük = daha tutarlı (phishing için iyi)
    num_predict: max üretilen token (küçük tut → daha hızlı)
    """
    messages: list[dict[str, str]] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model.strip(),
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
            "num_ctx": 2048,
        },
    }
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            timeout=timeout,
        )
    except requests.Timeout as e:
        raise OllamaError(
            f"Ollama zaman aşımı ({timeout:.0f}s, model={model}). "
            "Model yüklü ama yavaş yanıt verdi; tekrar dene veya daha küçük prompt kullan."
        ) from e
    except requests.RequestException as e:
        raise OllamaError(
            f"Ollama'ya bağlanılamadı ({model}): {e}. "
            "Ollama.app açık mı? `curl http://127.0.0.1:11434/api/tags`"
        ) from e

    if r.status_code >= 400:
        detail = (r.text or "")[:300]
        raise OllamaError(
            f"Ollama HTTP {r.status_code} (model={model}). "
            f"Yanıt: {detail or 'boş'} — model adı doğru mu? `ollama list`"
        )

    data = r.json()
    return data.get("message", {}).get("content", "").strip()


def chat_vision(
    prompt: str,
    *,
    images_b64: list[str],
    model: str,
    system: str | None = None,
    timeout: float = 90.0,
    temperature: float = 0.1,
    num_predict: int = 180,
) -> str:
    """
    Vision-capable Ollama modeli (llava / moondream …).
    images_b64: ham görüntü base64 (data-URI öneki olmadan).
    """
    if not images_b64:
        raise OllamaError("Vision için en az bir görüntü gerekli.")

    messages: list[dict] = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append(
        {
            "role": "user",
            "content": prompt,
            "images": images_b64,
        }
    )

    payload = {
        "model": model.strip(),
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": num_predict,
            "num_ctx": 2048,
        },
    }
    try:
        r = requests.post(
            f"{OLLAMA_URL}/api/chat",
            json=payload,
            timeout=timeout,
        )
    except requests.Timeout as e:
        raise OllamaError(
            f"Vision model zaman aşımı ({timeout:.0f}s, {model})."
        ) from e
    except requests.RequestException as e:
        raise OllamaError(f"Ollama vision çağrısı başarısız: {e}") from e

    if r.status_code >= 400:
        detail = (r.text or "")[:300]
        raise OllamaError(
            f"Vision HTTP {r.status_code} ({model}): {detail or 'boş'}"
        )

    data = r.json()
    return data.get("message", {}).get("content", "").strip()
