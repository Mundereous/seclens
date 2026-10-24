"""
Mod 2 — kurallar + (opsiyonel) kısa LLM özeti.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.code_rules import CodeScanResult, scan_code
from core.ollama_client import chat


@dataclass
class CodeScanReport:
    scan: CodeScanResult
    llm_note: str = ""


def analyze_code(code: str, *, model: str) -> CodeScanReport:
    scan = scan_code(code)

    if scan.risk == "orta" and scan.findings:
        bullets = "; ".join(
            f"L{f.line} {f.cwe} {f.title}" for f in scan.findings[:6]
        )
        try:
            llm_note = chat(
                "Türkçe 2 cümle özet + 2 maddelik düzeltme önceliği yaz.\n"
                f"Bulgular: {bullets}\nKod:\n{code[:500]}",
                system="Kısa AppSec asistanısın. OWASP/CWE adlarını doğru kullan, abartma.",
                model=model,
                timeout=30.0,
                num_predict=120,
            )
        except Exception as e:
            llm_note = f"(LLM atlandı: {e})"
    elif scan.findings:
        top = sorted(scan.by_owasp.items(), key=lambda x: -x[1])[:3]
        top_s = ", ".join(f"{k} ({v})" for k, v in top) if top else "—"
        llm_note = (
            f"Kurallar net bulgu verdi (LLM atlandı). "
            f"Öne çıkan OWASP kategorileri: {top_s}. "
            "Her bulguda CWE + düzeltme satırına bak."
        )
    else:
        llm_note = (
            "Bu mini-SAST kritik kural tetiklemedi. "
            "Taint analizi yoktur; yine de manuel / Semgrep incelemesi önerilir."
        )

    return CodeScanReport(scan=scan, llm_note=llm_note)
