"""SecLens UI ekran görüntüleri — README için."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
EXAMPLES = ROOT / "examples"
BASE = "http://127.0.0.1:8501"


def wait_streamlit(page) -> None:
    page.goto(BASE, wait_until="networkidle", timeout=60000)
    page.wait_for_selector("text=SecLens", timeout=60000)
    page.wait_for_timeout(1500)


def set_textarea(page, text: str) -> None:
    # Streamlit text_area
    area = page.locator("textarea").first
    area.click()
    area.fill(text)
    page.wait_for_timeout(500)


def click_analyze(page) -> None:
    page.get_by_role("button", name="Analiz et").click()
    # Sonuç gelsin
    page.wait_for_selector("text=Skor:", timeout=120000)
    page.wait_for_timeout(1000)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1400, "height": 900})

        wait_streamlit(page)
        page.screenshot(path=str(OUT / "01_home.png"), full_page=True)

        # Yüksek risk: uzlaştırma
        scam = (EXAMPLES / "scam_uzlastirma.txt").read_text(encoding="utf-8")
        set_textarea(page, scam)
        click_analyze(page)
        page.screenshot(path=str(OUT / "02_uzlastirma_high_risk.png"), full_page=True)

        # Düşük risk: güvenli e-posta
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(1500)
        safe = (EXAMPLES / "safe_email.txt").read_text(encoding="utf-8")
        set_textarea(page, safe)
        click_analyze(page)
        page.screenshot(path=str(OUT / "03_safe_email_low_risk.png"), full_page=True)

        # IBAN tuzağı
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(1500)
        iban = (EXAMPLES / "scam_iban_eft.txt").read_text(encoding="utf-8")
        set_textarea(page, iban)
        click_analyze(page)
        page.screenshot(path=str(OUT / "04_iban_eft_scam.png"), full_page=True)

        browser.close()

    print("Screenshots saved to", OUT)
    for f in sorted(OUT.glob("*.png")):
        print(" -", f.name, f.stat().st_size)


if __name__ == "__main__":
    main()
