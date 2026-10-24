"""SecLens UI ekran görüntüleri — README için (Mod 1 + Mod 2)."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
EXAMPLES = ROOT / "examples"
BASE = "http://127.0.0.1:8501"


def wait_streamlit(page) -> None:
    page.goto(BASE, wait_until="networkidle", timeout=90000)
    page.wait_for_selector("text=SecLens", timeout=90000)
    page.wait_for_timeout(2000)


def set_textarea(page, text: str, *, label: str | None = None) -> None:
    if label:
        area = page.get_by_label(label)
    else:
        area = page.locator("textarea:visible").first
    area.click()
    area.fill(text)
    page.wait_for_timeout(400)


def click_named(page, name: str) -> None:
    page.get_by_role("button", name=name).click()


def open_tab(page, label: str) -> None:
    page.get_by_role("tab", name=label).click()
    page.wait_for_timeout(800)


def pick_select_option(page, option_label: str) -> None:
    """Streamlit selectbox (Baseweb) — tıkla + seçeneği seç."""
    # Görüntü sekmesindeki ilk/ana selectbox
    combo = page.locator('[data-baseweb="select"]').first
    combo.click()
    page.wait_for_timeout(400)
    page.get_by_role("option", name=option_label).click()
    page.wait_for_timeout(400)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 960})

        # 01 — home (Mod 1)
        wait_streamlit(page)
        page.screenshot(path=str(OUT / "01_home.png"), full_page=True)

        # 02 — phishing yüksek risk
        scam = (EXAMPLES / "scam_uzlastirma.txt").read_text(encoding="utf-8")
        set_textarea(page, scam, label="Metni yapıştır")
        click_named(page, "Analiz et")
        page.wait_for_selector("text=Skor:", timeout=180000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "02_uzlastirma_high_risk.png"), full_page=True)

        # 03 — güvenli e-posta
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        safe = (EXAMPLES / "safe_email.txt").read_text(encoding="utf-8")
        set_textarea(page, safe, label="Metni yapıştır")
        click_named(page, "Analiz et")
        page.wait_for_selector("text=Skor:", timeout=180000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "03_safe_email_low_risk.png"), full_page=True)

        # 04 — IBAN / EFT
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        iban = (EXAMPLES / "scam_iban_eft.txt").read_text(encoding="utf-8")
        set_textarea(page, iban, label="Metni yapıştır")
        click_named(page, "Analiz et")
        page.wait_for_selector("text=Skor:", timeout=180000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "04_iban_eft_scam.png"), full_page=True)

        # 05 — OTP / WhatsApp (yeni phishing kuralları)
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        otp = (EXAMPLES / "scam_otp_whatsapp.txt").read_text(encoding="utf-8")
        set_textarea(page, otp, label="Metni yapıştır")
        click_named(page, "Analiz et")
        page.wait_for_selector("text=Skor:", timeout=180000)
        page.wait_for_timeout(1200)
        page.screenshot(path=str(OUT / "05_otp_whatsapp_scam.png"), full_page=True)

        # 06 — Mod 2 kod: Twisted / httpoxy
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        open_tab(page, "2 · Kod (güvenlik)")
        code = (EXAMPLES / "code" / "11_twisted_httpoxy.py.txt").read_text(
            encoding="utf-8"
        )
        set_textarea(page, code, label="Kod yapıştır")
        click_named(page, "Tara")
        page.wait_for_selector("text=Risk skoru:", timeout=60000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "06_code_twisted_high.png"), full_page=True)

        # 07 — Mod 2: PHP SQLi
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        open_tab(page, "2 · Kod (güvenlik)")
        php = (EXAMPLES / "code" / "14_php_sql_injection.php.txt").read_text(
            encoding="utf-8"
        )
        set_textarea(page, php, label="Kod yapıştır")
        click_named(page, "Tara")
        page.wait_for_selector("text=Risk skoru:", timeout=60000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "07_code_php_sqli.png"), full_page=True)

        # 08 — Mod 2: IDOR
        page.reload(wait_until="networkidle")
        page.wait_for_selector("text=SecLens")
        page.wait_for_timeout(2000)
        open_tab(page, "2 · Kod (güvenlik)")
        idor = (EXAMPLES / "code" / "13_idor_user_profile.js.txt").read_text(
            encoding="utf-8"
        )
        set_textarea(page, idor, label="Kod yapıştır")
        click_named(page, "Tara")
        page.wait_for_selector("text=Risk skoru:", timeout=60000)
        page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "08_code_idor.png"), full_page=True)

        def run_mod3(
            *,
            image: Path,
            url: str,
            notes: str,
            checks: list[str],
            out_name: str,
        ) -> None:
            page.reload(wait_until="networkidle")
            page.wait_for_selector("text=SecLens")
            page.wait_for_timeout(2000)
            open_tab(page, "3 · Görüntü (screenshot)")
            page.wait_for_timeout(1000)
            page.locator('input[type="file"]').set_input_files(str(image))
            page.wait_for_timeout(1200)
            page.get_by_label("Adres çubuğunda ne görüyorsun? (varsa yapıştır)").fill(
                url
            )
            page.get_by_label("Ek not (opsiyonel)").fill(notes)
            for label in checks:
                box = page.get_by_label(label)
                if box.count():
                    try:
                        box.check()
                    except Exception:
                        pass
            vis = page.get_by_label("Vision modeli kullan")
            if vis.count():
                try:
                    if not vis.is_checked():
                        vis.check()
                except Exception:
                    pass
            click_named(page, "Görüntüyü analiz et")
            page.wait_for_selector("text=Skor:", timeout=300000)
            page.wait_for_timeout(1500)
            page.screenshot(path=str(OUT / out_name), full_page=True)

        # 09 — Mod 3: sahte banka
        run_mod3(
            image=EXAMPLES / "screenshots" / "01_phish_fake_bank_login.png",
            url="http://garanti-guvenlik-dogrula.xyz/login?id=884",
            notes="SMS linkinden geldim; CVV ve OTP istiyor",
            checks=[
                "Adres çubuğunda marka taklidi / garip domain (xyz, IP, ek kelime)",
                "Kilit / HTTPS yok veya tarayıcı uyarıyor",
                "Ekranda aciliyet / korku dili (bloke, son 24 saat, hemen doğrula)",
                "CVV / OTP / kimlik fotoğrafı / seed phrase istiyor",
            ],
            out_name="09_screenshot_phish_bank.png",
        )

        # 10 — Mod 3: meşru tarzı
        run_mod3(
            image=EXAMPLES / "screenshots" / "02_legit_style_login.png",
            url="https://www.example-bank.com.tr/giris",
            notes="",
            checks=[],
            out_name="10_screenshot_legit_style.png",
        )

        # 11 — Mod 3: e-posta phishing örneği
        run_mod3(
            image=EXAMPLES / "screenshots" / "altay" / "resim09_phishing.png",
            url="http://ptt-kargotakip.xyz/takip",
            notes="Gönderici PTT gibi ama domain .xyz; kargo takip tuzağı",
            checks=[
                "Adres çubuğunda marka taklidi / garip domain (xyz, IP, ek kelime)",
                "Kilit / HTTPS yok veya tarayıcı uyarıyor",
                "Banka/kargo için beklenmeyen kanal (SMS linkinden açıldı)",
            ],
            out_name="11_screenshot_email_phish.png",
        )

        browser.close()

    print("Screenshots saved to", OUT)
    for f in sorted(OUT.glob("*.png")):
        print(" -", f.name, f.stat().st_size)


if __name__ == "__main__":
    main()
