"""
SecLens — ana arayüz (Streamlit).

Çalıştırma:
  1) Ollama açık olsun + model indirmiş ol
  2) pip install -r requirements.txt
  3) streamlit run app.py
"""

from __future__ import annotations

import importlib
from pathlib import Path

import streamlit as st

from core.code_rules import RULES
from core.code_scan import analyze_code
from core.ollama_client import DEFAULT_MODEL, OllamaError, is_ollama_up, list_models
from core.phishing import analyze_text
from core.breach_check import BreachCheckError, check_email
from core.screenshot_scan import (
    CHECK_ITEMS,
    analyze_screenshot,
    image_to_png_bytes,
    pick_vision_model,
)
from ui import theme as ui_theme

# Streamlit kısmi reload'da eski theme cache kalabiliyor
ui_theme = importlib.reload(ui_theme)

EXAMPLES_DIR = Path(__file__).parent / "examples"

EXAMPLE_LABELS = {
    "— örnek seç —": "",
    "Phishing (sahte banka)": "phishing_sms.txt",
    "Phishing (sahte kargo)": "phishing_email.txt",
    "Dolandırıcı (uzlaştırma)": "scam_uzlastirma.txt",
    "Spam hediye (maket)": "scam_hediye_maket.txt",
    "Sahte e-Devlet": "scam_edevlet.txt",
    "Sahte kargo/gümrük": "scam_kargo_gumruk.txt",
    "Kripto smishing": "scam_kripto.txt",
    "IBAN/EFT tuzağı": "scam_iban_eft.txt",
    "Valilik onaylı IBAN (IG)": "scam_valilik_iban.txt",
    "OTP + WhatsApp/AnyDesk": "scam_otp_whatsapp.txt",
    "Sahte Apple/tech support": "scam_tech_support.txt",
    "Forex/yatırım tuzağı": "scam_invest_forex.txt",
    "Güvenli SMS": "safe_sms.txt",
    "Güvenli e-posta": "safe_email.txt",
}


RISK_LABEL = {
    "dusuk": "Düşük risk",
    "orta": "Orta risk",
    "yuksek": "Yüksek risk",
}


def load_example(filename: str) -> str:
    path = EXAMPLES_DIR / filename
    return path.read_text(encoding="utf-8") if path.exists() else ""


CODE_EXAMPLE_LABELS = {
    "— zafiyet örneği seç —": "",
    # Bizim eğitim senaryoları (NEDEN açıklamalı)
    "01 Hardcoded secret (CWE-798)": "code/01_hardcoded_secret.py.txt",
    "02 SQL Injection (CWE-89)": "code/02_sql_injection.py.txt",
    "03 Command Injection (CWE-78)": "code/03_command_injection.py.txt",
    "04 XSS innerHTML (CWE-79)": "code/04_xss_innerhtml.js.txt",
    "05 Insecure deserialization (CWE-502)": "code/05_insecure_deserialization.py.txt",
    "06 Path traversal (CWE-22)": "code/06_path_traversal.py.txt",
    "07 SSRF (CWE-918)": "code/07_ssrf.py.txt",
    "08 Zayıf kripto / TLS (CWE-328/295)": "code/08_weak_crypto_tls.py.txt",
    "09 Secret in logs (CWE-532)": "code/09_secret_in_logs.py.txt",
    "10 Güvenli referans (temiz)": "code/10_safe_reference.py.txt",
    "11 Twisted /root + CGI (httpoxy)": "code/11_twisted_httpoxy.py.txt",
    "12 Genişletilmiş kurallar (karma)": "code/12_extended_rules_demo.py.txt",
    "13 IDOR userProfile (CWE-639)": "code/13_idor_user_profile.js.txt",
    "14 PHP SQL Injection (CWE-89)": "code/14_php_sql_injection.php.txt",
    "15 PHP MD5 parola (CWE-328)": "code/15_php_md5_password.php.txt",
    "16 Trojan Source bidi (CVE-2021-42574)": "code/external/trojansource.py",
    "Hepsi bir arada (karma)": "code_bad.py.txt",
    "Bandit: trojansource": "code/external/trojansource.py",
    "Bandit: xml_sax (XXE)": "code/external/xml_sax.py",
    "Bandit: xml_etree (XXE)": "code/external/xml_etree_elementtree.py",
    "Bandit: xml_minidom (XXE)": "code/external/xml_minidom.py",
    # Bandit resmi örnekleri (harici SAST testi)
    "Bandit: hardcoded-passwords": "code/external/hardcoded-passwords.py",
    "Bandit: subprocess_shell": "code/external/subprocess_shell.py",
    "Bandit: os_system": "code/external/os_system.py",
    "Bandit: pickle_deserialize": "code/external/pickle_deserialize.py",
    "Bandit: eval": "code/external/eval.py",
    "Bandit: crypto-md5": "code/external/crypto-md5.py",
    "Bandit: flask_debug": "code/external/flask_debug.py",
    "Bandit: django SQL raw": "code/external/django_sql_injection_raw.py",
    "Bandit: jinja2_templating": "code/external/jinja2_templating.py",
    "Bandit: mark_safe_insecure": "code/external/mark_safe_insecure.py",
    "Bandit: tarfile_extractall": "code/external/tarfile_extractall.py",
    "Bandit: telnetlib": "code/external/telnetlib.py",
    "Bandit: yaml_load": "code/external/yaml_load.py",
    "Bandit: requests-ssl-verify-disabled": "code/external/requests-ssl-verify-disabled.py",
    "Bandit: ssl-insecure-version": "code/external/ssl-insecure-version.py",
    "Bandit: no_host_key_verification": "code/external/no_host_key_verification.py",
    "Bandit: mktemp": "code/external/mktemp.py",
    "Bandit: assert": "code/external/assert.py",
    "Bandit: ftplib": "code/external/ftplib.py",
    "Bandit: marshal_deserialize": "code/external/marshal_deserialize.py",
    "Bandit: unverified_context": "code/external/unverified_context.py",
    "Bandit: okay (temiz)": "code/external/okay.py",
}


_PAGE_ICON = Path(__file__).parent / "assets" / "seclens-mark.png"
st.set_page_config(
    page_title="SecLens",
    page_icon=str(_PAGE_ICON) if _PAGE_ICON.exists() else "◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

ui_theme.inject()
ui_theme.hero(modes_ready=4)

# --- Sol kenar: Ollama durumu ---
with st.sidebar:
    ui_theme.sidebar_brand()
    st.markdown("##### Ayarlar")
    ollama_ok = is_ollama_up()
    if ollama_ok:
        st.markdown(
            '<div class="sl-status sl-status--ok">Ollama bağlı</div>',
            unsafe_allow_html=True,
        )
        try:
            models = list_models()
        except OllamaError:
            models = []
        if models:
            default_idx = 0
            for i, name in enumerate(models):
                if DEFAULT_MODEL in name:
                    default_idx = i
                    break
            # Vision varsa listede göster ama varsayılan metin modeli kalsın
            model = st.selectbox("Metin modeli", models, index=default_idx)
        else:
            st.warning(f"Model yok — `ollama pull {DEFAULT_MODEL}`")
            model = DEFAULT_MODEL
    else:
        st.markdown(
            '<div class="sl-status sl-status--bad">Ollama kapalı</div>',
            unsafe_allow_html=True,
        )
        st.markdown(
            "Ollama uygulamasını aç, sonra:\n\n"
            f"`ollama pull {DEFAULT_MODEL}`\n\n"
            "`ollama pull moondream`"
        )
        model = st.text_input("Model adı", value=DEFAULT_MODEL)

    vision = pick_vision_model() if ollama_ok else None
    if vision:
        st.caption(f"Vision: `{vision}`")
    else:
        st.caption("Vision: kurulu değil (Mod 3 opsiyonel)")

    st.divider()
    st.caption("MIT · yerel modeller")

    st.session_state["model"] = model

# --- Dört sekme ---
tab_text, tab_code, tab_image, tab_breach = st.tabs(
    [
        "Metin",
        "Kod",
        "Görüntü",
        "E-posta sızıntı",
    ]
)

with tab_text:
    st.subheader("Metin · Türkçe phishing / smishing")
    st.write(
        "SMS veya e-posta yapıştır → **Analiz et**. "
        "Skor kurallardan; gerekçe yerel modelden."
    )

    choice = st.selectbox("Hazır örnekler (TR dolandırıcılık kalıpları)", list(EXAMPLE_LABELS.keys()))
    if choice and EXAMPLE_LABELS[choice]:
        if st.button("Örneği yükle", key="load_example"):
            st.session_state["phishing_text"] = load_example(EXAMPLE_LABELS[choice])

    text = st.text_area(
        "Metni yapıştır",
        height=180,
        key="phishing_text",
        placeholder="Örn: Banka hesabınız bloke oldu, hemen tıklayın...",
    )

    run = st.button("Analiz et", type="primary", key="btn_text", disabled=not ollama_ok)

    if run:
        if not (text or "").strip():
            st.warning("Önce bir metin yapıştır veya örnek seç.")
        else:
            with st.spinner(
                "Kurallar + LLM birlikte çalışıyor… "
                "(llama3.2:1b bazen 15–60 sn sürebilir, bekleyin)"
            ):
                try:
                    result = analyze_text(text, model=model)
                except OllamaError as e:
                    st.error(str(e))
                    result = None

            if result is not None:
                title = RISK_LABEL.get(result.risk, "Bilinmiyor")
                ui_theme.risk_banner(
                    result.risk,
                    title,
                    result.skor,
                    extra=f"kural {result.kural_skoru}",
                )
                st.progress(result.skor / 100.0)

                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Gerekçeler**")
                    for g in result.gerekceler or ["—"]:
                        st.markdown(f"- {g}")
                with c2:
                    st.markdown("**Öneriler**")
                    for o in result.oneriler or ["—"]:
                        st.markdown(f"- {o}")

                status = getattr(result, "llm_status", "ok")
                if status == "ok":
                    with st.expander("Ham model cevabı"):
                        st.code(result.ham)
                elif status == "failed":
                    st.warning("LLM çağrısı başarısız; skor kurallardan.")
                    st.code(result.ham)
                elif status == "bad_json":
                    st.warning("LLM JSON bozuldu; kurallar + ham metin:")
                    st.code(result.ham)
                else:
                    with st.expander("Ham / durum"):
                        st.code(result.ham)

with tab_code:
    st.subheader("Kod · mini-SAST")
    st.write(
        f"**{len(RULES)} kural** · OWASP / CWE odaklı pattern tarama. "
        "Eğitim amaçlıdır; Semgrep/CodeQL yerine geçmez."
    )

    code_choice = st.selectbox(
        "Test senaryoları (her dosyada NEDEN zafiyet olduğu yazılı)",
        list(CODE_EXAMPLE_LABELS.keys()),
        key="code_example_choice",
    )
    if st.button("Örneği yükle", key="load_code_example"):
        fname = CODE_EXAMPLE_LABELS.get(code_choice, "")
        if fname:
            st.session_state["code_text"] = load_example(fname)

    code = st.text_area(
        "Kod yapıştır",
        height=300,
        key="code_text",
        placeholder='Örn: password = "123456"  veya  f"SELECT ... {user_id}"',
    )

    run_code = st.button("Tara", type="primary", key="btn_code")
    if run_code:
        if not (code or "").strip():
            st.warning("Önce kod yapıştır veya örnek yükle.")
        else:
            with st.spinner("Kod taranıyor (OWASP/CWE kuralları)…"):
                report = analyze_code(code, model=model)
            scan = report.scan
            title = RISK_LABEL.get(scan.risk, "Bilinmiyor")
            ui_theme.risk_banner(scan.risk, title, scan.skor, extra=scan.ozet[:80])
            st.progress(scan.skor / 100.0)
            st.caption(report.llm_note)

            if scan.by_owasp:
                st.markdown("**OWASP dağılımı**")
                for cat, n in sorted(scan.by_owasp.items(), key=lambda x: -x[1]):
                    st.markdown(f"- `{cat}` → **{n}** bulgu")

            if not scan.findings:
                st.success("Bu kural setine göre kritik bulgu yok.")
            else:
                for f in scan.findings:
                    badge = {"high": "HIGH", "medium": "MED", "low": "LOW"}.get(
                        f.severity, "?"
                    )
                    with st.expander(
                        f"[{badge}] L{f.line} · {f.rule_id} · {f.title}",
                        expanded=f.severity == "high",
                    ):
                        st.markdown(
                            f"**OWASP:** `{f.owasp}` · **CWE:** `{f.cwe}` · "
                            f"**Şiddet:** `{f.severity}`"
                        )
                        st.markdown(f"**Açıklama:** {f.detail}")
                        st.code(f.snippet, language="text")
                        st.markdown(f"**Düzeltme:** {f.fix}")

with tab_image:
    st.subheader("Login / e-posta screenshot (phishing UI)")
    st.write(
        "PNG/JPG yükle veya örnek seç. Skor **checklist + URL/not** ile çıkar; "
        "kuruluysa Ollama vision (`moondream` / `llava`) görsele bakar, "
        "yoksa metin modeli gerekçe yazar."
    )

    import json as _json

    SCREENSHOT_EXAMPLES = {
        "— örnek seç —": "",
        "Demo · Sahte banka login": "screenshots/01_phish_fake_bank_login.png",
        "Demo · Meşru tarzı login": "screenshots/02_legit_style_login.png",
        "Demo · Sahte kargo/gümrük": "screenshots/03_phish_cargo_customs.png",
    }
    SCREENSHOT_URL_HINTS = {
        "screenshots/01_phish_fake_bank_login.png": "http://garanti-guvenlik-dogrula.xyz/login?id=884",
        "screenshots/02_legit_style_login.png": "https://www.example-bank.com.tr/giris",
        "screenshots/03_phish_cargo_customs.png": "http://192.168.8.22/ptt-gumruk-odeme.top/pay",
    }
    SCREENSHOT_CHECK_HINTS = {
        "screenshots/01_phish_fake_bank_login.png": {
            "url_lookalike": True,
            "no_https": True,
            "urgency": True,
            "ask_extra": True,
            "spelling": True,
            "unexpected_channel": True,
        },
        "screenshots/02_legit_style_login.png": {},
        "screenshots/03_phish_cargo_customs.png": {
            "url_lookalike": True,
            "no_https": True,
            "urgency": True,
            "ask_extra": True,
            "unexpected_channel": True,
        },
    }
    SCREENSHOT_NOTE_HINTS: dict[str, str] = {}
    SCREENSHOT_TRUTH: dict[str, str] = {}

    _manifest_path = EXAMPLES_DIR / "screenshots" / "altay" / "manifest.json"
    if _manifest_path.exists():
        for item in _json.loads(_manifest_path.read_text(encoding="utf-8")):
            path = item["path"]
            tag = "PHISH" if item["correct"] == "phishing" else "GERÇEK"
            label = f"Örnek {item['id']:02d} · {tag}"
            SCREENSHOT_EXAMPLES[label] = path
            SCREENSHOT_URL_HINTS[path] = item.get("url_hint") or ""
            SCREENSHOT_CHECK_HINTS[path] = item.get("checked") or {}
            SCREENSHOT_NOTE_HINTS[path] = item.get("notes") or ""
            SCREENSHOT_TRUTH[path] = item["correct"]

    ss_choice = st.selectbox(
        "Hazır screenshot örnekleri",
        list(SCREENSHOT_EXAMPLES.keys()),
        key="ss_example_choice",
    )
    if st.button("Örneği yükle", key="load_ss_example"):
        fname = SCREENSHOT_EXAMPLES.get(ss_choice, "")
        if fname:
            raw = (EXAMPLES_DIR / fname).read_bytes()
            st.session_state["ss_bytes"] = image_to_png_bytes(raw)
            st.session_state["ss_name"] = Path(fname).name
            st.session_state["ss_url"] = SCREENSHOT_URL_HINTS.get(fname, "")
            st.session_state["ss_notes"] = SCREENSHOT_NOTE_HINTS.get(fname, "")
            st.session_state["ss_truth"] = SCREENSHOT_TRUTH.get(fname, "")
            hints = SCREENSHOT_CHECK_HINTS.get(fname, {})
            for cid, _, _ in CHECK_ITEMS:
                st.session_state[f"ss_chk_{cid}"] = bool(hints.get(cid))

    uploaded = st.file_uploader("PNG / JPG yükle", type=["png", "jpg", "jpeg"])
    if uploaded is not None:
        st.session_state["ss_bytes"] = image_to_png_bytes(uploaded.getvalue())
        st.session_state["ss_name"] = uploaded.name

    if st.session_state.get("ss_bytes"):
        st.image(
            st.session_state["ss_bytes"],
            caption=st.session_state.get("ss_name", "önizleme"),
            use_container_width=True,
        )

    url_bar = st.text_input(
        "Adres çubuğunda ne görüyorsun? (varsa yapıştır)",
        key="ss_url",
        placeholder="örn. http://garanti-guvenlik-dogrula.xyz/login",
    )
    notes = st.text_area(
        "Ek not (opsiyonel)",
        key="ss_notes",
        height=80,
        placeholder="SMS’ten geldim, logo bulanık, CVV istiyor…",
    )

    st.markdown("**Görsel checklist** (gördüklerini işaretle)")
    checked: dict[str, bool] = {}
    cols = st.columns(2)
    for i, (cid, label, _) in enumerate(CHECK_ITEMS):
        with cols[i % 2]:
            checked[cid] = st.checkbox(label, key=f"ss_chk_{cid}")

    vision_available = pick_vision_model() if ollama_ok else None
    if vision_available:
        st.caption(f"Vision model bulundu: `{vision_available}` (opsiyonel kullanılacak)")
        use_vision = st.checkbox("Vision modeli kullan", value=True, key="ss_use_vision")
    else:
        st.caption(
            "Vision model yok — checklist + metin LLM yeterli. "
            "İstersen: `ollama pull moondream`"
        )
        use_vision = False

    run_ss = st.button(
        "Görüntüyü analiz et",
        type="primary",
        key="btn_image",
        disabled=not st.session_state.get("ss_bytes"),
    )
    if run_ss:
        with st.spinner("Screenshot analiz ediliyor…"):
            result = analyze_screenshot(
                st.session_state["ss_bytes"],
                url_bar=url_bar or "",
                notes=notes or "",
                checked=checked,
                filename=st.session_state.get("ss_name", ""),
                model=st.session_state.get("model", DEFAULT_MODEL),
                use_vision=use_vision,
            )
        label = RISK_LABEL.get(result.risk, result.risk)
        extra = (
            f"kural {result.kural_skoru} · vision {result.vision_model}"
            if result.vision_used
            else f"kural {result.kural_skoru} · vision kapalı"
        )
        ui_theme.risk_banner(result.risk, label, result.skor, extra=extra)
        st.progress(min(100, max(0, result.skor)) / 100.0)
        st.markdown("**Gerekçeler**")
        for g in result.gerekceler:
            st.markdown(f"- {g}")
        st.markdown("**Öneriler**")
        for o in result.oneriler:
            st.markdown(f"- {o}")
        if result.findings:
            with st.expander("Checklist bulguları"):
                for f in result.findings:
                    st.markdown(f"- **{f.title}** (+{f.weight}) — {f.detail}")
        truth = st.session_state.get("ss_truth") or ""
        if truth:
            pred = "phishing" if result.skor >= 40 else "real"
            if pred == truth:
                st.success(
                    f"Beklenen etiket ile uyumlu: **{truth}**, SecLens skoru {result.skor}."
                )
            else:
                st.warning(
                    f"Beklenen **{truth}**, SecLens tahmini **{pred}** (skor {result.skor})."
                )
        if result.llm_status not in ("ok",):
            st.caption(f"LLM durumu: {result.llm_status}")
            if result.ham:
                with st.expander("Ham çıktı / hata"):
                    st.code(result.ham[:2000])

with tab_breach:
    st.subheader("E-posta sızıntı kontrolü (XposedOrNot)")
    st.write(
        "E-posta adresinin bilinen veri ihlallerinde görünüp görünmediğini "
        "[XposedOrNot](https://xposedornot.com) ücretsiz API’si ile kontrol eder. "
        "**API anahtarı gerekmez.** Adres yalnızca XposedOrNot’a gider; SecLens saklamaz."
    )
    st.caption(
        "Rate limit (ücretsiz): ~2 istek/sn, 25/saat, 100/gün · "
        "[API docs](https://xposedornot.com/api_doc)"
    )

    email_in = st.text_input(
        "E-posta adresi",
        key="breach_email",
        placeholder="ornek@domain.com",
    )
    run_breach = st.button("Sızıntı kontrol et", type="primary", key="btn_breach")

    if run_breach:
        with st.spinner("XposedOrNot sorgulanıyor…"):
            try:
                br = check_email(email_in)
            except BreachCheckError as e:
                st.error(str(e))
                br = None

        if br is not None:
            if br.error and br.ham_status == "invalid":
                st.warning(br.error)
            elif not br.found:
                ui_theme.risk_banner(
                    "dusuk",
                    "Sızıntıda görünmüyor",
                    5,
                    extra="XposedOrNot indeksi",
                )
                st.markdown("**Öneriler**")
                for o in br.oneriler:
                    st.markdown(f"- {o}")
            else:
                score = br.risk_score if br.risk_score is not None else min(
                    100, 40 + len(br.breaches)
                )
                risk_key = (
                    "yuksek"
                    if score >= 65
                    else "orta"
                    if score >= 30
                    else "dusuk"
                )
                ui_theme.risk_banner(
                    risk_key,
                    f"Sızıntıda bulundu · {len(br.breaches)} ihlal",
                    int(score),
                    extra=f"XposedOrNot {br.risk_label or 'risk'}",
                )
                st.progress(min(100, max(0, int(score))) / 100.0)
                if br.password_hint:
                    st.markdown("**Parola sızıntısı özeti (indeks)**")
                    st.json(br.password_hint)
                if br.xposed_summary:
                    st.markdown("**Sızan veri kategorileri (özet)**")
                    for x in br.xposed_summary:
                        st.markdown(f"- {x}")
                st.markdown("**İhlaller**")
                # Çok uzun listeleri kısalt
                show = br.breaches[:80]
                cols = st.columns(3)
                for i, name in enumerate(show):
                    cols[i % 3].markdown(f"- `{name}`")
                if len(br.breaches) > 80:
                    st.caption(f"… ve {len(br.breaches) - 80} ihlal daha")
                st.markdown("**Öneriler**")
                for o in br.oneriler:
                    st.markdown(f"- {o}")
                st.info(
                    "Detaylı rapor / alert: [xposedornot.com](https://xposedornot.com)"
                )

ui_theme.footnote()
