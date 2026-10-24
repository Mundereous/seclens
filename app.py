"""
SecLens — ana arayüz (Streamlit).

Çalıştırma:
  1) Ollama açık olsun + model indirmiş ol
  2) pip install -r requirements.txt
  3) streamlit run app.py
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from core.code_rules import RULES
from core.code_scan import analyze_code
from core.ollama_client import DEFAULT_MODEL, OllamaError, is_ollama_up, list_models
from core.phishing import analyze_text

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
    "dusuk": ("Düşük risk", "🟢"),
    "orta": ("Orta risk", "🟡"),
    "yuksek": ("Yüksek risk", "🔴"),
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


st.set_page_config(
    page_title="SecLens",
    page_icon="🔎",
    layout="wide",
)

st.title("SecLens")
st.caption(
    "Open-weight AI güvenlik asistanı — metin phishing, kod tarama, login screenshot. "
    "Eğitim amaçlıdır; gerçek antivirüs / uzman görüşü yerine geçmez."
)

# --- Sol kenar: Ollama durumu ---
with st.sidebar:
    st.header("Ayarlar")
    ollama_ok = is_ollama_up()
    if ollama_ok:
        st.success("Ollama çalışıyor")
        try:
            models = list_models()
        except OllamaError:
            models = []
        if models:
            # Varsayılan modeli mümkünse seç
            default_idx = 0
            for i, name in enumerate(models):
                if DEFAULT_MODEL in name:
                    default_idx = i
                    break
            model = st.selectbox("Model", models, index=default_idx)
        else:
            st.warning(f"Kurulu model yok. Terminalde: `ollama pull {DEFAULT_MODEL}`")
            model = DEFAULT_MODEL
    else:
        st.error("Ollama kapalı / bulunamadı")
        st.markdown(
            "Applications → **Ollama** uygulamasını aç, sonra: "
            f"`ollama pull {DEFAULT_MODEL}`"
        )
        model = st.text_input("Model adı (sonra)", value=DEFAULT_MODEL)

    st.session_state["model"] = model

# --- Üç sekme ---
tab_text, tab_code, tab_image = st.tabs(
    ["1 · Metin (phishing)", "2 · Kod (güvenlik)", "3 · Görüntü (screenshot)"]
)

with tab_text:
    st.subheader("Türkçe e-posta / SMS analizi")
    st.write(
        "Metni yapıştır veya örnek seç → **Analiz et**. "
        "Kurallar (BTK/Emniyet/PTT kalıpları) + yerel open-weight model."
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
                title, icon = RISK_LABEL.get(result.risk, ("Bilinmiyor", "⚪"))
                st.markdown(f"### {icon} {title}")
                st.progress(
                    result.skor / 100.0,
                    text=f"Skor: {result.skor}/100 (kural: {result.kural_skoru})",
                )

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
                    st.success("LLM cevap verdi.")
                    with st.expander("Ham model cevabı", expanded=True):
                        st.code(result.ham)
                elif status == "failed":
                    st.warning("LLM çağrısı başarısız; skor kurallardan.")
                    st.code(result.ham)
                elif status == "bad_json":
                    st.warning("LLM cevap verdi ama JSON bozuldu; kurallar + ham metin:")
                    st.code(result.ham)
                else:
                    with st.expander("Ham / durum"):
                        st.code(result.ham)

with tab_code:
    st.subheader("Kod snippet güvenlik taraması (mini-SAST)")
    st.write(
        f"**{len(RULES)} kural** · OWASP Top 10 + CWE (Bandit/Semgrep kalıpları): "
        "secrets, SQLi, RCE, XSS, deserialization, path traversal, SSRF, zayıf kripto, "
        "JWT, CGI/httpoxy, tar slip, Telnet/FTP… "
        "(Eğitim amaçlı pattern eşleme — Semgrep/CodeQL değildir.)"
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
            title, icon = RISK_LABEL.get(scan.risk, ("Bilinmiyor", "⚪"))
            st.markdown(f"### {icon} {title}")
            st.progress(
                scan.skor / 100.0,
                text=f"Risk skoru: {scan.skor}/100 — {scan.ozet}",
            )
            st.caption(report.llm_note)

            if scan.by_owasp:
                st.markdown("**OWASP dağılımı**")
                for cat, n in sorted(scan.by_owasp.items(), key=lambda x: -x[1]):
                    st.markdown(f"- `{cat}` → **{n}** bulgu")

            if not scan.findings:
                st.success("Bu kural setine göre kritik bulgu yok.")
            else:
                for f in scan.findings:
                    badge = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                        f.severity, "⚪"
                    )
                    with st.expander(
                        f"{badge} L{f.line} · {f.rule_id} · {f.title}",
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
    st.subheader("Login ekranı screenshot")
    st.info("Bu sekme en son doldurulacak (Mod 3 — daha zor).")
    uploaded = st.file_uploader("PNG / JPG yükle", type=["png", "jpg", "jpeg"])
    if uploaded is not None:
        st.image(uploaded, caption="Önizleme", use_container_width=True)
    if st.button("Görüntüyü analiz et (yakında)", key="btn_image", disabled=True):
        st.write("Yakında")
