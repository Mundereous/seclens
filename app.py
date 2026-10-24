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
            with st.spinner("Model düşünüyor..."):
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

                if not result.json_ok:
                    st.warning("JSON tam parse edilemedi; ham model cevabı:")
                    st.code(result.ham)
                else:
                    with st.expander("Ham model cevabı"):
                        st.code(result.ham)

with tab_code:
    st.subheader("Kod snippet güvenlik taraması")
    st.info("Bu sekme daha sonra doldurulacak (Mod 4).")
    code = st.text_area(
        "Kod yapıştır",
        height=200,
        placeholder='Örn: password = "123456"',
    )
    if st.button("Tara (yakında)", key="btn_code", disabled=True):
        st.code(code)

with tab_image:
    st.subheader("Login ekranı screenshot")
    st.info("Bu sekme en son doldurulacak (Mod 3 — daha zor).")
    uploaded = st.file_uploader("PNG / JPG yükle", type=["png", "jpg", "jpeg"])
    if uploaded is not None:
        st.image(uploaded, caption="Önizleme", use_container_width=True)
    if st.button("Görüntüyü analiz et (yakında)", key="btn_image", disabled=True):
        st.write("Yakında")
