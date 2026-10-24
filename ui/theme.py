"""SecLens UI — kurumsal konsol + sunum için premium yüzey."""

from __future__ import annotations

import base64
from pathlib import Path

import streamlit as st

ASSETS = Path(__file__).resolve().parent.parent / "assets"
_LOGO_JPG = ASSETS / "seclens-logo.jpg"
_MARK_SVG = ASSETS / "seclens-mark.svg"
_MARK_PNG = ASSETS / "seclens-mark.png"


def _data_uri(path: Path, mime: str) -> str:
    if not path.exists():
        return ""
    return f"data:{mime};base64,{base64.b64encode(path.read_bytes()).decode()}"


def logo_uri() -> str:
    uri = _data_uri(_LOGO_JPG, "image/jpeg")
    if uri:
        return uri
    return _data_uri(_MARK_PNG, "image/png") or _svg_data_uri()


def mark_uri() -> str:
    return _data_uri(_MARK_PNG, "image/png") or logo_uri() or _svg_data_uri()


def _svg_data_uri() -> str:
    if not _MARK_SVG.exists():
        return ""
    return f"data:image/svg+xml;base64,{base64.b64encode(_MARK_SVG.read_bytes()).decode()}"


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@24,400,0,0&display=swap');

:root {
  --bg: #0A0E14;
  --bg-lift: #0F141C;
  --panel: #141B24;
  --panel-2: #1A2330;
  --ink: #F0F4F8;
  --ink-2: #B8C5D4;
  --mute: #8494A7;
  --line: #273140;
  --line-2: #3A4A5C;
  --accent: #3EB9A5;
  --accent-deep: #1F8A78;
  --accent-soft: rgba(62, 185, 165, 0.14);
  --gold: #C9A227;
  --ok: #3FA66A;
  --warn: #C4922A;
  --bad: #C45C3A;
  --font: "IBM Plex Sans", "Segoe UI", sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, monospace;
  --r: 6px;
  --elev: 0 10px 28px rgba(0, 0, 0, 0.38);
}

html, body, .stApp {
  font-family: var(--font) !important;
  font-size: 15px !important;
}

.stApp {
  background:
    linear-gradient(180deg, #0C121A 0%, var(--bg) 42%, #090D12 100%) !important;
  color: var(--ink) !important;
}

#MainMenu { visibility: hidden; }
footer { visibility: hidden; }
header[data-testid="stHeader"] {
  background: rgba(10, 14, 20, 0.82) !important;
  backdrop-filter: blur(8px);
  border-bottom: 1px solid transparent;
}
[data-testid="stToolbar"] { right: 0.5rem; }

.block-container {
  padding-top: 1rem !important;
  padding-bottom: 2.25rem !important;
  max-width: 1100px !important;
}

.stMarkdown, .stMarkdown p, label, [data-testid="stWidgetLabel"] {
  font-family: var(--font) !important;
}

/* —— Premium top brand strip —— */
.sl-top {
  position: relative;
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 1.15rem 1.35rem;
  align-items: center;
  margin: 0 0 1.35rem 0;
  padding: 1.35rem 1.5rem 1.4rem;
  border-radius: 10px;
  border: 1px solid var(--line-2);
  background:
    linear-gradient(125deg, rgba(62, 185, 165, 0.09) 0%, transparent 42%),
    linear-gradient(180deg, #1A2431 0%, #121820 100%);
  box-shadow: var(--elev);
  overflow: hidden;
  animation: sl-enter 0.55s ease-out both;
}
.sl-top::before {
  content: "";
  position: absolute;
  inset: 0 0 auto 0;
  height: 2px;
  background: linear-gradient(90deg, var(--accent) 0%, var(--gold) 48%, transparent 100%);
}
.sl-top::after {
  content: "";
  position: absolute;
  inset: 0;
  background-image:
    linear-gradient(rgba(240,244,248,0.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(240,244,248,0.035) 1px, transparent 1px);
  background-size: 32px 32px;
  mask-image: linear-gradient(180deg, rgba(0,0,0,0.45), transparent 70%);
  pointer-events: none;
}
.sl-top > * { position: relative; z-index: 1; }
.sl-top img {
  width: 56px;
  height: 56px;
  object-fit: contain;
  background: #F5F7FA;
  border: 1px solid rgba(240,244,248,0.25);
  border-radius: 8px;
  padding: 4px;
  box-shadow: 0 6px 16px rgba(0,0,0,0.35);
}
.sl-top-text { min-width: 0; }
.sl-top-row {
  display: flex;
  align-items: baseline;
  gap: 0.85rem;
  flex-wrap: wrap;
  margin-bottom: 0.35rem;
}
.sl-name {
  margin: 0 !important;
  font-family: var(--font) !important;
  font-size: clamp(1.65rem, 3vw, 2rem) !important;
  font-weight: 700 !important;
  letter-spacing: -0.03em;
  color: #FFFFFF !important;
  line-height: 1.1 !important;
}
.sl-name span { color: var(--accent); }
.sl-meta {
  font-family: var(--mono) !important;
  font-size: 0.7rem !important;
  color: var(--gold) !important;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border: 1px solid rgba(201, 162, 39, 0.35);
  background: rgba(201, 162, 39, 0.08);
  padding: 0.2rem 0.5rem;
  border-radius: 3px;
}
.sl-desc {
  margin: 0 !important;
  font-size: 1rem !important;
  line-height: 1.5 !important;
  color: var(--ink-2) !important;
  max-width: 38rem;
  font-weight: 400 !important;
}

@keyframes sl-enter {
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #10161F 0%, #0C1118 100%) !important;
  border-right: 1px solid var(--line);
}
section[data-testid="stSidebar"] > div { background: transparent !important; }
section[data-testid="stSidebar"] .stMarkdown,
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] small,
section[data-testid="stSidebar"] [data-testid="stCaption"],
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
  color: var(--ink-2) !important;
}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] h5 {
  font-family: var(--font) !important;
  color: var(--ink) !important;
  font-weight: 600 !important;
  font-size: 0.92rem !important;
}
section[data-testid="stSidebar"] [data-baseweb="select"] > div,
section[data-testid="stSidebar"] input {
  background: var(--panel) !important;
  border-color: var(--line-2) !important;
  color: var(--ink) !important;
  border-radius: var(--r) !important;
}
.sl-side-brand {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  margin-bottom: 1.1rem;
  padding: 0.75rem;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
}
.sl-side-brand img {
  width: 36px;
  height: 36px;
  border-radius: 6px;
  background: #F5F7FA;
  padding: 2px;
}
.sl-side-brand strong {
  display: block;
  font-size: 1rem;
  color: #FFFFFF !important;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.sl-side-brand em {
  display: block;
  font-style: normal;
  font-size: 0.7rem;
  color: var(--accent) !important;
  font-family: var(--mono);
  letter-spacing: 0.03em;
}
hr { border-color: var(--line) !important; }

.sl-status {
  display: inline-block;
  font-family: var(--mono) !important;
  font-size: 0.75rem !important;
  font-weight: 600;
  padding: 0.4rem 0.65rem;
  border-radius: var(--r);
  margin-bottom: 0.85rem;
  border: 1px solid transparent;
}
.sl-status--ok {
  color: #A8E0C0 !important;
  background: rgba(63, 166, 106, 0.16);
  border-color: rgba(63, 166, 106, 0.4);
}
.sl-status--bad {
  color: #F0C4B4 !important;
  background: rgba(196, 92, 58, 0.16);
  border-color: rgba(196, 92, 58, 0.45);
}
.sl-dot { display: none; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
  gap: 0.15rem;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 0.3rem;
  margin-bottom: 1rem;
  box-shadow: 0 4px 14px rgba(0,0,0,0.2);
}
.stTabs [data-baseweb="tab"] {
  font-family: var(--font) !important;
  font-weight: 500 !important;
  font-size: 0.9rem !important;
  color: var(--mute) !important;
  background: transparent !important;
  border-radius: 5px !important;
  padding: 0.65rem 1.05rem !important;
  border: none !important;
  transition: color 0.15s ease, background 0.15s ease;
}
.stTabs [aria-selected="true"] {
  color: #FFFFFF !important;
  background: var(--accent-soft) !important;
  box-shadow: inset 0 0 0 1px rgba(62, 185, 165, 0.45);
}
.stTabs [data-baseweb="tab"] p {
  color: inherit !important;
  font-weight: 600 !important;
}
.stTabs [data-baseweb="tab-highlight"],
.stTabs [data-baseweb="tab-border"] {
  display: none !important;
}

/* Buttons */
.stButton > button,
.stDownloadButton > button,
button[kind="primary"],
button[kind="secondary"],
button[data-testid="baseButton-primary"],
button[data-testid="baseButton-secondary"],
button[data-testid="stBaseButton-secondary"],
div[data-testid="stButton"] > button {
  font-family: var(--font) !important;
  font-weight: 600 !important;
  font-size: 0.92rem !important;
  border-radius: var(--r) !important;
  min-height: 2.55rem !important;
  padding: 0.5rem 1.15rem !important;
  letter-spacing: 0.01em !important;
  transition: background 0.15s ease, border-color 0.15s ease, box-shadow 0.15s ease !important;
}
.stButton > button[kind="primary"],
.stButton > button[data-testid="baseButton-primary"],
button[kind="primary"],
button[data-testid="baseButton-primary"],
div[data-testid="stButton"] > button[kind="primary"] {
  background: var(--accent-deep) !important;
  background-image: linear-gradient(180deg, #2AA892 0%, var(--accent-deep) 100%) !important;
  color: #FFFFFF !important;
  border: 1px solid #177868 !important;
  box-shadow: 0 1px 0 rgba(255,255,255,0.12) inset, 0 8px 18px rgba(31, 138, 120, 0.28) !important;
}
.stButton > button[kind="primary"]:hover,
button[data-testid="baseButton-primary"]:hover {
  background: var(--accent) !important;
  background-image: linear-gradient(180deg, #4CCFBA 0%, #2AA892 100%) !important;
  box-shadow: 0 1px 0 rgba(255,255,255,0.16) inset, 0 10px 22px rgba(62, 185, 165, 0.35) !important;
}
.stButton > button[kind="primary"] p,
button[data-testid="baseButton-primary"] p,
.stButton > button[kind="primary"] span {
  color: #FFFFFF !important;
  font-weight: 700 !important;
}
.stButton > button:not([kind="primary"]),
button[data-testid="baseButton-secondary"],
button[data-testid="stBaseButton-secondary"],
div[data-testid="stButton"] > button:not([kind="primary"]) {
  background: var(--panel-2) !important;
  border: 1px solid var(--line-2) !important;
  color: var(--ink) !important;
  box-shadow: none !important;
}
.stButton > button:not([kind="primary"]) p,
button[data-testid="stBaseButton-secondary"] p {
  color: var(--ink) !important;
  font-weight: 600 !important;
}
.stButton > button:not([kind="primary"]):hover {
  border-color: var(--accent) !important;
  background: #203040 !important;
}

/* Inputs */
.stTextInput input,
.stTextArea textarea,
[data-baseweb="select"] > div,
.stNumberInput input {
  border-radius: var(--r) !important;
  border: 1px solid var(--line-2) !important;
  background: var(--panel) !important;
  color: var(--ink) !important;
  font-family: var(--font) !important;
  font-size: 0.94rem !important;
}
[data-baseweb="select"] > div,
[data-baseweb="select"] > div > div,
[data-baseweb="select"] span {
  background-color: var(--panel) !important;
  color: var(--ink) !important;
}
.stTextInput input::placeholder,
.stTextArea textarea::placeholder {
  color: var(--mute) !important;
  opacity: 1 !important;
}
.stTextArea textarea {
  font-family: var(--mono) !important;
  font-size: 0.86rem !important;
  line-height: 1.5 !important;
}
.stTextInput input:focus,
.stTextArea textarea:focus,
[data-baseweb="select"] > div:focus-within {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 2px rgba(62, 185, 165, 0.22) !important;
  background: var(--panel-2) !important;
}
[data-baseweb="popover"] [data-baseweb="menu"],
[data-baseweb="popover"] ul,
ul[role="listbox"],
li[role="option"] {
  background-color: var(--panel) !important;
  color: var(--ink) !important;
  border-color: var(--line) !important;
}
li[role="option"]:hover,
li[role="option"][aria-selected="true"] {
  background-color: var(--panel-2) !important;
}
[data-baseweb="select"] svg { fill: var(--mute) !important; }

label, [data-testid="stWidgetLabel"] p {
  color: var(--ink) !important;
  font-weight: 600 !important;
  font-size: 0.9rem !important;
}

h1, h2, h3, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3 {
  font-family: var(--font) !important;
  color: #FFFFFF !important;
  font-weight: 600 !important;
  letter-spacing: -0.02em;
}
.stMarkdown p, [data-testid="stMarkdownContainer"] p {
  color: var(--ink-2) !important;
  font-size: 0.95rem !important;
  line-height: 1.55 !important;
}
.stMarkdown a, a {
  color: var(--accent) !important;
  font-weight: 600 !important;
  text-decoration: underline;
  text-underline-offset: 2px;
}

/* Risk */
.sl-risk {
  display: flex;
  align-items: center;
  gap: 0.9rem;
  padding: 1rem 1.15rem;
  border-radius: 8px;
  margin: 0.85rem 0 1rem;
  border: 1px solid var(--line-2);
  background: var(--panel);
  box-shadow: 0 6px 16px rgba(0,0,0,0.22);
  animation: sl-enter 0.4s ease-out both;
}
.sl-risk--dusuk {
  background: linear-gradient(90deg, rgba(63,166,106,0.18), var(--panel) 55%);
  border-color: rgba(63,166,106,0.4);
}
.sl-risk--orta {
  background: linear-gradient(90deg, rgba(196,146,42,0.18), var(--panel) 55%);
  border-color: rgba(196,146,42,0.4);
}
.sl-risk--yuksek {
  background: linear-gradient(90deg, rgba(196,92,58,0.2), var(--panel) 55%);
  border-color: rgba(196,92,58,0.45);
}
.sl-risk-mark {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex-shrink: 0;
}
.sl-risk--dusuk .sl-risk-mark { background: var(--ok); }
.sl-risk--orta .sl-risk-mark { background: var(--warn); }
.sl-risk--yuksek .sl-risk-mark { background: var(--bad); }
.sl-risk-title {
  font-size: 1.2rem !important;
  font-weight: 700 !important;
  margin: 0 !important;
  color: #FFFFFF !important;
}
.sl-risk-meta {
  font-family: var(--mono) !important;
  font-size: 0.8rem !important;
  color: var(--ink-2) !important;
  margin: 0.2rem 0 0 !important;
}

.sl-footnote {
  margin-top: 1.85rem;
  padding-top: 0.85rem;
  border-top: 1px solid var(--line);
  font-size: 0.75rem !important;
  color: var(--mute) !important;
  font-family: var(--mono) !important;
}

div[data-testid="stExpander"] {
  background: var(--panel) !important;
  border: 1px solid var(--line) !important;
  border-radius: 8px !important;
}
div[data-testid="stExpander"] summary,
div[data-testid="stExpander"] p,
div[data-testid="stExpander"] span { color: var(--ink) !important; }
div[data-testid="stAlert"] { border-radius: var(--r) !important; }
div[data-testid="stAlert"] p,
div[data-testid="stAlert"] span { color: var(--ink) !important; }

.stCaption, [data-testid="stCaptionContainer"],
[data-testid="stCaptionContainer"] p {
  color: var(--mute) !important;
  font-size: 0.82rem !important;
}
.stCodeBlock, pre, code {
  background: var(--panel) !important;
  color: var(--ink) !important;
  border: 1px solid var(--line) !important;
  border-radius: var(--r) !important;
}

[data-testid="stIconMaterial"] {
  font-family: "Material Symbols Rounded" !important;
  font-variation-settings: "FILL" 0, "wght" 400, "GRAD" 0, "opsz" 24 !important;
  font-feature-settings: "liga" 1 !important;
}

[data-testid="stFileUploader"] { width: 100%; }
[data-testid="stFileUploaderDropzone"] {
  background: var(--panel) !important;
  border: 1px dashed rgba(62, 185, 165, 0.45) !important;
  border-radius: 8px !important;
  padding: 1rem 1.1rem !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] span {
  color: var(--mute) !important;
  font-size: 0.84rem !important;
  font-family: var(--font) !important;
}
[data-testid="stFileUploader"] button {
  background: var(--accent-deep) !important;
  background-image: linear-gradient(180deg, #2AA892 0%, var(--accent-deep) 100%) !important;
  color: #FFFFFF !important;
  border: 1px solid #177868 !important;
  border-radius: var(--r) !important;
  font-weight: 700 !important;
  min-height: 2.4rem !important;
  box-shadow: 0 6px 14px rgba(31, 138, 120, 0.28) !important;
}
[data-testid="stFileUploader"] button p {
  color: #FFFFFF !important;
  font-family: var(--font) !important;
  font-weight: 700 !important;
}
[data-testid="stFileUploader"] button [data-testid="stIconMaterial"] {
  display: none !important;
}

section[data-testid="stSidebar"] .stCaption,
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] p {
  color: var(--mute) !important;
}

@media (max-width: 720px) {
  .sl-top {
    grid-template-columns: 1fr;
    padding: 1.1rem;
  }
  .sl-top img { width: 48px; height: 48px; }
}
</style>
"""


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def hero(*, modes_ready: int = 4) -> None:
    del modes_ready
    src = logo_uri()
    logo = (
        f'<img src="{src}" alt="SecLens" width="56" height="56" />'
        if src
        else ""
    )
    st.markdown(
        f"""
<div class="sl-top">
  {logo}
  <div class="sl-top-text">
    <div class="sl-top-row">
      <h1 class="sl-name">Sec<span>Lens</span></h1>
      <span class="sl-meta">Hacktoberfest 2026</span>
    </div>
    <p class="sl-desc">
      Türkçe oltalama, kod zafiyeti, sahte giriş ekranı ve e-posta sızıntısı —
      kural tabanlı skor + yerel open-weight model.
    </p>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def sidebar_brand() -> None:
    src = logo_uri() or mark_uri()
    img = f'<img src="{src}" alt="" width="36" height="36" />' if src else ""
    st.markdown(
        f"""
<div class="sl-side-brand">
  {img}
  <div>
    <strong>SecLens</strong>
    <em>yerel güvenlik aracı</em>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def risk_banner(risk: str, title: str, skor: int, extra: str = "") -> None:
    cls = risk if risk in ("dusuk", "orta", "yuksek") else "orta"
    meta = f"Skor {skor}/100"
    if extra:
        meta = f"{meta} · {extra}"
    st.markdown(
        f"""
<div class="sl-risk sl-risk--{cls}">
  <span class="sl-risk-mark" aria-hidden="true"></span>
  <div>
    <p class="sl-risk-title">{title}</p>
    <p class="sl-risk-meta">{meta}</p>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def footnote() -> None:
    st.markdown(
        '<p class="sl-footnote">SecLens eğitim amaçlıdır · antivirüs / uzman görüşü yerine geçmez · '
        "şüpheli SMS: 5010</p>",
        unsafe_allow_html=True,
    )
