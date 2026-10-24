# SecLens

**Open-weight AI security assistant** focused on Turkish SMS/email smishing & phishing detection.

Hacktoberfest 2026 · [Best Open-Source AI Project](https://www.mlh.com/opensource-ai)  
Repo: [github.com/Mundereous/seclens](https://github.com/Mundereous/seclens)

> Educational / awareness tool. **Not** a replacement for antivirus, bank security products, or forensic expertise.

| TR | [Türkçe anlatım ↓](#seclens-türkçe) |
|----|-------------------------------------|
| EN | [English overview ↓](#seclens-english) |

---

## Screenshots

### Home — Mod 1 text analysis UI

![SecLens home](docs/screenshots/01_home.png)

### High risk — fake “uzlaştırma / savcılık” SMS

![High risk uzlastirma](docs/screenshots/02_uzlastirma_high_risk.png)

### Low risk — normal meeting email

![Low risk safe email](docs/screenshots/03_safe_email_low_risk.png)

### High risk — IBAN / EFT bait

![IBAN EFT scam](docs/screenshots/04_iban_eft_scam.png)

---

<a id="seclens-english"></a>
## SecLens (English)

### What it does

One Streamlit app with three planned modes; **Mode 1 is ready**:

| Mode | Status | Purpose |
|------|--------|---------|
| **1 · Text** | Ready | Turkish SMS/email → risk score + reasons + advice |
| **2 · Code** | Planned | Snippet scan (secrets, SQLi, XSS, …) |
| **3 · Image** | Planned | Login-page screenshot phishing UI check |

### How Mode 1 works (important)

Two layers — **not** neural fine-tuning:

1. **Rule-based signals** (`core/scam_patterns.py`) — common Turkish fraud patterns (keywords, links, phones, IBANs). Most of the score comes from here.
2. **Open-weight LLM** via [Ollama](https://ollama.com) (`llama3.2:1b`) — writes Turkish explanations/advice from the rule summary.

“What we trained on” means: **we curated detection rules from public warnings and real scam templates**, then wired a small local LLM for natural-language output. We did **not** fine-tune model weights for this MVP.

### What Mode 1 detects

| Pattern | Signal examples | Demo file |
|---------|-----------------|-----------|
| Fake bank SMS | Block / “security update” + shady link | `examples/phishing_sms.txt` |
| Fake cargo email | Courier + fee/return + link | `examples/phishing_email.txt` |
| Fake prosecution / mediation | “last day”, “call now” + phone | `examples/scam_uzlastirma.txt` |
| Fake e-Devlet | Account suspended + external link | `examples/scam_edevlet.txt` |
| Customs / HGS / cargo | “pay customs”, “update address” | `examples/scam_kargo_gumruk.txt` |
| Crypto smishing | “account at risk” + short link | `examples/scam_kripto.txt` |
| IBAN / EFT bait | IBAN + “transfer now / discount ends” | `examples/scam_iban_eft.txt` |
| Gift / model-kit spam | “special gift”, forwarded no-reply mail | `examples/scam_hediye_maket.txt` |
| Safe controls | Meeting / friend messages (low risk) | `examples/safe_*.txt` |

Also flags: suspicious TLDs, IP URLs, bit.ly-style shorteners, TR phone numbers, TR IBANs, brand name + link/phone combos.

### Sources used for the rule set

Public / institutional awareness material (defensive use), including:

- Turkish Interior Ministry / police operation notes (e-Devlet aid links, “criminal investigation last day” SMS)  
- BTK + police smishing warnings (fake cargo / bank update SMS)  
- [PTT official fraud warning](https://www.ptt.gov.tr/haberler/ptt-as-dolandiricilik-faaliyetlerine-karsi-vatandaslari-uyariyor-d20119c1273f42ac856e02f814b8d959)  
- Press / complaint platforms: crypto “account at risk”, IBAN+EFT discount traps  
- e-Devlet phishing awareness write-ups  

Code: `core/scam_patterns.py` · Scoring merge: `core/phishing.py`

### Model & dependencies

| Component | Detail |
|-----------|--------|
| **Model** | [`llama3.2:1b`](https://ollama.com/library/llama3.2) (~1B params → **small** LM for this challenge) |
| **Runtime** | Ollama local API (`http://127.0.0.1:11434`) |
| **Model terms** | Llama 3.2 Community License — [Meta Llama license](https://www.llama.com/llama3_2/license/) |
| **UI** | Streamlit |
| **HTTP** | `requests` |
| **Images (later)** | Pillow |

Open-weight ≠ the whole project is open source by default. **This repo is MIT**; the model keeps its own license. Weights are **not** vendored here.

### Quick start

```bash
git clone https://github.com/Mundereous/seclens.git
cd seclens
python3 -m pip install -r requirements.txt
ollama pull llama3.2:1b   # Ollama app must be running
streamlit run app.py
```

Open **http://127.0.0.1:8501** → pick an example → **Analiz et**.

---

<a id="seclens-türkçe"></a>
## SecLens (Türkçe)

### Ne yapıyor?

Tek Streamlit uygulaması; **Mod 1 hazır**:

| Mod | Durum | Ne yapar |
|-----|--------|----------|
| **1 · Metin** | Hazır | Türkçe SMS / e-posta → risk skoru + gerekçe + öneri |
| **2 · Kod** | Yakında | Snippet’te secret, SQLi, XSS vb. |
| **3 · Görüntü** | Yakında | Login screenshot phishing UI |

### Mod 1 nasıl çalışıyor?

1. **Kurallar** (`core/scam_patterns.py`) — skorun çoğu  
2. **Ollama + `llama3.2:1b`** — Türkçe gerekçe / öneri  

**Fine-tune yok.** “Eğittik” = kamu uyarılarından kalıp listesini zenginleştirdik.

### Neleri tespit ediyor?

Yukarıdaki İngilizce tablonun aynısı (`examples/` klasörü). Ek sinyaller: şüpheli TLD, IP link, kısa link, TR telefon, TR IBAN, marka+link.

### Kaynaklar

İçişleri/Emniyet duyuruları, BTK smishing uyarıları, [PTT dolandırıcılık uyarısı](https://www.ptt.gov.tr/haberler/ptt-as-dolandiricilik-faaliyetlerine-karsi-vatandaslari-uyariyor-d20119c1273f42ac856e02f814b8d959), kripto/IBAN haberleri, e-Devlet phishing farkındalık metinleri.

### Kurulum

```bash
git clone https://github.com/Mundereous/seclens.git
cd seclens
python3 -m pip install -r requirements.txt
ollama pull llama3.2:1b
streamlit run app.py
```

Tarayıcı: **http://127.0.0.1:8501**

---

## Project structure

```
seclens/
├── app.py
├── requirements.txt
├── LICENSE                 # MIT
├── README.md
├── HACKTOBERFEST-BAGLAM.md
├── docs/screenshots/       # UI captures for this README
├── scripts/capture_screenshots.py
├── core/
│   ├── ollama_client.py
│   ├── phishing.py
│   └── scam_patterns.py
└── examples/
```

Regenerate screenshots (app + Ollama must be running):

```bash
python3 -m pip install playwright
python3 -m playwright install chromium
python3 scripts/capture_screenshots.py
```

---

## Challenge checklist

- [x] Open-weight AI is central (Ollama + Llama 3.2)  
- [x] Public GitHub + [MIT](LICENSE)  
- [x] README: what / how / model + deps + model license link + screenshots  
- [x] Working demo (Mode 1)  
- [ ] Mode 2 code scan  
- [ ] Mode 3 screenshot  
- [ ] Optional cloud deploy  

---

## Ethics

- Examples are **synthetic / anonymized** training texts — no real victim PII dumps.  
- Goal: warn about patterns; no automated blocking or legal accusation.  
- In Turkey, suspicious SMS can be reported to **5010**.

---

## License

Code: [MIT](LICENSE) · Copyright (c) 2026 Mundereous  

Model: Llama 3.2 Community License (Meta) — downloaded via Ollama, not stored in this repo.
