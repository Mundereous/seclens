# SecLens — 15 Dakikalık Teknik Sunum Notları

> Hacktoberfest 2026 · **Best Open-Source AI Project**  
> Repo: https://github.com/Mundereous/seclens  
> Demo: `http://127.0.0.1:8501` · `streamlit run app.py`  
> Bu dosya: sunum sırasında okunacak / ezberlenecek senaryo + teknik derinlik.

**Toplam süre hedefi: ~15 dakika** (canlı demo dahil).  
Konuşma dili: Türkçe · jüriye İngilizce terimler serbest.

**Web slaytlar:** [`docs/sunum/index.html`](docs/sunum/index.html) — `open docs/sunum/index.html` · `→` / `←` · `F` tam ekran.

---

## Zaman çizelgesi (ezberle)

| Dk | Bölüm | Ne anlat / ne göster |
|----|--------|----------------------|
| 0:00–1:00 | Pitch + problem | Neden SecLens? |
| 1:00–3:00 | Mimari | Kurallar + LLM hibriti, neden fine-tune yok |
| 3:00–5:30 | Mod 1 canlı | Phishing SMS → skor |
| 5:30–8:00 | Mod 2 canlı | Mini-SAST (SQLi / IDOR) |
| 8:00–10:30 | Mod 3 canlı | Screenshot + moondream |
| 10:30–12:00 | Mod 4 | E-posta sızıntı (XposedOrNot) |
| 12:00–14:00 | Hatalar & çözümler | “Ne zorladı?” |
| 14:00–15:00 | Challenge uyumu + kapanış | MIT, open-weight, sınırlar |

---

## 0:00–1:00 · Elevator pitch

### Söyle

> **SecLens**, Türkçe oltalama (SMS/e-posta), güvensiz kod snippet’leri, sahte login ekranı screenshot’ları ve e-posta sızıntı kontrolünü **tek yerde** toplayan open-weight AI güvenlik asistanıdır.
>
> Eğitim ve farkındalık aracıdır; antivirüs veya adli bilişim yerine geçmez.
>
> Stack: **Streamlit UI + Ollama** üzerinde **Llama 3.2 1B** (metin) ve **moondream** (görüntü) + kendi yazdığımız **kural motorları**.

### Neden bu proje? (1 cümle)

Hackathon’da (~6 saat) jüriye **çalışan demo + açık lisans + open-weight AI’nın gerçekten iş yaptığı** bir şey göstermek; TR scam’e özel, kopya konu değil (bitki/ağaç değil).

---

## 1:00–3:00 · Mimari — neyi neden yaptık?

### Büyük resim

```
Kullanıcı (Streamlit / app.py)
        │
        ├─ Mod 1 Metin ──► core/phishing.py + scam_patterns.py
        │                        │
        │                        ├─ KURAL skoru (0–100)  ← güvence
        │                        └─ Ollama llama3.2:1b   ← Türkçe gerekçe / öneri
        │
        ├─ Mod 2 Kod ────► core/code_scan.py + code_rules.py (~185 kural)
        │                        └─ Ollama → bulguları açıkla / düzeltme öner
        │
        ├─ Mod 3 Görüntü ► core/screenshot_scan.py
        │                        ├─ Checklist + URL/notlar (skor ağırlığı)
        │                        └─ Ollama moondream (opsiyonel vision)
        │
        └─ Mod 4 Sızıntı ► core/breach_check.py → XposedOrNot API (ücretsiz)
```

### Tasarım kararı #1 — “Kurallar önce, LLM ikinci”

| Seçenek | Neden seçmedik / seçtik |
|---------|-------------------------|
| Sadece LLM | 1B model TR scam’de yetersiz; güvenli maili “şüpheli” sayabiliyor; skor rastgele |
| Sadece kurallar | Açıklama zayıf; jüri “AI nerede?” der |
| **Hibrit (bizim)** | Skor **kurallardan** (tekrarlanabilir); LLM **gerekçe + öneri** üretir |

**Dürüst cümle:** Fine-tune yok. “Öğrenme” = kamu uyarılarından / OWASP-CWE’den **kural seti çıkarmak**.

### Tasarım kararı #2 — Neden Llama 3.2 **1B**?

- Challenge: **small LM ≤ 10B** (1B net uyuyor)
- Mac’te lokal, hızlı indirme (~1.3 GB), API key şart değil
- Open-weight: Meta Llama 3.2 Community License (README’de link)
- Yetersizlikleri **kurallarla kapatıyoruz** — bunu açıkça söyle

### Tasarım kararı #3 — Neden Streamlit?

- Hackathon temposuna uygun tek dosya + sekmeler
- Demo için yeterli; production SAST değil

### Tasarım kararı #4 — Neden Ollama?

- Yerel inference, offline demo
- Aynı API ile metin + vision (`llama3.2:1b`, `moondream`)

### Dosya haritası (sunumda parmakla göster)

| Dosya | Rol |
|-------|-----|
| `app.py` | 4 sekme UI, Ollama durum, örnek yükleme |
| `ui/theme.py` | Marka / CSS (SecLens logo + koyu konsol) |
| `core/ollama_client.py` | `http://127.0.0.1:11434` chat / vision |
| `core/scam_patterns.py` | TR smishing sinyalleri (~400+ kalıp) |
| `core/phishing.py` | Mod 1 skor birleştirme + LLM prompt |
| `core/code_rules.py` | ~**185** OWASP/CWE kuralı |
| `core/code_scan.py` | Mini-SAST tarama + LLM notu |
| `core/screenshot_scan.py` | Checklist + moondream |
| `core/breach_check.py` | XposedOrNot e-posta sızıntı |
| `examples/` | Demo metin / kod / screenshot |
| `LICENSE` | MIT |
| `README.md` | Model + lisans + çalıştırma |

---

## 3:00–5:30 · Mod 1 — Türkçe phishing / smishing (CANLI)

### Ne yapıyor?

1. Metin → `scam_patterns` sinyalleri (banka, kargo, e-Devlet, IBAN, OTP+WhatsApp, savcılık/uzlaştırma, valilik+IG…)
2. Skor 0–100 + risk: düşük / orta / yüksek
3. Her analizde **llama3.2:1b** → kısa JSON: gerekçe + öneriler (Türkçe)

### Canlı adımlar

1. Sekme **Metin**
2. Örnek: **Sahte e-Devlet** veya **Uzlaştırma** → **Örneği yükle** → **Analiz et**
3. Beklenen: **Yüksek risk**, skor yüksek, “5010” / tıklama uyarısı
4. Kontrast: **Güvenli e-posta** → **Düşük risk**

### Neyi neden kodladık?

- **IBAN regex (bitişik TR…):** sosyal medya “valilik onaylı IBAN” vakaları
- **Telefon vs IBAN ayrımı:** IBAN içindeki rakamlar telefon sanılmasın diye maskeleme
- **Güvenli kelime seti:** toplantı / arkadaş mesajında false positive düşsün

### Söyleyecek teknik cümle

> “Skorun sahibi kurallar; LLM hikâyeyi anlatıyor. Böylece 1B model JSON’u bozsa bile risk bandı çökmez.”

---

## 5:30–8:00 · Mod 2 — Mini-SAST (CANLI)

### Ne yapıyor?

- Pattern eşleme (~185 kural): secrets, SQLi, RCE, XSS, IDOR, XXE, pickle/yaml, Trojan Source (bidi), Twisted/httpoxy, zayıf hash…
- Çıktı: satır, `rule_id`, OWASP, CWE, şiddet, düzeltme önerisi
- LLM: bulguları Türkçe özetler (eğitim dili)

### Canlı adımlar

1. Sekme **Kod**
2. **02 SQL Injection** → Tara → CWE-89 / A03
3. İsteğe bağlı: **13 IDOR** veya **14 PHP SQLi**
4. **10 Güvenli referans** → kritik bulgu yok (false positive kontrolü)

### Sınır (dürüst ol)

> “Bu Semgrep/CodeQL değil; eğitim amaçlı pattern SAST. Taint analizi yok. Hackathon’da jüriye gösterilebilir OWASP haritası üretmek için bilinçli trade-off.”

### Neden Bandit örnekleri var?

`examples/code/external/` — harici, bilinen zafiyet örnekleriyle kural setini doğrulamak (Trojan Source, XXE, pickle…).

---

## 8:00–10:30 · Mod 3 — Screenshot + vision (CANLI)

### Ne yapıyor?

1. PNG/JPG yükle veya örnek / “Örnek” quiz seti (`examples/screenshots/altay/`)
2. Adres çubuğu + görsel checklist (acil dil, lookalike domain, CVV/OTP…)
3. Opsiyonel **moondream** → ekranda ne göründüğüne dair ipuçları
4. Skor = checklist ağırlıklı; vision destekleyici

### Canlı adımlar

1. Sekme **Görüntü**
2. Örnek sahte banka login yükle veya listeden seç
3. Checklist’te 2–3 kutu işaretle + URL’ye şüpheli domain
4. **Görüntüyü analiz et** (Ollama + moondream kuruluysa vision notu gelir)

### Neyi neden?

- Saf OCR/vision’a güvenmedik: **insan checklist** skorun omurgası
- Vision: “logo / form alanı var mı?” gibi destek — jüriye multimodal open-weight gösterimi
- UI’da “Örnek” etiketi: eğitim seti; üçüncü parti marka adı öne çıkmasın diye bilinçli isimlendirme

### Teknik not (dürüst)

Quiz setinde bazı örneklerde açıklama metni checklist’e yardımcı olabilir; sunumda “eğitim senaryosu, production phishing detector değil” de.

---

## 10:30–12:00 · Mod 4 — E-posta sızıntı

### Ne yapıyor?

- `core/breach_check.py` → **XposedOrNot** ücretsiz API
- E-posta bilinen sızıntı listelerinde mi? Kaç breach / hangi kaynaklar (API cevabına göre)
- LLM şart değil; yine de UI’da risk bandı + öneriler (parola değiştir, 2FA…)

### Canlı

1. Sekme **E-posta sızıntı**
2. Test için bilinen sızmış / temiz adres (sunumda kendi test mailin veya örnek)
3. Rate limit’e dikkat: API ücretsiz katmanda sınırlı olabilir

### Neyi neden ekledik?

Metin/kod/görüntü “önleyici”; sızıntı “sonradan farkındalık” — ürünü 4 ayaklı güvenlik hikâyesine tamamlar.

---

## 12:00–14:00 · Nerelerde hata aldık, nasıl çözdük?

Sunumda “en çok ne zorladı?” gelirse buradan 4–5 madde seç; hepsini okuma.

### Ortam / toolchain

| # | Sorun | Çözüm |
|---|--------|--------|
| 1 | `gh` yok, GitHub CLI login yok | Homebrew `gh` + `gh auth login --web` → `Mundereous/seclens` |
| 2 | Streamlit ilk açılışta e-posta sorusu → process ölüyordu | `~/.streamlit/credentials.toml` + headless / `gatherUsageStats false` |
| 3 | Ollama app var, PATH/port 11434 yok | Ollama.app / `ollama serve`; CLI symlink |
| 4 | `llama3.2:1b` pull EOF ile kopuyor | Tekrarlı `ollama pull` (resume) |
| 5 | Ollama cloud “hesap aç” | **Local only** — challenge için yeterli |
| 6 | `git push` username hatası | `gh auth setup-git` |
| 7 | Commit’te şirket e-posta author | `filter-branch` / history düzeltme + force-push; author **Mundereous** |

### Model / skor mantığı

| # | Sorun | Çözüm |
|---|--------|--------|
| 8 | Güvenli mail → yüksek risk (1B model) | Kural motoru + güvenli kelime seti; skor kurallardan |
| 9 | Uzlaştırma/savcılık SMS düşük skor (link yok) | TR kamu scam kalıpları + telefon + “arayın” |
| 10 | Valilik+IBAN yakalanmıyor | Bitişik IBAN regex; IBAN maskeleme sonrası telefon; IG/bağış kuralları |
| 11 | LLM JSON kesiliyor / “JSON bozuldu” | Kısa JSON prompt; kesik JSON onarımı; `num_predict` artırma; skor yine kurallarda |
| 12 | Spinner’da “takıldı” hissi | “15–60 sn sürebilir” uyarısı; LLM her analizde (bilinçli tercih) |

### Mod 2 / Mod 3

| # | Sorun | Çözüm |
|---|--------|--------|
| 13 | IDOR / PHP SQLi / XXE / Trojan Source kaçıyordu | Kural genişletme; windowed alias; Unicode bidi (Trojan Source); Bandit örnekleriyle test |
| 14 | `chat_vision` ImportError / stale Streamlit | Process restart + hard refresh; gerekirse `importlib.reload` |
| 15 | Playwright ile örnek screenshot selectbox kırılgan | Mod 3’te dosya upload + hazır örnekler |
| 16 | SSL / urllib sorunları (API) | `curl` / requests ayarı; breach için sağlam HTTP yolu |

### UI (sunum öncesi cilâ)

| # | Sorun | Çözüm |
|---|--------|--------|
| 17 | Streamlit kısmi reload → eski `theme`, `sidebar_brand` AttributeError | `importlib.reload(ui_theme)` + sunucu restart |
| 18 | Upload “uploadpload” bozuk yazı | CSS tüm `span` font’unu eziyordu → Material Icon ligature bozuldu; icon gizlendi / font korundu |
| 19 | Okunmayan açık/koyu karma | Tek koyu konsol palet; CTA beyaz yazı + teal |
| 20 | “AI şablon” görünümü | Pill/glow azaltıldı; IBM Plex + premium üst şerit (sunumluk) |

### Öğrendiğimiz meta ders

> Küçük open-weight model + iyi kural seti, hackathon’da “büyük API model”den daha güvenilir demo verir.  
> Streamlit’te CSS agresif olursa widget’lar (file uploader) sessizce kırılır — seçicileri dar tut.

---

## 14:00–15:00 · Challenge uyumu + kapanış

### Checklist (jüriye tek slide gibi)

- [x] Open-weight AI **merkezi** (llama3.2:1b + moondream) — demoda gösteriliyor  
- [x] Public GitHub + **MIT**  
- [x] README: ne / nasıl / model adı + lisans linkleri  
- [x] Small LM ≤ 10B  
- [x] Fine-tune yok (dürüst)  
- [x] 4 mod çalışan demo  

### Sınırlar (güçlü görünür)

- Antivirus değil · production SAST değil · vision OCR mucizesi değil  
- Şüpheli SMS: **5010**

### Kapanış cümlesi

> “SecLens, Türkçe güvenlik farkındalığını open-weight AI ile birleştiriyor: skorlar kurallarla güvenilir, açıklamalar yerel modelle anlaşılır, her şey MIT ve public repo’da.”

---

## Canlı demo acil kit

```bash
# Uygulama
cd ~/Desktop/HACKTOBERFEST
streamlit run app.py
# → http://127.0.0.1:8501

# Ollama
open -a Ollama
ollama list
# yoksa:
ollama pull llama3.2:1b
ollama pull moondream
```

| Belirti | Ne yap |
|---------|--------|
| Ollama kapalı (sidebar) | Ollama.app aç |
| UI eski / hata | Process öldür, `streamlit run` yeniden, Cmd+Shift+R |
| Model yok | `ollama pull …` |
| Analiz yavaş | Normal (1B); spinner bekle |

---

## Jüri Q&A — hazır cevaplar

**“AI tam olarak nerede?”**  
Metin ve kodda Llama 3.2 1B gerekçe/öneri; görüntüde moondream; skor çoğunlukla kurallarda.

**“Fine-tune?”**  
Hayır. Pattern engineering + prompt.

**“Neden 1B?”**  
Hackathon + local + small LM kuralı; kurallarla desteklenince demo stabil.

**“Başka araçlardan farkı?”**  
TR smishing odaklı; dört mod tek UI; tamamen yerel open-weight (Mod 4 API hariç).

**“Yanlış alarm?”**  
Erken sürümde vardı; kural seti gerçek TR vakalarıyla büyütüldü. Hâlâ %100 değil.

**“Lisans?”**  
Kod MIT; Llama 3.2 Community; moondream model card’ına göre; ağırlıklar repo’da yok.

---

## İsteğe bağlı tek slayt — mimari (kopyala)

```
┌─────────────────────────────────────────────┐
│  SecLens (Streamlit)                        │
│  app.py · ui/theme.py                       │
├─────────┬─────────┬──────────┬──────────────┤
│ Metin   │ Kod     │ Görüntü  │ Sızıntı      │
│ phishing│ mini-   │ checklist│ XposedOrNot  │
│ +scam_* │ SAST    │ +vision  │ API          │
├─────────┴─────────┴──────────┴──────────────┤
│  Ollama :11434                              │
│  llama3.2:1b (text) · moondream (vision)    │
└─────────────────────────────────────────────┘
         ↑ skor güvencesi: kurallar
         ↑ anlatım: open-weight LLM
```

---

## Demo sıra listesi (tek bakış)

1. Pitch (30 sn)  
2. Mimari diyagramı anlat (90 sn)  
3. Metin: yüksek + düşük  
4. Kod: SQLi + temiz  
5. Görüntü: örnek + checklist  
6. Sızıntı: bir e-posta  
7. 3–4 hata hikâyesi (Ollama pull, kural vs LLM, uploadpload, author)  
8. Challenge checklist + kapanış  

**Toplam ~15 dk.**

---

*Son güncelleme: 2026-10-24 · SecLens Hacktoberfest sunum notu · Mundereous/seclens*
