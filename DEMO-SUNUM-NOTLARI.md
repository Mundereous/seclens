# SecLens — Demo & Sunum Notları

> Hacktoberfest 2026 · Best Open-Source AI Project  
> Repo: https://github.com/Mundereous/seclens  
> Bu dosya: jüriye demo yaparken / soru gelince bakılacak hatırlatma.

---

## 30 saniyelik elevator pitch

**SecLens**, Türkçe SMS/e-posta oltalamasını ve güvensiz kod snippet’lerini yakalayan open-weight AI güvenlik asistanıdır.

- **Mod 1:** Phishing / smishing (kurallar + Ollama LLM)  
- **Mod 2:** Mini-SAST (OWASP/CWE kuralları)  
- **Mod 3:** Screenshot (planlandı)  

Stack: **Streamlit + Ollama (`llama3.2:1b`) + MIT lisans**.  
Eğitim amaçlıdır; antivirüs yerine geçmez.

---

## 2 dakikalık demo akışı (ezberle)

1. **http://127.0.0.1:8501** aç → sol: Ollama çalışıyor, model `llama3.2:1b`  
2. **Metin sekmesi**  
   - Örnek: **Sahte e-Devlet** → Analiz et → Yüksek risk  
   - Örnek: **Güvenli e-posta** → Düşük risk  
   - İstersen: **Valilik onaylı IBAN** (sosyal medya tuzağı)  
3. **Kod sekmesi**  
   - Listeden **02 SQL Injection** yükle → Tara → CWE-89 / OWASP A03  
   - **10 Güvenli referans** → bulgu yok  
4. Kapanış: “Kurallar TR kamu uyarılarından; LLM gerekçe üretir. Open-weight + public MIT repo.”

**Ollama kapalıysa:** Applications → Ollama aç; gerekirse `ollama pull llama3.2:1b`.  
**Uygulama kapalıysa:**

```bash
cd ~/Desktop/HACKTOBERFEST
streamlit run app.py
```

---

## Jüriye söylenecek teknik noktalar

| Soru | Kısa cevap |
|------|------------|
| AI nerede? | Ollama’da yerel **Llama 3.2 1B** (open-weight, small LM ≤10B) |
| Neden kurallar da var? | 1B model tek başına yetersiz; TR scam kalıpları + skor güvenilirliği |
| Fine-tune ettiniz mi? | Hayır — kamu uyarılarından **kural seti** + LLM açıklama (dürüst anlat) |
| Lisans? | Repo **MIT**; model Meta Llama 3.2 Community License |
| Neden yerel? | API key şart değil; demo offline; challenge open-weight vurgusu |

---

## Karşılaştığımız sorunlar ve çözümler

Sunumda “ne öğrendiniz / ne zorlandı?” sorusu gelirse buradan anlat.

### 1) GitHub CLI yoktu / giriş yoktu
- **Sorun:** `gh` yüklü değildi; sonra device login gerekti.  
- **Çözüm:** Homebrew ile `gh` kuruldu; `gh auth login --web`; repo: `Mundereous/seclens`.

### 2) Streamlit açılmıyor / hemen kapanıyor
- **Sorun:** İlk çalıştırmada Streamlit e-posta soruyordu; terminal etkileşimsiz kalınca process ölüyordu.  
- **Çözüm:** `~/.streamlit/credentials.toml` + `config.toml` (headless, gatherUsageStats=false). Adres: `http://127.0.0.1:8501`.

### 3) Ollama kurulu ama PATH / servis yok
- **Sorun:** App vardı, `ollama` komutu ve port 11434 yoktu.  
- **Çözüm:** Ollama.app açıldı / `ollama serve`; CLI `~/bin/ollama` symlink.

### 4) Model indirme kopuyordu
- **Sorun:** `llama3.2:1b` (~1.3 GB) yavaş ağda EOF ile yarıda kalıyordu.  
- **Çözüm:** Tekrarlı `ollama pull` (resume); sonunda model listede göründü.

### 5) “Hesap açayım mı?” (Ollama cloud)
- **Sorun:** Sign up ekranı.  
- **Çözüm:** **No thanks, I’ll use Ollama locally** — challenge için local yeterli.

### 6) Güvenli maili yüksek risk sayıyordu
- **Sorun:** 1B model “gündem / SecLens” diye orta-yüksek risk veriyordu.  
- **Çözüm:** **Kural motoru** eklendi; güvenli kelimeler + link/telefon yoksa skor düşük tutuldu. Skor = kurallar ağırlıklı + LLM.

### 7) Uzlaştırma / savcılık SMS’i düşük risk
- **Sorun:** Link yok diye skor ~20; klasik TR dolandırıcılığı kaçıyordu.  
- **Çözüm:** Savcılık/uzlaştırma kelimeleri + telefon + “arayın” komboları eklendi.

### 8) Valilik onaylı IBAN düşük risk
- **Sorunlar:**  
  - Bitişik IBAN (`TR93…`) regex’e yakalanmıyordu.  
  - IBAN içindeki rakamlar **telefon** sanılıyordu.  
  - “Valilik onaylı + Instagram” kalıbı yoktu.  
- **Çözüm:** IBAN regex (bitişik), IBAN maskeleme sonrası telefon ara, sosyal bağış IBAN kuralları.

### 9) Kod değişti ama UI eski sonuç gösteriyordu
- **Sorun:** Streamlit eski process ile çalışıyordu.  
- **Çözüm:** Process öldürüp yeniden `streamlit run`; tarayıcıda hard refresh (Cmd+Shift+R).

### 10) “Model düşünüyor…”da takılı kalma
- **Sorun:** 1B model bazen 30–60 sn; kullanıcı dondu sanıyordu.  
- **Çözüm (geçici):** Net skorlarda LLM atlanmıştı.  
- **Son karar (senin isteğin):** LLM **her analizde** çalışsın; spinner’da “15–60 sn sürebilir” yazısı.

### 11) “JSON bozuldu” uyarısı
- **Sorun:** Model JSON’u yarıda kesiyordu (`num_predict` / uzun gerekçe); parse fail.  
- **Çözüm:** Kısa JSON prompt (SMS’i kopyalama); kesik JSON **onarımı**; token limiti artırıldı. Skor yine kurallarla güvence.

### 12) İkinci PC / Antigravity ile paralel geliştirme
- **Sorun:** Git bilmeden 2 IDE karmaşa yaratır.  
- **Karar:** Tek PC (Cursor) + GitHub yedek; git işlerini agent yönetir.

### 13) Push kimlik hatası
- **Sorun:** `could not read Username for https://github.com`.  
- **Çözüm:** `gh auth setup-git` sonra `git push`.

---

## Mod 1 — Ne tespit ediyoruz? (demo örnekleri)

| Örnek | Beklenen |
|--------|----------|
| Sahte banka / kargo | Yüksek |
| Uzlaştırma + telefon | Yüksek |
| e-Devlet + `.xyz` link | Yüksek |
| Valilik onaylı IBAN + IG | Yüksek |
| IBAN/EFT tuzağı | Yüksek |
| Güvenli toplantı / arkadaş | Düşük |

Kaynak fikri: İçişleri/Emniyet, BTK, PTT uyarıları, yaygın TR scam kalıpları → `core/scam_patterns.py`.

---

## Mod 2 — Kod (OWASP/CWE)

Test dosyaları: `examples/code/01…10` (her dosyada **NEDEN TEHLİKELİ** yazıyor).

| # | Konu | CWE |
|---|------|-----|
| 01 | Hardcoded secret | 798 |
| 02 | SQL Injection | 89 |
| 03 | Command Injection | 78 |
| 04 | XSS | 79 |
| 05 | Deserialization | 502 |
| 06 | Path traversal | 22 |
| 07 | SSRF | 918 |
| 08 | Zayıf kripto/TLS | 328/295 |
| 09 | Secret in logs | 532 |
| 10 | Güvenli referans | — |

Harici test için (isteğe bağlı): [Bandit examples](https://github.com/PyCQA/bandit/tree/main/examples), OWASP lab’ları — **sadece eğitim / kendi kurduğun ortam**.

---

## Mimari (tek cümlelik çizim)

```
Metin/Kod → Streamlit UI
              ├─ Kural motoru (hızlı, TR/OWASP kalıpları) → skor + gerekçe
              └─ Ollama llama3.2:1b → kısa JSON açıklama / öneri
         → Birleşik sonuç (kurallar skor güvencesi)
```

---

## Challenge checklist (teslim öncesi)

- [x] Open-weight AI merkezi  
- [x] Public GitHub + MIT  
- [x] README (TR+EN, model + lisans, ekran görüntüleri)  
- [x] Çalışan demo Mod 1 + Mod 2  
- [ ] Mod 3 screenshot (opsiyonel / sonraki)  
- [ ] Hack Day’de OrganizerHQ submit  
- [ ] DigitalOcean $25 → **Hack Day’e yakın aktive et** (3 gün!)

---

## Sık jüri / hoca soruları — hazır cevap

**“Bu antivirüs mü?”**  
Hayır; farkındalık + eğitim aracı. 5010’a bildirim öneririz.

**“Neden 1B model?”**  
Hackathon’da hızlı indirme / Mac’te lokal çalışır; kurallarla desteklenince güvenilir demo.

**“Yanlış pozitif/negatif?”**  
Erken sürümde vardı; kural setini gerçek TR vakalarıyla genişlettik (IBAN, uzlaştırma, e-Devlet…). Hâlâ %100 değil; dürüst sınır: pattern SAST/taint yok.

**“Neler zorladı?”**  
Ollama kurulum/indirme, Streamlit ilk açılış, küçük model JSON kesmesi, Streamlit cache — hepsini çözdük (bu dosyadaki liste).

---

## Dosya haritası (hızlı)

| Dosya | Ne işe yarar |
|-------|----------------|
| `app.py` | UI |
| `core/phishing.py` | Mod 1 |
| `core/scam_patterns.py` | TR scam sinyalleri |
| `core/code_rules.py` | Mod 2 OWASP/CWE kuralları |
| `core/ollama_client.py` | Ollama API |
| `examples/` | Metin + kod demo |
| `README.md` | Proje anlatımı |
| `HACKTOBERFEST-BAGLAM.md` | Yarışma planı / promo |
| **`DEMO-SUNUM-NOTLARI.md`** | **Bu dosya** |

---

*Son güncelleme: 2026-10-24 · SecLens demo hazırlık*
