# Hacktoberfest 2026 — Bağlam Dosyası (yeni sohbete yapıştır / oku)

> Bu dosya, önceki sohbet kaybolursa yeni AI oturumuna verilecek özetdir.  
> Konum: `/Users/tamer/Desktop/HACKTOBERFEST/`  
> Katılım: **bireysel**, okul yarışması — **şirket / LSOC / BuLab ile alakası yok**.

---

## 1) Ne yapıyoruz?

Hacktoberfest 2026 in-person Hack Day kapsamında MLH kategorisine proje üretiyoruz:

**Best Open-Source AI Project**  
Kurallar: https://www.mlh.com/opensource-ai

Promos (giriş gerekir): https://hacktoberfest.com/my/promos/

Çalışma klasörü: `/Users/tamer/Desktop/HACKTOBERFEST/`

---

## 2) Seçilen proje

### İsim (geçici)
**SecLens** — tek uygulama, üç güvenlik modu (kolay → zor)

| Mod | Ne yapar | Zorluk | Jüri sinyali |
|-----|----------|--------|--------------|
| **1 – Metin** | Türkçe e-posta/SMS → phishing skoru + gerekçe | Kolay | NLP / sınıflandırma (Suncak tarzı yöntem, farklı konu) |
| **4 – Kod** | Snippet → XSS/SQLi/secret uyarısı + düzeltme | Orta | Yazılım kalitesi (Gecit) |
| **3 – Görüntü** | Login screenshot → phishing UI riski | Zor | Görüntü analizi (Akyol tarzı yöntem, farklı konu) |

**Bilerek yapmıyoruz:** bitki hastalığı, ağaç tanıma, anlatım bozukluğu (jüri çalışmalarının kopyası değil).

### Teknik omurga (6 saat uyumlu)
- **UI:** Streamlit (tek sayfa, 3 sekme)
- **AI:** Ollama + küçük **open-weight** model (yerel; API key şart değil)
- **Opsiyonel cloud:** DigitalOcean / Render deploy (promo ile)
- **Lisans:** MIT
- **Dil:** TR UI + TR örnekler

### Challenge uyumu
- Open-weight AI projenin merkezi
- Public GitHub + MIT
- README: ne / nasıl / model adı + lisans linki / deps
- Çalışan demo (en az Mod 1 kesin)

---

## 3) Challenge kuralları (özet)

### Ne inşa edilebilir?
- Agent skill (Agent Skills open standard’a uymalı)
- Open-source veya **open-weight** AI ile çalışan uygulama
- Model harness: orijinal veya mevcut open-source harness’e **anlamlı** katkı (sadece rename yetmez)
- Bunları birleştirmek veya farklı yaklaşım OK

### Zorunlu şartlar
1. Open-source / open-weight AI, projenin **önemli** parçası olsun; demoda AI’nın ne yaptığı gösterilsin.
2. Proje **public GitHub** reposunda + **açık kaynak lisansı** (lisanssız public repo = uygun değil).
3. README şunları açıklasın:
   - Ne yaptın
   - Nasıl çalıştırılır / denenir
   - Hangi **model** ve kritik bağımlılıklar
4. Open-weight model kullanıyorsan: model adı + lisans/terms linki README’de.  
   Open-weight ≠ otomatik open source.
5. Tanım (bu challenge için):
   - **Small language model:** ≤ 10 milyar parametre
   - **Large language model:** > 10 milyar parametre

### Teslim
- OrganizerHQ Challenges → **Best Open-Source AI Project**
- Public repo URL, ad, açıklama, teknolojiler, varsa demo URL

### Kazanan
- Host bir kazanan seçer; PR sayısı ödülü belirlemez
- Çalışan demo + anlaşılır anlatım + doğrulanabilir lisans/model

---

## 4) Promos — ne var, SecLens için ne işe yarar?

Kaynak: https://hacktoberfest.com/my/promos/ (giriş gerekir; 2026-10-24 ekran özeti)

### Hemen alınabilir
| Teklif | Ne veriyor? | SecLens’te kullan? | Ne zaman? |
|--------|-------------|--------------------|-----------|
| **DigitalOcean $25** | Kredi; aktive edince **3 tam gün**; **31 Eki 2026** sonrası yok; **proprietary** Serverless Inference modellerinde **kullanılamaz** | Evet — App Platform / Droplet ile demo host | **Hack Day’e yakın** aktive et |
| **Render $50** | Hesaba kredi; kişi başı 1; claim **15 Kas 2026**’ya kadar | Evet — Streamlit/web deploy yedek | Erken claim OK; deploy Hack Day’de |
| **Backboard $5** | Billing kredisi; kart gerekmez | Zayıf uyum (zorunlu değil) | İstersen al, projeyi buna bağlama |

### MyMLH şartlı (telefon + GitHub bağla — yoksa gri)
| Teklif | Ne veriyor? | SecLens’te kullan? | Not |
|--------|-------------|--------------------|-----|
| **Free .tech domain 1 yıl** | Domain (~30 Ara 2026’ya) | Evet — `seclens.tech` demo URL | Nice-to-have |
| **Browserbase 1 ay** | Browser automation; **kart gerekir** | Opsiyonel — canlı URL ziyareti (Mod 1 gelişmiş) | 6 saatte **sonraya** |
| **ElevenLabs 1 ay Creator** | Ses AI | Zayıf — sesli uyarı stretch | Öncelik değil |
| **Paper Instruments $5** | Billing kredisi | Zayıf uyum | Skip OK |
| **Tinker $10** | Fine-tune kredisi | Hayır — 6 saatte fine-tune yok | Skip |

### Bu proje için önerilen promo sırası
1. **MyMLH:** telefon verify + GitHub connect  
2. **Render $50** claim (uzun ömürlü)  
3. **.tech** domain (demo URL istiyorsan)  
4. **DigitalOcean $25** → sadece Hack Day sabahı / bir gün önce aktive  
5. Browserbase / ElevenLabs / Tinker / Paper → **şimdilik alma** (odak dağılmasın)  
6. Backboard → isteğe bağlı, SecLens’e bağlama

**Token / API key ihtiyacı:** MVP için **gerekmez** (Ollama yerel). Cloud inference kullanırsan DO GradientAI’da **open-weight** modellere dikkat et; proprietary modeller kredi dışı.

**Not:** DO/Render challenge için zorunlu değil; host kolaylaştırır. Asıl kategori: Best Open-Source AI Project.

---

## 5) Detaylı yapım task listesi (kolay → zor)

> Kural: Mod 1 bitmeden Mod 3’e geçme. Her faz sonunda “çalışan bir şey” olsun.

### FAZ 0 — Hazırlık (hack’ten önce / ilk 30 dk)
- [ ] `HACKTOBERFEST-BAGLAM.md` güncel (bu dosya)
- [ ] MyMLH telefon + GitHub
- [ ] Render $50 claim (opsiyonel ama önerilir)
- [ ] DO $25’i **aktive etme** (sakla)
- [ ] Makinede Python 3.10+ ve `git` var mı kontrol
- [ ] Ollama kurulumu planı (local demo için kritik)

### FAZ 1 — İskelet (kolay) ~45–60 dk
- [ ] Proje klasörü: `seclens/` (veya kökte doğrudan paket)
- [ ] `requirements.txt`: `streamlit`, `requests` (Ollama HTTP), `Pillow` (görüntü için sonra)
- [ ] `.gitignore` (venv, `__pycache__`, `.env`)
- [ ] `LICENSE` → MIT
- [ ] `app.py`: Streamlit + 3 sekme iskeleti (Metin / Kod / Görüntü)
- [ ] `core/ollama_client.py`: `http://localhost:11434` chat helper
- [ ] Ollama’dan küçük model çek (ör. `llama3.2:3b` veya `gemma2:2b`) — README’ye adı yazılacak
- [ ] “Merhaba” test: model cevap veriyor mu?

### FAZ 2 — Mod 1 Metin phishing (kolay) ~60–90 dk
- [ ] `prompts/phishing_tr.txt` (veya Python string): Türkçe sistem prompt
- [ ] Girdi: textarea (SMS / e-posta)
- [ ] Çıktı parse: `risk` (düşük/orta/yüksek) + `skor` 0–100 + `gerekçeler[]` + `öneriler[]`
- [ ] JSON bozulursa düz metin fallback
- [ ] `examples/phishing_sms.txt`, `examples/safe_sms.txt` (en az 4 örnek)
- [ ] UI: örnekleri tek tıkla yükle
- [ ] **Checkpoint:** dışarıdan biri Mod 1’i deneyebiliyor

### FAZ 3 — Mod 4 Kod güvenlik (orta) ~60–90 dk
- [ ] `core/code_rules.py`: basit pattern’ler
  - hardcoded secret / API key
  - SQL f-string / string concat
  - `innerHTML` / `dangerouslySetInnerHTML` / `eval(`
  - `verify=False`, `shell=True` vb.
- [ ] Önce kurallar çalışsın (AI olmasa bile bulgu)
- [ ] Sonra LLM: bulguları açıkla + güvenli kod öner (Türkçe)
- [ ] Örnek kötü / iyi snippet dosyaları
- [ ] **Checkpoint:** Mod 1 + Mod 4 demo

### FAZ 4 — Mod 3 Screenshot (zor) ~60–90 dk
- [ ] Dosya upload (PNG/JPG) + önizleme
- [ ] Yol A (tercih): vision-capable open-weight (örn. `llava` / `moondream`) — RAM yeterse
- [ ] Yol B (yedek): OCR yoksa bile “açıklama + checklist” (logo yok, URL çubuğu tuhaf, aciliyet dili) — text LLM’e kullanıcı notu ile
- [ ] Çıktı: phishing UI olasılığı + görsel ipuçları
- [ ] `examples/screenshots/` sahte örnekler (kendi ürettiğin / kamu domain)
- [ ] **Checkpoint:** üç sekme de “bir şey” döndürüyor (boş sekme yok)

### FAZ 5 — Paketleme & teslim (zorunlu) ~45–60 dk
- [ ] README: ne / nasıl çalıştır / model adı + lisans linki / deps / uyarı (“eğitim amaçlı, gerçek antivirus değil”)
- [ ] Public GitHub repo + push
- [ ] (Opsiyonel) Render veya DO deploy — **DO kredisini bugün aktive etme**
- [ ] Demo prova: 2 dk anlatım (problem → 3 mod → live click)
- [ ] OrganizerHQ submit + **Best Open-Source AI Project**

### Hack Day 6 saat — sıkıştırılmış saat planı
| Saat | Odak |
|------|------|
| 0:00–0:45 | Faz 1 iskelet + Ollama |
| 0:45–2:15 | Faz 2 Mod 1 bitir |
| 2:15–3:45 | Faz 3 Mod 4 |
| 3:45–5:00 | Faz 4 Mod 3 (veya Yol B) |
| 5:00–5:45 | README + LICENSE + GitHub |
| 5:45–6:00 | Demo prova + submit |

---

## 6) Pratik checklist (genel)

- [ ] MyMLH telefon + GitHub  
- [x] Proje fikri net (SecLens — 3 mod güvenlik AI)  
- [ ] Public GitHub repo  
- [ ] LICENSE (MIT)  
- [ ] README (ne / nasıl / model / deps)  
- [ ] Çalışan demo (en az Mod 1)  
- [ ] (Opsiyonel) Render / DO deploy  
- [ ] OrganizerHQ submit  

---

## 7) Yeni sohbete verilecek kısa prompt (kopyala)

```
Hacktoberfest 2026 bireysel okul yarışması. Şirket/LSOC değil.
Klasör: /Users/tamer/Desktop/HACKTOBERFEST/
Önce şu dosyayı oku: HACKTOBERFEST-BAGLAM.md
Proje: SecLens — Streamlit + Ollama, 3 mod (TR phishing metin / kod güvenlik / login screenshot).
Hedef: MLH Best Open-Source AI Project.
Public repo + MIT + README (model dahil) + çalışan demo.
DO $25 Hack Day’e sakla; Render $50 erken claim OK.
Task list: BAGLAM Faz 0→5. Kaldığımız fazdan devam.
```

---

## 8) Bilinçli boşluklar

- Repo adı GitHub’da netleşecek (`seclens` önerilir)  
- Takım yok (bireysel)  
- Hack Day tarih/saat ve submit deadline → host’tan  
- Kesin model adı: makine RAM’ine göre seçilecek (Faz 1’de kilitle)  
- Browserbase / ElevenLabs / Tinker bu MVP’de yok  

---

*Son güncelleme: 2026-10-24 · Proje: SecLens · Kaynak: mlh.com/opensource-ai + hacktoberfest.com/my/promos*
