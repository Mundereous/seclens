# SecLens

**Open-weight AI güvenlik asistanı** — Türkçe SMS/e-posta oltalama (smishing/phishing) tespiti odaklı.

Hacktoberfest 2026 · [Best Open-Source AI Project](https://www.mlh.com/opensource-ai)  
Repo: [github.com/Mundereous/seclens](https://github.com/Mundereous/seclens)

> Eğitim / farkındalık aracıdır. Gerçek antivirüs, adli bilirkişi raporu veya banka güvenlik ürünü yerine **geçmez**.

---

## Ne yapıyor?

Tek Streamlit uygulamasında üç mod planlandı; **Mod 1 şu an çalışıyor**:

| Mod | Durum | Ne yapar |
|-----|--------|----------|
| **1 · Metin** | Hazır | Türkçe SMS / e-posta → risk skoru + gerekçe + öneri |
| **2 · Kod** | Yakında | Snippet’te secret, SQLi, XSS vb. tarama |
| **3 · Görüntü** | Yakında | Login screenshot phishing UI analizi |

### Mod 1 nasıl çalışıyor? (önemli)

İki katman:

1. **Kural tabanlı sinyaller** (`core/scam_patterns.py`) — Türkiye’de bilinen dolandırıcılık kalıpları (kelime, link, telefon, IBAN…). Skorun büyük kısmı buradan gelir.
2. **Open-weight LLM** (Ollama, `llama3.2:1b`) — kural özetine bakarak Türkçe gerekçe / öneri üretir.

Bu bir **fine-tune / “model eğitimi” değildir**. Küçük yerel model + kamu uyarılarından derlenen kurallar = 6 saatlik hackathon için güvenilir ve şeffaf yol. “Eğittik” derken kastettiğimiz: **kalıp listesini gerçek olay ve kurum uyarılarıyla zenginleştirdik**.

---

## Neleri tespit ediyor? (Mod 1)

| Kalıp | Örnek sinyal | Demo dosya |
|--------|--------------|------------|
| Sahte banka SMS | Bloke / güvenlik güncelle + şüpheli link | `examples/phishing_sms.txt` |
| Sahte kargo e-posta | PTT/kargo + iade / işlem bedeli + link | `examples/phishing_email.txt` |
| Uzlaştırma / savcılık | “son günü”, “arayın” + telefon | `examples/scam_uzlastirma.txt` |
| e-Devlet taklidi | Askıya alma + dış link | `examples/scam_edevlet.txt` |
| Gümrük / HGS / kargo | “gümrükte vergi”, “adres eksik” | `examples/scam_kargo_gumruk.txt` |
| Kripto smishing | “hesabınız tehlikede” + kısa link | `examples/scam_kripto.txt` |
| IBAN / EFT tuzağı | IBAN + “hemen havale / indirim kaçmasın” | `examples/scam_iban_eft.txt` |
| Hediye / maket spam | “özel hediye”, iletilmiş no-reply mail | `examples/scam_hediye_maket.txt` |
| Güvenli kontrol | Toplantı / arkadaş mesajı (düşük risk) | `examples/safe_*.txt` |

Ek teknik sinyaller:

- `http(s)` link, şüpheli TLD (`.xyz`, `.top`…), IP adresi link, bit.ly kısaltma  
- Türkiye telefon numarası (`0…` / `+90…`)  
- TR IBAN (`TR…`)  
- Banka / kargo markası + link veya telefon birlikte  

Çıktı: **risk** (`dusuk` / `orta` / `yuksek`), **skor 0–100**, gerekçeler, öneriler (ör. 5010 hattı).

---

## “Nelerle eğittik?” — kaynaklar

Sinir ağını yeniden eğitmedik. Kalıp listesi şu tür **açık kaynak / kamu uyarılarından** derlendi:

- T.C. İçişleri / Emniyet operasyon duyuruları (e-Devlet yardım linki, “ceza soruşturmanızın son günü” SMS’leri)  
- BTK + Emniyet smishing uyarıları (sahte kargo, banka güncelleme SMS)  
- [PTT resmi dolandırıcılık uyarısı](https://www.ptt.gov.tr/haberler/ptt-as-dolandiricilik-faaliyetlerine-karsi-vatandaslari-uyariyor-d20119c1273f42ac856e02f814b8d959) (gümrük vergisi, adres güncelleme)  
- Basın / şikayet platformları: kripto “hesabınız tehlikede”, IBAN+EFT “indirim kaybolacak” tuzakları  
- e-Devlet phishing farkındalık yazıları (askıya alma + login linki kalıbı)  

Kalıplar kodda: `core/scam_patterns.py`  
Skor birleştirme: `core/phishing.py`  

İleride daha büyük open-weight model veya (opsiyonel) fine-tune eklenebilir; MVP bilerek **kural + küçük LLM** ile kuruldu.

---

## Model ve bağımlılıklar

| Bileşen | Detay |
|---------|--------|
| **Model** | [`llama3.2:1b`](https://ollama.com/library/llama3.2) (Meta Llama 3.2, ~1B parametre → challenge tanımında **small language model**) |
| **Çalıştırma** | [Ollama](https://ollama.com) yerel API (`http://127.0.0.1:11434`) |
| **Model lisansı** | Llama 3.2 Community License — [Meta Llama](https://www.llama.com/llama3_2/license/) / model kartındaki terms |
| **UI** | Streamlit |
| **HTTP** | `requests` |
| **Görüntü (ileride)** | Pillow |

Open-weight ≠ projenin tamamı otomatik open source. Bu repo **MIT**; model kendi lisansına bağlıdır.

---

## Kurulum ve çalıştırma

### Gereksinimler

- Python 3.10+  
- [Ollama](https://ollama.com) (Mac: Applications → Ollama)  
- İnternet (yalnızca ilk `ollama pull` için)

### Adımlar

```bash
git clone https://github.com/Mundereous/seclens.git
cd seclens

python3 -m pip install -r requirements.txt

# Ollama açıkken:
ollama pull llama3.2:1b

streamlit run app.py
```

Tarayıcı: **http://127.0.0.1:8501**

İlk Streamlit açılışında e-posta sorulursa boş bırakılabilir (`~/.streamlit/credentials.toml` ile atlanabilir).

### Demo (Mod 1)

1. Sol menüde modelin `llama3.2:1b` olduğunu kontrol et  
2. “Hazır örnekler”den bir kalıp seç → **Örneği yükle**  
3. **Analiz et**  
4. Risk, skor (kural skoru da gösterilir), gerekçe ve önerileri oku  

---

## Proje yapısı

```
seclens/
├── app.py                  # Streamlit arayüz (3 sekme)
├── requirements.txt
├── LICENSE                 # MIT
├── README.md
├── HACKTOBERFEST-BAGLAM.md # Hack Day plan / promo notları
├── core/
│   ├── ollama_client.py    # Yerel Ollama chat API
│   ├── phishing.py         # Mod 1: kurallar + LLM birleşimi
│   └── scam_patterns.py    # TR dolandırıcılık sinyal sözlüğü
└── examples/               # Demo SMS / e-posta metinleri
```

---

## Challenge checklist

- [x] Open-weight AI projenin önemli parçası (Ollama + Llama 3.2)  
- [x] Public GitHub + [MIT](LICENSE)  
- [x] README: ne / nasıl / model + bağımlılık / model lisans linki  
- [x] Çalışan demo (Mod 1)  
- [ ] Mod 2 kod tarama  
- [ ] Mod 3 screenshot  
- [ ] (Opsiyonel) Render / DigitalOcean deploy  

---

## Yol haritası

1. **Mod 2** — kural tabanlı kod güvenlik + LLM açıklama  
2. **Mod 3** — vision model veya checklist ile login screenshot  
3. İsteğe bağlı daha büyük model (`llama3.2:3b` vb.)  
4. Deploy + OrganizerHQ submit  

Hack Day planı: `HACKTOBERFEST-BAGLAM.md`

---

## Güvenlik ve etik

- Örnekler **uydurma / anonimleştirilmiş** eğitim metinleridir; gerçek mağdur verisi yoktur.  
- Amaç: kullanıcıya “bu kalıp tehlikeli olabilir” demek; otomatik engelleme veya suç isnadı yok.  
- Şüpheli gerçek SMS’ler için Türkiye’de **5010** (Dolandırıcılıkla Mücadele) bildirimi önerilir.  

---

## Lisans

Kod: [MIT](LICENSE) · Copyright (c) 2026 Mundereous  

Model: Llama 3.2 Community License (Meta) — ağırlıklar Ollama üzerinden indirilir, bu repoda tutulmaz.
