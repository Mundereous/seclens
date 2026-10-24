# Altay Phishing Quiz örnekleri

Kaynak: [phisquiz.siberaltay.org](https://phisquiz.siberaltay.org/)  
Hazırlayan: **Altay Takımı / Siber Vatan** — eğitim amaçlı 30 e-posta ekran görüntüsü.

| | |
|--|--|
| Dosyalar | `resimNN_phishing.png` / `resimNN_real.png` |
| Etiketler | `manifest.json` (`correct`, açıklama, URL/not ipuçları) |
| Soru listesi | `questions.js` (orijinal quiz verisi) |

SecLens → **3 · Görüntü** → `Örnek NN · PHISH/GERÇEK` seç → **Örneği yükle** → **Görüntüyü analiz et**.

Karşılaştırma scripti (repo kökünden):

```bash
python3 scripts/test_altay_quiz.py
```
