# SecLens

Open-weight AI güvenlik asistanı — Hacktoberfest 2026 / [Best Open-Source AI Project](https://www.mlh.com/opensource-ai).

Tek uygulama, üç mod:

1. **Metin** — Türkçe e-posta/SMS phishing analizi  
2. **Kod** — snippet güvenlik taraması (secret, SQLi, XSS vb.)  
3. **Görüntü** — login ekranı screenshot phishing UI analizi  

Stack: Streamlit + Ollama (yerel open-weight model).

> Yapım aşamasında. Detaylı plan: `HACKTOBERFEST-BAGLAM.md`

## Hızlı başlangıç

```bash
# 1) Python paketleri
pip install -r requirements.txt

# 2) Ollama kur (https://ollama.com) sonra model çek
ollama pull llama3.2:3b

# 3) Uygulamayı aç
streamlit run app.py
```

## Lisans

[MIT](LICENSE)
