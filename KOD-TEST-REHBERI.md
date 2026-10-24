# Kod tarayıcıyı nasıl test edersin?

Uygulama: **http://127.0.0.1:8501** → sekme **2 · Kod**

---

## 1) En kolayı — uygulamadaki liste

**Örneği yükle** listesinde iki grup var:

### A) Bizim senaryolar (`examples/code/01…10`)
Üstünde **NEDEN TEHLİKELİ** yazıyor → öğrenmek + demo için ideal.

### B) Bandit harici örnekler (`examples/code/external/`)
[PyCQA Bandit](https://github.com/PyCQA/bandit/tree/main/examples) resmi SAST test dosyaları.  
SecLens’i “dışarıdan gelen gerçek örnek” ile denemek için.

Önerilen sıra:
1. `01 Hardcoded secret` → bulgu beklenir  
2. `02 SQL Injection` → bulgu beklenir  
3. `Bandit: subprocess_shell` → bulgu beklenir  
4. `Bandit: pickle_deserialize` → bulgu beklenir  
5. `10 Güvenli referans` veya `Bandit: okay` → az/sıfır bulgu  

---

## 2) İnternetten kendin kopyala

| Yer | Link |
|-----|------|
| **Bandit examples (en iyisi)** | https://github.com/PyCQA/bandit/tree/main/examples |
| Semgrep OWASP playground | https://semgrep.dev/p/owasp-top-ten |
| OWASP lab listesi | https://owasp.org/www-project-vulnerable-web-applications-directory/ |

Bandit’te bir `.py` aç → içeriği kopyala → SecLens’te **Kod yapıştır** → **Tara**.

---

## 3) Klasör yolları (Finder)

```
HACKTOBERFEST/
  examples/code/           ← bizim 01–10 (+ README)
  examples/code/external/  ← Bandit’ten indirilenler
```

---

## Not

- SecLens **pattern mini-SAST**; Bandit kadar derin değil. Bazı Bandit örneklerini yakalayamayabilir — bu normal, sunumda “kapsam sınırlı, eğitim amaçlı” de.  
- Gerçek sitelerden kod çalıp tarama; sadece eğitim örnekleri kullan.
