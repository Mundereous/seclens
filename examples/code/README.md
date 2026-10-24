# Kod zafiyet test senaryoları

Her dosyanın **üst yorumunda** zafiyetin adı, OWASP/CWE kodu, **neden tehlikeli olduğu** ve doğru yaklaşım yazar.

| Dosya | Zafiyet | CWE |
|-------|---------|-----|
| `01_hardcoded_secret.py.txt` | Hardcoded secret | CWE-798 |
| `02_sql_injection.py.txt` | SQL Injection | CWE-89 |
| `03_command_injection.py.txt` | OS Command Injection | CWE-78 |
| `04_xss_innerhtml.js.txt` | XSS | CWE-79 |
| `05_insecure_deserialization.py.txt` | Insecure deserialization | CWE-502 |
| `06_path_traversal.py.txt` | Path traversal | CWE-22 |
| `07_ssrf.py.txt` | SSRF | CWE-918 |
| `08_weak_crypto_tls.py.txt` | Weak crypto / TLS off | CWE-328, 295 |
| `09_secret_in_logs.py.txt` | Secrets in logs | CWE-532 |
| `10_safe_reference.py.txt` | Güvenli referans (bulgu beklenmez) | — |
| `11_twisted_httpoxy.py.txt` | Twisted /root + CGI (httpoxy) | CWE-552, 15 |
| `12_extended_rules_demo.py.txt` | Genişletilmiş kural demosu (karma) | çoklu |

`external/` altında [Bandit](https://github.com/PyCQA/bandit) resmi örnekleri de var (karşılaştırma için).

SecLens → **Kod** sekmesi → listeden seç → **Örneği yükle** → **Tara** (~118 OWASP/CWE kuralı).
