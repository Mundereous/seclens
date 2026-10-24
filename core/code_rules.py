"""
Mod 2 — Eğitim amaçlı mini-SAST (pattern / regex).

OWASP Top 10 ve yaygın CWE kalıplarına göre satır tarar.
Gerçek Semgrep/CodeQL/Bandit yerine geçmez; taint analizi yok.
Referans: OWASP SAST rehberi, yaygın injection/XSS/secrets kalıpları.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str  # high | medium | low
    owasp: str  # örn. A03:Injection
    cwe: str  # örn. CWE-89
    pattern: re.Pattern[str]
    detail: str
    fix: str
    window: int = 1  # >1 ise ardışık satır penceresinde ara (IDOR vb.)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    line: int
    snippet: str
    fix: str
    owasp: str = ""
    cwe: str = ""
    rule_id: str = ""


@dataclass
class CodeScanResult:
    findings: list[Finding] = field(default_factory=list)
    skor: int = 0
    risk: str = "dusuk"
    ozet: str = ""
    by_owasp: dict[str, int] = field(default_factory=dict)


def _r(
    rid: str,
    title: str,
    severity: str,
    owasp: str,
    cwe: str,
    pattern: str,
    detail: str,
    fix: str,
    flags: int = re.I,
    window: int = 1,
) -> Rule:
    return Rule(
        id=rid,
        title=title,
        severity=severity,
        owasp=owasp,
        cwe=cwe,
        pattern=re.compile(pattern, flags | (re.DOTALL if window > 1 else 0)),
        detail=detail,
        fix=fix,
        window=max(1, window),
    )


# --- Kural seti (OWASP 2021 odaklı) ---
RULES: list[Rule] = [
    # A02 Cryptographic Failures / secrets
    _r(
        "SEC001",
        "Hardcoded parola / secret",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)\s*=\s*['\"][^'\"]{4,}['\"]""",
        "Kimlik bilgisi kaynak koduna gömülü (CWE-798 Use of Hard-coded Credentials).",
        "os.environ / secret manager kullan; repoya commit etme; sızdıysa rotate et.",
    ),
    _r(
        "SEC002",
        "AWS access key ID",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
        "AWS access key kalıbı (AKIA/ASIA…) tespit edildi.",
        "IAM anahtarını iptal/rotate et; uzun ömürlü key yerine rol kullan.",
    ),
    _r(
        "SEC003",
        "Private key bloğu",
        "high",
        "A02:Cryptographic Failures",
        "CWE-321",
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        "Private key dosya içeriği koda yapıştırılmış.",
        "Key'i dosya/HSM'de tut; asla kaynak kontrolüne koyma.",
    ),
    _r(
        "SEC004",
        "Veritabanı URL içinde şifre",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""(mysql|postgres|postgresql|mongodb|redis|amqp):\/\/[^:\s\/]+:[^@\s\/]+@""",
        "Connection string içinde kullanıcı:şifre görünüyor.",
        "URI'yi env'den oku; şifreyi loglama.",
    ),
    _r(
        "SEC005",
        "JWT / Bearer token gömülü",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b""",
        "JWT benzeri token kaynakta duruyor olabilir.",
        "Token'ı kodda saklama; kısa ömürlü + httpOnly cookie tercih et.",
    ),
    _r(
        "SEC006",
        "Zayıf hash (MD5/SHA1)",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-328",
        r"""(hashlib\.)?(md5|sha1)\s*\(|\bhash\s*\(\s*['\"]md5['\"]""",
        "MD5/SHA1 çarpışmaya açık ve GPU ile hızlı kırılır; bütünlük için bile SHA-256+ tercih edilir. "
        "Parola saklama için asla kullanılmamalı (ayrıca SEC021).",
        "Bütünlük/checksum: SHA-256 veya BLAKE2. Parola: argon2id / bcrypt / scrypt (salt + cost).",
    ),
    _r(
        "SEC007",
        "Random yerine insecure random",
        "low",
        "A02:Cryptographic Failures",
        "CWE-330",
        r"""\brandom\.(random|randint|choice)\s*\(.*?(token|secret|password|otp|key)""",
        "Kriptografik değer için zayıf PRNG kullanımı şüphesi (tahmin edilebilir seed).",
        "Python: secrets modülü veya os.urandom. Node: crypto.randomBytes.",
    ),
    _r(
        "SEC021",
        "Parola MD5/SHA1 ile hashleniyor",
        "high",
        "A02:Cryptographic Failures",
        "CWE-328",
        r"""(password|passwd|pwd|parola|hashedPassword|password_hash).{0,100}\b(md5|sha1|sha1_hex|DigestUtils\.(md5|sha1))\s*\(|\b(md5|sha1)\s*\(\s*\$?(password|passwd|pwd|parola)\b""",
        "Kullanıcı parolasını MD5/SHA1 ile saklamak kritik zayıflık: rainbow table + ucuz brute-force. "
        "OWASP ASVS parola depolama (V2.4) ihlali.",
        "password_hash()/password_verify() (PHP), bcrypt/argon2id (Python/Node). Salt otomatik olsun; cost factor ayarla.",
        window=5,
    ),
    _r(
        "SEC022",
        "Parola düz metin karşılaştırma",
        "high",
        "A02:Cryptographic Failures",
        "CWE-256",
        r"""(password|passwd|parola)\s*===?\s*['\"][^'\"]+['\"]|['\"][^'\"]+['\"]\s*===?\s*(password|passwd|parola)\b""",
        "Parola sabit string ile karşılaştırılıyor — sızıntı/timing ve zayıf auth.",
        "Hash ile doğrula (password_verify / check_password); timing-safe compare kullan.",
    ),
    # A03 Injection
    _r(
        "INJ001",
        "SQL f-string / interpolasyon",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""f['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^'\"]*\{""",
        "SQL + f-string → SQL Injection (CWE-89).",
        "Parametreli sorgu: execute('... WHERE id=?', (id,)).",
    ),
    _r(
        "INJ002",
        "SQL execute + birleştirme",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""(execute|executemany|raw)\s*\(\s*(f['\"]|['\"][^'\"]*(\+|%)|.*\.format\s*\()""",
        "execute içinde string birleştirme SQLi riski.",
        "Placeholder (?, %s, $1) + tuple/dict parametre kullan.",
    ),
    _r(
        "INJ003",
        "SQL / execute + birleştirme",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""(execute|executemany)\s*\([^;]*\+""",
        "execute içinde + ile birleştirme → SQL Injection.",
        "ORM veya prepared statement kullan.",
    ),
    _r(
        "INJ004",
        "os.system / popen",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""\b(os\.system|os\.popen|commands\.getoutput|commands\.getstatusoutput)\s*\(""",
        "OS komut enjeksiyonu (CWE-78) için klasik sink.",
        "subprocess.run([...], shell=False) ve sabit argüman listesi.",
    ),
    _r(
        "INJ005",
        "subprocess shell=True",
        "high",
        "A03:Injection",
        "CWE-78",
        r"shell\s*=\s*True",
        "shell=True kullanıcı girdisiyle birleşince command injection olur.",
        "shell=False; gerekirse shlex.quote (yine de listed args tercih et).",
    ),
    _r(
        "INJ006",
        "Node child_process.exec",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""\b(exec|execSync|spawnSync)\s*\(\s*[`'\"].*\$\{""",
        "Node.js shell komutunda template literal + değişken.",
        "execFile / spawn ile argüman dizisi kullan; shell açma.",
    ),
    _r(
        "INJ007",
        "eval / exec (kod enjeksiyonu)",
        "high",
        "A03:Injection",
        "CWE-95",
        r"""\b(eval|exec|Function)\s*\(""",
        "Dinamik kod çalıştırma → RCE / code injection.",
        "eval yasakla; json.loads / ast.literal_eval gibi güvenli alternatifler.",
    ),
    _r(
        "INJ008",
        "NoSQL $operatör şüphesi",
        "medium",
        "A03:Injection",
        "CWE-943",
        r"""['\"]\$(gt|gte|lt|lte|ne|in|nin|regex|where)['\"]""",
        "MongoDB operatör enjeksiyonu için tipik anahtarlar.",
        "Kullanıcı JSON'unu olduğu gibi query'ye verme; tip zorla / whitelist.",
    ),
    # A05 Security Misconfiguration / XSS related often A03 too - XSS is often A03
    _r(
        "XSS001",
        "innerHTML ataması",
        "high",
        "A03:Injection",
        "CWE-79",
        r"\.innerHTML\s*=",
        "DOM XSS (CWE-79): innerHTML ile ham HTML.",
        "textContent kullan veya DOMPurify ile sanitize et.",
    ),
    _r(
        "XSS002",
        "dangerouslySetInnerHTML / v-html",
        "high",
        "A03:Injection",
        "CWE-79",
        r"(dangerouslySetInnerHTML|v-html\s*=)",
        "React/Vue'da kasıtlı HTML enjeksiyon yüzeyi.",
        "Mümkünse kaçın; HTML şartsa sıkı sanitize + CSP.",
    ),
    _r(
        "XSS003",
        "document.write",
        "medium",
        "A03:Injection",
        "CWE-79",
        r"document\.write\s*\(",
        "document.write XSS ve brittle DOM üretir.",
        "Güvenli DOM API ile ekleme yap.",
    ),
    _r(
        "XSS004",
        "jQuery .html() kullanıcı verisi",
        "medium",
        "A03:Injection",
        "CWE-79",
        r"""\$\([^)]*\)\.html\s*\(""",
        "jQuery .html() XSS için sık istismar edilir.",
        ".text() kullan veya sanitize et.",
    ),
    _r(
        "XSS005",
        "Jinja |safe / autoescape off",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""(\|\s*safe\b|autoescape\s+false|Markup\s*\()""",
        "Şablon motorunda escape kapatılmış.",
        "Autoescape açık tut; trusted HTML'i sıkı filtrele.",
    ),
    # A04 / A08 Software and Data Integrity - deserialization
    _r(
        "DES001",
        "pickle.loads",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"\bpickle\.loads\s*\(",
        "Insecure deserialization: pickle RCE yapabilir (CWE-502).",
        "JSON kullan; pickle yalnızca güvendiğin kaynakta.",
    ),
    _r(
        "DES002",
        "yaml.load (güvensiz)",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\byaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*yaml\.SafeLoader)""",
        "yaml.load varsayılanı nesne oluşturabilir.",
        "yaml.safe_load veya SafeLoader kullan.",
    ),
    _r(
        "DES003",
        "PHP unserialize",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"\bunserialize\s*\(",
        "PHP unserialize object injection riski.",
        "JSON kullan; unserialize'ı kullanıcı girdisinde yasakla.",
    ),
    # A01 Broken Access / path
    _r(
        "PTH001",
        "Dosya yolu birleştirme (şüphe)",
        "medium",
        "A01:Broken Access Control",
        "CWE-22",
        r"""(?:\bopen|\bsend_file|\bsendfile|\bfile_get_contents|\breadFile(?:Sync)?)\s*\(\s*(?:f['\"]|[^)\n]*\+)""",
        "Dosya yolu kullanıcı verisiyle birleşiyor olabilir → path traversal (CWE-22).",
        "basename + allowlist dizin; Path.resolve ile kök dışına çıkmayı engelle.",
    ),

    _r(
        "PTH002",
        "../ path traversal literal",
        "medium",
        "A01:Broken Access Control",
        "CWE-22",
        r"""['\"][^'\"]*\.\./|\.\.\\""",
        "Kodda '../' ile üst dizin gezinme.",
        "Kullanıcıdan gelen yolda .. reddet / normalize et.",
    ),
    # A05 / A07 Auth misconfig
    _r(
        "CFG001",
        "TLS verify=False",
        "high",
        "A05:Security Misconfiguration",
        "CWE-295",
        r"verify\s*=\s*False",
        "TLS sertifika doğrulaması kapalı (MITM).",
        "verify=True; kurumsal CA'yı trust store'a ekle.",
    ),
    _r(
        "CFG002",
        "DEBUG / Flask debug",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-489",
        r"""(DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True|Flask\(\s*__name__\s*\).*debug)""",
        "Debug modu production'da bilgi sızdırır / interactive console riski.",
        "Production'da DEBUG=False.",
    ),
    _r(
        "CFG003",
        "CORS Allow-Origin * + credentials şüphesi",
        "low",
        "A05:Security Misconfiguration",
        "CWE-942",
        r"""Access-Control-Allow-Origin['\"\s:]*\*""",
        "Wildcard CORS aşırı geniş erişim verebilir.",
        "Origin whitelist kullan.",
    ),
    _r(
        "CFG004",
        "HTTP (şifresiz) URL hardcode",
        "low",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]""",
        "Cleartext HTTP URL (CWE-319).",
        "HTTPS kullan.",
    ),
    # SSRF hints
    _r(
        "SSRF001",
        "SSRF: kullanıcı/istek URL'si",
        "medium",
        "A10:SSRF",
        "CWE-918",
        r"""(requests\.(get|post|put|delete)|urllib\.request\.urlopen|fetch\s*\()\s*\(\s*(request\.|req\.|params\[|query\.|user_url|target_url)""",
        "İstek/kullanıcı URL'si doğrudan fetch ediliyor → SSRF (CWE-918).",
        "Allowlist host; private IP / cloud metadata (169.254.169.254) engelle.",
    ),
    _r(
        "SSRF002",
        "SSRF: f-string / birleşik URL fetch",
        "medium",
        "A10:SSRF",
        "CWE-918",
        r"""(requests\.(get|post)|fetch\s*\()\s*\(\s*f['\"]""",
        "URL f-string ile kurulup isteniyor — SSRF/open redirect riski.",
        "Host'u sabit tut; path'i doğrula.",
    ),
    # XXE
    _r(
        "XXE001",
        "XML parse özellikler açık",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""resolve_entities\s*=\s*True|XMLParser\s*\([^)]*resolve_entities""",
        "XXE: external entity çözümleme açık bırakılmış.",
        "resolve_entities=False; tercihen defusedxml.",
    ),
    # Logging sensitive
    _r(
        "LOG001",
        "Log'a parola/token",
        "medium",
        "A09:Security Logging and Monitoring Failures",
        "CWE-532",
        r"""(print|log|logger\.(debug|info|warning|error)|console\.log)\s*\(.*?(password|passwd|token|secret|api_key|authorization)""",
        "Hassas veri loglanıyor olabilir (CWE-532).",
        "Secret'ları log'a yazma; maskele.",
    ),
    _r(
        "LOW001",
        "TODO güvenlik",
        "low",
        "A05:Security Misconfiguration",
        "CWE-546",
        r"TODO.*?(security|auth|password|hack|vuln|csrf|xss|sqli)",
        "Güvenlikle ilgili TODO bırakılmış.",
        "Release öncesi TODO'yu kapat veya ticket'a bağla.",
    ),
    # Twisted / httpoxy / hassas dizin servisi (Bandit httpoxy_twisted_* ailesi)
    _r(
        "CFG005",
        "Hassas dizin web'e açılmış (File/static)",
        "high",
        "A01:Broken Access Control",
        "CWE-552",
        r"""(?:static\.File|File)\s*\(\s*['\"]/(?:root|etc|home|var/root|Users)[^'\"]*['\"]""",
        "/root, /etc, /home gibi hassas yollar HTTP ile servis ediliyor (bilgi sızdırma).",
        "Sadece public document root sun; asla /root veya sistem dizinlerini açma.",
    ),
    _r(
        "CFG006",
        "Twisted CGIScript (httpoxy riski)",
        "high",
        "A05:Security Misconfiguration",
        "CWE-15",
        r"""\btwcgi\.(CGIScript|CGIDirectory)\s*\(""",
        "Twisted CGI, Proxy header'ı HTTP_PROXY env'e taşıyabilir (httpoxy).",
        "CGI kullanma; WSGI/ASGI tercih et. CGI şartsa Proxy header'ı filtrele.",
    ),
    _r(
        "CFG007",
        "Privileged port 80/443 dinleme",
        "low",
        "A05:Security Misconfiguration",
        "CWE-250",
        r"""listenTCP\s*\(\s*(80|443)\s*,""",
        "80/443 dinlemek genelde root gerektirir; yanlış yetki modeli.",
        "Reverse proxy (nginx) arkasına al; app yüksek portta çalışsın.",
    ),
    # ========== GENİŞLETİLMİŞ SET (Bandit / Semgrep / OWASP kalıpları) ==========
    # Crypto / weak algorithms
    _r(
        "SEC008",
        "DES / RC4 / Blowfish zayıf şifre",
        "high",
        "A02:Cryptographic Failures",
        "CWE-327",
        r"""\b(Cipher\.(DES|ARC4|ARC2|Blowfish)|algorithms\.(TripleDES|ARC4)|MODE_ECB|Crypto\.Cipher\.DES)\b|\bRC4\b""",
        "Zayıf/eskirmiş simetrik algoritma veya ECB modu şüphesi.",
        "AES-GCM / ChaCha20-Poly1305 kullan; ECB'den kaçın.",
    ),
    _r(
        "SEC009",
        "Insecure SSL/TLS sürümü",
        "high",
        "A02:Cryptographic Failures",
        "CWE-326",
        r"""ssl\.PROTOCOL_(SSLv2|SSLv3|TLSv1[^_]|TLSv1_1)\b|SSL\.(SSLv2|SSLv3|SSLv23|TLSv1|TLSv1_1)_METHOD\b""",
        "SSLv2/3 veya TLS1.0/1.1 güvensizdir.",
        "TLS 1.2+ zorunlu kıl.",
    ),
    _r(
        "SEC010",
        "ssl._create_unverified_context",
        "high",
        "A02:Cryptographic Failures",
        "CWE-295",
        r"""_create_unverified_context|CERT_NONE""",
        "Sertifika doğrulaması kapatılmış.",
        "Varsayılan SSL context kullan; CERT_REQUIRED.",
    ),
    _r(
        "SEC011",
        "Zayıf RSA/DSA anahtar boyutu",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-326",
        r"""generate(_private)?_key\s*\([^\)]*(1024|512)\b|key_size\s*=\s*(512|1024)\b""",
        "1024 bit altı/eşi anahtarlar kırılgandır.",
        "En az 2048 (tercihen 3072+) bit kullan.",
    ),
    _r(
        "SEC012",
        "Google API key kalıbı",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""\bAIza[0-9A-Za-z\-_]{35}\b""",
        "Google API key formatı tespit edildi.",
        "Key'i kısıtla (HTTP referrer/IP); rotate et; env'de tut.",
    ),
    _r(
        "SEC013",
        "Slack/GitHub token kalıbı",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""\b(xox[baprs]-|ghp_|gho_|github_pat_)[A-Za-z0-9_\-]{10,}\b""",
        "Slack veya GitHub personal token kalıbı.",
        "Token'ı iptal et; secret store kullan.",
    ),
    _r(
        "SEC014",
        "hashlib.new insecure",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-327",
        r"""hashlib\.new\s*\(\s*['\"]?(md5|sha1|MD5|SHA1)""",
        "hashlib.new ile zayıf algoritma.",
        "sha256+ veya blake2 kullan.",
    ),
    _r(
        "SEC015",
        "PyCrypto / insecure crypto lib",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-1104",
        r"""\bfrom Crypto\.|\bimport Crypto\b|\bfrom Cryptodome\.""",
        "Eski/yanlış kullanılan kripto paketleri dikkat ister.",
        "cryptography kütüphanesini tercih et; güncel tut.",
    ),
    # More injection
    _r(
        "INJ009",
        "Django raw SQL",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""\.(raw|extra)\s*\(|RawSQL\s*\(|cursor\.execute\s*\(\s*f['\"]""",
        "Django raw/extra SQL enjeksiyon riski.",
        "ORM / parametreli raw kullan.",
    ),
    _r(
        "INJ010",
        "os.popen / popen2",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""\b(os\.popen|popen2|commands\.getoutput)\s*\(""",
        "popen shell komut enjeksiyonuna açık.",
        "subprocess.run listed args ile.",
    ),
    _r(
        "INJ011",
        "os.exec* / spawn",
        "medium",
        "A03:Injection",
        "CWE-78",
        r"""\bos\.(execl|execle|execlp|execlpe|execv|execve|execvp|execvpe|spawn)\s*\(""",
        "Process spawn kullanıcı girdisiyle birleşirse tehlikeli.",
        "Argümanları doğrula; shell kullanma.",
    ),
    _r(
        "INJ012",
        "Paramiko exec_command + format",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""\.exec_command\s*\(""",
        "Paramiko exec_command — komut enjeksiyonu / uzaktan RCE yüzeyi.",
        "Sabit allowlist komutlar; kullanıcı girdisini shell'e birleştirme.",
    ),
    _r(
        "INJ013",
        "Wildcard injection (shell glob)",
        "medium",
        "A03:Injection",
        "CWE-78",
        r"""\b(chown|chmod|tar|rsync)\s+.*\*|/bin/(chown|chmod).*shell""",
        "Shell wildcard ile beklenmeyen dosya eşleşmesi riski.",
        "Glob'u Python'da çöz; shell'e * verme.",
    ),
    _r(
        "INJ014",
        "LDAP filtre birleştirme",
        "high",
        "A03:Injection",
        "CWE-90",
        r"""ldap.*search.*\+|filter\s*=\s*f['\"].*\(|\(\s*&.*\{""",
        "LDAP injection: filtreye kullanıcı girdisi.",
        "LDAP escape kullan; parametrik filtre.",
    ),
    _r(
        "INJ015",
        "SSTI / template format kullanıcıdan",
        "high",
        "A03:Injection",
        "CWE-1336",
        r"""(Template|Environment)\s*\(.*request\.|render_template_string\s*\(.*\+|format_map\s*\(\s*request""",
        "Server-Side Template Injection şüphesi.",
        "Kullanıcı girdisini template olarak çalıştırma.",
    ),
    # XSS / template
    _r(
        "XSS006",
        "Django mark_safe / SafeString",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""\bmark_safe\s*\(|SafeString\s*\(|SafeText\s*\(""",
        "mark_safe XSS için bilerek escape kapatır.",
        "Sadece güvendiğin HTML; aksi halde escape bırak.",
    ),
    _r(
        "XSS007",
        "Jinja autoescape False",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""autoescape\s*=\s*False|Environment\s*\([^\)]*autoescape\s*=\s*False""",
        "Jinja autoescape kapalı → XSS.",
        "autoescape=True (varsayılan) bırak.",
    ),
    _r(
        "XSS008",
        "Mako template (escape kapalı risk)",
        "medium",
        "A03:Injection",
        "CWE-79",
        r"""\bmako\.|TemplateLookup\s*\(|from mako""",
        "Mako varsayılan escape Django/Jinja kadar katı olmayabilir.",
        "default_filters=['h'] / sıkı escape ayarla.",
    ),
    _r(
        "XSS009",
        "Markup(user) / Markupsafe",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""Markup\s*\(\s*(request\.|user_|input_|data)""",
        "Markup() XSS üretebilir.",
        "Escape edilmiş içerik kullan.",
    ),
    _r(
        "XSS010",
        "React href=javascript:",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""javascript:\s*|href\s*=\s*\{?['\"]javascript:""",
        "javascript: URL XSS/phishing vektörü.",
        "URL protokol allowlist (https:).",
    ),
    # Deserialization extended
    _r(
        "DES004",
        "marshal.loads",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\bmarshal\.loads\s*\(""",
        "marshal güvensiz deserialization.",
        "JSON kullan.",
    ),
    _r(
        "DES005",
        "shelve.open kullanıcı yolu",
        "medium",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\bshelve\.open\s*\(""",
        "Shelve pickle tabanlıdır; bozuk dosya RCE riski.",
        "Güvenilmeyen shelve açma.",
    ),
    _r(
        "DES006",
        "jsonpickle / dill decode",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\b(jsonpickle\.decode|dill\.loads|dill\.load)\s*\(""",
        "jsonpickle/dill keyfi nesne üretir.",
        "Sadece güvenilir kaynak; tercihen JSON.",
    ),
    _r(
        "DES007",
        "torch.load / pandas read_pickle",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\b(torch\.load|pandas\.read_pickle|pd\.read_pickle)\s*\(""",
        "ML pickle yükleme RCE ile bilinen risk.",
        "weights_only=True (torch) / güvenilir dosya; safetensors tercih et.",
    ),
    _r(
        "DES008",
        "tarfile.extractall",
        "high",
        "A01:Broken Access Control",
        "CWE-22",
        r"""\.extractall\s*\(""",
        "Tar slip: arşivde ../ ile dizin dışına yazma.",
        "Üyeleri tek tek doğrula; path traversal engelle.",
    ),
    # Network / cleartext protocols
    _r(
        "NET001",
        "FTP (ftplib) cleartext",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""\bftplib\.|FTP\s*\(""",
        "FTP kimlik bilgisi ve veri cleartext gider.",
        "SFTP / FTPS kullan.",
    ),
    _r(
        "NET002",
        "Telnet",
        "high",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""\btelnetlib\.|Telnet\s*\(""",
        "Telnet tamamen şifresizdir.",
        "SSH kullan.",
    ),
    _r(
        "NET003",
        "Paramiko AutoAddPolicy / yok host key",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-295",
        r"""AutoAddPolicy|RejectPolicy|WarningPolicy|missing_host_key|set_missing_host_key_policy""",
        "SSH host key doğrulaması zayıf/yok → MITM.",
        "Known_hosts ile Strict host key checking.",
    ),
    _r(
        "NET004",
        "urllib urlopen",
        "low",
        "A10:SSRF",
        "CWE-918",
        r"""urllib\.request\.urlopen\s*\(|urllib2\.urlopen\s*\(""",
        "urlopen SSRF için sık sink.",
        "URL'yi doğrula; allowlist.",
    ),
    # Auth / session
    _r(
        "AUTH001",
        "Flask SECRET_KEY hardcode",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""SECRET_KEY\s*=\s*['\"][^'\"]+['\"]""",
        "Flask/Django SECRET_KEY gömülü.",
        "Env'den oku; tahmin edilemez uzun değer.",
    ),
    _r(
        "AUTH002",
        "JWT verify=False / algorithms none",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-347",
        r"""jwt\.decode\s*\([^\n]*verify_signature\s*=\s*False|algorithms\s*=\s*\[[^\]]*['\"]none['\"]|options\s*=\s*\{[^\}]*verify_signature['\"]?\s*:\s*False""",
        "JWT imza doğrulaması kapalı / alg=none.",
        "Algoritmayı sabitle; imzayı her zaman doğrula.",
    ),
    _r(
        "AUTH003",
        "csrf_exempt",
        "medium",
        "A01:Broken Access Control",
        "CWE-352",
        r"""\bcsrf_exempt\b|CSRF_COOKIE_SECURE\s*=\s*False""",
        "CSRF koruması kapatılmış olabilir.",
        "State-changing endpoint'lerde CSRF zorunlu tut.",
    ),
    _r(
        "AUTH004",
        "SESSION_COOKIE_SECURE False",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-614",
        r"""SESSION_COOKIE_SECURE\s*=\s*False|SESSION_COOKIE_HTTPONLY\s*=\s*False""",
        "Oturum çerezi güvensiz bayraklarla.",
        "Secure + HttpOnly + SameSite ayarla.",
    ),
    # File / permission
    _r(
        "PTH003",
        "tempfile.mktemp (race)",
        "medium",
        "A01:Broken Access Control",
        "CWE-377",
        r"""\bmktemp\s*\(|tempfile\.mktemp""",
        "mktemp TOCTOU yarışına açık.",
        "NamedTemporaryFile / mkstemp kullan.",
    ),
    _r(
        "PTH004",
        "Hardcoded /tmp dosya adı",
        "low",
        "A01:Broken Access Control",
        "CWE-377",
        r"""['\"]\/tmp\/[a-zA-Z0-9_\-\.]+['\"]""",
        "Sabit /tmp yolu tahmin/yarış riski.",
        "Benzersiz temp API kullan.",
    ),
    _r(
        "PTH005",
        "chmod 777 / world-writable",
        "medium",
        "A01:Broken Access Control",
        "CWE-732",
        r"""chmod\s*\([^\)]*(0o777|0o666|777|666)|\.chmod\s*\(\s*0o777""",
        "World-writable izin aşırı geniş.",
        "En az yetki: 0o600 / 0o640.",
    ),
    # XML XXE extended (Bandit B314/B405 ailesi)
    _r(
        "XXE002",
        "xml.sax.parse / parseString / make_parser",
        "high",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""xml\.sax\.(parse|parseString|make_parser)\s*\(""",
        "std xml.sax XXE ve billion laughs'a açık (güvenilmeyen XML).",
        "defusedxml.sax.parse / parseString / make_parser kullan.",
    ),
    _r(
        "XXE003",
        "xmlrpc",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""\bxmlrpc\.|SimpleXMLRPCServer""",
        "XML-RPC eski ve XXE/DoS yüzeyi.",
        "JSON-RPC / HTTPS API tercih et.",
    ),
    _r(
        "XXE004",
        "sax.parse (from xml import sax)",
        "high",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""(?<!defusedxml\.)(?<!\.)\bsax\.(parse|parseString|make_parser)\s*\(""",
        "`from xml import sax` sonrası sax.parse* — XXE riski (defusedxml hariç).",
        "from defusedxml import sax  veya defusedxml.sax.* kullan.",
    ),
    _r(
        "XXE005",
        "xml.etree ElementTree parse/fromstring",
        "high",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""(xml\.etree\.ElementTree|ElementTree)\.(parse|fromstring|XMLParser|iterparse)\s*\(|\bET\.(parse|fromstring|XMLParser)\s*\(""",
        "xml.etree güvenilmeyen XML'de XXE/DoS üretebilir.",
        "defusedxml.ElementTree kullan.",
    ),
    _r(
        "XXE006",
        "xml.dom.minidom / pulldom",
        "high",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""(xml\.dom\.minidom|minidom|xml\.dom\.pulldom|pulldom)\.(parse|parseString)\s*\(""",
        "minidom/pulldom stdlib parser — XXE yüzeyi.",
        "defusedxml.minidom / defusedxml.pulldom.",
    ),
    _r(
        "XXE007",
        "lxml etree (güvenilmeyen XML)",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""lxml\.etree\.(parse|fromstring|XMLParser)\s*\(""",
        "lxml varsayılanı entity'lere izin verebilir.",
        "resolve_entities=False; defusedxml veya sıkı parser ayarı.",
    ),
    _r(
        "XXE008",
        "Insecure XML import (xml.sax / etree)",
        "low",
        "A05:Security Misconfiguration",
        "CWE-611",
        r"""^\s*import xml\.sax|^\s*from xml import sax|^\s*import xml\.etree|^\s*from xml\.etree import|^\s*from xml\.dom\.minidom import|^\s*from xml\.dom import (minidom|pulldom)""",
        "Stdlib XML import — parse çağrıları defusedxml olmalı.",
        "import defusedxml.sax / defusedxml.ElementTree tercih et.",
    ),
    # Assert / bad practices
    _r(
        "CFG008",
        "assert ile güvenlik kontrolü",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-617",
        r"""\bassert\s+.*(auth|permission|is_admin|password|token|role)""",
        "python -O ile assert'ler silinir; güvenlik için kullanma.",
        "if not allowed: raise PermissionError.",
    ),
    _r(
        "CFG009",
        "except Pass / continue yutma",
        "low",
        "A09:Security Logging and Monitoring Failures",
        "CWE-390",
        r"""except\s*(Exception)?\s*:\s*(pass|continue)\s*$|^\s*except\s*:\s*$""",
        "Bare except veya hataları yutmak ihlalleri gizler.",
        "Spesifik exception; logla / yeniden fırlat.",
    ),
    _r(
        "CFG010",
        "binding 0.0.0.0",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-668",
        r"""(host\s*=\s*['\"]0\.0\.0\.0['\"]|listen\([^\)]*0\.0\.0\.0|\.bind\s*\(\s*\(\s*['\"]0\.0\.0\.0['\"])""",
        "Tüm arayüzlerde dinleme saldırı yüzeyini büyütür.",
        "Prod'da localhost + reverse proxy veya firewall.",
    ),
    _r(
        "CFG011",
        "SNMP community public/private",
        "medium",
        "A07:Identification and Authentication Failures",
        "CWE-798",
        r"""community\s*=\s*['\"](public|private)['\"]""",
        "Varsayılan SNMP community.",
        "Güçlü community / SNMPv3.",
    ),
    _r(
        "CFG012",
        "HuggingFace / unsafe model download",
        "medium",
        "A08:Software and Data Integrity Failures",
        "CWE-494",
        r"""from_pretrained\s*\([^\)]*trust_remote_code\s*=\s*True""",
        "trust_remote_code=True uzak kod çalıştırabilir.",
        "Güvenilir modeller; trust_remote_code=False.",
    ),
    # JS / Node extras
    _r(
        "INJ016",
        "child_process.exec",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""child_process\.(exec|execSync)\s*\(|require\(['\"]child_process['\"]\).*exec""",
        "Node exec shell injection.",
        "execFile / spawn argüman dizisi.",
    ),
    _r(
        "XSS011",
        "outerHTML ataması",
        "high",
        "A03:Injection",
        "CWE-79",
        r"\.outerHTML\s*=",
        "outerHTML XSS yüzeyi.",
        "textContent / güvenli DOM API.",
    ),
    _r(
        "XSS012",
        "postMessage * origin",
        "medium",
        "A01:Broken Access Control",
        "CWE-345",
        r"""postMessage\s*\([^,]+,\s*['\"]\*['\"]""",
        "targetOrigin '*' mesajı herkese açar.",
        "Somut origin belirt.",
    ),
    _r(
        "CFG013",
        "CORS Access-Control-Allow-Credentials + *",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-942",
        r"""Allow-Credentials['\"\s:]*true|credentials:\s*true""",
        "Credentials + geniş CORS tehlikeli kombinasyon.",
        "Origin'i net whitelist et.",
    ),
    _r(
        "SEC016",
        "Hardcoded Basic auth header",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""Authorization['\"\s:]*Basic\s+[A-Za-z0-9+/=]{8,}""",
        "Basic auth bilgisi koda gömülü olabilir.",
        "Credential'ı env/vault'tan al.",
    ),
    _r(
        "INJ017",
        "SQL multiline / % format",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""['\"][^'\"]*\bSELECT\b[^'\"]*['\"]\s*%|\"\s*%\s*\(.*request""",
        "Eski % formatting ile SQL.",
        "Parametreli sorgu kullan.",
    ),
    _r(
        "DES009",
        "yaml.unsafe_load",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\byaml\.unsafe_load\s*\(|Loader\s*=\s*yaml\.UnsafeLoader""",
        "yaml.unsafe_load keyfi nesne.",
        "safe_load kullan.",
    ),
    _r(
        "CFG014",
        "httpoxy CGIHandler",
        "high",
        "A05:Security Misconfiguration",
        "CWE-15",
        r"""CGIHandler|from wsgiref\.handlers import CGIHandler|cgi\.FieldStorage""",
        "CGI/WSGI CGIHandler httpoxy yüzeyine yakın.",
        "Modern WSGI sunucu; Proxy header temizle.",
    ),
    _r(
        "PTH006",
        "send_file kullanıcı adı",
        "high",
        "A01:Broken Access Control",
        "CWE-22",
        r"""send_file\s*\(\s*(request\.|os\.path\.join\s*\([^\)]*request)""",
        "send_file + kullanıcı girdisi path traversal.",
        "Sabit kök + basename doğrulama.",
    ),
    _r(
        "SSRF003",
        "cloud metadata IP",
        "high",
        "A10:SSRF",
        "CWE-918",
        r"""169\.254\.169\.254|metadata\.google\.internal""",
        "Cloud metadata adresi kodda — SSRF hedefi.",
        "Bu URL'lere kullanıcı kontrollü istek engelle.",
    ),
    _r(
        "AUTH005",
        "password == karşılaştırma",
        "medium",
        "A07:Identification and Authentication Failures",
        "CWE-208",
        r"""password\s*==\s*|==\s*password\b""",
        "Timing attack'e açık string karşılaştırma olabilir.",
        "hmac.compare_digest / password hasher verify kullan.",
    ),
    _r(
        "CFG015",
        "DEBUG toolbar / django debug",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-489",
        r"""debug_toolbar|DjangoDebugToolbar""",
        "Debug araçları production'da bilgi sızdırır.",
        "Prod'da kapat.",
    ),
    # --- ek tur: Bandit / Semgrep / OWASP ASVS kalıpları ---
    _r(
        "CFG016",
        "assert kullanımı (Bandit B101)",
        "low",
        "A05:Security Misconfiguration",
        "CWE-617",
        r"""^\s*assert\b""",
        "assert -O ile silinir; güvenlik/invariant için uygun değil.",
        "if/raise kullan; testlerde bırak.",
    ),
    _r(
        "CFG017",
        "ALLOWED_HOSTS = ['*']",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-20",
        r"""ALLOWED_HOSTS\s*=\s*\[[^\]]*['\"]\*['\"]""",
        "Host header saldırılarına açık.",
        "Somut domain listesi kullan.",
    ),
    _r(
        "CFG018",
        "CORS allow all origins",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-942",
        r"""CORS_ALLOW_ALL_ORIGINS\s*=\s*True|Access-Control-Allow-Origin['\"\s:]*\*""",
        "Tüm origin'lere CORS açmak CSRF/data leak riski.",
        "Whitelist origin kullan.",
    ),
    _r(
        "CFG019",
        "Django SECURE_* kapalı",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-16",
        r"""SECURE_SSL_REDIRECT\s*=\s*False|SECURE_HSTS_SECONDS\s*=\s*0|SECURE_BROWSER_XSS_FILTER\s*=\s*False""",
        "HTTPS/HSTS güvenlik başlıkları kapalı.",
        "SECURE_SSL_REDIRECT=True; HSTS aç.",
    ),
    _r(
        "INJ018",
        "NoSQL / Mongo $where",
        "high",
        "A03:Injection",
        "CWE-943",
        r"""\$where\b|\$regex\b.*request\.|find\s*\(\s*\{[^\}]*\+|collection\.find\s*\(\s*f['\"]""",
        "NoSQL injection kalıbı.",
        "Operatörleri allowlist; kullanıcı objesini doğrudan query yapma.",
    ),
    _r(
        "INJ019",
        "__import__ / importlib dinamik",
        "medium",
        "A03:Injection",
        "CWE-94",
        r"""\b__import__\s*\(|importlib\.import_module\s*\(\s*(request\.|input\(|sys\.argv)""",
        "Dinamik import RCE yüzeyi.",
        "Modül adını allowlist ile sınırla.",
    ),
    _r(
        "INJ020",
        "compile + exec/eval",
        "high",
        "A03:Injection",
        "CWE-94",
        r"""\bcompile\s*\(.*\)\s*(;|\n).*(exec|eval)|exec\s*\(\s*compile\s*\(""",
        "compile+exec keyfi kod çalıştırır.",
        "Kullanıcı girdisini compile etme.",
    ),
    _r(
        "INJ021",
        "Redis / EVAL Lua kullanıcıdan",
        "high",
        "A03:Injection",
        "CWE-94",
        r"""\.eval\s*\(\s*(f['\"]|request\.|user_)|redis.*execute_command\s*\(\s*f['\"]""",
        "Redis EVAL / komut birleştirme riski.",
        "Sabit script; girdiyi argüman olarak ver.",
    ),
    _r(
        "DES010",
        "pickle via codecs / encoding",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""pickle\.(Unpickler|load|loads)|cPickle\.(load|loads)|_\.?pickle""",
        "Pickle ailesi güvensiz deserialization.",
        "JSON / protobuf tercih et.",
    ),
    _r(
        "SEC017",
        "ECB cipher mode",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-327",
        r"""MODE_ECB|AES\.MODE_ECB|algorithms\.AES[^;\n]*ECB""",
        "ECB modu kalıp sızdırır.",
        "GCM / CTR kullan.",
    ),
    _r(
        "SEC018",
        "Hardcoded Fernet / AES key",
        "high",
        "A02:Cryptographic Failures",
        "CWE-321",
        r"""Fernet\s*\(\s*b?['\"][A-Za-z0-9_\-=]{16,}['\"]|AES\.new\s*\(\s*b?['\"]""",
        "Şifreleme anahtarı kaynakta gömülü.",
        "Anahtarı KMS/env'den yükle.",
    ),
    _r(
        "SEC019",
        "Stripe / Twilio / SendGrid key",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""\b(sk_live_|rk_live_|SG\.[A-Za-z0-9_\-]{20,}|AC[a-f0-9]{32})\b""",
        "Ödeme/iletişim servisi API key kalıbı.",
        "Rotate et; secret manager kullan.",
    ),
    _r(
        "AUTH006",
        "empty password / auth bypass",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-287",
        r"""password\s*=\s*['\"]['\"]|if\s+True:\s*(#.*)?(auth|login|is_admin)|AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]""",
        "Boş parola veya her zaman true auth bypass ipucu.",
        "Gerçek doğrulama zorunlu tut.",
    ),
    _r(
        "AUTH007",
        "HTTP Basic auth over cleartext",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""HTTPBasicAuth\s*\(|auth\s*=\s*\([^)]+,\s*[^)]+\)|Authorization.*Basic""",
        "Basic auth cleartext HTTP ile giderse sızar.",
        "Sadece HTTPS; mümkünse token/OAuth.",
    ),
    _r(
        "PTH007",
        "shutil.rmtree kullanıcı yolu",
        "high",
        "A01:Broken Access Control",
        "CWE-22",
        r"""shutil\.rmtree\s*\(\s*(request\.|os\.path\.join\s*\([^)]*request)""",
        "Kullanıcı kontrollü rmtree → silme / traversal.",
        "Kök dizini sabitle; resolve+commonpath kontrolü.",
    ),
    _r(
        "PTH008",
        "open() kullanıcı path",
        "medium",
        "A01:Broken Access Control",
        "CWE-22",
        r"""open\s*\(\s*(request\.(args|GET|POST|json)|os\.path\.join\s*\([^)]*request)""",
        "Kullanıcı path ile open → LFI/traversal.",
        "Allowlist + basename.",
    ),
    _r(
        "XSS013",
        "document.write",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""document\.write\s*\(|document\.writeln\s*\(""",
        "document.write XSS klasik vektörü.",
        "DOM API / textContent kullan.",
    ),
    _r(
        "XSS014",
        "v-html / dangerouslySetInnerHTML",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""v-html\s*=|dangerouslySetInnerHTML\s*=""",
        "Framework'ün 'ham HTML' API'si XSS üretir.",
        "Sanitize et veya kullanma.",
    ),
    _r(
        "SSRF004",
        "webhook / callback URL kullanıcıdan",
        "medium",
        "A10:SSRF",
        "CWE-918",
        r"""(webhook|callback)_?url\s*=\s*(request\.|req\.|params)""",
        "Kullanıcı webhook URL → SSRF.",
        "HTTPS + allowlist host.",
    ),
    _r(
        "LOG002",
        "logging.config.listen",
        "high",
        "A05:Security Misconfiguration",
        "CWE-502",
        r"""logging\.config\.listen\s*\(""",
        "logging.config.listen pickle tabanlı RCE bilineni.",
        "Kullanma; config'i dosyadan güvenli yükle.",
    ),
    _r(
        "NET005",
        "SNMP v1/v2c",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""CommunityData\s*\(|hlapi\.|pysnmp.*Community""",
        "SNMPv1/v2c zayıf auth.",
        "SNMPv3 + authPriv.",
    ),
    _r(
        "CFG020",
        "Docker privileged / host network",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-250",
        r"""privileged\s*:\s*true|network_mode\s*:\s*host|--privileged""",
        "Container aşırı yetki.",
        "Least privilege; gerekmiyorsa privileged kapat.",
    ),
    _r(
        "CFG021",
        "kubectl / kubeconfig gömülü",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""client-key-data:\s*[A-Za-z0-9+/=]{20,}|client-certificate-data:\s*[A-Za-z0-9+/=]{20,}""",
        "Kubeconfig client key/cert gömülü olabilir.",
        "Secret'tan mount et; commit etme.",
    ),
    _r(
        "INJ022",
        "GraphQL introspection herkese açık ipucu",
        "low",
        "A05:Security Misconfiguration",
        "CWE-200",
        r"""introspection\s*=\s*True|GraphQLView\.as_view\([^\)]*graphiql\s*=\s*True""",
        "Prod'da introspection/GraphiQL bilgi sızdırır.",
        "Prod'da kapat.",
    ),
    _r(
        "DES011",
        "HDF5 / joblib load",
        "medium",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\bjoblib\.load\s*\(|h5py\.File\s*\(""",
        "Bazı bilimsel formatlar güvensiz nesne taşıyabilir.",
        "Güvenilir dosya; mümkünse safetensors/JSON.",
    ),
    _r(
        "SEC020",
        "UUID1 zaman tabanlı ID",
        "low",
        "A02:Cryptographic Failures",
        "CWE-330",
        r"""uuid\.uuid1\s*\(|uuid1\s*\(\s*\)""",
        "UUID1 MAC/zaman sızdırabilir; tahmin edilebilirlik riski.",
        "Oturum/token için secrets.token_urlsafe; ID için uuid4.",
    ),
    # --- A01 IDOR / Broken Access (çok satırlı pencere) ---
    _r(
        "BAC001",
        "IDOR: kullanıcı ID → kayıt getir → JSON",
        "high",
        "A01:Broken Access Control",
        "CWE-639",
        r"""req\.(query|params|body)\.\w+.{0,220}(getUser|findUser|getById|findById|findOne|get_user|user_by_id|getObject).{0,180}(res\.(json|send|sendStatus)|response\.(json|write)|return\s+Json|jsonify\s*\()""",
        "İstek parametresindeki ID ile kayıt okunup yetki kontrolü olmadan dönülüyor → IDOR (CWE-639).",
        "Oturumdaki kullanıcı ile kaynak sahipliğini doğrula; yetkisizse 403.",
        window=8,
    ),
    _r(
        "BAC002",
        "IDOR: getById(req.query/params) doğrudan",
        "high",
        "A01:Broken Access Control",
        "CWE-639",
        r"""(getUserById|findById|findOne|get_object_or_404|User\.find|users\.find)\s*\(\s*(req\.(query|params|body)|request\.(args|GET|POST|query_params|path_params))""",
        "Kullanıcı girdisi doğrudan nesne lookup'a gidiyor (IDOR).",
        "Authz: resource.owner_id == current_user.id kontrolü ekle.",
    ),
    _r(
        "BAC003",
        "IDOR: Flask/Django request → get/filter",
        "high",
        "A01:Broken Access Control",
        "CWE-639",
        r"""request\.(args|GET|POST|query_params|path_params|view_args).{0,200}(\.get\(|\.filter\(|get_object_or_404|objects\.get).{0,160}(jsonify|JsonResponse|return\s+)""",
        "Request parametresi ile nesne çekilip yanıtlanıyor; sahiplik kontrolü yoksa IDOR.",
        "login_required + object-level permission.",
        window=8,
    ),
    _r(
        "BAC004",
        "Mass assignment / req.body doğrudan kaydet",
        "medium",
        "A01:Broken Access Control",
        "CWE-915",
        r"""(create|update|save|insert)\s*\(\s*(req\.body|request\.(json|data|POST|body))|\.update\s*\(\s*\{\s*\.\.\.req\.body""",
        "İstek gövdesi doğrudan modele yazılıyor (mass assignment / privilege escalate).",
        "Allowlist alanlar; role/isAdmin istemciden alma.",
    ),
    _r(
        "BAC005",
        "Profil/API endpoint auth middleware yok ipucu",
        "medium",
        "A01:Broken Access Control",
        "CWE-862",
        r"""(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"][^'\"]*(user|profile|account|admin|order|invoice)[^'\"]*['\"]\s*,\s*\(\s*req\s*,\s*res""",
        "Hassas rota doğrudan handler'a bağlı; auth/authz middleware görünmüyor.",
        "authenticate + authorize middleware zinciri ekle.",
    ),
    _r(
        "BAC006",
        "IDOR: path param ile dosya/kayıt sil",
        "high",
        "A01:Broken Access Control",
        "CWE-639",
        r"""req\.params\.\w+.{0,160}(\.delete|destroy|remove|unlink|rmtree).{0,120}(res\.|response\.)""",
        "URL parametresi ile silme — sahiplik kontrolü yoksa IDOR.",
        "Silmeden önce sahiplik/rol doğrula.",
        window=8,
    ),
    # --- PHP / klasik web SQLi & injection ---
    _r(
        "INJ023",
        "PHP SQL: string içinde $değişken",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^"']*['\"]?\s*\$\w+|\"[^\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^\"]*\$\w+""",
        "PHP'de SQL string'ine değişken gömülü → SQL Injection.",
        "Prepared statement: mysqli_prepare / PDO prepare + bind.",
    ),
    _r(
        "INJ024",
        "PHP SQL: birleştirme (.) ile sorgu",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""\b(SELECT|INSERT|UPDATE|DELETE)\b[^;]*\.\s*\$|\$.*\.\s*['\"][^'\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b""",
        "SQL + string birleştirme (.) SQLi riski.",
        "PDO prepare('... WHERE u=?') + execute([$user]).",
    ),
    _r(
        "INJ025",
        "PHP: $_GET/$_POST → SQL → query",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""\$_(GET|POST|REQUEST|COOKIE)\s*\[.{0,300}(SELECT|INSERT|UPDATE|DELETE).{0,200}(mysqli_query|mysql_query|pg_query|->query\s*\(|->exec\s*\()""",
        "Superglobal girdi SQL'e girip query ile çalıştırılıyor.",
        "Prepared statements; asla kullanıcıyı SQL string'ine gömme.",
        window=10,
    ),
    _r(
        "INJ026",
        "mysqli_query / mysql_query değişkenle",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""(mysqli_query|mysql_query|pg_query|mssql_query)\s*\([^)]*\$""",
        "mysql*_query içinde değişken — genelde dinamik SQL.",
        "mysqli_prepare + bind_param kullan.",
    ),
    _r(
        "INJ027",
        "PHP XSS: echo $_GET/POST",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""\b(echo|print)\s+\$_(GET|POST|REQUEST)|<\?=\s*\$_(GET|POST|REQUEST)""",
        "Kullanıcı girdisi escape edilmeden yazdırılıyor → XSS.",
        "htmlspecialchars(..., ENT_QUOTES, 'UTF-8').",
    ),
    _r(
        "INJ028",
        "PHP command injection",
        "high",
        "A03:Injection",
        "CWE-78",
        r"""\b(system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*\$|\b(system|exec|shell_exec)\s*\(\s*['\"][^'\"]*\$""",
        "PHP sistem çağrısına değişken → command injection.",
        "Escapeshellarg; mümkünse sistem çağrısı yapma.",
    ),
    _r(
        "INJ029",
        "PHP include/require kullanıcıdan",
        "high",
        "A03:Injection",
        "CWE-98",
        r"""\b(include|require|include_once|require_once)\s*\(?\s*\$_(GET|POST|REQUEST)""",
        "LFI/RFI: include + kullanıcı girdisi.",
        "Allowlist dosya adları; kullanıcı path'i kullanma.",
    ),
    _r(
        "INJ030",
        "PHP unserialize kullanıcıdan",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\bunserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)""",
        "unserialize + kullanıcı girdisi → object injection / RCE gadget zinciri.",
        "json_decode kullan; unserialize'a kullanıcı verisi verme.",
    ),
    # ========== DETAYLI GENİŞLETME (çok dilli + header/crypto/auth) ==========
    _r(
        "SEC023",
        "PHP crypt()/CRC32 parola",
        "high",
        "A02:Cryptographic Failures",
        "CWE-328",
        r"""\b(crypt|crc32|sha1)\s*\(\s*\$(password|passwd|pwd)|password_hash\s*\([^,]+,\s*PASSWORD_DEFAULT\s*\)\s*;[^\n]*md5""",
        "Eski crypt/CRC/SHA1 parola için yetersiz.",
        "password_hash($p, PASSWORD_ARGON2ID) veya PASSWORD_BCRYPT.",
    ),
    _r(
        "SEC024",
        "Node crypto.createHash(md5/sha1) parola",
        "high",
        "A02:Cryptographic Failures",
        "CWE-328",
        r"""createHash\s*\(\s*['\"](md5|sha1)['\"]\).{0,80}(password|passwd|pwd)|createHash\s*\(\s*['\"](md5|sha1)['\"]""",
        "Node createHash('md5'|'sha1') parola veya genel zayıf özet.",
        "Parola: bcrypt/argon2. Özet: sha256+. Token: crypto.randomBytes.",
        window=4,
    ),
    _r(
        "SEC025",
        "Java MessageDigest MD5/SHA1",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-328",
        r"""MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-?1)['\"]|DigestUtils\.(md5|sha1)Hex""",
        "Java'da MD5/SHA-1 MessageDigest — parola ve imza için uygunsuz.",
        "Parola: BCrypt/SCrypt/Argon2. Mesaj özeti: SHA-256.",
    ),
    _r(
        "SEC026",
        "Hardcoded encryption IV / salt",
        "high",
        "A02:Cryptographic Failures",
        "CWE-329",
        r"(iv|IV|salt|nonce)\s*=\s*(b?['\"][0-9a-fA-F]{8,}['\"]|bytes\(\s*\[)",
        "Sabit IV/salt şifrelemeyi zayıflatır (aynı plaintext → aynı ciphertext).",
        "Her işlemde rastgele IV/salt üret; ciphertext ile birlikte sakla.",
    ),
    _r(
        "HDR001",
        "CSP / helmet bilerek kapatılmış",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-693",
        r"contentSecurityPolicy\s*:\s*false|X-Frame-Options['\"\s:]*ALLOWALL|helmet\s*\(\s*\{\s*\}\)|DISABLE_CONTENT_SECURITY_POLICY",
        "CSP veya clickjacking koruması kapatılmış — XSS etkisini büyütür.",
        "helmet() varsayılanları; sıkı CSP (default-src 'self').",
    ),
    _r(
        "HDR002",
        "CORS origin yansıması",
        "high",
        "A05:Security Misconfiguration",
        "CWE-346",
        r"Access-Control-Allow-Origin['\"\s:]*\+|origin\s*:\s*(req\.|request\.|headers\[.origin)|cors\(\s*\{\s*origin\s*:\s*true",
        "İstek Origin'i olduğu gibi yansıtmak credential'lı CSRF/data theft'e yol açar.",
        "Sabit allowlist; credentials ile asla * veya yansıyan origin kullanma.",
    ),
    _r(
        "HDR003",
        "HSTS / Secure cookie kapalı",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-319",
        r"""Strict-Transport-Security['\"\s:]*max-age=0|secure\s*:\s*false.*cookie|cookie\([^)]*secure\s*:\s*false""",
        "HSTS kapatılmış veya cookie Secure değil — MITM'de oturum çalınabilir.",
        "HSTS max-age≥15552000; cookie: Secure, HttpOnly, SameSite=Lax/Strict.",
    ),
    _r(
        "INJ031",
        "Java SQL Statement + concat",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""createStatement\s*\(|Statement\.execute(Query|Update)?\s*\([^)]*\+|\"\s*\+\s*(request\.|user|input|param)""",
        "JDBC Statement + string birleştirme klasik SQLi.",
        "PreparedStatement + ? placeholder kullan.",
    ),
    _r(
        "INJ032",
        "C# SqlCommand string concat",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""SqlCommand\s*\([^)]*\+|ExecuteReader\s*\([^)]*\+|string\.Format\s*\(\s*['\"][^'\"]*SELECT""",
        "ADO.NET'te birleşik SQL → SQLi.",
        "Parametreli SqlCommand; Parameters.Add WithValue.",
    ),
    _r(
        "INJ033",
        "Ruby ActiveRecord where string",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""\.(where|find_by_sql)\s*\(\s*[\"'].*#\{|\.where\s*\(\s*[\"'][^\"']*%\s*\{""",
        "Rails where'e interpolate string SQLi riski.",
        "where(name: params[:name]) hash formu kullan.",
    ),
    _r(
        "INJ034",
        "Go database/sql fmt.Sprintf",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""fmt\.Sprintf\s*\(\s*[`'\"][^`'\"]*\b(SELECT|INSERT|UPDATE|DELETE)\b|db\.(Query|Exec)\s*\(\s*fmt\.Sprintf""",
        "Go'da Sprintf ile SQL birleştirme SQLi.",
        "db.Query(\"... WHERE id=$1\", id) placeholder kullan.",
    ),
    _r(
        "INJ035",
        "Node knex/raw veya mysql query concat",
        "high",
        "A03:Injection",
        "CWE-89",
        r"""\.(raw|query)\s*\(\s*[`'\"].*\$\{|mysql\.query\s*\(\s*[`'\"][^`'\"]*\$\{|knex\.raw\s*\(\s*`[^`]*\$\{""",
        "Node SQL template literal / concat → SQLi.",
        "Parametreli query: connection.query('...?', [val]).",
    ),
    _r(
        "INJ036",
        "PHP eval / assert / preg_replace /e",
        "high",
        "A03:Injection",
        "CWE-95",
        r"""\beval\s*\(\s*\$|\bassert\s*\(\s*\$|preg_replace\s*\(\s*['\"][^'\"]*/e""",
        "PHP eval/assert/preg_replace /e → uzaktan kod çalıştırma.",
        "eval kullanma; preg_replace_callback tercih et.",
    ),
    _r(
        "INJ037",
        "LDAP PHP/Java filtre birleştirme",
        "high",
        "A03:Injection",
        "CWE-90",
        r"""ldap_search\s*\([^)]*\$|BasicAttributes|\(uid=\"\s*\+|filter\s*=\s*[\"'].*\+""",
        "LDAP filtresine kullanıcı girdisi → auth bypass / data leak.",
        "ldap_escape / Encoder; sabit filtre iskeleti.",
    ),
    _r(
        "INJ038",
        "XPath injection",
        "high",
        "A03:Injection",
        "CWE-643",
        r"""xpath\s*\([^\)]*\+|selectNodes\s*\([^\)]*\+|\/\/\w+\[.*\$""",
        "XPath ifadesine girdi birleştirme → veri sızdırma.",
        "Parametrik XPath veya sıkı escape.",
    ),
    _r(
        "XSS015",
        "PHP print/echo değişken HTML",
        "medium",
        "A03:Injection",
        "CWE-79",
        r"""\b(echo|print)\s+\$\w+\s*;|\becho\s+[\"'][^\"']*\$\w+""",
        "Escape edilmemiş PHP çıktısı XSS olabilir (bağlama bağlı).",
        "htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); template engine escape.",
    ),
    _r(
        "XSS016",
        "Angular bypassSecurityTrust",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""bypassSecurityTrust(Html|Url|Script|Style|ResourceUrl)\s*\(""",
        "Angular sanitizer bypass — XSS kapısı.",
        "Yalnızca tamamen güvendiğin içerik; DomSanitizer'ı gevşetme.",
    ),
    _r(
        "XSS017",
        "jQuery html()/append kullanıcıdan",
        "high",
        "A03:Injection",
        "CWE-79",
        r"""\$\([^)]*\)\.(html|append|prepend|after|before)\s*\(\s*(location\.|document\.URL|window\.name|req\.|params)""",
        "jQuery html/append sink + kaynak → DOM XSS.",
        "text() kullan; DOMPurify ile sanitize et.",
    ),
    _r(
        "AUTH008",
        "Hardcoded admin / default credentials",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-798",
        r"""(admin|root)\s*[=:]\s*['\"](admin|password|123456|root)['\"]|username\s*=\s*['\"]admin['\"].{0,40}password\s*=\s*['\"]""",
        "Varsayılan/admin:admin tarzı kimlik bilgisi.",
        "Kurulumda zorunlu değiştir; güçlü parola politikası.",
        window=3,
    ),
    _r(
        "AUTH009",
        "OTP/SMS kodu loglanıyor veya sabit",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-330",
        r"""(otp|sms_code|verification_code)\s*=\s*['\"][0-9]{4,8}['\"]|(otp|sms_code).{0,40}(print|log|console\.log|echo)""",
        "Sabit OTP veya OTP'nin loglanması 2FA'yı bozar.",
        "Kriptografik rastgele OTP; loglama; kısa TTL.",
        window=3,
    ),
    _r(
        "AUTH010",
        "Session fixation / id kullanıcıdan",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-384",
        r"""session_id\s*\(\s*\$_(GET|POST|REQUEST)|PHPSESSID\s*=\s*\$_(GET|POST)|session\.sid\s*=\s*req\.""",
        "Oturum kimliği kullanıcıdan alınıyor → session fixation.",
        "Login sonrası session regenerate; id'yi URL'den okuma.",
    ),
    _r(
        "AUTH011",
        "password_verify yok / == hash",
        "medium",
        "A07:Identification and Authentication Failures",
        "CWE-208",
        r"""(password_hash|hashedPassword|pwd_hash)\s*===?\s*|===?\s*(password_hash|hashed_password)""",
        "Hash'i == ile karşılaştırmak timing ve algoritma hatalarına açık.",
        "password_verify() / check_password(); hash_equals.",
    ),
    _r(
        "BAC007",
        "isAdmin istemciden / body'den",
        "high",
        "A01:Broken Access Control",
        "CWE-807",
        r"""isAdmin\s*=\s*(req\.(body|query|params)|request\.(json|GET|POST)|JSON\.parse)|role\s*=\s*req\.body""",
        "Yetki bayrağı istemciden geliyor — privilege escalation.",
        "Rolü sunucu tarafı oturum/DB'den oku; istemciye güvenme.",
    ),
    _r(
        "BAC008",
        "Hidden field ile fiyat/rol",
        "medium",
        "A01:Broken Access Control",
        "CWE-472",
        r"""type\s*=\s*['\"]hidden['\"][^>]*(price|role|admin|discount|total)|name=['\"](price|isAdmin|role)['\"]""",
        "Gizli form alanı manipüle edilebilir.",
        "Fiyat/rolü sunucuda yeniden hesapla / yetkilendir.",
    ),
    _r(
        "CFG022",
        "PHP display_errors / expose_php",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-209",
        r"""display_errors\s*=\s*(On|1)|expose_php\s*=\s*(On|1)|ini_set\s*\(\s*['\"]display_errors['\"]\s*,\s*['\"]1['\"]""",
        "Hata mesajları ve PHP sürümü sızdırılıyor.",
        "Prod: display_errors=Off; log_errors=On.",
    ),
    _r(
        "CFG023",
        "allow_url_include / allow_url_fopen",
        "high",
        "A05:Security Misconfiguration",
        "CWE-98",
        r"""allow_url_include\s*=\s*(On|1)|allow_url_fopen\s*=\s*(On|1)""",
        "Uzak include/fopen RFI ve SSRF yüzeyini büyütür.",
        "allow_url_include=Off; uzak içeriği bilinçli HTTP istemcisiyle çek.",
    ),
    _r(
        "CFG024",
        "Spring security disable / permitAll",
        "high",
        "A05:Security Misconfiguration",
        "CWE-284",
        r"""permitAll\s*\(\s*\)|csrf\s*\(\s*\)\s*\.\s*disable\s*\(|http\.csrf\(\)\.disable|security\.enable\s*=\s*false""",
        "Spring Security CSRF veya tüm path'ler açık.",
        "CSRF'yi API token ile yönet; permitAll'ı daralt.",
    ),
    _r(
        "CFG025",
        "Django/Flask SECRET_KEY zayıf",
        "high",
        "A02:Cryptographic Failures",
        "CWE-798",
        r"""SECRET_KEY\s*=\s*['\"](dev|secret|changeme|django-insecure|asdf|1234)[^'\"]*['\"]""",
        "Tahmin edilebilir SECRET_KEY oturum/cookie imzasını kırdırır.",
        "Uzun rastgele değer; yalnızca env/secret store.",
    ),
    _r(
        "DES012",
        "PHP phar:// stream",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""phar://|Phar::|new\s+Phar\s*\(""",
        "phar:// deserialization / path abuse bilinen PHP vektörü.",
        "Kullanıcı kontrollü wrapper'ları engelle; phar disable.",
    ),
    _r(
        "DES013",
        "Java readObject / XMLDecoder",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""\.readObject\s*\(|XMLDecoder\s*\(|ObjectInputStream\s*\(""",
        "Java deserialization RCE (gadget chains) riski.",
        "JSON; look-ahead deserialization / allowlist.",
    ),
    _r(
        "DES014",
        "BinaryFormatter / NetDataContract",
        "high",
        "A08:Software and Data Integrity Failures",
        "CWE-502",
        r"""BinaryFormatter|NetDataContractSerializer|SoapFormatter|LosFormatter""",
        ".NET güvensiz serializer'lar — RCE.",
        "System.Text.Json / DataContractSerializer (güvenli ayar).",
    ),
    _r(
        "SSRF005",
        "PHP file_get_contents URL",
        "high",
        "A10:SSRF",
        "CWE-918",
        r"""file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)|file_get_contents\s*\(\s*\$|curl_setopt\s*\([^)]*CURLOPT_URL[^)]*\$""",
        "Kullanıcı URL'si ile sunucu tarafı istek → SSRF.",
        "Allowlist şema+host; private IP engelle.",
    ),
    _r(
        "SSRF006",
        "Java URL.openConnection kullanıcıdan",
        "high",
        "A10:SSRF",
        "CWE-918",
        r"""new\s+URL\s*\(\s*request\.|URL\s*\([^)]*\+|(openConnection|openStream)\s*\(\s*\)""",
        "Java URL sink SSRF için sık hedef.",
        "Allowlist; redirect takipini sınırla.",
    ),
    _r(
        "PTH009",
        "PHP path traversal move_uploaded_file",
        "high",
        "A01:Broken Access Control",
        "CWE-22",
        r"""move_uploaded_file\s*\([^)]*\$_(FILES|GET|POST)|basename\s*\(\s*\$_FILES.{0,80}move_uploaded_file""",
        "Yüklenen dosya adı doğrulanmadan yazılıyor olabilir.",
        "Uzantı allowlist; rastgele sunucu adı; webroot dışı sakla.",
        window=5,
    ),
    _r(
        "PTH010",
        "Zip Slip (extract kullanıcı arşivi)",
        "high",
        "A01:Broken Access Control",
        "CWE-22",
        r"""ZipFile\.extract|zipfile\.ZipFile|unzip\s*\(|ZipArchive|->extractTo""",
        "Arşivde ../ ile dizin dışına yazma (zip slip).",
        "Her üyede canonical path + kök dizini doğrula.",
    ),
    _r(
        "LOG003",
        "Log injection / CRLF",
        "medium",
        "A09:Security Logging and Monitoring Failures",
        "CWE-117",
        r"""(logger|log)\.(info|warn|error|debug)\s*\([^)]*request\.|error_log\s*\(\s*\$_(GET|POST)""",
        "Kullanıcı girdisi log'a ham yazılıyor — log forging / CRLF.",
        "Sanitize/newline strip; yapılandırılmış log (JSON).",
    ),
    _r(
        "NET006",
        "HTTP cleartext URL (http:// API)",
        "low",
        "A02:Cryptographic Failures",
        "CWE-319",
        r"""['\"]http://(?!localhost|127\.0\.0\.1)[^'\"]+['\"]""",
        "Cleartext HTTP API çağrısı MITM'e açık (localhost hariç).",
        "https:// kullan; HSTS.",
    ),
    _r(
        "CFG026",
        "Kubernetes runAsRoot / privileged",
        "medium",
        "A05:Security Misconfiguration",
        "CWE-250",
        r"""runAsUser:\s*0|privileged:\s*true|allowPrivilegeEscalation:\s*true|hostPID:\s*true""",
        "Pod root/privileged — konteyner kaçış etkisini büyütür.",
        "runAsNonRoot; privileged=false; drop ALL capabilities.",
    ),
    _r(
        "CFG027",
        "Terraform / IaC wildcard IAM",
        "medium",
        "A01:Broken Access Control",
        "CWE-269",
        r"""Action\s*=\s*\[?\s*[\"']\*[\"']|Resource\s*=\s*[\"']\*[\"'].*Action|\"Action\":\s*\"\*\" """,
        "IAM * Action/Resource aşırı yetki.",
        "Least privilege; somut Action ve Resource ARN.",
    ),
    _r(
        "INJ039",
        "GraphQL nested alias DoS ipucu",
        "low",
        "A04:Insecure Design",
        "CWE-400",
        r"""query\s*\{[^\}]{0,40}\w+\s*:\s*\w+\s*\{[^\}]*\w+\s*:\s*\w+\s*\{""",
        "Derin/alias GraphQL sorguları DoS vektörü olabilir.",
        "Query depth/complexity limit; timeout.",
    ),
    _r(
        "INJ040",
        "Prototype pollution merge",
        "high",
        "A03:Injection",
        "CWE-1321",
        r"""__proto__|constructor\s*\[|lodash\.merge\s*\(|deepmerge\s*\(|Object\.assign\s*\(\s*\{\s*\}\s*,\s*req\.body""",
        "Kullanıcı objesi deep-merge → prototype pollution.",
        "Object.create(null); __proto__ reddet; güvenli merge.",
    ),
    _r(
        "SEC027",
        "Weak PBKDF2 / düşük iteration",
        "medium",
        "A02:Cryptographic Failures",
        "CWE-916",
        r"""pbkdf2.{0,60}(iterations\s*=\s*[0-9]{1,3}\b|iterations:\s*[0-9]{1,3}\b)|PBKDF2WithHmacSHA1""",
        "Düşük iterasyonlu PBKDF2 veya SHA1 tabanlı türetme zayıf.",
        "En az 600k iterasyon (OWASP) veya argon2id.",
        window=3,
    ),
    _r(
        "SEC028",
        "Math.random token/OTP",
        "high",
        "A02:Cryptographic Failures",
        "CWE-330",
        r"""Math\.random\s*\(.{0,40}(token|otp|password|secret|session|nonce)|crypto\.pseudoRandomBytes""",
        "Math.random kriptografik değil; token tahmin edilebilir.",
        "crypto.randomBytes / secrets.token_urlsafe.",
        window=3,
    ),
    _r(
        "AUTH012",
        "JWT secret zayıf / 'secret'",
        "high",
        "A07:Identification and Authentication Failures",
        "CWE-798",
        r"""jwt\.(sign|encode)\s*\([^)]*['\"]secret['\"]|JWT_SECRET\s*=\s*['\"][^'\"]{1,8}['\"]""",
        "Zayıf JWT secret imzayı kırdırır.",
        "Uzun rastgele secret (≥32 byte); RS256 tercih edilebilir.",
    ),
    # Trojan Source — Unicode bidi (CVE-2021-42574); yorum satırlarında da ara
    _r(
        "TS001",
        "Trojan Source: Unicode bidi kontrol karakteri",
        "high",
        "A03:Injection",
        "CWE-94",
        # RLO/LRO/RLE/LRE/PDF + isolates (LRI/RLI/FSI/PDI) + BOM
        "[\u202a-\u202e\u2066-\u2069\ufeff]",
        "Kod görünümü ile çalışma mantığını ayıran Unicode yönlendirme karakteri (Trojan Source / CVE-2021-42574). "
        "Yorum veya string içinde gizlenerek yetki kontrolü tersine çevrilebilir.",
        "Dosyayı bidi'siz yeniden yaz; CI'da Unicode bidi ban'i (Bandit B614 / editorconfig).",
    ),
    _r(
        "TS002",
        "Trojan Source: sıfır genişlik / görünmez Unicode",
        "medium",
        "A03:Injection",
        "CWE-94",
        "[\u200b-\u200f\u2028\u2029]",
        "Sıfır genişlik veya satır ayırıcı Unicode — kimlik/anahtar çakışması ve gizleme riski.",
        "Görünmez karakterleri temizle; normalizer kullan.",
    ),
]


_PLACEHOLDER = re.compile(
    r"(?i)(changeme|your[_-]?key|xxx+|placeholder|example|dummy|test123|todo)"
)


def _is_placeholder_line(line: str) -> bool:
    return bool(_PLACEHOLDER.search(line))


def _risk_from_score(skor: int) -> str:
    if skor < 30:
        return "dusuk"
    if skor < 65:
        return "orta"
    return "yuksek"


# Bandit tarzı: `import xml.etree.ElementTree as badET` → badET.fromstring
_XML_ALIAS_IMPORT = [
    re.compile(
        r"^\s*import\s+xml\.etree\.ElementTree\s+as\s+(\w+)", re.I
    ),
    re.compile(
        r"^\s*from\s+xml\.etree(?:\.ElementTree)?\s+import\s+(\w+)", re.I
    ),
    re.compile(
        r"^\s*from\s+xml\.dom\.minidom\s+import\s+(parse(?:String)?)\s+as\s+(\w+)",
        re.I,
    ),
    re.compile(
        r"^\s*from\s+xml\.dom\.minidom\s+import\s+(parse(?:String)?)\s*$",
        re.I,
    ),
    re.compile(
        r"^\s*from\s+xml\.dom\.pulldom\s+import\s+(\w+)",
        re.I,
    ),
]


def _insecure_xml_aliases(lines: list[str]) -> dict[str, int]:
    """alias -> import satırı. defusedxml import'ları hariç."""
    aliases: dict[str, int] = {}
    for i, line in enumerate(lines, start=1):
        if "defusedxml" in line:
            continue
        for pat in _XML_ALIAS_IMPORT:
            m = pat.search(line)
            if not m:
                continue
            if m.lastindex and m.lastindex >= 2:
                aliases[m.group(2)] = i
            else:
                aliases[m.group(1)] = i
    return aliases


def _xxe_alias_findings(
    lines: list[str], aliases: dict[str, int]
) -> list[Finding]:
    if not aliases:
        return []
    out: list[Finding] = []
    # badET.fromstring / badParseString(...)
    call_re = re.compile(
        r"\b("
        + "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True))
        + r")\s*(?:\.(?:fromstring|parse|iterparse|XMLParser|parseString))?\s*\(",
        re.I,
    )
    for i, line in enumerate(lines, start=1):
        if "defusedxml" in line or line.strip().startswith(("import ", "from ")):
            continue
        m = call_re.search(line)
        if not m:
            continue
        name = m.group(1)
        out.append(
            Finding(
                severity="high",
                title=f"XXE: güvensiz XML alias kullanımı ({name})",
                detail=(
                    f"`{name}` stdlib XML'den alias (satır {aliases.get(name, '?')}); "
                    "parse/fromstring XXE (CWE-611) riski."
                ),
                line=i,
                snippet=line.strip()[:140],
                fix="defusedxml eşdeğerini import et; alias'ı güvenli modüle çevir.",
                owasp="A05:Security Misconfiguration",
                cwe="CWE-611",
                rule_id="XXE009",
            )
        )
    return out


def scan_code(code: str) -> CodeScanResult:
    code = code or ""
    if not code.strip():
        return CodeScanResult(
            findings=[],
            skor=0,
            risk="dusuk",
            ozet="Boş kod — yapıştırıp tekrar tara.",
            by_owasp={},
        )

    lines = code.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()  # (rule_id, line) — pencere kaymasında tekrarlama

    for i, line in enumerate(lines):
        lineno = i + 1
        stripped = line.strip()
        if not stripped:
            continue
        # Trojan Source / bidi: yorum satırında da tara (CVE-2021-42574)
        is_comment = (
            (stripped.startswith("#") and "PRIVATE KEY" not in stripped.upper())
            or (stripped.startswith("//") and "PRIVATE KEY" not in stripped.upper())
        )

        for rule in RULES:
            if is_comment and not rule.id.startswith("TS"):
                continue
            # defusedxml satırlarını XXE false-positive yapma
            if rule.id.startswith("XXE") and "defusedxml" in line:
                continue
            if rule.window <= 1:
                target = line
                snippet = stripped[:140]
            else:
                chunk_lines = lines[i : i + rule.window]
                target = "\n".join(chunk_lines)
                snippet = " ".join(c.strip() for c in chunk_lines if c.strip())[:140]
            if not rule.pattern.search(target):
                continue
            key = (rule.id, lineno)
            if key in seen:
                continue
            # Aynı kuralın kayan pencerede ardışık tetiklenmesini tek bulguya indir
            if rule.window > 1 and any(
                (rule.id, lineno - d) in seen for d in range(1, rule.window)
            ):
                continue
            seen.add(key)

            if rule.id.startswith("SEC") and _is_placeholder_line(line):
                sev = "low"
                detail = rule.detail + " (placeholder gibi görünüyor — yine de kontrol et)."
            else:
                sev = rule.severity
                detail = rule.detail
            findings.append(
                Finding(
                    severity=sev,
                    title=rule.title,
                    detail=detail,
                    line=lineno,
                    snippet=snippet,
                    fix=rule.fix,
                    owasp=rule.owasp,
                    cwe=rule.cwe,
                    rule_id=rule.id,
                )
            )

    # Alias'lı stdlib XML (Bandit xml_etree / xml_minidom örnekleri)
    for f in _xxe_alias_findings(lines, _insecure_xml_aliases(lines)):
        key = (f.rule_id, f.line)
        if key not in seen:
            seen.add(key)
            findings.append(f)

    weights = {"high": 28, "medium": 12, "low": 5}
    skor = min(100, sum(weights.get(f.severity, 8) for f in findings))
    high_n = sum(1 for f in findings if f.severity == "high")
    med_n = sum(1 for f in findings if f.severity == "medium")
    # Tek high bile "orta+" olmalı; 2+ high → yüksek risk tabanı
    if high_n >= 2:
        skor = max(skor, 75)
    elif high_n == 1:
        skor = max(skor, 55)
    elif med_n >= 2:
        skor = max(skor, 40)
    if not findings:
        skor = 5

    by_owasp = dict(Counter(f.owasp for f in findings))
    risk = _risk_from_score(skor)

    if not findings:
        ozet = "Bu kural setine göre kritik bulgu yok (taint analizi yok — sınırlı kapsama)."
    else:
        high = sum(1 for f in findings if f.severity == "high")
        cats = ", ".join(f"{k.split(':')[0]}×{v}" for k, v in list(by_owasp.items())[:4])
        ozet = f"{len(findings)} bulgu ({high} high). OWASP: {cats}"

    # Severity sırası
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.line))

    return CodeScanResult(
        findings=findings,
        skor=skor,
        risk=risk,
        ozet=ozet,
        by_owasp=by_owasp,
    )
