"""
Türkiye'de sık görülen SMS/e-posta dolandırıcılık sinyalleri.

Kaynak özeti (eğitim/savunma amaçlı derleme, 2024–2026 kamu uyarıları):
- İçişleri / Emniyet operasyon duyuruları (e-Devlet yardım, ceza soruşturması SMS)
- BTK + Emniyet smishing uyarıları (kargo, banka güncelleme)
- PTT resmi dolandırıcılık uyarısı (gümrük vergisi, adres güncelle, HGS)
- Şikayetvar / basın: kripto "hesabınız tehlikede", IBAN+EFT tuzağı
- e-Devlet phishing kalıpları (askıya alma, vergi, SGK)

Bu bir ML "eğitimi" değil: açık kurallar + örnekler.
Model (Ollama) gerekçe yazar; skor ağırlıklı olarak bu sinyallerden gelir.
"""

from __future__ import annotations

import re

URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.I)
SUSPICIOUS_TLD = re.compile(
    r"https?://[^\s]*\.(xyz|top|icu|click|loan|gq|tk|ml|cf|zip|mov|buzz|shop)\b",
    re.I,
)
IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")
PHONE_RE = re.compile(
    r"(?:\+90|0)\s*\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|\b0\d{10}\b"
)
# TR IBAN: TR + 24 hane (boşluklu da olabilir)
IBAN_RE = re.compile(r"\bTR[\s]?\d{2}(?:[\s]?\d{4}){5}[\s]?\d{2}\b", re.I)
SHORT_LINK = re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly)/\S+", re.I)

# Aciliyet / korku / baskı
RED_WORDS = [
    "bloke",
    "askıya",
    "askiya",
    "hemen doğrula",
    "hemen dogrula",
    "hemen tıkla",
    "hemen tikla",
    "hemen ara",
    "hemen arayın",
    "hemen arayin",
    "arayın",
    "arayin",
    "hesabınız kapat",
    "hesabiniz kapat",
    "hesabınız tehlikede",
    "hesabiniz tehlikede",
    "şifrenizi girin",
    "sifrenizi girin",
    "kart bilg",
    "cvv",
    "cvc",
    "otp",
    "sms kod",
    "doğrulama kod",
    "dogrulama kod",
    "işlem bedeli",
    "islem bedeli",
    "ödül kazandınız",
    "odul kazandiniz",
    "çekilişte kazand",
    "cekiliste kazand",
    "guvenlik nedeniyle",
    "güvenlik nedeniyle",
    "güvenlik güncelle",
    "guvenlik guncelle",
    "iade edilecektir",
    "imha edilir",
    "son 24 saat",
    "son günüdür",
    "son gunudur",
    "son gün",
    "son gun",
    "acil işlem",
    "mağduriyet",
    "magduriyet",
    "ceza soruştur",
    "ceza sorustur",
    "soruşturmanızın son",
    "sorusturmanizin son",
]

# Sahte savcılık / uzlaştırma / icra
LEGAL_SCAM = [
    "uzlaştırma",
    "uzlastirma",
    "uzlaştırm",
    "uzlastirm",
    "savcılık",
    "savcilik",
    "savcılığa",
    "savciliga",
    "adliye",
    "icra",
    "tebligat",
    "dava dosya",
    "dosyanızın",
    "dosyanizin",
    "mahkeme",
    "haciz",
    "idari para cezası",
    "idari para cezasi",
]

# e-Devlet / kamu taklidi
EDEVLET_SCAM = [
    "e-devlet",
    "edevlet",
    "e devlet",
    "turkiye.gov",
    "sgk yardım",
    "sgk yardim",
    "yardım başvurusu",
    "yardim basvurusu",
    "e-imza",
    "eimza",
    "gelir idaresi",
    "gib.gov",
    "vergi borcunuz",
    "trafik cezası",
    "trafik cezasi",
]

# Kargo / PTT / HGS / gümrük
CARGO_SCAM = [
    "gümrükte",
    "gumrukte",
    "gümrük vergi",
    "gumruk vergi",
    "adresiniz eksik",
    "adres bilgisi eksik",
    "teslim alınmamış kargo",
    "teslim alinmamis kargo",
    "teslim edilemedi",
    "kargo iade",
    "gönderim merkezine iade",
    "hgs borcunuz",
    "hgs borcu",
    "nakliye ücreti",
    "nakliye ucreti",
    "sadece kargo",
    "kargo bedeli",
    "koliniz yanlış",
    "koliniz yanlis",
]

# Banka / EFT / IBAN tuzağı
BANK_SCAM = [
    "mobil uygulamanızda güvenlik",
    "mobil uygulamanizda guvenlik",
    "internet şubeniz",
    "internet subeniz",
    "eft yapın",
    "eft yapin",
    "havale yapın",
    "havale yapin",
    "fast ile gönder",
    "fast ile gonder",
    "iban'a",
    "iban a",
    "iban numarası",
    "iban numarasi",
    "güvenli hesaba aktar",
    "guvenli hesaba aktar",
    "kart aidatı iade",
    "kart aidati iade",
]

# Kripto borsa smishing
CRYPTO_SCAM = [
    "kripto hesab",
    "cuzdaniniz bloke",
    "cüzdanınız bloke",
    "binance",
    "btcturk",
    "paribu",
    "kripto çekiliş",
    "kripto cekilis",
    "1000 tl yatırım",
    "vergi ödemeniz gerekiyor",
    "vergi odemeniz gerekiyor",
]

# Hediye / maket / çekiliş bait (istenmeyen reklam-spam / oltalama)
GIFT_BAIT = [
    "özel hediye",
    "ozel hediye",
    "hediye kazand",
    "ücretsiz hediye",
    "ucretsiz hediye",
    "bedava hediye",
    "size özel hediye",
    "maketinize özel",
    "maketinize ozel",
    "lisanslı maket",
    "lisansli maket",
    "hemen talep",
    "hemen kap",
    "son fırsat",
    "son firsat",
    "ödeme yapmadan",
    "odeme yapmadan",
    "ankete katıl",
    "ankete katil",
    "uçak bileti kazand",
    "ucak bileti kazand",
]

BANK_BRANDS = [
    "garanti",
    "iş bankası",
    "is bankasi",
    "akbank",
    "yapıkredi",
    "yapikredi",
    "ziraat",
    "vakıfbank",
    "vakifbank",
    "halkbank",
    "denizbank",
    "enpara",
    "qnb",
    "finansbank",
]

CARGO_BRANDS = [
    "ptt",
    "yurtiçi kargo",
    "yurtici kargo",
    "aras kargo",
    "mng kargo",
    "trendyol",
    "hepsiburada",
    "amazon",
    "sürat kargo",
    "surat kargo",
]

SAFE_WORDS = [
    "toplantı",
    "toplanti",
    "gündem",
    "gundem",
    "buluşalım",
    "bulusalim",
    "hacktoberfest",
    "iyi çalışmalar",
    "iyi calismalar",
    "katılamayacaksan",
    "katilamayacaksan",
    "yanıt yazman yeterli",
    "yanit yazman yeterli",
]
