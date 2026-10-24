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
# TR IBAN: TR + 24 rakam (bitişik veya boşluklu)
IBAN_RE = re.compile(
    r"\bTR[\s\-]?\d{2}(?:[\s\-]?\d{4}){5}[\s\-]?\d{2}\b"  # boşluklu
    r"|\bTR\d{24}\b",  # bitişik: TR930001500158007352303000
    re.I,
)
INSTAGRAM_RE = re.compile(
    r"(?:instagram\.com/|instagram\.com/\S+|@[a-z0-9._]{3,})\S*",
    re.I,
)
SHORT_LINK = re.compile(r"https?://(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly)/\S+", re.I)

# Instagram / sosyal medya "Valilik onaylı IBAN" bağış dolandırıcılığı
SOCIAL_IBAN_SCAM = [
    "valilik onaylı",
    "valilik onayli",
    "valilik onay",
    "kaymakamlık onay",
    "kaymakamlik onay",
    "izin no",
    "izin numarası",
    "izin numarasi",
    "onaylı iban",
    "onayli iban",
    "bağış iban",
    "bagis iban",
    "yardım iban",
    "yardim iban",
    "destek iban",
    "deprem bağış",
    "deprem bagis",
    "acil yardım",
    "acil yardim",
    "ibana yardım",
    "ibana yardim",
    "kişisel iban",
    "kisisel iban",
]


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
    "ders notları",
    "ders notlari",
    "projeyi yarın",
    "projeyi yarin",
    "pr review",
    "merge request",
    "standup",
    "iyi akşamlar",
    "iyi aksamlar",
]

# --- GENİŞLETİLMİŞ SİNYALLER (TR smishing / phishing 2024–2026) ---

# Sahte KYC / kimlik / hesap doğrulama
KYC_SCAM = [
    "kimlik doğrula",
    "kimlik dogrula",
    "kyc tamamla",
    "kyc doğrula",
    "kyc dogrula",
    "hesabınızı doğrulayın",
    "hesabinizi dogrulayin",
    "hesap doğrulama",
    "hesap dogrulama",
    "selfie çekin",
    "selfie cekin",
    "kimlik fotoğraf",
    "kimlik fotograf",
    "nüfus cüzdan",
    "nufus cuzdan",
    "ehliyet foto",
    "video doğrula",
    "video dogrula",
    "yüz tanıma",
    "yuz tanima",
]

# WhatsApp / Telegram / sosyal mühendislik
MESSENGER_SCAM = [
    "whatsapp'tan yaz",
    "whatsapptan yaz",
    "whatsapp hattı",
    "whatsapp hatti",
    "telegram'dan yaz",
    "telegramdan yaz",
    "telegram grubu",
    "özel sohbet",
    "ozel sohbet",
    "bu numaradan yazın",
    "bu numaradan yazin",
    "ben asistanıyım",
    "ben asistanıyim",
    "müşteri temsilcisiyim",
    "musteri temsilcisiyim",
    "destek ekibiyiz",
    "uzaktan erişim",
    "uzaktan erisim",
    "anydesk",
    "teamviewer",
    "ekran paylaş",
    "ekran paylas",
]

# Operatör / eSIM / SIM swap
TELCO_SCAM = [
    "esim aktivasyon",
    "e-sim",
    "sim kartınız bloke",
    "sim kartiniz bloke",
    "hattınız kapatılacak",
    "hattiniz kapatilacak",
    "paket yenileme link",
    "kontör yükle",
    "kontor yukle",
    "fatura borç",
    "fatura borc",
    "turkcell",
    "vodafone",
    "türk telekom",
    "turk telekom",
    "mobi̇l imza",
    "mobil imza doğrula",
]

# Fake tech support / hesap askıya alma (Apple, Google, Netflix…)
TECH_SUPPORT_SCAM = [
    "apple id",
    "icloud askıya",
    "icloud askiya",
    "google hesabınız",
    "google hesabiniz",
    "netflix üyeli",
    "spotify premium",
    "hesabınız askıya alındı",
    "hesabiniz askiya alindi",
    "güvenlik uyarısı microsoft",
    "guvenlik uyarisi microsoft",
    "lisansınız sona",
    "lisansiniz sona",
    "windows lisans",
    "virüs tespit",
    "virus tespit",
    "bilgisayarınız ele geçirildi",
    "bilgisayarınız tehlikede",
]

# Yatırım / forex / "kazanç" tuzağı
INVEST_SCAM = [
    "forex",
    "garantili kazanç",
    "garantili kazanc",
    "günlük %",
    "gunluk %",
    "yatırım danışmanı",
    "yatirim danismani",
    "borsa uzmanı",
    "borsa uzmani",
    "kripto sinyal",
    "vip sinyal grubu",
    "pasif gelir",
    "az risk yüksek getiri",
    "az risk yuksek getiri",
    "hesabına kar yatırılacak",
    "hesabina kar yatirilacak",
    "demo hesap aç",
    "demo hesap ac",
    "margin çağrısı",
    "margin cagrisi",
]

# İş ilanı / romance / "gönderi ücreti"
JOB_ROMANCE_SCAM = [
    "evden çalışma fırsat",
    "evden calisma firsat",
    "günlük 2000",
    "gunluk 2000",
    "başvuru ücreti",
    "basvuru ucreti",
    "kayıt ücreti yatır",
    "kayit ucreti yatir",
    "paket ücreti öde",
    "paket ucreti ode",
    "yurt dışı eşya",
    "yurt disi esya",
    "gümrük için para",
    "gumruk icin para",
    "aşkım iban",
    "askim iban",
    "acil param yok",
    "bilet paramı gönder",
    "bilet parami gonder",
]

# Vergi iadesi / SGK / maaş / destek ödemesi bait
REFUND_SCAM = [
    "vergi iadesi",
    "kdv iadesi",
    "sgk ödemeniz",
    "sgk odemeniz",
    "maaşınız yattı",
    "maasiniz yatti",
    "destek ödemesi bekliyor",
    "destek odemesi bekliyor",
    "ödemenizi almak için",
    "odemenizi almak icin",
    "hak ettiğiniz tutar",
    "hak ettiginiz tutar",
    "iade tutarınız",
    "iade tutariniz",
    "emekli ikramiye",
    "bayram ikramiye link",
]

# QR / fatura / sahte fatura
INVOICE_QR_SCAM = [
    "qr kodu okut",
    "karekod okut",
    "faturanız ektedir",
    "faturaniz ektedir",
    "ödenmemiş fatura",
    "odenmemis fatura",
    "elektrik borcu",
    "su borcu son",
    "doğalgaz borcu",
    "dogalgaz borcu",
    "trafik cezası öde",
    "trafik cezasi ode",
    "hızlı ödeme qr",
    "hizli odeme qr",
]

# OTP / remote code baskısı (asla paylaşılmaz)
OTP_PRESSURE = [
    "kodu bana söyle",
    "kodu bana soyle",
    "sms kodunu ilet",
    "doğrulama kodunu paylaş",
    "dogrulama kodunu paylas",
    "gelen kodu yaz",
    "otp'yi gönder",
    "otpyi gonder",
    "banka şifrenizi girin",
    "banka sifrenizi girin",
    "3d secure kod",
    "güvenlik sorusunun cevabı",
    "guvenlik sorusunun cevabi",
]

# Sahte kurumsal / HR / CEO fraud dili
CEO_FRAUD = [
    "acil eft yapmanı",
    "acil eft yapmani",
    "bugün mutlaka havale",
    "tedarikçiye ödeme",
    "tedarikciye odeme",
    "gizli tut",
    "kimseye söyleme",
    "muhasebeye söyleme",
    "ben tatildeyim öde",
    "ben tatildeyim ode",
    "ceo talimatı",
    "ceo talimati",
    "yönetim kurulu acil",
    "yonetim kurulu acil",
]

# Lookalike / phishing URL ipuçları (regex)
LOOKALIKE_HOST = re.compile(
    r"https?://[^\s]*(edevlet|e-devlet|turkiye-gov|turkiyegov|gib-gov|"
    r"ziraatbank|garanti-bbva|yapikredi|ptt-kargo|yurtici|"
    r"netflix-secure|appleid-|icloud-verify|turkcell-odeme)"
    r"[^\s]*\.(com|net|org|xyz|top|ru|cn|tk)\b",
    re.I,
)
# evrensel: login/verify/update path bait
PHISH_PATH = re.compile(
    r"https?://[^\s]+/(login|signin|verify|secure|update|account|odeme|dogrula|"
    r"confirm|wallet|kyc|reset-password)(/|\?|$)",
    re.I,
)
# mailto / tel baskısı
TEL_LINK = re.compile(r"\btel:\+?90?\d{10,}\b", re.I)

# Ek aciliyet / baskı kelimeleri
RED_WORDS_EXTRA = [
    "hemen öde",
    "hemen ode",
    "son şans",
    "son sans",
    "kaçırma",
    "kacirma",
    "bloke edilecek",
    "kapatılacak",
    "kapatilacak",
    "askıya alınacak",
    "askiya alinacak",
    "işleminizi onaylayın",
    "isleminizi onaylayin",
    "güvenliğiniz için tıklayın",
    "guvenliginiz icin tiklayin",
    "aksi halde",
    "yapmazsanız",
    "yapmazsaniz",
    "yasal işlem başlatılacak",
    "yasal islem baslatilacak",
    "polis gelecek",
    "gözaltı",
    "gozalti",
    "tutuklama",
]

# Ek markalar (banka dışı sık taklit)
EXTRA_BRANDS = [
    "migros",
    "a101",
    "bim",
    "şok",
    "sok market",
    "getir",
    "yemeksepeti",
    "trendyol",
    "hepsiburada",
    "n11",
    "sahibinden",
    "arabam",
    "pegasus",
    "thy",
    "anadolu jet",
    "turkcell",
    "vodafone",
    "netflix",
    "spotify",
    "instagram",
    "whatsapp",
]

# Ek kargo / marketplace
CARGO_SCAM_EXTRA = [
    "kargonuz bekliyor",
    "paketiniz gümrükte",
    "paketiniz gumrukte",
    "teslimat ücreti yatır",
    "teslimat ucreti yatir",
    "kapıda ödeme farkı",
    "kapida odeme farki",
    "adres doğrulama link",
    "adres dogrulama link",
    "kargo takip no",
    "gönderi numarası doğrula",
    "gonderi numarasi dogrula",
]

BANK_SCAM_EXTRA = [
    "limit aşımı",
    "limit asimi",
    "şüpheli işlem tespit",
    "supheli islem tespit",
    "kartınız kopyalandı",
    "kartiniz kopyalandi",
    "3d doğrulama gerekli",
    "3d dogrulama gerekli",
    "iban doğrulama",
    "iban dogrulama",
    "hesap hareketi onay",
    "mobil onay bekliyor",
    "güvenli ödeme sayfası",
    "guvenli odeme sayfasi",
]

EDEVLET_SCAM_EXTRA = [
    "mernis",
    "nüfus müdürlüğü",
    "nufus mudurlugu",
    "askerlik işlem",
    "askerlik islem",
    "ehliyet puan",
    "ceza puanınız",
    "ceza puaniniz",
    "i̇kametgah",
    "ikametgah belgesi link",
    "sgk hizmet döküm",
    "sgk hizmet dokum",
    "e-devlet şifre yenile",
    "edevlet sifre yenile",
]

LEGAL_SCAM_EXTRA = [
    "uymada bulunduğunuz",
    "uymada bulundugunuz",
    "suç duyurusu",
    "suc duyurusu",
    "ifade vermeniz",
    "elektronik tebligat",
    "e-tebligat",
    "uyap",
    "dosya esas no",
    "keşif ücreti",
    "kesif ucreti",
    "vekalet ücreti yatır",
    "vekalet ucreti yatir",
]

GIFT_BAIT_EXTRA = [
    "iphone kazandınız",
    "iphone kazandiniz",
    "15.000 tl kazand",
    "çarkıfelek",
    "carkifelek",
    "şanslı müşteri",
    "sansli musteri",
    "hediye çeki",
    "hediye ceki",
    "promosyon kodunuz",
    "ücretsiz tatil",
    "ucretsiz tatil",
    "vip üyelik hediye",
    "vip uyelik hediye",
]

# Mevcut listelere ekleri birleştir (geriye uyumlu)
RED_WORDS = RED_WORDS + RED_WORDS_EXTRA
LEGAL_SCAM = LEGAL_SCAM + LEGAL_SCAM_EXTRA
EDEVLET_SCAM = EDEVLET_SCAM + EDEVLET_SCAM_EXTRA
CARGO_SCAM = CARGO_SCAM + CARGO_SCAM_EXTRA
BANK_SCAM = BANK_SCAM + BANK_SCAM_EXTRA
GIFT_BAIT = GIFT_BAIT + GIFT_BAIT_EXTRA
BANK_BRANDS = BANK_BRANDS + EXTRA_BRANDS
