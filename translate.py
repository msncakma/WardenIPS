import os

replacements = {
    # main.py and general
    "Otonom Saldiri Onleme Sistemi": "Autonomous Intrusion Prevention System",
    "Linux tabanli sunucular icin botnet ve DDoS saldirilarini": "A high-performance IPS for Linux-based servers that detects botnet",
    "tespit edip otonom savunma yapan yuksek performansli IPS.": "and DDoS attacks entirely autonomously.",
    "Kullanim:": "Usage:",
    "Versiyon": "Version",
    "ana uygulama sinifi.": "main application class.",
    "Tum bilesenleri baslatir, pluginleri yukler,": "Initializes all components, loads plugins,",
    "log tailer'lari calistirir ve analiz dongusunu yonetir.": "runs log tailers and manages the analysis loop.",
    "baslatir ve tum bilesenleri yukler.": "Starts WardenIPS and loads all components.",
    "Yapilandirma": "Configuration",
    "Loglama": "Logging",
    "baslatiliyor...": "is starting...",
    "Cekirdek Bilesenler": "Core Components",
    "Whitelist:": "Whitelist:",
    "ASN Motoru:": "ASN Engine:",
    "Veritabani:": "Database:",
    "Guvenlik Duvari:": "Firewall:",
    "Pluginleri Yukle": "Load Plugins",
    "Log Tailer'lari Baslat": "Start Log Tailers",
    "WardenIPS AKTIF —": "WardenIPS is ACTIVE — monitoring",
    "plugin izleniyor": "plugins",
    "Yapılandırmaya gore pluginleri kaydeder.": "Registers plugins according to the configuration.",
    "Her aktif plugin icin LogTailer olusturup baslatir.": "Creates and starts a LogTailer for each active plugin.",
    "Log tailer baslatildi:": "Log tailer started:",
    "Bir plugin icin olay isleme callback'i olusturur.": "Creates an event processing callback for a plugin.",
    "Satiri ayristir": "Parse line",
    "Whitelist kontrolu": "Whitelist check",
    "IP hash'le": "Hash IP",
    "ASN bilgisi al": "ASN lookup",
    "Gecmis olay sayisini sorgula": "Query recent events count",
    "Risk skoru hesapla": "Calculate risk score",
    "Threat level belirle": "Determine threat level",
    "Guncellenmis olayi veritabanina kaydet": "Log updated event to database",
    "Geofencing kontrolu": "Geofencing check",
    "Aksiyon al": "Execute action",
    "TEHDIT TESPIT EDILDI:": "THREAT DETECTED:",
    "Risk=": "Risk=",
    "Aksiyon=": "Action=",
    "Plugin=": "Plugin=",
    "Tip=": "Type=",
    "SUPHE:": "SUSPICIOUS:",
    "Ana donguyu calistir — sinyal alana kadar bekle.": "Run the main loop — wait until a signal is received.",
    "Kapatma sinyali alindi...": "Shutdown signal received...",
    "Tum bilesenleri guvenli sekilde kapatir.": "Safely shutdown all components.",
    "WardenIPS kapatiliyor...": "Shutting down WardenIPS...",
    "Tailer'lari durdur": "Stop tailers",
    "Pluginleri durdur": "Stop plugins",
    "Servisleri kapat": "Close services",
    "WardenIPS guvenli sekilde kapatildi.": "WardenIPS shut down safely.",
    "Komut satiri argumenlarini ayristir.": "Parse command line arguments.",
    "Yapilandirma dosyasi yolu (varsayilan: config.yaml)": "Configuration file path (default: config.yaml)",
    "Ana giris noktasi.": "Main entry point.",
    
    # whitelist.py
    "WhitelistManager baslatildi": "WhitelistManager started",
    "Whitelist yüklendi —": "Whitelist loaded —",
    "tekil IP": "unique IP",
    "CIDR araligi": "CIDR range",
    "Geofencing DEVRE DISI": "Geofencing DISABLED",
    "Geofencing AKTIF": "Geofencing ACTIVE",
    "mod": "mode",
    "ulke": "countries",
    
    # database.py
    "Veritabani basariyla baslat ildi:": "Database successfully initialized:",
    "Veritabani baglantisi kapatildi.": "Database connection closed.",
    "Olay kaydedildi": "Event logged",
    "Ban kaydedildi": "Ban logged",
    "Sebep": "Reason",
    "Sure": "Duration",
    
    # ip_hasher.py
    "IP hash salt degeri degistirilmemis veya bos! Guvenlik riski — config.yaml'da salt degerini guncelleyin.": "IP hash salt is unchanged or empty! Security risk — please update the salt in config.yaml.",
    "baslatildi. Algoritma:": "started. Algorithm:",
    "Salt uzunlugu:": "Salt length:",
    
    # logger.py
    "Loglama sistemi başlatıldı. Seviye:": "Logging system started. Level:",
    
    # asn_lookup.py
    "MaxMind GeoLite2 veritabanlarini kullanarak IP adreslerinin": "MaxMind GeoLite2 ASN lookup engine.",
    "ASN ve ulke bilgilerini cozumler.": "",
    "geoip2 kutuphanesi kurulu degil — ASN motoru devre disi.": "geoip2 library not found — ASN engine disabled.",
    "GeoLite2-ASN veritabani bulunamadi:": "GeoLite2-ASN database not found:",
    "ASN sorgusu yapilamayacak.": "ASN lookup will be disabled.",
    "GeoLite2-Country veritabani bulunamadi:": "GeoLite2-Country database not found:",
    "Ulke sorgusu yapilamayacak.": "Country lookup will be disabled.",
    "Bilinen datacenter ASN sayisi:": "Known datacenter ASN count:",
    
    # firewall.py
    "Asenkron Guvenlik Duvari Modulu (ipset)": "Async Firewall Module (ipset)",
    "ipset + iptables kullanarak IP adreslerini yuksek performansla banlar.": "Blocks IP addresses with high performance using ipset + iptables.",
    "Sudo ile calistirildiginda /sbin PATH'te olmayabilir, bu yuzden manuel ekliyoruz": "Manual path for ipset when run with sudo",
    "Guvenlik duvari SIMULASYON modunda! Sebep:": "Firewall is in SIMULATION mode! Reason:",
    "Komutlar loglanacak ama calistirilmayacak.": "Commands will be logged but not executed.",
    "Root yetkisi yok — guvenlik duvari SIMULASYON modunda!": "No root privileges — firewall is in SIMULATION mode!",
    "Guvenlik duvari baslatildi. Set:": "Firewall started. Set:",
    "Varsayilan ban suresi:": "Default ban duration:",
    "Simulasyon:": "Simulation:",
    "BAN ENGELLENDI! IP whitelist'te:": "BAN BLOCKED! IP is in whitelist:",
    "Yonetici kilidi korumasi aktif.": "Admin lock protection active.",
    "IP BANLANDI:": "IP BANNED:",
    "IP BAN KALDIRILDI:": "IP UNBANNED:",
    "TUM BANLAR KALDIRILDI! Set": "ALL BANS REMOVED! Set",
    "bosaltildi.": "flushed.",
    "Ban sayisi alinamadi:": "Failed to get ban count:",
    "Guvenlik duvari modulu kapatiliyor.": "Firewall module shutting down.",
    "Not: ipset seti": "Note: ipset set",
    "ve kurallar korunacak.": "and rules will be preserved.",
    "Komut hata dondurdu (ignore):": "Command returned error (ignored):",
    "Guvenlik duvari komut hatasi:": "Firewall command error:",
    "Komut bulunamadi:": "Command not found:",
    "Komut calistirma hatasi:": "Command execution error:",
    
    # abuseipdb.py
    "Asenkron Raporlayici": "Async Reporter",
    "aiohttp kutuphanesi bulunamadi. AbuseIPDB devre disi.": "aiohttp library not found. AbuseIPDB disabled.",
    "AbuseIPDB raporlama devre disi (config).": "AbuseIPDB reporting disabled (config).",
    "AbuseIPDB API key tanimlanmamis — raporlama devre disi.": "AbuseIPDB API key not defined — reporting disabled.",
    "aiohttp kurulu degil — AbuseIPDB devre disi.": "aiohttp not installed — AbuseIPDB disabled.",
    "AbuseIPDB raporlayici baslatildi.": "AbuseIPDB reporter started.",
    "rapor/dakika.": "reports/minute.",
    "AbuseIPDB devre disi, rapor atlanıyor:": "AbuseIPDB disabled, skipping report:",
    "AbuseIPDB rate limit asildi": "AbuseIPDB rate limit exceeded",
    "Rapor atlanıyor:": "Skipping report:",
    "AbuseIPDB rapor basarili: IP=": "AbuseIPDB report successful: IP=",
    "Kategoriler=": "Categories=",
    "Skor=": "Score=",
    "AbuseIPDB rapor hatasi: HTTP": "AbuseIPDB report error: HTTP",
    "AbuseIPDB istek zaman asimi:": "AbuseIPDB request timeout:",
    "AbuseIPDB rapor hatasi:": "AbuseIPDB report error:",
    "AbuseIPDB rate limit — sorgu atlaniyor:": "AbuseIPDB rate limit — skipping query:",
    "AbuseIPDB session kapatildi.": "AbuseIPDB session closed.",
    
    # log_tailer.py
    "Asenkron Log Tailing Motoru": "Async Log Tailing Engine",
    "Log tailer iptal edildi.": "Log tailer cancelled.",
    "Log tailer hatasi:": "Log tailer error:",
    "5s sonra tekrar denenecek.": "will retry in 5s.",
    "Log tailer durdu.": "Log tailer stopped.",
    "Log tailer durduruldu. Toplam islenen satir:": "Log tailer stopped. Total lines processed:",
    "Dosya bulunamadi, bekleniyor:": "File not found, waiting:",
    "Dosya stat hatasi:": "File stat error:",
    "Dosya izleniyor (boyut:": "Monitoring file (size:",
    "bytes, pozisyon:": "bytes, position:",
    "Callback hatasi:": "Callback error:",
    "satir:": "line:",
    "Dosya rotasyonu algilandi!": "File rotation detected!",
    "Dosya silindi, yeniden olusturulmasini bekleniyor.": "File deleted, waiting for recreation.",
    "Okuma hatasi:": "Read error:",
    
    # base_plugin.py
    "Soyut Sinifi": "Abstract Class",
    "Plugin baslatildi:": "Plugin started:",
    "Plugin durduruldu:": "Plugin stopped:",
    "Islenen:": "Processed:",
    "olay": "events",
    "Satir ayristirma hatasi:": "Line parsing error:",
    "Plugin zaten kayitli:": "Plugin already registered:",
    "Plugin kaydedildi:": "Plugin registered:",
    "Plugin baslatma hatasi": "Plugin start error",
    "Plugin durdurma hatasi": "Plugin stop error",
    
    # plugins
    "Basarisiz sifre": "Failed password",
    "Gecersiz kullanici": "Invalid user",
    "Baglanti kopma": "Connection closed",
    "Oyuncu girisi": "Player login",
    "Paket hatasi": "Packet error"
}

import os
from pathlib import Path

def translate_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    
    original = content
    for tr, en in replacements.items():
        content = content.replace(tr, en)
        
    if original != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Translated {path}")

def main():
    root_dir = r"c:\Users\KayganYol\GithubProjects\WardenIPS\wardenips"
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith(".py"):
                translate_file(os.path.join(dirpath, file))
    
    # main is already translated but let's just make sure we got everything
    translate_file(r"c:\Users\KayganYol\GithubProjects\WardenIPS\main.py")

if __name__ == "__main__":
    main()
