# WARDEN IPS - MİMARİ VE GELİŞTİRME GEREKSİNİMLERİ

Sen uzman bir DevOps mühendisi, Etik Hacker (Blue Team / Defansif Güvenlik uzmanı) ve Kıdemli Python Geliştiricisisin. Seninle birlikte Linux tabanlı (özellikle Minecraft sunucuları ve SSH için) çalışan, botnet ve DDoS saldırılarını tespit edip otonom savunma yapan, son derece yüksek performanslı bir IPS (Intrusion Prevention System) yazılımı geliştireceğiz. Bu projenin adı: **WardenIPS**

Token tasarrufu sağlamak ve süreci hızlandırmak için adım adım ama BÜYÜK parçalar (Fazlar) halinde ilerleyeceğiz. Her fazda, o modülün kodlarını eksiksiz ve çalışır durumda yazacaksın. Yarım kod, "burayı sen doldur" gibi yorum satırları istemiyorum. Bir fazı bitirdiğinde bana sadece ne yaptığını özetle ve "Hazırsanız 'Okay' yazın, Faz X'e geçeyim" diye sor.

### SİSTEM MİMARİSİ VE GEREKSİNİMLER (BUNLARA KESİNLİKLE UYULACAK):
1. **ASN ve Veri Merkezi Tespit:** API limitlerine takılmamak için MaxMind GeoLite2 ASN veritabanı lokal olarak kullanılacak. IP'nin AWS, OVH, DigitalOcean gibi datacenter'lara ait olup olmadığı saniyenin binde biri hızında lokalden çözülecek.
2. **Yüksek Performanslı Banlama:** Standart iptables yerine `ipset` kullanılacak. Güvenlik duvarı entegrasyonu sunucuyu yormayacak.
3. **Asenkron Mimari:** Tüm sistem Python `asyncio` kütüphanesi üzerine kurulacak. Log okuma (tailing), analiz etme, veritabanına yazma ve banlama işlemleri tamamen asenkron olacak (Self-DDoS'u engellemek için).
4. **Güvenlik Duvarı ve Whitelist:** Kesin bir Whitelist mekanizması ve Geofencing (Örn: Sadece TR'ye izin ver) yeteneği olacak. Yöneticilerin dışarıda kilitli kalması engellenecek.
5. **KVKK ve AI Hazırlığı (Veritabanı):** SQLite (veya PostgreSQL) kullanılacak. Kayıtlar (Zaman damgası, Oyuncu Nicki, Bağlantı Türü, ASN, Risk Skoru) temiz tutulacak. Ancak KVKK ve güvenlik gereği IP adresleri veritabanına direkt DÜZ METİN YAZILMAYACAK, güvenli bir "Salt" değeri ile Hash'lenerek (anonimleştirilerek) saklanacak.
6. **Modüler Plugin Desteği:** WardenIPS çekirdek bir analiz motoru olacak. SSH (auth.log) ve Minecraft (latest.log) sadece bu motorun pluginleri olacak. İleride kolayca Nginx modülü eklenebilecek bir Interface/BaseClass yapısı kurulacak.
7. **İleri Aşama:** AbuseIPDB'ye asenkron olarak otomatik raporlama yapılacak (Rate limit kurallarına uyarak).

### GELİŞTİRME FAZLARI (Bu sırayla ilerleyeceksin):

*   **Faz 1: Proje Kurulumu ve Çekirdek Mimari:** WardenIPS dosya dizini mimarisinin oluşturulması, `requirements.txt` dosyasının yazılması ve `config.yaml` / `config.json` ile Whitelist yöneticisinin (asenkron okuyucu) kodlanması.
*   **Faz 2: Lokal ASN Motoru ve Veritabanı:** MaxMind GeoLite2 okuyucu sınıfı ile KVKK uyumlu (Salt+Hash IP) SQLite veritabanı yönetim sınıfının asenkron kodlanması.
*   **Faz 3: Aksiyon Motoru (ipset) & AbuseIPDB:** `ipset` kullanarak IP drop eden asenkron banlama modülü ve AbuseIPDB API postlayıcı modülün kodlanması.
*   **Faz 4: Log Tailing ve Plugin Sistemi:** Asenkron dosya izleyici (async log tailing) motoru ve `BasePlugin` sınıfının yazılması.
*   **Faz 5: SSH ve Minecraft Pluginleri & Main.py:** `auth.log` ve `latest.log` için regex ayrıştırıcı modüllerin yazılıp, tüm parçaları birleştiren WardenIPS `main.py` dosyasının kodlanması.

GÖREV:
Eğer bu dosyayı okuduysan ve tüm mimariyi anladıysan, şimdi doğrudan **Faz 1**'in tam ve eksiksiz kodlarını yazarak başla. Dosya ve klasör isimlerini belirterek kod bloklarını ver. Faz 1 bitince bana "Hazırsanız 'Okay' yazın, Faz 2'ye geçeyim." de.