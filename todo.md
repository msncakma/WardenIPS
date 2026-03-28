1. Port Scan & Honeypot Plugin (Erken Uyarı Sistemi)

Hedef: Saldırgan daha gerçek servislere (SSH, Web) ulaşmadan, kapalı portları kurcalarken yakalamak.

    Prompt: > "WardenIPS projem için bir 'Port Scan' plugini yazmanı istiyorum. Bu plugin, Linux sistemindeki iptables loglarını (örn: /var/log/kern.log veya /var/log/syslog) asenkron olarak okumalı.

        Plugin, loglar içindeki 'WARDEN_SCAN' prefix'ine sahip satırları yakalamalı.

        Belirli bir zaman penceresinde (örneğin 10 saniye) aynı kaynak IP'den gelen farklı hedef port (DPT) isteklerini saymalı.

        Eğer eşik değer (threshold) aşılırsa veya kullanıcı tarafından belirlenen 'Honeypot' portlarına (örn: 23, 445, 3389) tek bir istek bile gelirse, bu IP'ye yüksek bir risk puanı atamalı.

        Bu veriyi WardenIPS'in mevcut Risk Scoring pipeline'ına göndermeli. Kodun performanslı olması için regex ve asenkron dosya okuma (aiofiles gibi) kullanmalısın."

2. Görsel Tehdit Haritası (Heatmap & Dashboard Geo-Visualization)

Hedef: Dashboard'da veriyi görselleştirip kullanıcıya saldırıların coğrafi dağılımını göstermek.

    Prompt: > "WardenIPS dashboard'u için bir coğrafi görselleştirme özelliği eklemek istiyorum.

        Mevcut SQLite/Redis veritabanındaki engellenen IP'leri alıp, GeoLite2 veritabanını kullanarak bu IP'lerin ülke kodlarını ve koordinatlarını (Enlem/Boylam) çıkaran bir API endpoint'i yaz (Python/FastAPI veya kullandığım framework hangisiyse).

        Dashboard'un (HTML/JS) ön yüzüne 'Leaflet.js' veya 'Datamaps' kütüphanesini kullanarak küçük bir dünya haritası ekle.

        API'den gelen verileri bu harita üzerinde ısı haritası (heatmap) veya kırmızı noktalar şeklinde göster.

        Harita üzerinde bir ülkeye tıklandığında, o ülkeden gelen toplam saldırı sayısını gösteren bir popup ekle."

3. Akıllı Skorlama ve Korelasyon (Smart Scoring)

Hedef: Farklı saldırı türlerini birleştirip "gerçek saldırganı" daha hızlı banlamak.

    Prompt: > "WardenIPS'in mevcut risk puanlama sistemini 'Akıllı Korelasyon' (Correlation) özelliği ile güncellemeni istiyorum.

        Sistem, bir IP'nin sadece tek bir servise (örn: sadece SSH) saldırmasıyla, aynı anda birden fazla servise (örn: hem SSH hem Nginx hem Port Scan) saldırmasını ayırt etmeli.

        Eğer bir IP farklı kategorilerde (Multi-Vector Attack) aktivite gösteriyorsa, toplam risk puanına %50 'Multi-Vector Bonusu' ekle.

        Belirli bir IP daha önce banlanıp açılmışsa (Recidivist), tekrar suç işlediğinde ban süresini logaritmik olarak artır (Örn: 1. ban 1 saat, 2. ban 24 saat, 3. ban 1 hafta).

        Bu mantığı core/scoring.py (veya ilgili dosya) içine temiz bir sınıfla entegre et."

4. Operatör Tavsiyesi (AI-Driven/Rule-Based Actionable Advice)

Hedef: Kullanıcıya "IP banlandı" demek yerine, saldırının ne olduğunu açıklamak.

    Prompt: > "WardenIPS dashboard'undaki 'Events' kısmına bir 'Operatör Tavsiyesi' (Operator Advice) sütunu eklemek istiyorum.

        Yakalanan loglardaki paternleri analiz eden basit bir kural motoru yaz.

        Eğer logda 'wp-login.php' veya 'admin-ajax.php' varsa tavsiye olarak: 'WordPress Brute Force girişimi algılandı. WP-Admin panelini kısıtlamayı düşünün.' yazmalı.

        Eğer logda 'sql syntax', 'union select' gibi ifadeler varsa: 'SQL Injection denemesi. Veritabanı sorgularınızı sanitize edin.' yazmalı.

        Eğer çok kısa sürede çok fazla bağlantı varsa: 'DDoS/Flood saldırısı belirtisi. Bant genişliğini kontrol edin.' demeli.

        Bu tavsiyeleri dashboard'da bir bilgi ikonu (tooltip) olarak göster."

5. Otomatik Whitelist ve Yanlış Ban Önleme (Safety First)

Hedef: Kullanıcının yanlışlıkla kendi IP'sini banlamasını imkansız hale getirmek.

    Prompt: > "WardenIPS için gelişmiş bir 'Kendi Kendini Koruma' (Anti-Lockout) modülü yaz.

        Sistem her başladığında, o anki aktif SSH oturumlarının IP adreslerini ve sistemdeki varsayılan ağ geçidini (gateway) otomatik olarak tespit edip geçici whitelist'e almalı.

        Dashboard üzerinden sisteme erişen kullanıcının IP'sini X-Forwarded-For veya Remote-Addr üzerinden tespit edip, bu IP'ye asla ban atılmamasını garanti etmeli.

        Eğer bir ban işlemi kritik bir sistem IP'sini (localhost, gateway vb.) hedefliyorsa, işlemi durdurup loglara 'CRITICAL: Lockout prevented' uyarısı düşmeli."