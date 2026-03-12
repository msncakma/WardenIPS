# WardenIPS - Sanal Makine (VM) Test Rehberi

Bu rehber, WardenIPS'i gercek sunucunuza kurmadan once bir sanal makinede
nasil test edecginizi adim adim anlatir.

---

## 1. VM Hazirlik

### Ne Lazim?

| Gereksinim | Oneri |
|-----------|-------|
| **VM Yazilimi** | VirtualBox (ucretsiz) veya VMware |
| **ISO** | Ubuntu Server 22.04 LTS |
| **RAM** | 1 GB yeter |
| **Disk** | 10 GB yeter |
| **Ag** | Bridged Adapter (host'tan SSH icin) |

### VM Olusturma (VirtualBox)

1. VirtualBox'i ac → **New** → Ad: `WardenTest`
2. Type: Linux, Version: Ubuntu (64-bit)
3. RAM: 1024 MB, Disk: 10 GB
4. **Settings → Network → Adapter 1 → Bridged Adapter** sec (kendi ag kartini sec)
5. **Settings → Network → Adapter 1 → Advanced → Port Forwarding** ile SSH ekle:
   - Host Port: `2222`, Guest Port: `22`, Protocol: TCP
6. Ubuntu Server ISO'yu takit ve kur
   - Kurulumda **OpenSSH Server** secenegini isaretle!
   - Kullanici adi/sifre: `warden` / `warden123` (test icin)

### VM IP Adresini Ogren

```bash
# VM icinde calistir
ip addr show | grep "inet "
# Ornek cikti: inet 192.168.1.50/24 ...
```

> Bu IP'yi not al — testlerde kullanacaksin.

---

## 2. VM'ye WardenIPS Kur

### 2.1 Sistem Paketleri

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv ipset iptables git
```

### 2.2 Proje Dosyalarini Aktar

**Yontem A — Git ile (repo varsa):**
```bash
cd /opt
sudo git clone <REPO_URL> wardenips
```

**Yontem B — SCP ile (Windows'tan kopyala):**

Windows PowerShell'de calistir:
```powershell
# Tum projeyi VM'ye kopyala
scp -P 2222 -r C:\Users\KayganYol\GithubProjects\WardenIPS\* warden@127.0.0.1:/tmp/wardenips/
```

Sonra VM icinde:
```bash
sudo mkdir -p /opt/wardenips
sudo cp -r /tmp/wardenips/* /opt/wardenips/
cd /opt/wardenips
```

### 2.3 Bagimliklar

```bash
cd /opt/wardenips
sudo pip3 install -r requirements.txt
```

### 2.4 Dizinleri Olustur

```bash
sudo mkdir -p /var/log/wardenips
sudo mkdir -p /var/lib/wardenips
```

---

## 3. Test Icin config.yaml Ayarla

```bash
cd /opt/wardenips
sudo nano config.yaml
```

### Degistirilmesi GEREKEN yerler:

```yaml
general:
  log_level: "DEBUG"          # <-- Test icin DEBUG yap (her seyi gorursun)

whitelist:
  ips:
    - "127.0.0.1"
    - "::1"
    - "192.168.1.1"           # <-- KENDI BILGISAYARININ IP'SI (host)

database:
  sqlite:
    path: "/var/lib/wardenips/warden.db"
  ip_hashing:
    salt: "test-salt-degeri-vm-icin-12345"   # <-- Test icin basit olabilir

maxmind:
  asn_db_path: "/var/lib/wardenips/GeoLite2-ASN.mmdb"
  country_db_path: "/var/lib/wardenips/GeoLite2-Country.mmdb"

geofencing:
  enabled: false              # <-- Test icin kapali tut (once temel sistemi test et)

abuseipdb:
  enabled: false              # <-- Test icin kapali tut

plugins:
  ssh:
    enabled: true
    log_path: "/var/log/auth.log"
    max_failed_attempts: 3     # <-- Test icin dusur (3 denemede tetiklensin)

  minecraft:
    enabled: false             # <-- Minecraft yoksa kapat
```

**Kaydet:** `Ctrl+O`, `Enter`, `Ctrl+X`

> **ONEMLI:** Whitelist'e kendi bilgisayarinin IP'sini (host) ekle,
> yoksa test sirasinda kendin banlanabilirsin!

---

## 4. MaxMind Veritabanlari (Opsiyonel ama Onerilen)

MaxMind olmadan da calisir (ASN bilgisi bos doner). Ama tam test icin:

```bash
# MaxMind hesabi acin: https://www.maxmind.com/en/geolite2/signup
# Lisans anahtarinizi alin, sonra:

cd /tmp
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=ANAHTARINIZ&suffix=tar.gz" -O GeoLite2-ASN.tar.gz
tar xzf GeoLite2-ASN.tar.gz
sudo cp GeoLite2-ASN_*/GeoLite2-ASN.mmdb /var/lib/wardenips/

wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=ANAHTARINIZ&suffix=tar.gz" -O GeoLite2-Country.tar.gz
tar xzf GeoLite2-Country.tar.gz
sudo cp GeoLite2-Country_*/GeoLite2-Country.mmdb /var/lib/wardenips/
```

> MaxMind olmadan da test edebilirsin — sadece ASN/ulke bilgisi bos kalir.

---

## 5. WardenIPS'i Baslat

Eger Python virtual environment (venv) kullaniyorsaniz, `sudo python3` komutu sistemin genel Python'unu kullanacagi icin modulleri bulamayacaktir. Venv icindeki Python'u `sudo` ile calistirmak icin venv'in tam yolunu kullanmalisiniz.

```bash
cd /opt/wardenips

# Eger venv klasorunuzun adi "venv" ise:
sudo ./venv/bin/python main.py

# Alternatif olarak venv Python yolunu bularak:
# sudo $(which python) main.py
```

Beklenen cikti:
```
WardenIPS Loglama sistemi baslatildi. Seviye: DEBUG
============================================================
  WardenIPS v0.1.0 baslatiliyor...
============================================================
Whitelist yuklendi — 3 tekil IP, 3 CIDR araligi.
Guvenlik duvari baslatildi. Set: 'warden_blacklist', ...
Log tailer baslatildi: SSH -> /var/log/auth.log
============================================================
  WardenIPS AKTIF — 1 plugin izleniyor
============================================================
```

> WardenIPS calistiktan sonra **yeni bir terminal ac** ve testleri yap.
> WardenIPS terminalini acik birak — loglari canli izle.

---

## 6. TEST SENARYOLARI

### Test 1: SSH Brute-Force Simulasyonu

**Windows bilgisayarından** (host) yap — VM'ye yanlis sifre ile SSH:

```powershell
# PowerShell'de calistir (port forwarding yoksa direkt VM IP kullan)
ssh fake_user@VM_IP_ADRESI
# Sifre sorunca yanlis bir sey yaz, 3-5 kere tekrarla
```

Veya **hizli otomatik test** (VM icinde baska bir terminalden):

```bash
# 5 kere basarisiz giris denemesi simule et
for i in {1..5}; do
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes sahte_kullanici@127.0.0.1 2>/dev/null
    echo "Deneme $i yapildi"
done
```

**WardenIPS terminalinde su loglari gormen lazim:**
```
TEHDIT TESPIT EDILDI: IP=... Risk=XX Aksiyon=BAN Plugin=SSH Tip=invalid_user
IP BANLANDI: ... | Sure: 3600s | Sebep: [SSH] Risk=XX ...
```

### Test 2: ipset Kontrolu

Banlama sonrasi ipset setini kontrol et:

```bash
sudo ipset list warden_blacklist
```

Beklenen cikti:
```
Name: warden_blacklist
Type: hash:ip
Members:
203.0.113.50 timeout 3500
```

### Test 3: Veritabani Kontrolu

```bash
sqlite3 /var/lib/wardenips/warden.db

-- Olaylari gor
SELECT * FROM connection_events ORDER BY id DESC LIMIT 10;

-- Banlari gor
SELECT * FROM ban_history ORDER BY id DESC LIMIT 10;

-- Cik
.quit
```

### Test 4: Whitelist Korumasi

Kendi IP'ni (whitelist'teki) banlama denemesine karsi koruma:

```bash
# WardenIPS loglarinda bu mesaji gormelisin:
# "BAN ENGELLENDI! IP whitelist'te: 192.168.x.x"
```

### Test 5: Log Dosyasini Kontrol Et

```bash
tail -f /var/log/wardenips/warden.log
```

### Test 6: Ban Kaldirma (Manuel)

```bash
# Bir IP'yi manuel olarak banlisteden cikar
sudo ipset del warden_blacklist IP_ADRESI

# Tum banlari kaldir
sudo ipset flush warden_blacklist
```

---

## 7. Minecraft Testi (Opsiyonel)

Eger Minecraft sunucusu da test etmek istersen:

```bash
# Ornek minecraft log dosyasi olustur
sudo mkdir -p /opt/minecraft/logs
sudo tee /opt/minecraft/logs/latest.log << 'EOF'
[14:30:22] [Server thread/INFO]: BotPlayer1[/203.0.113.50:12345] logged in
[14:30:23] [Server thread/INFO]: BotPlayer2[/203.0.113.50:12346] logged in
[14:30:24] [Server thread/INFO]: BotPlayer3[/203.0.113.50:12347] logged in
[14:30:25] [Server thread/WARN]: Failed to handle packet for /203.0.113.51:12348
EOF
```

config.yaml'da Minecraft plugin'i aktifle:
```yaml
plugins:
  minecraft:
    enabled: true
    log_path: "/opt/minecraft/logs/latest.log"
```

WardenIPS'i yeniden baslat ve loglari izle.

---

## 8. Geofencing Testi (Opsiyonel)

MaxMind veritabanlarini yuklediysen:

```yaml
# config.yaml
geofencing:
  enabled: true
  mode: "allow"
  countries:
    - "TR"
```

WardenIPS'i yeniden baslat. TR disindaki IP'ler otomatik olarak
daha yuksek risk skoru alacak.

---

## 9. Temizlik ve Sifirlama

```bash
# WardenIPS'i durdur
# (WardenIPS terminalinde Ctrl+C)

# Veritabanini sifirla
sudo rm -f /var/lib/wardenips/warden.db

# ipset'i temizle
sudo ipset flush warden_blacklist
sudo ipset destroy warden_blacklist

# iptables kuralini kaldir
sudo iptables -D INPUT -m set --match-set warden_blacklist src -j DROP
```

---

## 10. Checklist — Her Sey Calisiyor mu?

- [ ] VM'de WardenIPS baslatildi (hata yok)
- [ ] SSH brute-force tespiti calisti (logda TEHDIT goruldu)
- [ ] ipset'e IP eklendi (`sudo ipset list warden_blacklist`)
- [ ] Veritabaninda olay kaydi var (`sqlite3 ... SELECT ...`)
- [ ] Whitelist korumasi calisiyor (kendi IP'n banlanmiyor)
- [ ] Log dosyasi yaziliyor (`/var/log/wardenips/warden.log`)
- [ ] `Ctrl+C` ile temiz kapanma calisiyor

**Tumu OK ise → gercek sunucuya kurabilirsin!**
