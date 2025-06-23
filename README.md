# Modular Web Scanner Vulnerability

Scanner kerentanan web komprehensif dengan arsitektur modular untuk pengembangan dan ekstensi yang mudah. Mendukung 16+ jenis kerentanan web modern dengan kemampuan pemilihan plugin fleksibel dan rate limiting global.

## 🏗️ **Arsitektur**

Scanner ini menggunakan **arsitektur berbasis plugin modular** dimana:

- **Scanner utama** (`main_scanner.py`) secara otomatis mendeteksi dan menjalankan semua plugin kerentanan
- **Setiap jenis kerentanan** memiliki file plugin sendiri di folder `vuln_plugins/`
- **Menambah kerentanan baru** semudah membuat file Python baru di folder plugin
- **Kini Anda dapat memilih plugin tertentu yang ingin dijalankan dengan parameter `-p/--plugin`**
- **Mendukung rate limiting global dengan parameter `--delay/-d` untuk mencegah website target tumbang**

## 📁 **Struktur Project**

```
main_scanner.py              # Aplikasi scanner utama
vuln_plugins/                # Folder berisi semua plugin kerentanan (16+ plugin)
├── xss.py                  # Cross-Site Scripting (XSS)
├── sqli.py                 # SQL Injection
├── lfi_rfi.py              # Local/Remote File Inclusion
├── csrf.py                 # Cross-Site Request Forgery
├── ssrf.py                 # Server-Side Request Forgery
├── xxe.py                  # XML External Entity
├── directory_traversal.py  # Directory Traversal
├── open_redirect.py        # Open Redirect
├── nosqli.py               # NoSQL Injection
├── auth_bypass.py          # Authentication Bypass
├── command_injection.py    # Command Injection
├── security_headers.py     # Security Headers Audit
├── sensitive_data_exposure.py # Sensitive Data Exposure
├── subdomain_enumeration.py   # Subdomain Enumeration
├── idor.py                 # Insecure Direct Object Reference
├── file_upload.py          # Insecure File Upload
└── ... (plugin lain dapat ditambah)
requirements_unified.txt    # Dependencies Python
README.md                   # Dokumentasi ini
```

## 🔍 **Plugin Kerentanan yang Tersedia (16 Plugin)**

### **Kerentanan Injection & Code Execution:**

1. **Cross-Site Scripting (XSS)** - Deteksi XSS reflected melalui form input
2. **SQL Injection** - Deteksi SQL injection dengan error-based detection
3. **NoSQL Injection** - Deteksi kerentanan NoSQL injection (MongoDB, dll)
4. **Command Injection** - Deteksi OS command injection (Linux/Windows)
5. **XML External Entity (XXE)** - Deteksi XXE melalui XML input

### **Kerentanan File & Path:**

6. **Local File Inclusion (LFI)** - Deteksi LFI vulnerabilities
7. **Remote File Inclusion (RFI)** - Deteksi RFI vulnerabilities
8. **Directory Traversal** - Deteksi path traversal vulnerabilities
9. **Insecure File Upload** - Deteksi file upload vulnerabilities

### **Kerentanan Authentication & Authorization:**

10. **Authentication Bypass** - Deteksi bypass login dan default credentials
11. **Insecure Direct Object Reference (IDOR)** - Deteksi horizontal privilege escalation

### **Kerentanan Server-Side:**

12. **Cross-Site Request Forgery (CSRF)** - Deteksi form tanpa CSRF protection
13. **Server-Side Request Forgery (SSRF)** - Deteksi SSRF melalui URL parameters
14. **Open Redirect** - Deteksi unvalidated redirects

### **Kerentanan Information Disclosure:**

15. **Security Headers Audit** - Audit missing/weak security headers
16. **Sensitive Data Exposure** - Deteksi sensitive data dalam response
17. **Subdomain Enumeration** - Discovery subdomain dan DNS records

## 🚀 **Instalasi**

1. **Clone atau download project:**

   ```bash
   git clone <repository-url>
   cd security
   ```
2. **Install dependencies:**

   ```bash
   pip install -r requirements_unified.txt
   ```
3. **Jalankan scanner:**

   ```bash
   python main_scanner.py https://example.com
   ```

## 📖 **Cara Penggunaan**

### **Penggunaan Dasar (semua plugin):**

```bash
python main_scanner.py https://example.com
```

### **Menjalankan Plugin Tertentu Saja:**

```bash
# Hanya plugin XSS
python main_scanner.py https://example.com -p xss

# Hanya plugin XSS dan SQLi
python main_scanner.py https://example.com -p xss,sqli

# Kombinasi plugin injection
python main_scanner.py https://example.com -p xss,sqli,nosqli,command_injection

# Kombinasi plugin authentication
python main_scanner.py https://example.com -p auth_bypass,idor

# Kombinasi plugin information disclosure
python main_scanner.py https://example.com -p security_headers,sensitive_data_exposure,subdomain_enumeration
```

### **Rate Limiting (Delay Antar Request)**

Untuk mencegah website target tumbang, gunakan parameter `--delay` (atau `-d`) untuk mengatur jeda antar request (dalam detik).

- **Default:** 0.2 detik (200ms)
- **Contoh penggunaan:**

```bash
# Scan dengan delay default (0.2 detik)
python main_scanner.py https://example.com

# Scan dengan delay 1 detik antar request
python main_scanner.py https://example.com --delay 1

# Scan plugin tertentu dengan delay 0.5 detik
python main_scanner.py https://example.com -p xss,sqli --delay 0.5
```

**Best Practice:**

- Gunakan delay lebih besar (misal 1 detik) untuk website produksi atau website yang resource-nya terbatas.
- Jika website mulai lambat/timeout, tingkatkan delay.
- Jangan gunakan delay terlalu kecil pada website yang bukan milik sendiri.

### **Kombinasi dengan Report PDF:**

```bash
# Scan semua plugin + generate PDF
python main_scanner.py https://example.com -r

# Scan plugin tertentu + generate PDF
python main_scanner.py https://example.com -p xss,sqli,csrf -r

# Scan dengan timeout kustom + generate PDF
python main_scanner.py https://example.com --timeout 60 -p xss,sqli -r
```

### **Parameter yang Tersedia:**

- `target` - URL target untuk di-scan (wajib)
- `--timeout` - Timeout request dalam detik (default: 30)
- `-r, --report` - Generate report PDF dari hasil scan
- `-p, --plugin` - Jalankan plugin tertentu saja (pisahkan dengan koma)
- `-d, --delay` - Delay (detik) antar request ke target (default: 0.2)

### **Contoh Output:**

```
[INFO] Loading plugins from: vuln_plugins
[INFO] Running plugin: xss.py
[PLUGIN] Scanning for XSS vulnerabilities...
[INFO] Running plugin: sqli.py
[PLUGIN] Scanning for SQL Injection vulnerabilities...
[INFO] Running plugin: auth_bypass.py
[PLUGIN] Scanning for Authentication Bypass vulnerabilities...
[INFO] Running plugin: security_headers.py
[PLUGIN] Scanning for Security Headers vulnerabilities...

[SUMMARY] Kerentanan yang ditemukan:
- [High] Cross-Site Scripting (XSS): XSS vulnerability detected in parameter search
- [Critical] SQL Injection: SQL injection vulnerability detected in parameter id
- [Medium] Missing Security Header: Missing HSTS header
- [Info] Subdomain Discovery: Subdomain found: admin.example.com

[SUCCESS] Report PDF berhasil dibuat: vulnerability_scan_report_20241215_143025.pdf
[INFO] Report PDF telah dibuat untuk analisis lebih lanjut.
```

## 📄 **Fitur Report PDF**

Scanner ini mendukung pembuatan report dalam format PDF yang berisi:

- **Informasi Pemindaian** (target, waktu, durasi, total kerentanan)
- **Ringkasan Kerentanan** (berdasarkan tingkat keparahan)
- **Detail Kerentanan** (deskripsi lengkap dengan bukti)
- **Rekomendasi Keamanan** (saran perbaikan)
- **Format profesional** (A4, tabel berwarna, timestamp)

### **Cara Menggunakan:**

```bash
python main_scanner.py https://example.com -r
```

### **Lokasi File Report:**

File PDF akan disimpan di folder `reports/` dengan format nama: `vulnerability_scan_report_YYYYMMDD_HHMMSS.pdf`

## 🛠️ **Panduan Pengembangan: Menambah Plugin Kerentanan Baru**

### **Langkah 1: Buat File Plugin Baru**

```bash
touch vuln_plugins/nama_kerentanan.py
```

### **Langkah 2: Implementasikan Plugin**

```python
def scan(scanner):
    """Scan untuk kerentanan [Nama Kerentanan]"""
    print("[PLUGIN] Scanning for [Nama Kerentanan] vulnerabilities...")
  
    try:
        # Logika deteksi kerentanan Anda di sini
        # Contoh: Test untuk kerentanan tertentu
      
        # Jika kerentanan ditemukan:
        scanner.log_vulnerability(
            'Nama Kerentanan',
            'Severity',  # Critical, High, Medium, Low, Info
            'Deskripsi kerentanan',
            'Bukti kerentanan',
            'CWE-xxx'
        )
      
    except Exception as e:
        print(f"[PLUGIN][Nama Kerentanan] Error: {e}")
```

### **Langkah 3: Test Plugin**

```bash
python main_scanner.py https://example.com -p nama_kerentanan
```

### **Method Scanner yang Tersedia:**

- `scanner.target_url` - URL target untuk di-scan
- `scanner.session` - Objek session requests (sudah otomatis rate limited)
- `scanner.timeout` - Timeout request
- `scanner.log_vulnerability(type, severity, description, evidence, cwe)` - Log kerentanan
- `scanner.urllib` - Modul urllib untuk manipulasi URL
- `scanner.re` - Modul re untuk operasi regex
- `scanner.urljoin` - Fungsi urljoin untuk menggabungkan URL

## 🔧 **Best Practices Pengembangan Plugin**

### **1. Penanganan Error**

```python
try:
    # Logika scanning Anda
    pass
except Exception as e:
    print(f"[PLUGIN][YourPlugin] Error: {e}")
```

### **2. Rate Limiting**

```python
# Tidak perlu implementasi manual, sudah otomatis di session
```

### **3. Payload Aman**

```python
# Baik: Payload test yang aman
payloads = ['test', '{{7*7}}', 'admin\'--']

# Buruk: Payload yang merusak
payloads = ['DROP TABLE users', 'rm -rf /']
```

### **4. Bukti yang Jelas**

```python
scanner.log_vulnerability(
    'XSS',
    'High',
    'XSS vulnerability detected',
    f'Payload: {payload}, Response contains: {response.text[:100]}',
    'CWE-79'
)
```

## 🚨 **Pertimbangan Keamanan**

⚠️ **Peringatan Penting:**

- **Kepatuhan Hukum**: Hanya scan website yang Anda miliki atau memiliki izin eksplisit
- **Rate Limiting**: Hormati server target dan implementasikan delay yang sesuai
- **False Positives**: Verifikasi manual direkomendasikan untuk temuan kritis
- **Testing Aman**: Gunakan payload yang tidak merusak di plugin Anda
- **Penanganan Error**: Selalu tangani exception dengan baik

## 📦 **Dependencies**

- **requests** - HTTP library untuk web requests
- **beautifulsoup4** - HTML parsing
- **urllib3** - HTTP client library
- **dnspython** - DNS resolution (untuk subdomain enumeration)
- **python-nmap** - Port scanning (jika diperlukan)
- **reportlab** - Generate report PDF
- **lxml** - XML parsing (untuk XXE detection)

## 🤝 **Kontribusi**

Untuk berkontribusi plugin kerentanan baru:

1. Buat file Python baru di `vuln_plugins/`
2. Implementasikan fungsi `scan(scanner)`
3. Ikuti persyaratan interface plugin
4. Test plugin Anda secara menyeluruh
5. Dokumentasikan plugin Anda di README ini

## 📄 **Lisensi & Disclaimer**

Project ini untuk tujuan pendidikan dan testing keamanan yang diizinkan saja. Pengguna bertanggung jawab untuk memastikan mereka memiliki otorisasi yang tepat sebelum memindai sistem apapun.

**⚠️ Disclaimer:**
Tool ini disediakan apa adanya untuk tujuan pendidikan. Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang disebabkan oleh tool ini. Selalu pastikan Anda memiliki otorisasi yang tepat sebelum melakukan penilaian keamanan.

## 🎯 **Roadmap**

Fitur yang direncanakan untuk versi mendatang:

- Plugin untuk GraphQL vulnerabilities
- Plugin untuk JWT vulnerabilities
- Plugin untuk API security testing
- Plugin untuk WebSocket vulnerabilities
- Plugin untuk rate limiting bypass
- Plugin untuk business logic flaws
- Plugin untuk template injection
- Plugin untuk HTTP request smuggling
