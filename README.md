# 🛠️ Deskripsi Tools

### Tools ini bernama **Digital Forensic Tools for Phishing Website Analysis v2.0**. Ini adalah skrip Python yang dikembangkan oleh seorang Digital Forensic Specialist untuk melakukan analisis forensik digital terhadap domain atau situs yang dicurigai sebagai phishing.

Tools ini menyediakan berbagai macam modul dan fungsi analisis, baik secara aktif maupun pasif, terhadap target domain yang mencakup:
- WHOIS Lookup
- DNS record analysis
- IP Geolocation
- SSL Certificate inspection
- Wayback Machine check
- Google cache check
- Shodan lookup
- Subdomain enumeration
- Reverse DNS lookup
- HTTP headers analysis
- Passive DNS history
- Certificate transparency logs
- Threat intelligence & reputation checks
- Search engine dorking
- Social media threat intel

---

# 🎯 Tujuan Dibuatnya Tools Ini

- **Mendeteksi dan menganalisis website phishing**  
  Tools ini membantu analis siber atau investigator forensik untuk mengumpulkan bukti teknis tentang situs phishing melalui berbagai pendekatan OSINT dan protokol jaringan.

- **Menyediakan laporan lengkap dan terstruktur**  
  Setelah analisis, tools ini dapat menghasilkan laporan forensik dalam format JSON yang bisa digunakan sebagai dokumentasi atau bukti investigasi.

- **Mendukung kegiatan respons insiden siber**  
  Dengan informasi seperti subdomain aktif, lokasi IP, riwayat DNS, dan keberadaan di cache/arsip, tools ini memperkuat investigasi saat insiden keamanan terjadi.

- **Membantu penegakan hukum dan dokumentasi**  
  Fitur seperti certificate transparency logs dan Wayback Machine snapshot sangat berguna dalam pelacakan infrastruktur dan pelaporan legal.

- **Memberikan rekomendasi keamanan**  
  Tools ini juga menyertakan rekomendasi langkah lanjutan berdasarkan hasil analisis untuk membantu proses mitigasi.

---

# ⚙️ Instalasi

## 1. Install Dependencies:

```bash
pip install requests dnspython python-whois beautifulsoup4

```


## 2. Penggunaan:

```bash
python forensic_tools.py domain --output report.json

```

## 3. Menggunakan API KEY Shodan
```bash
python3 forensik_update.py domain --shodan-key --output hasil.json

```

## 4. Butuh Bantuan?
```bash
python3 forensik_update.py --help

```
