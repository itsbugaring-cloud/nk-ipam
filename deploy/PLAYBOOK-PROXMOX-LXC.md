# Proxmox / LXC Rollout Playbook

Dokumen ini dipakai untuk rollout staging pertama di LXC/VM yang sudah punya route ke WireGuard.

## 1. Prasyarat Host

- Host sudah bisa reach IP WireGuard router MikroTik.
- Docker dan Docker Compose Plugin sudah terpasang.
- Port `8080` diizinkan dari jaringan admin yang relevan.
- Folder kerja disiapkan di `/opt/netking-ipam`.

## 2. Validasi WireGuard Sebelum Deploy

Uji dari host LXC/VM:

```bash
ping 10.10.50.1
curl -k -u 'admin:secret' https://10.10.50.1/rest/ip/pool
curl -k -u 'admin:secret' https://10.10.50.1/rest/ip/route
```

Kalau tiga tes ini gagal, hentikan rollout dan perbaiki routing/tunnel lebih dulu.

## 3. Ambil Kode

```bash
cd /opt
git clone https://github.com/itsbugaring-cloud/nk-ipam.git netking-ipam
cd /opt/netking-ipam
```

Kalau repo sudah ada:

```bash
cd /opt/netking-ipam
git pull origin main
```

## 4. Siapkan Environment

```bash
cp .env.production.example .env
nano .env
```

Minimum yang wajib diisi:

- `APP_ADMIN_USERNAME`
- `APP_ADMIN_PASSWORD`
- `APP_SESSION_TOKEN`
- `APP_CRYPTO_KEY`
- `MIKROTIK_USERNAME` dan `MIKROTIK_PASSWORD` jika ingin default global

Kalau tiap router beda kredensial, `MIKROTIK_USERNAME` dan `MIKROTIK_PASSWORD` boleh dikosongkan.
`SCAN_COOLDOWN_SECS` bisa dibiarkan default 20 detik untuk mencegah scan beruntun ke router yang sama.

## 5. Jalankan Aplikasi

```bash
mkdir -p /opt/netking-ipam/data
docker compose up --build -d
docker compose ps
docker compose logs -f
```

## 6. Smoke Test Backend

```bash
curl http://127.0.0.1:8080/api/health
```

Respons minimal yang diharapkan:

```json
{
  "status": "ok",
  "database": "ok",
  "default_credentials": true,
  "auth_enabled": true
}
```

## 7. Login Dashboard

1. Buka `http://IP-LXC:8080`
2. Login dengan `APP_ADMIN_USERNAME` dan `APP_ADMIN_PASSWORD`
3. Pastikan badge auth berubah menjadi aktif

## 8. Uji Alur Fungsional

### Import Bookmark

1. Upload `bookmarks.html`
2. Pastikan muncul pesan sukses
3. Cek panel `Audit Activity`

### Single Scan

1. Input 1 IP WireGuard router
2. Tambahkan kredensial per-router jika perlu
3. Verifikasi:
   - status koneksi
   - IP pool tampil
   - OLT mapping otomatis jika cocok

### Manual Mapping

1. Pilih OLT dari dropdown di kolom aksi
2. Klik `Simpan Mapping`
3. Pastikan label `manual` muncul pada kolom mapping

### Detail Router

1. Klik `Detail`
2. Pastikan daftar `IP Pools` dan `Routes` tampil
3. Cocokkan `mapping_source` apakah `auto_route`, `auto_pool`, `manual`, atau `unmapped`

### Bulk Scan

1. Isi 3-5 router
2. Gunakan format `ip|nama|username|password` bila perlu
3. Cek success/failure counter
4. Cek audit log

### Export

1. Gunakan search
2. Uji `Export CSV`, `Export to Excel`, dan `Export to PDF`
3. Pastikan data export mengikuti filter aktif

## 9. Validasi Data dan Mapping

Checklist:

- Nama router benar
- IP WireGuard benar
- OLT hasil auto-map sesuai ekspektasi
- Manual override tersimpan
- Error router gagal terlihat jelas

## 10. Aktifkan systemd Untuk Auto Start

```bash
cp deploy/systemd/netking-ipam.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netking-ipam.service
systemctl status netking-ipam.service
```

## 11. Aktifkan Backup Harian

```bash
chmod +x /opt/netking-ipam/deploy/scripts/backup-sqlite.sh
cp deploy/systemd/netking-ipam-backup.service /etc/systemd/system/
cp deploy/systemd/netking-ipam-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now netking-ipam-backup.timer
systemctl list-timers | grep netking-ipam-backup
```

## 12. Troubleshooting Cepat

### Dashboard tidak bisa login

- Cek `APP_ADMIN_USERNAME`, `APP_ADMIN_PASSWORD`, `APP_SESSION_TOKEN`
- Pastikan container direstart setelah env berubah

### Scan router gagal

- Uji `curl -k` langsung ke IP WireGuard router
- Cek kredensial
- Cek REST API RouterOS v7 aktif

### Mapping OLT tidak cocok

- Cek `bookmarks.html` benar
- Lihat apakah `route dst-address` atau `ip pool ranges` memang mengandung IP OLT
- Gunakan manual mapping sebagai override

### Export CSV gagal

- Pastikan login masih aktif
- Coba refresh halaman lalu login ulang

## 13. Kriteria Lolos Staging

Staging dianggap layak lanjut bila:

- Healthcheck `ok`
- Login dashboard stabil
- Import bookmark sukses
- Single scan sukses pada minimal 2 router
- Bulk scan sukses pada minimal 5 router
- Manual mapping bekerja
- Export CSV/XLSX/PDF bekerja
- Backup timer aktif
