# Netking IPAM & Network Inventory Explorer

Dashboard ringan untuk sinkronisasi data OLT dari `bookmarks.html`, menarik IP pool MikroTik lewat RouterOS v7 REST API pada IP WireGuard, lalu memetakan router ke OLT secara otomatis tanpa network scanning.

## Fitur Saat Ini

- Import OLT dari file export bookmark browser.
- Scan single router berdasarkan IP WireGuard.
- Bulk scan banyak router sekaligus.
- Kredensial MikroTik bisa global via environment atau override per-router saat scan.
- Auto-mapping OLT berdasarkan kecocokan `route dst-address` dan `ip pool ranges`.
- Manual override mapping OLT dan rescan per-router dari dashboard.
- Explorer table dengan live search dan export Excel/PDF/CSV.
- Login ringan berbasis bearer token env untuk staging.
- Audit log 100 aksi terakhir via API.
- Packaging Docker multi-stage dan contoh deploy LXC/Proxmox.
- Workflow CI GitHub Actions untuk format, test, dan build.

## Arsitektur Ringkas

- Backend: Rust + Axum + Tokio
- Database: SQLite + sqlx
- Integrasi MikroTik: RouterOS v7 REST API via `reqwest`
- Frontend: HTML + Vanilla JS + Tailwind CDN

## Environment

Salin `.env.example` menjadi `.env`.

```env
APP_HOST=0.0.0.0
APP_PORT=8080
DATABASE_URL=sqlite://data/netking.db
APP_ADMIN_USERNAME=admin
APP_ADMIN_PASSWORD=change-me-admin
APP_SESSION_TOKEN=replace-with-long-random-token
MIKROTIK_USERNAME=admin
MIKROTIK_PASSWORD=change-me
MIKROTIK_ALLOW_INSECURE_TLS=true
MIKROTIK_REQUEST_TIMEOUT_SECS=20
MAX_SCAN_CONCURRENCY=8
```

Catatan:

- Jika `MIKROTIK_USERNAME` dan `MIKROTIK_PASSWORD` tidak diisi, user wajib mengisi kredensial per-router dari UI atau payload API.
- Jika `APP_ADMIN_USERNAME`, `APP_ADMIN_PASSWORD`, dan `APP_SESSION_TOKEN` diisi, dashboard akan meminta login dan seluruh endpoint API selain health/login akan diproteksi bearer token.
- Untuk staging awal, password router masih disimpan di SQLite bila diinput per-router. Ini pragmatis untuk operasional cepat, tetapi untuk produksi sebaiknya dipindah ke secret store atau dienkripsi.

## Menjalankan Dengan Docker Compose

```bash
cp .env.example .env
mkdir -p data
docker compose up --build -d
docker compose logs -f
```

Setelah hidup:

- UI: `http://HOST:8080`
- Healthcheck: `http://HOST:8080/api/health`

## Pengujian Konektivitas Sebelum Aplikasi

Pastikan host staging memang bisa menjangkau IP WireGuard router:

```bash
ping 10.10.50.1
curl -k -u 'admin:secret' https://10.10.50.1/rest/ip/pool
curl -k -u 'admin:secret' https://10.10.50.1/rest/ip/route
```

Kalau `curl` gagal, aplikasi juga akan gagal.

## Workflow Staging yang Disarankan

1. Deploy di LXC/VM yang sudah punya route ke WireGuard.
2. Import `bookmarks.html`.
3. Uji single scan ke 1 router.
4. Validasi hasil auto-mapping OLT.
5. Uji bulk scan 3-5 router.
6. Lihat status error dan kecocokan pool/routing.
7. Setelah aman, baru naikkan volume scan.

## API Ringkas

### `GET /api/health`

```json
{
  "status": "ok",
  "database": "ok",
  "default_credentials": true,
  "auth_enabled": true
}
```

### `POST /api/auth/login`

```json
{
  "username": "admin",
  "password": "change-me-admin"
}
```

### `POST /api/bookmarks/import`

Multipart form-data dengan field `file`.

### `POST /api/routers/scan`

```json
{
  "wireguard_ip": "10.10.50.1",
  "device_name": "MK-JKT-01",
  "username": "admin",
  "password": "secret"
}
```

### `POST /api/routers/bulk-scan`

```json
{
  "routers": [
    {
      "wireguard_ip": "10.10.50.1",
      "device_name": "MK-JKT-01"
    },
    {
      "wireguard_ip": "10.10.50.2",
      "device_name": "MK-BDG-01",
      "username": "admin",
      "password": "secret"
    }
  ]
}
```

## Proxmox / LXC

### Build image

```bash
docker build -t netking-ipam:latest .
```

### Jalankan container

```bash
mkdir -p /opt/netking-ipam/data
cp .env.example /opt/netking-ipam/.env
docker run -d \
  --name netking-ipam \
  --restart unless-stopped \
  --env-file /opt/netking-ipam/.env \
  -v /opt/netking-ipam/data:/app/data \
  -p 8080:8080 \
  netking-ipam:latest
```

### Menjalankan via systemd

Contoh unit file ada di `deploy/systemd/netking-ipam.service`.

## Reverse Proxy

Contoh konfigurasi Nginx untuk staging ada di `deploy/nginx/netking-ipam.conf`.

## Backup SQLite

Minimal lakukan backup direktori `data/` secara berkala:

```bash
sqlite3 /opt/netking-ipam/data/netking.db ".backup /opt/netking-ipam/data/netking-$(date +%F).db"
```

Atau gunakan script helper:

```bash
chmod +x deploy/scripts/backup-sqlite.sh
./deploy/scripts/backup-sqlite.sh /opt/netking-ipam/data/netking.db /opt/netking-ipam/data/backups
```

## Yang Masih Perlu Sebelum Production

- Enkripsi atau external secret store untuk password per-router.
- Metrics/alerting yang lebih formal.
- CI build/test image.
- Validasi respons real RouterOS dari seluruh varian router Anda.
