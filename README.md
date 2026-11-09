# GenCheckSocksGT

CLI untuk mengecek apakah sebuah proxy SOCKS5 benar-benar bisa dipakai untuk Growtopia, lalu menghasilkan file berisi proxy yang lolos.

Tool ini **tidak** terintegrasi dengan NitesProxy. Tidak ada API apply/control, tidak menulis config NitesProxy, dan tidak mengubah project lain. Proxy yang lolos dipakai manual.

## Yang dicek

Untuk setiap endpoint:

1. TCP connect ke proxy.
2. SOCKS5 greeting dan pemilihan metode auth.
3. Auth username/password (jika diperlukan).
4. SOCKS5 `CONNECT` ke `www.growtopia2.com:443` (fallback ke `www.growtopia1.com`).
5. TLS + HTTP `POST /growtopia/server_data.php` dengan body dan User-Agent yang sama seperti client Growtopia.
6. HTTP ke `login.growtopiagame.com`.
7. SOCKS5 `UDP ASSOCIATE` + DNS query nyata lewat relay UDP.
8. Exit IP check, dua kali untuk melihat apakah exit IP sticky atau rotating.

Proxy dianggap **USABLE** kalau HTTP Growtopia OK, login host OK, UDP OK, dan exit IP stabil.

> Catatan: UDP dan sticky check bisa dimatikan. `gen --allow-no-udp` menerima proxy TCP-only, `gen --allow-rotating` menerima proxy yang exit IP-nya berubah.

## Build

Butuh Rust stable (edition 2024).

```bash
cargo build --release
```

Binary ada di:

```text
target/release/gencheck.exe
```

## Quick start

Normalisasi list:

```bash
gencheck fmt -i proxies.txt -o normalized.txt
```

Cek semua proxy dan tampilkan tabel:

```bash
gencheck check -i proxies.txt
```

Buat file proxy yang benar-benar bisa dipakai:

```bash
gencheck gen -i proxies.txt -o working.txt
```

Cek satu proxy dengan trace SOCKS5 lengkap:

```bash
gencheck test "host:port:user:pass"
```

## Format input

Semua format berikut diterima dan bisa dicampur dalam satu file:

```text
host:port:user:pass
host|port|user|pass
host:port
user:pass@host:port
socks5://user:pass@host:port
socks5h://user:pass@host:port
```

Detail:

- Password boleh mengandung `:` pada format colon, karena field password mengambil sisa baris.
- Password boleh mengandung `|` pada format pipe, karena field password mengambil sisa baris.
- IPv6 memakai bracket pada format colon: `[2001:db8::1]:1080:user:pass`.
- Baris kosong dan baris yang diawali `#` diabaikan.
- Duplikat dihapus otomatis (kecuali `fmt --no-unique`).
- `socks4://` dan URL `http://`/`https://` ditolak dengan pesan yang jelas.

## Format output

`fmt` dan `gen` mendukung:

```bash
--format colon   # host:port:user:pass
--format pipe    # host|port|user|pass
```

Contoh:

```bash
gencheck gen -i proxies.txt -o working.txt --format pipe
gencheck fmt -i working.txt --format colon
```

## Perintah

### `fmt`

```bash
gencheck fmt -i proxies.txt -o normalized.txt --format colon
```

- Input bisa dari stdin: `gencheck fmt < proxies.txt` atau `gencheck fmt -i - < proxies.txt`.
- `--no-unique` mempertahankan duplikat.
- `--strict` membuat baris invalid menjadi error, bukan warning.

### `check`

```bash
gencheck check -i proxies.txt
gencheck check -i proxies.txt --out results.json --csv results.csv
gencheck check -i proxies.txt --fast
```

Default `check` menjalankan pengecekan lengkap: HTTP + login + UDP + sticky.

Flag:

```text
--skip-udp        lewati UDP ASSOCIATE
--skip-sticky     lewati pengecekan exit IP dua kali
--skip-exit-ip    lewati exit IP lookup (sticky otomatis mati)
--fast            HTTP + login saja
--concurrency N   jumlah proxy paralel, default 16
--timeout N       timeout per operasi, default 15 detik
--total-timeout N timeout total per endpoint, default 120 detik
--trace           sertakan trace SOCKS5 di JSON
```

Output:

- Tabel di stdout. Password dimasking menjadi `***`.
- `--out results.json` menyimpan report lengkap. Password **tidak** disertakan di JSON.
- `--csv results.csv` menyimpan CSV datar. Password juga tidak disertakan.

### `gen`

```bash
gencheck gen -i proxies.txt -o working.txt
gencheck gen -i proxies.txt -o working.txt --format pipe --top 10
gencheck gen -i proxies.txt -o working.txt --allow-no-udp
gencheck gen -i proxies.txt -o working.txt --allow-rotating
gencheck gen -i proxies.txt -o working.txt --details results.json
```

Default:

- Hanya proxy berstatus `USABLE` yang ditulis.
- UDP wajib OK.
- Exit IP wajib sticky.
- `working.txt` berisi kredensial plaintext supaya bisa langsung dipakai.
- stdout menampilkan daftar password yang dimasking; file berisi versi lengkap.

`--top N` mengambil N proxy tercepat. `--details` menyimpan report JSON lengkap untuk semua proxy, termasuk yang gagal.

### `test`

```bash
gencheck test "host:port:user:pass"
gencheck test "host|port|user|pass" --json
gencheck test "socks5://user:pass@host:port" --fast
```

`test` selalu menampilkan trace SOCKS5:

- hasil resolve proxy dan IP yang dipakai,
- isi greeting,
- metode auth yang dipilih proxy,
- status auth,
- reply code `CONNECT`/`UDP ASSOCIATE`,
- preview bytes mentah kalau proxy ternyata bukan SOCKS5,
- daftar event dan timing.

Ini cara tercepat untuk mendiagnosis error seperti `SOCKS error: failed parsing server response`.

## Arti status

| Status | Arti |
|---|---|
| `USABLE` | Semua stage yang diwajibkan lolos. |
| `HTTP_ONLY` | HTTP Growtopia dan login OK, tapi UDP atau sticky gagal. Lihat kolom UDP/Sticky. |
| `BLOCKED` | `server_data.php` membalas 401/403. Exit IP kemungkinan ditolak Growtopia. |
| `NOT_SOCKS5` | Endpoint membalas sesuatu yang bukan SOCKS5, misalnya `HTTP/1.1 ...`. Biasanya ini port HTTP proxy, bukan port SOCKS5. |
| `SOCKS_AUTH_FAILED` | Username/password salah, atau parameter username kurang lengkap. |
| `SOCKS_NO_AUTH_METHOD` | Proxy menolak semua metode auth yang ditawarkan. |
| `SOCKS_CONNECT_FAILED` | Proxy menerima handshake tapi gagal `CONNECT` ke target. Reply code SOCKS5 ikut ditampilkan. |
| `SOCKS_BAD_REPLY` | Balasan SOCKS5 tidak valid/terpotong. |
| `TCP_FAILED` | Tidak bisa TCP connect ke endpoint proxy. |
| `DNS_FAILED` | Hostname proxy tidak bisa di-resolve. |
| `TIMEOUT` | Operasi atau total check melewati batas waktu. |
| `TLS_FAILED` | TLS handshake ke host Growtopia gagal. |
| `HTTP_FAILED` | Request HTTP gagal atau status tidak diharapkan. |
| `BAD_SERVER_DATA` | HTTP 200, tapi body tidak berisi `server|`/`port|` yang valid. |
| `LOGIN_FAILED` | `login.growtopiagame.com` tidak bisa diakses atau menolak exit IP. |

Status stage:

| Stage | Arti |
|---|---|
| `OK` | Stage lolos. |
| `SKIPPED` | Stage dimatikan lewat flag. |
| `UNSUPPORTED` | Proxy tidak mendukung `UDP ASSOCIATE`. |
| `ROTATING` | Exit IP berubah antara dua request. |
| `UNKNOWN` | Stage tidak bisa disimpulkan, misalnya exit IP lookup gagal. |

## Troubleshooting FloppyData

Beberapa hal yang sering terjadi:

1. **Port HTTP vs SOCKS5.** Contoh dokumentasi FloppyData memakai `geo.floppydata.com:10080` untuk HTTP proxy dan port lain (misalnya `10800`) untuk SOCKS5. Kalau `gencheck test` menghasilkan `NOT_SOCKS5` dengan preview `HTTP/1.1 ...`, berarti yang dicek adalah port HTTP.
2. **Gunakan `connectionString` dari response API.** Jangan merangkai sendiri kalau API sudah mengembalikan string koneksi lengkap.
3. **Username harus lengkap.** Username SOCKS5 kadang bukan username dasar, tetapi parameter lengkap seperti `type-residential-session-...-rotation-0-udp-1`. Username yang terpotong biasanya menghasilkan `SOCKS_AUTH_FAILED`.
4. **Cek UDP terpisah.** Kalau HTTP lolos tapi UDP gagal, statusnya `HTTP_ONLY`. Gunakan `gencheck test ...` dan lihat stage UDP.
5. **Sticky vs rotating.** Kalau exit IP berubah, statusnya `HTTP_ONLY` dan stage Sticky `ROTATING`. Gunakan `--allow-rotating` hanya kalau memang tidak butuh IP stabil.

Contoh diagnosis:

```bash
gencheck test "geo.floppydata.com:10080:user:pass"
gencheck test "geo.floppydata.com:10800:user:pass"
```

## Batasan

`USABLE` berarti proxy lolos prerequisite yang dicek tool ini. Tool tidak membuka koneksi ENet/gameplay ke server Growtopia yang sebenarnya; IP dan port server game hanya ditampilkan untuk verifikasi manual. UDP yang diuji adalah `UDP ASSOCIATE` + DNS lewat relay, bukan koneksi ke server game.

## Keamanan

- `working.txt`, output `fmt`, dan output `gen` berisi kredensial **plaintext**.
- Jangan commit file tersebut ke git.
- `results.json` dan CSV tidak menyertakan password.
- Tabel console dan output `test` memasking password.
- Tool ini hanya melakukan koneksi keluar ke proxy dan host Growtopia/Cloudflare/ipify. Tidak ada telemetry.

## Exit code

| Code | Arti |
|---|---|
| `0` | Ada minimal satu proxy `USABLE` (`check`/`gen`/`test`), atau command sukses (`fmt`). |
| `1` | Tidak ada proxy `USABLE`, atau `gen` tidak menghasilkan baris. |
| `2` | Error input/IO/fatal. |

## Test

```bash
cargo test
```

Unit test mencakup parser, SOCKS5 target encoding, preview formatting, DNS query, parsing `server_data.php`, dan mock SOCKS5 server untuk kasus HTTP proxy, auth failure, dan CONNECT sukses.
