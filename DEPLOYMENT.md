# Hướng dẫn triển khai DMS Production

Tài liệu này hướng dẫn triển khai đầy đủ từ đầu trên 1 máy chủ Linux
(Ubuntu/Debian — các lệnh cài gói có thể khác đôi chút trên CentOS/RHEL).
Đọc theo đúng thứ tự nếu là lần triển khai đầu tiên; nếu chỉ cần cập nhật
code mới, xem thẳng mục **"Cập nhật lên bản mới"**.

## Mục lục

1. [Tổng quan kiến trúc](#1-tổng-quan-kiến-trúc)
2. [Yêu cầu hệ thống](#2-yêu-cầu-hệ-thống)
3. [Cài Node.js, MariaDB, Nginx](#3-cài-nodejs-mariadb-nginx)
4. [Tạo cơ sở dữ liệu](#4-tạo-cơ-sở-dữ-liệu)
5. [Lấy mã nguồn + cấu hình `.env`](#5-lấy-mã-nguồn--cấu-hình-env)
6. [Tạo tài khoản hệ thống riêng (bảo mật)](#6-tạo-tài-khoản-hệ-thống-riêng-bảo-mật)
7. [Cài dependencies + build](#7-cài-dependencies--build)
8. [Cluster nhiều worker](#8-cluster-nhiều-worker)
9. [Cài đặt systemd service](#9-cài-đặt-systemd-service)
10. [Nginx reverse proxy + HTTPS](#10-nginx-reverse-proxy--https)
11. [Tường lửa](#11-tường-lửa)
12. [Vận hành hàng ngày](#12-vận-hành-hàng-ngày)
13. [Cập nhật lên bản mới](#13-cập-nhật-lên-bản-mới)
14. [Sao lưu (backup)](#14-sao-lưu-backup)
15. [Xử lý sự cố thường gặp](#15-xử-lý-sự-cố-thường-gặp)
16. [Bảng biến môi trường (`.env`)](#16-bảng-biến-môi-trường-env)

---

## 1. Tổng quan kiến trúc

```
Người dùng (trình duyệt)
        │  HTTPS (443)
        ▼
      Nginx  ──── chứng chỉ TLS (Let's Encrypt), nén, giới hạn kích thước upload
        │  HTTP nội bộ (127.0.0.1:3000)
        ▼
 ┌──────────────────────────────────────────┐
 │  systemd: dms-prod.service                │
 │  Tiến trình CHÍNH (primary, PID cố định)  │  ← chỉ giám sát worker + chạy
 │    ├── Worker #1 ─┐                       │    tác vụ định kỳ (đồng bộ AD,
 │    ├── Worker #2 ─┼─ cùng lắng nghe :3000  │    nhắc hạn CNTT), KHÔNG nhận
 │    └── Worker #N ─┘  (chia tải round-robin│    request HTTP trực tiếp
 │        do Node cluster tự làm)            │
 │  Chạy bằng tài khoản hệ thống "dms"       │  ← không phải root, không login được
 └──────────────────────────────────────────┘
        │
        ▼
     MariaDB (CSDL) + thư mục uploads/ (file PDF trên đĩa)
```

Vài điểm cần nhớ:
- Chỉ Nginx mở ra internet (cổng 443). Ứng dụng Node chỉ lắng nghe ở
  `127.0.0.1`, không ai truy cập thẳng được từ bên ngoài.
- Nhiều **worker** (tiến trình Node con) dùng chung 1 cổng nhờ module
  `cluster` có sẵn của Node — tận dụng nhiều lõi CPU, worker nào crash sẽ
  tự được khởi động lại mà không ảnh hưởng các worker còn lại.
- Ứng dụng chạy bằng tài khoản hệ thống riêng (`dms`), không phải `root`
  và không đăng nhập/SSH được — giảm thiệt hại nếu có lỗ hổng bị khai thác.

## 2. Yêu cầu hệ thống

- Node.js **20.x LTS trở lên** (khuyến nghị dùng bản LTS mới nhất còn được hỗ trợ).
- MariaDB 10.6+ (hoặc MySQL 8+).
- Nginx (hoặc reverse proxy tương đương).
- Máy chủ Linux có `systemd` (Ubuntu 20.04+, Debian 11+, CentOS/RHEL 8+...).
- RAM: tối thiểu ~512MB cho 1 worker; cộng thêm ~150-200MB cho mỗi worker
  nếu chạy cluster nhiều worker (xem mục 8).

## 3. Cài Node.js, MariaDB, Nginx

```bash
# Node.js (ví dụ bản 20.x LTS qua NodeSource — điều chỉnh version nếu cần)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# MariaDB
sudo apt-get install -y mariadb-server
sudo mysql_secure_installation

# Nginx
sudo apt-get install -y nginx
```

Kiểm tra:
```bash
node -v      # phải >= v20
mariadb --version
nginx -v
```

## 4. Tạo cơ sở dữ liệu

```bash
sudo mysql -u root -p
```
Trong console MySQL:
```sql
CREATE DATABASE dms_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'dms_app'@'localhost' IDENTIFIED BY 'MẬT-KHẨU-MẠNH-Ở-ĐÂY';
GRANT ALL PRIVILEGES ON dms_db.* TO 'dms_app'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```
Nạp cấu trúc bảng:
```bash
mysql -u dms_app -p dms_db < /opt/dms-prod/schema.sql
```
> Đặt mật khẩu MySQL đủ mạnh và lưu lại an toàn — sẽ dùng ở bước 5 (`.env`).

## 5. Lấy mã nguồn + cấu hình `.env`

```bash
sudo mkdir -p /opt/dms-prod
sudo git clone <URL-repo-của-bạn> /opt/dms-prod
# hoặc: giải nén bản mã nguồn đã tải về vào /opt/dms-prod

cd /opt/dms-prod
cp .env.example .env
nano .env   # điền đầy đủ thông tin thật
```

Tối thiểu cần điền:
```ini
DB_HOST=localhost
DB_USER=dms_app
DB_PASSWORD=MẬT-KHẨU-MẠNH-ĐÃ-TẠO-Ở-BƯỚC-4
DB_NAME=dms_db

PORT=3000
NODE_ENV=production
TRUST_PROXY=true          # BẮT BUỘC true vì chạy sau Nginx (bước 10)

# Bắt buộc đặt cố định — để trống thì mỗi lần restart mọi phiên đăng nhập sẽ mất hiệu lực
JWT_SECRET=$(openssl rand -hex 32)   # chạy lệnh này để sinh 1 chuỗi ngẫu nhiên rồi dán vào

UPLOAD_DIR=/opt/dms-prod/uploads     # đặt ngoài thư mục mã nguồn để dễ backup riêng

WEB_CONCURRENCY=2          # số worker cluster — xem mục 8 để chọn số phù hợp
DB_CONNECTION_LIMIT=30     # số kết nối CSDL cho MỖI worker — xem mục 8
```

> `$(openssl rand -hex 32)` chỉ chạy được trong shell, không paste thẳng
> được vào file `.env`. Chạy lệnh `openssl rand -hex 32` riêng, copy kết
> quả rồi dán vào dòng `JWT_SECRET=`.

## 6. Tạo tài khoản hệ thống riêng (bảo mật)

Đây là bước quan trọng nhất về bảo mật: ứng dụng sẽ chạy bằng 1 tài khoản
hệ thống (`dms`) không phải `root`, không có shell đăng nhập/SSH, và
**không ai khác trên máy đọc được `.env`** (chứa mật khẩu CSDL, JWT
secret, mật khẩu SMTP/LDAP nếu có).

Script `deploy/setup-service-account.sh` tự động hóa toàn bộ:
```bash
cd /opt/dms-prod
sudo bash deploy/setup-service-account.sh /opt/dms-prod
```
Script này sẽ:
- Tạo group + user hệ thống `dms` (shell `/usr/sbin/nologin` — không login/SSH được).
- Đổi chủ sở hữu toàn bộ `/opt/dms-prod` thành `dms:dms`.
- Khóa quyền thư mục gốc về `750` (chỉ `dms` và root vào được, người khác bị chặn hẳn).
- Khóa quyền `.env` về `600` (chỉ chủ sở hữu `dms` đọc/ghi được).
- Tạo sẵn thư mục `uploads/` theo đúng `UPLOAD_DIR` đã khai trong `.env`.

Kiểm tra lại:
```bash
ls -ld /opt/dms-prod        # phải thấy drwxr-x--- dms dms
ls -la /opt/dms-prod/.env   # phải thấy -rw------- dms dms
```
An toàn chạy lại script này mỗi lần cập nhật code mới (idempotent).

## 7. Cài dependencies + build

```bash
cd /opt/dms-prod
sudo -u dms npm ci          # cài đủ cả dependencies lẫn devDependencies
sudo -u dms npm run build   # build CSS (Tailwind) + vendor (ExcelJS) + minify JS
```
> Chạy bằng `sudo -u dms` để các file/thư mục được tạo ra (vd.
> `node_modules/`) thuộc đúng chủ sở hữu `dms`, khớp với quyền đã khóa ở
> bước 6 — tránh phải chạy lại `chown` sau đó.

`npm run build` sinh ra `public/style.css`, `public/vendor/exceljs.min.js`,
`public/app.min.js` — đây là những gì trình duyệt người dùng thực sự tải
về. Chỉ cần chạy lại bước này khi có code mới (xem mục 13).

## 8. Cluster nhiều worker

Ứng dụng dùng module `cluster` có sẵn của Node để chạy nhiều tiến trình
song song, tận dụng nhiều lõi CPU và tự phục hồi khi 1 worker gặp lỗi.

Bật bằng biến `WEB_CONCURRENCY` trong `.env`:

| Giá trị | Hành vi |
|---|---|
| Không đặt, hoặc `1` | Chạy 1 tiến trình duy nhất (mặc định, phù hợp máy nhỏ/thử nghiệm) |
| `2`, `3`, `4`... | Tiến trình chính (primary) tự fork đúng số đó worker, chia tải qua cùng 1 cổng |

**Chọn số worker bao nhiêu?** Thường đặt bằng **số lõi CPU**, hoặc số lõi
trừ 1 nếu máy còn chạy MariaDB/Nginx cùng chỗ. Xem số lõi:
```bash
nproc
```

**Quan trọng — chỉnh `DB_CONNECTION_LIMIT` theo số worker**: mỗi worker
tự giữ 1 pool kết nối CSDL riêng, tổng số kết nối tới MariaDB xấp xỉ:

```
WEB_CONCURRENCY × DB_CONNECTION_LIMIT  ≤  max_connections của MariaDB
```

Ví dụ: 4 worker × `DB_CONNECTION_LIMIT=30` = tối đa 120 kết nối cùng lúc.
Kiểm tra giới hạn hiện tại của MariaDB:
```sql
SHOW VARIABLES LIKE 'max_connections';   -- mặc định thường là 151
```
Nếu cần, tăng `max_connections` trong `/etc/mysql/mariadb.conf.d/50-server.cnf`
(mục `[mysqld]`) rồi `sudo systemctl restart mariadb`.

**Vài lưu ý khác khi bật cluster:**
- Đăng nhập dùng JWT (không lưu session trong bộ nhớ) nên hoạt động đúng
  dù mỗi request rơi vào worker khác nhau — không cần cấu hình gì thêm.
- Các tác vụ chạy theo lịch (đồng bộ AD, nhắc hạn CNTT qua email) chỉ chạy
  ở đúng 1 nơi (tiến trình chính) dù bật bao nhiêu worker — không lo bị
  chạy trùng/gửi email trùng.
- Giới hạn số lần đăng nhập/gọi API (rate limit) hiện tính RIÊNG cho từng
  worker — nếu bật N worker, hạn mức thực tế cao gấp khoảng N lần cấu hình
  gốc. Với hạn mức hiện tại (300 lần đăng nhập sai/15 phút, 6000
  request/15 phút) và cluster vài worker thì vẫn đủ chặt; nếu triển khai
  quy mô rất lớn (>5-6 worker) và muốn hạn mức chính xác tuyệt đối, cần bổ
  sung một kho lưu đếm dùng chung (VD Redis) — nằm ngoài phạm vi bản hiện tại.
- Restart service sẽ dừng **toàn bộ** worker cùng lúc rồi khởi động lại
  (gián đoạn vài giây), không phải kiểu "rolling update" từng worker một.
  Với 1 ứng dụng nội bộ công ty, vài giây gián đoạn lúc restart thường
  chấp nhận được — cứ restart ngoài giờ cao điểm.

## 9. Cài đặt systemd service

File `deploy/dms-prod.service` đã viết sẵn (bao gồm các dòng hardening
bảo mật — xem chú thích trong file). Cài đặt:

```bash
sudo cp /opt/dms-prod/deploy/dms-prod.service /etc/systemd/system/dms-prod.service
sudo systemctl daemon-reload
sudo systemctl enable dms-prod    # tự khởi động cùng máy chủ
sudo systemctl start dms-prod
```

Kiểm tra:
```bash
sudo systemctl status dms-prod
sudo journalctl -u dms-prod -f    # xem log trực tiếp (Ctrl+C để thoát)
```
Log đúng khi khởi động thành công với `WEB_CONCURRENCY=2`:
```
🧵 Tiến trình chính (PID 1234) đang khởi động 2 worker...
🧵 Tiến trình chính (PID 1234) không phục vụ HTTP trực tiếp — chỉ giám sát worker + chạy tác vụ định kỳ.
🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:3000 (worker #1, PID 1240)
✅ Kết nối CSDL MySQL Production thành công!
🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:3000 (worker #2, PID 1241)
✅ Kết nối CSDL MySQL Production thành công!
```

> ⚠️ Nếu sửa `WorkingDirectory` trong file `.service` (triển khai ở thư
> mục khác `/opt/dms-prod`), nhớ sửa luôn dòng `ReadWritePaths=` cho khớp
> `UPLOAD_DIR` trong `.env` — nếu không, ứng dụng sẽ báo lỗi không ghi
> được file khi upload tài liệu (do dòng `ProtectSystem=strict` chặn ghi
> ra ngoài các đường dẫn đã liệt kê).

## 10. Nginx reverse proxy + HTTPS

Tạo file cấu hình site mới:
```bash
sudo nano /etc/nginx/sites-available/dms-prod
```
Nội dung:
```nginx
server {
    listen 80;
    server_name dms.congty-cua-ban.vn;   # đổi thành domain thật

    # Phải khớp (hoặc lớn hơn) MAX_PDF_SIZE_MB trong .env, nếu không Nginx
    # sẽ tự chặn upload trước khi tới được ứng dụng.
    client_max_body_size 25m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
Kích hoạt:
```bash
sudo ln -s /etc/nginx/sites-available/dms-prod /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Bật HTTPS miễn phí bằng Let's Encrypt (khuyến nghị bắt buộc cho production):
```bash
sudo apt-get install -y certbot python3-certbot-nginx
sudo certbot --nginx -d dms.congty-cua-ban.vn
```
Certbot sẽ tự sửa file Nginx ở trên để chuyển sang HTTPS + tự gia hạn
chứng chỉ định kỳ.

## 11. Tường lửa

Chỉ mở cổng cần thiết ra internet (80/443 cho Nginx, 22 cho SSH quản trị
— **không** mở cổng 3000/3111 của Node ra ngoài):
```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
sudo ufw status
```

## 12. Vận hành hàng ngày

| Việc cần làm | Lệnh |
|---|---|
| Xem log trực tiếp | `sudo journalctl -u dms-prod -f` |
| Xem log 100 dòng gần nhất | `sudo journalctl -u dms-prod -n 100` |
| Khởi động lại (VD sau khi đổi `.env`) | `sudo systemctl restart dms-prod` |
| Dừng | `sudo systemctl stop dms-prod` |
| Xem trạng thái (đang chạy/lỗi/PID) | `sudo systemctl status dms-prod` |
| Bật/tắt tự khởi động cùng máy chủ | `sudo systemctl enable\|disable dms-prod` |

Đổi `.env` (VD đổi mật khẩu CSDL, bật cluster...) luôn cần
`sudo systemctl restart dms-prod` để có hiệu lực.

## 13. Cập nhật lên bản mới

```bash
cd /opt/dms-prod
sudo -u dms git pull                      # hoặc giải nén bản mã nguồn mới đè lên
sudo -u dms npm ci                        # cập nhật dependencies nếu package.json đổi
sudo -u dms npm run build                 # build lại CSS/vendor/JS minify
sudo bash deploy/setup-service-account.sh /opt/dms-prod   # đảm bảo quyền vẫn đúng
sudo systemctl restart dms-prod
sudo journalctl -u dms-prod -f            # theo dõi log để chắc khởi động thành công
```
Nếu `schema.sql` có thay đổi cấu trúc bảng, đọc kỹ ghi chú kèm theo bản
cập nhật đó trước khi áp dụng — không tự ý chạy lại toàn bộ `schema.sql`
lên CSDL đã có dữ liệu thật.

## 14. Sao lưu (backup)

Cần backup **2 thứ**, thiếu 1 trong 2 là mất dữ liệu không phục hồi được:

1. **Cơ sở dữ liệu** (toàn bộ dữ liệu nghiệp vụ):
   ```bash
   mysqldump -u dms_app -p dms_db | gzip > dms_db_$(date +%Y%m%d).sql.gz
   ```
2. **Thư mục `UPLOAD_DIR`** (file PDF tài liệu thật trên đĩa — CSDL chỉ
   lưu đường dẫn, không lưu nội dung file):
   ```bash
   tar -czf uploads_$(date +%Y%m%d).tar.gz -C /opt/dms-prod uploads
   ```

Nên đặt lịch tự động (cron) chạy 2 lệnh trên hàng ngày và lưu bản sao ra
một nơi khác (ổ đĩa khác/server khác/dịch vụ lưu trữ ngoài) — backup nằm
cùng ổ với dữ liệu gốc sẽ mất luôn cùng lúc nếu ổ đĩa hỏng.

## 15. Xử lý sự cố thường gặp

**Service không khởi động được (`systemctl status` báo `failed`):**
```bash
sudo journalctl -u dms-prod -n 50 --no-pager
```
Các lỗi hay gặp:
- `Cannot find module` → chưa chạy `npm ci` ở `/opt/dms-prod` bằng đúng user `dms`.
- Lỗi kết nối CSDL → kiểm tra lại `DB_HOST/DB_USER/DB_PASSWORD/DB_NAME` trong `.env`.
- `EACCES: permission denied, mkdir ... uploads` → `UPLOAD_DIR` trong
  `.env` không khớp `ReadWritePaths=` trong file `.service`, hoặc chưa
  chạy lại `deploy/setup-service-account.sh` sau khi đổi `UPLOAD_DIR`.

**Đăng nhập xong bị văng ra liên tục / phiên đăng nhập không giữ được:**
`JWT_SECRET` trong `.env` đang để trống hoặc bị đổi giữa các lần restart
— đặt cố định 1 chuỗi ngẫu nhiên dài (xem mục 5) và không đổi nữa trừ khi
cố ý muốn buộc mọi người đăng nhập lại.

**Upload file báo lỗi "quá dung lượng":**
Kiểm tra cả 2 nơi cùng lúc phải đủ lớn: `MAX_PDF_SIZE_MB` trong `.env`
VÀ `client_max_body_size` trong cấu hình Nginx (mục 10) — cái nhỏ hơn sẽ
là giới hạn thực tế.

**Nghi ngờ 1 worker bị "treo" (không phản hồi) nhưng service vẫn báo `active`:**
```bash
sudo systemctl restart dms-prod
```
An toàn — chỉ gây gián đoạn vài giây (xem lưu ý ở mục 8).

## 16. Bảng biến môi trường (`.env`)

Tham khảo đầy đủ trong `.env.example` (có chú thích tiếng Việt kèm theo
từng biến). Các biến quan trọng nhất cho production:

| Biến | Bắt buộc? | Ghi chú |
|---|---|---|
| `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | ✅ | Thông tin kết nối MariaDB |
| `JWT_SECRET` | ✅ | Chuỗi ngẫu nhiên cố định — để trống sẽ mất phiên đăng nhập mỗi lần restart |
| `NODE_ENV=production` | ✅ | |
| `TRUST_PROXY=true` | ✅ nếu chạy sau Nginx | Để nhận đúng IP thật của người dùng |
| `UPLOAD_DIR` | Khuyến nghị | Đặt đường dẫn tuyệt đối ngoài thư mục mã nguồn |
| `WEB_CONCURRENCY` | Tùy chọn | Số worker cluster — xem mục 8 |
| `DB_CONNECTION_LIMIT` | Tùy chọn | Số kết nối CSDL/worker — xem mục 8 |
| `MAX_PDF_SIZE_MB` | Tùy chọn | Nhớ khớp với `client_max_body_size` ở Nginx |
| `CORS_ORIGIN` | Tùy chọn | Chỉ cần nếu frontend chạy khác domain với API (hiếm khi cần) |
