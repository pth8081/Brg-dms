#!/bin/bash
# Tạo tài khoản hệ thống riêng để chạy DMS Production (không dùng root, không
# thể đăng nhập/SSH) và phân quyền thư mục ứng dụng + .env cho tài khoản đó.
#
# Chạy 1 lần (bằng root/sudo) SAU KHI đã copy mã nguồn vào APP_DIR:
#   sudo bash deploy/setup-service-account.sh /opt/dms-prod
#
# An toàn chạy lại nhiều lần (idempotent) — dùng lại khi cập nhật code mới.

set -euo pipefail

APP_DIR="${1:-/opt/dms-prod}"
SERVICE_USER="dms"
SERVICE_GROUP="dms"

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Cần chạy bằng root (sudo bash deploy/setup-service-account.sh $APP_DIR)" >&2
    exit 1
fi

if [ ! -d "$APP_DIR" ]; then
    echo "❌ Không tìm thấy thư mục $APP_DIR — copy mã nguồn vào đó trước." >&2
    exit 1
fi

# --- 1) Tạo group + user hệ thống (không có shell đăng nhập, không có mật khẩu) ---
if ! getent group "$SERVICE_GROUP" > /dev/null; then
    groupadd --system "$SERVICE_GROUP"
    echo "✅ Đã tạo group $SERVICE_GROUP"
else
    echo "ℹ️  Group $SERVICE_GROUP đã tồn tại, bỏ qua."
fi

if ! id "$SERVICE_USER" > /dev/null 2>&1; then
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$APP_DIR" \
        --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    echo "✅ Đã tạo user hệ thống $SERVICE_USER (không thể đăng nhập/SSH)"
else
    echo "ℹ️  User $SERVICE_USER đã tồn tại, bỏ qua."
fi

# --- 2) Thư mục upload phải tồn tại trước khi phân quyền (đọc UPLOAD_DIR từ .env nếu có) ---
UPLOAD_DIR="$APP_DIR/uploads"
if [ -f "$APP_DIR/.env" ]; then
    ENV_UPLOAD_DIR=$(grep -E '^UPLOAD_DIR=' "$APP_DIR/.env" | cut -d'=' -f2- || true)
    if [ -n "$ENV_UPLOAD_DIR" ]; then
        UPLOAD_DIR="$ENV_UPLOAD_DIR"
    fi
fi
mkdir -p "$UPLOAD_DIR"

# --- 3) Phân quyền: toàn bộ thư mục ứng dụng thuộc về dms:dms ---
# Chỉ khóa THƯ MỤC GỐC về 750 (chủ sở hữu đọc/ghi/vào, group chỉ vào+đọc,
# người khác KHÔNG được vào) — chặn mọi tài khoản khác trên máy truy cập cả
# cây thư mục ngay từ đây, không cần chmod đệ quy từng file bên trong (rủi
# ro làm mất quyền thực thi của các script/binary do npm cài đặt sẵn).
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR"
chmod 750 "$APP_DIR"

# --- 4) .env khóa chặt nhất — chỉ chủ sở hữu (dms) đọc/ghi được, không ai khác ---
if [ -f "$APP_DIR/.env" ]; then
    chmod 600 "$APP_DIR/.env"
    echo "✅ Đã khóa quyền .env về 600 (chỉ $SERVICE_USER đọc được)"
else
    echo "⚠️  Chưa thấy $APP_DIR/.env — nhớ tạo file này (copy từ .env.example) trước khi khởi động service."
fi

echo ""
echo "🎉 Hoàn tất. Kiểm tra nhanh:"
echo "   ls -ld $APP_DIR"
echo "   ls -la $APP_DIR/.env"
echo ""
echo "Bước tiếp theo: cài systemd unit rồi khởi động service — xem DEPLOYMENT.md."
