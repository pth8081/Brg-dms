// Chạy 1 lần trên DB production hiện có (tài liệu đang lưu nội dung file dạng
// base64 trong cột docs.file_data) để chuyển toàn bộ file ra lưu trên đĩa
// (thư mục UPLOAD_DIR) và ghi lại đường dẫn vào cột docs.file_path.
//
// BẮT BUỘC backup CSDL trước khi chạy script này.
//
// An toàn khi chạy lại nhiều lần (bỏ qua các dòng đã có file_path). Cột
// file_data KHÔNG bị xoá sau khi migrate — giữ lại làm lưới an toàn tạm thời,
// có thể dọn (UPDATE docs SET file_data = NULL) sau khi xác nhận hệ thống
// chạy ổn định với file trên đĩa.
//
// Sử dụng: node scripts/migrate-files-to-disk.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, '..', 'uploads'));

async function main() {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });

    const pool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'dms_db',
        port: process.env.DB_PORT || 3306
    });

    const [rows] = await pool.query(
        "SELECT id, code, file_data FROM docs WHERE file_path IS NULL AND file_data IS NOT NULL AND file_data <> ''"
    );

    let migrated = 0;
    for (const row of rows) {
        try {
            const base64 = String(row.file_data).replace(/^data:[^;]+;base64,/, '');
            const buffer = Buffer.from(base64, 'base64');
            if (buffer.length === 0) {
                console.warn(`⚠️  Bỏ qua tài liệu id=${row.id} (${row.code}): nội dung file rỗng sau khi giải mã.`);
                continue;
            }
            const filePath = `${row.id}.pdf`;
            fs.writeFileSync(path.join(UPLOAD_DIR, filePath), buffer);
            await pool.query('UPDATE docs SET file_path = ? WHERE id = ?', [filePath, row.id]);
            migrated++;
            console.log(`✅ Đã chuyển file cho tài liệu id=${row.id} (${row.code}) — ${buffer.length} bytes.`);
        } catch (e) {
            console.error(`❌ Lỗi xử lý tài liệu id=${row.id} (${row.code}):`, e.message);
        }
    }

    console.log(`\nHoàn tất. Đã chuyển ${migrated}/${rows.length} tài liệu sang lưu trên đĩa (${UPLOAD_DIR}).`);
    console.log('Cột file_data trong CSDL vẫn được giữ nguyên làm lưới an toàn — có thể dọn sau khi xác nhận hệ thống ổn định.');
    await pool.end();
}

main().catch(err => {
    console.error('❌ Lỗi migration:', err);
    process.exit(1);
});
