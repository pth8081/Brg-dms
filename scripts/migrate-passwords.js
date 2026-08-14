// Chạy 1 lần trên DB production hiện có (đã tồn tại user với mật khẩu plaintext)
// để chuyển toàn bộ sang bcrypt hash. An toàn khi chạy lại nhiều lần (bỏ qua
// các mật khẩu đã ở dạng hash).
//
// Sử dụng: node scripts/migrate-passwords.js
require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const BCRYPT_HASH_RE = /^\$2[aby]\$\d{2}\$/;

async function main() {
    const pool = mysql.createPool({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'dms_db',
        port: process.env.DB_PORT || 3306
    });

    const [rows] = await pool.query('SELECT id, username, pass FROM users');
    let migrated = 0;

    for (const row of rows) {
        if (BCRYPT_HASH_RE.test(row.pass || '')) continue; // đã hash, bỏ qua
        const hash = await bcrypt.hash(row.pass, 12);
        await pool.query('UPDATE users SET pass = ? WHERE id = ?', [hash, row.id]);
        migrated++;
        console.log(`✅ Đã hash mật khẩu cho user: ${row.username}`);
    }

    console.log(`\nHoàn tất. Đã chuyển đổi ${migrated}/${rows.length} tài khoản sang bcrypt hash.`);
    await pool.end();
}

main().catch(err => {
    console.error('❌ Lỗi migration:', err);
    process.exit(1);
});
