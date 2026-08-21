// Công cụ dọn dẹp một lần: chuyển các tài liệu CŨ vẫn còn lưu nội dung PDF
// dạng base64 trong cột docs.file_data (upload từ trước khi có bản refactor
// lưu file ra ổ đĩa) ra thư mục UPLOAD_DIR, giải phóng dung lượng CSDL.
// Tài liệu upload MỚI đã tự động lưu ra đĩa từ trước, KHÔNG bị ảnh hưởng.
//
// Cách chạy (trên server, cùng thư mục với server.js, cùng file .env):
//   node migrate-legacy-files-to-disk.js --dry-run   (xem trước, KHÔNG đổi gì)
//   node migrate-legacy-files-to-disk.js             (chạy thật)
//
// An toàn chạy lại nhiều lần — chỉ xử lý các dòng còn file_data mà chưa có
// file_path. NÊN sao lưu CSDL (mysqldump) trước khi chạy chế độ thật.

require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

const isDryRun = process.argv.includes('--dry-run');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
const BATCH_SIZE = 50;

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'dms_db',
    port: process.env.DB_PORT || 3306
};

async function runDryRun(pool) {
    // Chỉ lấy độ dài (LENGTH), KHÔNG tải nội dung base64 thật về — tránh tốn
    // băng thông/bộ nhớ khi CSDL có nhiều tài liệu cũ dung lượng lớn.
    const [rows] = await pool.query(
        `SELECT id, code, title, LENGTH(file_data) AS byte_len
         FROM docs WHERE file_path IS NULL AND file_data IS NOT NULL
         ORDER BY id`
    );
    if (rows.length === 0) {
        console.log('✅ Không còn tài liệu nào cần chuyển — mọi thứ đã nằm trên đĩa.');
        return;
    }
    let totalBytes = 0;
    for (const r of rows) {
        totalBytes += r.byte_len || 0;
        console.log(`  [${r.code || r.id}] ${r.title || ''} — ~${((r.byte_len || 0) / 1024).toFixed(1)} KB (base64, sẽ nhỏ hơn ~25% sau khi giải mã)`);
    }
    console.log(`\n=== XEM TRƯỚC: ${rows.length} tài liệu còn lưu trong CSDL, tổng ~${(totalBytes / 1024 / 1024).toFixed(1)} MB (dạng base64). ===`);
    console.log('Chạy lại KHÔNG có --dry-run để thực sự chuyển ra đĩa.');
}

async function runReal(pool) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    console.log(`📂 Thư mục lưu file: ${UPLOAD_DIR}\n`);

    let migrated = 0, skipped = 0, totalSeen = 0;

    const [[{ pending }]] = await pool.query(
        'SELECT COUNT(*) AS pending FROM docs WHERE file_path IS NULL AND file_data IS NOT NULL'
    );
    // Lưới an toàn: mỗi dòng xử lý xong PHẢI khiến nó không còn khớp WHERE nữa
    // (thành công -> có file_path thật; lỗi/không hợp lệ -> đánh dấu __MIGRATE_*),
    // nên số vòng lặp không thể vượt quá số dòng ban đầu chia cho BATCH_SIZE.
    // Giới hạn cứng thêm để KHÔNG BAO GIỜ treo vô hạn nếu có tình huống phát
    // sinh ngoài dự kiến (VD lỗi UPDATE âm thầm không throw).
    const maxIterations = Math.ceil(pending / BATCH_SIZE) + 2;
    let iterations = 0;

    // WHERE file_path IS NULL tự thu hẹp dần sau mỗi lần UPDATE thành công,
    // nên LUÔN lấy batch tiếp theo đúng, không cần OFFSET.
    while (true) {
        iterations++;
        if (iterations > maxIterations) {
            throw new Error(`Vượt quá số vòng lặp an toàn (${maxIterations}) — có dòng không được đánh dấu đúng sau khi xử lý, dừng lại để tránh treo vô hạn. Đã xử lý ${totalSeen}/${pending} dòng trước khi dừng.`);
        }
        const [rows] = await pool.query(
            'SELECT id, code, title, file_data FROM docs WHERE file_path IS NULL AND file_data IS NOT NULL ORDER BY id LIMIT ?',
            [BATCH_SIZE]
        );
        if (rows.length === 0) break;
        totalSeen += rows.length;

        for (const row of rows) {
            const label = row.code || `#${row.id}`;
            try {
                const buffer = Buffer.from(row.file_data, 'base64');
                if (buffer.length === 0 || buffer.slice(0, 4).toString('latin1') !== '%PDF') {
                    console.log(`⚠️  Bỏ qua [${label}] — nội dung không phải PDF hợp lệ, cần kiểm tra thủ công.`);
                    skipped++;
                    // BẮT BUỘC đánh dấu lại (file_path không còn NULL) để dòng này
                    // không bị WHERE khớp lại ở batch sau — nếu không sẽ lặp vô hạn
                    // vì file_data vẫn còn nguyên và file_path vẫn NULL mãi mãi.
                    await pool.query('UPDATE docs SET file_path = ? WHERE id = ?', [`__MIGRATE_INVALID_${row.id}.pdf`, row.id]);
                    continue;
                }
                const filePath = `${row.id}.pdf`;
                fs.writeFileSync(path.join(UPLOAD_DIR, filePath), buffer);
                // Chỉ xóa file_data SAU KHI đã ghi file thành công ra đĩa.
                await pool.query('UPDATE docs SET file_path = ?, file_data = NULL WHERE id = ?', [filePath, row.id]);
                console.log(`✅ Đã chuyển [${label}] (${(buffer.length / 1024).toFixed(1)} KB) ra đĩa.`);
                migrated++;
            } catch (err) {
                console.error(`❌ Lỗi khi xử lý [${label}]: ${err.message} — bỏ qua, giữ nguyên dòng này trong CSDL.`);
                skipped++;
                // Đánh dấu tạm để vòng lặp không kẹt mãi ở dòng lỗi này (WHERE
                // vẫn khớp nó vì file_path còn NULL) — set file_path rỗng đặc
                // biệt để nhận diện, KHÔNG xóa file_data, admin xem log để xử lý tay.
                await pool.query('UPDATE docs SET file_path = ? WHERE id = ?', [`__MIGRATE_FAILED_${row.id}.pdf`, row.id]).catch(() => {});
            }
        }
    }

    console.log(`\n=== KẾT QUẢ: ${migrated} tài liệu đã chuyển ra đĩa thành công, ${skipped} bị bỏ qua (xem log ở trên), tổng ${totalSeen} tài liệu đã xử lý. ===`);
    if (skipped > 0) {
        console.log('Các dòng bị bỏ qua được đánh dấu file_path bắt đầu bằng "__MIGRATE_" để không lặp lại — cần Admin kiểm tra tay rồi tự sửa file_path/file_data cho đúng.');
    }
    return { migrated, skipped, totalSeen };
}

async function main() {
    console.log(isDryRun
        ? '🔍 Chế độ xem trước (--dry-run) — KHÔNG ghi file, KHÔNG đổi CSDL.\n'
        : '⚠️  Chế độ thực thi — sẽ ghi file ra đĩa và cập nhật CSDL. Đảm bảo đã sao lưu CSDL trước khi tiếp tục!\n');

    const pool = mysql.createPool(dbConfig);
    try {
        if (isDryRun) {
            await runDryRun(pool);
        } else {
            const { skipped } = await runReal(pool);
            if (skipped > 0) process.exitCode = 1;
        }
    } finally {
        await pool.end();
    }
}

main().catch(err => {
    console.error('❌ Lỗi hệ thống khi chạy migration:', err.message);
    process.exit(1);
});
