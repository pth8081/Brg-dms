// Công cụ dọn dẹp một lần: xóa TOÀN BỘ dữ liệu nghiệp vụ/test (tài liệu, toàn
// bộ dữ liệu module Bản quyền, Ngân sách, CNTT, Ngân sách 2, Nhật ký hệ
// thống), CHỈ giữ lại cấu hình hệ thống và danh mục nền tảng:
//   GIỮ LẠI: users, depts, cats, workflows, app_configs (deptWorkflows/
//            emailConfig/ldapConfig/...), sync_versions, lic_software_catalog,
//            lic_budget_item_catalog, it_categories.
//   XÓA:     docs (+ file vật lý trên đĩa), toàn bộ lic_companies/lic_org_units/
//            lic_employees/lic_license_batches/lic_license_codes/
//            lic_license_code_assignments/lic_purchase_rounds/
//            lic_purchase_round_items/lic_purchase_registrations/
//            lic_bulk_allocation_requests/lic_bulk_allocation_items/
//            lic_budget_rounds/lic_budget_round_items/lic_budget_registrations/
//            lic_budget_actuals/ad_accounts/it_items/it_reminder_sent/
//            budget2_lines/system_logs (xem cờ --keep-logs bên dưới nếu muốn
//            giữ lại Nhật ký hệ thống).
//
// Cách chạy (trên server, cùng thư mục với server.js, cùng file .env):
//   node reset-test-data.js --dry-run          (xem trước, KHÔNG đổi gì)
//   node reset-test-data.js                    (chạy thật, sẽ hỏi xác nhận)
//   node reset-test-data.js --yes              (chạy thật, không hỏi xác nhận
//                                                — dùng khi chạy tự động/CI)
//   node reset-test-data.js --keep-logs        (giữ lại Nhật ký hệ thống,
//                                                chỉ xóa dữ liệu nghiệp vụ)
//
// BẮT BUỘC sao lưu CSDL (mysqldump) trước khi chạy chế độ thật — thao tác
// này KHÔNG THỂ HOÀN TÁC. Luôn chạy --dry-run trước để xem đúng số dòng sẽ
// bị xóa trước khi chạy thật.

require('dotenv').config();
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const isDryRun = process.argv.includes('--dry-run');
const skipConfirm = process.argv.includes('--yes');
const keepLogs = process.argv.includes('--keep-logs');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));

const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'dms_db',
    port: process.env.DB_PORT || 3306
};

// Thứ tự liệt kê không quan trọng (schema.sql không có ràng buộc FOREIGN KEY
// nào giữa các bảng này), nhưng vẫn xóa bảng "con" trước bảng "cha" cho rõ
// ràng, dễ đọc log theo đúng luồng nghiệp vụ.
const TABLES_TO_CLEAR = [
    // Module Bản quyền (License) — toàn bộ dữ liệu vận hành, GIỮ LẠI riêng
    // lic_software_catalog (danh mục phần mềm nền tảng).
    'lic_bulk_allocation_items',
    'lic_bulk_allocation_requests',
    'lic_license_code_assignments',
    'lic_license_codes',
    'lic_license_batches',
    'lic_purchase_registrations',
    'lic_purchase_round_items',
    'lic_purchase_rounds',
    'lic_budget_registrations',
    'lic_budget_round_items',
    'lic_budget_rounds',
    'lic_budget_actuals',
    'lic_employees',
    'lic_org_units',
    'lic_companies',
    'ad_accounts',
    // Module CNTT — GIỮ LẠI it_categories (danh mục loại đầu mục).
    'it_reminder_sent',
    'it_items',
    // Module Ngân sách 2 (Đề xuất -> Phê duyệt -> Sử dụng).
    'budget2_lines',
    // Module Tài liệu (docs) — xử lý riêng bên dưới vì còn phải xóa file trên
    // đĩa tương ứng trước khi xóa dòng CSDL.
];
if (!keepLogs) TABLES_TO_CLEAR.push('system_logs');

async function countRows(pool, table) {
    const [[{ cnt }]] = await pool.query(`SELECT COUNT(*) AS cnt FROM ${table}`);
    return cnt;
}

async function main() {
    const pool = await mysql.createPool(dbConfig);

    console.log(`\n=== Dọn dẹp dữ liệu test — CSDL "${dbConfig.database}"@${dbConfig.host} ===`);
    console.log(isDryRun ? '(Chế độ XEM TRƯỚC — --dry-run, KHÔNG thay đổi gì)\n' : '(Chế độ CHẠY THẬT — sẽ xóa dữ liệu)\n');

    // Đếm trước để người dùng biết chính xác sẽ mất bao nhiêu dòng mỗi bảng.
    const [docRows] = await pool.query('SELECT id, file_path FROM docs');
    const counts = {};
    for (const table of TABLES_TO_CLEAR) counts[table] = await countRows(pool, table);
    counts['docs'] = docRows.length;

    console.log('Số dòng sẽ bị xóa theo từng bảng:');
    for (const table of [...TABLES_TO_CLEAR, 'docs']) {
        console.log(`  - ${table}: ${counts[table]}`);
    }
    const totalRows = Object.values(counts).reduce((a, b) => a + b, 0);
    console.log(`  TỔNG: ${totalRows} dòng\n`);

    console.log('Các bảng được GIỮ NGUYÊN (cấu hình hệ thống + danh mục):');
    console.log('  users, depts, cats, workflows, app_configs, sync_versions,');
    console.log('  lic_software_catalog, lic_budget_item_catalog, it_categories' + (keepLogs ? ', system_logs (--keep-logs)' : ''));
    console.log('');

    if (isDryRun) {
        console.log('✅ Chỉ xem trước — chưa xóa gì. Bỏ --dry-run để chạy thật.');
        await pool.end();
        return;
    }

    if (!skipConfirm) {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const answer = await new Promise(resolve => {
            rl.question('Gõ đúng chữ "XOA" (không dấu, viết hoa) để xác nhận xóa thật, Enter để hủy: ', resolve);
        });
        rl.close();
        if (answer.trim() !== 'XOA') {
            console.log('❌ Đã hủy — không có gì bị xóa.');
            await pool.end();
            return;
        }
    }

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        for (const table of TABLES_TO_CLEAR) {
            await conn.query(`DELETE FROM ${table}`);
        }
        // docs xóa sau cùng trong transaction — file vật lý chỉ xóa SAU KHI
        // transaction commit thành công, tránh mất file nếu phần CSDL lỡ phải
        // rollback (VD lỗi giữa chừng).
        await conn.query('DELETE FROM docs');
        await conn.commit();
    } catch (e) {
        await conn.rollback();
        console.error('❌ Lỗi khi xóa dữ liệu, đã rollback toàn bộ (không có gì bị mất):', e.message);
        conn.release();
        await pool.end();
        process.exit(1);
    }
    conn.release();

    console.log('✅ Đã xóa xong dữ liệu CSDL.');

    // Xóa file vật lý tương ứng các tài liệu vừa xóa khỏi CSDL — chỉ xóa file
    // thực sự nằm trong UPLOAD_DIR (không tin file_path tuyệt đối/đi ra ngoài
    // thư mục), giống đúng kiểm tra an toàn dùng ở route xem/tải file thật.
    let filesDeleted = 0, filesFailed = 0;
    for (const d of docRows) {
        if (!d.file_path) continue;
        const absPath = path.join(UPLOAD_DIR, d.file_path);
        const relPath = path.relative(UPLOAD_DIR, absPath);
        if (relPath.startsWith('..') || path.isAbsolute(relPath)) continue;
        try {
            if (fs.existsSync(absPath)) { fs.unlinkSync(absPath); filesDeleted++; }
        } catch (e) {
            filesFailed++;
            console.error(`  ⚠️  Không xóa được file ${absPath}: ${e.message}`);
        }
    }
    console.log(`✅ Đã xóa ${filesDeleted} file tài liệu trên đĩa${filesFailed > 0 ? ` (${filesFailed} file lỗi, xem chi tiết ở trên)` : ''}.`);
    console.log(`\n🎉 Hoàn tất — đã xóa ${totalRows} dòng dữ liệu test, chỉ còn lại cấu hình hệ thống + danh mục.`);

    await pool.end();
}

main().catch(e => { console.error('❌ LỖI:', e); process.exit(1); });
