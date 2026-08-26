CREATE DATABASE IF NOT EXISTS dms_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dms_db;

-- Thủ tục dùng nội bộ cho việc nâng cấp CSDL: "CREATE INDEX IF NOT EXISTS"
-- là cú pháp RIÊNG của MariaDB — MySQL chuẩn (kể cả bản mới nhất) KHÔNG hỗ
-- trợ, sẽ báo lỗi cú pháp (ERROR 1064) nếu dùng trực tiếp. Thủ tục này tự
-- kiểm tra qua information_schema trước khi tạo, chạy được trên CẢ MySQL
-- lẫn MariaDB, mọi phiên bản. Được xóa lại ở cuối file sau khi dùng xong.
DELIMITER $$
DROP PROCEDURE IF EXISTS create_index_if_not_exists$$
CREATE PROCEDURE create_index_if_not_exists(
    IN p_table_name VARCHAR(64),
    IN p_index_name VARCHAR(64),
    IN p_columns VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table_name AND INDEX_NAME = p_index_name
    ) THEN
        SET @create_idx_sql = CONCAT('CREATE INDEX ', p_index_name, ' ON ', p_table_name, ' (', p_columns, ')');
        PREPARE stmt_create_idx FROM @create_idx_sql;
        EXECUTE stmt_create_idx;
        DEALLOCATE PREPARE stmt_create_idx;
    END IF;
END$$
DELIMITER ;

-- Tương tự create_index_if_not_exists nhưng tạo UNIQUE INDEX — dùng để chặn
-- trùng lặp ở tầng CSDL (VD mã tài liệu trùng do 2 request ghi đồng thời),
-- không chỉ dựa vào kiểm tra ở tầng ứng dụng (vốn không atomic).
DELIMITER $$
DROP PROCEDURE IF EXISTS create_unique_index_if_not_exists$$
CREATE PROCEDURE create_unique_index_if_not_exists(
    IN p_table_name VARCHAR(64),
    IN p_index_name VARCHAR(64),
    IN p_columns VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table_name AND INDEX_NAME = p_index_name
    ) THEN
        SET @create_uidx_sql = CONCAT('CREATE UNIQUE INDEX ', p_index_name, ' ON ', p_table_name, ' (', p_columns, ')');
        PREPARE stmt_create_uidx FROM @create_uidx_sql;
        EXECUTE stmt_create_uidx;
        DEALLOCATE PREPARE stmt_create_uidx;
    END IF;
END$$
DELIMITER ;

-- "ADD COLUMN IF NOT EXISTS" cũng là cú pháp RIÊNG của MariaDB — MySQL chuẩn
-- (đã kiểm chứng thật trên MySQL 8.0.46) KHÔNG hỗ trợ, báo lỗi cú pháp giống
-- hệt CREATE INDEX ở trên. Thủ tục này thay thế, chạy được trên cả 2 hệ.
DELIMITER $$
DROP PROCEDURE IF EXISTS add_column_if_not_exists$$
CREATE PROCEDURE add_column_if_not_exists(
    IN p_table_name VARCHAR(64),
    IN p_column_name VARCHAR(64),
    IN p_column_def VARCHAR(255)
)
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table_name AND COLUMN_NAME = p_column_name
    ) THEN
        SET @add_col_sql = CONCAT('ALTER TABLE ', p_table_name, ' ADD COLUMN ', p_column_name, ' ', p_column_def);
        PREPARE stmt_add_col FROM @add_col_sql;
        EXECUTE stmt_add_col;
        DEALLOCATE PREPARE stmt_add_col;
    END IF;
END$$
DELIMITER ;

-- "DROP COLUMN IF EXISTS" cũng không được MySQL chuẩn hỗ trợ (chỉ MariaDB có) —
-- thủ tục này bổ trợ add_column_if_not_exists ở trên, dùng khi cần dọn cột cũ
-- sau khi đã di chuyển dữ liệu sang cấu trúc mới.
DELIMITER $$
DROP PROCEDURE IF EXISTS drop_column_if_exists$$
CREATE PROCEDURE drop_column_if_exists(
    IN p_table_name VARCHAR(64),
    IN p_column_name VARCHAR(64)
)
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = p_table_name AND COLUMN_NAME = p_column_name
    ) THEN
        SET @drop_col_sql = CONCAT('ALTER TABLE ', p_table_name, ' DROP COLUMN ', p_column_name);
        PREPARE stmt_drop_col FROM @drop_col_sql;
        EXECUTE stmt_drop_col;
        DEALLOCATE PREPARE stmt_drop_col;
    END IF;
END$$
DELIMITER ;

-- 1. Bảng Phòng Ban
CREATE TABLE IF NOT EXISTS depts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    abbr VARCHAR(20) NOT NULL DEFAULT ''
);

-- 2. Bảng Phân Loại Tài Liệu
CREATE TABLE IF NOT EXISTS cats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    abbr VARCHAR(20) NOT NULL DEFAULT ''
);

-- 3. Bảng Người Dùng & Phân Quyền
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    pass VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    dept VARCHAR(255),
    perms JSON,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

-- 4. Bảng Tài Liệu
CREATE TABLE IF NOT EXISTS docs (
    id BIGINT PRIMARY KEY,
    code VARCHAR(100),
    title TEXT,
    ver VARCHAR(50),
    dept VARCHAR(255),
    cat VARCHAR(255),
    summary TEXT,
    file_name TEXT,
    file_type TEXT,
    file_data LONGTEXT,
    file_path VARCHAR(500) NULL DEFAULT NULL,
    created_by VARCHAR(255),
    creator_username VARCHAR(100),
    created_at VARCHAR(100),
    workflow_id VARCHAR(100),
    current_step_order INT,
    status VARCHAR(50),
    history JSON,
    doc_group_id BIGINT,
    version_no INT NOT NULL DEFAULT 1,
    deleted_at DATETIME NULL DEFAULT NULL,
    deleted_by VARCHAR(100) NULL DEFAULT NULL
);
-- Chặn trùng mã tài liệu ở tầng CSDL: mã tự sinh (đếm-rồi-tăng, không atomic)
-- có thể trùng nếu 2 người upload gần như đồng thời cho cùng phòng ban+phân
-- loại — UNIQUE (code, version_no) vẫn cho phép NHIỀU phiên bản của CÙNG 1
-- tài liệu dùng chung 1 mã (version_no khác nhau), chỉ chặn 2 tài liệu KHÁC
-- NHAU (2 doc_group_id khác nhau) cùng nhận trùng mã ở version_no=1.
-- Lưu ý khi nâng cấp CSDL cũ: nếu ALTER này báo lỗi trùng lặp, nghĩa là CSDL
-- đã có sẵn dữ liệu trùng mã từ trước (đúng lỗi mà ràng buộc này ngăn chặn) —
-- cần dò và xử lý thủ công các dòng trùng trước khi chạy lại.
CALL create_unique_index_if_not_exists('docs', 'uq_docs_code_version', 'code, version_no');

-- Migrate cho CSDL đã tồn tại từ trước (không có sẵn các cột trên): thêm cột
-- nếu thiếu, rồi gán mỗi tài liệu cũ thành nhóm 1 phiên bản của chính nó.
-- PHẢI chạy trước CREATE INDEX bên dưới vì CSDL cũ chưa có cột doc_group_id.
CALL add_column_if_not_exists('depts', 'abbr', 'VARCHAR(20) NOT NULL DEFAULT \'\'');
CALL add_column_if_not_exists('cats', 'abbr', 'VARCHAR(20) NOT NULL DEFAULT \'\'');
CALL add_column_if_not_exists('docs', 'doc_group_id', 'BIGINT');
CALL add_column_if_not_exists('docs', 'version_no', 'INT NOT NULL DEFAULT 1');
CALL add_column_if_not_exists('users', 'active', 'BOOLEAN NOT NULL DEFAULT TRUE');
CALL add_column_if_not_exists('docs', 'deleted_at', 'DATETIME NULL DEFAULT NULL');
CALL add_column_if_not_exists('docs', 'deleted_by', 'VARCHAR(100) NULL DEFAULT NULL');
CALL add_column_if_not_exists('docs', 'file_path', 'VARCHAR(500) NULL DEFAULT NULL');
UPDATE docs SET doc_group_id = id WHERE doc_group_id IS NULL;

CALL create_index_if_not_exists('docs', 'idx_docs_group', 'doc_group_id');
CALL create_index_if_not_exists('docs', 'idx_docs_deleted_at', 'deleted_at');

-- 5. Bảng Quy Trình
CREATE TABLE IF NOT EXISTS workflows (
    id VARCHAR(100) PRIMARY KEY,
    name VARCHAR(255),
    steps JSON
);

-- 6. Bảng Cấu Hình Ứng Dụng (Gán quy trình phòng ban, Cấu hình Email SMTP)
CREATE TABLE IF NOT EXISTS app_configs (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value JSON
);

-- 7. Bảng Log Hệ Thống
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGINT PRIMARY KEY,
    timestamp VARCHAR(100),
    username VARCHAR(100),
    fullName VARCHAR(255),
    ipAddress VARCHAR(100),
    module VARCHAR(100),
    actionType VARCHAR(100),
    targetObject VARCHAR(255),
    description TEXT,
    status VARCHAR(50)
);

-- 8. Module Quản Lý Bản Quyền Phần Mềm — Giai đoạn 1 (nền tảng): Công ty, cây
-- Đơn vị tổ chức (N cấp, tự tham chiếu qua parent_id, KHÔNG cứng 4 cấp), Nhân
-- viên, Danh mục phần mềm. Độc lập hoàn toàn với depts/users của module Quản
-- lý Tài liệu (theo yêu cầu — nhân sự giữ bản quyền không nhất thiết có tài
-- khoản đăng nhập DMS).
CREATE TABLE IF NOT EXISTS lic_companies (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    code VARCHAR(20) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS lic_org_units (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    company_id BIGINT NOT NULL,
    parent_id BIGINT NULL DEFAULT NULL,
    name VARCHAR(255) NOT NULL,
    level_label VARCHAR(50) NOT NULL,
    sort_order INT NOT NULL DEFAULT 0
);
CALL create_index_if_not_exists('lic_org_units', 'idx_lic_org_units_company', 'company_id');
CALL create_index_if_not_exists('lic_org_units', 'idx_lic_org_units_parent', 'parent_id');

CREATE TABLE IF NOT EXISTS lic_employees (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    org_unit_id BIGINT NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NULL DEFAULT NULL,
    employee_code VARCHAR(50) NULL DEFAULT NULL,
    email VARCHAR(255) NULL DEFAULT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CALL create_index_if_not_exists('lic_employees', 'idx_lic_employees_org_unit', 'org_unit_id');

CREATE TABLE IF NOT EXISTS lic_software_catalog (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    code VARCHAR(50) NOT NULL,
    default_duration_months INT NULL DEFAULT NULL,
    max_assignees INT NOT NULL DEFAULT 1,
    allow_cross_company_share TINYINT(1) NOT NULL DEFAULT 0,
    license_type VARCHAR(20) NOT NULL DEFAULT 'TERM'
);
-- Nâng cấp CSDL cũ: thêm cột thời hạn mặc định (tháng) cho từng phần mềm —
-- NULL nghĩa là chưa cấu hình, khi tạo hạng mục kỳ mua vẫn phải nhập tay
-- Ngày hết hạn như trước; có cấu hình thì tự tính = hôm nay + số tháng này.
CALL add_column_if_not_exists('lic_software_catalog', 'default_duration_months', 'INT NULL DEFAULT NULL');
-- Nâng cấp CSDL cũ: số người tối đa được phép gán chung 1 mã (mặc định 1 =
-- hành vi cũ, 1 mã chỉ 1 người); cờ cho phép dùng chung mã khác công ty; loại
-- license (PERPETUAL = vĩnh viễn, TERM = có thời hạn, MAINTENANCE = bảo trì).
CALL add_column_if_not_exists('lic_software_catalog', 'max_assignees', 'INT NOT NULL DEFAULT 1');
CALL add_column_if_not_exists('lic_software_catalog', 'allow_cross_company_share', 'TINYINT(1) NOT NULL DEFAULT 0');
CALL add_column_if_not_exists('lic_software_catalog', 'license_type', "VARCHAR(20) NOT NULL DEFAULT 'TERM'");

-- Phát hành license: MỖI LẦN phát hành cho 1 công ty + 1 phần mềm là 1 lần
-- "gia hạn" — số lượng nhập vào là TỔNG SỐ LƯỢNG MONG MUỐN hiện tại (không
-- phải số mã mới cộng dồn). Hệ thống tự tính chênh lệch so với số mã đang có
-- để CHỈ SINH THÊM đúng phần chênh (mã cũ đã gán người dùng giữ nguyên), rồi
-- CẬP NHẬT ngày hết hạn cho TOÀN BỘ mã cũ + mã mới của công ty+phần mềm đó về
-- ngày hết hạn của lần phát hành này. Mua ít hơn số đang có KHÔNG tự xóa/thu
-- hồi gì — Admin chủ động thu hồi tay ở tab Phân bổ (VD nhân sự đã nghỉ việc).
-- lic_license_batches giờ là LỊCH SỬ các lần phát hành (không còn là nơi lưu
-- ngày hết hạn áp dụng cho mã — ngày hết hạn nằm trực tiếp ở lic_license_codes
-- vì nó được cập nhật hàng loạt độc lập với lô đã sinh ra mã).
-- expiry_date cho phép NULL: phần mềm loại "Vĩnh viễn" (PERPETUAL) không có
-- ngày hết hạn.
CREATE TABLE IF NOT EXISTS lic_license_batches (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    company_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    total_quantity INT NOT NULL DEFAULT 0,
    codes_generated INT NOT NULL DEFAULT 0,
    issued_date DATE NOT NULL,
    expiry_date DATE NULL DEFAULT NULL,
    note VARCHAR(500) NULL DEFAULT NULL,
    created_at VARCHAR(100)
);
CALL create_index_if_not_exists('lic_license_batches', 'idx_lic_license_batches_company', 'company_id');
CALL create_index_if_not_exists('lic_license_batches', 'idx_lic_license_batches_software', 'software_id');
-- Nâng cấp CSDL cũ (bản trước dùng cột "quantity" là số mã sinh ra ngay từ đầu).
CALL add_column_if_not_exists('lic_license_batches', 'total_quantity', 'INT NOT NULL DEFAULT 0');
CALL add_column_if_not_exists('lic_license_batches', 'codes_generated', 'INT NOT NULL DEFAULT 0');
-- Nâng cấp CSDL cũ: nới lỏng expiry_date thành cho phép NULL (license Vĩnh
-- viễn không có ngày hết hạn) — MODIFY COLUMN là cú pháp chuẩn, chạy được
-- trên cả MySQL lẫn MariaDB, không cần thủ tục IF NOT EXISTS.
ALTER TABLE lic_license_batches MODIFY COLUMN expiry_date DATE NULL DEFAULT NULL;
-- Nếu CSDL cũ còn cột "quantity" (bản trước khi có Kỳ mua), chuyển toàn bộ
-- lịch sử phát hành cũ sang total_quantity/codes_generated (dùng SQL động vì
-- cài đặt mới hoàn toàn không có cột "quantity" nên không thể tham chiếu
-- thẳng trong câu UPDATE tĩnh — sẽ báo lỗi "unknown column" nếu không có cột).
SET @has_old_quantity_col = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lic_license_batches' AND COLUMN_NAME = 'quantity'
);
SET @migrate_old_quantity_sql = IF(@has_old_quantity_col > 0,
    'UPDATE lic_license_batches SET total_quantity = quantity, codes_generated = quantity WHERE total_quantity = 0 AND quantity IS NOT NULL',
    'SELECT 1');
PREPARE stmt_migrate_quantity FROM @migrate_old_quantity_sql;
EXECUTE stmt_migrate_quantity;
DEALLOCATE PREPARE stmt_migrate_quantity;

-- Mã license lẻ: company_id/software_id/expiry_date lưu trực tiếp (không tra
-- qua batch) vì ngày hết hạn được cập nhật hàng loạt theo công ty+phần mềm ở
-- mỗi lần gia hạn, độc lập với lô nào đã sinh ra mã. batch_id chỉ để tra cứu
-- lịch sử mã này được sinh ra ở lần phát hành nào.
-- Việc gán người dùng cho mã KHÔNG còn là 1-1 (xem lic_license_code_assignments
-- bên dưới) — 1 mã có thể gán cho nhiều người (tối đa theo
-- lic_software_catalog.max_assignees) để hỗ trợ license dùng chung.
CREATE TABLE IF NOT EXISTS lic_license_codes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    batch_id BIGINT NOT NULL,
    company_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    code VARCHAR(100) UNIQUE NOT NULL,
    expiry_date DATE NULL DEFAULT NULL
);
-- Nâng cấp CSDL cũ: thêm cột company_id/software_id/expiry_date TRƯỚC khi tạo
-- index dùng tới chúng (bản trước không có các cột này, lưu ngày hết hạn qua
-- batch) — PHẢI đứng trước CREATE INDEX idx_lic_license_codes_company_software
-- bên dưới, nếu không CSDL cũ sẽ báo lỗi "column doesn't exist" khi tạo index.
CALL add_column_if_not_exists('lic_license_codes', 'company_id', 'BIGINT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_license_codes', 'software_id', 'BIGINT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_license_codes', 'expiry_date', 'DATE NULL DEFAULT NULL');
ALTER TABLE lic_license_codes MODIFY COLUMN expiry_date DATE NULL DEFAULT NULL;
UPDATE lic_license_codes c JOIN lic_license_batches b ON b.id = c.batch_id
    SET c.company_id = b.company_id, c.software_id = b.software_id, c.expiry_date = b.expiry_date
    WHERE c.company_id IS NULL;
CALL create_index_if_not_exists('lic_license_codes', 'idx_lic_license_codes_batch', 'batch_id');
CALL create_index_if_not_exists('lic_license_codes', 'idx_lic_license_codes_company_software', 'company_id, software_id');

-- Bảng gán mã license cho nhân viên — nhiều-nhiều (thay cho cột đơn
-- assigned_employee_id của bản trước) để hỗ trợ 1 mã dùng chung cho nhiều
-- người (VD license theo gói nhiều chỗ ngồi). Số lượng người được gán tối đa
-- cho 1 mã do lic_software_catalog.max_assignees quyết định, kiểm tra ở server.
CREATE TABLE IF NOT EXISTS lic_license_code_assignments (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    code_id BIGINT NOT NULL,
    employee_id BIGINT NOT NULL,
    assigned_at DATE NOT NULL,
    UNIQUE KEY uq_lic_code_assignment (code_id, employee_id)
);
CALL create_index_if_not_exists('lic_license_code_assignments', 'idx_lic_code_assign_code', 'code_id');
CALL create_index_if_not_exists('lic_license_code_assignments', 'idx_lic_code_assign_employee', 'employee_id');
-- Nâng cấp CSDL cũ: di chuyển dữ liệu gán 1-1 cũ (cột assigned_employee_id)
-- sang bảng nhiều-nhiều mới trước khi xóa cột cũ — dùng SQL động vì cài đặt
-- mới hoàn toàn không có cột này nên không thể tham chiếu thẳng trong câu
-- INSERT/SELECT tĩnh (sẽ báo lỗi "unknown column" nếu không có cột).
SET @has_old_assigned_col = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'lic_license_codes' AND COLUMN_NAME = 'assigned_employee_id'
);
SET @migrate_old_assign_sql = IF(@has_old_assigned_col > 0,
    'INSERT IGNORE INTO lic_license_code_assignments (code_id, employee_id, assigned_at) '
    'SELECT id, assigned_employee_id, COALESCE(assigned_at, CURDATE()) FROM lic_license_codes WHERE assigned_employee_id IS NOT NULL',
    'SELECT 1');
PREPARE stmt_migrate_assign FROM @migrate_old_assign_sql;
EXECUTE stmt_migrate_assign;
DEALLOCATE PREPARE stmt_migrate_assign;
CALL drop_column_if_exists('lic_license_codes', 'assigned_employee_id');
CALL drop_column_if_exists('lic_license_codes', 'assigned_at');

-- 9. Module Đăng ký / Phát hành đăng ký mua bản quyền — Admin tạo "Kỳ mua",
-- định nghĩa phần mềm + đơn giá + ngày hết hạn dự kiến cho kỳ đó; các công ty
-- vào đăng ký nhu cầu (tham khảo số lượng đang dùng, tự nhập số lượng mới
-- mong muốn); Admin duyệt/từ chối. Độc lập với việc phát hành license thực tế
-- (Admin vẫn chủ động vào tab Phát hành license để sinh mã).
CREATE TABLE IF NOT EXISTS lic_purchase_rounds (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    note VARCHAR(500) NULL DEFAULT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    created_at VARCHAR(100)
);

-- expiry_date cho phép NULL: hạng mục phần mềm loại "Vĩnh viễn" không có hạn.
CREATE TABLE IF NOT EXISTS lic_purchase_round_items (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL,
    expiry_date DATE NULL DEFAULT NULL
);
CALL create_index_if_not_exists('lic_purchase_round_items', 'idx_lic_round_items_round', 'round_id');
ALTER TABLE lic_purchase_round_items MODIFY COLUMN expiry_date DATE NULL DEFAULT NULL;

CREATE TABLE IF NOT EXISTS lic_purchase_registrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    round_item_id BIGINT NOT NULL,
    company_id BIGINT NOT NULL,
    current_quantity INT NOT NULL DEFAULT 0,
    requested_quantity INT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL,
    total_amount DECIMAL(18,2) NOT NULL,
    expiry_date DATE NULL DEFAULT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    note VARCHAR(500) NULL DEFAULT NULL,
    created_at VARCHAR(100),
    decided_by VARCHAR(100) NULL DEFAULT NULL,
    decided_at VARCHAR(100) NULL DEFAULT NULL
);
CALL create_index_if_not_exists('lic_purchase_registrations', 'idx_lic_reg_round', 'round_id');
CALL create_index_if_not_exists('lic_purchase_registrations', 'idx_lic_reg_company', 'company_id');
ALTER TABLE lic_purchase_registrations MODIFY COLUMN expiry_date DATE NULL DEFAULT NULL;

-- 10. Module Ngân sách — ĐỘC LẬP hoàn toàn với Kỳ mua bản quyền ở trên (không
-- liên kết dữ liệu, không tự sinh Kỳ mua). Dùng để LẬP DỰ TRÙ ngân sách theo
-- kỳ (vd năm/quý) TRƯỚC khi mở Kỳ mua thật: Admin tạo Kỳ ngân sách + hạng mục
-- phần mềm (đơn giá dự kiến); dự trù được nhập theo TỪNG ĐƠN VỊ TRỰC THUỘC
-- (org_unit, chi tiết hơn cấp công ty của Kỳ mua) — hệ thống tự tính số lượng
-- license đang thực sự được gán cho nhân viên trong đơn vị đó (kể cả các đơn
-- vị con bên dưới) để gợi ý tham khảo; mỗi dòng dự trù có trạng thái
-- PENDING/APPROVED/REJECTED, Admin duyệt riêng từng dòng — sau khi duyệt xong,
-- Admin tự tay tạo Kỳ mua thật dựa trên số liệu đã tổng hợp (không tự động).
CREATE TABLE IF NOT EXISTS lic_budget_rounds (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    note VARCHAR(500) NULL DEFAULT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    created_at VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS lic_budget_round_items (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL
);
CALL create_index_if_not_exists('lic_budget_round_items', 'idx_lic_budget_items_round', 'round_id');

CREATE TABLE IF NOT EXISTS lic_budget_registrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    round_item_id BIGINT NOT NULL,
    org_unit_id BIGINT NOT NULL,
    current_quantity INT NOT NULL DEFAULT 0,
    requested_quantity INT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL,
    total_amount DECIMAL(18,2) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    note VARCHAR(500) NULL DEFAULT NULL,
    created_at VARCHAR(100),
    decided_by VARCHAR(100) NULL DEFAULT NULL,
    decided_at VARCHAR(100) NULL DEFAULT NULL
);
CALL create_index_if_not_exists('lic_budget_registrations', 'idx_lic_budget_reg_round', 'round_id');
CALL create_index_if_not_exists('lic_budget_registrations', 'idx_lic_budget_reg_orgunit', 'org_unit_id');

-- Snapshot tài khoản Active Directory lấy qua đồng bộ LDAP định kỳ — dùng để
-- đối chiếu với nhân viên đang giữ license (khớp theo email) ở tab Phân bổ.
-- disabled_at KHÔNG phải ngày AD thực sự disable account (AD không lưu sẵn
-- mốc này) — đây là ngày HỆ THỐNG lần đầu phát hiện tài khoản chuyển từ
-- active sang disable qua so sánh giữa 2 lần đồng bộ liên tiếp.
CREATE TABLE IF NOT EXISTS ad_accounts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    full_name VARCHAR(255) NULL DEFAULT NULL,
    email VARCHAR(255) NULL DEFAULT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    company VARCHAR(255) NULL DEFAULT NULL,
    org_unit VARCHAR(255) NULL DEFAULT NULL,
    disabled_at DATE NULL DEFAULT NULL,
    last_synced_at VARCHAR(100) NULL DEFAULT NULL
);
CALL create_index_if_not_exists('ad_accounts', 'idx_ad_accounts_email', 'email');

-- 11. Liên kết Kỳ mua với Kỳ ngân sách (tùy chọn) — Kỳ mua vẫn hoạt động độc
-- lập như trước nếu không chọn; nếu Admin chọn 1 Kỳ ngân sách khi tạo Kỳ mua,
-- mỗi lượt đăng ký mua trong kỳ đó sẽ tham chiếu thêm số lượng đã được duyệt
-- dự trù (cộng dồn theo mọi đơn vị trực thuộc của công ty đăng ký) cho đúng
-- phần mềm, hiển thị cột "Ngân sách" bên cạnh "Đang dùng"/"Mua thực tế" —
-- không thay đổi gì tới bảng lic_budget_* đã có.
CALL add_column_if_not_exists('lic_purchase_rounds', 'budget_round_id', 'BIGINT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_purchase_registrations', 'budget_quantity', 'INT NULL DEFAULT NULL');

-- 12. Phạm vi cho Kỳ mua / Kỳ ngân sách — mỗi Kỳ Admin tạo gắn đúng 1 phạm vi:
-- 'COMPANY' (scope_id = id trong lic_companies, áp dụng cho toàn bộ công ty đó)
-- hoặc 'ORG_UNIT' (scope_id = id trong lic_org_units, áp dụng cho đúng 1
-- khối/phòng/ban đó và mọi đơn vị con bên dưới). NULL = chưa gán phạm vi (dữ
-- liệu cũ trước khi có tính năng này, hoặc admin bỏ trống — vẫn hoạt động như
-- trước, không giới hạn ai được đăng ký). Chỉ tài khoản có phạm vi tự phục vụ
-- (lưu trong users.perms, không cần cột riêng) khớp với phạm vi của Kỳ mới tự
-- đăng ký/dự trù được; Admin luôn có thể tạo Kỳ và duyệt không phụ thuộc phạm vi.
CALL add_column_if_not_exists('lic_purchase_rounds', 'scope_type', "ENUM('COMPANY','ORG_UNIT') NULL DEFAULT NULL");
CALL add_column_if_not_exists('lic_purchase_rounds', 'scope_id', 'BIGINT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_budget_rounds', 'scope_type', "ENUM('COMPANY','ORG_UNIT') NULL DEFAULT NULL");
CALL add_column_if_not_exists('lic_budget_rounds', 'scope_id', 'BIGINT NULL DEFAULT NULL');

-- 13. Kỳ mua 2 loại: 'RENEWAL' (gia hạn — giữ nguyên logic cũ: đối chiếu SL
-- đang dùng, hạng mục kỳ có sẵn Ngày hết hạn áp dụng chung, đăng ký hiện Hạn
-- hiện tại/Hạn mới) và 'NEW' (mua mới — hạng mục kỳ KHÔNG cần Ngày hết hạn vì
-- chưa biết trước, đăng ký chỉ hiện Đang dùng + SL mua thêm, Ngày hết hạn
-- được nhập trực tiếp lúc Phát hành). Dữ liệu Kỳ cũ trước tính năng này mặc
-- định RENEWAL — giữ nguyên 100% hành vi trước đây.
CALL add_column_if_not_exists('lic_purchase_rounds', 'round_type', "ENUM('RENEWAL','NEW') NOT NULL DEFAULT 'RENEWAL'");
-- Phát hành license nay BẮT BUỘC gắn với 1 đăng ký đã duyệt (không còn phát
-- hành tự do ngoài Kỳ mua) — theo dõi đăng ký đã được phát hành bằng lô nào,
-- số lượng THỰC TẾ phát hành (có thể khác số đã duyệt nếu Admin điều chỉnh
-- lúc phát hành) và thời điểm phát hành. issued_batch_id NULL = chưa phát
-- hành. registration_id trên lic_license_batches NULL cho các lô lịch sử đã
-- phát hành trước khi có tính năng này (không hồi tố).
CALL add_column_if_not_exists('lic_purchase_registrations', 'issued_batch_id', 'BIGINT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_purchase_registrations', 'issued_quantity', 'INT NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_purchase_registrations', 'issued_at', 'VARCHAR(100) NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_license_batches', 'registration_id', 'BIGINT NULL DEFAULT NULL');
CALL create_index_if_not_exists('lic_purchase_registrations', 'idx_lic_reg_issued_batch', 'issued_batch_id');
CALL create_index_if_not_exists('lic_license_batches', 'idx_lic_license_batches_registration', 'registration_id');

-- 14. Kỳ ngân sách mở rộng: hạng mục không còn giới hạn chỉ Phần mềm — thêm
-- item_type ('SOFTWARE' giữ nguyên hành vi cũ liên kết lic_software_catalog,
-- 'HARDWARE'/'SERVICE' nhập tên tự do qua item_name, không liên kết danh mục
-- nào — vì phần cứng/dịch vụ không có "SL đang dùng" tự động như license).
-- capex_opex BẮT BUỘC chọn khi tạo hạng mục (không tự gợi ý theo license_type
-- hay bất kỳ suy đoán nào) — dùng để gộp báo cáo CAPEX/OPEX sau này. Dữ liệu
-- hạng mục cũ trước tính năng này mặc định SOFTWARE/OPEX (không hồi tố phân
-- loại — Admin có thể sửa lại thủ công nếu cần).
CALL add_column_if_not_exists('lic_budget_round_items', 'item_type', "ENUM('SOFTWARE','HARDWARE','SERVICE') NOT NULL DEFAULT 'SOFTWARE'");
CALL add_column_if_not_exists('lic_budget_round_items', 'item_name', 'VARCHAR(255) NULL DEFAULT NULL');
CALL add_column_if_not_exists('lic_budget_round_items', 'capex_opex', "ENUM('CAPEX','OPEX') NOT NULL DEFAULT 'OPEX'");
ALTER TABLE lic_budget_round_items MODIFY COLUMN software_id BIGINT NULL DEFAULT NULL;

-- Sổ ghi nhận mua thực tế (nhiều dòng theo thời gian) cho từng hạng mục ngân
-- sách — ĐỘC LẬP với lic_budget_registrations (dự trù theo đơn vị): "Kế
-- hoạch" = tổng dự trù đã duyệt của hạng mục, "Thực tế" = tổng các dòng ở
-- đây, dùng để so sánh dự trù vs thực hiện. Không gắn với đơn vị trực thuộc
-- vì 1 lần mua thực tế có thể gộp chung cho nhiều đơn vị hoặc cả kỳ.
CREATE TABLE IF NOT EXISTS lic_budget_actuals (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_item_id BIGINT NOT NULL,
    purchase_date DATE NOT NULL,
    vendor VARCHAR(255) NULL DEFAULT NULL,
    quantity DECIMAL(18,2) NOT NULL DEFAULT 1,
    unit_price DECIMAL(18,2) NOT NULL,
    amount DECIMAL(18,2) NOT NULL,
    note VARCHAR(500) NULL DEFAULT NULL,
    created_by VARCHAR(100) NULL DEFAULT NULL,
    created_at VARCHAR(100)
);
CALL create_index_if_not_exists('lic_budget_actuals', 'idx_lic_budget_actuals_item', 'round_item_id');

-- 15. Theo dõi ngân sách theo Công ty: "Kế hoạch" (dự trù đã duyệt) đã suy ra
-- được theo công ty sẵn qua lic_budget_registrations.org_unit_id ->
-- lic_org_units.company_id, không cần cột mới. Nhưng "Thực tế" (mua thực tế)
-- không gắn đơn vị trực thuộc (1 lần mua có thể gộp chung nhiều công ty) nên
-- cần company_id RIÊNG, TÙY CHỌN — để trống khi mua chung/không phân bổ theo
-- công ty cụ thể (vẫn tính vào tổng thực tế của hạng mục, chỉ không gộp được
-- vào báo cáo theo công ty).
CALL add_column_if_not_exists('lic_budget_actuals', 'company_id', 'BIGINT NULL DEFAULT NULL');
CALL create_index_if_not_exists('lic_budget_actuals', 'idx_lic_budget_actuals_company', 'company_id');

-- 16. Module Quản lý CNTT: theo dõi ngày hết hạn các dịch vụ/bản quyền do
-- CNTT quản lý (cước Internet, bản quyền Firewall, tên miền, SSL, email,
-- phần mềm hệ thống, phần mềm khác...) và tự động gửi email nhắc trước khi
-- hết hạn theo cấu hình. Danh mục (it_categories) tự cấu hình được (không cố
-- định cứng trong code), giống Phòng ban/Phân loại của module Tài liệu.
CREATE TABLE IF NOT EXISTS it_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    sort_order INT NOT NULL DEFAULT 0
);

-- owner_user_id: người phụ trách là tài khoản hệ thống (tùy chọn) — dùng để
-- lấy email gửi nhắc. owner_email: dự phòng khi người phụ trách KHÔNG có tài
-- khoản trong hệ thống (vd nhà cung cấp bên ngoài) — nhập tay. Cả 2 đều tùy
-- chọn; nếu bỏ trống cả 2 thì chỉ Admin nhận được email nhắc hết hạn.
-- active=0: tạm ngừng theo dõi/nhắc hẹn mà không mất lịch sử (khác xóa hẳn).
CREATE TABLE IF NOT EXISTS it_items (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    category_id INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(255) NULL DEFAULT NULL,
    description VARCHAR(1000) NULL DEFAULT NULL,
    start_date DATE NULL DEFAULT NULL,
    expiry_date DATE NOT NULL,
    cost DECIMAL(18,2) NULL DEFAULT NULL,
    owner_user_id BIGINT NULL DEFAULT NULL,
    owner_email VARCHAR(255) NULL DEFAULT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_by VARCHAR(100) NULL DEFAULT NULL,
    created_at VARCHAR(100),
    updated_at VARCHAR(100)
);
CALL create_index_if_not_exists('it_items', 'idx_it_items_category', 'category_id');
CALL create_index_if_not_exists('it_items', 'idx_it_items_expiry', 'expiry_date');

-- Sổ ghi nhận đã gửi nhắc — khóa theo (item_id, expiry_date, days_before) để
-- không gửi trùng trong 1 chu kỳ hạn; nếu đầu mục được gia hạn (expiry_date
-- đổi sang ngày mới) thì tự động được nhắc lại từ đầu vì cặp khóa đổi theo.
CREATE TABLE IF NOT EXISTS it_reminder_sent (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    item_id BIGINT NOT NULL,
    expiry_date DATE NOT NULL,
    days_before INT NOT NULL,
    sent_at VARCHAR(100)
);
CALL create_unique_index_if_not_exists('it_reminder_sent', 'uq_it_reminder_sent', 'item_id, expiry_date, days_before');

-- Dọn dẹp: xóa các thủ tục tạm sau khi dùng xong, không để lại trong CSDL thật.
DROP PROCEDURE IF EXISTS create_index_if_not_exists;
DROP PROCEDURE IF EXISTS create_unique_index_if_not_exists;
DROP PROCEDURE IF EXISTS add_column_if_not_exists;
DROP PROCEDURE IF EXISTS drop_column_if_exists;

-- Khởi tạo Dữ liệu Mẫu Ban Đầu Cho Môi Trường Mới (Chỉ tạo Admin gốc nếu chưa tồn tại)
INSERT INTO depts (name, abbr) VALUES ('Phòng IT', 'IT'), ('Phòng Nhân Sự', 'NS'), ('Phòng Kế Toán', 'KT'), ('Ban Giám Đốc', 'BGD')
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO cats (name, abbr) VALUES ('Quy trình / Quy định', 'QT'), ('Báo cáo tài chính', 'BC'), ('Hợp đồng / Hồ sơ', 'HD')
ON DUPLICATE KEY UPDATE name=name;

-- Mật khẩu mặc định: Admin@123456 (đã hash bằng bcrypt, cost=12).
-- BẮT BUỘC đổi mật khẩu này ngay sau lần đăng nhập đầu tiên trên môi trường production.
INSERT INTO users (username, pass, name, email, phone, dept, perms) VALUES
('admin', '$2b$12$oMp2RrpBU3Yij0zky5NVGeWI5FUPjHKZh7Bi3zX/NHT5olFKfDLSW', 'Quản Trị Viên Hệ Thống', 'admin@company.com', '0901112223', 'Phòng IT', '{"admin": true, "uploadAll": true, "uploadDepts": [], "viewDraftAll": true, "viewDraftDepts": [], "viewApprovedAll": true, "viewApprovedDepts": [], "downloadAll": true, "downloadDepts": []}')
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO workflows (id, name, steps) VALUES 
('WF_1STEP', 'Quy trình 1 bước (Lãnh đạo duyệt)', '[{"order": 1, "name": "Phê duyệt"}]'),
('WF_2STEP', 'Quy trình 2 bước (Trưởng phòng -> BGD)', '[{"order": 1, "name": "Trưởng Phòng"}, {"order": 2, "name": "Ban Giám Đốc"}]')
ON DUPLICATE KEY UPDATE name=name;