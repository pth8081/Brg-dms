CREATE DATABASE IF NOT EXISTS dms_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dms_db;

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

-- Migrate cho CSDL đã tồn tại từ trước (không có sẵn các cột trên): thêm cột
-- nếu thiếu, rồi gán mỗi tài liệu cũ thành nhóm 1 phiên bản của chính nó.
-- PHẢI chạy trước CREATE INDEX bên dưới vì CSDL cũ chưa có cột doc_group_id.
ALTER TABLE depts ADD COLUMN IF NOT EXISTS abbr VARCHAR(20) NOT NULL DEFAULT '';
ALTER TABLE cats ADD COLUMN IF NOT EXISTS abbr VARCHAR(20) NOT NULL DEFAULT '';
ALTER TABLE docs ADD COLUMN IF NOT EXISTS doc_group_id BIGINT;
ALTER TABLE docs ADD COLUMN IF NOT EXISTS version_no INT NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE docs ADD COLUMN IF NOT EXISTS deleted_at DATETIME NULL DEFAULT NULL;
ALTER TABLE docs ADD COLUMN IF NOT EXISTS deleted_by VARCHAR(100) NULL DEFAULT NULL;
ALTER TABLE docs ADD COLUMN IF NOT EXISTS file_path VARCHAR(500) NULL DEFAULT NULL;
UPDATE docs SET doc_group_id = id WHERE doc_group_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_docs_group ON docs (doc_group_id);
CREATE INDEX IF NOT EXISTS idx_docs_deleted_at ON docs (deleted_at);

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
CREATE INDEX IF NOT EXISTS idx_lic_org_units_company ON lic_org_units (company_id);
CREATE INDEX IF NOT EXISTS idx_lic_org_units_parent ON lic_org_units (parent_id);

CREATE TABLE IF NOT EXISTS lic_employees (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    org_unit_id BIGINT NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    title VARCHAR(255) NULL DEFAULT NULL,
    employee_code VARCHAR(50) NULL DEFAULT NULL,
    email VARCHAR(255) NULL DEFAULT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_lic_employees_org_unit ON lic_employees (org_unit_id);

CREATE TABLE IF NOT EXISTS lic_software_catalog (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    code VARCHAR(50) NOT NULL
);

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
CREATE TABLE IF NOT EXISTS lic_license_batches (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    company_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    total_quantity INT NOT NULL DEFAULT 0,
    codes_generated INT NOT NULL DEFAULT 0,
    issued_date DATE NOT NULL,
    expiry_date DATE NOT NULL,
    note VARCHAR(500) NULL DEFAULT NULL,
    created_at VARCHAR(100)
);
CREATE INDEX IF NOT EXISTS idx_lic_license_batches_company ON lic_license_batches (company_id);
CREATE INDEX IF NOT EXISTS idx_lic_license_batches_software ON lic_license_batches (software_id);
-- Nâng cấp CSDL cũ (bản trước dùng cột "quantity" là số mã sinh ra ngay từ đầu).
ALTER TABLE lic_license_batches ADD COLUMN IF NOT EXISTS total_quantity INT NOT NULL DEFAULT 0;
ALTER TABLE lic_license_batches ADD COLUMN IF NOT EXISTS codes_generated INT NOT NULL DEFAULT 0;

-- Mã license lẻ: company_id/software_id/expiry_date lưu trực tiếp (không tra
-- qua batch) vì ngày hết hạn được cập nhật hàng loạt theo công ty+phần mềm ở
-- mỗi lần gia hạn, độc lập với lô nào đã sinh ra mã. batch_id chỉ để tra cứu
-- lịch sử mã này được sinh ra ở lần phát hành nào.
CREATE TABLE IF NOT EXISTS lic_license_codes (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    batch_id BIGINT NOT NULL,
    company_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    code VARCHAR(100) UNIQUE NOT NULL,
    expiry_date DATE NOT NULL,
    assigned_employee_id BIGINT NULL DEFAULT NULL,
    assigned_at DATE NULL DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_lic_license_codes_batch ON lic_license_codes (batch_id);
CREATE INDEX IF NOT EXISTS idx_lic_license_codes_employee ON lic_license_codes (assigned_employee_id);
CREATE INDEX IF NOT EXISTS idx_lic_license_codes_company_software ON lic_license_codes (company_id, software_id);
-- Nâng cấp CSDL cũ: thêm cột rồi lấy company_id/software_id/expiry_date từ
-- batch gốc (bản trước lưu ngày hết hạn qua batch).
ALTER TABLE lic_license_codes ADD COLUMN IF NOT EXISTS company_id BIGINT NULL DEFAULT NULL;
ALTER TABLE lic_license_codes ADD COLUMN IF NOT EXISTS software_id BIGINT NULL DEFAULT NULL;
ALTER TABLE lic_license_codes ADD COLUMN IF NOT EXISTS expiry_date DATE NULL DEFAULT NULL;
UPDATE lic_license_codes c JOIN lic_license_batches b ON b.id = c.batch_id
    SET c.company_id = b.company_id, c.software_id = b.software_id, c.expiry_date = b.expiry_date
    WHERE c.company_id IS NULL;

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

CREATE TABLE IF NOT EXISTS lic_purchase_round_items (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    software_id BIGINT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL,
    expiry_date DATE NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lic_round_items_round ON lic_purchase_round_items (round_id);

CREATE TABLE IF NOT EXISTS lic_purchase_registrations (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    round_id BIGINT NOT NULL,
    round_item_id BIGINT NOT NULL,
    company_id BIGINT NOT NULL,
    current_quantity INT NOT NULL DEFAULT 0,
    requested_quantity INT NOT NULL,
    unit_price DECIMAL(18,2) NOT NULL,
    total_amount DECIMAL(18,2) NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    note VARCHAR(500) NULL DEFAULT NULL,
    created_at VARCHAR(100),
    decided_by VARCHAR(100) NULL DEFAULT NULL,
    decided_at VARCHAR(100) NULL DEFAULT NULL
);
CREATE INDEX IF NOT EXISTS idx_lic_reg_round ON lic_purchase_registrations (round_id);
CREATE INDEX IF NOT EXISTS idx_lic_reg_company ON lic_purchase_registrations (company_id);

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