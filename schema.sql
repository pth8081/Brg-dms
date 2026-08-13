CREATE DATABASE IF NOT EXISTS dms_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dms_db;

-- 1. Bảng Phòng Ban
CREATE TABLE IF NOT EXISTS depts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

-- 2. Bảng Phân Loại Tài Liệu
CREATE TABLE IF NOT EXISTS cats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL
);

-- 3. Bảng Người Dùng & Phân Quyền
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    pass VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    phone VARCHAR(50),
    dept VARCHAR(255),
    perms JSON
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
    created_by VARCHAR(255),
    creator_username VARCHAR(100),
    created_at VARCHAR(100),
    workflow_id VARCHAR(100),
    current_step_order INT,
    status VARCHAR(50),
    history JSON
);

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

-- Khởi tạo Dữ liệu Mẫu Ban Đầu Cho Môi Trường Mới (Chỉ tạo Admin gốc nếu chưa tồn tại)
INSERT INTO depts (name) VALUES ('Phòng IT'), ('Phòng Nhân Sự'), ('Phòng Kế Toán'), ('Ban Giám Đốc')
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO cats (name) VALUES ('Quy trình / Quy định'), ('Báo cáo tài chính'), ('Hợp đồng / Hồ sơ')
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO users (username, pass, name, email, phone, dept, perms) VALUES 
('admin', 'Admin@123456', 'Quản Trị Viên Hệ Thống', 'admin@company.com', '0901112223', 'Phòng IT', '{"admin": true, "uploadAll": true, "uploadDepts": [], "viewDraftAll": true, "viewDraftDepts": [], "viewApprovedAll": true, "viewApprovedDepts": [], "downloadAll": true, "downloadDepts": []}')
ON DUPLICATE KEY UPDATE name=name;

INSERT INTO workflows (id, name, steps) VALUES 
('WF_1STEP', 'Quy trình 1 bước (Lãnh đạo duyệt)', '[{"order": 1, "name": "Phê duyệt"}]'),
('WF_2STEP', 'Quy trình 2 bước (Trưởng phòng -> BGD)', '[{"order": 1, "name": "Trưởng Phòng"}, {"order": 2, "name": "Ban Giám Đốc"}]')
ON DUPLICATE KEY UPDATE name=name;