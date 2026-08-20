require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { PDFDocument, rgb, degrees } = require('pdf-lib');
const fontkit = require('@pdf-lib/fontkit');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

if (process.env.TRUST_PROXY === 'true') {
    app.set('trust proxy', 1);
}

// --- BẢO MẬT: HTTP Security Headers ---
// CSP nới lỏng cho script-src/style-src 'unsafe-inline' vì frontend hiện dùng
// onclick= inline và <script>/<style> nội tuyến (chưa tách file riêng).
// LƯU Ý QUAN TRỌNG: script-src-attr là directive RIÊNG (CSP Level 3) áp dụng
// cho thuộc tính sự kiện inline (onclick=, onchange=...), TÁCH BIỆT với
// script-src. Helmet mặc định set script-src-attr: 'none' nếu không khai báo
// rõ, và giá trị đó SẼ GHI ĐÈ 'unsafe-inline' trong script-src đối với riêng
// onclick/onchange — làm toàn bộ nút bấm trong app ngừng hoạt động dù
// script-src đã cho phép 'unsafe-inline'. Phải khai báo scriptSrcAttr riêng.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com", "'unsafe-inline'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            frameSrc: ["'self'", "data:"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        }
    }
}));

// --- BẢO MẬT: CORS giới hạn theo whitelist (mặc định không cho cross-origin) ---
// Lưu ý: trình duyệt vẫn gửi header Origin cho các request fetch() same-origin
// (không chỉ request thật sự cross-origin), nên phải tự so sánh Origin với
// chính origin đang phục vụ request để không chặn nhầm request hợp lệ.
const allowedOrigins = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
app.use((req, res, next) => {
    const selfOrigin = `${req.protocol}://${req.get('host')}`;
    cors({
        origin(origin, callback) {
            if (!origin || origin === selfOrigin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }
            return callback(new Error('CORS: origin không được phép'));
        },
        credentials: true
    })(req, res, next);
});

app.use(cookieParser());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Cấu hình kết nối MySQL hỗ trợ Biến Môi Trường (Environment Variables)
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'dms_db',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    // Tăng lên để đáp ứng nhiều người dùng đồng thời (khoảng 200-300 người);
    // các truy vấn ở đây đa số ngắn nên pool lớn hơn giúp giảm thời gian chờ
    // giờ cao điểm mà không tốn nhiều tài nguyên CSDL.
    connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT, 10) || 60,
    queueLimit: 0
};

let pool;
async function initPool() {
    try {
        pool = mysql.createPool(dbConfig);
        await pool.query('SELECT 1');
        console.log('✅ Kết nối CSDL MySQL Production thành công!');
    } catch (err) {
        console.error('❌ Lỗi kết nối CSDL MySQL:', err.message);
    }
}
initPool();

// --- JWT ---
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    JWT_SECRET = crypto.randomBytes(48).toString('hex');
    console.warn('⚠️  Chưa cấu hình JWT_SECRET trong biến môi trường — đã sinh secret ngẫu nhiên tạm thời.');
    console.warn('⚠️  Phiên đăng nhập sẽ mất hiệu lực mỗi khi khởi động lại server. Vui lòng đặt JWT_SECRET cố định trong .env cho môi trường production.');
}
const TOKEN_COOKIE = 'dms_token';
const TOKEN_TTL = '8h';

function signToken(user) {
    return jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: TOKEN_TTL }
    );
}

function setAuthCookie(res, token) {
    res.cookie(TOKEN_COOKIE, token, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'strict',
        maxAge: 8 * 60 * 60 * 1000
    });
}

function sanitizeUser(u) {
    if (!u) return u;
    const { pass, ...rest } = u;
    return rest;
}

// --- AUDIT LOG TỰ ĐỘNG Ở SERVER ---
// Dùng cho các hành động nhạy cảm (đăng nhập/đăng xuất, xóa tài liệu...) —
// ghi trực tiếp từ server, không phụ thuộc client có chủ động gửi log lên
// hay không, đảm bảo không thể bỏ sót khi audit.
let serverLogIdSeq = 0;
async function writeAuditLog({ module, actionType, targetObject = '', description, status = 'SUCCESS', username, fullName, ip }) {
    const id = Date.now() * 1000 + (serverLogIdSeq++ % 1000);
    const timestamp = new Date().toLocaleString('vi-VN');
    try {
        await pool.query(
            'INSERT INTO system_logs (id, timestamp, username, fullName, ipAddress, module, actionType, targetObject, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [id, timestamp, username || 'system', fullName || 'Hệ Thống', ip || '', module, actionType, targetObject, description, status]
        );
    } catch (e) {
        console.error('❌ Lỗi ghi audit log:', e.message);
    }
}

// --- KIỂM TRA QUYỀN XEM/TẢI TÀI LIỆU (áp dụng cho dòng dữ liệu thô từ DB) ---
function canViewDocRow(user, doc, deptWorkflows) {
    if (user.perms.admin) return true;
    if (doc.status === 'APPROVED') {
        if (user.perms.viewApprovedAll) return true;
        if (user.perms.viewApprovedDepts && user.perms.viewApprovedDepts.includes(doc.dept)) return true;
    } else {
        if (user.perms.viewDraftAll) return true;
        if (user.perms.viewDraftDepts && user.perms.viewDraftDepts.includes(doc.dept)) return true;
        if (doc.creator_username === user.username) return true;
    }
    const cfg = deptWorkflows[doc.dept];
    if (cfg && cfg.approvers && cfg.approvers[doc.current_step_order] === user.username) return true;
    return false;
}

function canDownloadDocRow(user, doc) {
    if (user.perms.admin) return true;
    if (user.perms.downloadAll) return true;
    if (user.perms.downloadDepts && user.perms.downloadDepts.includes(doc.dept)) return true;
    return false;
}

// --- MIDDLEWARE XÁC THỰC / PHÂN QUYỀN ---
async function requireAuth(req, res, next) {
    try {
        const token = req.cookies[TOKEN_COOKIE];
        if (!token) return res.status(401).json({ error: 'Chưa đăng nhập.' });

        const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [payload.id]);
        const dbUser = rows[0];
        if (!dbUser) return res.status(401).json({ error: 'Tài khoản không tồn tại.' });
        if (!dbUser.active) return res.status(401).json({ error: 'Tài khoản đã bị khóa, vui lòng liên hệ quản trị viên.' });

        req.user = dbUser;
        req.user.perms = typeof dbUser.perms === 'string' ? JSON.parse(dbUser.perms || '{}') : (dbUser.perms || {});
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Phiên đăng nhập không hợp lệ hoặc đã hết hạn.' });
    }
}

function requireAdmin(req, res, next) {
    if (!req.user || !req.user.perms || !req.user.perms.admin) {
        return res.status(403).json({ error: 'Yêu cầu quyền Quản trị viên.' });
    }
    next();
}

// Lưu ý: mặc định express-rate-limit tính theo địa chỉ IP (req.ip). Nếu nhiều
// người dùng cùng ra internet qua 1 địa chỉ IP chung (NAT văn phòng — rất phổ
// biến), TẤT CẢ sẽ dùng chung 1 hạn mức bên dưới. Hạn mức được đặt đủ rộng để
// chịu tải khoảng 200-300 người dùng đồng thời sau chung 1 IP mà vẫn chặn
// được dò mật khẩu hàng loạt.
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // chỉ đếm số lần đăng nhập THẤT BẠI, không tính lần thành công
    message: { error: 'Quá nhiều lần đăng nhập thất bại. Vui lòng thử lại sau ít phút.' }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 6000,
    standardHeaders: true,
    legacyHeaders: false
});
app.use('/api', apiLimiter);

// --- API AUTH ---
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body || {};
        if (!username || !password) {
            return res.status(400).json({ error: 'Vui lòng nhập tên đăng nhập và mật khẩu.' });
        }

        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];
        if (!user) {
            await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_FAILED', status: 'FAILED', username, fullName: username, ip: req.ip, targetObject: username, description: `Đăng nhập thất bại: tài khoản [${username}] không tồn tại.` });
            return res.status(401).json({ error: 'Tài khoản hoặc mật khẩu không chính xác!' });
        }

        const ok = await bcrypt.compare(password, user.pass);
        if (!ok) {
            await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_FAILED', status: 'FAILED', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: `Đăng nhập thất bại: sai mật khẩu.` });
            return res.status(401).json({ error: 'Tài khoản hoặc mật khẩu không chính xác!' });
        }

        if (!user.active) {
            await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_FAILED', status: 'FAILED', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: `Đăng nhập thất bại: tài khoản đã bị khóa.` });
            return res.status(401).json({ error: 'Tài khoản đã bị khóa, vui lòng liên hệ quản trị viên.' });
        }

        const token = signToken(user);
        setAuthCookie(res, token);

        await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_SUCCESS', status: 'SUCCESS', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: 'Đăng nhập hệ thống thành công.' });

        const perms = typeof user.perms === 'string' ? JSON.parse(user.perms || '{}') : user.perms;
        res.json({ user: sanitizeUser({ ...user, perms }) });
    } catch (err) {
        console.error('❌ Lỗi đăng nhập:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/auth/logout', async (req, res) => {
    try {
        const token = req.cookies[TOKEN_COOKIE];
        if (token) {
            const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
            const [rows] = await pool.query('SELECT username, name FROM users WHERE id = ?', [payload.id]);
            if (rows[0]) {
                await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGOUT', status: 'SUCCESS', username: rows[0].username, fullName: rows[0].name, ip: req.ip, targetObject: rows[0].username, description: 'Đăng xuất khỏi hệ thống.' });
            }
        }
    } catch (e) { /* token không hợp lệ/hết hạn — vẫn cho đăng xuất bình thường, không chặn */ }

    res.clearCookie(TOKEN_COOKIE, { httpOnly: true, secure: isProd, sameSite: 'strict' });
    res.json({ success: true });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ user: sanitizeUser(req.user) });
});

// --- API CẬP NHẬT HỒ SƠ CÁ NHÂN (tự phục vụ, không cần quyền admin) ---
app.post('/api/profile', requireAuth, async (req, res) => {
    try {
        const { name, email, phone, newPassword } = req.body || {};
        if (!name || !email) {
            return res.status(400).json({ error: 'Họ tên và Email là bắt buộc.' });
        }
        if (newPassword && newPassword.length < 6) {
            return res.status(400).json({ error: 'Mật khẩu mới phải có ít nhất 6 ký tự.' });
        }

        let passHash = req.user.pass;
        if (newPassword) {
            passHash = await bcrypt.hash(newPassword, 12);
        }

        await pool.query(
            'UPDATE users SET name = ?, email = ?, phone = ?, pass = ? WHERE id = ?',
            [name, email, phone || '', passHash, req.user.id]
        );

        const [rows] = await pool.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
        const updated = rows[0];
        const perms = typeof updated.perms === 'string' ? JSON.parse(updated.perms || '{}') : updated.perms;
        res.json({ user: sanitizeUser({ ...updated, perms }) });
    } catch (err) {
        console.error('❌ Lỗi cập nhật hồ sơ:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- API BOOTSTRAP (Lấy toàn bộ dữ liệu khởi tạo cho 4 Module) ---
app.get('/api/bootstrap', requireAuth, async (req, res) => {
    try {
        const [depts] = await pool.query('SELECT id, name, abbr FROM depts');
        const [cats] = await pool.query('SELECT id, name, abbr FROM cats');
        const [users] = await pool.query('SELECT * FROM users');
        // Không lấy cột file_data (nội dung PDF dạng base64) ở đây — với nhiều
        // tài liệu/phiên bản và nhiều người dùng cùng đăng nhập, việc tải cả nội
        // dung file mọi tài liệu về ngay từ đầu rất nặng (băng thông + bộ nhớ).
        // Nội dung file chỉ tải riêng khi người dùng thực sự bấm Xem/Tải, qua
        // GET /api/docs/:id/file.
        const [docs] = await pool.query(
            `SELECT id, code, title, ver, dept, cat, summary, file_name, file_type, created_by,
                    creator_username, created_at, workflow_id, current_step_order, status, history,
                    doc_group_id, version_no
             FROM docs WHERE deleted_at IS NULL ORDER BY id DESC`
        );
        const [workflows] = await pool.query('SELECT * FROM workflows');
        const [configs] = await pool.query('SELECT * FROM app_configs');
        const [logs] = await pool.query('SELECT * FROM system_logs ORDER BY id DESC LIMIT 300');

        let configMap = {};
        configs.forEach(c => configMap[c.config_key] = c.config_value);

        res.json({
            depts: depts.map(d => ({ id: d.id, name: d.name, abbr: d.abbr })),
            cats: cats.map(c => ({ id: c.id, name: c.name, abbr: c.abbr })),
            users: users.map(u => sanitizeUser({ ...u, perms: typeof u.perms === 'string' ? JSON.parse(u.perms || '{}') : u.perms })),
            // Bảng docs lưu cột dạng snake_case (file_name, current_step_order...) nhưng
            // toàn bộ frontend dùng camelCase (fileName, currentStepOrder...) — phải ánh
            // xạ lại đây, nếu không mọi thao tác xem/tải/duyệt tài liệu cũ (đã qua
            // bootstrap) sẽ nhận giá trị undefined ngay sau khi tải lại trang.
            docs: docs.map(d => ({
                id: d.id,
                code: d.code,
                title: d.title,
                ver: d.ver,
                dept: d.dept,
                cat: d.cat,
                summary: d.summary,
                fileName: d.file_name,
                fileType: d.file_type,
                createdBy: d.created_by,
                creatorUsername: d.creator_username,
                createdAt: d.created_at,
                workflowId: d.workflow_id,
                currentStepOrder: d.current_step_order,
                status: d.status,
                history: typeof d.history === 'string' ? JSON.parse(d.history || '[]') : d.history,
                docGroupId: d.doc_group_id,
                versionNo: d.version_no
            })),
            workflows: workflows.map(w => ({ ...w, steps: typeof w.steps === 'string' ? JSON.parse(w.steps || '[]') : w.steps })),
            deptWorkflows: configMap.deptWorkflows || {},
            emailConfig: configMap.emailConfig || { enabled: true, smtpHost: 'smtp.gmail.com', smtpPort: 587, senderEmail: 'dms-noreply@company.com' },
            systemLogs: logs
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu bootstrap:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Các bảng cấu hình hệ thống chỉ Admin mới được ghi
const ADMIN_ONLY_TABLES = new Set(['users', 'workflows', 'depts', 'cats', 'deptWorkflows', 'emailConfig']);
const KNOWN_TABLES = new Set(['docs', 'users', 'depts', 'cats', 'workflows', 'deptWorkflows', 'emailConfig', 'system_logs']);
const MAX_SYNC_ROWS = 5000;

// --- API LẤY NỘI DUNG FILE THEO YÊU CẦU (không còn gửi kèm trong bootstrap) ---
// Kiểm tra quyền xem/tải Zero Trust ngay tại đây — không tin việc client chỉ
// hiển thị nút Xem/Tải là đã đủ, vì trước đây bootstrap gửi file_data của MỌI
// tài liệu cho MỌI người dùng đã đăng nhập (chỉ ẩn ở giao diện), nay đã khắc
// phục luôn cùng lúc với việc giảm tải bootstrap.
app.get('/api/docs/:id/file', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const mode = req.query.mode === 'download' ? 'download' : 'view';

        const [rows] = await pool.query('SELECT * FROM docs WHERE id = ? AND deleted_at IS NULL', [id]);
        const doc = rows[0];
        if (!doc) return res.status(404).json({ error: 'Không tìm thấy tài liệu.' });

        const [cfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'deptWorkflows'");
        const deptWorkflows = cfgRows[0]
            ? (typeof cfgRows[0].config_value === 'string' ? JSON.parse(cfgRows[0].config_value) : cfgRows[0].config_value)
            : {};

        const allowed = mode === 'download' ? canDownloadDocRow(req.user, doc) : canViewDocRow(req.user, doc, deptWorkflows);
        if (!allowed) return res.status(403).json({ error: 'Bạn không có quyền truy cập tài liệu này.' });

        res.json({ fileName: doc.file_name, fileType: doc.file_type, fileData: doc.file_data });
    } catch (err) {
        console.error('❌ Lỗi lấy nội dung file:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- API THÙNG RÁC / XÓA MỀM TÀI LIỆU (chỉ Admin) ---
app.get('/api/docs/trash', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT id, code, title, ver, dept, cat, created_by, creator_username, created_at,
                    doc_group_id, version_no, deleted_at, deleted_by
             FROM docs WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC`
        );
        res.json({
            docs: rows.map(d => ({
                id: d.id, code: d.code, title: d.title, ver: d.ver, dept: d.dept, cat: d.cat,
                createdBy: d.created_by, creatorUsername: d.creator_username, createdAt: d.created_at,
                docGroupId: d.doc_group_id, versionNo: d.version_no,
                deletedAt: d.deleted_at, deletedBy: d.deleted_by
            }))
        });
    } catch (err) {
        console.error('❌ Lỗi tải thùng rác:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

function parseGroupIds(body) {
    const groupIds = Array.isArray(body.groupIds) ? body.groupIds : [];
    return groupIds.filter(v => v !== null && v !== undefined && String(v).trim() !== '').slice(0, MAX_SYNC_ROWS);
}

app.post('/api/docs/delete', requireAuth, requireAdmin, async (req, res) => {
    try {
        const groupIds = parseGroupIds(req.body);
        if (groupIds.length === 0) return res.status(400).json({ error: 'Chưa chọn tài liệu nào để xóa.' });

        const placeholders = groupIds.map(() => '?').join(',');
        const [rows] = await pool.query(
            `SELECT id, code, doc_group_id FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NULL`,
            groupIds
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Không tìm thấy tài liệu để xóa (có thể đã bị xóa trước đó).' });

        await pool.query(
            `UPDATE docs SET deleted_at = NOW(), deleted_by = ? WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NULL`,
            [req.user.username, ...groupIds]
        );

        const codes = [...new Set(rows.map(r => r.code))];
        await writeAuditLog({
            module: 'INTERACTION', actionType: 'DELETE_DOC', status: 'SUCCESS',
            username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: codes.join(', '),
            description: `Xóa mềm ${rows.length} phiên bản tài liệu (${codes.length} nhóm): ${codes.join(', ')}`
        });

        res.json({ success: true, deletedCount: rows.length });
    } catch (err) {
        console.error('❌ Lỗi xóa tài liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/docs/restore', requireAuth, requireAdmin, async (req, res) => {
    try {
        const groupIds = parseGroupIds(req.body);
        if (groupIds.length === 0) return res.status(400).json({ error: 'Chưa chọn tài liệu nào để khôi phục.' });

        const placeholders = groupIds.map(() => '?').join(',');
        const [rows] = await pool.query(
            `SELECT id, code, doc_group_id FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Không tìm thấy tài liệu trong thùng rác.' });

        await pool.query(
            `UPDATE docs SET deleted_at = NULL, deleted_by = NULL WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );

        const codes = [...new Set(rows.map(r => r.code))];
        await writeAuditLog({
            module: 'INTERACTION', actionType: 'RESTORE_DOC', status: 'SUCCESS',
            username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: codes.join(', '),
            description: `Khôi phục ${rows.length} phiên bản tài liệu (${codes.length} nhóm): ${codes.join(', ')}`
        });

        res.json({ success: true, restoredCount: rows.length });
    } catch (err) {
        console.error('❌ Lỗi khôi phục tài liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/docs/purge', requireAuth, requireAdmin, async (req, res) => {
    try {
        const groupIds = parseGroupIds(req.body);
        if (groupIds.length === 0) return res.status(400).json({ error: 'Chưa chọn tài liệu nào để xóa vĩnh viễn.' });

        const placeholders = groupIds.map(() => '?').join(',');
        const [rows] = await pool.query(
            `SELECT id, code, doc_group_id FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Không tìm thấy tài liệu trong thùng rác để xóa vĩnh viễn.' });

        await pool.query(
            `DELETE FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );

        const codes = [...new Set(rows.map(r => r.code))];
        await writeAuditLog({
            module: 'INTERACTION', actionType: 'PURGE_DOC', status: 'SUCCESS',
            username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: codes.join(', '),
            description: `Xóa VĨNH VIỄN ${rows.length} phiên bản tài liệu (${codes.length} nhóm): ${codes.join(', ')}`
        });

        res.json({ success: true, purgedCount: rows.length });
    } catch (err) {
        console.error('❌ Lỗi xóa vĩnh viễn tài liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- BẢO MẬT: Zero Trust cho file upload — không tin định dạng client khai báo.
// Chỉ chấp nhận PDF, xác thực bằng magic bytes thật của file (%PDF- ở đầu file),
// không chỉ dựa vào đuôi file hay MIME type (dễ giả mạo).
const MAX_PDF_SIZE_BYTES = 20 * 1024 * 1024; // 20MB — điều chỉnh nếu cần
const PDF_MAGIC_BYTES = Buffer.from('%PDF-', 'ascii');

function validatePdfUpload(fileName, fileType, fileDataUri) {
    if (fileType !== 'application/pdf') {
        return 'Chỉ chấp nhận file PDF (định dạng application/pdf).';
    }
    if (!fileName || !/\.pdf$/i.test(String(fileName))) {
        return 'Tên file phải có đuôi .pdf.';
    }
    if (typeof fileDataUri !== 'string') {
        return 'Dữ liệu file không hợp lệ.';
    }
    const match = fileDataUri.match(/^data:application\/pdf;base64,([A-Za-z0-9+/=]+)$/);
    if (!match) {
        return 'Dữ liệu file không đúng định dạng data URI của PDF.';
    }
    let buffer;
    try {
        buffer = Buffer.from(match[1], 'base64');
    } catch (e) {
        return 'Không thể giải mã dữ liệu file.';
    }
    if (buffer.length === 0) {
        return 'File rỗng.';
    }
    if (buffer.length > MAX_PDF_SIZE_BYTES) {
        return `Kích thước file vượt quá giới hạn cho phép (${MAX_PDF_SIZE_BYTES / (1024 * 1024)}MB).`;
    }
    if (!buffer.subarray(0, PDF_MAGIC_BYTES.length).equals(PDF_MAGIC_BYTES)) {
        return 'Nội dung file không phải PDF hợp lệ (sai magic bytes ở đầu file).';
    }
    return null; // hợp lệ
}

// --- Đóng dấu bản quyền lên mọi tài liệu PDF ngay khi upload ---
// Watermark chéo (kiểu "CONFIDENTIAL" quen thuộc) được nhúng vĩnh viễn vào file
// trước khi lưu vào CSDL, nên luôn xuất hiện dù xem trực tiếp hay tải file về.
const COPYRIGHT_WATERMARK_TEXT = 'Tài liệu thuộc bản quyền của Trung tâm CNTT';
const WATERMARK_FONT_PATH = path.join(__dirname, 'assets', 'fonts', 'DejaVuSans-Bold.ttf');
let watermarkFontBytesCache = null;
function loadWatermarkFontBytes() {
    if (!watermarkFontBytesCache) {
        watermarkFontBytesCache = fs.readFileSync(WATERMARK_FONT_PATH);
    }
    return watermarkFontBytesCache;
}

async function stampCopyrightWatermark(fileDataUri) {
    const match = fileDataUri.match(/^data:application\/pdf;base64,([A-Za-z0-9+/=]+)$/);
    const originalBuffer = Buffer.from(match[1], 'base64');

    const pdfDoc = await PDFDocument.load(originalBuffer);
    pdfDoc.registerFontkit(fontkit);
    const font = await pdfDoc.embedFont(loadWatermarkFontBytes(), { subset: true });

    const angleDeg = 45;
    const angleRad = (angleDeg * Math.PI) / 180;

    for (const page of pdfDoc.getPages()) {
        const { width, height } = page.getSize();
        const fontSize = Math.max(18, Math.min(48, Math.min(width, height) / 12));
        const textWidth = font.widthOfTextAtSize(COPYRIGHT_WATERMARK_TEXT, fontSize);
        const x = width / 2 - (textWidth / 2) * Math.cos(angleRad);
        const y = height / 2 - (textWidth / 2) * Math.sin(angleRad);
        page.drawText(COPYRIGHT_WATERMARK_TEXT, {
            x, y,
            size: fontSize,
            font,
            color: rgb(0.6, 0.6, 0.6),
            opacity: 0.35,
            rotate: degrees(angleDeg)
        });
    }

    const stampedBytes = await pdfDoc.save();
    return `data:application/pdf;base64,${Buffer.from(stampedBytes).toString('base64')}`;
}

const DOC_FIELD_LIMITS = { code: 100, title: 500, ver: 50, summary: 5000, fileName: 255 };
function validateDocFieldLengths(d) {
    for (const [field, max] of Object.entries(DOC_FIELD_LIMITS)) {
        const val = d[field];
        if (val != null && String(val).length > max) {
            return `Trường [${field}] vượt quá ${max} ký tự cho phép.`;
        }
    }
    if (!d.code || !String(d.code).trim()) return 'Thiếu mã tài liệu.';
    if (!d.title || !String(d.title).trim()) return 'Thiếu tiêu đề tài liệu.';
    return null;
}

// --- API SYNC / LƯU DỮ LIỆU ĐỒNG BỘ ---
app.post('/api/sync/:table', requireAuth, async (req, res, next) => {
    if (ADMIN_ONLY_TABLES.has(req.params.table)) return requireAdmin(req, res, next);
    next();
}, async (req, res) => {
    const { table } = req.params;
    const data = req.body.data;

    if (!KNOWN_TABLES.has(table)) {
        return res.status(400).json({ error: `Bảng dữ liệu không hợp lệ: ${table}` });
    }
    if (['docs', 'users', 'depts', 'cats', 'workflows', 'system_logs'].includes(table)) {
        if (!Array.isArray(data)) return res.status(400).json({ error: 'Dữ liệu gửi lên phải là một mảng.' });
        if (data.length > MAX_SYNC_ROWS) return res.status(400).json({ error: 'Số lượng bản ghi vượt giới hạn cho phép.' });
    }

    try {
        if (table === 'docs') {
            // Bảo mật: không xoá-chèn-lại toàn bảng nữa (tránh 2 người dùng ghi đè
            // mất tài liệu của nhau). Chỉ ghi (thêm mới / cập nhật) đúng những dòng
            // thực sự thay đổi, và kiểm tra quyền ở server thay vì tin client:
            //  - Tài liệu mới: kiểm tra quyền upload theo phòng ban, ép trạng thái
            //    khởi tạo (PENDING, bước 1, không lịch sử) và người tạo do server
            //    xác định — client không thể tự tạo tài liệu "đã duyệt sẵn".
            //  - Tài liệu đã có: không cho sửa nội dung/metadata (không có tính
            //    năng sửa tài liệu trên UI); chỉ cho đổi trạng thái/bước duyệt nếu
            //    người dùng là admin hoặc đúng người duyệt của bước hiện tại.
            const [existingRows] = await pool.query('SELECT * FROM docs');
            const existingMap = new Map(existingRows.map(r => [String(r.id), r]));

            const [cfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'deptWorkflows'");
            const deptWorkflows = cfgRows[0]
                ? (typeof cfgRows[0].config_value === 'string' ? JSON.parse(cfgRows[0].config_value) : cfgRows[0].config_value)
                : {};

            function canApproveStep(existingDoc) {
                if (req.user.perms.admin) return true;
                const cfg = deptWorkflows[existingDoc.dept];
                if (!cfg || !cfg.approvers) return false;
                return cfg.approvers[existingDoc.current_step_order] === req.user.username;
            }

            // Mã tài liệu do SERVER tự sinh (Zero Trust — không tin mã do client
            // gửi lên), theo quy tắc {Viết tắt Phân loại}-{Viết tắt Phòng ban}-{Năm}-{STT}.
            // Bộ đếm theo prefix được cache trong 1 lần gọi API để nhiều tài liệu
            // mới trong cùng 1 lượt upload (nhiều file) không bị trùng số thứ tự.
            const [deptAbbrRows] = await pool.query('SELECT name, abbr FROM depts');
            const [catAbbrRows] = await pool.query('SELECT name, abbr FROM cats');
            const deptAbbrMap = new Map(deptAbbrRows.map(r => [r.name, r.abbr]));
            const catAbbrMap = new Map(catAbbrRows.map(r => [r.name, r.abbr]));
            const codeSeqCache = new Map();
            async function nextCodeForPrefix(prefix) {
                if (!codeSeqCache.has(prefix)) {
                    const [rows] = await pool.query(
                        'SELECT COUNT(DISTINCT doc_group_id) AS cnt FROM docs WHERE code LIKE ?',
                        [`${prefix}%`]
                    );
                    codeSeqCache.set(prefix, (rows[0].cnt || 0) + 1);
                }
                const seq = codeSeqCache.get(prefix);
                codeSeqCache.set(prefix, seq + 1);
                return seq;
            }

            const toUpsert = [];
            for (const d of data) {
                const existing = existingMap.get(String(d.id));
                if (existing && existing.deleted_at) {
                    return res.status(400).json({ error: `Tài liệu [${existing.code}] đã bị xóa, không thể thao tác. Vui lòng khôi phục trước nếu cần.` });
                }

                if (!existing) {
                    let finalDept = d.dept, finalCat = d.cat, finalTitle = d.title;
                    let docGroupId, versionNo, code, ver;

                    if (d.targetGroupId) {
                        // Chế độ "Cập nhật": nộp phiên bản mới cho tài liệu đã tồn tại.
                        // Phòng ban/Phân loại/Tên tài liệu kế thừa từ tài liệu gốc — không
                        // tin dept/cat/title client gửi (tránh 1 phiên bản "nhảy" sang
                        // phòng ban/phân loại khác so với các phiên bản trước).
                        const groupRows = existingRows.filter(r => String(r.doc_group_id) === String(d.targetGroupId) && !r.deleted_at);
                        if (groupRows.length === 0) {
                            return res.status(400).json({ error: `Không tìm thấy tài liệu gốc để cập nhật (nhóm: ${d.targetGroupId}).` });
                        }
                        const latest = groupRows.reduce((a, b) => (a.version_no > b.version_no ? a : b));
                        if (groupRows.some(r => r.status === 'PENDING')) {
                            return res.status(400).json({ error: `Tài liệu [${latest.code}] còn phiên bản đang chờ duyệt, chưa thể nộp phiên bản mới.` });
                        }
                        finalDept = latest.dept;
                        finalCat = latest.cat;
                        finalTitle = latest.title;
                        const canUploadTarget = req.user.perms.admin || req.user.perms.uploadAll ||
                            (req.user.perms.uploadDepts || []).includes(finalDept);
                        if (!canUploadTarget) {
                            return res.status(403).json({ error: `Bạn không có quyền cập nhật tài liệu cho phòng ban [${finalDept}].` });
                        }
                        docGroupId = latest.doc_group_id;
                        versionNo = latest.version_no + 1;
                        ver = `v${versionNo}.0`;
                        code = latest.code;
                    } else {
                        // Chế độ "Nhập mới"
                        const canUpload = req.user.perms.admin || req.user.perms.uploadAll ||
                            (req.user.perms.uploadDepts || []).includes(finalDept);
                        if (!canUpload) {
                            return res.status(403).json({ error: `Bạn không có quyền tải lên tài liệu cho phòng ban [${finalDept}].` });
                        }
                        const deptAbbr = deptAbbrMap.get(finalDept);
                        const catAbbr = catAbbrMap.get(finalCat);
                        if (!deptAbbr || !catAbbr) {
                            return res.status(400).json({ error: `Phòng ban [${finalDept}] hoặc Phân loại [${finalCat}] chưa được cấu hình viết tắt — không thể tự sinh mã tài liệu.` });
                        }
                        const year = new Date().getFullYear();
                        const prefix = `${catAbbr}-${deptAbbr}-${year}-`;
                        const seq = await nextCodeForPrefix(prefix);
                        code = `${prefix}${String(seq).padStart(3, '0')}`;
                        docGroupId = d.id;
                        versionNo = 1;
                        ver = 'v1.0';
                    }

                    const fieldError = validateDocFieldLengths({ code, title: finalTitle, ver, summary: d.summary, fileName: d.fileName });
                    if (fieldError) {
                        return res.status(400).json({ error: fieldError });
                    }
                    const pdfError = validatePdfUpload(d.fileName, d.fileType, d.fileData);
                    if (pdfError) {
                        return res.status(400).json({ error: `Tài liệu [${code}]: ${pdfError}` });
                    }

                    let stampedFileData;
                    try {
                        stampedFileData = await stampCopyrightWatermark(d.fileData);
                    } catch (e) {
                        return res.status(400).json({ error: `Tài liệu [${code}]: không thể xử lý file PDF để đóng dấu bản quyền.` });
                    }

                    toUpsert.push([
                        d.id, code, finalTitle, ver, finalDept, finalCat, d.summary, d.fileName, d.fileType, stampedFileData,
                        req.user.name, req.user.username, d.createdAt, d.workflowId, 1, 'PENDING', JSON.stringify([]),
                        docGroupId, versionNo
                    ]);
                    continue;
                }

                const existingHistory = typeof existing.history === 'string' ? JSON.parse(existing.history || '[]') : (existing.history || []);
                // Không so sánh file_data ở đây — từ khi bootstrap không còn gửi kèm
                // nội dung file cho client (giảm tải), d.fileData luôn undefined phía
                // client dù tài liệu không hề bị sửa. Việc ghi dữ liệu bên dưới vẫn
                // luôn dùng existing.file_data (giá trị thật trên server), không bao
                // giờ tin d.fileData, nên bỏ so sánh này không làm giảm an toàn.
                const metadataChanged = existing.code !== d.code || existing.title !== d.title || existing.ver !== d.ver ||
                    existing.dept !== d.dept || existing.cat !== d.cat || existing.summary !== d.summary ||
                    existing.file_name !== d.fileName || existing.file_type !== d.fileType;
                const workflowChanged = existing.status !== d.status || existing.current_step_order !== d.currentStepOrder ||
                    JSON.stringify(existingHistory) !== JSON.stringify(d.history || []);

                if (!metadataChanged && !workflowChanged) continue; // không đổi gì, bỏ qua

                if (metadataChanged) {
                    return res.status(400).json({ error: `Không được phép sửa thông tin tài liệu đã tồn tại [${d.code}].` });
                }
                if (!canApproveStep(existing)) {
                    return res.status(403).json({ error: `Bạn không có quyền duyệt/từ chối tài liệu [${d.code}] ở bước hiện tại.` });
                }
                toUpsert.push([
                    d.id, existing.code, existing.title, existing.ver, existing.dept, existing.cat, existing.summary,
                    existing.file_name, existing.file_type, existing.file_data, existing.created_by, existing.creator_username,
                    existing.created_at, d.workflowId, d.currentStepOrder, d.status, JSON.stringify(d.history || []),
                    existing.doc_group_id, existing.version_no
                ]);
            }

            for (const row of toUpsert) {
                await pool.query(
                    `INSERT INTO docs (id, code, title, ver, dept, cat, summary, file_name, file_type, file_data, created_by, creator_username, created_at, workflow_id, current_step_order, status, history, doc_group_id, version_no)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE current_step_order = VALUES(current_step_order), status = VALUES(status), history = VALUES(history)`,
                    row
                );
            }
        } else if (table === 'users') {
            // Bảo mật: mật khẩu không bao giờ được client gửi dạng đã biết trước (bootstrap không trả field `pass`).
            // Nếu client không gửi mật khẩu mới (trống) cho một user đã tồn tại, giữ nguyên hash cũ trong DB.
            const [existingRows] = await pool.query('SELECT username, pass FROM users');
            const existingPassMap = {};
            existingRows.forEach(r => existingPassMap[r.username] = r.pass);

            const rowsToInsert = [];
            for (let u of data) {
                let passHash;
                if (u.pass && String(u.pass).trim()) {
                    if (String(u.pass).trim().length < 6) {
                        return res.status(400).json({ error: `Mật khẩu cho user [${u.username}] phải có ít nhất 6 ký tự.` });
                    }
                    passHash = await bcrypt.hash(String(u.pass).trim(), 12);
                } else if (existingPassMap[u.username]) {
                    passHash = existingPassMap[u.username];
                } else {
                    return res.status(400).json({ error: `Thiếu mật khẩu cho tài khoản mới: ${u.username}` });
                }

                const active = u.active !== false;
                if (!active && u.username === 'admin') {
                    return res.status(400).json({ error: 'Không thể khóa tài khoản Admin gốc!' });
                }
                if (!active && String(u.id) === String(req.user.id)) {
                    return res.status(400).json({ error: 'Không thể tự khóa chính tài khoản đang đăng nhập!' });
                }

                rowsToInsert.push([u.id, u.username, passHash, u.name, u.email, u.phone, u.dept, JSON.stringify(u.perms || {}), active]);
            }

            await pool.query('DELETE FROM users');
            for (let row of rowsToInsert) {
                await pool.query(
                    'INSERT INTO users (id, username, pass, name, email, phone, dept, perms, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    row
                );
            }
        } else if (table === 'depts' || table === 'cats') {
            // Viết tắt (abbr) dùng để sinh mã tài liệu tự động (VD: HD-IT-2026-001)
            // nên bắt buộc, chỉ chữ/số không dấu, và không được trùng giữa các
            // phòng ban/phân loại khác nhau (tránh sinh mã gây nhầm lẫn).
            //
            // Đổi TÊN được coi là "rename" (không phải xóa+tạo mới) khi client gửi
            // kèm đúng `id` của dòng đang sửa — lúc đó server cập nhật lại toàn bộ
            // nơi đang tham chiếu tên cũ (tài liệu, phân quyền user theo phòng ban,
            // cấu hình gán quy trình theo phòng ban) để dữ liệu luôn nhất quán,
            // trong 1 transaction để tránh nửa vời nếu có lỗi giữa chừng.
            const label = table === 'depts' ? 'phòng ban' : 'phân loại';
            const [existingRows] = await pool.query(`SELECT id, name, abbr FROM ${table}`);
            const existingById = new Map(existingRows.map(r => [String(r.id), r]));

            const names = new Set();
            const abbrs = new Set();
            const toUpdate = []; // { id, name, abbr, oldName }
            const toInsert = []; // { name, abbr }
            for (const item of data) {
                const name = String((item && item.name) || '').trim();
                const abbr = String((item && item.abbr) || '').trim().toUpperCase();
                const id = item && item.id != null ? String(item.id) : null;
                if (!name) return res.status(400).json({ error: `Tên ${label} không được để trống.` });
                if (!/^[A-Z0-9]{1,10}$/.test(abbr)) {
                    return res.status(400).json({ error: `Viết tắt của ${label} [${name}] không hợp lệ (chỉ chữ/số không dấu, tối đa 10 ký tự, không được để trống).` });
                }
                if (names.has(name)) return res.status(400).json({ error: `Tên ${label} [${name}] bị trùng.` });
                if (abbrs.has(abbr)) return res.status(400).json({ error: `Viết tắt [${abbr}] bị trùng giữa các ${label}.` });
                names.add(name);
                abbrs.add(abbr);

                const existing = id ? existingById.get(id) : null;
                if (existing) {
                    toUpdate.push({ id: existing.id, name, abbr, oldName: existing.name });
                } else {
                    toInsert.push({ name, abbr });
                }
            }

            const keptIds = new Set(toUpdate.map(u => String(u.id)));
            const toDeleteIds = existingRows.filter(r => !keptIds.has(String(r.id))).map(r => r.id);
            const renames = toUpdate.filter(u => u.oldName !== u.name);

            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

                for (const u of toUpdate) {
                    await conn.query(`UPDATE ${table} SET name = ?, abbr = ? WHERE id = ?`, [u.name, u.abbr, u.id]);
                }
                for (const ins of toInsert) {
                    await conn.query(`INSERT INTO ${table} (name, abbr) VALUES (?, ?)`, [ins.name, ins.abbr]);
                }
                if (toDeleteIds.length > 0) {
                    await conn.query(`DELETE FROM ${table} WHERE id IN (${toDeleteIds.map(() => '?').join(',')})`, toDeleteIds);
                }

                for (const { oldName, name } of renames) {
                    if (table === 'depts') {
                        await conn.query('UPDATE docs SET dept = ? WHERE dept = ?', [name, oldName]);

                        const [userRows] = await conn.query('SELECT id, perms FROM users');
                        for (const u of userRows) {
                            const perms = typeof u.perms === 'string' ? JSON.parse(u.perms || '{}') : (u.perms || {});
                            let changed = false;
                            for (const key of ['uploadDepts', 'viewDraftDepts', 'viewApprovedDepts', 'downloadDepts']) {
                                if (Array.isArray(perms[key]) && perms[key].includes(oldName)) {
                                    perms[key] = perms[key].map(d => d === oldName ? name : d);
                                    changed = true;
                                }
                            }
                            if (perms.dept === oldName) { perms.dept = name; changed = true; }
                            if (changed) {
                                await conn.query('UPDATE users SET perms = ? WHERE id = ?', [JSON.stringify(perms), u.id]);
                            }
                        }
                        await conn.query('UPDATE users SET dept = ? WHERE dept = ?', [name, oldName]);

                        const [cfgRows] = await conn.query("SELECT config_value FROM app_configs WHERE config_key = 'deptWorkflows'");
                        if (cfgRows[0]) {
                            const deptWorkflows = typeof cfgRows[0].config_value === 'string' ? JSON.parse(cfgRows[0].config_value) : cfgRows[0].config_value;
                            if (deptWorkflows && Object.prototype.hasOwnProperty.call(deptWorkflows, oldName)) {
                                deptWorkflows[name] = deptWorkflows[oldName];
                                delete deptWorkflows[oldName];
                                await conn.query('UPDATE app_configs SET config_value = ? WHERE config_key = ?', [JSON.stringify(deptWorkflows), 'deptWorkflows']);
                            }
                        }
                    } else {
                        await conn.query('UPDATE docs SET cat = ? WHERE cat = ?', [name, oldName]);
                    }
                }

                await conn.commit();
            } catch (e) {
                await conn.rollback();
                throw e;
            } finally {
                conn.release();
            }
        } else if (table === 'workflows') {
            await pool.query('DELETE FROM workflows');
            for (let w of data) {
                await pool.query('INSERT INTO workflows (id, name, steps) VALUES (?, ?, ?)', [w.id, w.name, JSON.stringify(w.steps || [])]);
            }
        } else if (['deptWorkflows', 'emailConfig'].includes(table)) {
            await pool.query(
                'INSERT INTO app_configs (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?',
                [table, JSON.stringify(data), JSON.stringify(data)]
            );
        } else if (table === 'system_logs') {
            // Bảo mật: chống giả mạo nhật ký. Log đã tồn tại là bất biến (không cho
            // sửa nội dung); chỉ chèn log THỰC SỰ MỚI, và danh tính/IP của log mới
            // do server tự xác định từ phiên đăng nhập thật (không tin client).
            // Xoá bớt log khỏi hệ thống (kể cả xoá toàn bộ qua nút "Xóa Log") chỉ
            // Admin mới được phép.
            const [existingRows] = await pool.query('SELECT id FROM system_logs');
            const existingIds = new Set(existingRows.map(r => String(r.id)));
            const incomingIds = new Set(data.map(l => String(l.id)));

            const isRemovingAny = existingRows.some(r => !incomingIds.has(String(r.id)));
            if (isRemovingAny && !req.user.perms.admin) {
                return res.status(403).json({ error: 'Chỉ Quản trị viên mới được phép xoá nhật ký hệ thống.' });
            }

            if (isRemovingAny) {
                await pool.query('DELETE FROM system_logs');
            }

            for (const l of data) {
                if (!isRemovingAny && existingIds.has(String(l.id))) continue; // log cũ, giữ nguyên, không ghi đè
                await pool.query(
                    'INSERT INTO system_logs (id, timestamp, username, fullName, ipAddress, module, actionType, targetObject, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    [l.id, l.timestamp, req.user.username, req.user.name, req.ip || '', l.module, l.actionType, l.targetObject, l.description, l.status]
                );
            }
        }
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi đồng bộ dữ liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:${PORT}`);
});
