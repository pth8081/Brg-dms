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
const multer = require('multer');
const { Client: LdapClient } = require('ldapts');

const app = express();
const isProd = process.env.NODE_ENV === 'production';

// --- LƯU FILE TÀI LIỆU: ổ đĩa server, KHÔNG lưu trong CSDL nữa ---
// Đặt ngoài thư mục public/ để không bị express.static phục vụ trực tiếp
// không qua xác thực — chỉ truy cập được qua API có kiểm tra quyền.
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(__dirname, 'uploads'));
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Dung lượng file PDF tối đa cho phép upload, cấu hình qua .env (MB).
const MAX_PDF_SIZE_MB = parseInt(process.env.MAX_PDF_SIZE_MB, 10) || 20;
const MAX_PDF_SIZE_BYTES = MAX_PDF_SIZE_MB * 1024 * 1024;

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
            // Font trang đăng nhập (Spectral, Be Vietnam Pro) tải từ Google Fonts —
            // styleSrc cho stylesheet @font-face, fontSrc riêng cho file font nhị phân.
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "blob:"],
            frameSrc: ["'self'", "data:", "blob:"],
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

// --- ĐĂNG NHẬP QUA LDAP / ACTIVE DIRECTORY (tùy chọn, cấu hình trong Quản trị) ---
// Chỉ dùng kiểu "Direct Bind": ghép username với domain (UPN dạng
// user@domain hoặc NetBIOS dạng DOMAIN\user) rồi bind thẳng bằng chính mật
// khẩu người dùng nhập — không cần tài khoản dịch vụ (service account) để
// tra cứu AD trước. Dùng làm phương án dự phòng: chỉ thử LDAP khi mật khẩu
// local không khớp (xem route /api/auth/login bên dưới).
const LDAP_USERNAME_RE = /^[A-Za-z0-9._-]{1,100}$/;

function buildLdapBindDn(username, ldapConfig) {
    if (ldapConfig.bindFormat === 'netbios') {
        return `${ldapConfig.domain}\\${username}`;
    }
    return `${username}@${ldapConfig.domain}`;
}

async function getLdapConfig() {
    const [cfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'ldapConfig'");
    if (!cfgRows[0]) return null;
    return typeof cfgRows[0].config_value === 'string' ? JSON.parse(cfgRows[0].config_value) : cfgRows[0].config_value;
}

async function ldapAuthenticate(username, password, ldapConfig) {
    // Chặn ký tự lạ trước khi ghép vào chuỗi bind DN — không phải vì đây là bộ
    // lọc LDAP search (không có nguy cơ LDAP injection kiểu filter ở đây do
    // dùng bind trực tiếp), mà để tránh username dị dạng gây lỗi khó hiểu hoặc
    // hành vi không mong muốn phía server AD.
    if (!LDAP_USERNAME_RE.test(username)) return false;
    // Lưu ý: thư viện ldapts coi kết nối là TLS bất cứ khi nào có truyền
    // tlsOptions, BẤT KỂ giao thức trong URL — nếu luôn truyền tlsOptions,
    // kết nối ldap:// (không mã hoá) sẽ bị ép thành ldaps:// và không bao giờ
    // kết nối được. Chỉ truyền tlsOptions khi URL thật sự là ldaps://.
    const isSecure = /^ldaps:\/\//i.test(String(ldapConfig.url || ''));
    const client = new LdapClient({
        url: ldapConfig.url,
        timeout: 5000,
        connectTimeout: 5000,
        ...(isSecure ? { tlsOptions: { rejectUnauthorized: ldapConfig.tlsRejectUnauthorized !== false } } : {})
    });
    try {
        await client.bind(buildLdapBindDn(username, ldapConfig), password);
        return true;
    } catch (e) {
        return false;
    } finally {
        try { await client.unbind(); } catch (e) { /* bỏ qua lỗi khi đóng kết nối */ }
    }
}

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

        // Xác thực: thử mật khẩu local trước; nếu sai VÀ LDAP/AD đang được bật,
        // thử xác thực qua LDAP với đúng username/password vừa nhập (không tạo
        // tài khoản mới — username phải đã tồn tại sẵn trong DMS). Tài khoản
        // local luôn được thử trước nên không phụ thuộc hoàn toàn vào AD (nếu
        // AD lỗi, ai còn nhớ mật khẩu local vẫn đăng nhập được bình thường).
        let authOk = await bcrypt.compare(password, user.pass);
        let authSource = 'LOCAL';

        if (!authOk) {
            const ldapConfig = await getLdapConfig();
            if (ldapConfig && ldapConfig.enabled && ldapConfig.url && ldapConfig.domain) {
                authOk = await ldapAuthenticate(username, password, ldapConfig);
                if (authOk) authSource = 'LDAP';
            }
        }

        if (!authOk) {
            await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_FAILED', status: 'FAILED', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: `Đăng nhập thất bại: sai mật khẩu.` });
            return res.status(401).json({ error: 'Tài khoản hoặc mật khẩu không chính xác!' });
        }

        if (!user.active) {
            await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_FAILED', status: 'FAILED', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: `Đăng nhập thất bại: tài khoản đã bị khóa.` });
            return res.status(401).json({ error: 'Tài khoản đã bị khóa, vui lòng liên hệ quản trị viên.' });
        }

        const token = signToken(user);
        setAuthCookie(res, token);

        await writeAuditLog({ module: 'USER_MGM', actionType: 'LOGIN_SUCCESS', status: 'SUCCESS', username: user.username, fullName: user.name, ip: req.ip, targetObject: user.username, description: authSource === 'LDAP' ? 'Đăng nhập hệ thống thành công qua LDAP/Active Directory.' : 'Đăng nhập hệ thống thành công.' });

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
            ldapConfig: configMap.ldapConfig || { enabled: false, url: '', bindFormat: 'upn', domain: '', tlsRejectUnauthorized: true },
            systemLogs: logs,
            maxPdfSizeMB: MAX_PDF_SIZE_MB
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu bootstrap:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Các bảng cấu hình hệ thống chỉ Admin mới được ghi
const ADMIN_ONLY_TABLES = new Set(['users', 'workflows', 'depts', 'cats', 'deptWorkflows', 'emailConfig', 'ldapConfig']);
const KNOWN_TABLES = new Set(['docs', 'users', 'depts', 'cats', 'workflows', 'deptWorkflows', 'emailConfig', 'ldapConfig', 'system_logs']);
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

        // Tài liệu mới: file nằm trên đĩa (file_path), stream thẳng ra — không
        // còn phải nạp cả file vào bộ nhớ / mã hoá base64 qua JSON như trước.
        // Tài liệu cũ (upload trước khi chuyển sang lưu đĩa) vẫn còn base64 ở
        // cột file_data — giữ lại đường phục vụ cũ cho tới khi chạy migration.
        if (doc.file_path) {
            const absPath = path.join(UPLOAD_DIR, doc.file_path);
            if (!absPath.startsWith(UPLOAD_DIR)) return res.status(400).json({ error: 'Đường dẫn file không hợp lệ.' });
            if (!fs.existsSync(absPath)) return res.status(404).json({ error: 'Không tìm thấy file trên máy chủ.' });
            const safeName = String(doc.file_name || 'document.pdf').replace(/["\r\n]/g, '');
            const disposition = mode === 'download' ? 'attachment' : 'inline';
            res.setHeader('Content-Type', doc.file_type || 'application/pdf');
            res.setHeader('Content-Disposition', `${disposition}; filename="${safeName}"`);
            return res.sendFile(absPath, (err) => {
                if (err && !res.headersSent) res.status(404).json({ error: 'Không tìm thấy file trên máy chủ.' });
            });
        }

        if (doc.file_data) {
            return res.json({ fileName: doc.file_name, fileType: doc.file_type, fileData: doc.file_data });
        }

        return res.status(404).json({ error: 'Tài liệu không có file đính kèm.' });
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
            `SELECT id, code, doc_group_id, file_path FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );
        if (rows.length === 0) return res.status(404).json({ error: 'Không tìm thấy tài liệu trong thùng rác để xóa vĩnh viễn.' });

        await pool.query(
            `DELETE FROM docs WHERE doc_group_id IN (${placeholders}) AND deleted_at IS NOT NULL`,
            groupIds
        );

        // Dọn file vật lý trên đĩa — cố gắng hết sức (best-effort), không chặn
        // việc xóa bản ghi CSDL nếu file đã không còn tồn tại.
        for (const r of rows) {
            if (r.file_path) fs.unlink(path.join(UPLOAD_DIR, r.file_path), () => {});
        }

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
const PDF_MAGIC_BYTES = Buffer.from('%PDF-', 'ascii');

function validatePdfUpload(fileName, fileType, buffer) {
    if (fileType !== 'application/pdf') {
        return 'Chỉ chấp nhận file PDF (định dạng application/pdf).';
    }
    if (!fileName || !/\.pdf$/i.test(String(fileName))) {
        return 'Tên file phải có đuôi .pdf.';
    }
    if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
        return 'File rỗng hoặc không hợp lệ.';
    }
    if (buffer.length > MAX_PDF_SIZE_BYTES) {
        return `Kích thước file vượt quá giới hạn cho phép (${MAX_PDF_SIZE_MB}MB).`;
    }
    if (!buffer.subarray(0, PDF_MAGIC_BYTES.length).equals(PDF_MAGIC_BYTES)) {
        return 'Nội dung file không phải PDF hợp lệ (sai magic bytes ở đầu file).';
    }
    return null; // hợp lệ
}

// --- Đóng dấu bản quyền lên mọi tài liệu PDF ngay khi upload ---
// Watermark chéo (kiểu "CONFIDENTIAL" quen thuộc) được nhúng vĩnh viễn vào file
// trước khi lưu ra đĩa, nên luôn xuất hiện dù xem trực tiếp hay tải file về.
const COPYRIGHT_WATERMARK_TEXT = 'Tài liệu thuộc bản quyền của Trung tâm CNTT';
const WATERMARK_FONT_PATH = path.join(__dirname, 'assets', 'fonts', 'DejaVuSans-Bold.ttf');
let watermarkFontBytesCache = null;
function loadWatermarkFontBytes() {
    if (!watermarkFontBytesCache) {
        watermarkFontBytesCache = fs.readFileSync(WATERMARK_FONT_PATH);
    }
    return watermarkFontBytesCache;
}

async function stampCopyrightWatermark(originalBuffer) {
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
    return Buffer.from(stampedBytes);
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

// --- API TẢI LÊN TÀI LIỆU (multipart/form-data thật — file stream thẳng vào
// RAM tạm rồi ghi ra đĩa, không còn nhồi base64 vào JSON như trước) ---
let docIdSeq = 0;
function nextDocId() {
    return Date.now() * 1000 + (docIdSeq++ % 1000);
}

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: MAX_PDF_SIZE_BYTES }
});

app.post('/api/docs/upload', requireAuth, (req, res, next) => {
    upload.array('files', 50)(req, res, (err) => {
        if (err) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: `Kích thước file vượt quá giới hạn cho phép (${MAX_PDF_SIZE_MB}MB).` });
            }
            return res.status(400).json({ error: 'Lỗi khi tải file lên: ' + err.message });
        }
        next();
    });
}, async (req, res) => {
    try {
        const files = req.files || [];
        if (files.length === 0) {
            return res.status(400).json({ error: 'Chưa chọn file nào để tải lên.' });
        }

        const mode = req.body.mode === 'update' ? 'update' : 'new';
        const dept = req.body.dept;
        const cat = req.body.cat;
        const summary = req.body.summary || '';
        const targetGroupId = req.body.targetGroupId;
        const customTitle = (req.body.title || '').trim();

        if (mode === 'update' && files.length > 1) {
            return res.status(400).json({ error: 'Chế độ Cập nhật chỉ được chọn 1 file.' });
        }
        if (mode === 'new' && files.length === 1 && !customTitle) {
            return res.status(400).json({ error: 'Thiếu tiêu đề tài liệu.' });
        }

        const [existingRows] = await pool.query('SELECT * FROM docs');
        const [deptAbbrRows] = await pool.query('SELECT name, abbr FROM depts');
        const [catAbbrRows] = await pool.query('SELECT name, abbr FROM cats');
        const deptAbbrMap = new Map(deptAbbrRows.map(r => [r.name, r.abbr]));
        const catAbbrMap = new Map(catAbbrRows.map(r => [r.name, r.abbr]));
        const [cfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'deptWorkflows'");
        const deptWorkflows = cfgRows[0]
            ? (typeof cfgRows[0].config_value === 'string' ? JSON.parse(cfgRows[0].config_value) : cfgRows[0].config_value)
            : {};

        const codeSeqCache = new Map();
        async function nextCodeForPrefix(prefix) {
            if (!codeSeqCache.has(prefix)) {
                const [rows] = await pool.query('SELECT COUNT(DISTINCT doc_group_id) AS cnt FROM docs WHERE code LIKE ?', [`${prefix}%`]);
                codeSeqCache.set(prefix, (rows[0].cnt || 0) + 1);
            }
            const seq = codeSeqCache.get(prefix);
            codeSeqCache.set(prefix, seq + 1);
            return seq;
        }

        // Lỗi nghiệp vụ (validate/permission/xử lý PDF) mang theo status HTTP —
        // luôn throw thay vì res.status(...) trực tiếp trong vòng lặp, để catch
        // bên dưới CHẮC CHẮN chạy dọn dẹp (file đã ghi ra đĩa + dòng CSDL đã
        // insert của các file TRƯỚC ĐÓ trong cùng lượt) trước khi trả lỗi —
        // tránh để lại "tài liệu mồ côi" khi 1 file giữa chừng trong lượt
        // upload nhiều file bị lỗi.
        class UploadError extends Error {
            constructor(status, message) { super(message); this.status = status; }
        }

        const savedFilePaths = [];
        const createdDocs = [];
        const createdIds = [];

        try {
            for (const file of files) {
                let finalDept = dept, finalCat = cat, finalTitle = customTitle;
                let docGroupId, versionNo, code, ver, workflowId;

                if (mode === 'update') {
                    const groupRows = existingRows.filter(r => String(r.doc_group_id) === String(targetGroupId) && !r.deleted_at);
                    if (groupRows.length === 0) {
                        throw new UploadError(400, `Không tìm thấy tài liệu gốc để cập nhật (nhóm: ${targetGroupId}).`);
                    }
                    const latest = groupRows.reduce((a, b) => (a.version_no > b.version_no ? a : b));
                    if (groupRows.some(r => r.status === 'PENDING')) {
                        throw new UploadError(400, `Tài liệu [${latest.code}] còn phiên bản đang chờ duyệt, chưa thể nộp phiên bản mới.`);
                    }
                    finalDept = latest.dept;
                    finalCat = latest.cat;
                    finalTitle = latest.title;
                    const canUploadTarget = req.user.perms.admin || req.user.perms.uploadAll ||
                        (req.user.perms.uploadDepts || []).includes(finalDept);
                    if (!canUploadTarget) {
                        throw new UploadError(403, `Bạn không có quyền cập nhật tài liệu cho phòng ban [${finalDept}].`);
                    }
                    docGroupId = latest.doc_group_id;
                    versionNo = latest.version_no + 1;
                    ver = `v${versionNo}.0`;
                    code = latest.code;
                } else {
                    const canUpload = req.user.perms.admin || req.user.perms.uploadAll ||
                        (req.user.perms.uploadDepts || []).includes(finalDept);
                    if (!canUpload) {
                        throw new UploadError(403, `Bạn không có quyền tải lên tài liệu cho phòng ban [${finalDept}].`);
                    }
                    const deptAbbr = deptAbbrMap.get(finalDept);
                    const catAbbr = catAbbrMap.get(finalCat);
                    if (!deptAbbr || !catAbbr) {
                        throw new UploadError(400, `Phòng ban [${finalDept}] hoặc Phân loại [${finalCat}] chưa được cấu hình viết tắt — không thể tự sinh mã tài liệu.`);
                    }
                    if (files.length > 1) {
                        finalTitle = file.originalname.replace(/\.pdf$/i, '');
                    }
                    // Mã tài liệu: BRG-{Viết tắt Phòng ban}-{Viết tắt Phân loại}-{STT tăng dần
                    // theo các mã có cùng tiền tố}. VD: BRG-IT-QT-001, BRG-IT-QT-002...
                    const prefix = `BRG-${deptAbbr}-${catAbbr}-`;
                    const seq = await nextCodeForPrefix(prefix);
                    code = `${prefix}${String(seq).padStart(3, '0')}`;
                    docGroupId = nextDocId();
                    versionNo = 1;
                    ver = 'v1.0';
                }

                workflowId = (deptWorkflows[finalDept] && deptWorkflows[finalDept].workflowId) || 'WF_1STEP';
                const id = mode === 'update' ? nextDocId() : docGroupId;

                const fieldError = validateDocFieldLengths({ code, title: finalTitle, ver, summary, fileName: file.originalname });
                if (fieldError) {
                    throw new UploadError(400, fieldError);
                }
                const pdfError = validatePdfUpload(file.originalname, file.mimetype, file.buffer);
                if (pdfError) {
                    throw new UploadError(400, `Tài liệu [${code}]: ${pdfError}`);
                }

                let stampedBuffer;
                try {
                    stampedBuffer = await stampCopyrightWatermark(file.buffer);
                } catch (e) {
                    throw new UploadError(400, `Tài liệu [${code}]: không thể xử lý file PDF để đóng dấu bản quyền.`);
                }

                const filePath = `${id}.pdf`;
                fs.writeFileSync(path.join(UPLOAD_DIR, filePath), stampedBuffer);
                savedFilePaths.push(filePath);

                await pool.query(
                    `INSERT INTO docs (id, code, title, ver, dept, cat, summary, file_name, file_type, file_path, created_by, creator_username, created_at, workflow_id, current_step_order, status, history, doc_group_id, version_no)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [id, code, finalTitle, ver, finalDept, finalCat, summary, file.originalname, 'application/pdf', filePath,
                        req.user.name, req.user.username, new Date().toISOString(), workflowId, 1, 'PENDING', JSON.stringify([]),
                        docGroupId, versionNo]
                );

                createdDocs.push({ id, code, ver, title: finalTitle });
                createdIds.push(id);
                // Nếu upload nhiều file 1 lượt, các file sau tính "đã tồn tại" để mã tự sinh không trùng nhau.
                existingRows.push({ doc_group_id: docGroupId, version_no: versionNo, status: 'PENDING', dept: finalDept, cat: finalCat, code });
            }
        } catch (e) {
            // Dọn các file đã ghi ra đĩa VÀ các dòng CSDL đã insert trong lượt
            // upload này nếu có lỗi giữa chừng — tránh để lại tài liệu/file mồ
            // côi khi 1 trong nhiều file bị lỗi (toàn bộ lượt upload là 1 đơn vị,
            // không được để lại kết quả nửa vời).
            for (const fp of savedFilePaths) {
                fs.unlink(path.join(UPLOAD_DIR, fp), () => {});
            }
            if (createdIds.length > 0) {
                const placeholders = createdIds.map(() => '?').join(',');
                await pool.query(`DELETE FROM docs WHERE id IN (${placeholders})`, createdIds).catch(() => {});
            }
            if (e instanceof UploadError) {
                return res.status(e.status).json({ error: e.message });
            }
            throw e;
        }

        res.json({ success: true, docs: createdDocs });
    } catch (err) {
        console.error('❌ Lỗi tải lên tài liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

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

            const toUpsert = [];
            for (const d of data) {
                const existing = existingMap.get(String(d.id));
                if (existing && existing.deleted_at) {
                    return res.status(400).json({ error: `Tài liệu [${existing.code}] đã bị xóa, không thể thao tác. Vui lòng khôi phục trước nếu cần.` });
                }

                // Tài liệu mới không còn được tạo qua kênh sync này nữa — phải qua
                // POST /api/docs/upload (multipart thật, file ghi ra đĩa thay vì
                // nhồi base64 vào JSON). Nếu id không khớp tài liệu nào đã có, coi
                // là lỗi thay vì âm thầm tạo mới.
                if (!existing) {
                    return res.status(400).json({ error: 'Tài liệu mới phải được tạo qua chức năng tải lên file, không qua đồng bộ dữ liệu.' });
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
        } else if (['deptWorkflows', 'emailConfig', 'ldapConfig'].includes(table)) {
            if (table === 'ldapConfig' && data && data.enabled) {
                if (!data.url || !/^ldaps?:\/\//i.test(String(data.url))) {
                    return res.status(400).json({ error: 'URL máy chủ LDAP không hợp lệ (phải bắt đầu bằng ldap:// hoặc ldaps://).' });
                }
                if (!data.domain || !String(data.domain).trim()) {
                    return res.status(400).json({ error: 'Thiếu Domain (hoặc tên NetBIOS) cho cấu hình LDAP.' });
                }
                if (!['upn', 'netbios'].includes(data.bindFormat)) {
                    return res.status(400).json({ error: 'Định dạng đăng nhập LDAP không hợp lệ.' });
                }
            }
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

// ============================================================
// MODULE QUẢN LÝ BẢN QUYỀN PHẦN MỀM — GIAI ĐOẠN 1 (NỀN TẢNG)
// Công ty / Cây đơn vị tổ chức (N cấp) / Nhân viên / Danh mục phần mềm.
// Độc lập hoàn toàn với depts/users của module Quản lý Tài liệu (quyết định
// đã thống nhất với người dùng). Toàn bộ module chỉ Admin được truy cập.
// ============================================================
function mapCompany(c) { return { id: c.id, name: c.name, code: c.code, active: !!c.active }; }
function mapOrgUnit(u) { return { id: u.id, companyId: u.company_id, parentId: u.parent_id, name: u.name, level: u.level_label, sortOrder: u.sort_order }; }
function mapEmployee(e) { return { id: e.id, orgUnitId: e.org_unit_id, fullName: e.full_name, title: e.title, employeeCode: e.employee_code, email: e.email, active: !!e.active }; }
function mapSoftware(s) { return { id: s.id, name: s.name, code: s.code, defaultDurationMonths: s.default_duration_months }; }
// Trả về số tháng hợp lệ (1-120), hoặc null nếu không cấu hình. Ném lỗi rõ
// ràng nếu client gửi giá trị không hợp lệ (không phải số nguyên dương).
function parseDurationMonths(raw) {
    if (raw === undefined || raw === null || raw === '') return { value: null };
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 120) return { error: 'Thời hạn mặc định phải là số nguyên từ 1 đến 120 tháng, hoặc để trống nếu không cấu hình.' };
    return { value: n };
}
function validCode(code, maxLen) {
    return typeof code === 'string' && new RegExp(`^[A-Z0-9]{1,${maxLen}}$`).test(code);
}
// Cột kiểu DATE trả về dạng đối tượng Date (giờ local) — quy về chuỗi
// YYYY-MM-DD bằng getFullYear/getMonth/getDate, KHÔNG dùng toISOString() vì
// nó quy đổi sang UTC và có thể lệch ngày.
function fmtDate(d) {
    if (!d) return null;
    if (typeof d === 'string') return d.slice(0, 10);
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}
function validDateStr(s) { return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s); }
function mapBatch(b) { return { id: b.id, companyId: b.company_id, softwareId: b.software_id, totalQuantity: b.total_quantity, codesGenerated: b.codes_generated, issuedDate: fmtDate(b.issued_date), expiryDate: fmtDate(b.expiry_date), note: b.note }; }
function mapCode(c) { return { id: c.id, batchId: c.batch_id, companyId: c.company_id, softwareId: c.software_id, code: c.code, expiryDate: fmtDate(c.expiry_date), assignedEmployeeId: c.assigned_employee_id, assignedAt: fmtDate(c.assigned_at) }; }
function mapRound(r) { return { id: r.id, name: r.name, note: r.note, status: r.status, createdAt: r.created_at }; }
function mapRoundItem(i) { return { id: i.id, roundId: i.round_id, softwareId: i.software_id, unitPrice: Number(i.unit_price), expiryDate: fmtDate(i.expiry_date) }; }
function mapRegistration(r) { return { id: r.id, roundId: r.round_id, roundItemId: r.round_item_id, companyId: r.company_id, currentQuantity: r.current_quantity, requestedQuantity: r.requested_quantity, unitPrice: Number(r.unit_price), totalAmount: Number(r.total_amount), expiryDate: fmtDate(r.expiry_date), status: r.status, note: r.note, createdAt: r.created_at, decidedBy: r.decided_by, decidedAt: r.decided_at }; }

app.get('/api/license/bootstrap', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [companies] = await pool.query('SELECT * FROM lic_companies ORDER BY name');
        const [orgUnits] = await pool.query('SELECT * FROM lic_org_units ORDER BY sort_order, name');
        const [employees] = await pool.query('SELECT * FROM lic_employees ORDER BY full_name');
        const [software] = await pool.query('SELECT * FROM lic_software_catalog ORDER BY name');
        const [batches] = await pool.query('SELECT * FROM lic_license_batches ORDER BY id DESC');
        const [codes] = await pool.query('SELECT * FROM lic_license_codes ORDER BY code');
        const [rounds] = await pool.query('SELECT * FROM lic_purchase_rounds ORDER BY id DESC');
        const [roundItems] = await pool.query('SELECT * FROM lic_purchase_round_items ORDER BY id');
        const [registrations] = await pool.query('SELECT * FROM lic_purchase_registrations ORDER BY id DESC');
        res.json({
            companies: companies.map(mapCompany),
            orgUnits: orgUnits.map(mapOrgUnit),
            employees: employees.map(mapEmployee),
            softwareCatalog: software.map(mapSoftware),
            licenseBatches: batches.map(mapBatch),
            licenseCodes: codes.map(mapCode),
            purchaseRounds: rounds.map(mapRound),
            purchaseRoundItems: roundItems.map(mapRoundItem),
            purchaseRegistrations: registrations.map(mapRegistration)
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu module Bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Công ty ---
app.post('/api/license/companies', requireAuth, requireAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên công ty không được để trống.' });
        if (!validCode(code, 20)) return res.status(400).json({ error: 'Mã công ty không hợp lệ (chỉ chữ/số không dấu, tối đa 20 ký tự).' });
        const [result] = await pool.query('INSERT INTO lic_companies (name, code, active) VALUES (?, ?, TRUE)', [name, code]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_COMPANY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm công ty [${name}] (mã ${code}) vào module Bản quyền.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên công ty đã tồn tại.' });
        console.error('❌ Lỗi thêm công ty:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/companies/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên công ty không được để trống.' });
        if (!validCode(code, 20)) return res.status(400).json({ error: 'Mã công ty không hợp lệ (chỉ chữ/số không dấu, tối đa 20 ký tự).' });
        const [result] = await pool.query('UPDATE lic_companies SET name = ?, code = ? WHERE id = ?', [name, code, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy công ty.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_COMPANY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật công ty [${name}] (mã ${code}).` });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên công ty đã tồn tại.' });
        console.error('❌ Lỗi cập nhật công ty:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/companies/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_companies WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy công ty.' });
        const [units] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_org_units WHERE company_id = ?', [id]);
        if (units[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — công ty vẫn còn đơn vị trực thuộc. Hãy xóa hết đơn vị con trước.' });
        await pool.query('DELETE FROM lic_companies WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_COMPANY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa công ty [${rows[0].name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa công ty:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Đơn vị tổ chức (cây N cấp) ---
app.post('/api/license/org-units', requireAuth, requireAdmin, async (req, res) => {
    try {
        const companyId = Number(req.body && req.body.companyId);
        const parentId = req.body && req.body.parentId ? Number(req.body.parentId) : null;
        const name = String((req.body && req.body.name) || '').trim();
        const level = String((req.body && req.body.level) || '').trim();
        if (!companyId) return res.status(400).json({ error: 'Thiếu công ty.' });
        if (!name) return res.status(400).json({ error: 'Tên đơn vị không được để trống.' });
        if (!level) return res.status(400).json({ error: 'Vui lòng nhập Cấp cho đơn vị.' });
        const [companyRows] = await pool.query('SELECT id FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });
        if (parentId) {
            const [parentRows] = await pool.query('SELECT id, company_id FROM lic_org_units WHERE id = ?', [parentId]);
            if (!parentRows[0]) return res.status(400).json({ error: 'Đơn vị cha không tồn tại.' });
            if (parentRows[0].company_id !== companyId) return res.status(400).json({ error: 'Đơn vị cha phải thuộc cùng công ty.' });
        }
        const [result] = await pool.query('INSERT INTO lic_org_units (company_id, parent_id, name, level_label, sort_order) VALUES (?, ?, ?, ?, 0)', [companyId, parentId, name, level]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_ORG_UNIT', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm đơn vị [${name}] (${level}).` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm đơn vị:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Không cho đổi công ty/đơn vị cha khi sửa — tránh vòng lặp cha-con và đảo
// lộn dữ liệu Phân bổ ở giai đoạn sau; muốn chuyển nhánh thì xóa/tạo lại.
app.put('/api/license/org-units/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        const level = String((req.body && req.body.level) || '').trim();
        if (!name) return res.status(400).json({ error: 'Tên đơn vị không được để trống.' });
        if (!level) return res.status(400).json({ error: 'Vui lòng nhập Cấp cho đơn vị.' });
        const [result] = await pool.query('UPDATE lic_org_units SET name = ?, level_label = ? WHERE id = ?', [name, level, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy đơn vị.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_ORG_UNIT', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật đơn vị [${name}] (${level}).` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cập nhật đơn vị:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/org-units/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_org_units WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đơn vị.' });
        const [children] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_org_units WHERE parent_id = ?', [id]);
        if (children[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đơn vị này còn đơn vị con bên dưới.' });
        const [emps] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_employees WHERE org_unit_id = ?', [id]);
        if (emps[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — vẫn còn nhân viên thuộc đơn vị này.' });
        await pool.query('DELETE FROM lic_org_units WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_ORG_UNIT', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa đơn vị [${rows[0].name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa đơn vị:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Nhân viên ---
app.post('/api/license/employees', requireAuth, requireAdmin, async (req, res) => {
    try {
        const orgUnitId = Number(req.body && req.body.orgUnitId);
        const fullName = String((req.body && req.body.fullName) || '').trim();
        const title = String((req.body && req.body.title) || '').trim();
        const employeeCode = String((req.body && req.body.employeeCode) || '').trim();
        const email = String((req.body && req.body.email) || '').trim();
        if (!orgUnitId) return res.status(400).json({ error: 'Vui lòng chọn Đơn vị.' });
        if (!fullName) return res.status(400).json({ error: 'Họ và tên không được để trống.' });
        const [unitRows] = await pool.query('SELECT id FROM lic_org_units WHERE id = ?', [orgUnitId]);
        if (!unitRows[0]) return res.status(400).json({ error: 'Đơn vị không tồn tại.' });
        const [result] = await pool.query(
            'INSERT INTO lic_employees (org_unit_id, full_name, title, employee_code, email, active) VALUES (?, ?, ?, ?, ?, TRUE)',
            [orgUnitId, fullName, title || null, employeeCode || null, email || null]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_EMPLOYEE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: fullName, description: `Thêm nhân viên [${fullName}] vào module Bản quyền.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm nhân viên:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/employees/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const orgUnitId = Number(req.body && req.body.orgUnitId);
        const fullName = String((req.body && req.body.fullName) || '').trim();
        const title = String((req.body && req.body.title) || '').trim();
        const employeeCode = String((req.body && req.body.employeeCode) || '').trim();
        const email = String((req.body && req.body.email) || '').trim();
        if (!orgUnitId) return res.status(400).json({ error: 'Vui lòng chọn Đơn vị.' });
        if (!fullName) return res.status(400).json({ error: 'Họ và tên không được để trống.' });
        const [unitRows] = await pool.query('SELECT id FROM lic_org_units WHERE id = ?', [orgUnitId]);
        if (!unitRows[0]) return res.status(400).json({ error: 'Đơn vị không tồn tại.' });
        const [result] = await pool.query(
            'UPDATE lic_employees SET org_unit_id = ?, full_name = ?, title = ?, employee_code = ?, email = ? WHERE id = ?',
            [orgUnitId, fullName, title || null, employeeCode || null, email || null, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy nhân viên.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_EMPLOYEE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: fullName, description: `Cập nhật nhân viên [${fullName}].` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cập nhật nhân viên:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/employees/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT full_name FROM lic_employees WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy nhân viên.' });
        await pool.query('DELETE FROM lic_employees WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_EMPLOYEE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].full_name, description: `Xóa nhân viên [${rows[0].full_name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa nhân viên:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Danh mục phần mềm ---
app.post('/api/license/software', requireAuth, requireAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên phần mềm không được để trống.' });
        if (!validCode(code, 50)) return res.status(400).json({ error: 'Mã phần mềm không hợp lệ (chỉ chữ/số không dấu, tối đa 50 ký tự).' });
        const duration = parseDurationMonths(req.body && req.body.defaultDurationMonths);
        if (duration.error) return res.status(400).json({ error: duration.error });
        const [result] = await pool.query('INSERT INTO lic_software_catalog (name, code, default_duration_months) VALUES (?, ?, ?)', [name, code, duration.value]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm phần mềm [${name}] (mã ${code}) vào danh mục${duration.value ? `, thời hạn mặc định ${duration.value} tháng` : ''}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên phần mềm đã tồn tại.' });
        console.error('❌ Lỗi thêm phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/software/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên phần mềm không được để trống.' });
        if (!validCode(code, 50)) return res.status(400).json({ error: 'Mã phần mềm không hợp lệ (chỉ chữ/số không dấu, tối đa 50 ký tự).' });
        const duration = parseDurationMonths(req.body && req.body.defaultDurationMonths);
        if (duration.error) return res.status(400).json({ error: duration.error });
        const [result] = await pool.query('UPDATE lic_software_catalog SET name = ?, code = ?, default_duration_months = ? WHERE id = ?', [name, code, duration.value, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy phần mềm.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật phần mềm [${name}] (mã ${code}).` });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên phần mềm đã tồn tại.' });
        console.error('❌ Lỗi cập nhật phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/software/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_software_catalog WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy phần mềm.' });
        const [batches] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_batches WHERE software_id = ?', [id]);
        if (batches[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — phần mềm này đã có lô license được phát hành.' });
        await pool.query('DELETE FROM lic_software_catalog WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa phần mềm [${rows[0].name}] khỏi danh mục.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Phát hành license (lịch sử phát hành + mã license) ---
// Sinh mã dạng {mã công ty}-{mã phần mềm}-{6 ký tự ngẫu nhiên chữ+số, không
// trùng}, không dùng số thứ tự tuần tự nữa.
function randomCodeSuffix(len) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // bỏ 0/O, 1/I/L để tránh nhầm lẫn khi đọc
    let s = '';
    for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
    return s;
}
async function generateLicenseCodes(companyCode, softwareCode, count) {
    const prefix = `${companyCode}-${softwareCode}-`;
    const [existingRows] = await pool.query('SELECT code FROM lic_license_codes WHERE code LIKE ?', [`${prefix}%`]);
    const existing = new Set(existingRows.map(r => r.code));
    const codes = [];
    while (codes.length < count) {
        const candidate = `${prefix}${randomCodeSuffix(6)}`;
        if (existing.has(candidate)) continue;
        existing.add(candidate);
        codes.push(candidate);
    }
    return codes;
}

// Mỗi lần phát hành = 1 lần "gia hạn" cho công ty+phần mềm: totalQuantity là
// TỔNG SỐ LƯỢNG MONG MUỐN hiện tại (không phải số mã mới) — server tự tính
// phần chênh lệch so với số mã đang có để CHỈ SINH THÊM đúng phần đó (mã cũ đã
// gán người dùng giữ nguyên), rồi cập nhật ngày hết hạn cho TOÀN BỘ mã cũ+mới
// của công ty+phần mềm này. Mua ít hơn số đang có KHÔNG tự xóa/thu hồi gì.
app.post('/api/license/batches', requireAuth, requireAdmin, async (req, res) => {
    try {
        const companyId = Number(req.body && req.body.companyId);
        const softwareId = Number(req.body && req.body.softwareId);
        const totalQuantity = Number(req.body && req.body.totalQuantity);
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        const expiryDate = String((req.body && req.body.expiryDate) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        if (!companyId) return res.status(400).json({ error: 'Vui lòng chọn Công ty.' });
        if (!softwareId) return res.status(400).json({ error: 'Vui lòng chọn Phần mềm.' });
        if (!Number.isInteger(totalQuantity) || totalQuantity < 0 || totalQuantity > 5000) return res.status(400).json({ error: 'Tổng số lượng phải là số nguyên từ 0 đến 5000.' });
        if (!validDateStr(issuedDate)) return res.status(400).json({ error: 'Ngày cấp không hợp lệ.' });
        if (!validDateStr(expiryDate)) return res.status(400).json({ error: 'Ngày hết hạn không hợp lệ.' });
        if (expiryDate <= issuedDate) return res.status(400).json({ error: 'Ngày hết hạn phải sau Ngày cấp.' });

        const [companyRows] = await pool.query('SELECT id, code FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });
        const [softwareRows] = await pool.query('SELECT id, code FROM lic_software_catalog WHERE id = ?', [softwareId]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });

        const [existingCountRows] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_codes WHERE company_id = ? AND software_id = ?', [companyId, softwareId]);
        const existingCount = existingCountRows[0].cnt;
        const toGenerate = Math.max(0, totalQuantity - existingCount);

        const [batchResult] = await pool.query(
            'INSERT INTO lic_license_batches (company_id, software_id, total_quantity, codes_generated, issued_date, expiry_date, note, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [companyId, softwareId, totalQuantity, toGenerate, issuedDate, expiryDate, note || null, new Date().toISOString()]
        );
        const batchId = batchResult.insertId;

        if (toGenerate > 0) {
            const codes = await generateLicenseCodes(companyRows[0].code, softwareRows[0].code, toGenerate);
            await pool.query(
                'INSERT INTO lic_license_codes (batch_id, company_id, software_id, code, expiry_date) VALUES ?',
                [codes.map(c => [batchId, companyId, softwareId, c, expiryDate])]
            );
        }
        // Gia hạn: đưa ngày hết hạn của TOÀN BỘ mã (cũ lẫn vừa sinh) của công
        // ty+phần mềm này về cùng 1 mốc — đúng bản chất "phát hành cho gia hạn".
        await pool.query('UPDATE lic_license_codes SET expiry_date = ? WHERE company_id = ? AND software_id = ?', [expiryDate, companyId, softwareId]);

        await writeAuditLog({ module: 'LICENSE', actionType: 'ISSUE_BATCH', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `${companyRows[0].code}/${softwareRows[0].code}`, description: `Phát hành license [${softwareRows[0].code}] cho công ty [${companyRows[0].code}]: tổng ${totalQuantity} (sinh mới ${toGenerate}), gia hạn toàn bộ đến ${expiryDate}.` });
        res.json({ success: true, id: batchId, codesGenerated: toGenerate });
    } catch (err) {
        console.error('❌ Lỗi phát hành license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/batches/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_license_batches WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy lượt phát hành.' });
        const [assigned] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_codes WHERE batch_id = ? AND assigned_employee_id IS NOT NULL', [id]);
        if (assigned[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — lượt phát hành này đã sinh ra mã đang được phân bổ cho nhân viên. Hãy thu hồi hết trước.' });
        await pool.query('DELETE FROM lic_license_codes WHERE batch_id = ?', [id]);
        await pool.query('DELETE FROM lic_license_batches WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BATCH', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Lượt phát hành #${id}`, description: `Xóa lượt phát hành license #${id} (chưa có mã nào được phân bổ).` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa lượt phát hành license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Phân bổ (gán / thu hồi 1 mã license cho 1 nhân viên) ---
// Zero-trust: server tự tra lại công ty của mã và công ty của nhân viên (qua
// đơn vị) để đối chiếu — không tin companyId client gửi kèm.
app.post('/api/license/codes/:id/assign', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const employeeId = Number(req.body && req.body.employeeId);
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        if (!employeeId) return res.status(400).json({ error: 'Vui lòng chọn Nhân viên.' });
        if (!validDateStr(issuedDate)) return res.status(400).json({ error: 'Ngày cấp không hợp lệ.' });

        const [codeRows] = await pool.query('SELECT id, code, company_id, assigned_employee_id FROM lic_license_codes WHERE id = ?', [id]);
        if (!codeRows[0]) return res.status(404).json({ error: 'Không tìm thấy mã license.' });
        if (codeRows[0].assigned_employee_id) return res.status(400).json({ error: 'Mã license này đã được cấp cho người khác.' });

        const [empRows] = await pool.query(
            'SELECT e.id, e.full_name, u.company_id FROM lic_employees e JOIN lic_org_units u ON u.id = e.org_unit_id WHERE e.id = ?',
            [employeeId]
        );
        if (!empRows[0]) return res.status(400).json({ error: 'Nhân viên không tồn tại.' });
        if (empRows[0].company_id !== codeRows[0].company_id) return res.status(400).json({ error: 'Nhân viên không thuộc công ty của mã license này.' });

        await pool.query('UPDATE lic_license_codes SET assigned_employee_id = ?, assigned_at = ? WHERE id = ?', [employeeId, issuedDate, id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'ASSIGN_CODE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: codeRows[0].code, description: `Cấp mã license [${codeRows[0].code}] cho nhân viên [${empRows[0].full_name}], ngày cấp ${issuedDate}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cấp phát license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/codes/:id/unassign', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query(
            'SELECT c.id, c.code, c.assigned_employee_id, e.full_name FROM lic_license_codes c LEFT JOIN lic_employees e ON e.id = c.assigned_employee_id WHERE c.id = ?',
            [id]
        );
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy mã license.' });
        if (!rows[0].assigned_employee_id) return res.status(400).json({ error: 'Mã license này chưa được cấp cho ai.' });
        await pool.query('UPDATE lic_license_codes SET assigned_employee_id = NULL, assigned_at = NULL WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'UNASSIGN_CODE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].code, description: `Thu hồi mã license [${rows[0].code}] từ nhân viên [${rows[0].full_name}].` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi thu hồi license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Kỳ mua bản quyền (Admin tạo kỳ + danh mục phần mềm khả dụng trong kỳ) ---
// Tạo kỳ mua kèm luôn danh sách phần mềm (items) trong 1 lượt gửi — validate
// TOÀN BỘ items trước, chỉ ghi khi tất cả hợp lệ; nếu bước ghi hạng mục lỗi
// giữa chừng thì xóa lại kỳ vừa tạo (không để lại kỳ trống/thiếu phần mềm).
app.post('/api/license/rounds', requireAuth, requireAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (!name) return res.status(400).json({ error: 'Tên kỳ mua không được để trống.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng phần mềm trong 1 lần tạo không được vượt quá 200.' });

        const softwareIdSet = new Set();
        const normalizedItems = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const softwareId = Number(it.softwareId);
            const unitPrice = Number(it.unitPrice);
            const expiryDate = String(it.expiryDate || '').trim();
            if (!softwareId) return res.status(400).json({ error: `Dòng ${i + 1}: vui lòng chọn Phần mềm.` });
            if (softwareIdSet.has(softwareId)) return res.status(400).json({ error: `Dòng ${i + 1}: phần mềm này đã được thêm ở dòng khác.` });
            softwareIdSet.add(softwareId);
            if (!Number.isFinite(unitPrice) || unitPrice < 0) return res.status(400).json({ error: `Dòng ${i + 1}: Đơn giá không hợp lệ.` });
            if (!validDateStr(expiryDate)) return res.status(400).json({ error: `Dòng ${i + 1}: Ngày hết hạn không hợp lệ.` });
            normalizedItems.push({ softwareId, unitPrice, expiryDate });
        }
        if (normalizedItems.length > 0) {
            const ids = normalizedItems.map(it => it.softwareId);
            const [softwareRows] = await pool.query(`SELECT id FROM lic_software_catalog WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
            const foundIds = new Set(softwareRows.map(s => s.id));
            if (normalizedItems.some(it => !foundIds.has(it.softwareId))) {
                return res.status(400).json({ error: 'Có phần mềm không tồn tại trong danh mục.' });
            }
        }

        let roundId;
        try {
            const [result] = await pool.query(
                'INSERT INTO lic_purchase_rounds (name, note, status, created_at) VALUES (?, ?, ?, ?)',
                [name, note || null, 'OPEN', new Date().toISOString()]
            );
            roundId = result.insertId;
            if (normalizedItems.length > 0) {
                await pool.query(
                    'INSERT INTO lic_purchase_round_items (round_id, software_id, unit_price, expiry_date) VALUES ?',
                    [normalizedItems.map(it => [roundId, it.softwareId, it.unitPrice, it.expiryDate])]
                );
            }
        } catch (insertErr) {
            if (roundId) await pool.query('DELETE FROM lic_purchase_rounds WHERE id = ?', [roundId]).catch(() => {});
            throw insertErr;
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_ROUND', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Tạo kỳ mua bản quyền [${name}] với ${normalizedItems.length} phần mềm.` });
        res.json({ success: true, id: roundId });
    } catch (err) {
        console.error('❌ Lỗi tạo kỳ mua bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/rounds/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const status = String((req.body && req.body.status) || '').trim().toUpperCase();
        if (!['OPEN', 'CLOSED'].includes(status)) return res.status(400).json({ error: 'Trạng thái không hợp lệ.' });
        const [result] = await pool.query('UPDATE lic_purchase_rounds SET status = ? WHERE id = ?', [status, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy kỳ mua.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_ROUND_STATUS', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Kỳ mua #${id}`, description: `Đổi trạng thái kỳ mua #${id} thành ${status}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cập nhật kỳ mua:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/rounds/:id/items', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const softwareId = Number(req.body && req.body.softwareId);
        const unitPrice = Number(req.body && req.body.unitPrice);
        const expiryDate = String((req.body && req.body.expiryDate) || '').trim();
        if (!softwareId) return res.status(400).json({ error: 'Vui lòng chọn Phần mềm.' });
        if (!Number.isFinite(unitPrice) || unitPrice < 0) return res.status(400).json({ error: 'Đơn giá không hợp lệ.' });
        if (!validDateStr(expiryDate)) return res.status(400).json({ error: 'Ngày hết hạn không hợp lệ.' });

        const [roundRows] = await pool.query('SELECT id, status FROM lic_purchase_rounds WHERE id = ?', [id]);
        if (!roundRows[0]) return res.status(404).json({ error: 'Không tìm thấy kỳ mua.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ mua đã đóng, không thể thêm phần mềm.' });
        const [softwareRows] = await pool.query('SELECT id, name FROM lic_software_catalog WHERE id = ?', [softwareId]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });
        const [dupRows] = await pool.query('SELECT id FROM lic_purchase_round_items WHERE round_id = ? AND software_id = ?', [id, softwareId]);
        if (dupRows[0]) return res.status(400).json({ error: 'Phần mềm này đã có trong kỳ mua.' });

        const [result] = await pool.query(
            'INSERT INTO lic_purchase_round_items (round_id, software_id, unit_price, expiry_date) VALUES (?, ?, ?, ?)',
            [id, softwareId, unitPrice, expiryDate]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'ADD_ROUND_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: softwareRows[0].name, description: `Thêm phần mềm [${softwareRows[0].name}] vào kỳ mua #${id}, đơn giá ${unitPrice}, hạn ${expiryDate}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm phần mềm vào kỳ mua:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/rounds/:roundId/items/:itemId', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { roundId, itemId } = req.params;
        const [itemRows] = await pool.query('SELECT id FROM lic_purchase_round_items WHERE id = ? AND round_id = ?', [itemId, roundId]);
        if (!itemRows[0]) return res.status(404).json({ error: 'Không tìm thấy hạng mục trong kỳ mua.' });
        const [regRows] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_purchase_registrations WHERE round_item_id = ?', [itemId]);
        if (regRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đã có công ty đăng ký mua phần mềm này trong kỳ.' });
        await pool.query('DELETE FROM lic_purchase_round_items WHERE id = ?', [itemId]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_ROUND_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Hạng mục #${itemId}`, description: `Xóa hạng mục #${itemId} khỏi kỳ mua #${roundId}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa hạng mục kỳ mua:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Đăng ký mua bản quyền (công ty đăng ký nhu cầu + Admin duyệt/từ chối) ---
// 1 công ty đăng ký NHIỀU phần mềm cùng lúc (items) cho 1 kỳ mua — validate
// toàn bộ trước, ghi bằng 1 câu INSERT nhiều dòng (thành công/thất bại cùng
// lúc, không tạo dở dang nếu 1 dòng lỗi).
app.post('/api/license/registrations', requireAuth, requireAdmin, async (req, res) => {
    try {
        const roundId = Number(req.body && req.body.roundId);
        const companyId = Number(req.body && req.body.companyId);
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (!roundId) return res.status(400).json({ error: 'Vui lòng chọn Kỳ mua.' });
        if (!companyId) return res.status(400).json({ error: 'Vui lòng chọn Công ty.' });
        if (items.length === 0) return res.status(400).json({ error: 'Vui lòng thêm ít nhất 1 phần mềm để đăng ký.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng phần mềm trong 1 lần đăng ký không được vượt quá 200.' });

        const [roundRows] = await pool.query('SELECT id, status FROM lic_purchase_rounds WHERE id = ?', [roundId]);
        if (!roundRows[0]) return res.status(400).json({ error: 'Kỳ mua không tồn tại.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ mua đã đóng, không thể đăng ký.' });
        const [companyRows] = await pool.query('SELECT id, name FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });

        const roundItemIdSet = new Set();
        const normalizedItems = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const roundItemId = Number(it.roundItemId);
            const requestedQuantity = Number(it.requestedQuantity);
            if (!roundItemId) return res.status(400).json({ error: `Dòng ${i + 1}: vui lòng chọn Phần mềm.` });
            if (roundItemIdSet.has(roundItemId)) return res.status(400).json({ error: `Dòng ${i + 1}: phần mềm này đã được đăng ký ở dòng khác.` });
            roundItemIdSet.add(roundItemId);
            if (!Number.isInteger(requestedQuantity) || requestedQuantity < 1 || requestedQuantity > 5000) return res.status(400).json({ error: `Dòng ${i + 1}: Số lượng phải là số nguyên từ 1 đến 5000.` });
            normalizedItems.push({ roundItemId, requestedQuantity });
        }

        const itemIds = normalizedItems.map(it => it.roundItemId);
        const [itemRows] = await pool.query(
            `SELECT * FROM lic_purchase_round_items WHERE round_id = ? AND id IN (${itemIds.map(() => '?').join(',')})`,
            [roundId, ...itemIds]
        );
        const itemsById = new Map(itemRows.map(r => [r.id, r]));
        if (normalizedItems.some(it => !itemsById.has(it.roundItemId))) {
            return res.status(400).json({ error: 'Có hạng mục phần mềm không thuộc kỳ mua này.' });
        }

        const softwareIds = itemRows.map(r => r.software_id);
        const [usageRows] = await pool.query(
            `SELECT software_id, COUNT(*) AS cnt FROM lic_license_codes WHERE company_id = ? AND software_id IN (${softwareIds.map(() => '?').join(',')}) GROUP BY software_id`,
            [companyId, ...softwareIds]
        );
        const usageBySoftware = new Map(usageRows.map(r => [r.software_id, r.cnt]));

        const insertValues = normalizedItems.map(it => {
            const item = itemsById.get(it.roundItemId);
            const currentQuantity = usageBySoftware.get(item.software_id) || 0;
            const unitPrice = Number(item.unit_price);
            const totalAmount = it.requestedQuantity * unitPrice;
            return [roundId, it.roundItemId, companyId, currentQuantity, it.requestedQuantity, unitPrice, totalAmount, item.expiry_date, 'PENDING', note || null, new Date().toISOString()];
        });

        await pool.query(
            'INSERT INTO lic_purchase_registrations (round_id, round_item_id, company_id, current_quantity, requested_quantity, unit_price, total_amount, expiry_date, status, note, created_at) VALUES ?',
            [insertValues]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: companyRows[0].name, description: `Công ty [${companyRows[0].name}] đăng ký mua ${normalizedItems.length} phần mềm (kỳ mua #${roundId}), chờ duyệt.` });
        res.json({ success: true, count: normalizedItems.length });
    } catch (err) {
        console.error('❌ Lỗi tạo đăng ký mua bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/registrations/:id/approve', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_purchase_registrations WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đăng ký.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Đăng ký này đã được xử lý.' });
        await pool.query('UPDATE lic_purchase_registrations SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?', ['APPROVED', req.user.username, new Date().toISOString(), id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'APPROVE_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Đăng ký #${id}`, description: `Duyệt đăng ký mua bản quyền #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi duyệt đăng ký:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/registrations/:id/reject', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_purchase_registrations WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đăng ký.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Đăng ký này đã được xử lý.' });
        await pool.query('UPDATE lic_purchase_registrations SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?', ['REJECTED', req.user.username, new Date().toISOString(), id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'REJECT_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Đăng ký #${id}`, description: `Từ chối đăng ký mua bản quyền #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi từ chối đăng ký:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Nhập CSV hàng loạt (Tổ chức công ty / Nhân viên) ---
// Client chỉ parse CSV thành mảng dòng thô rồi gửi lên — server tự validate
// và tạo dữ liệu hoàn toàn, không tin cấu trúc/quan hệ do client suy luận sẵn.
app.post('/api/license/org-units/import', requireAuth, requireAdmin, async (req, res) => {
    try {
        const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows.slice(0, 2000) : [];
        if (rows.length === 0) return res.status(400).json({ error: 'File không có dữ liệu hợp lệ.' });

        const [existingCompanies] = await pool.query('SELECT * FROM lic_companies');
        const companyByCode = new Map(existingCompanies.map(c => [c.code, c]));
        const [existingUnits] = await pool.query('SELECT * FROM lic_org_units');
        const unitByKey = new Map(existingUnits.map(u => [`${u.company_id}::${u.name}`, u]));

        const errors = [];
        let companiesCreated = 0, unitsCreated = 0;

        // Bước 1: đảm bảo mọi công ty được nhắc tới đều tồn tại (tạo mới nếu thiếu).
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i] || {};
            const code = String(r.ma_cong_ty || '').trim().toUpperCase();
            const name = String(r.ten_cong_ty || '').trim();
            if (!code || !name) { errors.push(`Dòng ${i + 2}: thiếu mã hoặc tên công ty.`); continue; }
            if (!companyByCode.has(code)) {
                try {
                    const [result] = await pool.query('INSERT INTO lic_companies (name, code, active) VALUES (?, ?, TRUE)', [name, code]);
                    companyByCode.set(code, { id: result.insertId, name, code });
                    companiesCreated++;
                } catch (e) {
                    if (e.code === 'ER_DUP_ENTRY') errors.push(`Dòng ${i + 2}: công ty tên [${name}] đã tồn tại với mã khác.`);
                    else throw e;
                }
            }
        }

        // Bước 2: tạo đơn vị theo nhiều lượt — mỗi lượt chỉ tạo được các dòng có
        // đơn vị cha đã tồn tại (hoặc không cha); lặp tới khi hết tiến triển, để
        // không phụ thuộc thứ tự dòng trong file (cha có thể nằm sau con).
        const pending = rows
            .map((r, i) => ({ r: r || {}, rowNo: i + 2 }))
            .filter(({ r }) => String(r.ten_don_vi || '').trim());

        let progress = true;
        while (progress && pending.length > 0) {
            progress = false;
            for (let idx = pending.length - 1; idx >= 0; idx--) {
                const { r, rowNo } = pending[idx];
                const code = String(r.ma_cong_ty || '').trim().toUpperCase();
                const company = companyByCode.get(code);
                if (!company) { pending.splice(idx, 1); continue; } // đã báo lỗi ở bước 1
                const unitName = String(r.ten_don_vi || '').trim();
                const level = String(r.cap || '').trim();
                const parentName = String(r.don_vi_cha || '').trim();
                if (!level) { errors.push(`Dòng ${rowNo}: thiếu Cấp cho đơn vị [${unitName}].`); pending.splice(idx, 1); continue; }

                let parentId = null;
                if (parentName) {
                    const parent = unitByKey.get(`${company.id}::${parentName}`);
                    if (!parent) continue; // chưa tạo được cha, thử lượt sau
                    parentId = parent.id;
                }

                const key = `${company.id}::${unitName}`;
                if (unitByKey.has(key)) { pending.splice(idx, 1); continue; } // đã có sẵn, bỏ qua
                const [result] = await pool.query(
                    'INSERT INTO lic_org_units (company_id, parent_id, name, level_label, sort_order) VALUES (?, ?, ?, ?, 0)',
                    [company.id, parentId, unitName, level]
                );
                unitByKey.set(key, { id: result.insertId, company_id: company.id, name: unitName });
                unitsCreated++;
                pending.splice(idx, 1);
                progress = true;
            }
        }
        for (const { r, rowNo } of pending) {
            errors.push(`Dòng ${rowNo}: không tìm thấy đơn vị cha [${r.don_vi_cha}] — kiểm tra lại tên hoặc thứ tự dòng.`);
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'IMPORT_ORG_UNITS', status: errors.length ? 'PARTIAL' : 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: 'Tổ chức công ty', description: `Nhập CSV: ${companiesCreated} công ty mới, ${unitsCreated} đơn vị mới, ${errors.length} lỗi.` });
        res.json({ success: true, companiesCreated, unitsCreated, errors });
    } catch (err) {
        console.error('❌ Lỗi nhập CSV tổ chức công ty:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/employees/import', requireAuth, requireAdmin, async (req, res) => {
    try {
        const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows.slice(0, 2000) : [];
        if (rows.length === 0) return res.status(400).json({ error: 'File không có dữ liệu hợp lệ.' });

        const [companies] = await pool.query('SELECT * FROM lic_companies');
        const companyByCode = new Map(companies.map(c => [c.code, c]));
        const [units] = await pool.query('SELECT * FROM lic_org_units');
        const unitByKey = new Map(units.map(u => [`${u.company_id}::${u.name}`, u]));
        const [existingEmployees] = await pool.query('SELECT * FROM lic_employees');
        const employeeByCode = new Map(existingEmployees.filter(e => e.employee_code).map(e => [e.employee_code, e]));

        const errors = [];
        let created = 0, updated = 0;

        for (let i = 0; i < rows.length; i++) {
            const r = rows[i] || {};
            const rowNo = i + 2;
            const fullName = String(r.ho_ten || '').trim();
            const companyCode = String(r.ma_cong_ty || '').trim().toUpperCase();
            const unitName = String(r.don_vi || '').trim();
            const employeeCode = String(r.ma_nv || '').trim();
            const title = String(r.chuc_danh || '').trim();
            const email = String(r.email || '').trim();

            if (!fullName) { errors.push(`Dòng ${rowNo}: thiếu Họ và tên.`); continue; }
            const company = companyByCode.get(companyCode);
            if (!company) { errors.push(`Dòng ${rowNo}: không tìm thấy công ty mã [${companyCode}].`); continue; }
            const unit = unitByKey.get(`${company.id}::${unitName}`);
            if (!unit) { errors.push(`Dòng ${rowNo}: không tìm thấy đơn vị [${unitName}] trong công ty [${companyCode}] — nhập Tổ chức công ty trước.`); continue; }

            if (employeeCode && employeeByCode.has(employeeCode)) {
                const existing = employeeByCode.get(employeeCode);
                await pool.query(
                    'UPDATE lic_employees SET org_unit_id = ?, full_name = ?, title = ?, email = ? WHERE id = ?',
                    [unit.id, fullName, title || null, email || null, existing.id]
                );
                updated++;
            } else {
                const [result] = await pool.query(
                    'INSERT INTO lic_employees (org_unit_id, full_name, title, employee_code, email, active) VALUES (?, ?, ?, ?, ?, TRUE)',
                    [unit.id, fullName, title || null, employeeCode || null, email || null]
                );
                if (employeeCode) employeeByCode.set(employeeCode, { id: result.insertId, employee_code: employeeCode });
                created++;
            }
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'IMPORT_EMPLOYEES', status: errors.length ? 'PARTIAL' : 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: 'Danh sách nhân viên', description: `Nhập CSV: ${created} nhân viên mới, ${updated} cập nhật, ${errors.length} lỗi.` });
        res.json({ success: true, created, updated, errors });
    } catch (err) {
        console.error('❌ Lỗi nhập CSV nhân viên:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:${PORT}`);
});
