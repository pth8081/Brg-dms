require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { PDFDocument, rgb, degrees } = require('pdf-lib');
const fontkit = require('@pdf-lib/fontkit');
const multer = require('multer');
const { Client: LdapClient } = require('ldapts');
const nodemailer = require('nodemailer');

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
// Toàn bộ JS đã tách ra file riêng (public/app.js, nạp qua <script src>) và
// 315 thuộc tính onclick=/onchange=/oninput=/onsubmit= nội tuyến đã chuyển
// sang cơ chế điều phối sự kiện (data-evt-*, xem app.js) — nên script-src và
// script-src-attr KHÔNG còn cần 'unsafe-inline': mọi <script> tiêm được qua
// lỗ XSS (nếu có) hoặc thuộc tính onclick= tiêm được đều bị CSP chặn thẳng,
// không cần dựa hoàn toàn vào lớp escape ở tầng ứng dụng nữa.
// style-src VẪN giữ 'unsafe-inline' — còn 8 chỗ style="..." nội tuyến thuần
// CSS (không có mã JS chạy được), rủi ro thấp hơn hẳn script-src nên chấp
// nhận giữ lại thay vì viết lại code sinh biểu đồ SVG đang hoạt động tốt.
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "https://cdn.tailwindcss.com"],
            scriptSrcAttr: ["'none'"],
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

// Dành riêng cho các route /api/license/* — cho phép Admin HOẶC tài khoản có
// quyền "Người quản lý License" (perms.licenseManager, toàn quyền trong module
// Bản quyền nhưng KHÔNG có quyền Admin ở các module khác) — không dùng
// requireAdmin thẳng cho các route này nữa để không khóa License Manager ra.
function requireLicenseOrAdmin(req, res, next) {
    if (!req.user || !req.user.perms || (!req.user.perms.admin && !req.user.perms.licenseManager)) {
        return res.status(403).json({ error: 'Yêu cầu quyền Quản trị viên hoặc Người quản lý License.' });
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

// --- Đồng bộ tài khoản Active Directory (module AD) ---
// Độc lập với ldapAuthenticate ở trên (dùng để đăng nhập) — bind bằng 1 tài
// khoản DỊCH VỤ có quyền duyệt thư mục, tìm toàn bộ user trong searchBaseDn,
// lưu snapshot vào ad_accounts. AD không lưu sẵn "ngày disable" nên hệ thống
// tự ghi nhận: chỉ đặt disabled_at = hôm nay ở đúng lần đồng bộ ĐẦU TIÊN phát
// hiện tài khoản chuyển từ active sang disable (so với lần đồng bộ trước).
async function ldapSyncAccounts() {
    const ldapConfig = await getLdapConfig();
    if (!ldapConfig || !ldapConfig.adSyncEnabled || !ldapConfig.url || !ldapConfig.serviceBindDn || !ldapConfig.searchBaseDn) {
        throw new Error('Chưa cấu hình đủ thông tin để đồng bộ AD (URL/Bind DN/Base DN).');
    }
    const isSecure = /^ldaps:\/\//i.test(String(ldapConfig.url || ''));
    const client = new LdapClient({
        url: ldapConfig.url,
        timeout: 20000,
        connectTimeout: 5000,
        ...(isSecure ? { tlsOptions: { rejectUnauthorized: ldapConfig.tlsRejectUnauthorized !== false } } : {})
    });
    let entries;
    try {
        await client.bind(ldapConfig.serviceBindDn, ldapConfig.servicePassword || '');
        const attributes = ['sAMAccountName', 'displayName', 'mail', 'userAccountControl'];
        if (ldapConfig.companyAttr) attributes.push(ldapConfig.companyAttr);
        if (ldapConfig.orgUnitAttr) attributes.push(ldapConfig.orgUnitAttr);
        // AD mặc định giới hạn ~1000 kết quả/lượt tìm kiếm (LDAP code 0x4 —
        // sizeLimitExceeded) nếu không bật phân trang; bật paged để client tự
        // lấy hết nhiều trang, không phụ thuộc quy mô OU tìm kiếm.
        const result = await client.search(ldapConfig.searchBaseDn, {
            scope: 'sub',
            filter: '(&(objectClass=user)(objectCategory=person))',
            attributes,
            paged: { pageSize: 1000 }
        });
        entries = result.searchEntries;
    } finally {
        try { await client.unbind(); } catch (e) { /* bỏ qua lỗi khi đóng kết nối */ }
    }

    const [existingRows] = await pool.query('SELECT username, active FROM ad_accounts');
    const wasActiveByUsername = new Map(existingRows.map(r => [r.username, !!r.active]));
    const today = new Date().toISOString().slice(0, 10);
    const nowIso = new Date().toISOString();

    let created = 0, updated = 0;
    for (const entry of entries) {
        const username = String(entry.sAMAccountName || '').trim();
        if (!username) continue;
        const fullName = String(entry.displayName || '').trim() || null;
        const email = String(entry.mail || '').trim() || null;
        const uac = Number(entry.userAccountControl) || 0;
        const active = (uac & 2) === 0; // bit ACCOUNTDISABLE
        const company = ldapConfig.companyAttr ? (String(entry[ldapConfig.companyAttr] || '').trim() || null) : null;
        const orgUnit = ldapConfig.orgUnitAttr ? (String(entry[ldapConfig.orgUnitAttr] || '').trim() || null) : null;

        if (!wasActiveByUsername.has(username)) {
            // Lần đầu thấy tài khoản này — nếu đã disable ngay từ lần đầu thì
            // không biết chính xác ngày disable thật, để trống thay vì đoán.
            await pool.query(
                'INSERT INTO ad_accounts (username, full_name, email, active, company, org_unit, disabled_at, last_synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [username, fullName, email, active, company, orgUnit, null, nowIso]
            );
            created++;
        } else {
            const wasActive = wasActiveByUsername.get(username);
            const justDisabled = wasActive && !active;
            if (justDisabled) {
                await pool.query(
                    'UPDATE ad_accounts SET full_name=?, email=?, active=?, company=?, org_unit=?, disabled_at=?, last_synced_at=? WHERE username=?',
                    [fullName, email, active, company, orgUnit, today, nowIso, username]
                );
            } else if (active) {
                await pool.query(
                    'UPDATE ad_accounts SET full_name=?, email=?, active=?, company=?, org_unit=?, disabled_at=NULL, last_synced_at=? WHERE username=?',
                    [fullName, email, active, company, orgUnit, nowIso, username]
                );
            } else {
                await pool.query(
                    'UPDATE ad_accounts SET full_name=?, email=?, active=?, company=?, org_unit=?, last_synced_at=? WHERE username=?',
                    [fullName, email, active, company, orgUnit, nowIso, username]
                );
            }
            updated++;
        }
    }
    return { total: entries.length, created, updated };
}

async function getAdLastSyncAt() {
    const [rows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'adLastSyncAt'");
    if (!rows[0]) return 0;
    const v = typeof rows[0].config_value === 'string' ? JSON.parse(rows[0].config_value) : rows[0].config_value;
    return v && v.at ? new Date(v.at).getTime() : 0;
}
async function setAdLastSyncAt() {
    const payload = JSON.stringify({ at: new Date().toISOString() });
    await pool.query(
        'INSERT INTO app_configs (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?',
        ['adLastSyncAt', payload, payload]
    );
}
// Đồng bộ AD theo lịch hàng ngày: kiểm tra mỗi giờ xem đã quá 24h kể từ lần
// đồng bộ gần nhất chưa, thay vì dùng cron riêng — đơn giản, không cần thêm
// hạ tầng, phù hợp với 1 tiến trình Node duy nhất của ứng dụng này.
async function maybeRunScheduledAdSync() {
    try {
        const ldapConfig = await getLdapConfig();
        if (!ldapConfig || !ldapConfig.adSyncEnabled) return;
        const lastSyncAt = await getAdLastSyncAt();
        if (Date.now() - lastSyncAt < 24 * 60 * 60 * 1000) return;
        const result = await ldapSyncAccounts();
        await setAdLastSyncAt();
        console.log(`🔄 Đồng bộ AD tự động theo lịch: ${result.created} mới, ${result.updated} cập nhật (tổng ${result.total}).`);
    } catch (e) {
        console.error('❌ Lỗi đồng bộ AD theo lịch:', e.message);
    }
}
setInterval(maybeRunScheduledAdSync, 60 * 60 * 1000);
setTimeout(maybeRunScheduledAdSync, 10000);

// --- Module Quản lý CNTT: cấu hình email SMTP thật + engine nhắc hết hạn ---
// Đọc cấu hình SMTP thật (kể cả tài khoản/mật khẩu) — CHỈ dùng nội bộ server,
// khác với bootstrap trả về client (phải che mật khẩu, xem route bên dưới).
async function getEmailConfig() {
    const [rows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'emailConfig'");
    if (!rows[0]) return null;
    return typeof rows[0].config_value === 'string' ? JSON.parse(rows[0].config_value) : rows[0].config_value;
}

function buildMailTransporter(emailConfig) {
    return nodemailer.createTransport({
        host: emailConfig.smtpHost,
        port: Number(emailConfig.smtpPort) || 587,
        secure: !!emailConfig.smtpSecure,
        auth: (emailConfig.smtpUser && emailConfig.smtpPass) ? { user: emailConfig.smtpUser, pass: emailConfig.smtpPass } : undefined,
        // Không để 1 SMTP không phản hồi (sai host/mạng chặn) làm treo request
        // lâu — báo lỗi sớm để Admin biết cấu hình sai thay vì chờ vô thời hạn.
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        socketTimeout: 10000
    });
}

// Gửi email THẬT qua SMTP đã cấu hình — dùng chung cho mọi nơi cần gửi email
// thật trong hệ thống (hiện tại: nhắc hết hạn module CNTT). Luôn ghi audit
// log kết quả (thành công/thất bại/bỏ qua) để Admin tra cứu trong Log Hệ Thống.
async function sendRealEmail(to, subject, html) {
    if (!to) return { skipped: true };
    const emailConfig = await getEmailConfig();
    if (!emailConfig || !emailConfig.enabled) {
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'SEND_EMAIL_SKIPPED', status: 'FAILED', targetObject: to, description: `Email "${subject}" tới ${to} bị bỏ qua vì cấu hình SMTP đang tắt.` });
        return { skipped: true };
    }
    try {
        const transporter = buildMailTransporter(emailConfig);
        await transporter.sendMail({ from: emailConfig.senderEmail || 'dms-noreply@company.com', to, subject, html });
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'SEND_EMAIL_SUCCESS', status: 'SUCCESS', targetObject: to, description: `Đã gửi email "${subject}" tới ${to}.` });
        return { success: true };
    } catch (err) {
        console.error(`❌ Lỗi gửi email tới ${to}:`, err.message);
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'SEND_EMAIL_FAILED', status: 'FAILED', targetObject: to, description: `Gửi email "${subject}" tới ${to} thất bại: ${err.message}` });
        return { success: false, error: err.message };
    }
}

function escapeHtmlServer(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function getItReminderConfig() {
    const [rows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'itReminderConfig'");
    const raw = rows[0] ? (typeof rows[0].config_value === 'string' ? JSON.parse(rows[0].config_value) : rows[0].config_value) : {};
    const days = Array.isArray(raw.daysBeforeList) ? raw.daysBeforeList.map(Number).filter(n => Number.isInteger(n) && n >= 1 && n <= 365) : [];
    return {
        enabled: raw.enabled !== false,
        daysBeforeList: days.length ? [...new Set(days)].sort((a, b) => b - a) : [30, 15, 7]
    };
}

// Quét toàn bộ đầu mục CNTT còn theo dõi (active=1), gửi email nhắc tới người
// phụ trách + toàn bộ Admin khi hôm nay khớp đúng 1 trong các mốc đã cấu hình
// (VD 30/15/7 ngày trước hạn) HOẶC đúng ngày hết hạn (mốc 0 — LUÔN kiểm tra,
// không phụ thuộc cấu hình, để không bao giờ bỏ sót thông báo ngày hết hạn
// thật sự). it_reminder_sent khoá theo (item, ngày hết hạn, mốc) để 1 mốc chỉ
// gửi đúng 1 lần cho mỗi chu kỳ hạn — nếu đầu mục được gia hạn sang ngày hết
// hạn mới, khoá đổi theo nên sẽ được nhắc lại từ đầu, đúng như mong đợi.
async function runExpiryReminderCheck() {
    const reminderConfig = await getItReminderConfig();
    if (!reminderConfig.enabled) return { checked: 0, sent: 0, disabled: true };
    const thresholds = [...new Set([...reminderConfig.daysBeforeList, 0])];

    const [items] = await pool.query(
        'SELECT i.*, c.name AS category_name FROM it_items i JOIN it_categories c ON c.id = i.category_id WHERE i.active = 1'
    );
    const [allUsers] = await pool.query('SELECT id, email, active, perms FROM users');
    const adminEmails = allUsers
        .filter(u => u.active && (typeof u.perms === 'string' ? JSON.parse(u.perms || '{}') : (u.perms || {})).admin)
        .map(u => u.email).filter(Boolean);
    const emailById = new Map(allUsers.map(u => [u.id, u.email]));

    const todayStr = fmtDate(new Date());
    let sentCount = 0;
    for (const item of items) {
        const expiryStr = fmtDate(item.expiry_date);
        const daysLeft = Math.round((new Date(`${expiryStr}T00:00:00`) - new Date(`${todayStr}T00:00:00`)) / 86400000);
        for (const daysBefore of thresholds) {
            if (daysLeft !== daysBefore) continue;
            const [existing] = await pool.query(
                'SELECT id FROM it_reminder_sent WHERE item_id = ? AND expiry_date = ? AND days_before = ?',
                [item.id, expiryStr, daysBefore]
            );
            if (existing[0]) continue;

            const recipients = new Set(adminEmails);
            if (item.owner_user_id && emailById.get(item.owner_user_id)) recipients.add(emailById.get(item.owner_user_id));
            if (item.owner_email) recipients.add(item.owner_email);
            const toList = [...recipients].filter(Boolean);

            if (toList.length) {
                const subject = daysBefore === 0
                    ? `[DMS] "${item.name}" đã đến hạn hôm nay (${expiryStr})`
                    : `[DMS] "${item.name}" sẽ hết hạn sau ${daysBefore} ngày (${expiryStr})`;
                const html = `<p>Đầu mục <b>${escapeHtmlServer(item.name)}</b> (${escapeHtmlServer(item.category_name)})`
                    + `${item.provider ? ` — nhà cung cấp <b>${escapeHtmlServer(item.provider)}</b>` : ''} `
                    + `${daysBefore === 0 ? 'đã đến ngày hết hạn' : `sẽ hết hạn trong <b>${daysBefore} ngày</b> nữa`} `
                    + `(ngày hết hạn: <b>${expiryStr}</b>).</p>`
                    + `<p>Vui lòng kiểm tra và gia hạn kịp thời để tránh gián đoạn dịch vụ.</p>`;
                for (const to of toList) {
                    await sendRealEmail(to, subject, html);
                }
                sentCount++;
            }
            // Vẫn ghi nhận đã xử lý mốc này dù không có ai nhận (chưa gán người phụ
            // trách và không có email Admin nào) — tránh quét lại y hệt mãi mãi.
            await pool.query(
                'INSERT INTO it_reminder_sent (item_id, expiry_date, days_before, sent_at) VALUES (?, ?, ?, ?)',
                [item.id, expiryStr, daysBefore, new Date().toISOString()]
            );
        }
    }
    return { checked: items.length, sent: sentCount };
}

async function getItExpiryLastCheckAt() {
    const [rows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'itExpiryLastCheckAt'");
    if (!rows[0]) return 0;
    const v = typeof rows[0].config_value === 'string' ? JSON.parse(rows[0].config_value) : rows[0].config_value;
    return v && v.at ? new Date(v.at).getTime() : 0;
}
async function setItExpiryLastCheckAt() {
    const payload = JSON.stringify({ at: new Date().toISOString() });
    await pool.query(
        'INSERT INTO app_configs (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?',
        ['itExpiryLastCheckAt', payload, payload]
    );
}
// Kiểm tra hạn CNTT theo lịch hàng ngày — cùng cơ chế với đồng bộ AD ở trên
// (kiểm tra mỗi giờ xem đã quá 24h kể từ lần chạy gần nhất chưa), không cần
// thêm hạ tầng cron riêng.
async function maybeRunScheduledExpiryCheck() {
    try {
        const lastCheckAt = await getItExpiryLastCheckAt();
        if (Date.now() - lastCheckAt < 24 * 60 * 60 * 1000) return;
        const result = await runExpiryReminderCheck();
        await setItExpiryLastCheckAt();
        console.log(`🔔 Kiểm tra hạn CNTT theo lịch: ${result.checked} đầu mục, ${result.sent} email nhắc đã gửi.`);
    } catch (e) {
        console.error('❌ Lỗi kiểm tra hạn CNTT theo lịch:', e.message);
    }
}
setInterval(maybeRunScheduledExpiryCheck, 60 * 60 * 1000);
setTimeout(maybeRunScheduledExpiryCheck, 15000);

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
            emailConfig: (() => {
                const raw = configMap.emailConfig
                    ? (typeof configMap.emailConfig === 'string' ? JSON.parse(configMap.emailConfig) : configMap.emailConfig)
                    : {};
                return {
                    enabled: raw.enabled !== false,
                    smtpHost: raw.smtpHost || 'smtp.gmail.com',
                    smtpPort: raw.smtpPort || 587,
                    smtpSecure: raw.smtpSecure || false,
                    senderEmail: raw.senderEmail || 'dms-noreply@company.com',
                    smtpUser: raw.smtpUser || '',
                    // Bảo mật: mật khẩu SMTP thật không bao giờ trả về cho client, chỉ
                    // báo đã có cấu hình hay chưa — giống hệt mật khẩu tài khoản dịch
                    // vụ AD ở ldapConfig bên dưới.
                    smtpPass: raw.smtpPass ? '••••••••' : ''
                };
            })(),
            ldapConfig: (() => {
                const raw = configMap.ldapConfig
                    ? (typeof configMap.ldapConfig === 'string' ? JSON.parse(configMap.ldapConfig) : configMap.ldapConfig)
                    : {};
                return {
                    enabled: raw.enabled || false,
                    url: raw.url || '',
                    bindFormat: raw.bindFormat || 'upn',
                    domain: raw.domain || '',
                    tlsRejectUnauthorized: raw.tlsRejectUnauthorized !== false,
                    // Đồng bộ tài khoản AD (module AD) — mật khẩu tài khoản dịch vụ
                    // KHÔNG bao giờ trả về thật cho client, chỉ báo đã có cấu hình hay
                    // chưa (giống hệt cách xử lý mật khẩu user ở bootstrap).
                    adSyncEnabled: raw.adSyncEnabled || false,
                    serviceBindDn: raw.serviceBindDn || '',
                    servicePassword: raw.servicePassword ? '••••••••' : '',
                    searchBaseDn: raw.searchBaseDn || '',
                    companyAttr: raw.companyAttr || '',
                    orgUnitAttr: raw.orgUnitAttr || ''
                };
            })(),
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
// system_logs KHÔNG còn nằm trong danh sách này — bảng log dùng route riêng
// (POST/DELETE /api/logs) thay vì cơ chế sync-theo-mảng chung, vì kiểu sync
// "so sánh ID để suy luận có xoá hay không" vốn dùng cho các bảng nhỏ/toàn bộ
// dữ liệu tải hết 1 lần sẽ PHÁ HUỶ log khi bảng thật đã vượt quá 300 dòng
// (bootstrap chỉ tải 300 log mới nhất) — xem route mới bên dưới để biết lý do.
const KNOWN_TABLES = new Set(['docs', 'users', 'depts', 'cats', 'workflows', 'deptWorkflows', 'emailConfig', 'ldapConfig']);
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
        // Số thứ tự tiếp theo PHẢI tính từ số hậu tố LỚN NHẤT đang thực sự tồn
        // tại trong các mã hiện có (không phải đếm số lượng mã) — nếu dùng
        // COUNT, xoá vĩnh viễn (Purge) 1 tài liệu ở giữa dãy số làm count giảm
        // đi, sinh lại đúng số của 1 mã còn tồn tại phía sau -> ER_DUP_ENTRY lặp
        // lại vô hạn (không tự phục hồi) cho MỌI upload mới của phòng ban/phân
        // loại đó. Dùng MAX số hậu tố thì mã mới luôn lớn hơn mọi mã hiện có.
        async function nextCodeForPrefix(prefix) {
            if (!codeSeqCache.has(prefix)) {
                const [rows] = await pool.query('SELECT code FROM docs WHERE code LIKE ?', [`${prefix}%`]);
                let maxSeq = 0;
                for (const r of rows) {
                    const n = parseInt(r.code.slice(prefix.length), 10);
                    if (Number.isFinite(n) && n > maxSeq) maxSeq = n;
                }
                codeSeqCache.set(prefix, maxSeq + 1);
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
                let docGroupId, versionNo, code, ver, workflowId, prefix;

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
                    prefix = `BRG-${deptAbbr}-${catAbbr}-`;
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

                // Mã tài liệu mới sinh ra từ bộ đếm trong bộ nhớ (không atomic) có thể
                // trùng với 1 request khác vừa insert xong gần như cùng lúc — ràng buộc
                // UNIQUE (code, version_no) ở CSDL sẽ chặn insert đó lại; khi gặp đúng
                // lỗi này (chỉ với tài liệu MỚI, chưa từng insert code cũ nào), làm mới
                // bộ đếm từ CSDL thực tế rồi sinh mã khác và thử lại (tối đa vài lần).
                let insertAttempts = 0;
                while (true) {
                    try {
                        await pool.query(
                            `INSERT INTO docs (id, code, title, ver, dept, cat, summary, file_name, file_type, file_path, created_by, creator_username, created_at, workflow_id, current_step_order, status, history, doc_group_id, version_no)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                            [id, code, finalTitle, ver, finalDept, finalCat, summary, file.originalname, 'application/pdf', filePath,
                                req.user.name, req.user.username, new Date().toISOString(), workflowId, 1, 'PENDING', JSON.stringify([]),
                                docGroupId, versionNo]
                        );
                        break;
                    } catch (insertErr) {
                        const isCodeConflict = mode !== 'update' && insertErr.code === 'ER_DUP_ENTRY' &&
                            /uq_docs_code_version/.test(insertErr.sqlMessage || '');
                        insertAttempts++;
                        if (!isCodeConflict || insertAttempts >= 5) throw insertErr;
                        codeSeqCache.delete(prefix);
                        code = `${prefix}${String(await nextCodeForPrefix(prefix)).padStart(3, '0')}`;
                    }
                }

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
    if (['docs', 'users', 'depts', 'cats', 'workflows'].includes(table)) {
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
            const [workflowRows] = await pool.query('SELECT id, steps FROM workflows');
            const totalStepsById = new Map(workflowRows.map(w => {
                const steps = typeof w.steps === 'string' ? JSON.parse(w.steps || '[]') : (w.steps || []);
                return [w.id, steps.length || 1];
            }));

            function canApproveStep(existingDoc) {
                if (req.user.perms.admin) return true;
                const cfg = deptWorkflows[existingDoc.dept];
                if (!cfg || !cfg.approvers) return false;
                return cfg.approvers[existingDoc.current_step_order] === req.user.username;
            }
            // Server tự tính transition hợp lệ duy nhất cho 1 lượt duyệt/từ chối —
            // KHÔNG tin currentStepOrder/status/history client gửi lên nguyên vẹn
            // (trước đây chỉ kiểm tra người dùng có phải người duyệt bước hiện tại
            // hay không, rồi ghi thẳng toàn bộ 3 giá trị này từ client — cho phép
            // người duyệt bước 1 tự ý gửi thẳng status=APPROVED/currentStepOrder ở
            // bước cuối kèm history bịa để "nhảy cóc" qua các bước duyệt sau).
            // Trả về { ok: true } nếu hợp lệ, hoặc { ok: false, error } nếu không.
            function validateWorkflowTransition(existingDoc, newStatus, newStepOrder, newHistory, existingHistory) {
                if (existingDoc.status !== 'PENDING') {
                    return { ok: false, error: `Tài liệu [${existingDoc.code}] đã được xử lý xong (${existingDoc.status}), không thể sửa lại.` };
                }
                if (!Array.isArray(newHistory) || newHistory.length !== existingHistory.length + 1) {
                    return { ok: false, error: `Dữ liệu duyệt tài liệu [${existingDoc.code}] không hợp lệ.` };
                }
                for (let i = 0; i < existingHistory.length; i++) {
                    if (JSON.stringify(newHistory[i]) !== JSON.stringify(existingHistory[i])) {
                        return { ok: false, error: `Không được sửa lịch sử duyệt đã có của tài liệu [${existingDoc.code}].` };
                    }
                }
                const entry = newHistory[newHistory.length - 1] || {};
                if (entry.username !== req.user.username) {
                    return { ok: false, error: `Dữ liệu duyệt tài liệu [${existingDoc.code}] không hợp lệ (sai người thực hiện).` };
                }
                if (entry.stepOrder !== existingDoc.current_step_order) {
                    return { ok: false, error: `Dữ liệu duyệt tài liệu [${existingDoc.code}] không hợp lệ (sai bước duyệt).` };
                }
                const totalSteps = totalStepsById.get(existingDoc.workflow_id) || 1;
                if (entry.action === 'REJECTED') {
                    if (newStatus !== 'REJECTED' || newStepOrder !== existingDoc.current_step_order) {
                        return { ok: false, error: `Dữ liệu từ chối tài liệu [${existingDoc.code}] không hợp lệ.` };
                    }
                    return { ok: true };
                }
                if (entry.action === 'APPROVED') {
                    const isFinalStep = existingDoc.current_step_order >= totalSteps;
                    const expectedStatus = isFinalStep ? 'APPROVED' : 'PENDING';
                    const expectedStepOrder = isFinalStep ? existingDoc.current_step_order : existingDoc.current_step_order + 1;
                    if (newStatus !== expectedStatus || newStepOrder !== expectedStepOrder) {
                        return { ok: false, error: `Dữ liệu phê duyệt tài liệu [${existingDoc.code}] không hợp lệ.` };
                    }
                    return { ok: true };
                }
                return { ok: false, error: `Hành động duyệt tài liệu [${existingDoc.code}] không hợp lệ.` };
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
                // Admin được bỏ qua kiểm tra transition chặt chẽ (có thể cần sửa tay
                // 1 tài liệu bị kẹt) — người duyệt thường thì bắt buộc đúng transition
                // hợp lệ duy nhất, không tự ý nhảy bước/bịa lịch sử.
                if (!req.user.perms.admin) {
                    const transitionCheck = validateWorkflowTransition(existing, d.status, d.currentStepOrder, d.history || [], existingHistory);
                    if (!transitionCheck.ok) return res.status(400).json({ error: transitionCheck.error });
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
            // Đồng bộ tài khoản AD (module AD, độc lập với việc dùng LDAP để đăng
            // nhập ở trên) cần thêm tài khoản dịch vụ có quyền duyệt thư mục.
            if (table === 'ldapConfig' && data && data.adSyncEnabled) {
                if (!data.url || !/^ldaps?:\/\//i.test(String(data.url))) {
                    return res.status(400).json({ error: 'URL máy chủ LDAP không hợp lệ (phải bắt đầu bằng ldap:// hoặc ldaps://).' });
                }
                if (!data.serviceBindDn || !String(data.serviceBindDn).trim()) {
                    return res.status(400).json({ error: 'Thiếu Bind DN của tài khoản dịch vụ để đồng bộ AD.' });
                }
                if (!data.searchBaseDn || !String(data.searchBaseDn).trim()) {
                    return res.status(400).json({ error: 'Thiếu Base DN để tìm kiếm tài khoản trong AD.' });
                }
            }
            // Bảo mật: mật khẩu tài khoản dịch vụ AD không bao giờ trả về cho
            // client (bootstrap che đi) — nếu client không gửi mật khẩu mới (trống)
            // thì giữ nguyên mật khẩu cũ đã lưu, giống hệt cách xử lý mật khẩu user.
            if (table === 'ldapConfig') {
                const [existingCfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'ldapConfig'");
                const existingCfg = existingCfgRows[0]
                    ? (typeof existingCfgRows[0].config_value === 'string' ? JSON.parse(existingCfgRows[0].config_value) : existingCfgRows[0].config_value)
                    : {};
                if (!data.servicePassword || !String(data.servicePassword).trim()) {
                    data.servicePassword = existingCfg.servicePassword || '';
                }
            }
            // Mật khẩu SMTP thật cũng che ở bootstrap giống mật khẩu AD ở trên —
            // nếu client không gửi mật khẩu mới (trống, hoặc gửi lại chuỗi che
            // '••••••••' vì form không đổi) thì giữ nguyên mật khẩu cũ đã lưu.
            if (table === 'emailConfig') {
                const [existingCfgRows] = await pool.query("SELECT config_value FROM app_configs WHERE config_key = 'emailConfig'");
                const existingCfg = existingCfgRows[0]
                    ? (typeof existingCfgRows[0].config_value === 'string' ? JSON.parse(existingCfgRows[0].config_value) : existingCfgRows[0].config_value)
                    : {};
                if (!data.smtpPass || !String(data.smtpPass).trim() || data.smtpPass === '••••••••') {
                    data.smtpPass = existingCfg.smtpPass || '';
                }
            }
            await pool.query(
                'INSERT INTO app_configs (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?',
                [table, JSON.stringify(data), JSON.stringify(data)]
            );
        }
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi đồng bộ dữ liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- API GHI/XOÁ NHẬT KÝ HỆ THỐNG ---
// Thay cho cơ chế sync-theo-mảng cũ (đã bỏ) — mỗi hành động ghi ĐÚNG 1 dòng
// log mới (không gửi/so sánh toàn bộ mảng), nên không thể vô tình bị hiểu
// nhầm là "xoá bớt" chỉ vì client chỉ giữ 300 log gần nhất trong bộ nhớ.
// Danh tính (username/fullName) và IP do server tự xác định từ phiên đăng
// nhập thật, không tin giá trị client gửi lên — dùng lại writeAuditLog().
app.post('/api/logs', requireAuth, async (req, res) => {
    try {
        const module = String((req.body && req.body.module) || '').trim();
        const actionType = String((req.body && req.body.actionType) || '').trim();
        const description = String((req.body && req.body.description) || '').trim();
        const status = String((req.body && req.body.status) || 'SUCCESS').trim();
        const targetObject = String((req.body && req.body.targetObject) || '').trim();
        if (!module || !actionType || !description) {
            return res.status(400).json({ error: 'Thiếu thông tin bắt buộc (module/actionType/description) để ghi log.' });
        }
        await writeAuditLog({ module, actionType, targetObject, description, status, username: req.user.username, fullName: req.user.name, ip: req.ip });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi ghi nhật ký hệ thống:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Xoá toàn bộ nhật ký hệ thống — hành động tường minh (nút "Xóa Log"), không
// còn suy luận từ so sánh mảng. Chỉ Admin. Tự ghi lại 1 dòng log cho chính
// hành động xoá này ngay sau khi xoá xong, để vẫn còn dấu vết ai đã xoá.
app.delete('/api/logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM system_logs');
        await writeAuditLog({ module: 'CONFIG', actionType: 'CLEAR_SYSTEM_LOGS', targetObject: 'ALL', description: 'Xoá toàn bộ nhật ký hệ thống.', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xoá nhật ký hệ thống:', err.message);
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
const LICENSE_TYPES = ['PERPETUAL', 'TERM', 'MAINTENANCE'];
function mapSoftware(s) {
    return {
        id: s.id, name: s.name, code: s.code,
        defaultDurationMonths: s.default_duration_months,
        maxAssignees: s.max_assignees,
        allowCrossCompanyShare: !!s.allow_cross_company_share,
        licenseType: s.license_type
    };
}
// Trả về số tháng hợp lệ (1-120), hoặc null nếu không cấu hình. Ném lỗi rõ
// ràng nếu client gửi giá trị không hợp lệ (không phải số nguyên dương).
function parseDurationMonths(raw) {
    if (raw === undefined || raw === null || raw === '') return { value: null };
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 120) return { error: 'Thời hạn mặc định phải là số nguyên từ 1 đến 120 tháng, hoặc để trống nếu không cấu hình.' };
    return { value: n };
}
// Số người tối đa được phép dùng chung 1 mã license (mặc định 1 = hành vi cũ).
function parseMaxAssignees(raw) {
    if (raw === undefined || raw === null || raw === '') return { value: 1 };
    const n = Number(raw);
    if (!Number.isInteger(n) || n < 1 || n > 100) return { error: 'Số người tối đa/mã phải là số nguyên từ 1 đến 100.' };
    return { value: n };
}
function parseLicenseType(raw) {
    const v = String(raw || 'TERM').trim().toUpperCase();
    if (!LICENSE_TYPES.includes(v)) return { error: 'Loại license không hợp lệ.' };
    return { value: v };
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
function mapBatch(b) { return { id: b.id, companyId: b.company_id, softwareId: b.software_id, totalQuantity: b.total_quantity, codesGenerated: b.codes_generated, issuedDate: fmtDate(b.issued_date), expiryDate: fmtDate(b.expiry_date), note: b.note, registrationId: b.registration_id }; }
function mapCode(c) { return { id: c.id, batchId: c.batch_id, companyId: c.company_id, softwareId: c.software_id, code: c.code, expiryDate: fmtDate(c.expiry_date) }; }
function mapCodeAssignment(a) { return { id: a.id, codeId: a.code_id, employeeId: a.employee_id, assignedAt: fmtDate(a.assigned_at) }; }
function mapAdAccount(a) { return { id: a.id, username: a.username, fullName: a.full_name, email: a.email, active: !!a.active, company: a.company, orgUnit: a.org_unit, disabledAt: fmtDate(a.disabled_at), lastSyncedAt: a.last_synced_at }; }
function mapRound(r) { return { id: r.id, name: r.name, note: r.note, status: r.status, createdAt: r.created_at, budgetRoundId: r.budget_round_id, scopeType: r.scope_type, scopeId: r.scope_id, roundType: r.round_type }; }
function mapRoundItem(i) { return { id: i.id, roundId: i.round_id, softwareId: i.software_id, unitPrice: Number(i.unit_price), expiryDate: fmtDate(i.expiry_date) }; }
function mapRegistration(r) { return { id: r.id, roundId: r.round_id, roundItemId: r.round_item_id, companyId: r.company_id, currentQuantity: r.current_quantity, requestedQuantity: r.requested_quantity, budgetQuantity: r.budget_quantity === null || r.budget_quantity === undefined ? null : Number(r.budget_quantity), unitPrice: Number(r.unit_price), totalAmount: Number(r.total_amount), expiryDate: fmtDate(r.expiry_date), status: r.status, note: r.note, createdAt: r.created_at, createdBy: r.created_by, decidedBy: r.decided_by, decidedAt: r.decided_at, issuedBatchId: r.issued_batch_id, issuedQuantity: r.issued_quantity, issuedAt: r.issued_at }; }
function mapBudgetRound(r) { return { id: r.id, name: r.name, note: r.note, status: r.status, createdAt: r.created_at, scopeType: r.scope_type, scopeId: r.scope_id }; }
function mapBudgetRoundItem(i) { return { id: i.id, roundId: i.round_id, softwareId: i.software_id, itemType: i.item_type || 'SOFTWARE', itemName: i.item_name, catalogItemId: i.catalog_item_id, capexOpex: i.capex_opex || 'OPEX', unitPrice: Number(i.unit_price), description: i.description }; }
function mapBudgetItemCatalog(c) { return { id: c.id, itemType: c.item_type, name: c.name, unit: c.unit, active: !!c.active }; }
function mapBudgetActual(a) { return { id: a.id, roundItemId: a.round_item_id, companyId: a.company_id, purchaseDate: fmtDate(a.purchase_date), vendor: a.vendor, quantity: Number(a.quantity), unitPrice: Number(a.unit_price), amount: Number(a.amount), note: a.note, createdBy: a.created_by, createdAt: a.created_at }; }
function mapBudgetRegistration(r) { return { id: r.id, roundId: r.round_id, roundItemId: r.round_item_id, orgUnitId: r.org_unit_id, currentQuantity: r.current_quantity, requestedQuantity: r.requested_quantity, unitPrice: Number(r.unit_price), totalAmount: Number(r.total_amount), status: r.status, note: r.note, createdAt: r.created_at, createdBy: r.created_by, decidedBy: r.decided_by, decidedAt: r.decided_at }; }
function mapBulkAllocationRequest(r) { return { id: r.id, companyId: r.company_id, orgUnitId: r.org_unit_id, softwareId: r.software_id, issuedDate: fmtDate(r.issued_date), expiryDate: fmtDate(r.expiry_date), note: r.note, status: r.status, requestedBy: r.requested_by, requestedAt: r.requested_at, approvedBy: r.approved_by, approvedAt: r.approved_at, rejectReason: r.reject_reason }; }
function mapBulkAllocationItem(i) { return { id: i.id, requestId: i.request_id, employeeCode: i.employee_code, fullName: i.full_name, deptLabel: i.dept_label, orgUnitId: i.org_unit_id, email: i.email, employeeId: i.employee_id, conflictType: i.conflict_type, resolution: i.resolution }; }
function mapItCategory(c) { return { id: c.id, name: c.name, active: !!c.active, sortOrder: c.sort_order }; }
function mapItItem(i) { return { id: i.id, categoryId: i.category_id, name: i.name, provider: i.provider, description: i.description, startDate: fmtDate(i.start_date), expiryDate: fmtDate(i.expiry_date), cost: i.cost === null || i.cost === undefined ? null : Number(i.cost), ownerUserId: i.owner_user_id, ownerEmail: i.owner_email, active: !!i.active, createdBy: i.created_by, createdAt: i.created_at, updatedAt: i.updated_at }; }
// Trả về [orgUnitId, ...toàn bộ id đơn vị con cháu] — dùng để tính số license
// đang dùng cho 1 đơn vị trực thuộc (gồm cả nhân viên ở các đơn vị con bên
// dưới), vd chọn "Khối Kinh doanh" thì tính luôn nhân viên ở "Phòng Bán hàng"
// nằm dưới khối đó.
function orgUnitSubtreeIds(allOrgUnits, rootId) {
    const childrenByParent = new Map();
    allOrgUnits.forEach(u => {
        const key = u.parent_id || 0;
        if (!childrenByParent.has(key)) childrenByParent.set(key, []);
        childrenByParent.get(key).push(u.id);
    });
    const result = [rootId];
    const queue = [rootId];
    while (queue.length > 0) {
        const cur = queue.shift();
        const children = childrenByParent.get(cur) || [];
        for (const childId of children) { result.push(childId); queue.push(childId); }
    }
    return result;
}

// Đọc phạm vi tự phục vụ của user (nếu có) từ perms.licenseScopeType/licenseScopeId.
function getUserLicenseScope(user) {
    const perms = user && user.perms;
    if (!perms || !perms.licenseScopeType || !perms.licenseScopeId) return null;
    if (perms.licenseScopeType !== 'COMPANY' && perms.licenseScopeType !== 'ORG_UNIT') return null;
    return { type: perms.licenseScopeType, id: Number(perms.licenseScopeId) };
}

// scope = null nghĩa là không giới hạn (dữ liệu cũ / chưa gán phạm vi) -> luôn
// coi là chứa target. scope COMPANY chứa mọi đơn vị/công ty thuộc công ty đó.
// scope ORG_UNIT chứa chính đơn vị đó và mọi đơn vị con cháu (subtree).
function scopeContainsTarget(scope, allOrgUnits, targetCompanyId, targetOrgUnitId) {
    if (!scope) return true;
    if (scope.type === 'COMPANY') {
        if (targetCompanyId != null) return Number(targetCompanyId) === scope.id;
        if (targetOrgUnitId != null) {
            const unit = allOrgUnits.find(u => u.id === targetOrgUnitId);
            return !!unit && Number(unit.company_id) === scope.id;
        }
        return false;
    }
    // scope.type === 'ORG_UNIT'
    if (targetOrgUnitId != null) {
        return orgUnitSubtreeIds(allOrgUnits, scope.id).includes(Number(targetOrgUnitId));
    }
    if (targetCompanyId != null) {
        const scopeUnit = allOrgUnits.find(u => u.id === scope.id);
        return !!scopeUnit && Number(scopeUnit.company_id) === Number(targetCompanyId);
    }
    return false;
}

// Có cho phép user (không phải Admin) thao tác (dự trù/đăng ký) lên
// target (company/org-unit) hay không: user phải có phạm vi, phạm vi user
// phải bao trùm target, VÀ Kỳ đang thao tác phải có phạm vi rõ ràng (Kỳ
// chưa gán phạm vi = dữ liệu cũ, chỉ Admin thao tác được).
function userCanActOnTarget({ isAdmin, userScope, roundScope, allOrgUnits, targetCompanyId, targetOrgUnitId }) {
    if (isAdmin) return true;
    if (!userScope) return false;
    // Kỳ chưa gán phạm vi (dữ liệu cũ) chỉ Admin thao tác được — tài khoản tự
    // phục vụ không được coi là "khớp" một Kỳ không có phạm vi xác định.
    if (!roundScope) return false;
    return scopeContainsTarget(userScope, allOrgUnits, targetCompanyId, targetOrgUnitId)
        && scopeContainsTarget(roundScope, allOrgUnits, targetCompanyId, targetOrgUnitId);
}

// Đọc + validate scopeType/scopeId từ body khi Admin tạo Kỳ mua/Kỳ ngân sách.
// Không truyền (hoặc để trống) -> Kỳ không gán phạm vi, hoạt động như trước
// (bất kỳ ai có quyền Admin cũng thao tác được, không có tài khoản tự phục vụ
// nào khớp phạm vi cả vì phạm vi = null).
async function resolveRoundScope(body) {
    const scopeTypeRaw = body && body.scopeType ? String(body.scopeType).trim().toUpperCase() : '';
    if (!scopeTypeRaw) return { scopeType: null, scopeId: null };
    if (!['COMPANY', 'ORG_UNIT'].includes(scopeTypeRaw)) return { error: 'Phạm vi không hợp lệ.' };
    const scopeId = Number(body.scopeId);
    if (!scopeId) return { error: 'Vui lòng chọn công ty/đơn vị cho phạm vi.' };
    if (scopeTypeRaw === 'COMPANY') {
        const [rows] = await pool.query('SELECT id FROM lic_companies WHERE id = ?', [scopeId]);
        if (!rows[0]) return { error: 'Công ty được chọn cho phạm vi không tồn tại.' };
    } else {
        const [rows] = await pool.query('SELECT id FROM lic_org_units WHERE id = ?', [scopeId]);
        if (!rows[0]) return { error: 'Đơn vị được chọn cho phạm vi không tồn tại.' };
    }
    return { scopeType: scopeTypeRaw, scopeId };
}

// Chuẩn hóa + kiểm tra 1 hạng mục ngân sách (dùng chung cho tạo Kỳ ngân sách
// kèm items[] và thêm hạng mục lẻ) — itemType/capexOpex BẮT BUỘC chọn, không
// suy đoán mặc định; SOFTWARE cần softwareId hợp lệ trong lic_software_catalog,
// HARDWARE/SERVICE/OTHER cần catalogItemId hợp lệ trong lic_budget_item_catalog
// (không còn cho nhập tên tự do — tránh dữ liệu rác/trùng lặp không đồng nhất).
// Chỉ kiểm tra định dạng số ở đây; việc catalogItemId có TỒN TẠI, ĐÚNG LOẠI và
// ĐANG ACTIVE hay không do nơi gọi tự truy vấn (khác nhau giữa tạo hàng loạt
// và thêm lẻ 1 dòng nên không tiện gộp DB query vào hàm thuần này).
function normalizeBudgetItem(raw, label) {
    const itemType = String((raw && raw.itemType) || '').trim().toUpperCase();
    if (!['SOFTWARE', 'HARDWARE', 'SERVICE', 'OTHER'].includes(itemType)) return { error: `${label}: vui lòng chọn Loại hạng mục.` };
    const capexOpex = String((raw && raw.capexOpex) || '').trim().toUpperCase();
    if (!['CAPEX', 'OPEX'].includes(capexOpex)) return { error: `${label}: vui lòng chọn CAPEX hoặc OPEX.` };
    const unitPrice = Number(raw && raw.unitPrice);
    if (!Number.isFinite(unitPrice) || unitPrice < 0) return { error: `${label}: Đơn giá không hợp lệ.` };
    const descriptionRaw = String((raw && raw.description) || '').trim();
    if (descriptionRaw.length > 500) return { error: `${label}: Mô tả quá dài (tối đa 500 ký tự).` };
    const description = descriptionRaw || null;
    if (itemType === 'SOFTWARE') {
        const softwareId = Number(raw && raw.softwareId);
        if (!softwareId) return { error: `${label}: vui lòng chọn Phần mềm.` };
        return { itemType, capexOpex, unitPrice, softwareId, catalogItemId: null, description };
    }
    const catalogItemId = Number(raw && raw.catalogItemId);
    if (!catalogItemId) return { error: `${label}: vui lòng chọn hạng mục trong danh mục.` };
    return { itemType, capexOpex, unitPrice, softwareId: null, catalogItemId, description };
}

app.get('/api/license/bootstrap', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const [companies] = await pool.query('SELECT * FROM lic_companies ORDER BY name');
        const [orgUnits] = await pool.query('SELECT * FROM lic_org_units ORDER BY sort_order, name');
        const [employees] = await pool.query('SELECT * FROM lic_employees ORDER BY full_name');
        const [software] = await pool.query('SELECT * FROM lic_software_catalog ORDER BY name');
        const [batches] = await pool.query('SELECT * FROM lic_license_batches ORDER BY id DESC');
        const [codes] = await pool.query('SELECT * FROM lic_license_codes ORDER BY code');
        const [codeAssignments] = await pool.query('SELECT * FROM lic_license_code_assignments ORDER BY id');
        const [rounds] = await pool.query('SELECT * FROM lic_purchase_rounds ORDER BY id DESC');
        const [roundItems] = await pool.query('SELECT * FROM lic_purchase_round_items ORDER BY id');
        const [registrations] = await pool.query('SELECT * FROM lic_purchase_registrations ORDER BY id DESC');
        const [budgetRounds] = await pool.query('SELECT * FROM lic_budget_rounds ORDER BY id DESC');
        const [budgetRoundItems] = await pool.query('SELECT * FROM lic_budget_round_items ORDER BY id');
        const [budgetRegistrations] = await pool.query('SELECT * FROM lic_budget_registrations ORDER BY id DESC');
        const [budgetActuals] = await pool.query('SELECT * FROM lic_budget_actuals ORDER BY purchase_date DESC, id DESC');
        const [budgetItemCatalog] = await pool.query('SELECT * FROM lic_budget_item_catalog ORDER BY item_type, name');
        const [adAccounts] = await pool.query('SELECT * FROM ad_accounts ORDER BY username');
        const adLastSyncAt = await getAdLastSyncAt();
        const [bulkAllocRequests] = await pool.query('SELECT * FROM lic_bulk_allocation_requests ORDER BY id DESC');
        const [bulkAllocItems] = await pool.query('SELECT * FROM lic_bulk_allocation_items ORDER BY id');
        res.json({
            companies: companies.map(mapCompany),
            orgUnits: orgUnits.map(mapOrgUnit),
            employees: employees.map(mapEmployee),
            softwareCatalog: software.map(mapSoftware),
            licenseBatches: batches.map(mapBatch),
            licenseCodes: codes.map(mapCode),
            licenseCodeAssignments: codeAssignments.map(mapCodeAssignment),
            purchaseRounds: rounds.map(mapRound),
            purchaseRoundItems: roundItems.map(mapRoundItem),
            purchaseRegistrations: registrations.map(mapRegistration),
            budgetRounds: budgetRounds.map(mapBudgetRound),
            budgetRoundItems: budgetRoundItems.map(mapBudgetRoundItem),
            budgetRegistrations: budgetRegistrations.map(mapBudgetRegistration),
            budgetActuals: budgetActuals.map(mapBudgetActual),
            budgetItemCatalog: budgetItemCatalog.map(mapBudgetItemCatalog),
            adAccounts: adAccounts.map(mapAdAccount),
            adLastSyncAt: adLastSyncAt || null,
            bulkAllocationRequests: bulkAllocRequests.map(mapBulkAllocationRequest),
            bulkAllocationItems: bulkAllocItems.map(mapBulkAllocationItem)
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu module Bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Cổng tự phục vụ (Ngân sách + Kỳ mua) cho tài khoản có phạm vi công
// ty/đơn vị — CHỈ trả về đúng phần dữ liệu nằm trong phạm vi của user, không
// lộ công ty/đơn vị khác. Khác hẳn /api/license/bootstrap (dành cho Admin,
// trả về toàn bộ dữ liệu module). Yêu cầu user phải có phạm vi hợp lệ (không
// cần quyền Admin) — tài khoản chỉ dùng module Tài liệu bị từ chối ở đây.
app.get('/api/license/portal/bootstrap', requireAuth, async (req, res) => {
    try {
        const userScope = getUserLicenseScope(req.user);
        if (!userScope) return res.status(403).json({ error: 'Tài khoản này chưa được cấp phạm vi tự phục vụ Bản quyền.' });

        const [allOrgUnits] = await pool.query('SELECT * FROM lic_org_units ORDER BY sort_order, name');
        const [allCompanies] = await pool.query('SELECT * FROM lic_companies ORDER BY name');

        let reachableOrgUnitIds, reachableCompanyIds;
        if (userScope.type === 'COMPANY') {
            reachableOrgUnitIds = allOrgUnits.filter(u => u.company_id === userScope.id).map(u => u.id);
            reachableCompanyIds = [userScope.id];
        } else {
            reachableOrgUnitIds = orgUnitSubtreeIds(allOrgUnits, userScope.id);
            const scopeUnit = allOrgUnits.find(u => u.id === userScope.id);
            reachableCompanyIds = scopeUnit ? [scopeUnit.company_id] : [];
        }
        const reachableOrgUnitSet = new Set(reachableOrgUnitIds);
        const reachableCompanySet = new Set(reachableCompanyIds);

        const [software] = await pool.query('SELECT * FROM lic_software_catalog ORDER BY name');

        const [allBudgetRounds] = await pool.query('SELECT * FROM lic_budget_rounds ORDER BY id DESC');
        const visibleBudgetRounds = allBudgetRounds.filter(r => {
            if (!r.scope_type) return false;
            const roundScope = { type: r.scope_type, id: r.scope_id };
            return userScope.type === 'COMPANY'
                ? scopeContainsTarget(roundScope, allOrgUnits, userScope.id, null)
                : scopeContainsTarget(roundScope, allOrgUnits, null, userScope.id);
        });
        const visibleBudgetRoundIds = new Set(visibleBudgetRounds.map(r => r.id));
        const [allBudgetRoundItems] = await pool.query('SELECT * FROM lic_budget_round_items ORDER BY id');
        const visibleBudgetRoundItems = allBudgetRoundItems.filter(i => visibleBudgetRoundIds.has(i.round_id));
        const [allBudgetRegistrations] = await pool.query('SELECT * FROM lic_budget_registrations ORDER BY id DESC');
        const visibleBudgetRegistrations = allBudgetRegistrations.filter(r => reachableOrgUnitSet.has(r.org_unit_id));

        const [allPurchaseRounds] = await pool.query('SELECT * FROM lic_purchase_rounds ORDER BY id DESC');
        const visiblePurchaseRounds = allPurchaseRounds.filter(r => {
            if (!r.scope_type) return false;
            const roundScope = { type: r.scope_type, id: r.scope_id };
            return userScope.type === 'COMPANY'
                ? scopeContainsTarget(roundScope, allOrgUnits, userScope.id, null)
                : scopeContainsTarget(roundScope, allOrgUnits, null, userScope.id);
        });
        const visiblePurchaseRoundIds = new Set(visiblePurchaseRounds.map(r => r.id));
        const [allPurchaseRoundItems] = await pool.query('SELECT * FROM lic_purchase_round_items ORDER BY id');
        const visiblePurchaseRoundItems = allPurchaseRoundItems.filter(i => visiblePurchaseRoundIds.has(i.round_id));
        const [allPurchaseRegistrations] = await pool.query('SELECT * FROM lic_purchase_registrations ORDER BY id DESC');
        const visiblePurchaseRegistrations = allPurchaseRegistrations.filter(r => reachableCompanySet.has(r.company_id));

        // Chỉ trả về SỐ LƯỢNG mã đang có theo công ty+phần mềm (không trả mã
        // thật) — để Cổng tự phục vụ hiện cột "Đang dùng" khi đăng ký, giống
        // phía Admin, mà không lộ danh sách mã license thật ra ngoài.
        let licenseUsage = [];
        if (reachableCompanyIds.length > 0) {
            const [usageRows] = await pool.query(
                `SELECT company_id, software_id, COUNT(*) AS cnt FROM lic_license_codes
                 WHERE company_id IN (${reachableCompanyIds.map(() => '?').join(',')})
                 GROUP BY company_id, software_id`,
                reachableCompanyIds
            );
            licenseUsage = usageRows.map(r => ({ companyId: r.company_id, softwareId: r.software_id, count: Number(r.cnt) }));
        }

        const scopeLabel = userScope.type === 'COMPANY'
            ? (allCompanies.find(c => c.id === userScope.id)?.name || '—')
            : (allOrgUnits.find(u => u.id === userScope.id)?.name || '—');

        const [budgetItemCatalog] = await pool.query('SELECT * FROM lic_budget_item_catalog ORDER BY item_type, name');

        res.json({
            scope: { type: userScope.type, id: userScope.id, label: scopeLabel },
            companies: allCompanies.filter(c => reachableCompanySet.has(c.id)).map(mapCompany),
            orgUnits: allOrgUnits.filter(u => reachableOrgUnitSet.has(u.id)).map(mapOrgUnit),
            softwareCatalog: software.map(mapSoftware),
            purchaseRounds: visiblePurchaseRounds.map(mapRound),
            purchaseRoundItems: visiblePurchaseRoundItems.map(mapRoundItem),
            purchaseRegistrations: visiblePurchaseRegistrations.map(mapRegistration),
            budgetRounds: visibleBudgetRounds.map(mapBudgetRound),
            budgetRoundItems: visibleBudgetRoundItems.map(mapBudgetRoundItem),
            budgetRegistrations: visibleBudgetRegistrations.map(mapBudgetRegistration),
            budgetItemCatalog: budgetItemCatalog.map(mapBudgetItemCatalog),
            licenseUsage
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu Cổng tự phục vụ Bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Module Báo cáo — tổng hợp số liệu cho 2 phân hệ nghiệp vụ (Tài liệu,
// Bản quyền). Chỉ đọc, không có tham số lọc phức tạp ở bản đầu tiên này.
app.get('/api/reports/docs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT dept, status, created_at, history FROM docs WHERE deleted_at IS NULL');
        const totals = { total: rows.length, pending: 0, approved: 0, rejected: 0 };
        const byDeptMap = new Map();
        // Thời gian "nằm ở bước X" = khoảng cách từ mốc trước đó (ngày tạo hoặc
        // lượt duyệt trước) đến lúc bước X được xử lý — ước lượng bước nào đang
        // là điểm nghẽn trong quy trình duyệt.
        const stepDurations = new Map();
        rows.forEach(d => {
            if (d.status === 'PENDING') totals.pending++;
            else if (d.status === 'APPROVED') totals.approved++;
            else if (d.status === 'REJECTED') totals.rejected++;
            const deptKey = d.dept || 'Chưa phân loại';
            byDeptMap.set(deptKey, (byDeptMap.get(deptKey) || 0) + 1);
            let history = d.history;
            if (typeof history === 'string') { try { history = JSON.parse(history); } catch { history = []; } }
            if (Array.isArray(history) && history.length > 0) {
                let prevTime = new Date(d.created_at);
                for (const h of history) {
                    const at = new Date(h.at);
                    if (isNaN(prevTime.getTime()) || isNaN(at.getTime())) { prevTime = at; continue; }
                    const days = (at - prevTime) / 86400000;
                    if (days >= 0 && Number.isInteger(h.stepOrder)) {
                        if (!stepDurations.has(h.stepOrder)) stepDurations.set(h.stepOrder, []);
                        stepDurations.get(h.stepOrder).push(days);
                    }
                    prevTime = at;
                }
            }
        });
        const byDept = [...byDeptMap.entries()].map(([dept, count]) => ({ dept, count })).sort((a, b) => b.count - a.count);
        const avgDaysByStep = [...stepDurations.entries()]
            .map(([stepOrder, arr]) => ({ stepOrder, avgDays: Math.round((arr.reduce((s, x) => s + x, 0) / arr.length) * 10) / 10 }))
            .sort((a, b) => a.stepOrder - b.stepOrder);
        res.json({ totals, byDept, avgDaysByStep });
    } catch (err) {
        console.error('❌ Lỗi tải báo cáo tài liệu:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.get('/api/reports/license', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [[{ totalCodes }]] = await pool.query('SELECT COUNT(*) AS totalCodes FROM lic_license_codes');
        const [[{ assignedCodes }]] = await pool.query('SELECT COUNT(DISTINCT code_id) AS assignedCodes FROM lic_license_code_assignments');
        const today = new Date().toISOString().slice(0, 10);
        const in30 = new Date(Date.now() + 30 * 86400000).toISOString().slice(0, 10);
        const [[expiryCounts]] = await pool.query(
            `SELECT
               SUM(expiry_date IS NULL) AS perpetualCnt,
               SUM(expiry_date IS NOT NULL AND expiry_date < ?) AS expiredCnt,
               SUM(expiry_date IS NOT NULL AND expiry_date >= ? AND expiry_date <= ?) AS expiringSoonCnt,
               SUM(expiry_date IS NOT NULL AND expiry_date > ?) AS validCnt
             FROM lic_license_codes`,
            [today, today, in30, in30]
        );
        const [byCompanyRows] = await pool.query(
            `SELECT co.name AS companyName, COUNT(*) AS cnt
             FROM lic_license_codes c JOIN lic_companies co ON co.id = c.company_id
             GROUP BY co.id ORDER BY cnt DESC LIMIT 6`
        );
        const [latestRoundRows] = await pool.query('SELECT id, name FROM lic_budget_rounds ORDER BY id DESC LIMIT 1');
        let budgetVsUsage = [];
        if (latestRoundRows[0]) {
            const [regRows] = await pool.query(
                `SELECT r.current_quantity, r.requested_quantity, u.name AS unitName, COALESCE(sw.name, bi.item_name) AS softwareName
                 FROM lic_budget_registrations r
                 JOIN lic_org_units u ON u.id = r.org_unit_id
                 JOIN lic_budget_round_items bi ON bi.id = r.round_item_id
                 LEFT JOIN lic_software_catalog sw ON sw.id = bi.software_id
                 WHERE r.round_id = ? ORDER BY r.id`,
                [latestRoundRows[0].id]
            );
            budgetVsUsage = regRows.map(r => ({ unitName: r.unitName, softwareName: r.softwareName, currentQuantity: r.current_quantity, requestedQuantity: r.requested_quantity }));
        }
        // So sánh Kế hoạch (dự trù đã duyệt) vs Thực tế (sổ mua thực tế) theo
        // từng hạng mục ngân sách có ít nhất 1 trong 2 số liệu > 0, gộp lại theo
        // CAPEX/OPEX ở tầng JS bên dưới.
        const [budgetItemComparisonRows] = await pool.query(
            `SELECT bi.id AS itemId, bi.item_type AS itemType, bi.capex_opex AS capexOpex, br.name AS roundName,
                    COALESCE(sw.name, bi.item_name) AS itemLabel,
                    COALESCE(planned.total, 0) AS planned, COALESCE(actual.total, 0) AS actual
             FROM lic_budget_round_items bi
             JOIN lic_budget_rounds br ON br.id = bi.round_id
             LEFT JOIN lic_software_catalog sw ON sw.id = bi.software_id
             LEFT JOIN (SELECT round_item_id, SUM(total_amount) AS total FROM lic_budget_registrations WHERE status = 'APPROVED' GROUP BY round_item_id) planned ON planned.round_item_id = bi.id
             LEFT JOIN (SELECT round_item_id, SUM(amount) AS total FROM lic_budget_actuals GROUP BY round_item_id) actual ON actual.round_item_id = bi.id
             WHERE COALESCE(planned.total, 0) > 0 OR COALESCE(actual.total, 0) > 0
             ORDER BY br.id DESC, bi.id`
        );
        const budgetItemComparison = budgetItemComparisonRows.map(r => ({ itemId: r.itemId, itemType: r.itemType, capexOpex: r.capexOpex, roundName: r.roundName, itemLabel: r.itemLabel, planned: Number(r.planned) || 0, actual: Number(r.actual) || 0 }));
        const budgetCapexOpexSummary = ['CAPEX', 'OPEX'].map(kind => {
            const rows = budgetItemComparison.filter(r => r.capexOpex === kind);
            return { capexOpex: kind, planned: rows.reduce((s, r) => s + r.planned, 0), actual: rows.reduce((s, r) => s + r.actual, 0) };
        });
        // Theo dõi ngân sách theo Công ty — "Kế hoạch" suy ra qua đơn vị trực
        // thuộc (org_unit.company_id) của dự trù đã duyệt; "Thực tế" lấy trực
        // tiếp từ company_id (tùy chọn) trên sổ mua thực tế — dòng nào không gán
        // công ty cụ thể (mua chung) gộp vào nhóm "Chưa phân bổ" riêng.
        const [plannedByCompanyRows] = await pool.query(
            `SELECT co.id AS companyId, co.name AS companyName, SUM(r.total_amount) AS total
             FROM lic_budget_registrations r
             JOIN lic_org_units u ON u.id = r.org_unit_id
             JOIN lic_companies co ON co.id = u.company_id
             WHERE r.status = 'APPROVED'
             GROUP BY co.id`
        );
        const [actualByCompanyRows] = await pool.query('SELECT company_id AS companyId, SUM(amount) AS total FROM lic_budget_actuals GROUP BY company_id');
        const companyNameMap = new Map(plannedByCompanyRows.map(r => [r.companyId, r.companyName]));
        const unnamedCompanyIds = actualByCompanyRows.filter(r => r.companyId != null && !companyNameMap.has(r.companyId)).map(r => r.companyId);
        if (unnamedCompanyIds.length > 0) {
            const [extraCompanyRows] = await pool.query(`SELECT id, name FROM lic_companies WHERE id IN (${unnamedCompanyIds.map(() => '?').join(',')})`, unnamedCompanyIds);
            extraCompanyRows.forEach(c => companyNameMap.set(c.id, c.name));
        }
        const budgetByCompanyMap = new Map();
        plannedByCompanyRows.forEach(r => budgetByCompanyMap.set(r.companyId, { companyId: r.companyId, companyName: r.companyName, planned: Number(r.total) || 0, actual: 0 }));
        actualByCompanyRows.forEach(r => {
            const key = r.companyId;
            if (!budgetByCompanyMap.has(key)) {
                budgetByCompanyMap.set(key, { companyId: key, companyName: key === null ? 'Chưa phân bổ' : (companyNameMap.get(key) || `#${key}`), planned: 0, actual: 0 });
            }
            budgetByCompanyMap.get(key).actual = Number(r.total) || 0;
        });
        const budgetByCompany = Array.from(budgetByCompanyMap.values()).sort((a, b) => (b.planned + b.actual) - (a.planned + a.actual));
        const [spendRows] = await pool.query(
            `SELECT ro.id AS roundId, ro.name AS roundName, SUM(reg.total_amount) AS total
             FROM lic_purchase_registrations reg JOIN lic_purchase_rounds ro ON ro.id = reg.round_id
             WHERE reg.status IN ('APPROVED', 'ISSUED')
             GROUP BY ro.id ORDER BY ro.id DESC LIMIT 6`
        );
        const [controlRows] = await pool.query(
            `SELECT COUNT(DISTINCT e.id) AS cnt
             FROM ad_accounts a
             JOIN lic_employees e ON LOWER(e.email) = LOWER(a.email)
             JOIN lic_license_code_assignments asg ON asg.employee_id = e.id
             WHERE a.active = 0 AND a.email IS NOT NULL AND a.email != ''`
        );
        res.json({
            totals: {
                totalCodes,
                assignedCodes,
                freeCodes: totalCodes - assignedCodes,
                expiringSoon: Number(expiryCounts.expiringSoonCnt) || 0
            },
            byCompany: byCompanyRows.map(r => ({ companyName: r.companyName, count: r.cnt })),
            expiryBreakdown: [
                { label: 'Còn hạn', count: Number(expiryCounts.validCnt) || 0 },
                { label: 'Sắp hết hạn (≤30 ngày)', count: Number(expiryCounts.expiringSoonCnt) || 0 },
                { label: 'Đã hết hạn', count: Number(expiryCounts.expiredCnt) || 0 },
                { label: 'Vĩnh viễn', count: Number(expiryCounts.perpetualCnt) || 0 }
            ],
            budgetVsUsage,
            spendByRound: spendRows.reverse().map(r => ({ roundName: r.roundName, total: Number(r.total) || 0 })),
            budgetItemComparison,
            budgetCapexOpexSummary,
            budgetByCompany,
            controlAlertCount: controlRows[0].cnt
        });
    } catch (err) {
        console.error('❌ Lỗi tải báo cáo bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/ad/sync', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const ldapConfig = await getLdapConfig();
        if (!ldapConfig || !ldapConfig.adSyncEnabled) {
            return res.status(400).json({ error: 'Chưa bật đồng bộ tài khoản AD trong cấu hình LDAP (mục Quản trị).' });
        }
        const result = await ldapSyncAccounts();
        await setAdLastSyncAt();
        await writeAuditLog({ module: 'LICENSE', actionType: 'AD_SYNC', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: 'Đồng bộ AD', description: `Đồng bộ tài khoản AD: ${result.created} mới, ${result.updated} cập nhật (tổng ${result.total}).` });
        res.json({ success: true, ...result });
    } catch (err) {
        console.error('❌ Lỗi đồng bộ AD:', err.message);
        res.status(500).json({ error: 'Không thể kết nối hoặc đồng bộ với máy chủ AD — kiểm tra lại cấu hình LDAP.' });
    }
});

// --- Công ty ---
app.post('/api/license/companies', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.put('/api/license/companies/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.delete('/api/license/companies/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_companies WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy công ty.' });
        const [units] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_org_units WHERE company_id = ?', [id]);
        if (units[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — công ty vẫn còn đơn vị trực thuộc. Hãy xóa hết đơn vị con trước.' });
        // Công ty có thể đã được phát hành license / đăng ký mua trước khi có
        // đơn vị tổ chức nào — kiểm tra thêm để không để lại dữ liệu mồ côi
        // tham chiếu company_id không còn tồn tại (giống logic xóa phần mềm).
        const [batches] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_batches WHERE company_id = ?', [id]);
        if (batches[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — công ty này đã có lô license được phát hành.' });
        const [regs] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_purchase_registrations WHERE company_id = ?', [id]);
        if (regs[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — công ty này đã có đăng ký mua bản quyền.' });
        await pool.query('DELETE FROM lic_companies WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_COMPANY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa công ty [${rows[0].name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa công ty:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Đơn vị tổ chức (cây N cấp) ---
app.post('/api/license/org-units', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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
app.put('/api/license/org-units/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.delete('/api/license/org-units/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_org_units WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đơn vị.' });
        const [children] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_org_units WHERE parent_id = ?', [id]);
        if (children[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đơn vị này còn đơn vị con bên dưới.' });
        const [emps] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_employees WHERE org_unit_id = ?', [id]);
        if (emps[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — vẫn còn nhân viên thuộc đơn vị này.' });
        // Đơn vị có thể đã được dùng để lập dự trù ngân sách (module Ngân sách,
        // độc lập với nhân viên/mã license) — xóa thẳng sẽ để lại dòng dự trù
        // mồ côi, không còn tra được tên đơn vị trong bảng Ngân sách.
        const [budgetRegs] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_budget_registrations WHERE org_unit_id = ?', [id]);
        if (budgetRegs[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đơn vị này đã có dự trù ngân sách. Không thể xóa đơn vị đã có lịch sử dự trù.' });
        await pool.query('DELETE FROM lic_org_units WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_ORG_UNIT', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa đơn vị [${rows[0].name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa đơn vị:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Nhân viên ---
app.post('/api/license/employees', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.put('/api/license/employees/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.delete('/api/license/employees/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT full_name FROM lic_employees WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy nhân viên.' });
        // Không có ràng buộc FK ở tầng CSDL — nếu xóa thẳng mà nhân viên vẫn còn
        // đang giữ license, dòng lic_license_code_assignments sẽ mồ côi: bảng
        // Phân bổ tự lọc bỏ (employee_id không tra được), nên Admin không còn
        // cách nào thấy/thu hồi nữa — mã đó coi như mất vĩnh viễn 1 slot.
        const [assignments] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_code_assignments WHERE employee_id = ?', [id]);
        if (assignments[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — nhân viên này vẫn đang giữ license. Hãy thu hồi hết license ở tab Phân bổ trước.' });
        await pool.query('DELETE FROM lic_employees WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_EMPLOYEE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].full_name, description: `Xóa nhân viên [${rows[0].full_name}] khỏi module Bản quyền.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa nhân viên:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Danh mục phần mềm ---
app.post('/api/license/software', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên phần mềm không được để trống.' });
        if (!validCode(code, 50)) return res.status(400).json({ error: 'Mã phần mềm không hợp lệ (chỉ chữ/số không dấu, tối đa 50 ký tự).' });
        const duration = parseDurationMonths(req.body && req.body.defaultDurationMonths);
        if (duration.error) return res.status(400).json({ error: duration.error });
        const maxAssignees = parseMaxAssignees(req.body && req.body.maxAssignees);
        if (maxAssignees.error) return res.status(400).json({ error: maxAssignees.error });
        const licenseType = parseLicenseType(req.body && req.body.licenseType);
        if (licenseType.error) return res.status(400).json({ error: licenseType.error });
        const allowCrossCompanyShare = !!(req.body && req.body.allowCrossCompanyShare);
        const [result] = await pool.query(
            'INSERT INTO lic_software_catalog (name, code, default_duration_months, max_assignees, allow_cross_company_share, license_type) VALUES (?, ?, ?, ?, ?, ?)',
            [name, code, duration.value, maxAssignees.value, allowCrossCompanyShare, licenseType.value]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm phần mềm [${name}] (mã ${code}) vào danh mục${duration.value ? `, thời hạn mặc định ${duration.value} tháng` : ''}, tối đa ${maxAssignees.value} người/mã.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên phần mềm đã tồn tại.' });
        console.error('❌ Lỗi thêm phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/software/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        const code = String((req.body && req.body.code) || '').trim().toUpperCase();
        if (!name) return res.status(400).json({ error: 'Tên phần mềm không được để trống.' });
        if (!validCode(code, 50)) return res.status(400).json({ error: 'Mã phần mềm không hợp lệ (chỉ chữ/số không dấu, tối đa 50 ký tự).' });
        const duration = parseDurationMonths(req.body && req.body.defaultDurationMonths);
        if (duration.error) return res.status(400).json({ error: duration.error });
        const maxAssignees = parseMaxAssignees(req.body && req.body.maxAssignees);
        if (maxAssignees.error) return res.status(400).json({ error: maxAssignees.error });
        const licenseType = parseLicenseType(req.body && req.body.licenseType);
        if (licenseType.error) return res.status(400).json({ error: licenseType.error });
        const allowCrossCompanyShare = !!(req.body && req.body.allowCrossCompanyShare);
        const [result] = await pool.query(
            'UPDATE lic_software_catalog SET name = ?, code = ?, default_duration_months = ?, max_assignees = ?, allow_cross_company_share = ?, license_type = ? WHERE id = ?',
            [name, code, duration.value, maxAssignees.value, allowCrossCompanyShare, licenseType.value, id]
        );
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy phần mềm.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật phần mềm [${name}] (mã ${code}).` });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên phần mềm đã tồn tại.' });
        console.error('❌ Lỗi cập nhật phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/software/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_software_catalog WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy phần mềm.' });
        const [batches] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_license_batches WHERE software_id = ?', [id]);
        if (batches[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — phần mềm này đã có lô license được phát hành.' });
        // Phần mềm có thể đã được thêm vào Kỳ mua hoặc Kỳ ngân sách (dạng hạng
        // mục dự kiến) dù chưa từng phát hành mã thật nào — xóa thẳng sẽ để lại
        // hạng mục mồ côi trong 2 module đó (hiện "—" không tra được tên).
        const [purchaseItems] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_purchase_round_items WHERE software_id = ?', [id]);
        if (purchaseItems[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — phần mềm này đang là hạng mục trong một Kỳ mua bản quyền.' });
        const [budgetItems] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_budget_round_items WHERE software_id = ?', [id]);
        if (budgetItems[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — phần mềm này đang là hạng mục trong một Kỳ ngân sách.' });
        await pool.query('DELETE FROM lic_software_catalog WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_SOFTWARE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa phần mềm [${rows[0].name}] khỏi danh mục.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa phần mềm:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Danh mục hạng mục Phần cứng/Dịch vụ/Khác (dùng để chọn khi thêm hạng
// mục vào Kỳ ngân sách, thay cho nhập tên tự do dễ ra dữ liệu rác) ---
app.post('/api/license/budget-item-catalog', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const itemType = String((req.body && req.body.itemType) || '').trim().toUpperCase();
        if (!['HARDWARE', 'SERVICE', 'OTHER'].includes(itemType)) return res.status(400).json({ error: 'Loại hạng mục không hợp lệ.' });
        const name = String((req.body && req.body.name) || '').trim();
        if (!name) return res.status(400).json({ error: 'Tên hạng mục không được để trống.' });
        if (name.length > 255) return res.status(400).json({ error: 'Tên hạng mục quá dài (tối đa 255 ký tự).' });
        const unit = String((req.body && req.body.unit) || '').trim() || null;
        const [result] = await pool.query('INSERT INTO lic_budget_item_catalog (item_type, name, unit, active) VALUES (?, ?, ?, 1)', [itemType, name, unit]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_BUDGET_ITEM_CATALOG', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm hạng mục [${name}] (${itemType}) vào danh mục ngân sách.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Hạng mục này đã có trong danh mục.' });
        console.error('❌ Lỗi thêm hạng mục danh mục:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/budget-item-catalog/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        if (!name) return res.status(400).json({ error: 'Tên hạng mục không được để trống.' });
        if (name.length > 255) return res.status(400).json({ error: 'Tên hạng mục quá dài (tối đa 255 ký tự).' });
        const unit = String((req.body && req.body.unit) || '').trim() || null;
        const active = req.body && req.body.active !== undefined ? !!req.body.active : true;
        const [result] = await pool.query('UPDATE lic_budget_item_catalog SET name = ?, unit = ?, active = ? WHERE id = ?', [name, unit, active, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy hạng mục.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_BUDGET_ITEM_CATALOG', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật hạng mục [${name}] trong danh mục ngân sách.` });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Hạng mục này đã có trong danh mục.' });
        console.error('❌ Lỗi cập nhật hạng mục danh mục:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/budget-item-catalog/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM lic_budget_item_catalog WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy hạng mục.' });
        const [used] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_budget_round_items WHERE catalog_item_id = ?', [id]);
        if (used[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — hạng mục này đang được dùng trong một Kỳ ngân sách. Có thể tắt "Đang dùng" thay vì xóa.' });
        await pool.query('DELETE FROM lic_budget_item_catalog WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BUDGET_ITEM_CATALOG', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa hạng mục [${rows[0].name}] khỏi danh mục ngân sách.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa hạng mục danh mục:', err.message);
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
// Phát hành license BẮT BUỘC gắn với 1 đăng ký mua đã duyệt (registrationId)
// — không còn đường phát hành tự do ngoài Kỳ mua. Số lượng lấy mặc định từ
// đăng ký đã duyệt nhưng Admin có thể ĐIỀU CHỈNH lúc phát hành (thực tế mua
// có thể khác số đã duyệt). Logic sinh mã rẽ theo loại Kỳ mua:
// - RENEWAL: giữ nguyên 100% logic delta + gia hạn hàng loạt cũ (đối chiếu
//   SL đang có, ưu tiên gia hạn mã đã gán trước).
// - NEW: sinh THẲNG đúng số lượng nhập vào KHO, không đụng/gia hạn mã cũ nào.
// Lỗi nghiệp vụ trong lúc PHÁT HÀNH — mang theo status HTTP, luôn throw thay
// vì res.status(...) trực tiếp bên trong transaction, để catch bên ngoài
// CHẮC CHẮN rollback trước khi trả lỗi (không để lại trạng thái nửa vời).
class IssueBatchError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

app.post('/api/license/batches', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const registrationId = Number(req.body && req.body.registrationId);
        const quantity = Number(req.body && req.body.quantity);
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        const rawExpiryDate = String((req.body && req.body.expiryDate) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        if (!registrationId) return res.status(400).json({ error: 'Vui lòng chọn Đăng ký mua đã duyệt để phát hành.' });
        if (!Number.isInteger(quantity) || quantity < 0 || quantity > 5000) return res.status(400).json({ error: 'Số lượng phải là số nguyên từ 0 đến 5000.' });
        if (!validDateStr(issuedDate)) return res.status(400).json({ error: 'Ngày cấp không hợp lệ.' });

        const conn = await pool.getConnection();
        let outcome, companyCode, softwareCode;
        try {
            await conn.beginTransaction();

            // Khoá dòng đăng ký NGAY TỪ ĐẦU + re-check trạng thái TRONG transaction
            // — chống race condition khi 2 request phát hành cùng registrationId
            // gần như đồng thời (double-click, 2 tab admin) đều đọc thấy
            // issued_batch_id NULL trước khi bên nào commit UPDATE cuối, dẫn tới
            // sinh 2 lô mã cho cùng 1 đăng ký (thừa số lượng license đã mua thực tế).
            const [regRows] = await conn.query('SELECT * FROM lic_purchase_registrations WHERE id = ? FOR UPDATE', [registrationId]);
            if (!regRows[0]) throw new IssueBatchError(404, 'Không tìm thấy đăng ký mua.');
            const registration = regRows[0];
            if (registration.status !== 'APPROVED') throw new IssueBatchError(400, 'Chỉ phát hành được cho đăng ký đã duyệt.');
            if (registration.issued_batch_id) throw new IssueBatchError(400, 'Đăng ký này đã được phát hành trước đó.');

            const [roundRows] = await conn.query('SELECT id, round_type FROM lic_purchase_rounds WHERE id = ?', [registration.round_id]);
            if (!roundRows[0]) throw new IssueBatchError(400, 'Kỳ mua của đăng ký này không còn tồn tại.');
            const roundType = roundRows[0].round_type;
            const [itemRows] = await conn.query('SELECT id, software_id FROM lic_purchase_round_items WHERE id = ?', [registration.round_item_id]);
            if (!itemRows[0]) throw new IssueBatchError(400, 'Hạng mục phần mềm của đăng ký này không còn tồn tại.');
            const companyId = registration.company_id;
            const softwareId = itemRows[0].software_id;

            const [companyRows] = await conn.query('SELECT id, code FROM lic_companies WHERE id = ?', [companyId]);
            if (!companyRows[0]) throw new IssueBatchError(400, 'Công ty không tồn tại.');
            const [softwareRows] = await conn.query('SELECT id, code, license_type FROM lic_software_catalog WHERE id = ?', [softwareId]);
            if (!softwareRows[0]) throw new IssueBatchError(400, 'Phần mềm không tồn tại.');
            companyCode = companyRows[0].code;
            softwareCode = softwareRows[0].code;

            // Phần mềm Vĩnh viễn (PERPETUAL) không có ngày hết hạn — bỏ qua yêu cầu
            // nhập Ngày hết hạn, luôn lưu NULL bất kể client gửi gì.
            const isPerpetual = softwareRows[0].license_type === 'PERPETUAL';
            let expiryDate = null;
            if (!isPerpetual) {
                if (!validDateStr(rawExpiryDate)) throw new IssueBatchError(400, 'Ngày hết hạn không hợp lệ.');
                if (rawExpiryDate <= issuedDate) throw new IssueBatchError(400, 'Ngày hết hạn phải sau Ngày cấp.');
                expiryDate = rawExpiryDate;
            }

            // Sắp theo số lượt đang được gán giảm dần — khi mua ÍT HƠN số mã đang có,
            // các mã đã gán cho nhân viên được ƯU TIÊN gia hạn trước, mã còn trống mới
            // bị loại ra (giữ nguyên hạn cũ) nếu không đủ chỗ trong tổng số lượng mới.
            // Với Kỳ mua mới (NEW) danh sách này chỉ để tính total_quantity báo cáo —
            // không dùng để tính toGenerate hay để gia hạn.
            const [existingCodesRaw] = await conn.query(
                `SELECT c.id, COUNT(a.id) AS assign_count
                 FROM lic_license_codes c LEFT JOIN lic_license_code_assignments a ON a.code_id = c.id
                 WHERE c.company_id = ? AND c.software_id = ?
                 GROUP BY c.id ORDER BY assign_count DESC, c.id ASC`,
                [companyId, softwareId]
            );
            const existingCount = existingCodesRaw.length;
            // RENEWAL: quantity = TỔNG số lượng mong muốn sau lô này (như thiết kế cũ).
            // NEW: quantity = số lượng MUA THÊM, cộng thẳng vào kho, không đụng mã cũ.
            const toGenerate = roundType === 'NEW' ? quantity : Math.max(0, quantity - existingCount);
            const totalQuantityForRecord = roundType === 'NEW' ? existingCount + quantity : quantity;

            const [batchResult] = await conn.query(
                'INSERT INTO lic_license_batches (company_id, software_id, total_quantity, codes_generated, issued_date, expiry_date, note, created_at, registration_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [companyId, softwareId, totalQuantityForRecord, toGenerate, issuedDate, expiryDate, note || null, new Date().toISOString(), registrationId]
            );
            const batchId = batchResult.insertId;

            if (toGenerate > 0) {
                const codes = await generateLicenseCodes(companyRows[0].code, softwareRows[0].code, toGenerate);
                await conn.query(
                    'INSERT INTO lic_license_codes (batch_id, company_id, software_id, code, expiry_date) VALUES ?',
                    [codes.map(c => [batchId, companyId, softwareId, c, expiryDate])]
                );
            }

            // Gia hạn (CHỈ áp dụng cho Kỳ mua RENEWAL): mã cũ được giữ lại theo thứ tự
            // ưu tiên ở trên + toàn bộ mã vừa sinh, đúng bằng quantity mã. Nếu quantity
            // ÍT HƠN số mã đang có, phần dư GIỮ NGUYÊN ngày hết hạn cũ, không tự động
            // gia hạn theo lần phát hành này. Kỳ mua NEW không đụng tới mã cũ nào.
            let renewedCount = 0;
            if (roundType === 'RENEWAL' && expiryDate) {
                const keepExistingCount = quantity - toGenerate; // = min(quantity, existingCount)
                const idsToRenew = existingCodesRaw.slice(0, keepExistingCount).map(r => r.id);
                renewedCount = idsToRenew.length;
                if (idsToRenew.length > 0) {
                    await conn.query(`UPDATE lic_license_codes SET expiry_date = ? WHERE id IN (${idsToRenew.map(() => '?').join(',')})`, [expiryDate, ...idsToRenew]);
                }
            }
            const keptOldExpiryCount = roundType === 'RENEWAL' ? existingCount - (quantity - toGenerate) : 0;

            const issuedAt = new Date().toISOString();
            await conn.query(
                'UPDATE lic_purchase_registrations SET status = ?, issued_batch_id = ?, issued_quantity = ?, issued_at = ? WHERE id = ?',
                ['ISSUED', batchId, quantity, issuedAt, registrationId]
            );

            await conn.commit();
            outcome = { batchId, toGenerate, renewedCount, keptOldExpiryCount, roundType, quantity, expiryDate };
        } catch (e) {
            await conn.rollback();
            if (e instanceof IssueBatchError) return res.status(e.status).json({ error: e.message });
            throw e;
        } finally {
            conn.release();
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'ISSUE_BATCH', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `${companyCode}/${softwareCode}`, description: `Phát hành license [${softwareCode}] cho công ty [${companyCode}] theo đăng ký #${registrationId} (${outcome.roundType === 'NEW' ? 'Mua mới' : 'Gia hạn'}): ${outcome.roundType === 'NEW' ? `mua thêm ${outcome.quantity}` : `tổng ${outcome.quantity}`} (sinh mới ${outcome.toGenerate})${outcome.expiryDate ? (outcome.roundType === 'RENEWAL' ? `, gia hạn ${outcome.renewedCount} mã đến ${outcome.expiryDate}` : `, hạn ${outcome.expiryDate}`) : ' (license vĩnh viễn, không có hạn)'}${outcome.keptOldExpiryCount > 0 ? `, ${outcome.keptOldExpiryCount} mã cũ giữ nguyên hạn trước đó` : ''}.` });
        res.json({ success: true, id: outcome.batchId, codesGenerated: outcome.toGenerate, renewedCount: outcome.renewedCount, keptOldExpiryCount: outcome.keptOldExpiryCount });
    } catch (err) {
        console.error('❌ Lỗi phát hành license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/batches/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_license_batches WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy lượt phát hành.' });
        const [assigned] = await pool.query(
            'SELECT COUNT(*) AS cnt FROM lic_license_code_assignments a JOIN lic_license_codes c ON c.id = a.code_id WHERE c.batch_id = ?',
            [id]
        );
        if (assigned[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — lượt phát hành này đã sinh ra mã đang được phân bổ cho nhân viên. Hãy thu hồi hết trước.' });
        await pool.query('DELETE FROM lic_license_codes WHERE batch_id = ?', [id]);
        await pool.query('DELETE FROM lic_license_batches WHERE id = ?', [id]);
        // Nếu lượt phát hành này gắn với 1 đăng ký mua (luồng mới bắt buộc theo
        // registrationId), đưa đăng ký về lại APPROVED để Admin có thể phát hành
        // lại (VD lỡ nhập sai số lượng/hạn) — không để đăng ký kẹt ở ISSUED mà
        // lô phát hành tương ứng đã bị xóa.
        if (rows[0].registration_id) {
            await pool.query(
                'UPDATE lic_purchase_registrations SET status = ?, issued_batch_id = NULL, issued_quantity = NULL, issued_at = NULL WHERE id = ? AND issued_batch_id = ?',
                ['APPROVED', rows[0].registration_id, id]
            );
        }
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BATCH', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Lượt phát hành #${id}`, description: `Xóa lượt phát hành license #${id} (chưa có mã nào được phân bổ).` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa lượt phát hành license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Phân bổ (gán / thu hồi mã license cho nhân viên — nhiều-nhiều) ---
// Zero-trust: server tự tra lại công ty của mã và công ty của nhân viên (qua
// đơn vị) để đối chiếu — không tin companyId client gửi kèm. Số người được
// gán tối đa cho 1 mã và việc có cho phép khác công ty hay không đều tra lại
// từ lic_software_catalog của chính mã đó (không tin cấu hình client gửi).
// Khóa dòng mã license (FOR UPDATE) để 2 lượt gán gần như đồng thời cho CÙNG
// 1 mã phải xếp hàng tuần tự — tránh cả 2 cùng đọc "chưa đầy slot" rồi cùng
// insert, vượt quá max_assignees đã cấu hình. Khóa trên chính dòng
// lic_license_codes (luôn tồn tại) thay vì dòng lic_license_code_assignments
// (có thể chưa có dòng nào nếu là lượt gán đầu tiên — khóa trên tập rỗng
// không chặn được request thứ 2). Trả { error } nếu thất bại thay vì throw,
// để hàm gọi hàng loạt (batch) có thể báo lỗi từng dòng mà không rớt cả loạt.
async function assignLicenseCodeToEmployee(codeId, employeeId, issuedDate) {
    if (!codeId) return { error: 'Thiếu mã license.' };
    if (!employeeId) return { error: 'Vui lòng chọn Nhân viên.' };
    if (!validDateStr(issuedDate)) return { error: 'Ngày cấp không hợp lệ.' };

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const [codeRows] = await conn.query(
            `SELECT c.id, c.code, c.company_id, s.max_assignees, s.allow_cross_company_share
             FROM lic_license_codes c JOIN lic_software_catalog s ON s.id = c.software_id WHERE c.id = ? FOR UPDATE`,
            [codeId]
        );
        if (!codeRows[0]) { await conn.rollback(); return { error: 'Không tìm thấy mã license.' }; }
        const code = codeRows[0];

        const [empRows] = await conn.query(
            'SELECT e.id, e.full_name, u.company_id FROM lic_employees e JOIN lic_org_units u ON u.id = e.org_unit_id WHERE e.id = ?',
            [employeeId]
        );
        if (!empRows[0]) { await conn.rollback(); return { error: 'Nhân viên không tồn tại.' }; }
        if (!code.allow_cross_company_share && empRows[0].company_id !== code.company_id) {
            await conn.rollback();
            return { error: 'Nhân viên không thuộc công ty của mã license này (phần mềm chưa cho phép dùng chung khác công ty).' };
        }

        const [existingAssignments] = await conn.query('SELECT employee_id FROM lic_license_code_assignments WHERE code_id = ?', [codeId]);
        if (existingAssignments.some(a => a.employee_id === employeeId)) {
            await conn.rollback();
            return { error: 'Nhân viên này đã được cấp mã license này rồi.' };
        }
        if (existingAssignments.length >= code.max_assignees) {
            await conn.rollback();
            return { error: `Mã license này đã đủ số người tối đa (${code.max_assignees}) — không thể cấp thêm.` };
        }

        await conn.query('INSERT INTO lic_license_code_assignments (code_id, employee_id, assigned_at) VALUES (?, ?, ?)', [codeId, employeeId, issuedDate]);
        await conn.commit();
        return { success: true, codeLabel: code.code, empFullName: empRows[0].full_name, assignedCount: existingAssignments.length + 1 };
    } catch (e) {
        await conn.rollback();
        throw e;
    } finally {
        conn.release();
    }
}

app.post('/api/license/codes/:id/assign', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const employeeId = Number(req.body && req.body.employeeId);
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        const result = await assignLicenseCodeToEmployee(Number(id), employeeId, issuedDate);
        if (result.error) return res.status(result.error === 'Không tìm thấy mã license.' ? 404 : 400).json({ error: result.error });

        await writeAuditLog({ module: 'LICENSE', actionType: 'ASSIGN_CODE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: result.codeLabel, description: `Cấp mã license [${result.codeLabel}] cho nhân viên [${result.empFullName}], ngày cấp ${issuedDate} (${result.assignedCount}).` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cấp phát license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Phân bổ dạng bảng nhiều dòng — mỗi dòng xử lý ĐỘC LẬP (không phải 1 giao
// dịch chung), để 1 dòng lỗi (vd nhân viên đã có mã này) không làm rớt các
// dòng khác — trả kết quả PASS/FAIL từng dòng để admin sửa nhanh dòng lỗi,
// giống tinh thần báo lỗi từng dòng khi nhập Excel.
app.post('/api/license/allocations/batch', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (items.length === 0) return res.status(400).json({ error: 'Danh sách phân bổ trống.' });
        if (items.length > 500) return res.status(400).json({ error: 'Tối đa 500 dòng mỗi lượt.' });

        const results = [];
        let successCount = 0;
        for (const item of items) {
            const codeId = Number(item && item.codeId);
            const employeeId = Number(item && item.employeeId);
            const issuedDate = String((item && item.issuedDate) || '').trim();
            const result = await assignLicenseCodeToEmployee(codeId, employeeId, issuedDate);
            if (result.error) {
                results.push({ codeId, employeeId, success: false, error: result.error });
                continue;
            }
            successCount++;
            results.push({ codeId, employeeId, success: true });
            await writeAuditLog({ module: 'LICENSE', actionType: 'ASSIGN_CODE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: result.codeLabel, description: `Cấp mã license [${result.codeLabel}] cho nhân viên [${result.empFullName}] (phân bổ hàng loạt), ngày cấp ${issuedDate} (${result.assignedCount}).` });
        }
        res.json({ success: true, successCount, failCount: results.length - successCount, results });
    } catch (err) {
        console.error('❌ Lỗi phân bổ dạng bảng:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/codes/:id/unassign', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const employeeId = Number(req.body && req.body.employeeId);
        if (!employeeId) return res.status(400).json({ error: 'Vui lòng chọn Nhân viên cần thu hồi.' });
        const [rows] = await pool.query(
            `SELECT a.id, c.code, e.full_name FROM lic_license_code_assignments a
             JOIN lic_license_codes c ON c.id = a.code_id
             JOIN lic_employees e ON e.id = a.employee_id
             WHERE a.code_id = ? AND a.employee_id = ?`,
            [id, employeeId]
        );
        if (!rows[0]) return res.status(400).json({ error: 'Mã license này chưa được cấp cho nhân viên đó.' });
        await pool.query('DELETE FROM lic_license_code_assignments WHERE code_id = ? AND employee_id = ?', [id, employeeId]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'UNASSIGN_CODE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].code, description: `Thu hồi mã license [${rows[0].code}] từ nhân viên [${rows[0].full_name}].` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi thu hồi license:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Gia hạn/Thu hồi hàng loạt: xử lý hàng loạt nhân viên đang giữ mã ĐÃ HẾT
// HẠN (thường phát sinh khi 1 lần phát hành mua ít hơn số mã đang có — xem
// POST /api/license/batches). Với mỗi dòng Admin xác nhận: RENEW = gia hạn
// thẳng đúng mã đang cầm lên ngày hết hạn của LÔ PHÁT HÀNH GẦN NHẤT của công
// ty+phần mềm đó; REVOKE = thu hồi hẳn (nhân viên đã nghỉ/không dùng nữa).
// LƯU Ý: đây KHÔNG phải tính năng cấp phát mới theo nhân sự — endpoint đó là
// POST /api/license/companies/:companyId/bulk-allocate bên dưới. Route vẫn
// giữ nguyên "/auto-allocate" để không phá tương thích, chỉ đổi tên hiển thị
// (giao diện + audit log) cho rõ nghĩa.
app.post('/api/license/companies/:companyId/auto-allocate', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { companyId } = req.params;
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (items.length === 0) return res.status(400).json({ error: 'Không có mục nào để xử lý.' });
        if (items.length > 500) return res.status(400).json({ error: 'Số lượng xử lý trong 1 lần không được vượt quá 500.' });

        const normalized = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const codeId = Number(it.codeId);
            const employeeId = Number(it.employeeId);
            const action = String(it.action || '').toUpperCase();
            if (!codeId || !employeeId) return res.status(400).json({ error: `Dòng ${i + 1}: thiếu mã license hoặc nhân viên.` });
            if (!['RENEW', 'REVOKE'].includes(action)) return res.status(400).json({ error: `Dòng ${i + 1}: hành động không hợp lệ.` });
            normalized.push({ codeId, employeeId, action });
        }

        // Zero-trust: xác nhận lại toàn bộ mã đều thuộc đúng công ty này và lượt
        // gán đó có thực sự tồn tại — không tin dữ liệu client gửi kèm.
        const codeIds = [...new Set(normalized.map(n => n.codeId))];
        const [codeRows] = await pool.query(
            `SELECT id, company_id, software_id FROM lic_license_codes WHERE id IN (${codeIds.map(() => '?').join(',')})`,
            codeIds
        );
        const codeById = new Map(codeRows.map(r => [r.id, r]));
        for (const n of normalized) {
            const code = codeById.get(n.codeId);
            if (!code || String(code.company_id) !== String(companyId)) {
                return res.status(400).json({ error: 'Có mã license không thuộc công ty này.' });
            }
        }
        const [assignRows] = await pool.query(
            `SELECT code_id, employee_id FROM lic_license_code_assignments WHERE code_id IN (${codeIds.map(() => '?').join(',')})`,
            codeIds
        );
        const assignSet = new Set(assignRows.map(r => `${r.code_id}::${r.employee_id}`));
        for (const n of normalized) {
            if (!assignSet.has(`${n.codeId}::${n.employeeId}`)) {
                return res.status(400).json({ error: 'Có phân bổ không tồn tại hoặc đã thay đổi — vui lòng tải lại trang.' });
            }
        }

        // Ngày hết hạn "gia hạn theo" = ngày hết hạn của lô phát hành GẦN NHẤT
        // (id lớn nhất) của đúng công ty + phần mềm đó.
        const softwareIds = [...new Set(codeIds.map(id => codeById.get(id).software_id))];
        const [latestBatchRows] = await pool.query(
            `SELECT b1.software_id, b1.expiry_date FROM lic_license_batches b1
             INNER JOIN (
                 SELECT software_id, MAX(id) AS max_id FROM lic_license_batches
                 WHERE company_id = ? AND software_id IN (${softwareIds.map(() => '?').join(',')})
                 GROUP BY software_id
             ) b2 ON b1.software_id = b2.software_id AND b1.id = b2.max_id`,
            [companyId, ...softwareIds]
        );
        const latestExpiryBySoftware = new Map(latestBatchRows.map(r => [r.software_id, fmtDate(r.expiry_date)]));

        let renewedCount = 0, revokedCount = 0;
        for (const n of normalized) {
            const code = codeById.get(n.codeId);
            if (n.action === 'REVOKE') {
                await pool.query('DELETE FROM lic_license_code_assignments WHERE code_id = ? AND employee_id = ?', [n.codeId, n.employeeId]);
                revokedCount++;
            } else {
                const newExpiry = latestExpiryBySoftware.get(code.software_id);
                if (newExpiry) {
                    await pool.query('UPDATE lic_license_codes SET expiry_date = ? WHERE id = ?', [newExpiry, n.codeId]);
                    renewedCount++;
                }
            }
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'BULK_RENEW_REVOKE', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Công ty #${companyId}`, description: `Gia hạn/thu hồi hàng loạt: gia hạn ${renewedCount} mã, thu hồi ${revokedCount} mã.` });
        res.json({ success: true, renewedCount, revokedCount });
    } catch (err) {
        console.error('❌ Lỗi gia hạn/thu hồi hàng loạt:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Cấp phát hàng loạt theo nhân sự (MỚI, khác hẳn "Gia hạn/Thu hồi hàng
// loạt" ở trên) — dùng khi vừa phát hành xong 1 lô mã cho 1 phần mềm, muốn
// tự động gán cho tất cả nhân viên trong công ty (hoặc 1 đơn vị trực thuộc
// cụ thể) CHƯA có license phần mềm đó. Server tự tính toán và ghép cặp
// (không nhận danh sách ghép cặp từ client) để luôn khớp đúng dữ liệu tại
// thời điểm chạy — nếu mã còn ÍT hơn số nhân viên cần cấp thì trả về danh
// sách "thiếu" để Admin biết cần mua thêm; nếu mã còn NHIỀU hơn thì phần dư
// tiếp tục nằm trong "kho" (mã chưa gán) để cấp cho lượt sau/nhân viên mới.
app.post('/api/license/companies/:companyId/bulk-allocate', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { companyId } = req.params;
        const softwareId = Number(req.body && req.body.softwareId);
        const orgUnitId = req.body && req.body.orgUnitId ? Number(req.body.orgUnitId) : null;
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        if (!softwareId) return res.status(400).json({ error: 'Vui lòng chọn Phần mềm.' });
        if (!validDateStr(issuedDate)) return res.status(400).json({ error: 'Ngày cấp không hợp lệ.' });

        const [companyRows] = await pool.query('SELECT id, name FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });
        const [softwareRows] = await pool.query('SELECT id, name, max_assignees, allow_cross_company_share FROM lic_software_catalog WHERE id = ?', [softwareId]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });
        const software = softwareRows[0];

        // Phạm vi nhân viên: toàn bộ đơn vị trực thuộc công ty, hoặc thu hẹp về
        // 1 đơn vị (kèm mọi đơn vị con bên dưới) nếu Admin chọn orgUnitId.
        const [allOrgUnits] = await pool.query('SELECT id, parent_id, company_id FROM lic_org_units');
        let scopeOrgUnitIds = allOrgUnits.filter(u => u.company_id === Number(companyId)).map(u => u.id);
        if (orgUnitId) {
            const targetUnit = allOrgUnits.find(u => u.id === orgUnitId);
            if (!targetUnit || targetUnit.company_id !== Number(companyId)) {
                return res.status(400).json({ error: 'Đơn vị trực thuộc không hợp lệ.' });
            }
            const subtreeIds = new Set(orgUnitSubtreeIds(allOrgUnits, orgUnitId));
            scopeOrgUnitIds = scopeOrgUnitIds.filter(id => subtreeIds.has(id));
        }
        if (scopeOrgUnitIds.length === 0) return res.status(400).json({ error: 'Phạm vi đơn vị không có dữ liệu.' });

        const conn = await pool.getConnection();
        let result;
        try {
            await conn.beginTransaction();

            // Nhân viên trong phạm vi CHƯA giữ license phần mềm này (tính cả mã
            // được chia sẻ khác công ty nếu phần mềm cho phép — họ đã có quyền
            // dùng rồi thì không cần cấp thêm).
            const [targetEmployees] = await conn.query(
                `SELECT e.id, e.full_name FROM lic_employees e
                 WHERE e.org_unit_id IN (${scopeOrgUnitIds.map(() => '?').join(',')})
                   AND e.id NOT IN (
                     SELECT a.employee_id FROM lic_license_code_assignments a
                     JOIN lic_license_codes c ON c.id = a.code_id
                     WHERE c.software_id = ?
                   )
                 ORDER BY e.id`,
                [...scopeOrgUnitIds, softwareId]
            );

            // Mã còn slot trống của đúng công ty này (khóa dòng để tránh 2 lượt
            // cấp phát hàng loạt chạy đồng thời cùng giành 1 mã).
            const [codesWithCount] = await conn.query(
                `SELECT c.id, COUNT(a.id) AS assigned_count
                 FROM lic_license_codes c LEFT JOIN lic_license_code_assignments a ON a.code_id = c.id
                 WHERE c.company_id = ? AND c.software_id = ?
                 GROUP BY c.id HAVING assigned_count < ?
                 ORDER BY c.id FOR UPDATE`,
                [companyId, softwareId, software.max_assignees]
            );

            // Mở rộng thành danh sách "slot" (1 dòng = 1 chỗ trống còn lại của 1
            // mã) để hỗ trợ đúng phần mềm multi-assign (max_assignees > 1).
            const slots = [];
            for (const c of codesWithCount) {
                const free = software.max_assignees - c.assigned_count;
                for (let i = 0; i < free; i++) slots.push(c.id);
            }

            const pairCount = Math.min(targetEmployees.length, slots.length);
            const assignedAt = issuedDate;
            for (let i = 0; i < pairCount; i++) {
                await conn.query(
                    'INSERT INTO lic_license_code_assignments (code_id, employee_id, assigned_at) VALUES (?, ?, ?)',
                    [slots[i], targetEmployees[i].id, assignedAt]
                );
            }

            const shortage = targetEmployees.slice(pairCount).map(e => ({ employeeId: e.id, fullName: e.full_name }));
            const leftoverSlots = slots.length - pairCount;

            await conn.commit();
            result = { assignedCount: pairCount, shortage, leftoverSlots };
        } catch (e) {
            await conn.rollback();
            throw e;
        } finally {
            conn.release();
        }

        await writeAuditLog({
            module: 'LICENSE', actionType: 'BULK_ALLOCATE', status: 'SUCCESS',
            username: req.user.username, fullName: req.user.name, ip: req.ip,
            targetObject: `${companyRows[0].name} / ${software.name}`,
            description: `Cấp phát hàng loạt [${software.name}] cho công ty [${companyRows[0].name}]: đã gán ${result.assignedCount}, thiếu ${result.shortage.length}, còn dư trong kho ${result.leftoverSlots}.`
        });
        res.json({ success: true, ...result });
    } catch (err) {
        console.error('❌ Lỗi cấp phát hàng loạt theo nhân sự:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Cấp phát hàng loạt từ file (đích danh nhân sự) — khác hẳn bulk-allocate
// theo phạm vi ở trên: đi thẳng theo danh sách nhân sự import từ Excel, tạo
// yêu cầu CHỜ DUYỆT chứ không cấp ngay. Đối chiếu trùng/khớp nhân viên đã làm
// ở client (dữ liệu employees/licenseCodeAssignments đã có sẵn trong
// bootstrap) — server chỉ lưu lại đúng những gì client đã xác nhận qua bước
// xem trước (conflictType/resolution), không tính lại ở đây.
app.post('/api/license/bulk-allocation-requests', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const companyId = Number(req.body && req.body.companyId);
        const orgUnitId = req.body && req.body.orgUnitId ? Number(req.body.orgUnitId) : null;
        const softwareId = Number(req.body && req.body.softwareId);
        const issuedDate = String((req.body && req.body.issuedDate) || '').trim();
        const rawExpiryDate = String((req.body && req.body.expiryDate) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];

        if (!companyId) return res.status(400).json({ error: 'Vui lòng chọn Công ty.' });
        if (!softwareId) return res.status(400).json({ error: 'Vui lòng chọn Phần mềm.' });
        if (!validDateStr(issuedDate)) return res.status(400).json({ error: 'Ngày cấp không hợp lệ.' });
        if (items.length === 0) return res.status(400).json({ error: 'Danh sách nhân sự trống.' });
        if (items.length > 1000) return res.status(400).json({ error: 'Tối đa 1000 dòng mỗi yêu cầu.' });

        const [companyRows] = await pool.query('SELECT id, name FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });
        const [softwareRows] = await pool.query('SELECT id, name, license_type FROM lic_software_catalog WHERE id = ?', [softwareId]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });

        if (orgUnitId) {
            const [unitRows] = await pool.query('SELECT id FROM lic_org_units WHERE id = ? AND company_id = ?', [orgUnitId, companyId]);
            if (!unitRows[0]) return res.status(400).json({ error: 'Đơn vị mặc định không thuộc công ty đã chọn.' });
        }

        const isPerpetual = softwareRows[0].license_type === 'PERPETUAL';
        let expiryDate = null;
        if (!isPerpetual) {
            if (!validDateStr(rawExpiryDate)) return res.status(400).json({ error: 'Ngày hết hạn không hợp lệ.' });
            if (rawExpiryDate <= issuedDate) return res.status(400).json({ error: 'Ngày hết hạn phải sau Ngày cấp.' });
            expiryDate = rawExpiryDate;
        }

        // Bỏ dòng resolution=SKIP (admin đã chọn bỏ qua lúc xem trước). Nhân
        // viên MỚI (chưa khớp employeeId) bắt buộc phải có đơn vị (theo dòng
        // hoặc đơn vị mặc định của yêu cầu) để biết đặt vào đâu lúc duyệt.
        const cleanItems = [];
        for (const raw of items) {
            const employeeCode = String((raw && raw.employeeCode) || '').trim();
            const fullName = String((raw && raw.fullName) || '').trim();
            if (!employeeCode || !fullName) continue;
            if (raw && raw.resolution === 'SKIP') continue;
            const employeeId = raw && raw.employeeId ? Number(raw.employeeId) : null;
            const itemOrgUnitId = raw && raw.orgUnitId ? Number(raw.orgUnitId) : (orgUnitId || null);
            if (!employeeId && !itemOrgUnitId) {
                return res.status(400).json({ error: `Dòng [${employeeCode}] là nhân viên mới nhưng chưa xác định được đơn vị — chọn Đơn vị mặc định hoặc điền cột Đơn vị trong file.` });
            }
            cleanItems.push({
                employeeCode, fullName,
                deptLabel: raw && raw.deptLabel ? String(raw.deptLabel).trim() : null,
                orgUnitId: itemOrgUnitId,
                email: raw && raw.email ? String(raw.email).trim() : null,
                employeeId,
                conflictType: raw && raw.conflictType ? String(raw.conflictType) : null,
                resolution: raw && raw.resolution ? String(raw.resolution) : null
            });
        }
        if (cleanItems.length === 0) return res.status(400).json({ error: 'Không còn dòng nào để gửi (đã bỏ qua toàn bộ).' });

        const requestedAt = new Date().toISOString();
        const [reqResult] = await pool.query(
            'INSERT INTO lic_bulk_allocation_requests (company_id, org_unit_id, software_id, issued_date, expiry_date, note, status, requested_by, requested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [companyId, orgUnitId, softwareId, issuedDate, expiryDate, note || null, 'PENDING', req.user.username, requestedAt]
        );
        const requestId = reqResult.insertId;
        await pool.query(
            'INSERT INTO lic_bulk_allocation_items (request_id, employee_code, full_name, dept_label, org_unit_id, email, employee_id, conflict_type, resolution) VALUES ?',
            [cleanItems.map(it => [requestId, it.employeeCode, it.fullName, it.deptLabel, it.orgUnitId, it.email, it.employeeId, it.conflictType, it.resolution])]
        );

        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_BULK_ALLOC_REQUEST', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `${companyRows[0].name} / ${softwareRows[0].name}`, description: `Gửi yêu cầu cấp phát hàng loạt [${softwareRows[0].name}] cho công ty [${companyRows[0].name}], ${cleanItems.length} nhân viên, chờ duyệt.` });
        res.json({ success: true, id: requestId, itemCount: cleanItems.length });
    } catch (err) {
        console.error('❌ Lỗi tạo yêu cầu cấp phát hàng loạt:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/bulk-allocation-requests/:id/reject', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const reason = String((req.body && req.body.reason) || '').trim();
        const [rows] = await pool.query('SELECT * FROM lic_bulk_allocation_requests WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy yêu cầu.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Yêu cầu này đã được xử lý trước đó.' });
        await pool.query(
            'UPDATE lic_bulk_allocation_requests SET status = ?, approved_by = ?, approved_at = ?, reject_reason = ? WHERE id = ?',
            ['REJECTED', req.user.username, new Date().toISOString(), reason || null, id]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'REJECT_BULK_ALLOC_REQUEST', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Yêu cầu #${id}`, description: `Từ chối yêu cầu cấp phát hàng loạt #${id}.${reason ? ` Lý do: ${reason}` : ''}` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi từ chối yêu cầu cấp phát hàng loạt:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Lỗi nghiệp vụ trong lúc DUYỆT — mang theo status HTTP, luôn throw thay vì
// res.status(...) trực tiếp bên trong transaction, để catch bên ngoài CHẮC
// CHẮN rollback trước khi trả lỗi (không để lại trạng thái nửa vời).
class BulkAllocApprovalError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

// Duyệt yêu cầu cấp phát hàng loạt — TỰ ĐỘNG trong 1 giao dịch: tạo nhân viên
// mới cho các dòng chưa có (employee_id NULL), phát hành thêm mã còn thiếu
// (tái dùng generateLicenseCodes), rồi gán mã cho từng người. Chặn TỰ DUYỆT ở
// đây (không chỉ ẩn nút ở client) — người duyệt phải khác requested_by.
app.post('/api/license/bulk-allocation-requests/:id/approve', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const [preRows] = await pool.query('SELECT * FROM lic_bulk_allocation_requests WHERE id = ?', [id]);
        if (!preRows[0]) return res.status(404).json({ error: 'Không tìm thấy yêu cầu.' });
        if (preRows[0].status !== 'PENDING') return res.status(400).json({ error: 'Yêu cầu này đã được xử lý trước đó.' });
        if (preRows[0].requested_by === req.user.username) return res.status(403).json({ error: 'Không thể tự duyệt yêu cầu do chính mình tạo — cần một Admin/Người quản lý License khác duyệt.' });

        const [items] = await pool.query('SELECT * FROM lic_bulk_allocation_items WHERE request_id = ?', [id]);
        if (items.length === 0) return res.status(400).json({ error: 'Yêu cầu không có dòng nhân sự nào.' });
        const [companyRows] = await pool.query('SELECT id, code, name FROM lic_companies WHERE id = ?', [preRows[0].company_id]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty của yêu cầu không còn tồn tại.' });
        const [softwareRows] = await pool.query('SELECT id, code, name, max_assignees FROM lic_software_catalog WHERE id = ?', [preRows[0].software_id]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm của yêu cầu không còn tồn tại.' });
        const company = companyRows[0], software = softwareRows[0];

        const conn = await pool.getConnection();
        let outcome;
        try {
            await conn.beginTransaction();

            // Khóa lại dòng yêu cầu + re-check trạng thái — phòng 2 người bấm
            // Duyệt/Từ chối gần như đồng thời.
            const [lockedReq] = await conn.query('SELECT status FROM lic_bulk_allocation_requests WHERE id = ? FOR UPDATE', [id]);
            if (!lockedReq[0] || lockedReq[0].status !== 'PENDING') {
                throw new BulkAllocApprovalError(409, 'Yêu cầu vừa được xử lý bởi người khác, vui lòng tải lại trang.');
            }

            // Tạo nhân viên mới cho các dòng chưa khớp employee_id, hoặc cập
            // nhật hồ sơ nếu admin đã chọn "Cập nhật theo file" lúc xem trước.
            const employeeIdByItemId = new Map();
            for (const item of items) {
                let employeeId = item.employee_id;
                if (employeeId) {
                    if (item.resolution === 'UPDATE_INFO') {
                        if (item.org_unit_id) {
                            await conn.query('UPDATE lic_employees SET full_name = ?, email = ?, org_unit_id = ? WHERE id = ?', [item.full_name, item.email, item.org_unit_id, employeeId]);
                        } else {
                            await conn.query('UPDATE lic_employees SET full_name = ?, email = ? WHERE id = ?', [item.full_name, item.email, employeeId]);
                        }
                    }
                } else {
                    if (!item.org_unit_id) throw new BulkAllocApprovalError(400, `Dòng [${item.employee_code}] là nhân viên mới nhưng thiếu đơn vị, không thể tạo.`);
                    const [unitRows] = await conn.query('SELECT id FROM lic_org_units WHERE id = ?', [item.org_unit_id]);
                    if (!unitRows[0]) throw new BulkAllocApprovalError(400, `Đơn vị của dòng [${item.employee_code}] không còn tồn tại.`);
                    const [insertEmp] = await conn.query(
                        'INSERT INTO lic_employees (org_unit_id, full_name, title, employee_code, email, active) VALUES (?, ?, NULL, ?, ?, TRUE)',
                        [item.org_unit_id, item.full_name, item.employee_code, item.email]
                    );
                    employeeId = insertEmp.insertId;
                }
                employeeIdByItemId.set(item.id, employeeId);
            }

            // An toàn cuối cùng: nhân viên đã có license phần mềm này (tính lại
            // NGAY LÚC DUYỆT, không tin theo conflict_type đã lưu lúc gửi yêu
            // cầu vì dữ liệu có thể đổi trong lúc chờ duyệt) thì BỎ QUA, trừ khi
            // admin đã chủ động chọn "Vẫn cấp thêm" (resolution ALLOCATE_ANYWAY).
            const employeeIds = [...employeeIdByItemId.values()];
            const [alreadyRows] = employeeIds.length
                ? await conn.query(
                    `SELECT DISTINCT a.employee_id FROM lic_license_code_assignments a
                     JOIN lic_license_codes c ON c.id = a.code_id
                     WHERE c.software_id = ? AND a.employee_id IN (${employeeIds.map(() => '?').join(',')})`,
                    [preRows[0].software_id, ...employeeIds]
                )
                : [[]];
            const alreadyLicensedSet = new Set(alreadyRows.map(r => r.employee_id));

            const toAllocate = items.filter(item => {
                const empId = employeeIdByItemId.get(item.id);
                if (alreadyLicensedSet.has(empId) && item.resolution !== 'ALLOCATE_ANYWAY') return false;
                return true;
            });

            // Mã còn slot trống (khóa dòng để tránh race với lượt cấp phát khác
            // chạy song song trên cùng công ty+phần mềm).
            const [codesWithCount] = await conn.query(
                `SELECT c.id, COUNT(a.id) AS assigned_count
                 FROM lic_license_codes c LEFT JOIN lic_license_code_assignments a ON a.code_id = c.id
                 WHERE c.company_id = ? AND c.software_id = ?
                 GROUP BY c.id HAVING assigned_count < ?
                 ORDER BY c.id FOR UPDATE`,
                [preRows[0].company_id, preRows[0].software_id, software.max_assignees]
            );
            const slots = [];
            for (const c of codesWithCount) {
                const free = software.max_assignees - c.assigned_count;
                for (let i = 0; i < free; i++) slots.push(c.id);
            }

            const shortfall = Math.max(0, toAllocate.length - slots.length);
            let codesGenerated = 0;
            if (shortfall > 0) {
                const codes = await generateLicenseCodes(company.code, software.code, shortfall);
                const [batchResult] = await conn.query(
                    'INSERT INTO lic_license_batches (company_id, software_id, total_quantity, codes_generated, issued_date, expiry_date, note, created_at, registration_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)',
                    [preRows[0].company_id, preRows[0].software_id, shortfall, shortfall, preRows[0].issued_date, preRows[0].expiry_date, `Tự động phát hành khi duyệt yêu cầu cấp phát hàng loạt #${id}`, new Date().toISOString()]
                );
                const batchId = batchResult.insertId;
                await conn.query(
                    'INSERT INTO lic_license_codes (batch_id, company_id, software_id, code, expiry_date) VALUES ?',
                    [codes.map(c => [batchId, preRows[0].company_id, preRows[0].software_id, c, preRows[0].expiry_date])]
                );
                const [newCodeRows] = await conn.query('SELECT id FROM lic_license_codes WHERE batch_id = ? ORDER BY id', [batchId]);
                newCodeRows.forEach(r => slots.push(r.id));
                codesGenerated = shortfall;
            }

            let assignedCount = 0;
            const assignedAt = preRows[0].issued_date;
            for (const item of toAllocate) {
                if (slots.length === 0) break;
                const codeId = slots.shift();
                const empId = employeeIdByItemId.get(item.id);
                await conn.query('INSERT INTO lic_license_code_assignments (code_id, employee_id, assigned_at) VALUES (?, ?, ?)', [codeId, empId, assignedAt]);
                assignedCount++;
            }

            await conn.query(
                'UPDATE lic_bulk_allocation_requests SET status = ?, approved_by = ?, approved_at = ? WHERE id = ?',
                ['APPROVED', req.user.username, new Date().toISOString(), id]
            );

            await conn.commit();
            outcome = { assignedCount, skippedCount: items.length - assignedCount, codesGenerated };
        } catch (e) {
            await conn.rollback();
            if (e instanceof BulkAllocApprovalError) return res.status(e.status).json({ error: e.message });
            throw e;
        } finally {
            conn.release();
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'APPROVE_BULK_ALLOC_REQUEST', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `${company.name} / ${software.name}`, description: `Duyệt yêu cầu cấp phát hàng loạt #${id} [${software.name}] cho công ty [${company.name}]: đã cấp ${outcome.assignedCount}, bỏ qua ${outcome.skippedCount}, phát hành thêm ${outcome.codesGenerated} mã mới.` });
        res.json({ success: true, ...outcome });
    } catch (err) {
        console.error('❌ Lỗi duyệt yêu cầu cấp phát hàng loạt:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Kỳ mua bản quyền (Admin tạo kỳ + danh mục phần mềm khả dụng trong kỳ) ---
// Tạo kỳ mua kèm luôn danh sách phần mềm (items) trong 1 lượt gửi — validate
// TOÀN BỘ items trước, chỉ ghi khi tất cả hợp lệ; nếu bước ghi hạng mục lỗi
// giữa chừng thì xóa lại kỳ vừa tạo (không để lại kỳ trống/thiếu phần mềm).
app.post('/api/license/rounds', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        const budgetRoundId = req.body && req.body.budgetRoundId ? Number(req.body.budgetRoundId) : null;
        const roundType = String((req.body && req.body.roundType) || 'RENEWAL').trim().toUpperCase();
        if (!['RENEWAL', 'NEW'].includes(roundType)) return res.status(400).json({ error: 'Loại kỳ mua không hợp lệ.' });
        if (!name) return res.status(400).json({ error: 'Tên kỳ mua không được để trống.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng phần mềm trong 1 lần tạo không được vượt quá 200.' });
        if (budgetRoundId) {
            const [budgetRoundRows] = await pool.query('SELECT id FROM lic_budget_rounds WHERE id = ?', [budgetRoundId]);
            if (!budgetRoundRows[0]) return res.status(400).json({ error: 'Kỳ ngân sách được chọn không tồn tại.' });
        }
        const { scopeType, scopeId, error: scopeErr } = await resolveRoundScope(req.body);
        if (scopeErr) return res.status(400).json({ error: scopeErr });

        const softwareIdSet = new Set();
        const rawItems = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const softwareId = Number(it.softwareId);
            const unitPrice = Number(it.unitPrice);
            const rawExpiryDate = String(it.expiryDate || '').trim();
            if (!softwareId) return res.status(400).json({ error: `Dòng ${i + 1}: vui lòng chọn Phần mềm.` });
            if (softwareIdSet.has(softwareId)) return res.status(400).json({ error: `Dòng ${i + 1}: phần mềm này đã được thêm ở dòng khác.` });
            softwareIdSet.add(softwareId);
            if (!Number.isFinite(unitPrice) || unitPrice < 0) return res.status(400).json({ error: `Dòng ${i + 1}: Đơn giá không hợp lệ.` });
            rawItems.push({ line: i + 1, softwareId, unitPrice, rawExpiryDate });
        }
        const softwareTypeById = new Map();
        if (rawItems.length > 0) {
            const ids = rawItems.map(it => it.softwareId);
            const [softwareRows] = await pool.query(`SELECT id, license_type FROM lic_software_catalog WHERE id IN (${ids.map(() => '?').join(',')})`, ids);
            softwareRows.forEach(s => softwareTypeById.set(s.id, s.license_type));
            if (rawItems.some(it => !softwareTypeById.has(it.softwareId))) {
                return res.status(400).json({ error: 'Có phần mềm không tồn tại trong danh mục.' });
            }
        }
        // Phần mềm Vĩnh viễn (PERPETUAL) không cần Ngày hết hạn — các loại còn
        // lại vẫn bắt buộc nhập như trước, TRỪ Kỳ mua mới (NEW) — hạng mục kỳ
        // mua mới chưa biết trước hạn (Ngày hết hạn được nhập lúc Phát hành).
        const normalizedItems = [];
        for (const it of rawItems) {
            const isPerpetual = softwareTypeById.get(it.softwareId) === 'PERPETUAL';
            let expiryDate = null;
            if (!isPerpetual && roundType === 'RENEWAL') {
                if (!validDateStr(it.rawExpiryDate)) return res.status(400).json({ error: `Dòng ${it.line}: Ngày hết hạn không hợp lệ.` });
                expiryDate = it.rawExpiryDate;
            } else if (!isPerpetual && it.rawExpiryDate && validDateStr(it.rawExpiryDate)) {
                expiryDate = it.rawExpiryDate;
            }
            normalizedItems.push({ softwareId: it.softwareId, unitPrice: it.unitPrice, expiryDate });
        }

        let roundId;
        try {
            const [result] = await pool.query(
                'INSERT INTO lic_purchase_rounds (name, note, status, created_at, budget_round_id, scope_type, scope_id, round_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                [name, note || null, 'OPEN', new Date().toISOString(), budgetRoundId, scopeType, scopeId, roundType]
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

app.put('/api/license/rounds/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

app.post('/api/license/rounds/:id/items', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const softwareId = Number(req.body && req.body.softwareId);
        const unitPrice = Number(req.body && req.body.unitPrice);
        const rawExpiryDate = String((req.body && req.body.expiryDate) || '').trim();
        if (!softwareId) return res.status(400).json({ error: 'Vui lòng chọn Phần mềm.' });
        if (!Number.isFinite(unitPrice) || unitPrice < 0) return res.status(400).json({ error: 'Đơn giá không hợp lệ.' });

        const [roundRows] = await pool.query('SELECT id, status, round_type FROM lic_purchase_rounds WHERE id = ?', [id]);
        if (!roundRows[0]) return res.status(404).json({ error: 'Không tìm thấy kỳ mua.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ mua đã đóng, không thể thêm phần mềm.' });
        const [softwareRows] = await pool.query('SELECT id, name, license_type FROM lic_software_catalog WHERE id = ?', [softwareId]);
        if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });
        const [dupRows] = await pool.query('SELECT id FROM lic_purchase_round_items WHERE round_id = ? AND software_id = ?', [id, softwareId]);
        if (dupRows[0]) return res.status(400).json({ error: 'Phần mềm này đã có trong kỳ mua.' });

        // Kỳ mua mới (NEW) không bắt buộc Ngày hết hạn ở bước này — hạn sẽ được
        // nhập trực tiếp lúc Phát hành.
        const isPerpetual = softwareRows[0].license_type === 'PERPETUAL';
        let expiryDate = null;
        if (!isPerpetual && roundRows[0].round_type === 'RENEWAL') {
            if (!validDateStr(rawExpiryDate)) return res.status(400).json({ error: 'Ngày hết hạn không hợp lệ.' });
            expiryDate = rawExpiryDate;
        } else if (!isPerpetual && rawExpiryDate && validDateStr(rawExpiryDate)) {
            expiryDate = rawExpiryDate;
        }

        const [result] = await pool.query(
            'INSERT INTO lic_purchase_round_items (round_id, software_id, unit_price, expiry_date) VALUES (?, ?, ?, ?)',
            [id, softwareId, unitPrice, expiryDate]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'ADD_ROUND_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: softwareRows[0].name, description: `Thêm phần mềm [${softwareRows[0].name}] vào kỳ mua #${id}, đơn giá ${unitPrice}${expiryDate ? `, hạn ${expiryDate}` : ' (license vĩnh viễn)'}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm phần mềm vào kỳ mua:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/rounds/:roundId/items/:itemId', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

// Xóa nguyên 1 Kỳ mua (dùng khi tạo nhầm) — CHẶN nếu đã có bất kỳ đăng ký nào
// (kể cả PENDING) để không mất dữ liệu công ty đã đăng ký; admin phải tự xóa/
// từ chối đăng ký trước nếu thực sự muốn xóa cả kỳ. Xóa cascade các hạng mục
// (round_items) của kỳ vì lúc này chắc chắn chưa có đăng ký nào tham chiếu.
app.delete('/api/license/rounds/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [roundRows] = await pool.query('SELECT id, name FROM lic_purchase_rounds WHERE id = ?', [id]);
        if (!roundRows[0]) return res.status(404).json({ error: 'Không tìm thấy kỳ mua.' });
        const [regRows] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_purchase_registrations WHERE round_id = ?', [id]);
        if (regRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — kỳ mua này đã có công ty đăng ký. Hãy xóa/từ chối các đăng ký trước.' });
        await pool.query('DELETE FROM lic_purchase_round_items WHERE round_id = ?', [id]);
        await pool.query('DELETE FROM lic_purchase_rounds WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_ROUND', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: roundRows[0].name, description: `Xóa kỳ mua [${roundRows[0].name}] (#${id}) do tạo nhầm.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa kỳ mua:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Đăng ký mua bản quyền (công ty đăng ký nhu cầu + Admin duyệt/từ chối) ---
// 1 công ty đăng ký NHIỀU phần mềm cùng lúc (items) cho 1 kỳ mua — validate
// toàn bộ trước, ghi bằng 1 câu INSERT nhiều dòng (thành công/thất bại cùng
// lúc, không tạo dở dang nếu 1 dòng lỗi).
app.post('/api/license/registrations', requireAuth, async (req, res) => {
    try {
        const roundId = Number(req.body && req.body.roundId);
        const companyId = Number(req.body && req.body.companyId);
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (!roundId) return res.status(400).json({ error: 'Vui lòng chọn Kỳ mua.' });
        if (!companyId) return res.status(400).json({ error: 'Vui lòng chọn Công ty.' });
        if (items.length === 0) return res.status(400).json({ error: 'Vui lòng thêm ít nhất 1 phần mềm để đăng ký.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng phần mềm trong 1 lần đăng ký không được vượt quá 200.' });

        const [roundRows] = await pool.query('SELECT id, status, budget_round_id, scope_type, scope_id FROM lic_purchase_rounds WHERE id = ?', [roundId]);
        if (!roundRows[0]) return res.status(400).json({ error: 'Kỳ mua không tồn tại.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ mua đã đóng, không thể đăng ký.' });
        const [companyRows] = await pool.query('SELECT id, name FROM lic_companies WHERE id = ?', [companyId]);
        if (!companyRows[0]) return res.status(400).json({ error: 'Công ty không tồn tại.' });

        const isAdmin = !!(req.user.perms && (req.user.perms.admin || req.user.perms.licenseManager));
        if (!isAdmin) {
            const userScope = getUserLicenseScope(req.user);
            const [allOrgUnitsRows] = await pool.query('SELECT id, parent_id, company_id FROM lic_org_units');
            const roundScope = roundRows[0].scope_type ? { type: roundRows[0].scope_type, id: roundRows[0].scope_id } : null;
            const allowed = userCanActOnTarget({ isAdmin, userScope, roundScope, allOrgUnits: allOrgUnitsRows, targetCompanyId: companyId, targetOrgUnitId: null });
            if (!allowed) return res.status(403).json({ error: 'Bạn không có quyền đăng ký mua cho công ty này trong kỳ mua này.' });
        }

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

        // Nếu Kỳ mua này có liên kết Kỳ ngân sách: tra thêm số lượng đã được
        // DUYỆT ở bước dự trù (cộng dồn mọi đơn vị trực thuộc của công ty đang
        // đăng ký) theo từng phần mềm, để hiển thị cột "Ngân sách" tham chiếu.
        // Không liên kết thì budget_quantity = NULL (ẩn cột, không phải 0).
        let budgetBySoftware = new Map();
        if (roundRows[0].budget_round_id) {
            const [budgetUsageRows] = await pool.query(
                `SELECT bi.software_id, SUM(br.requested_quantity) AS cnt
                 FROM lic_budget_registrations br
                 JOIN lic_budget_round_items bi ON bi.id = br.round_item_id
                 JOIN lic_org_units u ON u.id = br.org_unit_id
                 WHERE br.round_id = ? AND br.status = 'APPROVED' AND u.company_id = ?
                   AND bi.software_id IN (${softwareIds.map(() => '?').join(',')})
                 GROUP BY bi.software_id`,
                [roundRows[0].budget_round_id, companyId, ...softwareIds]
            );
            budgetBySoftware = new Map(budgetUsageRows.map(r => [r.software_id, Number(r.cnt) || 0]));
        }

        const insertValues = normalizedItems.map(it => {
            const item = itemsById.get(it.roundItemId);
            const currentQuantity = usageBySoftware.get(item.software_id) || 0;
            const unitPrice = Number(item.unit_price);
            const totalAmount = it.requestedQuantity * unitPrice;
            const budgetQuantity = roundRows[0].budget_round_id ? (budgetBySoftware.get(item.software_id) ?? 0) : null;
            return [roundId, it.roundItemId, companyId, currentQuantity, it.requestedQuantity, unitPrice, totalAmount, item.expiry_date, 'PENDING', note || null, new Date().toISOString(), budgetQuantity, req.user.username];
        });

        await pool.query(
            'INSERT INTO lic_purchase_registrations (round_id, round_item_id, company_id, current_quantity, requested_quantity, unit_price, total_amount, expiry_date, status, note, created_at, budget_quantity, created_by) VALUES ?',
            [insertValues]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: companyRows[0].name, description: `Công ty [${companyRows[0].name}] đăng ký mua ${normalizedItems.length} phần mềm (kỳ mua #${roundId}), chờ duyệt.` });
        res.json({ success: true, count: normalizedItems.length });
    } catch (err) {
        console.error('❌ Lỗi tạo đăng ký mua bản quyền:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/registrations/:id/approve', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_purchase_registrations WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đăng ký.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Đăng ký này đã được xử lý.' });
        if (rows[0].created_by && rows[0].created_by === req.user.username) return res.status(403).json({ error: 'Không thể tự duyệt đăng ký do chính mình tạo — cần một Admin/Người quản lý License khác duyệt.' });
        await pool.query('UPDATE lic_purchase_registrations SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?', ['APPROVED', req.user.username, new Date().toISOString(), id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'APPROVE_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Đăng ký #${id}`, description: `Duyệt đăng ký mua bản quyền #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi duyệt đăng ký:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/registrations/:id/reject', requireAuth, requireLicenseOrAdmin, async (req, res) => {
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

// --- Kỳ ngân sách (module ĐỘC LẬP với Kỳ mua bản quyền ở trên) — dự trù ngân
// sách theo kỳ, dữ liệu nhập theo TỪNG ĐƠN VỊ TRỰC THUỘC (org_unit) thay vì
// theo công ty. Cấu trúc endpoint mirror y hệt Kỳ mua để nhất quán cho Admin.
app.post('/api/license/budget-rounds', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (!name) return res.status(400).json({ error: 'Tên kỳ ngân sách không được để trống.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng hạng mục trong 1 lần tạo không được vượt quá 200.' });
        const { scopeType, scopeId, error: scopeErr } = await resolveRoundScope(req.body);
        if (scopeErr) return res.status(400).json({ error: scopeErr });

        const dedupKeySet = new Set();
        const normalizedItems = [];
        for (let i = 0; i < items.length; i++) {
            const normalized = normalizeBudgetItem(items[i], `Dòng ${i + 1}`);
            if (normalized.error) return res.status(400).json({ error: normalized.error });
            const dedupKey = normalized.itemType === 'SOFTWARE' ? `sw:${normalized.softwareId}` : `cat:${normalized.catalogItemId}`;
            if (dedupKeySet.has(dedupKey)) return res.status(400).json({ error: `Dòng ${i + 1}: hạng mục này đã được thêm ở dòng khác.` });
            dedupKeySet.add(dedupKey);
            normalizedItems.push(normalized);
        }
        const softwareIds = normalizedItems.filter(it => it.itemType === 'SOFTWARE').map(it => it.softwareId);
        if (softwareIds.length > 0) {
            const [softwareRows] = await pool.query(`SELECT id FROM lic_software_catalog WHERE id IN (${softwareIds.map(() => '?').join(',')})`, softwareIds);
            if (softwareRows.length !== new Set(softwareIds).size) return res.status(400).json({ error: 'Có phần mềm không tồn tại trong danh mục.' });
        }
        const catalogItemIds = normalizedItems.filter(it => it.itemType !== 'SOFTWARE').map(it => it.catalogItemId);
        if (catalogItemIds.length > 0) {
            const [catalogRows] = await pool.query(`SELECT id, item_type FROM lic_budget_item_catalog WHERE id IN (${catalogItemIds.map(() => '?').join(',')}) AND active = 1`, catalogItemIds);
            const catalogTypeById = new Map(catalogRows.map(r => [r.id, r.item_type]));
            for (const it of normalizedItems) {
                if (it.itemType !== 'SOFTWARE' && catalogTypeById.get(it.catalogItemId) !== it.itemType) {
                    return res.status(400).json({ error: 'Có hạng mục trong danh mục không hợp lệ hoặc không đúng loại đã chọn.' });
                }
            }
        }

        let roundId;
        try {
            const [result] = await pool.query(
                'INSERT INTO lic_budget_rounds (name, note, status, created_at, scope_type, scope_id) VALUES (?, ?, ?, ?, ?, ?)',
                [name, note || null, 'OPEN', new Date().toISOString(), scopeType, scopeId]
            );
            roundId = result.insertId;
            if (normalizedItems.length > 0) {
                await pool.query(
                    'INSERT INTO lic_budget_round_items (round_id, software_id, item_type, item_name, catalog_item_id, capex_opex, unit_price, description) VALUES ?',
                    [normalizedItems.map(it => [roundId, it.softwareId, it.itemType, null, it.catalogItemId, it.capexOpex, it.unitPrice, it.description])]
                );
            }
        } catch (insertErr) {
            if (roundId) await pool.query('DELETE FROM lic_budget_rounds WHERE id = ?', [roundId]).catch(() => {});
            throw insertErr;
        }

        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_BUDGET_ROUND', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Tạo kỳ ngân sách [${name}] với ${normalizedItems.length} hạng mục.` });
        res.json({ success: true, id: roundId });
    } catch (err) {
        console.error('❌ Lỗi tạo kỳ ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.put('/api/license/budget-rounds/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const status = String((req.body && req.body.status) || '').trim().toUpperCase();
        if (!['OPEN', 'CLOSED'].includes(status)) return res.status(400).json({ error: 'Trạng thái không hợp lệ.' });
        const [result] = await pool.query('UPDATE lic_budget_rounds SET status = ? WHERE id = ?', [status, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy kỳ ngân sách.' });
        await writeAuditLog({ module: 'LICENSE', actionType: 'UPDATE_BUDGET_ROUND_STATUS', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Kỳ ngân sách #${id}`, description: `Đổi trạng thái kỳ ngân sách #${id} thành ${status}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cập nhật kỳ ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/budget-rounds/:id/items', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const normalized = normalizeBudgetItem(req.body, 'Hạng mục');
        if (normalized.error) return res.status(400).json({ error: normalized.error });

        const [roundRows] = await pool.query('SELECT id, status FROM lic_budget_rounds WHERE id = ?', [id]);
        if (!roundRows[0]) return res.status(404).json({ error: 'Không tìm thấy kỳ ngân sách.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ ngân sách đã đóng, không thể thêm hạng mục.' });
        let itemLabel;
        if (normalized.itemType === 'SOFTWARE') {
            const [softwareRows] = await pool.query('SELECT id, name FROM lic_software_catalog WHERE id = ?', [normalized.softwareId]);
            if (!softwareRows[0]) return res.status(400).json({ error: 'Phần mềm không tồn tại.' });
            itemLabel = softwareRows[0].name;
            const [dupRows] = await pool.query('SELECT id FROM lic_budget_round_items WHERE round_id = ? AND item_type = ? AND software_id = ?', [id, 'SOFTWARE', normalized.softwareId]);
            if (dupRows[0]) return res.status(400).json({ error: 'Phần mềm này đã có trong kỳ ngân sách.' });
        } else {
            const [catalogRows] = await pool.query('SELECT id, name, item_type FROM lic_budget_item_catalog WHERE id = ? AND active = 1', [normalized.catalogItemId]);
            if (!catalogRows[0] || catalogRows[0].item_type !== normalized.itemType) return res.status(400).json({ error: 'Hạng mục trong danh mục không hợp lệ hoặc không đúng loại đã chọn.' });
            itemLabel = catalogRows[0].name;
            const [dupRows] = await pool.query('SELECT id FROM lic_budget_round_items WHERE round_id = ? AND item_type = ? AND catalog_item_id = ?', [id, normalized.itemType, normalized.catalogItemId]);
            if (dupRows[0]) return res.status(400).json({ error: 'Hạng mục này đã có trong kỳ ngân sách.' });
        }

        const [result] = await pool.query(
            'INSERT INTO lic_budget_round_items (round_id, software_id, item_type, item_name, catalog_item_id, capex_opex, unit_price, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [id, normalized.softwareId, normalized.itemType, null, normalized.catalogItemId, normalized.capexOpex, normalized.unitPrice, normalized.description]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'ADD_BUDGET_ROUND_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: itemLabel, description: `Thêm hạng mục [${itemLabel}] (${normalized.itemType}/${normalized.capexOpex}) vào kỳ ngân sách #${id}, đơn giá ${normalized.unitPrice}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm hạng mục vào kỳ ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/budget-rounds/:roundId/items/:itemId', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { roundId, itemId } = req.params;
        const [itemRows] = await pool.query('SELECT id FROM lic_budget_round_items WHERE id = ? AND round_id = ?', [itemId, roundId]);
        if (!itemRows[0]) return res.status(404).json({ error: 'Không tìm thấy hạng mục trong kỳ ngân sách.' });
        const [regRows] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_budget_registrations WHERE round_item_id = ?', [itemId]);
        if (regRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đã có đơn vị dự trù ngân sách cho hạng mục này trong kỳ.' });
        const [actualRows] = await pool.query('SELECT COUNT(*) AS cnt FROM lic_budget_actuals WHERE round_item_id = ?', [itemId]);
        if (actualRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — đã có dòng mua thực tế ghi nhận cho hạng mục này.' });
        await pool.query('DELETE FROM lic_budget_round_items WHERE id = ?', [itemId]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BUDGET_ROUND_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Hạng mục #${itemId}`, description: `Xóa hạng mục #${itemId} khỏi kỳ ngân sách #${roundId}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa hạng mục kỳ ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Xóa nguyên 1 Kỳ ngân sách (dùng khi tạo nhầm) — CHẶN nếu bất kỳ hạng mục nào
// trong kỳ đã có dự trù (registrations) hoặc mua thực tế (actuals) ghi nhận.
app.delete('/api/license/budget-rounds/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [roundRows] = await pool.query('SELECT id, name FROM lic_budget_rounds WHERE id = ?', [id]);
        if (!roundRows[0]) return res.status(404).json({ error: 'Không tìm thấy kỳ ngân sách.' });
        const [regRows] = await pool.query(
            'SELECT COUNT(*) AS cnt FROM lic_budget_registrations r JOIN lic_budget_round_items i ON i.id = r.round_item_id WHERE i.round_id = ?', [id]
        );
        if (regRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — kỳ ngân sách này đã có đơn vị dự trù. Hãy xóa các dự trù trước.' });
        const [actualRows] = await pool.query(
            'SELECT COUNT(*) AS cnt FROM lic_budget_actuals a JOIN lic_budget_round_items i ON i.id = a.round_item_id WHERE i.round_id = ?', [id]
        );
        if (actualRows[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — kỳ ngân sách này đã có dòng mua thực tế ghi nhận.' });
        await pool.query('DELETE FROM lic_budget_round_items WHERE round_id = ?', [id]);
        await pool.query('DELETE FROM lic_budget_rounds WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BUDGET_ROUND', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: roundRows[0].name, description: `Xóa kỳ ngân sách [${roundRows[0].name}] (#${id}) do tạo nhầm.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa kỳ ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Đăng ký dự trù ngân sách theo đơn vị trực thuộc — currentQuantity tự tính
// = số license ĐANG THỰC SỰ ĐƯỢC GÁN cho nhân viên trong đơn vị đó (kể cả các
// đơn vị con bên dưới), KHÁC với currentQuantity của Kỳ mua (đếm theo tổng số
// mã công ty đang SỞ HỮU, không phân biệt đã gán hay chưa) — vì ở cấp đơn vị
// trực thuộc, chỉ có nhân viên (qua org_unit_id) mới xác định được đơn vị,
// còn mã license chỉ gắn với company_id, không gắn trực tiếp với đơn vị.
app.post('/api/license/budget-registrations', requireAuth, async (req, res) => {
    try {
        const roundId = Number(req.body && req.body.roundId);
        const orgUnitId = Number(req.body && req.body.orgUnitId);
        const note = String((req.body && req.body.note) || '').trim();
        const items = Array.isArray(req.body && req.body.items) ? req.body.items : [];
        if (!roundId) return res.status(400).json({ error: 'Vui lòng chọn Kỳ ngân sách.' });
        if (!orgUnitId) return res.status(400).json({ error: 'Vui lòng chọn Đơn vị trực thuộc.' });
        if (items.length === 0) return res.status(400).json({ error: 'Vui lòng thêm ít nhất 1 phần mềm để dự trù.' });
        if (items.length > 200) return res.status(400).json({ error: 'Số lượng phần mềm trong 1 lần dự trù không được vượt quá 200.' });

        const [roundRows] = await pool.query('SELECT id, status, scope_type, scope_id FROM lic_budget_rounds WHERE id = ?', [roundId]);
        if (!roundRows[0]) return res.status(400).json({ error: 'Kỳ ngân sách không tồn tại.' });
        if (roundRows[0].status !== 'OPEN') return res.status(400).json({ error: 'Kỳ ngân sách đã đóng, không thể dự trù.' });
        const [orgUnitRows] = await pool.query('SELECT id, name FROM lic_org_units WHERE id = ?', [orgUnitId]);
        if (!orgUnitRows[0]) return res.status(400).json({ error: 'Đơn vị trực thuộc không tồn tại.' });
        const [allOrgUnits] = await pool.query('SELECT id, parent_id, company_id FROM lic_org_units');

        const isAdmin = !!(req.user.perms && (req.user.perms.admin || req.user.perms.licenseManager));
        if (!isAdmin) {
            const userScope = getUserLicenseScope(req.user);
            const roundScope = roundRows[0].scope_type ? { type: roundRows[0].scope_type, id: roundRows[0].scope_id } : null;
            const allowed = userCanActOnTarget({ isAdmin, userScope, roundScope, allOrgUnits, targetCompanyId: null, targetOrgUnitId: orgUnitId });
            if (!allowed) return res.status(403).json({ error: 'Bạn không có quyền dự trù ngân sách cho đơn vị này trong kỳ ngân sách này.' });
        }

        const roundItemIdSet = new Set();
        const normalizedItems = [];
        for (let i = 0; i < items.length; i++) {
            const it = items[i] || {};
            const roundItemId = Number(it.roundItemId);
            const requestedQuantity = Number(it.requestedQuantity);
            if (!roundItemId) return res.status(400).json({ error: `Dòng ${i + 1}: vui lòng chọn Phần mềm.` });
            if (roundItemIdSet.has(roundItemId)) return res.status(400).json({ error: `Dòng ${i + 1}: phần mềm này đã được dự trù ở dòng khác.` });
            roundItemIdSet.add(roundItemId);
            if (!Number.isInteger(requestedQuantity) || requestedQuantity < 1 || requestedQuantity > 5000) return res.status(400).json({ error: `Dòng ${i + 1}: Số lượng phải là số nguyên từ 1 đến 5000.` });
            normalizedItems.push({ roundItemId, requestedQuantity });
        }

        const itemIds = normalizedItems.map(it => it.roundItemId);
        const [itemRows] = await pool.query(
            `SELECT * FROM lic_budget_round_items WHERE round_id = ? AND id IN (${itemIds.map(() => '?').join(',')})`,
            [roundId, ...itemIds]
        );
        const itemsById = new Map(itemRows.map(r => [r.id, r]));
        if (normalizedItems.some(it => !itemsById.has(it.roundItemId))) {
            return res.status(400).json({ error: 'Có hạng mục không thuộc kỳ ngân sách này.' });
        }

        const subtreeIds = orgUnitSubtreeIds(allOrgUnits, orgUnitId);
        const softwareIds = itemRows.filter(r => r.item_type === 'SOFTWARE' && r.software_id).map(r => r.software_id);
        let usageBySoftware = new Map();
        if (softwareIds.length > 0) {
            const [usageRows] = await pool.query(
                `SELECT c.software_id, COUNT(*) AS cnt
                 FROM lic_license_code_assignments a
                 JOIN lic_license_codes c ON c.id = a.code_id
                 JOIN lic_employees e ON e.id = a.employee_id
                 WHERE e.org_unit_id IN (${subtreeIds.map(() => '?').join(',')}) AND c.software_id IN (${softwareIds.map(() => '?').join(',')})
                 GROUP BY c.software_id`,
                [...subtreeIds, ...softwareIds]
            );
            usageBySoftware = new Map(usageRows.map(r => [r.software_id, r.cnt]));
        }

        const insertValues = normalizedItems.map(it => {
            const item = itemsById.get(it.roundItemId);
            const currentQuantity = item.item_type === 'SOFTWARE' ? (usageBySoftware.get(item.software_id) || 0) : 0;
            const unitPrice = Number(item.unit_price);
            const totalAmount = it.requestedQuantity * unitPrice;
            return [roundId, it.roundItemId, orgUnitId, currentQuantity, it.requestedQuantity, unitPrice, totalAmount, 'PENDING', note || null, new Date().toISOString(), req.user.username];
        });

        await pool.query(
            'INSERT INTO lic_budget_registrations (round_id, round_item_id, org_unit_id, current_quantity, requested_quantity, unit_price, total_amount, status, note, created_at, created_by) VALUES ?',
            [insertValues]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_BUDGET_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: orgUnitRows[0].name, description: `Đơn vị [${orgUnitRows[0].name}] dự trù ngân sách ${normalizedItems.length} phần mềm (kỳ ngân sách #${roundId}), chờ duyệt.` });
        res.json({ success: true, count: normalizedItems.length });
    } catch (err) {
        console.error('❌ Lỗi tạo dự trù ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/budget-registrations/:id/approve', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_budget_registrations WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy dự trù.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Dự trù này đã được xử lý.' });
        if (rows[0].created_by && rows[0].created_by === req.user.username) return res.status(403).json({ error: 'Không thể tự duyệt dự trù do chính mình tạo — cần một Admin/Người quản lý License khác duyệt.' });
        await pool.query('UPDATE lic_budget_registrations SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?', ['APPROVED', req.user.username, new Date().toISOString(), id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'APPROVE_BUDGET_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Dự trù #${id}`, description: `Duyệt dự trù ngân sách #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi duyệt dự trù ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.post('/api/license/budget-registrations/:id/reject', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM lic_budget_registrations WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy dự trù.' });
        if (rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Dự trù này đã được xử lý.' });
        await pool.query('UPDATE lic_budget_registrations SET status = ?, decided_by = ?, decided_at = ? WHERE id = ?', ['REJECTED', req.user.username, new Date().toISOString(), id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'REJECT_BUDGET_REGISTRATION', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Dự trù #${id}`, description: `Từ chối dự trù ngân sách #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi từ chối dự trù ngân sách:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// Sổ ghi nhận mua thực tế cho 1 hạng mục ngân sách — ĐỘC LẬP với dự trù theo
// đơn vị, dùng để so sánh Kế hoạch (dự trù đã duyệt) vs Thực tế (tổng các
// dòng ở đây). Cho phép nhiều dòng theo thời gian (nhiều đợt/nhà cung cấp).
app.post('/api/license/budget-round-items/:itemId/actuals', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { itemId } = req.params;
        const purchaseDate = String((req.body && req.body.purchaseDate) || '').trim();
        const vendor = String((req.body && req.body.vendor) || '').trim();
        const quantity = Number(req.body && req.body.quantity);
        const unitPrice = Number(req.body && req.body.unitPrice);
        const note = String((req.body && req.body.note) || '').trim();
        const companyId = req.body && req.body.companyId ? Number(req.body.companyId) : null;
        if (!purchaseDate || !/^\d{4}-\d{2}-\d{2}$/.test(purchaseDate)) return res.status(400).json({ error: 'Vui lòng chọn Ngày mua hợp lệ.' });
        if (!Number.isFinite(quantity) || quantity <= 0) return res.status(400).json({ error: 'Số lượng phải lớn hơn 0.' });
        if (!Number.isFinite(unitPrice) || unitPrice < 0) return res.status(400).json({ error: 'Đơn giá không hợp lệ.' });

        const [itemRows] = await pool.query('SELECT id FROM lic_budget_round_items WHERE id = ?', [itemId]);
        if (!itemRows[0]) return res.status(404).json({ error: 'Không tìm thấy hạng mục ngân sách.' });
        if (companyId) {
            const [companyRows] = await pool.query('SELECT id FROM lic_companies WHERE id = ?', [companyId]);
            if (!companyRows[0]) return res.status(400).json({ error: 'Công ty được chọn không tồn tại.' });
        }

        const amount = quantity * unitPrice;
        const [result] = await pool.query(
            'INSERT INTO lic_budget_actuals (round_item_id, company_id, purchase_date, vendor, quantity, unit_price, amount, note, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [itemId, companyId, purchaseDate, vendor || null, quantity, unitPrice, amount, note || null, req.user.username, new Date().toISOString()]
        );
        await writeAuditLog({ module: 'LICENSE', actionType: 'CREATE_BUDGET_ACTUAL', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Hạng mục #${itemId}`, description: `Ghi nhận mua thực tế cho hạng mục #${itemId}: SL ${quantity} x ${unitPrice} = ${amount}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi ghi nhận mua thực tế:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

app.delete('/api/license/budget-actuals/:id', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT id FROM lic_budget_actuals WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy dòng mua thực tế.' });
        await pool.query('DELETE FROM lic_budget_actuals WHERE id = ?', [id]);
        await writeAuditLog({ module: 'LICENSE', actionType: 'DELETE_BUDGET_ACTUAL', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: `Mua thực tế #${id}`, description: `Xóa dòng mua thực tế #${id}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa dòng mua thực tế:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Nhập CSV hàng loạt (Tổ chức công ty / Nhân viên) ---
// Client chỉ parse CSV thành mảng dòng thô rồi gửi lên — server tự validate
// và tạo dữ liệu hoàn toàn, không tin cấu trúc/quan hệ do client suy luận sẵn.
app.post('/api/license/org-units/import', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows.slice(0, 2000) : [];
        if (rows.length === 0) return res.status(400).json({ error: 'File không có dữ liệu hợp lệ.' });

        const [existingCompanies] = await pool.query('SELECT * FROM lic_companies');
        const companyByCode = new Map(existingCompanies.map(c => [c.code, c]));
        const [existingUnits] = await pool.query('SELECT * FROM lic_org_units');
        // Key theo CẢ company + parent + tên — không chỉ company + tên — vì cây
        // tổ chức là N cấp, 2 đơn vị cùng tên nhưng khác nhánh cha (VD "Phòng Kế
        // Toán" ở Chi nhánh A và Chi nhánh B) là 2 đơn vị KHÁC NHAU, không phải
        // trùng lặp cần bỏ qua.
        const orgUnitKey = (companyId, parentId, name) => `${companyId}::${parentId ?? 'root'}::${name}`;
        const unitByKey = new Map(existingUnits.map(u => [orgUnitKey(u.company_id, u.parent_id, u.name), u]));

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
                    // Cha được tìm theo tên trong TOÀN công ty (không biết trước cha của
                    // cha), nên nếu công ty có 2 đơn vị trùng tên ở 2 nhánh khác nhau thì
                    // đây vẫn là 1 giới hạn đã biết của việc tra theo tên — chỉ áp dụng
                    // cho việc tìm CHA, không ảnh hưởng tới việc dedup đơn vị hiện tại
                    // (đã sửa bên dưới để phân biệt đúng theo từng nhánh cha).
                    const parentCandidates = [...unitByKey.values()].filter(u => u.company_id === company.id && u.name === parentName);
                    if (parentCandidates.length === 0) continue; // chưa tạo được cha, thử lượt sau
                    if (parentCandidates.length > 1) { errors.push(`Dòng ${rowNo}: có nhiều hơn 1 đơn vị tên [${parentName}] trong công ty — không thể xác định đúng đơn vị cha, hãy đổi tên cho không trùng.`); pending.splice(idx, 1); continue; }
                    parentId = parentCandidates[0].id;
                }

                const key = orgUnitKey(company.id, parentId, unitName);
                if (unitByKey.has(key)) { pending.splice(idx, 1); continue; } // đã có sẵn (đúng công ty + đúng cha + đúng tên), bỏ qua
                const [result] = await pool.query(
                    'INSERT INTO lic_org_units (company_id, parent_id, name, level_label, sort_order) VALUES (?, ?, ?, ?, 0)',
                    [company.id, parentId, unitName, level]
                );
                unitByKey.set(key, { id: result.insertId, company_id: company.id, parent_id: parentId, name: unitName });
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

app.post('/api/license/employees/import', requireAuth, requireLicenseOrAdmin, async (req, res) => {
    try {
        const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows.slice(0, 2000) : [];
        if (rows.length === 0) return res.status(400).json({ error: 'File không có dữ liệu hợp lệ.' });

        const [companies] = await pool.query('SELECT * FROM lic_companies');
        const companyByCode = new Map(companies.map(c => [c.code, c]));
        const [units] = await pool.query('SELECT * FROM lic_org_units');
        const [existingEmployees] = await pool.query('SELECT * FROM lic_employees');
        const unitById = new Map(units.map(u => [u.id, u]));
        // Key theo CẢ company + mã NV — không chỉ mã NV — vì mỗi công ty tự đánh
        // số mã nhân viên độc lập, trùng mã giữa 2 công ty khác nhau là bình
        // thường (không phải cùng 1 người) — trước đây match toàn hệ thống nên
        // nhập CSV công ty B có thể ghi đè nhầm nhân viên trùng mã của công ty A.
        const employeeByCompanyAndCode = new Map();
        existingEmployees.forEach(e => {
            if (!e.employee_code) return;
            const unit = unitById.get(e.org_unit_id);
            if (!unit) return;
            employeeByCompanyAndCode.set(`${unit.company_id}::${e.employee_code}`, e);
        });

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
            const candidateUnits = units.filter(u => u.company_id === company.id && u.name === unitName);
            if (candidateUnits.length === 0) { errors.push(`Dòng ${rowNo}: không tìm thấy đơn vị [${unitName}] trong công ty [${companyCode}] — nhập Tổ chức công ty trước.`); continue; }
            if (candidateUnits.length > 1) { errors.push(`Dòng ${rowNo}: có nhiều hơn 1 đơn vị tên [${unitName}] trong công ty [${companyCode}] — không thể xác định đúng đơn vị, hãy đổi tên đơn vị cho không trùng.`); continue; }
            const unit = candidateUnits[0];

            const employeeKey = `${company.id}::${employeeCode}`;
            if (employeeCode && employeeByCompanyAndCode.has(employeeKey)) {
                const existing = employeeByCompanyAndCode.get(employeeKey);
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
                if (employeeCode) employeeByCompanyAndCode.set(employeeKey, { id: result.insertId, employee_code: employeeCode });
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

// ============================================================
// MODULE QUẢN LÝ CNTT — theo dõi ngày hết hạn các dịch vụ/bản quyền do CNTT
// quản lý (cước Internet, bản quyền Firewall, tên miền, SSL, email, phần mềm
// hệ thống, phần mềm khác...) và tự động gửi email nhắc trước khi hết hạn.
// Toàn bộ module chỉ Admin mới truy cập được (giống các mục Quản trị khác) —
// người phụ trách 1 đầu mục không cần vào app, chỉ cần nhận được email nhắc.
// ============================================================
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

app.get('/api/it/bootstrap', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [categories] = await pool.query('SELECT * FROM it_categories ORDER BY sort_order, name');
        const [items] = await pool.query('SELECT * FROM it_items ORDER BY expiry_date');
        const reminderConfig = await getItReminderConfig();
        const lastCheckAt = await getItExpiryLastCheckAt();
        res.json({
            categories: categories.map(mapItCategory),
            items: items.map(mapItItem),
            reminderConfig,
            lastCheckAt: lastCheckAt || null
        });
    } catch (err) {
        console.error('❌ Lỗi tải dữ liệu module Quản lý CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Danh mục loại dịch vụ/bản quyền (tự cấu hình được) ---
app.post('/api/it/categories', requireAuth, requireAdmin, async (req, res) => {
    try {
        const name = String((req.body && req.body.name) || '').trim();
        if (!name) return res.status(400).json({ error: 'Tên danh mục không được để trống.' });
        const sortOrder = Number.isFinite(Number(req.body && req.body.sortOrder)) ? Number(req.body.sortOrder) : 0;
        const [result] = await pool.query('INSERT INTO it_categories (name, active, sort_order) VALUES (?, TRUE, ?)', [name, sortOrder]);
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'CREATE_IT_CATEGORY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Thêm danh mục CNTT [${name}].` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên danh mục đã tồn tại.' });
        console.error('❌ Lỗi thêm danh mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});
app.put('/api/it/categories/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const name = String((req.body && req.body.name) || '').trim();
        if (!name) return res.status(400).json({ error: 'Tên danh mục không được để trống.' });
        const sortOrder = Number.isFinite(Number(req.body && req.body.sortOrder)) ? Number(req.body.sortOrder) : 0;
        const active = req.body && req.body.active !== undefined ? !!req.body.active : true;
        const [result] = await pool.query('UPDATE it_categories SET name = ?, sort_order = ?, active = ? WHERE id = ?', [name, sortOrder, active, id]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Không tìm thấy danh mục.' });
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'UPDATE_IT_CATEGORY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: name, description: `Cập nhật danh mục CNTT [${name}].` });
        res.json({ success: true });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Tên danh mục đã tồn tại.' });
        console.error('❌ Lỗi cập nhật danh mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});
app.delete('/api/it/categories/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM it_categories WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy danh mục.' });
        const [used] = await pool.query('SELECT COUNT(*) AS cnt FROM it_items WHERE category_id = ?', [id]);
        if (used[0].cnt > 0) return res.status(400).json({ error: 'Không thể xóa — danh mục này vẫn còn đầu mục đang theo dõi. Hãy xóa/chuyển các đầu mục đó trước.' });
        await pool.query('DELETE FROM it_categories WHERE id = ?', [id]);
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'DELETE_IT_CATEGORY', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa danh mục CNTT [${rows[0].name}].` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa danh mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Đầu mục theo dõi gia hạn ---
async function validateItItemBody(body, { partial = false } = {}) {
    const out = {};
    if (!partial || body.name !== undefined) {
        out.name = String((body && body.name) || '').trim();
        if (!out.name) return { error: 'Tên đầu mục không được để trống.' };
    }
    if (!partial || body.categoryId !== undefined) {
        const categoryId = Number(body && body.categoryId);
        if (!Number.isInteger(categoryId) || categoryId <= 0) return { error: 'Vui lòng chọn Danh mục.' };
        const [cat] = await pool.query('SELECT id FROM it_categories WHERE id = ?', [categoryId]);
        if (!cat[0]) return { error: 'Danh mục không tồn tại.' };
        out.categoryId = categoryId;
    }
    if (!partial || body.expiryDate !== undefined) {
        if (!validDateStr(body && body.expiryDate)) return { error: 'Ngày hết hạn không hợp lệ.' };
        out.expiryDate = body.expiryDate;
    }
    if (body && body.startDate !== undefined) {
        if (body.startDate && !validDateStr(body.startDate)) return { error: 'Ngày bắt đầu không hợp lệ.' };
        out.startDate = body.startDate || null;
    }
    if (body && body.provider !== undefined) out.provider = String(body.provider || '').trim() || null;
    if (body && body.description !== undefined) out.description = String(body.description || '').trim() || null;
    if (body && body.cost !== undefined) {
        if (body.cost === null || body.cost === '') {
            out.cost = null;
        } else {
            const cost = Number(body.cost);
            if (!Number.isFinite(cost) || cost < 0) return { error: 'Chi phí không hợp lệ.' };
            out.cost = cost;
        }
    }
    if (body && body.ownerUserId !== undefined) {
        if (body.ownerUserId === null || body.ownerUserId === '') {
            out.ownerUserId = null;
        } else {
            const ownerUserId = Number(body.ownerUserId);
            const [u] = await pool.query('SELECT id FROM users WHERE id = ?', [ownerUserId]);
            if (!u[0]) return { error: 'Người phụ trách (tài khoản hệ thống) không tồn tại.' };
            out.ownerUserId = ownerUserId;
        }
    }
    if (body && body.ownerEmail !== undefined) {
        const ownerEmail = String(body.ownerEmail || '').trim();
        if (ownerEmail && !EMAIL_RE.test(ownerEmail)) return { error: 'Email người phụ trách không hợp lệ.' };
        out.ownerEmail = ownerEmail || null;
    }
    if (body && body.active !== undefined) out.active = !!body.active;
    return { value: out };
}

app.post('/api/it/items', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { error, value } = await validateItItemBody(req.body || {});
        if (error) return res.status(400).json({ error });
        const nowIso = new Date().toISOString();
        const [result] = await pool.query(
            `INSERT INTO it_items (category_id, name, provider, description, start_date, expiry_date, cost, owner_user_id, owner_email, active, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, TRUE, ?, ?, ?)`,
            [value.categoryId, value.name, value.provider || null, value.description || null, value.startDate || null, value.expiryDate, value.cost === undefined ? null : value.cost, value.ownerUserId === undefined ? null : value.ownerUserId, value.ownerEmail || null, req.user.username, nowIso, nowIso]
        );
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'CREATE_IT_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: value.name, description: `Thêm đầu mục CNTT [${value.name}], hạn ${value.expiryDate}.` });
        res.json({ success: true, id: result.insertId });
    } catch (err) {
        console.error('❌ Lỗi thêm đầu mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});
app.put('/api/it/items/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT * FROM it_items WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đầu mục.' });
        const { error, value } = await validateItItemBody(req.body || {});
        if (error) return res.status(400).json({ error });
        await pool.query(
            `UPDATE it_items SET category_id = ?, name = ?, provider = ?, description = ?, start_date = ?, expiry_date = ?, cost = ?, owner_user_id = ?, owner_email = ?, active = ?, updated_at = ? WHERE id = ?`,
            [value.categoryId, value.name, value.provider || null, value.description || null, value.startDate || null, value.expiryDate, value.cost === undefined ? null : value.cost, value.ownerUserId === undefined ? null : value.ownerUserId, value.ownerEmail || null, value.active === undefined ? true : value.active, new Date().toISOString(), id]
        );
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'UPDATE_IT_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: value.name, description: `Cập nhật đầu mục CNTT [${value.name}], hạn ${value.expiryDate}.` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi cập nhật đầu mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});
app.delete('/api/it/items/:id', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await pool.query('SELECT name FROM it_items WHERE id = ?', [id]);
        if (!rows[0]) return res.status(404).json({ error: 'Không tìm thấy đầu mục.' });
        await pool.query('DELETE FROM it_reminder_sent WHERE item_id = ?', [id]);
        await pool.query('DELETE FROM it_items WHERE id = ?', [id]);
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'DELETE_IT_ITEM', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: rows[0].name, description: `Xóa đầu mục CNTT [${rows[0].name}].` });
        res.json({ success: true });
    } catch (err) {
        console.error('❌ Lỗi xóa đầu mục CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Cấu hình mốc nhắc hẹn (dùng chung cho toàn bộ đầu mục) ---
app.put('/api/it/reminder-config', requireAuth, requireAdmin, async (req, res) => {
    try {
        const enabled = req.body && req.body.enabled !== undefined ? !!req.body.enabled : true;
        const daysBeforeListRaw = Array.isArray(req.body && req.body.daysBeforeList) ? req.body.daysBeforeList : [];
        const daysBeforeList = daysBeforeListRaw.map(Number);
        if (!daysBeforeList.length || daysBeforeList.some(n => !Number.isInteger(n) || n < 1 || n > 365)) {
            return res.status(400).json({ error: 'Danh sách mốc nhắc phải có ít nhất 1 mốc, mỗi mốc là số nguyên từ 1 đến 365 ngày.' });
        }
        const value = { enabled, daysBeforeList: [...new Set(daysBeforeList)].sort((a, b) => b - a) };
        await pool.query(
            'INSERT INTO app_configs (config_key, config_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE config_value = ?',
            ['itReminderConfig', JSON.stringify(value), JSON.stringify(value)]
        );
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'UPDATE_IT_REMINDER_CONFIG', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: 'Cấu hình nhắc hẹn', description: `Cập nhật cấu hình nhắc hẹn CNTT: ${enabled ? 'bật' : 'tắt'}, mốc [${value.daysBeforeList.join(', ')}] ngày.` });
        res.json({ success: true, reminderConfig: value });
    } catch (err) {
        console.error('❌ Lỗi cập nhật cấu hình nhắc hẹn CNTT:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

// --- Kích hoạt kiểm tra & gửi nhắc ngay (thủ công, giống nút "Đồng bộ AD ngay") ---
app.post('/api/it/check-expiry-now', requireAuth, requireAdmin, async (req, res) => {
    try {
        const result = await runExpiryReminderCheck();
        await setItExpiryLastCheckAt();
        await writeAuditLog({ module: 'IT_ASSETS', actionType: 'CHECK_EXPIRY_NOW', status: 'SUCCESS', username: req.user.username, fullName: req.user.name, ip: req.ip, targetObject: 'Kiểm tra hạn CNTT', description: `Kiểm tra thủ công: ${result.checked} đầu mục, ${result.sent} email nhắc đã gửi.` });
        res.json({ success: true, ...result });
    } catch (err) {
        console.error('❌ Lỗi kiểm tra hạn CNTT thủ công:', err.message);
        res.status(500).json({ error: 'Đã xảy ra lỗi hệ thống, vui lòng thử lại sau.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:${PORT}`);
});
