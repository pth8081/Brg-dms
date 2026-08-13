const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
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
    connectionLimit: 20,
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

// --- API BOOTSTRAP (Lấy toàn bộ dữ liệu khởi tạo cho 4 Module) ---
app.get('/api/bootstrap', async (req, res) => {
    try {
        const [depts] = await pool.query('SELECT name FROM depts');
        const [cats] = await pool.query('SELECT name FROM cats');
        const [users] = await pool.query('SELECT * FROM users');
        const [docs] = await pool.query('SELECT * FROM docs ORDER BY id DESC');
        const [workflows] = await pool.query('SELECT * FROM workflows');
        const [configs] = await pool.query('SELECT * FROM app_configs');
        const [logs] = await pool.query('SELECT * FROM system_logs ORDER BY id DESC LIMIT 300');

        let configMap = {};
        configs.forEach(c => configMap[c.config_key] = c.config_value);

        res.json({
            depts: depts.map(d => d.name),
            cats: cats.map(c => c.name),
            users: users.map(u => ({ ...u, perms: typeof u.perms === 'string' ? JSON.parse(u.perms || '{}') : u.perms })),
            docs: docs.map(d => ({ ...d, history: typeof d.history === 'string' ? JSON.parse(d.history || '[]') : d.history })),
            workflows: workflows.map(w => ({ ...w, steps: typeof w.steps === 'string' ? JSON.parse(w.steps || '[]') : w.steps })),
            deptWorkflows: configMap.deptWorkflows || {},
            emailConfig: configMap.emailConfig || { enabled: true, smtpHost: 'smtp.gmail.com', smtpPort: 587, senderEmail: 'dms-noreply@company.com' },
            systemLogs: logs
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- API SYNC / LƯU DỮ LIỆU ĐỒNG BỘ ---
app.post('/api/sync/:table', async (req, res) => {
    const { table } = req.params;
    const data = req.body.data;
    try {
        if (table === 'docs') {
            await pool.query('DELETE FROM docs');
            for (let d of data) {
                await pool.query(
                    'INSERT INTO docs (id, code, title, ver, dept, cat, summary, file_name, file_type, file_data, created_by, creator_username, created_at, workflow_id, current_step_order, status, history) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    [d.id, d.code, d.title, d.ver, d.dept, d.cat, d.summary, d.fileName, d.fileType, d.fileData, d.createdBy, d.creatorUsername, d.createdAt, d.workflowId, d.currentStepOrder, d.status, JSON.stringify(d.history || [])]
                );
            }
        } else if (table === 'users') {
            await pool.query('DELETE FROM users');
            for (let u of data) {
                await pool.query(
                    'INSERT INTO users (id, username, pass, name, email, phone, dept, perms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    [u.id, u.username, u.pass, u.name, u.email, u.phone, u.dept, JSON.stringify(u.perms || {})]
                );
            }
        } else if (table === 'depts') {
            await pool.query('DELETE FROM depts');
            for (let d of data) {
                await pool.query('INSERT INTO depts (name) VALUES (?)', [d]);
            }
        } else if (table === 'cats') {
            await pool.query('DELETE FROM cats');
            for (let c of data) {
                await pool.query('INSERT INTO cats (name) VALUES (?)', [c]);
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
            await pool.query('DELETE FROM system_logs');
            for (let l of data) {
                await pool.query(
                    'INSERT INTO system_logs (id, timestamp, username, fullName, ipAddress, module, actionType, targetObject, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                    [l.id, l.timestamp, l.username, l.fullName, l.ipAddress, l.module, l.actionType, l.targetObject, l.description, l.status]
                );
            }
        }
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Máy chủ DMS Production đang chạy tại cổng http://localhost:${PORT}`);
});