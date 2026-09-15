// Tự động tăng phiên bản ứng dụng: mỗi lần chạy tăng số "minor" thêm 1
// (v6.0 -> v6.1 -> v6.2...), giữ nguyên "major" và luôn đặt "patch" về 0.
// Cập nhật cả package.json lẫn chuỗi hiển thị "DMS vX.Y" trong public/index.html.
const fs = require('fs');
const path = require('path');

const pkgPath = path.join(__dirname, '..', 'package.json');
const htmlPath = path.join(__dirname, '..', 'public', 'index.html');
const appJsPath = path.join(__dirname, '..', 'public', 'app.js');
const swJsPath = path.join(__dirname, '..', 'public', 'sw.js');

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const [major, minor] = pkg.version.split('.').map(Number);
const newMinor = minor + 1;
const newVersion = `${major}.${newMinor}.0`;
const newLabel = `v${major}.${newMinor}`;

pkg.version = newVersion;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');

let html = fs.readFileSync(htmlPath, 'utf8');
// Khớp theo REGEX bất kỳ nhãn "DMS vX.Y" nào đang có trong file — không chỉ
// đúng nhãn cũ tính từ package.json — để tự sửa lại kể cả khi 1 nhánh tính
// năng merge vào mang theo nhãn cũ/lệch (đã từng khiến nhãn bị kẹt ở v6.0
// trong khi package.json đã lên tới 6.6.0).
html = html.replace(/DMS v\d+\.\d+/g, `DMS ${newLabel}`);
fs.writeFileSync(htmlPath, html);

// (BUILD-VERSION) Đồng bộ CLIENT_BUILD_VERSION trong public/app.js với
// package.json — dùng để client tự phát hiện lệch phiên bản với server (xem
// checkClientBuildVersion() trong app.js) khi bundle build sẵn
// (public/app.min.js) bị quên rebuild trước khi deploy. Workflow CI đã tự
// chạy `npm run build` SAU bước này nên app.min.js luôn khớp giá trị mới.
let appJs = fs.readFileSync(appJsPath, 'utf8');
appJs = appJs.replace(/const CLIENT_BUILD_VERSION = '[^']*'/, `const CLIENT_BUILD_VERSION = '${newVersion}'`);
fs.writeFileSync(appJsPath, appJs);

// (PWA) Đồng bộ CACHE_NAME trong public/sw.js với version mới — bắt buộc để
// trình duyệt luôn phát hiện service worker "đổi byte" sau mỗi lần deploy và
// tự cài bản mới + xóa cache vỏ ứng dụng cũ (xem "activate" trong sw.js),
// tránh PWA bị kẹt vỏ ứng dụng ở bản cũ giống lỗi app.min.js quên rebuild
// trước đây (Đợt 7).
if (fs.existsSync(swJsPath)) {
    let swJs = fs.readFileSync(swJsPath, 'utf8');
    swJs = swJs.replace(/const CACHE_NAME = 'dms-shell-v[^']*'/, `const CACHE_NAME = 'dms-shell-v${newVersion}'`);
    fs.writeFileSync(swJsPath, swJs);
}

console.log(`Đã tăng phiên bản: -> ${newLabel} (package.json: ${newVersion})`);
