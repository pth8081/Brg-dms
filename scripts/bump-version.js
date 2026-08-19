// Tự động tăng phiên bản ứng dụng: mỗi lần chạy tăng số "minor" thêm 1
// (v6.0 -> v6.1 -> v6.2...), giữ nguyên "major" và luôn đặt "patch" về 0.
// Cập nhật cả package.json lẫn chuỗi hiển thị "DMS vX.Y" trong public/index.html.
const fs = require('fs');
const path = require('path');

const pkgPath = path.join(__dirname, '..', 'package.json');
const htmlPath = path.join(__dirname, '..', 'public', 'index.html');

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const [major, minor] = pkg.version.split('.').map(Number);
const oldLabel = `v${major}.${minor}`;
const newMinor = minor + 1;
const newVersion = `${major}.${newMinor}.0`;
const newLabel = `v${major}.${newMinor}`;

pkg.version = newVersion;
fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');

let html = fs.readFileSync(htmlPath, 'utf8');
html = html.split(`DMS ${oldLabel}`).join(`DMS ${newLabel}`);
fs.writeFileSync(htmlPath, html);

console.log(`Đã tăng phiên bản: ${oldLabel} -> ${newLabel} (package.json: ${newVersion})`);
