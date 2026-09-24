// (PWA) Service worker "vỏ ứng dụng" (app-shell) — CHỈ cache tài nguyên tĩnh
// (JS/CSS/icon) để cài đặt được về màn hình chính + tải nhanh hơn ở lần sau,
// KHÔNG cache bất kỳ request /api/ nào. Đây là lựa chọn có chủ đích: DMS là hệ
// thống phê duyệt/ngân sách có tính đúng-thời-điểm cao (VD duyệt nhầm vì thấy
// số dư ngân sách cũ do cache) — an toàn hơn nhiều so với offline-first đầy đủ.
// Không có ứng dụng nào được thao tác khi mất mạng; chỉ vỏ giao diện tải nhanh
// hơn/cài được lên máy.
//
// CACHE_NAME đổi theo version mỗi lần build (do scripts/bump-version.js tự
// đồng bộ, giống cách nó đồng bộ CLIENT_BUILD_VERSION trong app.js) — trình
// duyệt tự phát hiện file sw.js đổi byte sau mỗi lần deploy, cài bản mới, và
// "activate" bên dưới tự xóa cache phiên bản cũ ngay, tránh vỏ ứng dụng bị kẹt
// ở bản cũ giống lỗi app.min.js quên rebuild trước đây (xem Đợt 7).
const CACHE_NAME = 'dms-shell-v7.30.0';
const SHELL_ASSETS = ['/', '/app.min.js', '/style.css', '/vendor/exceljs.min.js', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  // KHÔNG BAO GIỜ cache /api/* — luôn phải lấy dữ liệu mới nhất trực tiếp từ
  // server, để tránh duyệt/thao tác nhầm theo số liệu cũ.
  if (url.pathname.startsWith('/api/')) return;
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req).then((res) => {
        if (res && res.ok) {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
        }
        return res;
      }).catch(() => cached);
      return cached || network;
    })
  );
});
