# Tài liệu Nghiệp vụ — Hệ thống DMS Production

> Tài liệu này mô tả **toàn bộ nghiệp vụ hiện tại** của ứng dụng DMS (Document
> Management System), dựa trên đúng hành vi đang triển khai trong mã nguồn
> (`server.js`, `public/app.js`, `schema.sql`) tại thời điểm biên soạn. Đây là
> tài liệu tham khảo nghiệp vụ (mô tả module/luồng/quy tắc), khác với file
> Excel test case (liệt kê bước kiểm thử) đã cung cấp trước đó.
>
> Cập nhật lần cuối: 2026-09-13, sau khi hoàn tất Đợt 4 (sửa lỗi Low + các
> lỗi phát hiện qua kiểm thử nghiệp vụ chuyên sâu).

---

## 1. Giới thiệu chung

DMS là hệ thống nội bộ phục vụ 3 nhóm nghiệp vụ chính, dùng chung một nền
tảng xác thực/phân quyền:

1. **Quản lý tài liệu** (Docs) — số hóa quy trình tạo, duyệt nhiều bước, lưu
   trữ và tra cứu văn bản/tài liệu nội bộ theo phòng ban.
2. **Quản lý Bản quyền phần mềm** (License) — theo dõi công ty/đơn vị/nhân
   viên, danh mục phần mềm, mua sắm (kỳ mua), phát hành mã license, và phân
   bổ license cho từng nhân viên.
3. **Quản lý Ngân sách** (Budget, 2 module song song) — dự trù, phê duyệt và
   theo dõi sử dụng ngân sách mua sắm CNTT (phần mềm/phần cứng/dịch vụ).

Ngoài ra có module **CNTT (IT Assets)** theo dõi hạn dùng dịch vụ/tài sản CNTT
kèm nhắc hẹn tự động qua email, module **Báo cáo** tổng hợp số liệu, và module
**Quản trị & Bảo mật** làm nền cho toàn bộ hệ thống.

Kiến trúc: Node.js/Express phục vụ API JSON, MariaDB/MySQL lưu trữ dữ liệu,
giao diện là trang đơn (SPA) `public/index.html` + `public/app.js`. Xác thực
qua JWT lưu trong cookie `httpOnly`.

---

## 2. Vai trò & Phân quyền

Không có bảng "vai trò" cố định — mỗi tài khoản (`users`) có 1 object `perms`
linh hoạt, kết hợp nhiều quyền độc lập:

| Quyền (`perms.*`) | Ý nghĩa |
|---|---|
| `admin` | Toàn quyền hệ thống — bỏ qua mọi kiểm tra quyền khác. |
| `uploadAll` / `uploadDepts[]` | Được tải lên tài liệu cho tất cả / các phòng ban chỉ định. |
| `viewDraftAll` / `viewDraftDepts[]` | Được xem tài liệu **chưa duyệt xong** (PENDING/REJECTED) của tất cả / phòng ban chỉ định. |
| `viewApprovedAll` / `viewApprovedDepts[]` | Được xem tài liệu **đã duyệt** (APPROVED) của tất cả / phòng ban chỉ định. |
| `downloadAll` / `downloadDepts[]` | Được tải file PDF của tất cả / phòng ban chỉ định (tách riêng khỏi quyền Xem). |
| `licenseManager` | Toàn quyền thao tác module Bản quyền + phần lớn module Ngân sách (theo Kỳ mua). |
| `budgetManager` | Toàn quyền thao tác module Ngân sách 2 (Đề xuất/Phê duyệt/Sử dụng). |
| `licenseScopeType` + `licenseScopeId` | Phạm vi tự phục vụ (COMPANY hoặc ORG_UNIT) — cho tài khoản không phải Admin/License Manager vẫn được dự trù ngân sách/đăng ký mua **trong đúng phạm vi công ty/đơn vị** được gán. |

Người tạo tài liệu/nhân viên/tài khoản luôn tự động có quyền xem tài liệu do
chính mình tạo (dù không có quyền `viewDraft*`/`viewApproved*` tương ứng).

Người tự tạo 1 yêu cầu (đăng ký mua, dự trù ngân sách, yêu cầu cấp phát hàng
loạt, dòng ngân sách chờ duyệt...) **không bao giờ được tự duyệt/tự từ chối
chính yêu cầu đó** — luôn cần một người khác có quyền tương ứng thực hiện.
Đây là quy tắc "tách biệt nhiệm vụ" (segregation of duties) áp dụng nhất
quán trên toàn hệ thống.

---

## 3. Module Tài liệu (Docs)

### 3.1. Tải lên tài liệu

- Mỗi tài liệu thuộc 1 **Phòng ban** và 1 **Phân loại** — cả hai đều có
  **Viết tắt** (abbr, chỉ chữ/số, duy nhất) dùng để tự sinh mã tài liệu dạng
  `BRG-{PhòngBan}-{PhânLoại}-{STT 3 chữ số}` (VD `BRG-IT-QT-001`). STT tính
  theo số hậu tố **lớn nhất đang tồn tại** trong các mã cùng tiền tố (không
  phải đếm số lượng) — để xóa vĩnh viễn 1 tài liệu ở giữa dãy không làm mã
  mới bị sinh trùng.
- File phải là PDF thật (kiểm tra cả đuôi file lẫn magic byte đầu file),
  giới hạn dung lượng theo cấu hình (`MAX_PDF_SIZE_MB`). Mọi PDF được **đóng
  dấu bản quyền (watermark) tự động** trước khi lưu ra đĩa.
- Tài liệu mới luôn khởi tạo ở trạng thái **PENDING**, bước duyệt 1, phiên
  bản `v1.0`.

### 3.2. Cập nhật phiên bản (Update version)

- Nộp phiên bản mới cho 1 nhóm tài liệu (`doc_group_id`) đã có: mã tài liệu
  giữ nguyên, `version_no` tăng thêm 1, kế thừa Phòng ban/Phân loại/Tiêu đề
  của bản mới nhất, quay lại PENDING bước 1.
- Không cho nộp phiên bản mới nếu nhóm đang có 1 bản **PENDING** (chưa xử lý
  xong). Nếu 2 người cùng nộp gần như đồng thời, người thứ 2 nhận lỗi 409 rõ
  ràng ("đã có người khác vừa nộp phiên bản mới hơn") thay vì lỗi hệ thống.

### 3.3. Quy trình duyệt (Workflow)

- Mỗi Phòng ban được gán **1 mẫu quy trình** (`workflows`, 1–5 bước, mỗi
  bước có 1 người duyệt cụ thể theo `deptWorkflows[tênPhòngBan].approvers`).
  Người duyệt phải là 1 tài khoản đang tồn tại và đang hoạt động (kiểm tra
  khi lưu cấu hình).
- Duyệt qua từng bước tuần tự: duyệt xong bước cuối → **APPROVED**. **Trả về
  (từ chối)** bắt buộc phải kèm lý do (không rỗng, ≤1000 ký tự) — kiểm tra cả
  ở giao diện lẫn ở server.
- Server luôn **tự tính lại** trạng thái/bước kế tiếp đúng theo quy trình đã
  cấu hình, không tin trạng thái do client tự gửi lên (chống giả mạo duyệt).
- Admin có thể **ghi đè (override)** quy trình để gỡ tài liệu bị kẹt, nhưng
  **không được sửa/xóa các mục lịch sử duyệt đã có** — chỉ được nối thêm
  đúng 1 mục mới (append-only).
- Sau khi duyệt xong 1 bước (chưa phải bước cuối), hệ thống **tự gửi email
  thật** cho người duyệt bước kế tiếp (người nhận do server tự tính từ trạng
  thái tài liệu, không nhận từ client). Chỉ người có quyền xem tài liệu đó
  mới gọi được hành động này (chặn dùng làm công cụ dội email/dò dữ liệu).

### 3.4. Xem / tải & Thùng rác

- Nội dung file **chỉ trả về khi thực sự bấm Xem/Tải** (không gửi kèm sẵn
  cho mọi tài liệu khi tải trang) — server luôn kiểm tra lại quyền theo đúng
  dòng dữ liệu (Zero Trust), và **ghi audit log ngay tại server** cho mỗi
  lần xem/tải, không phụ thuộc việc client có tự gửi log hay không.
- Xóa tài liệu là **xóa mềm** (Thùng rác, chỉ Admin) — khôi phục được. Xóa
  vĩnh viễn (Purge) mới xóa hẳn khỏi CSDL + file trên đĩa.

---

## 4. Module Quản trị & Bảo mật

### 4.1. Đăng nhập & phiên làm việc

- Đăng nhập yêu cầu **CAPTCHA ảnh (raster)** hợp lệ trước khi kiểm tra mật
  khẩu. Sai mật khẩu liên tiếp đủ **10 lần** → khóa tạm tài khoản 15 phút
  (tự hết hạn, không khóa vĩnh viễn).
- Nếu sai mật khẩu local **và** LDAP/AD đang bật, hệ thống thử xác thực qua
  LDAP (username phải đã tồn tại sẵn trong DMS, không tự tạo tài khoản mới).
- JWT mang theo `token_version` — **đổi mật khẩu** (tự đổi hoặc Admin đặt
  lại cho người khác) và **đăng xuất** đều tăng `token_version` của tài
  khoản, vô hiệu hóa NGAY mọi token cũ (kể cả chưa hết hạn 8h, kể cả bị đánh
  cắp trước đó). *Đánh đổi*: đăng xuất 1 thiết bị sẽ đăng xuất luôn các
  phiên khác của cùng tài khoản.
- Mật khẩu tối thiểu 8 ký tự, kết hợp ít nhất 2 trong 3 loại ký tự (chữ/số/
  đặc biệt).
- Để chống dò username qua thời gian phản hồi, khi username không tồn tại,
  server vẫn thực hiện 1 phép so sánh mật khẩu "giả" để thời gian phản hồi
  tương đương trường hợp có tài khoản thật.

### 4.2. Quản lý người dùng, Phòng ban, Phân loại

- Danh sách user được đồng bộ theo kiểu **thay thế toàn bộ** (xóa-chèn-lại
  trong 1 transaction) — luôn phải còn **ít nhất 1 tài khoản Admin đang hoạt
  động** trong payload, không cho tự khóa chính tài khoản đang đăng nhập,
  không cho khóa tài khoản Admin gốc (`admin`).
- Đổi tên Phòng ban/Phân loại (giữ nguyên id) tự động cập nhật lại mọi nơi
  đang tham chiếu tên cũ (tài liệu, phân quyền user, cấu hình quy trình).
  Không cho xóa Phòng ban/Phân loại còn tài liệu/quyền user gắn với nó.

### 4.3. LDAP/Active Directory

- **Đăng nhập qua LDAP**: chỉ kiểu Direct Bind (ghép username + domain),
  không tạo tài khoản mới.
- **Đồng bộ tài khoản AD** (module riêng, độc lập với đăng nhập): dùng tài
  khoản dịch vụ (service bind DN + search base) để đồng bộ danh sách tài
  khoản AD vào bảng riêng (`ad_accounts`), hỗ trợ phân trang tìm kiếm LDAP
  để tránh lỗi giới hạn kết quả trả về. Tài khoản không còn thấy trong AD sẽ
  tự động bị đánh dấu `active=false` — dùng để **đối chiếu** với nhân viên
  trong module License (cảnh báo nhân viên có email khớp tài khoản AD đã bị
  khóa, gợi ý rà soát thu hồi license). Có lịch tự động chạy hàng ngày.

### 4.4. Cấu hình Email (SMTP) & Log hệ thống

- Cấu hình SMTP thật (host/port/bảo mật/tài khoản/mật khẩu/người gửi) được
  validate khi lưu (host không rỗng, port 1–65535, email người gửi đúng
  định dạng). Mật khẩu SMTP không bao giờ trả về client dạng thật.
- **System Logs** ghi lại mọi hành động quan trọng (đăng nhập/đăng xuất,
  xem/tải/xóa tài liệu, thao tác License/Ngân sách/CNTT, gửi email, đồng bộ
  AD...) kèm module/loại hành động/username/IP/mô tả — chỉ Admin xem được,
  và được ghi **ngay tại server** khi xử lý request (không phụ thuộc client).

### 4.5. Bảo mật hạ tầng

Rate limiting nhiều lớp (chung + riêng cho đăng nhập/CAPTCHA/ghi log/tải
lên/thông báo duyệt), header bảo mật (CSP script-src chỉ `'self'`, Cache-
Control: no-store cho mọi API, Permissions-Policy tắt camera/micro/định
vị/thanh toán/USB), middleware xử lý lỗi tập trung (luôn trả JSON nhất
quán), lưới an toàn cấp tiến trình (không sập cả server vì 1 lỗi bất ngờ).

---

## 5. Module Bản quyền (License)

Đây là module lớn và phức tạp nhất hệ thống. Vai trò truy cập: `admin` hoặc
`perms.licenseManager`.

### 5.1. Danh mục nền tảng

- **Công ty** (`lic_companies`): tên duy nhất, mã công ty (≤20 ký tự,
  chữ/số). Không xóa được nếu còn đơn vị/lô license/đăng ký mua.
- **Đơn vị tổ chức** (`lic_org_units`): cây N cấp (có đơn vị cha), thuộc 1
  công ty, có "Cấp" tùy chỉnh (Khối/Ban/Phòng...). Không đổi công ty/cha khi
  sửa (tránh vòng lặp) — muốn chuyển nhánh phải xóa/tạo lại. Không xóa được
  nếu còn đơn vị con/nhân viên/dự trù ngân sách gắn với nó.
- **Nhân viên** (`lic_employees`): thuộc 1 đơn vị. `(công ty, mã nhân viên)`
  là cặp định danh duy nhất (dùng để import CSV khớp cập nhật/tạo mới) —
  chặn trùng ngay khi thêm/sửa thủ công. Không xóa được nếu đang giữ
  license (phải thu hồi hết trước).
- **Danh mục phần mềm** (`lic_software_catalog`): tên duy nhất, mã, **Loại
  license** (`PERPETUAL` Vĩnh viễn / `TERM` Có thời hạn / `MAINTENANCE` Bảo
  trì), **Số người dùng chung tối đa** (`max_assignees` — hỗ trợ 1 mã license
  gán cho nhiều nhân viên), **Thời hạn mặc định** (tháng, tự gợi ý khi tạo
  hạng mục kỳ mua/ngân sách), cho phép/không cho phép chia sẻ liên công ty.

Nhập CSV/Excel hàng loạt cho Đơn vị tổ chức (theo cây, xử lý nhiều lượt để
ghép đúng cha-con dù thứ tự dòng bất kỳ) và Nhân viên (theo mã công ty + tên
đơn vị, khớp theo cặp company+employeeCode) — dòng lỗi báo rõ trong
`errors[]`, dòng hợp lệ vẫn được xử lý, toàn bộ bọc trong 1 transaction.

### 5.2. Kỳ mua bản quyền & Đăng ký mua

- **Kỳ mua** (`lic_purchase_rounds`) có 2 loại: **Gia hạn** (`RENEWAL`, dành
  cho phần mềm công ty đã có license — số lượng gợi ý = số đang dùng) và
  **Mua mới** (`NEW`, không ràng buộc theo số hiện có). Kỳ có thể giới hạn
  **Phạm vi** (1 Công ty hoặc 1 Đơn vị cụ thể, kèm cây con) — chỉ user có
  phạm vi tự phục vụ khớp mới thấy/đăng ký được.
- **Đăng ký mua** (company/đơn vị tự đăng ký nhu cầu qua Cổng tự phục vụ,
  hoặc Admin nhập hộ): dạng bảng nhiều dòng, mỗi dòng 1 phần mềm + số lượng
  yêu cầu. Chặn tạo trùng đăng ký PENDING cho cùng hạng mục (double-submit).
  Người tạo không tự duyệt được đăng ký của chính mình.

### 5.3. Phát hành license (Batch & Codes)

- Mỗi lô phát hành **bắt buộc gắn với 1 Đăng ký mua đã APPROVED** — không
  phát hành tùy ý ngoài luồng.
- Sinh mã theo **delta** (chênh lệch): chỉ sinh thêm đúng số mã còn thiếu so
  với số đã đăng ký (không sinh lại toàn bộ), mã sinh ngẫu nhiên không
  trùng. Toàn bộ mã hiện có được khóa (`SELECT...FOR UPDATE`) trước khi tính
  delta, tránh sinh sai/trùng khi 2 request phát hành chạy đồng thời.
- **Xóa 1 lô phát hành** chỉ xóa các mã MỚI được sinh trong lô đó —
  **không** hoàn tác việc gia hạn hạn dùng đã áp dụng lên các mã cũ trước
  đó trong cùng lượt phát hành (hành vi có chủ đích, được ghi rõ khi xác
  nhận xóa).

### 5.4. Phân bổ (Allocation) & Cấp phát hàng loạt

- Gán/hủy gán license cho nhân viên theo bảng nhiều dòng, hỗ trợ license đa
  gán (nhiều người dùng chung 1 mã, giới hạn bởi `max_assignees`). Khóa
  dòng mã license trước khi đếm số người đang dùng — chống vượt giới hạn
  khi 2 request gán đồng thời.
- **Cấp phát hàng loạt theo nhân sự**: tự động gán 1 phần mềm cho toàn bộ
  nhân viên trong công ty/1 đơn vị đang thiếu license đó; nếu thiếu mã, trả
  về danh sách nhân viên còn thiếu để mua thêm.
- **Cấp phát hàng loạt từ file Excel**: xem trước (đối chiếu tên/mã nhân
  viên với dữ liệu hiện có, cảnh báo cứng nếu tên không khớp mã) → tạo
  **Yêu cầu** chờ 1 người KHÁC duyệt. Khi duyệt: chặn trùng mã nhân viên
  mới trong cùng file, chặn trùng với nhân viên đã có trong công ty, và
  kiểm tra lại nhân viên đã khớp trước đó **còn tồn tại** (phòng trường hợp
  bị xóa trong lúc chờ duyệt).
- **Gia hạn/Thu hồi hàng loạt** (chọn theo mã đã gán): Gia hạn cập nhật hạn
  theo lô phát hành mới nhất của phần mềm đó; nếu phần mềm chưa từng có lô
  phát hành, dòng đó được báo rõ trong `skipped[]` kèm lý do thay vì âm
  thầm bỏ qua.

---

## 6. Module Ngân sách (Budget — gắn với Kỳ mua License)

Vai trò truy cập: `admin` hoặc `perms.licenseManager` (lưu ý: **không phải**
`budgetManager` — 2 quyền này tách biệt, xem mục 8).

- **Kỳ ngân sách** (`lic_budget_rounds`): tương tự Kỳ mua, có Năm ngân sách
  và Phạm vi (Công ty/Đơn vị) tùy chọn.
- **Hạng mục kỳ ngân sách** (`lic_budget_round_items`): mỗi hạng mục bắt
  buộc chọn **Loại** (SOFTWARE/HARDWARE/SERVICE/OTHER) và **CAPEX/OPEX**
  (không có mặc định ngầm). Hạng mục SOFTWARE tham chiếu trực tiếp danh mục
  phần mềm; hạng mục Phần cứng/Dịch vụ/Khác tham chiếu **Danh mục hạng mục
  ngân sách** (`lic_budget_item_catalog`, quản lý riêng). Có thể **sửa lại**
  CAPEX/OPEX/đơn giá/mô tả sau khi tạo, miễn kỳ còn mở và hạng mục **chưa**
  có dự trù/mua thực tế nào tham chiếu (nếu đã có, phải xóa dự trù/thực tế
  trước, hoặc không sửa được nữa).
- **Dự trù ngân sách** (`lic_budget_registrations`, Company/đơn vị tự đăng
  ký hoặc Admin nhập hộ): với hạng mục SOFTWARE, số lượng hiện có
  (`current_quantity`) tự gợi ý theo số license công ty/đơn vị đang dùng.
  Chặn tạo trùng dự trù PENDING cho cùng hạng mục+đơn vị bằng ràng buộc
  **UNIQUE cấp CSDL** thật (không chỉ kiểm tra ở tầng ứng dụng). Người tạo
  không tự duyệt được dự trù của chính mình.
- **Mua thực tế** (`lic_budget_actuals`): ghi nhận riêng, độc lập với dự
  trù, có thể gắn theo 1 Công ty cụ thể (tùy chọn) để so sánh Kế hoạch vs
  Thực tế theo từng công ty.
- **Báo cáo so sánh** (Dự trù đã duyệt vs Thực tế đã mua, theo CAPEX/OPEX
  và theo Công ty): chỉ tính đăng ký/dự trù đã **APPROVED**, loại bỏ
  PENDING/REJECTED khỏi số liệu.

---

## 7. Module Ngân sách 2 (Đề xuất → Phê duyệt → Sử dụng)

Vai trò truy cập: `admin` hoặc `perms.budgetManager` — **module độc lập**
với mục 6, dùng chung bảng `lic_companies`/`lic_org_units` để chọn phạm vi
nhưng có luồng và bảng dữ liệu riêng (`budget2_lines`).

Một dòng ngân sách đi qua tối đa 3 giai đoạn (`stage`):

1. **Đề xuất (PROPOSED)** — tạo tự do, sửa/xóa tự do khi còn ở giai đoạn
   này. Nội dung, số lượng, đơn giá, %VAT (tổng tiền tự tính =
   `quantity × unitPrice × (1+vat%)`), loại ngân sách CAPEX/OPEX, năm/tháng
   ngân sách.
2. **Phê duyệt (APPROVED, `status`: SUBMITTED/APPROVED/REJECTED)** — vào
   giai đoạn này bằng cách **gửi 1 Đề xuất sang chờ duyệt** (tạo dòng mới,
   giữ liên kết `source_line_id` về đề xuất gốc; đề xuất gốc sau đó không
   xóa được nữa) hoặc **nhập trực tiếp** (không qua Đề xuất). Duyệt/từ chối
   chỉ có ở giai đoạn này; người tạo không tự duyệt/tự từ chối được. Duyệt
   thành công **tự động sinh 1 dòng Sử dụng** tương ứng.
3. **Sử dụng (USED, `usage_status`: NOT_USED/PARTIALLY_USED/USED)** — dòng
   cha sinh ra sau khi duyệt; có thể thêm nhiều **mục con** ghi nhận từng
   lần sử dụng thực tế, tổng các mục con được tự tính lại vào dòng cha (kể
   cả khi xóa 1 mục con, số liệu dòng cha tính lại đúng, không bị "đông
   cứng" sai).

Nhập hàng loạt từ Excel vào giai đoạn Đề xuất **hoặc** thẳng vào Phê duyệt
(dùng mã công ty + tên đơn vị để tự tra ID) — dòng nhập ở giai đoạn Phê
duyệt vẫn ở trạng thái **chờ duyệt**, không tự động APPROVED hay tự sinh
dòng Sử dụng.

---

## 8. Module CNTT (IT Assets)

Vai trò truy cập: chỉ `admin`.

- **Danh mục & Đầu mục CNTT**: mỗi đầu mục thuộc 1 danh mục, có ngày hết
  hạn, người/email phụ trách. Xóa là **xóa mềm** (khôi phục được qua API,
  hiện chưa có màn hình riêng cho việc này trên giao diện).
- **Cấu hình nhắc hẹn**: khai báo các mốc số ngày trước hạn cần nhắc (VD
  30/15/7 ngày). Engine kiểm tra hết hạn (`check-expiry-now` hoặc lịch tự
  động hàng ngày) rà mọi đầu mục đang hoạt động:
  - Dùng cơ chế **"bắt kịp mốc bị bỏ lỡ"**: nếu số ngày còn lại ≤ 1 ngưỡng
    đã cấu hình thì gửi nhắc cho ngưỡng đó (không chỉ khớp chính xác 1 ngày)
    — tránh bỏ sót mốc khi server ngừng chạy đúng lúc hoặc cấu hình vừa bật
    lại. Do đó 1 đầu mục mới/lâu chưa quét có thể khớp **nhiều ngưỡng cùng
    lúc** trong 1 lượt quét → gửi nhiều email, nhưng **nội dung mỗi email
    luôn nêu đúng số ngày còn lại thực tế** tại thời điểm gửi (không dùng
    ngưỡng để mô tả), tránh nói sai sự thật.
  - Chống gửi trùng bằng cơ chế "giành quyền gửi trước" (`INSERT IGNORE`
    dựa trên khóa duy nhất `(item_id, expiry_date, days_before)`) — atomic
    ở tầng CSDL, an toàn khi 2 lượt quét chạy gần như đồng thời.
  - Người nhận: toàn bộ Admin đang hoạt động + người phụ trách đầu mục (nếu
    tài khoản đó còn hoạt động) + email phụ trách khai báo riêng (nếu có).
  - Gửi email thật qua SMTP đã cấu hình (nodemailer). Nếu SMTP đang tắt,
    ghi log bỏ qua thay vì báo lỗi.

---

## 9. Module Báo cáo

Vai trò truy cập: `admin`, `licenseManager`, hoặc `budgetManager` (mở rộng
từ chỉ-Admin ban đầu).

- **Báo cáo Tài liệu**: tổng hợp số lượng theo trạng thái/phòng ban/phân
  loại — chỉ tính **phiên bản mới nhất/đại diện** của mỗi nhóm tài liệu,
  không đếm trùng khi 1 tài liệu có nhiều phiên bản.
- **Báo cáo Bản quyền**: so sánh Dự trù (đã duyệt) vs Sử dụng thực tế theo
  CAPEX/OPEX và theo Công ty; mục **Kiểm soát** cảnh báo nhân viên có email
  khớp tài khoản AD đã bị vô hiệu hóa (gợi ý rà soát thu hồi license).

---

## 10. Nhật ký & Kiểm toán (Audit log)

Bảng `system_logs` ghi mọi hành động nhạy cảm ngay tại server (không phụ
thuộc client): đăng nhập/đăng xuất (thành công/thất bại), xem/tải/xóa/khôi
phục tài liệu, mọi thao tác tạo/sửa/xóa/duyệt trong License/Ngân sách/CNTT,
gửi email (thành công/thất bại/bỏ qua), đồng bộ AD, ghi đè quy trình bởi
Admin... Mỗi dòng gồm: thời điểm, người thực hiện, IP, module, loại hành
động, đối tượng tác động, mô tả, trạng thái. Chỉ Admin xem được, có phân
trang (bootstrap chỉ tải 300 dòng mới nhất).

---

## 11. Hạ tầng & Vận hành

- Hỗ trợ chạy **nhiều tiến trình** (cluster nội bộ qua `WEB_CONCURRENCY`,
  hoặc PM2 cluster ngoài) — các tác vụ nền định kỳ (đồng bộ AD, kiểm tra hết
  hạn CNTT) chỉ chạy ở đúng 1 tiến trình duy nhất để tránh trùng lặp.
- Nén response (gzip/brotli), phân trang cho mọi bảng danh sách dài, minify
  JS phía trình duyệt cho production, xuất dữ liệu ra Excel (có chống
  Formula Injection) thay vì CSV thô.
- Lưới an toàn cấp tiến trình (`uncaughtException`/`unhandledRejection`) +
  middleware xử lý lỗi tập trung, để 1 lỗi bất ngờ không làm sập toàn bộ
  server đang phục vụ nhiều người dùng.
- Triển khai khuyến nghị: chạy dưới `systemd` bằng tài khoản hệ thống riêng
  (không phải root), xem `DEPLOYMENT.md`.

---

## 12. Phụ lục — Quy ước chung

**Mã lỗi HTTP** (đã chuẩn hóa toàn hệ thống):
- `400` — lỗi dữ liệu đầu vào/vi phạm quy tắc nghiệp vụ (validate, ràng
  buộc trùng lặp, trạng thái không cho phép thao tác...).
- `403` — lỗi phân quyền (không đủ quyền, hoặc vi phạm quy tắc "không được
  tự duyệt/tự thực hiện hành động do chính mình tạo").
- `404` — không tìm thấy đối tượng.
- `409` — xung đột do 2 request chạy gần như đồng thời (đã có người khác
  xử lý xong trước).
- `429` — vượt giới hạn tốc độ (rate limit) hoặc tài khoản đang bị khóa tạm.

**Nguyên tắc thiết kế xuyên suốt**:
- *Zero Trust*: server luôn tự tính lại/kiểm tra lại quyền và trạng thái
  theo dữ liệu thật trong CSDL, không tin bất kỳ giá trị nào client tự gửi
  lên (trạng thái duyệt, quyền xem, số lượng hiện có...).
- *Tách biệt nhiệm vụ*: người tạo yêu cầu không bao giờ tự duyệt được chính
  yêu cầu đó.
- *Xóa mềm trước, xóa cứng sau*: các thao tác xóa dữ liệu quan trọng (tài
  liệu, đầu mục CNTT) đều qua xóa mềm trước, có đường khôi phục, xóa vĩnh
  viễn là bước riêng biệt và có chủ đích.
- *Chặn ở CSDL, không chỉ ở tầng ứng dụng*: các quy tắc "không được trùng"
  quan trọng (mã tài liệu, mã nhân viên trong công ty, dự trù PENDING trùng
  hạng mục, hạng mục kỳ ngân sách trùng phần mềm...) đều có ràng buộc UNIQUE
  thật ở CSDL đứng sau, không chỉ dựa vào kiểm tra SELECT-rồi-INSERT ở tầng
  ứng dụng (vốn có thể bị race condition khi nhiều request chạy đồng thời).
