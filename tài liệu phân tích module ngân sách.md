# Tài liệu Phân tích & Triển khai — Module Quản lý Ngân sách (Ngân sách 2.0)

> Tài liệu này mô tả chi tiết thiết kế, dữ liệu và luồng nghiệp vụ của module
> **Quản lý Ngân sách** (mục 💵 riêng trên sidebar, code gọi là "Ngân sách 2"
> để phân biệt với tính năng Ngân sách nằm bên trong module Bản quyền — xem
> mục 0 bên dưới). Đối tượng đọc: người kế thừa/bảo trì mã nguồn, hoặc người
> cần hiểu đúng nghiệp vụ trước khi thay đổi module này.

---

## 0. Phân biệt với "Ngân sách" trong module Bản quyền

Hệ thống có **2 khái niệm "ngân sách" độc lập**, dễ nhầm lẫn:

| | Ngân sách (trong License) | **Ngân sách 2.0 (module này)** |
|---|---|---|
| Vị trí | Bản quyền → Kỳ ngân sách | Sidebar riêng "💵 Quản lý Ngân sách" |
| Bảng dữ liệu | `lic_budget_rounds`, `lic_budget_round_items`, `lic_budget_registrations`, `lic_budget_actuals` | `budget2_lines` (1 bảng duy nhất) |
| Gắn với | Kỳ mua bản quyền phần mềm cụ thể | Độc lập, không gắn kỳ mua nào |
| Quyền truy cập | `admin` hoặc `licenseManager` | `admin` hoặc `budgetManager` |
| Luồng | Dự trù (đăng ký) → Mua thực tế (ghi nhận riêng) | Đề xuất → Phê duyệt → Sử dụng (3 giai đoạn tuần tự) |

Tài liệu này **chỉ nói về Ngân sách 2.0**. Hai module dùng chung danh mục
Công ty/Đơn vị (`lic_companies`/`lic_org_units`) nhưng hoàn toàn không chia
sẻ bảng dữ liệu nghiệp vụ nào khác.

---

## 1. Nguyên tắc thiết kế cốt lõi

Module đã trải qua 1 lần **thiết kế lại toàn diện** (PR #67, v6.64) theo
đúng yêu cầu nghiệp vụ, thay thế thiết kế cũ (Đề xuất "gửi sang" Phê duyệt
tạo bản sao). Các nguyên tắc chi phối toàn bộ module hiện tại:

1. **3 giai đoạn hoàn toàn ĐỘC LẬP.** Đề xuất, Phê duyệt, Sử dụng là 3 luồng
   dữ liệu tách biệt — không có chuyện dữ liệu tự "chảy" từ giai đoạn này
   sang giai đoạn khác trừ đúng 1 điểm nối duy nhất: **duyệt 1 dòng Phê
   duyệt → tự sinh đúng 1 dòng Sử dụng**. Đề xuất dù được duyệt/từ chối vẫn
   ở lại tab Đề xuất vĩnh viễn, không tạo bản sao, không đẩy sang Phê duyệt.
2. **Khóa cứng dữ liệu theo chuỗi kế thừa (Zero-Trust).** Một khi dữ liệu đã
   "chốt" ở dòng gốc, các dòng sinh ra sau nó (Sử dụng ← Phê duyệt) không
   được phép ghi đè khác đi, **kể cả khi client cố tình gửi giá trị khác**
   — server luôn tự ghi đè bằng giá trị của dòng cha trước khi lưu, không
   tin dữ liệu client cho các trường này. Áp dụng cho: Nội dung, Mô tả,
   **Danh mục**.
3. **Tách 2 hệ phân loại khác nhau, không được nhầm:**
   - `budget_type` (OPEX/CAPEX) — phân loại **kế toán**.
   - `item_category` (Phần mềm/Phần cứng/Dịch vụ/Hệ thống) — phân loại
     **theo đối tượng mua/chi**, phục vụ báo cáo nhóm theo danh mục.
4. **Không ai tự duyệt/tự từ chối được thứ do chính mình tạo** — áp dụng ở
   mọi bước quyết định (duyệt/từ chối Đề xuất, duyệt/từ chối Phê duyệt).
5. **Ngân sách sử dụng** con số phải luôn đúng theo thời gian thực — mọi
   thao tác thêm/sửa/xóa mục con đều **tính lại ngay** trạng thái sử dụng
   của dòng cha, không có số liệu "đông cứng" sai.

---

## 2. Kiến trúc dữ liệu

Toàn bộ module dùng **1 bảng duy nhất** `budget2_lines`, phân biệt giai đoạn
bằng cột `stage`. Đây là lựa chọn có chủ đích: cho phép báo cáo tổng hợp
Đề xuất/Phê duyệt/Sử dụng bằng đúng 1 câu `GROUP BY` (xem mục 6).

```
budget2_lines
├─ id                   PK
├─ stage                ENUM('PROPOSED','APPROVED','USED')
├─ parent_id            NULL — CHỈ dùng cho quan hệ Sử dụng cha↔con
├─ source_line_id       NULL — CHỈ dùng để dòng Sử dụng cha trỏ về dòng
│                        Phê duyệt đã sinh ra nó (khác hẳn parent_id!)
├─ company_id, org_unit_id   NULL — phạm vi (tùy chọn), tham chiếu
│                        lic_companies / lic_org_units
├─ content, description      Nội dung/Mô tả — khóa cứng khi kế thừa
├─ quantity, unit_price, vat_percent, total_amount
│                        total_amount tự tính = quantity × unit_price × (1+vat%)
├─ budget_type          ENUM('OPEX','CAPEX') — phân loại kế toán
├─ item_category        ENUM('SOFTWARE','HARDWARE','SERVICE','SYSTEM') NULL
│                        — Danh mục, bắt buộc ở dòng gốc, khóa cứng khi kế thừa
├─ usage_status         ENUM('NOT_USED','PARTIALLY_USED','USED') — CHỈ có ý
│                        nghĩa ở dòng cha Sử dụng, tự tính lại
├─ reallocation_reason  Lý do tái phân bổ — chỉ bắt buộc khi mục con Sử dụng
│                        khác Loại (OPEX/CAPEX) với mục cha
├─ status               ENUM('DRAFT','SUBMITTED','APPROVED','REJECTED')
├─ note                 Ghi chú tự do, không bắt buộc
├─ created_by, created_at, decided_by, decided_at
├─ budget_year, budget_month    Kỳ ngân sách — mục con Sử dụng kế thừa từ mục cha
└─ purchase_month       TINYINT NULL — CHỈ có ở mục con Sử dụng, là tháng
                         MUA THỰC TẾ (khác budget_month là tháng dự trù)
```

**Lưu ý quan trọng khi đọc mã nguồn:** `parent_id` và `source_line_id` là
**2 mối quan hệ khác nhau, dễ nhầm**:
- `parent_id`: mục con Sử dụng → dòng cha Sử dụng (cùng `stage='USED'`).
- `source_line_id`: dòng cha Sử dụng → dòng Phê duyệt đã sinh ra nó
  (`stage='APPROVED'`) — dùng khi cần "mở khóa" lại dòng Phê duyệt gốc lúc
  xóa dòng cha Sử dụng (xem mục 4.3).

Index: `stage`, `parent_id`, `source_line_id`, `company_id`, `org_unit_id`,
`budget_month`... `item_category` — đủ cho mọi truy vấn nhóm/lọc của báo cáo.

---

## 3. Luồng nghiệp vụ theo từng giai đoạn

### 3.1. Đề xuất (PROPOSED)

- Tạo tự do (`POST /api/budget2/lines`) hoặc nhập hàng loạt Excel.
- Bắt buộc: Nội dung, Số lượng, Đơn giá, Loại (OPEX/CAPEX), **Danh mục**,
  Năm + Tháng ngân sách. Công ty/Đơn vị/Ghi chú tùy chọn.
- Sửa/Xóa: chỉ khi `status = SUBMITTED` (chưa quyết định).
- **Duyệt/Từ chối ngay tại dòng này** (`POST .../approve-proposal`,
  `.../reject-proposal`) — chỉ đổi `status`, **KHÔNG tạo bản sao, KHÔNG đẩy
  sang tab Phê duyệt**. Sau khi quyết định, dòng khóa sửa/xóa, chỉ còn hiện
  "Đã xử lý bởi …".
- Không thể tự duyệt/tự từ chối đề xuất do chính mình tạo (403).

### 3.2. Phê duyệt (APPROVED)

Hoàn toàn độc lập với Đề xuất — **không** đọc dữ liệu từ Đề xuất sang.

- Tạo bằng nhập trực tiếp (`POST /api/budget2/lines/approved-direct`) hoặc
  Excel — luôn khởi tạo ở `status = SUBMITTED` (chờ duyệt), **không bao giờ
  tự động APPROVED**.
- Bắt buộc các trường giống Đề xuất (kể cả Danh mục).
- Duyệt (`POST .../approve`, chạy trong 1 transaction có `FOR UPDATE`
  chống race condition 2 người duyệt cùng lúc) → **tự động sinh đúng 1 dòng
  Sử dụng** (`stage='USED'`, `parent_id=NULL`, `source_line_id` = id dòng
  Phê duyệt này), sao chép nguyên vẹn: Nội dung, Mô tả, SL, Đơn giá, VAT,
  Thành tiền, Loại, **Danh mục**, Ghi chú, Công ty/Đơn vị, Năm/Tháng.
- Từ chối (`POST .../reject`) chỉ đổi `status`, không sinh gì thêm.
- Không thể tự duyệt/tự từ chối dòng do chính mình tạo (403).

### 3.3. Sử dụng (USED)

Có 2 loại dòng trong cùng giai đoạn này:

**Dòng cha** (`parent_id IS NULL`) — tự sinh khi duyệt 1 dòng Phê duyệt,
không tạo tay được. Người dùng chỉ có thể:
- **Sửa** (`PUT /api/budget2/lines/:id`): **CHỈ** Công ty/Đơn vị/Ghi chú —
  Nội dung/Mô tả/Số tiền/Loại/Danh mục **khóa cứng** theo dòng Phê duyệt
  gốc, kể cả khi client cố gửi giá trị khác server cũng bỏ qua.
- **Xóa**: chỉ khi **chưa có mục con nào**. Xóa xong, dòng Phê duyệt gốc
  (qua `source_line_id`) **tự động quay lại `status = SUBMITTED`**
  (`decided_by`/`decided_at` xóa) để có thể duyệt lại — dùng cho trường hợp
  lỡ duyệt nhầm.

**Mục con** (`parent_id` trỏ về dòng cha) — ghi nhận từng lần sử dụng thực
tế:
- Nội dung/Mô tả/**Danh mục** luôn khóa cứng, kế thừa nguyên văn từ dòng
  cha (không hiển thị ô nhập cho phép sửa, server cũng ghi đè nếu client cố
  gửi khác).
- **Tháng mua thực tế** (`purchase_month`, 1–12) **bắt buộc** — khác với
  `budget_month` (tháng dự trù kế thừa từ dòng cha), phục vụ báo cáo so
  sánh chính xác theo đúng thời điểm phát sinh mua.
- Nếu mục con chọn Loại (OPEX/CAPEX) **khác** dòng cha → bắt buộc nhập Lý
  do tái phân bổ.
- Thêm/sửa/xóa mục con đều gọi `recomputeBudget2ParentUsage()` — tính lại
  `usage_status` của dòng cha dựa trên `SUM(total_amount)` các mục con so
  với ngân sách được duyệt (`NOT_USED` / `PARTIALLY_USED` / `USED`).

---

## 4. Trường Danh mục (`item_category`) — bổ sung PR #70 (v6.71)

Trường phân loại **theo đối tượng mua/chi**, tách biệt hoàn toàn với
`budget_type` (OPEX/CAPEX vốn là phân loại kế toán):

| Mã | Nhãn hiển thị |
|---|---|
| `SOFTWARE` | Phần mềm |
| `HARDWARE` | Phần cứng |
| `SERVICE` | Dịch vụ |
| `SYSTEM` | Hệ thống |

- **Bắt buộc chọn** khi tạo dòng Đề xuất hoặc Phê duyệt (kể cả nhập Excel —
  file mẫu có thêm cột "Danh mục", chấp nhận cả nhãn tiếng Việt lẫn mã nội
  bộ, không phân biệt hoa/thường, qua hàm `normalizeBudget2ItemCategory()`).
- **Luôn kế thừa** xuống dòng Sử dụng (cả cha lẫn con) — không được chọn
  lại, đúng nguyên tắc khóa cứng ở mục 1.
- Dữ liệu tạo **trước** khi có cột này (`NULL`) hiển thị "—" (bảng) hoặc
  "(Chưa gán danh mục)" (báo cáo) — không lỗi, không chặn thao tác.
- Dùng cho báo cáo nhóm theo Danh mục — xem mục 6.

## 5. Trường Ghi chú (`note`)

Trường tự do, đã tồn tại sẵn trong dữ liệu (nhập được qua form) nhưng
**trước PR #70 không hiển thị ở bất kỳ bảng nào** — nay đã lên đủ cả 3 bảng
(Đề xuất, Phê duyệt, mục con Sử dụng). Không bắt buộc, không khóa cứng
(dòng cha Sử dụng vẫn sửa được Ghi chú riêng, không kế thừa).

---

## 6. Báo cáo (`GET /api/budget2/reports`)

Trả về cùng lúc nhiều "lát cắt" từ 1 lần gọi API, dựng từ hàm dùng chung
`buildDimension(groupCol)` — gộp Đề xuất/Phê duyệt/Sử dụng theo bất kỳ cột
nào truyền vào (Công ty, Đơn vị, hoặc `'1'` cho tổng toàn công ty):

| Khóa JSON | Nhóm theo | Ghi chú |
|---|---|---|
| `byCompany` | `company_id` | |
| `byOrgUnit` | `org_unit_id` | |
| `byCategory` | `item_category` | Thêm ở PR #70 — tái dùng nguyên `buildDimension()`, không cần endpoint riêng vì mọi dòng USED (kể cả mục con) đã có sẵn `item_category` kế thừa |
| `total` | gộp toàn công ty | |
| `variance` | — | Chênh lệch **Đã duyệt vs Đã dùng** cho từng dòng Phê duyệt đã APPROVED (join sang dòng Sử dụng cha + SUM mục con) |

Mỗi dòng dimension mang theo `budget_year`/`budget_month` riêng — cho phép
UI vừa lọc đúng 1 kỳ cụ thể ("Theo kỳ"), vừa dựng bảng pivot nhiều kỳ cạnh
nhau ("So sánh nhiều kỳ") từ **cùng một lần gọi API**, không cần gọi lại.
Lưu ý riêng cho tổng hợp: dòng `APPROVED` chỉ tính khi `status='APPROVED'`
(loại `SUBMITTED`/`REJECTED` khỏi số liệu); dòng `USED` chỉ tính mục con
(`parent_id IS NOT NULL`), không tính trùng dòng cha.

UI báo cáo còn có "4 lát cắt nhanh" dựng trực tiếp từ dữ liệu đã tải (không
gọi thêm API): (a) Sử dụng vs Phê duyệt năm hiện tại theo Công ty; (b)(c)(d)
Sử dụng/Phê duyệt/Đề xuất theo năm, so năm hiện tại với các năm trước.

---

## 7. Phân quyền & an toàn dữ liệu

- Toàn bộ endpoint yêu cầu `requireAuth` + `requireBudgetOrAdmin`
  (`perms.admin` hoặc `perms.budgetManager`).
- **Chặn tự duyệt/tự từ chối** (403, không phải lỗi dữ liệu 400) áp dụng ở
  4 điểm quyết định: duyệt Đề xuất, từ chối Đề xuất, duyệt Phê duyệt, từ
  chối Phê duyệt — so `created_by === req.user.username`.
- **Zero-Trust khóa cứng**: mọi endpoint tạo/sửa mục con hoặc dòng cha Sử
  dụng đều **ghi đè** `content`/`description`/`item_category` bằng giá trị
  đọc từ dòng cha/nguồn trước khi validate — không tin giá trị client gửi
  lên cho các trường này, dù có gửi lên cũng bị bỏ qua.
- Race condition khi duyệt: dùng transaction + `SELECT ... FOR UPDATE`
  trên dòng Phê duyệt, tránh 2 người cùng bấm Duyệt/Từ chối 1 lúc.

---

## 8. Danh sách API endpoint

| Method | Path | Chức năng |
|---|---|---|
| GET | `/api/budget2/bootstrap` | Toàn bộ dòng ngân sách + danh mục Công ty/Đơn vị |
| POST | `/api/budget2/lines` | Tạo dòng Đề xuất |
| PUT | `/api/budget2/lines/:id` | Sửa — nhánh xử lý khác nhau theo `stage` (PROPOSED/APPROVED/USED cha/USED con) |
| DELETE | `/api/budget2/lines/:id` | Xóa — nhánh xử lý khác nhau theo `stage`, riêng USED cha tự mở khóa lại dòng Phê duyệt gốc |
| POST | `/api/budget2/lines/:id/approve-proposal` | Duyệt Đề xuất tại chỗ (không sinh dòng mới) |
| POST | `/api/budget2/lines/:id/reject-proposal` | Từ chối Đề xuất tại chỗ |
| POST | `/api/budget2/lines/:id/approve` | Duyệt dòng Phê duyệt → tự sinh dòng Sử dụng |
| POST | `/api/budget2/lines/:id/reject` | Từ chối dòng Phê duyệt |
| POST | `/api/budget2/lines/approved-direct` | Nhập trực tiếp 1 dòng Phê duyệt (không qua Đề xuất) |
| POST | `/api/budget2/import` | Nhập hàng loạt Excel vào Đề xuất hoặc Phê duyệt |
| POST | `/api/budget2/lines/:id/children` | Thêm mục con Sử dụng dưới 1 dòng cha |
| GET | `/api/budget2/reports` | Báo cáo tổng hợp (xem mục 6) |

---

## 9. Nhập/Xuất Excel

- Cột nhập (`BUDGET2_XLSX_HEADER_LABELS`): Nội dung, Mô tả, Số lượng, Đơn
  giá, VAT (%), Loại (OPEX/CAPEX), **Danh mục** (nhãn tiếng Việt), Tháng/Năm
  ngân sách, Mã công ty, Đơn vị.
- Mã công ty + Tên đơn vị được tra ngược ra ID thật (không cần biết ID nội
  bộ) — báo lỗi rõ ràng theo từng dòng nếu không khớp.
- Xuất Excel (Đề xuất/Phê duyệt) có thêm cột Danh mục + Ghi chú, và cột
  Trạng thái riêng cho Phê duyệt.

---

## 10. Lịch sử phát triển liên quan (xem `version.md` để biết chi tiết PR)

| Version | Nội dung |
|---|---|
| v6.41 (PR #50) | Khởi tạo module (Đề xuất → Phê duyệt → Sử dụng) |
| v6.42 (PR #51) | Chỉ giai đoạn Phê duyệt cần bước duyệt/từ chối |
| v6.43 (PR #52) | Tách cột Công ty/Khối-Ban-Phòng riêng + Năm ngân sách |
| v6.48 (PR #57) | Thêm cột Tháng ngân sách |
| v6.57 (PR #63) | Optimistic concurrency, sửa race condition |
| **v6.64 (PR #67)** | **Thiết kế lại toàn diện**: 3 giai đoạn độc lập, bỏ "gửi sang duyệt", thêm Tháng mua thực tế, 4 lát cắt báo cáo nhanh |
| v6.69 (PR #69) | Sửa/Xóa dòng cha Sử dụng (chỉ Công ty/Đơn vị/Ghi chú, tự mở khóa dòng Phê duyệt gốc khi xóa) |
| **v6.71 (PR #70)** | Thêm cột **Ghi chú** hiển thị + cột **Danh mục**, báo cáo nhóm theo Danh mục |

---

## 11. Hạn chế đã biết / định hướng tiếp theo

- **Không sửa được Danh mục sau khi tạo dòng Đề xuất/Phê duyệt đã bị khóa**
  (chỉ sửa được khi còn `SUBMITTED`) — nếu chọn nhầm sau khi đã duyệt, phải
  xóa dòng Sử dụng (nếu chưa có mục con) để mở khóa lại dòng Phê duyệt gốc
  rồi mới sửa được.
- Chỉ hỗ trợ 1 loại tiền tệ (đơn vị tiền tệ hệ thống, không có multi-currency).
- Báo cáo `variance` (Phê duyệt vs Sử dụng) hiện chưa lọc theo Danh mục
  (chỉ báo cáo dimension chính có Danh mục) — có thể bổ sung nếu cần.
- Chưa có cơ chế nhắc hạn/thông báo tự động khi ngân sách Sử dụng gần chạm
  mức được duyệt (mới chỉ hiển thị trạng thái NOT_USED/PARTIALLY_USED/USED
  tĩnh, không có email/notification).
