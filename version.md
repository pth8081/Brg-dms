# Lịch sử phiên bản — DMS Production

File này ghi lại **mỗi lần tăng phiên bản** của ứng dụng (số phiên bản tự động
tăng bởi `.github/workflows/version-bump.yml` mỗi khi có merge vào `main`,
xem `scripts/bump-version.js`). Mỗi dòng tương ứng đúng 1 Pull Request đã merge.

Quy ước: **mới nhất ở trên cùng**. Từ nay, mỗi khi có PR mới được merge vào
`main`, thêm 1 dòng mới vào đầu bảng bên dưới với đúng số phiên bản mà CI
sinh ra sau merge, số PR, ngày merge, và mô tả ngắn gọn nội dung thay đổi.

## Nhật ký

| Phiên bản | PR | Ngày merge | Nội dung |
|---|---|---|---|
| v6.87 | [#78](https://github.com/pth8081/Brg-dms/pull/78) | 2026-09-15 | Sửa khẩn 2 lỗi khiến Admin bị kẹt hoàn toàn ở màn đăng ký/đăng nhập 2FA (PR #77): (1) otplib mặc định window:0 — không có dung sai thời gian nào, mã TOTP đúng vẫn bị từ chối nếu lệch đồng hồ vài giây hoặc thời gian đọc+gõ mã vượt ranh giới 30 giây, nay đặt window:1 (dung sai ~30-60 giây); (2) `.toast-stack` và `#loginSection` cùng z-index:100 khiến `#loginSection` (đứng sau trong DOM) vẽ đè lên mọi thông báo trong lúc đăng nhập — người dùng bấm nút nhưng không thấy phản hồi gì, nay nâng z-index toast lên 200 |
| v6.85 | [#77](https://github.com/pth8081/Brg-dms/pull/77) | 2026-09-15 | Thêm xác thực hai yếu tố (2FA/TOTP) bắt buộc riêng cho Admin: đăng nhập (mật khẩu lẫn vân tay/Face ID) — Admin chưa đăng ký bị bắt đăng ký ngay (QR code + mã nhập tay), đã đăng ký phải nhập đúng mã 6 số mỗi lần; Admin không tự gỡ được 2FA của chính mình, chỉ Admin khác gỡ hộ được (tài khoản bị gỡ phải đăng ký lại ngay lần đăng nhập kế tiếp); bí mật TOTP chỉ ghi DB sau khi xác minh đúng mã đầu tiên, không bao giờ lộ ra client; sửa kèm 1 lỗi phát hiện trong lúc làm — cơ chế lưu danh sách người dùng (xóa-chèn-lại toàn bảng) trước đây sẽ vô tình xóa sạch 2FA của mọi Admin khi sửa bất kỳ user nào, nay đã giữ nguyên |
| v6.83 | [#76](https://github.com/pth8081/Brg-dms/pull/76) | 2026-09-15 | Ngân sách Đề xuất/Phê duyệt: chọn nhiều dòng để Duyệt/Từ chối/Xóa hàng loạt; thêm Kiểm soát License tự động (job nền N lần/ngày, mặc định 8h/20h, đối chiếu tài khoản AD disable, tùy chọn tự động thu hồi — mặc định TẮT, chỉ cảnh báo email cho tới khi Admin bật — luôn gửi email báo cáo cho Admin + Người quản lý License, thêm bảng cấu hình + nút chạy thử ngay trong modal "Kiểm soát"); Tổ chức công ty thêm nút Xuất Excel; Danh mục HC/DV/Khác thêm tag tùy chọn "Danh mục hệ thống" (không thay trường Loại hiện có); Log hệ thống sửa bộ lọc phân hệ — thêm LICENSE/BUDGET2/IT_ASSETS (đã ghi log từ trước nhưng thiếu lọc), bỏ 2 giá trị chưa từng dùng |
| v6.81 | [#75](https://github.com/pth8081/Brg-dms/pull/75) | 2026-09-15 | Gộp Phòng ban, Phân loại tài liệu, Tổ chức công ty, Danh mục HC/DV/Khác vào 1 tab "🗂️ Quản Lý Danh Mục" trong Hệ thống (tách khỏi module License mang tính riêng tư); thêm Danh mục hệ thống (bảng budget2_item_categories) cho Admin tự thêm/sửa/ẩn/xóa thay vì 4 giá trị viết cứng, chặn xóa khi danh mục đang dùng; Ngân sách Đề xuất/Phê duyệt/Sử dụng thêm lọc theo năm/loại/danh mục/nội dung/khối phòng ban + group theo năm kèm phân trang + chọn nhiều dòng xóa hàng loạt (chỉ Admin); thêm biểu đồ báo cáo "Sử dụng vs Ngân sách phê duyệt theo Danh mục" |
| v6.79 | [#74](https://github.com/pth8081/Brg-dms/pull/74) | 2026-09-15 | Hệ thống: thêm sub-tab mới "📘 Quy Trình Nghiệp Vụ" — trang tĩnh chỉ xem/tham khảo (không cấu hình gì), khác hẳn tab sẵn có "Quy Trình & Luồng Duyệt" (dùng để cấu hình ai duyệt tài liệu theo phòng ban); gồm 3 sơ đồ SVG + giải thích cho quy trình License (Kỳ mua→Đăng ký mua→Duyệt/Từ chối→Phát hành→Phân bổ/Cấp phát→Gia hạn/Thu hồi), Ngân sách (Đề xuất và Phê duyệt là 2 luồng độc lập chỉ nối nhau ở điểm duyệt sinh dòng Sử dụng), và CNTT (đầu mục hết hạn→cấu hình ngưỡng→engine quét hằng ngày→gửi email 3 nhóm người nhận) |
| v6.77 | [#73](https://github.com/pth8081/Brg-dms/pull/73) | 2026-09-15 | Ngân sách: thêm nút Sửa/Xóa cho Đề xuất + Phê duyệt (trước chỉ hiện ở dòng chờ duyệt); Xóa (mọi trạng thái/giai đoạn) giờ chỉ Admin mới có quyền; Admin sửa/xóa được cả dòng đã duyệt/từ chối, Người quản lý Ngân sách chỉ thao tác được dòng chờ duyệt như cũ; sửa dòng Phê duyệt đã duyệt tự đồng bộ dòng Sử dụng tương ứng; xóa dòng đã duyệt cascade xóa kèm dòng Sử dụng nếu chưa có mục con, chặn nếu đã có mục con |
| v6.75 | [#72](https://github.com/pth8081/Brg-dms/pull/72) | 2026-09-15 | Đăng nhập: khi chip "tài khoản được nhớ" đang hiện, thông báo lỗi sai mật khẩu giờ nêu rõ đang thử tài khoản nào + nhắc bấm "Tài khoản khác" nếu không đúng — tránh gõ sai mật khẩu liên tục làm khóa tạm nhầm tài khoản; sửa 1 chỗ có thể throw im lặng (không hiện toast) nếu thiếu phần tử chip khi build thông báo lỗi |
| v6.73 | [#71](https://github.com/pth8081/Brg-dms/pull/71) | 2026-09-15 | Thêm tài liệu phân tích/triển khai module Quản lý Ngân sách; Sửa lỗi logout() vô tình xóa ô tên đăng nhập ngay sau khi điền sẵn tài khoản được nhớ; Đăng nhập giờ hiện chip "tài khoản được nhớ" (kiểu admin / Tài khoản khác) thay ô nhập username khi đã từng đăng nhập/đăng ký vân tay-Face ID thành công trên trình duyệt — chỉ đổi khi tự bấm Tài khoản khác hoặc đăng nhập thành công bằng tài khoản khác |
| v6.71 | [#70](https://github.com/pth8081/Brg-dms/pull/70) | 2026-09-15 | Sửa lỗi sidebar (z-50, menu kéo di động) đè lên màn hình đăng nhập sau khi đăng xuất ở độ rộng máy tính (dùng !hidden cho #appShell + nâng z-index màn hình đăng nhập); Ngân sách — thêm cột Ghi chú vào cả 3 bảng + cột Danh mục (Phần mềm/Phần cứng/Dịch vụ/Hệ thống) bắt buộc khi tạo Đề xuất/Phê duyệt (kể cả nhập Excel), luôn kế thừa xuống Sử dụng, thêm vào báo cáo nhóm theo; Làm gọn trang đăng nhập + đổi nội dung phản ánh đúng 3 mục đích hệ thống (Tài liệu/Bản quyền phần mềm/Dịch vụ CNTT) |
| v6.69 | [#69](https://github.com/pth8081/Brg-dms/pull/69) | 2026-09-15 | Ngân sách sử dụng: thêm Sửa (chỉ Công ty/Đơn vị/Ghi chú, khóa cứng phần còn lại theo dòng Phê duyệt gốc) + Xóa dòng cha (chỉ khi chưa có mục con, tự mở lại dòng Phê duyệt gốc về chờ duyệt); Đăng nhập vân tay/Face ID (WebAuthn/passkey) — lối vào nhanh bổ sung, không thay mật khẩu; Trang chủ thêm 3 thẻ module chính (Tài liệu/Bản quyền/CNTT); Chuyển ứng dụng thành PWA (manifest + icon + service worker chỉ cache vỏ tài nguyên tĩnh, không cache API) |
| v6.67 | [#68](https://github.com/pth8081/Brg-dms/pull/68) | 2026-09-14 | Menu kéo (drawer) cho di động thay thế sidebar tràn thành khối dài trên mọi màn hình (appShell trước đây thiếu cơ chế thu gọn dưới breakpoint md) + thêm liên kết tùy chọn depts.org_unit_id sang lic_org_units để đối chiếu/báo cáo chính xác khi tên phòng ban giữa 2 module lệch nhau, không gộp 2 danh mục |
| v6.64 | [#67](https://github.com/pth8081/Brg-dms/pull/67) | 2026-09-14 | Redesign module Ngân sách 2.0: Đề xuất — Duyệt/Từ chối chỉ đổi trạng thái tại chỗ, không tạo bản sao/không đẩy sang tab Phê duyệt; Phê duyệt — hoàn toàn độc lập, luôn nhập/upload trực tiếp, duyệt xong mới tự sinh dòng ở Sử dụng; Sử dụng — mục con khóa cứng Nội dung/Mô tả theo đúng dòng Phê duyệt gốc + bắt buộc Tháng mua; Báo cáo — thêm 4 lát cắt nhanh so sánh sử dụng/phê duyệt/đề xuất năm hiện tại vs quá khứ |
| v6.62 | [#66](https://github.com/pth8081/Brg-dms/pull/66) | 2026-09-14 | Sửa cảnh báo sai "Vui lòng chọn công ty/đơn vị cho phạm vi tự phục vụ!" khi lưu user không hề đụng tới mục Phạm vi tự phục vụ — resetUserForm() trước đây chỉ reset select loại phạm vi khi licenseDB.loaded, để sót giá trị cũ từ lần sửa user trước |
| v6.61 | [#65](https://github.com/pth8081/Brg-dms/pull/65) | 2026-09-14 | Đợt 7: Sửa lỗi nghiêm trọng — public/app.min.js (bundle JS production thật sự phục vụ) không được rebuild kể từ v6.48 dù mã nguồn đã qua 6 PR (bao gồm toàn bộ vá bảo mật Đợt 2 + cơ chế baseVersion Đợt 6), gây lỗi 400 ở mọi thao tác Lưu trong module Hệ thống; rebuild ngay bundle + workflow CI tự `npm run build` trên mọi lần merge từ nay + banner cảnh báo khi bundle trình duyệt lệch phiên bản server |
| v6.59 | [#64](https://github.com/pth8081/Brg-dms/pull/64) | 2026-09-14 | Thêm script dọn dẹp dữ liệu test (reset-test-data.js) — xóa toàn bộ tài liệu/License/Ngân sách 1+2/CNTT/Nhật ký hệ thống, chỉ giữ lại cấu hình hệ thống và danh mục nền tảng |
| v6.57 | [#63](https://github.com/pth8081/Brg-dms/pull/63) | 2026-09-13 | Đợt 5+6: Sửa 6 lỗi phát hiện qua kiểm thử chuyên sâu (race condition đăng ký mua License, lỗ hổng phạm vi tự phục vụ, bỏ qua đối chiếu tên khi duyệt cấp phát hàng loạt, lỗi ép kiểu mở khóa oan, quyền Báo cáo Tài liệu, bộ lọc công ty ở Báo cáo License) + thêm optimistic concurrency (sync_versions) cho các bảng đồng bộ toàn snapshot + phân trang thật cho System Logs |
| v6.54 | [#62](https://github.com/pth8081/Brg-dms/pull/62) | 2026-09-13 | Thêm tài liệu nghiệp vụ.md — mô tả toàn bộ nghiệp vụ ứng dụng (kiến trúc, vai trò/phân quyền, chi tiết từng module, quy ước mã lỗi HTTP + nguyên tắc thiết kế xuyên suốt) |
| v6.53 | [#61](https://github.com/pth8081/Brg-dms/pull/61) | 2026-09-13 | Đợt 3+4: Nâng cấp nodemailer v10 + vá CVE uuid; sửa toàn bộ ~16 lỗi Low (Docs/Admin/bảo mật toàn ứng dụng) + lỗi Low License + các lỗi phát hiện mới qua kiểm thử nghiệp vụ chuyên sâu trên server thật (race condition dự trù ngân sách, validate độ dài CNTT, nội dung email nhắc hạn sai sự thật) |
| v6.51 | [#60](https://github.com/pth8081/Brg-dms/pull/60) | 2026-09-11 | Đợt 2: Sửa toàn bộ ~29 lỗi Medium (thu hồi JWT khi đổi mật khẩu, xác thực lại mật khẩu hiện tại, ẩn systemLogs, transaction/FOR UPDATE cho License, soft-delete CNTT, chống race condition ngân sách, mở quyền báo cáo license) |
| v6.50 | [#59](https://github.com/pth8081/Brg-dms/pull/59) | 2026-09-11 | Sửa 6 lỗi bảo mật mức Cao: CAPTCHA raster, khóa tài khoản, lộ dữ liệu bootstrap, transaction sync users/workflows, chặn admin ghi đè lịch sử duyệt |
| v6.49 | [#58](https://github.com/pth8081/dms-prod/pull/58) | 2026-09-11 | Cập nhật version.md: thêm dòng v6.48 (PR #57) |
| v6.48 | [#57](https://github.com/pth8081/dms-prod/pull/57) | 2026-09-11 | Thêm cột Tháng ngân sách + Thu hồi theo nhân viên + Gán nhiều license cho 1 người |
| v6.47 | [#56](https://github.com/pth8081/dms-prod/pull/56) | 2026-09-11 | Cập nhật version.md: thêm dòng v6.46 (PR #55) |
| v6.46 | [#55](https://github.com/pth8081/dms-prod/pull/55) | 2026-09-11 | Tự động tra cứu AD khi nhập username + cập nhật version.md |
| v6.45 | [#54](https://github.com/pth8081/dms-prod/pull/54) | 2026-09-11 | Thêm CAPTCHA đăng nhập + xác thực AD khi tạo user + cập nhật version.md |
| v6.44 | [#53](https://github.com/pth8081/dms-prod/pull/53) | 2026-09-11 | Thêm version.md — nhật ký phiên bản đầy đủ + hướng dẫn cập nhật |
| v6.43 | [#52](https://github.com/pth8081/dms-prod/pull/52) | 2026-09-11 | Thêm cột Công ty/Khối-Ban-Phòng riêng biệt + Năm ngân sách + báo cáo theo năm |
| v6.42 | [#51](https://github.com/pth8081/dms-prod/pull/51) | 2026-09-09 | Chỉ giai đoạn Ngân sách phê duyệt mới cần bước duyệt/từ chối |
| v6.41 | [#50](https://github.com/pth8081/dms-prod/pull/50) | 2026-09-09 | Thêm module Quản lý Ngân sách (Đề xuất → Phê duyệt → Sử dụng) |
| v6.40 | [#49](https://github.com/pth8081/dms-prod/pull/49) | 2026-09-06 | Cluster nhiều worker + tài khoản hệ thống riêng + hướng dẫn triển khai production |
| v6.39 | [#48](https://github.com/pth8081/dms-prod/pull/48) | 2026-09-04 | Minify public/app.js phục vụ production |
| v6.38 | [#47](https://github.com/pth8081/dms-prod/pull/47) | 2026-09-04 | Kiểm tra đúng định dạng cột XLSX trước khi đọc, chặn đọc lệch cột |
| v6.37 | [#46](https://github.com/pth8081/dms-prod/pull/46) | 2026-09-04 | Cấp phát hàng loạt từ file: bắt buộc khớp đúng đơn vị đã chọn |
| v6.36 | [#45](https://github.com/pth8081/dms-prod/pull/45) | 2026-09-04 | Bật nén response (gzip/brotli) cho toàn bộ HTTP response |
| v6.35 | [#44](https://github.com/pth8081/dms-prod/pull/44) | 2026-09-03 | Chặn sai tên công ty/đơn vị khi cấp phát hàng loạt + thu hồi hàng loạt theo chọn nhiều |
| v6.34 | [#43](https://github.com/pth8081/dms-prod/pull/43) | 2026-09-02 | Tách JS ra file riêng + chuyển 315 sự kiện nội tuyến, thắt chặt CSP |
| v6.33 | [#42](https://github.com/pth8081/dms-prod/pull/42) | 2026-09-01 | Sửa 4 lỗi nghiêm trọng phát hiện qua kiểm toán nghiệp vụ + an ninh |
| v6.32 | [#41](https://github.com/pth8081/dms-prod/pull/41) | 2026-08-29 | Thêm trường Mô tả khi thêm hạng mục vào Kỳ ngân sách |
| v6.31 | [#40](https://github.com/pth8081/dms-prod/pull/40) | 2026-08-29 | Đổi module Quản trị thành Hệ thống, căn chỉnh sidebar, danh mục hạng mục ngân sách |
| v6.30 | [#39](https://github.com/pth8081/dms-prod/pull/39) | 2026-08-29 | Người quản lý License, cấp phát hàng loạt từ file, phân bổ bảng nhiều dòng, xóa Kỳ |
| v6.29 | [#38](https://github.com/pth8081/dms-prod/pull/38) | 2026-08-26 | Sidebar điều hướng trái + Trang chủ dashboard + License 1 hàng tab phẳng |
| v6.28 | [#37](https://github.com/pth8081/dms-prod/pull/37) | 2026-08-26 | Thêm module Quản lý CNTT: theo dõi hạn dịch vụ/bản quyền + email nhắc tự động |
| v6.27 | [#36](https://github.com/pth8081/dms-prod/pull/36) | 2026-08-26 | Thiết kế lại UI/UX: gọn nút/ô, top-nav License, accordion Kỳ mua/Ngân sách |
| v6.26 | [#35](https://github.com/pth8081/dms-prod/pull/35) | 2026-08-25 | Phân trang + bộ lọc cho các bảng danh sách, sửa lỗi nhập Excel hyperlink |
| v6.25 | [#34](https://github.com/pth8081/dms-prod/pull/34) | 2026-08-25 | Bật phân trang khi tìm kiếm LDAP để tránh lỗi sizeLimitExceeded (0x4) |
| v6.24 | [#33](https://github.com/pth8081/dms-prod/pull/33) | 2026-08-23 | Theo dõi ngân sách theo Công ty (Kế hoạch vs Thực tế) |
| v6.22 | [#32](https://github.com/pth8081/dms-prod/pull/32) | 2026-08-23 | CAPEX/OPEX cho hạng mục ngân sách + theo dõi mua thực tế |
| v6.20 | [#31](https://github.com/pth8081/dms-prod/pull/31) | 2026-08-23 | Kỳ mua 2 loại (Gia hạn/Mua mới) + Phát hành bắt buộc theo đăng ký đã duyệt |
| v6.18 | [#30](https://github.com/pth8081/dms-prod/pull/30) | 2026-08-23 | Phạm vi công ty/đơn vị cho Kỳ mua & Kỳ ngân sách + Cổng tự phục vụ |
| v6.16 | [#29](https://github.com/pth8081/dms-prod/pull/29) | 2026-08-23 | Fix: biểu đồ Ngân sách dự trù hiện rõ tên phần mềm thay vì trùng tên đơn vị |
| v6.15 | [#28](https://github.com/pth8081/dms-prod/pull/28) | 2026-08-23 | Fix: giữ nguyên lựa chọn Phần mềm trong modal Cấp phát hàng loạt theo nhân sự |
| v6.14 | [#27](https://github.com/pth8081/dms-prod/pull/27) | 2026-08-23 | Cấp phát license theo nhân sự + liên kết Kỳ mua với Kỳ ngân sách |
| v6.12 | [#26](https://github.com/pth8081/dms-prod/pull/26) | 2026-08-23 | Fix responsive di động + chuẩn hóa hệ màu nút/menu + CSV sang Excel |
| v6.11 | [#25](https://github.com/pth8081/dms-prod/pull/25) | 2026-08-23 | Đổi bcrypt sang bản gốc (native) để tránh chặn event loop |
| v6.10 | [#24](https://github.com/pth8081/dms-prod/pull/24) | 2026-08-23 | Chặn xóa nhân viên/đơn vị/phần mềm khi vẫn còn dữ liệu liên quan |
| v6.9 | [#23](https://github.com/pth8081/dms-prod/pull/23) | 2026-08-22 | Sắp xếp lại module Bản quyền theo nhóm + thêm module Báo cáo |
| v6.8 | [#22](https://github.com/pth8081/dms-prod/pull/22) | 2026-08-22 | Sửa 7 lỗi logic nghiệp vụ phát hiện qua rà soát toàn diện |
| v6.7 | [#21](https://github.com/pth8081/dms-prod/pull/21) | 2026-08-21 | Sửa script tự động tăng version bị kẹt nhãn hiển thị |
| v6.6 | [#20](https://github.com/pth8081/dms-prod/pull/20) | 2026-08-21 | License đa gán (dùng chung) + loại license Vĩnh viễn/Có thời hạn/Bảo trì |
| v6.5 | [#19](https://github.com/pth8081/dms-prod/pull/19) | 2026-08-21 | Bảng nhiều dòng cho Tạo kỳ mua và Đăng ký mua bản quyền |
| v6.4 | [#18](https://github.com/pth8081/dms-prod/pull/18) | 2026-08-21 | Sửa schema.sql tương thích MySQL chuẩn + script chuyển file cũ ra đĩa |
| v6.3 | [#17](https://github.com/pth8081/dms-prod/pull/17) | 2026-08-21 | Sửa lỗi migration nâng cấp schema.sql cho module Bản quyền |
| v6.2 | [#16](https://github.com/pth8081/dms-prod/pull/16) | 2026-08-21 | Thêm Kỳ mua/Đăng ký mua bản quyền, đổi logic Phát hành license theo gia hạn chênh lệch |
| v6.1 | [#15](https://github.com/pth8081/dms-prod/pull/15) | 2026-08-21 | Thêm tab Phát hành license và Phân bổ license cho module Bản quyền |
| v6.0 | [#1](https://github.com/pth8081/dms-prod/pull/1)–[#14](https://github.com/pth8081/dms-prod/pull/14) | 2026-08-14 → 2026-08-21 | Phiên bản nền tảng ban đầu: xác thực server-side + hash mật khẩu, vá XSS/upload PDF an toàn, quản lý phiên bản tài liệu (mã tự sinh, cây version), gộp Log/Quy trình vào Quản trị, xóa mềm (Thùng rác) + audit log, nâng cấp UI/UX, lưu file ra đĩa, đăng nhập LDAP/AD, và thêm nền tảng module Quản lý Bản quyền Phần mềm |

> **Ghi chú:** các số phiên bản v6.13, v6.17, v6.19, v6.21, v6.23, v6.52,
> v6.55, v6.56, v6.58, v6.60, v6.63, v6.65, v6.66, v6.68, v6.70, v6.72,
> v6.74, v6.76, v6.78, v6.80, v6.82, v6.84, v6.86 bị nhảy cóc trong lịch sử —
> không có Pull Request tương ứng để đối chiếu nội dung (nhiều khả năng do
> chạy lại workflow tăng version hoặc sửa trực tiếp trên `main` ngoài luồng
> PR — ví dụ v6.52 phát sinh từ chính commit cập nhật version.md cho v6.51,
> v6.55/v6.56/v6.58/v6.60 phát sinh tương tự từ các commit cập nhật
> version.md trực tiếp trên `main` sau mỗi lần merge, v6.63 phát sinh từ
> commit merge nhánh `main` (đã có sẵn bump v6.63) ngược vào nhánh PR #67 để
> giải quyết xung đột trước khi merge, v6.65/v6.66 phát sinh từ 2 commit
> liên tiếp sửa lại version.md sau PR #67, v6.68 phát sinh tương tự từ
> commit cập nhật version.md cho v6.67, và v6.70/v6.72/v6.74/v6.76/v6.78/
> v6.80/v6.82/v6.84/v6.86 phát sinh tương tự từ các commit cập nhật
> version.md trực tiếp trên `main` cho v6.69/v6.71/v6.73/v6.75/v6.77/v6.79/
> v6.81/v6.83/v6.85 — mỗi lần commit trực tiếp/merge như vậy đều vô tình
> kích hoạt lại workflow tăng version thêm 1 lần nữa). Từ PR #65 trở đi,
> workflow còn tự rebuild `public/app.min.js`/`style.css` trên mỗi lần chạy
> (xem Đợt 7), nên các lần nhảy cóc này không ảnh hưởng gì tới bundle
> production. Không ảnh hưởng tới các phiên bản khác.

## Cách cập nhật file này

Mỗi khi merge xong 1 Pull Request vào `main` (dù người dùng yêu cầu merge
hay tự động), thêm ngay 1 dòng mới **lên đầu bảng** ở trên với:
- **Phiên bản**: đúng số mà `chore: bump version to vX.Y [skip ci]` sinh ra
  (xem commit này xuất hiện trên `main` ngay sau merge, hoặc suy ra bằng
  cách tăng "minor" thêm 1 so với phiên bản liền trước, "patch" luôn về 0).
- **PR**: số PR vừa merge, kèm link.
- **Ngày merge**: ngày thực hiện merge (giờ UTC theo GitHub).
- **Nội dung**: tóm tắt 1 dòng đúng với tiêu đề/tóm tắt PR.
