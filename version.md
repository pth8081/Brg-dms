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

> **Ghi chú:** các số phiên bản v6.13, v6.17, v6.19, v6.21, v6.23 bị nhảy cóc
> trong lịch sử — không có Pull Request tương ứng để đối chiếu nội dung
> (nhiều khả năng do chạy lại workflow tăng version hoặc sửa trực tiếp trên
> `main` ngoài luồng PR). Không ảnh hưởng tới các phiên bản khác.

## Cách cập nhật file này

Mỗi khi merge xong 1 Pull Request vào `main` (dù người dùng yêu cầu merge
hay tự động), thêm ngay 1 dòng mới **lên đầu bảng** ở trên với:
- **Phiên bản**: đúng số mà `chore: bump version to vX.Y [skip ci]` sinh ra
  (xem commit này xuất hiện trên `main` ngay sau merge, hoặc suy ra bằng
  cách tăng "minor" thêm 1 so với phiên bản liền trước, "patch" luôn về 0).
- **PR**: số PR vừa merge, kèm link.
- **Ngày merge**: ngày thực hiện merge (giờ UTC theo GitHub).
- **Nội dung**: tóm tắt 1 dòng đúng với tiêu đề/tóm tắt PR.
