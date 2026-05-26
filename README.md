# Tool ký IPA local

Tool web chạy trên macOS để ký lại file `.ipa` bằng `.p12` và `.mobileprovision`.

## Yêu cầu

- macOS có `codesign`, `security`, `zip`, `unzip`, `/usr/libexec/PlistBuddy`
- Node.js 18+
- File `.p12` có private key hợp lệ
- Provisioning profile phải khớp app id/bundle id bạn dùng để ký

## Chạy

```sh
npm install
npm run start:cloudflare
```

Mở URL `https://...trycloudflare.com` mà terminal in ra. Có thể mở `http://localhost:3000` để thao tác trên máy Mac, nhưng link OTA/QR vẫn sẽ dùng Cloudflare Tunnel khi chạy bằng lệnh trên.

## OTA bằng QR

Sau khi ký xong, tool hiển thị QR chứa link `itms-services` để cài OTA trên iPhone.

## Public HTTPS bằng Cloudflare Tunnel

Cloudflare Worker không chạy được phần ký IPA vì Worker không có macOS `codesign`, `security` và keychain. Cách chạy đúng là để app ký trên máy Mac, rồi public qua Cloudflare Tunnel:

```sh
npm run start:cloudflare
```

Lệnh này tự chạy cả local server và Cloudflare Tunnel. Mặc định nó đọc `~/.cloudflared/config.yml`, lấy hostname/tunnel hiện có, để hệ điều hành tự cấp port local còn trống, rồi tạo config tạm trong project để trỏ hostname đó về đúng port. File config gốc của bạn không bị sửa.

Để tắt local server và tunnel của tool:

```sh
npm run stop:cloudflare
```

Nếu muốn dùng quick tunnel ngẫu nhiên:

```sh
npm run start:cloudflare:quick
```

Nếu muốn tự tách hai terminal:

```sh
npm start
npm run tunnel
```

Khi dùng lệnh tách riêng, hãy mở trực tiếp URL `https://...trycloudflare.com` để QR OTA dùng đúng domain HTTPS đó.

Lưu ý:

- Nếu mở tool bằng `localhost`, iPhone sẽ không truy cập được IPA trên máy Mac. Hãy mở bằng IP LAN, ví dụ `http://192.168.1.10:3000`, hoặc chạy server sau proxy HTTPS và đặt `PUBLIC_BASE_URL`.
- iOS thường yêu cầu OTA manifest và IPA qua HTTPS. Khi dùng domain HTTPS:

```sh
PUBLIC_BASE_URL=https://your-domain.example npm start
```

## Ghi chú

- Tool dùng keychain tạm trong thư mục hệ thống và xóa sau khi xử lý.
- Nếu đổi bundle identifier, provisioning profile phải là wildcard hoặc đúng bundle id mới.
- Tùy chọn `Xóa embedded.mobileprovision` sẽ không nhúng profile mới vào app. Với IPA cài lên thiết bị thật, thường nên để tùy chọn này tắt.
