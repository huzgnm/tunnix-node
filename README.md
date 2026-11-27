# TunnixNode

Node VPN viết bằng Rust cho panel **XiaoBoard** (wyx2685/v2board), **Xboard**, **V2Board** và **Remnawave**.
Thay thế v2node / remnanode (Xray/Go): ít RAM hơn, không có bộ dọn rác (GC) nên tốc độ ổn định khi đông người dùng.

## Tính năng

- Lấy cấu hình node và danh sách user từ panel, tự cập nhật khi panel đổi (không cần khởi động lại).
- Thêm/xoá user khi đang chạy. User bị xoá/hết hạn bị ngắt kết nối ngay ở lần đồng bộ kế tiếp.
- Đếm traffic từng user, báo về panel theo `push_interval`. Báo lỗi thì giữ lại và báo lần sau, không mất traffic.
- Giới hạn tốc độ theo user (`speed_limit`, Mbps) và giới hạn thiết bị (`device_limit`, theo IP).
- Báo IP online (XiaoBoard, Xboard) và trạng thái máy CPU/RAM/đĩa (Xboard).
- Chặn sẵn truy cập vào dải IP nội bộ của máy chủ (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16…).
- REALITY: SNI lạ hoặc kết nối không có khoá được chuyển sang trang đích như Xray, chống dò quét.
- Chế độ **Remnawave**: thay thế `remnawave/node` (API mTLS + JWT, nhận cấu hình Xray từ panel).

### Giao thức

Đã test chéo với client thật (Xray 26.11.9, sing-box): nhiều user, đếm traffic, giới hạn tốc độ, xoá user là ngắt.

| Giao thức | TCP | UDP |
|---|:---:|:---:|
| VLESS (REALITY + Vision, TLS, mã hoá ML-KEM) | ✅ | ✅ |
| VMess (AEAD) | ✅ | ✅ |
| Trojan | ✅ | ✅ |
| Shadowsocks AEAD / 2022 (nhiều user qua EIH) | ✅ | ✅ |
| Hysteria2 (kể cả obfs `salamander`) | ✅ | ✅ |
| TUIC v5 | ✅ | ✅ |
| AnyTLS | ✅ | ✅ |

Kiểu truyền: TCP, WebSocket (cả `?ed=` dữ liệu sớm), gRPC, HTTPUpgrade, XHTTP.
Chưa hỗ trợ: mKCP, Shadowsocks-2022 ChaCha20 nhiều user, nhà DNS cho ACME ngoài Cloudflare.

> Client Xray 26 đã bỏ `allowInsecure`: node dùng chứng chỉ tự ký thì client phải ghim mã băm
> (`pinnedPeerCertSha256`) hoặc dùng chứng chỉ thật (`cert_mode` http/dns, xem dưới).

### Chứng chỉ TLS (`cert_mode` trên panel)

| cert_mode | Cách làm |
|---|---|
| `http` | Let's Encrypt qua HTTP-01. Cần **cổng 80 mở** lúc xin/gia hạn; nhiều node trên một VPS dùng chung cổng. |
| `dns` | Let's Encrypt qua DNS-01. Hiện hỗ trợ **Cloudflare**: `provider = cloudflare`, `dns_env = CF_DNS_API_TOKEN=...` (hoặc `CF_API_EMAIL=...,CF_API_KEY=...`). |
| `file` | Dùng `cert_file` / `key_file` có sẵn trên máy chủ. |
| `remote` | Chứng chỉ do panel gửi xuống (`tls_cert` / `tls_key`). |
| `self` | Chứng chỉ tự ký (client Xray 26 phải ghim mã băm). |

- Chứng chỉ lưu ở `/var/lib/tunnix-node/acme/<tên miền>/`, tự gia hạn khi còn dưới 30 ngày, nạp lại không cắt kết nối.
- Xin cấp lỗi thì node vẫn chạy bằng chứng chỉ tự ký và thử lại sau 1 giờ (tránh giới hạn số lần thử của Let's Encrypt).
- Chọn `http`/`dns` nghĩa là đồng ý điều khoản của Let's Encrypt (giống v2node). Thêm `"AcmeEmail": "..."` vào cấu hình nếu muốn nhận thư báo.

## Cài đặt nhanh

Chạy bằng root trên VPS Linux (amd64 hoặc arm64):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huzgnm/tunnix-node/main/scripts/install.sh) \
  --panel xiaoboard --api-host 'https://panel.example.com' --node-id 1 --api-key 'SERVER_TOKEN'
```

- `--panel`: `xiaoboard` | `xboard` | `v2board`. V2Board gốc cần thêm `--node-type vmess|trojan|shadowsocks`.
- Mặc định chạy bằng **Docker** (`network_mode: host`). Thêm `--mode systemd` để chạy thẳng không cần Docker.
- Không truyền tham số thì script hỏi từng bước.
- Chạy lại lệnh với node khác thì node đó được **thêm** vào cùng một tiến trình. Dùng `--replace` để thay toàn bộ.

Lệnh cài giống v2node (`--api-host --node-id --api-key`), nên dán lệnh từ panel XiaoBoard rồi đổi đường dẫn script là được.

### Remnawave

Trên panel Remnawave: **Nodes → tạo node** → lấy `SECRET_KEY` trong phần docker-compose, rồi chạy trên VPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/huzgnm/tunnix-node/main/scripts/install.sh) \
  --panel remnawave --secret-key 'SECRET_KEY_TỪ_PANEL' --node-port 2222
```

Panel đẩy cấu hình Xray (profile) xuống node như với remnanode. Hỗ trợ inbound VLESS, VMess, Trojan, Shadowsocks,
Hysteria với REALITY/TLS và các kiểu truyền ở trên; inbound khác (socks, dokodemo…) được bỏ qua.
Có thể chạy chung một tiến trình với các node Xboard/XiaoBoard. Nên chỉ mở `NODE_PORT` cho IP panel.

## Quản lý

```text
tunnix status | start | stop | restart | log
tunnix add --panel xboard --api-host URL --node-id 2 --api-key KEY
tunnix remove --api-host URL --node-id 2
tunnix config        # sửa /etc/tunnix-node/config.json
tunnix update        # cập nhật bản mới nhất
tunnix x25519        # tạo cặp khoá REALITY
tunnix uninstall
```

## Cấu hình

`/etc/tunnix-node/config.json` (cùng tên trường với v2node, thêm `PanelType`):

```json
{
  "Log": { "Level": "info" },
  "Nodes": [
    { "PanelType": "xiaoboard", "ApiHost": "https://panel.example.com", "NodeID": 1, "ApiKey": "TOKEN", "Timeout": 15 },
    { "PanelType": "xboard", "ApiHost": "https://xboard.example.com", "NodeID": 7, "ApiKey": "TOKEN" }
  ]
}
```

Chuyển từ v2node: copy `/etc/v2node/config.json` sang `/etc/tunnix-node/config.json` (mặc định `PanelType` là `xiaoboard`).

## Build

```bash
cargo build --release -p tunnix-node
# Linux tĩnh (musl) từ macOS:
cargo zigbuild --release -p tunnix-node --target x86_64-unknown-linux-musl
# Docker từ mã nguồn:
docker build -f docker/Dockerfile.source -t tunnix-node .
```

Đẩy tag `vX.Y.Z` lên GitHub thì workflow `release` tự build bản Linux amd64/arm64, tạo Release và đẩy image lên `ghcr.io`.

## Giấy phép

Mã nguồn độc quyền, xem [LICENSE](LICENSE). Lõi giao thức (`crates/core`) là bản sửa đổi của
[shoes](https://github.com/cfal/shoes) theo giấy phép MIT, xem [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
