# tiktok-android-signer

TikTok Android 客户端签名算法的纯 Go 离线实现，不依赖 unidbg / Frida / 任何第三方签名服务。

覆盖设备注册、msToken 获取与 aweme detail 接口的完整签名链路，并用真机抓包样本做了逐字节校验。

## 算法覆盖

| 模块 | 说明 |
|---|---|
| `crypto/xargus.go` | X-Argus 签名（protobuf 输入，SM3 + 动态 dyn algo） |
| `crypto/xgnarly.go` | X-Gnarly 签名 |
| `crypto/xgorgon.go` | X-Gorgon（v8404，query + cookie md5 stub 输入） |
| `crypto/xgorgon_331005_ref.go` | X-Gorgon 33.1.0.5 参考实现（离线校验用） |
| `crypto/xladon.go` | X-Ladon 签名 |
| `crypto/xbogus.go` | X-Bogus 签名 |
| `crypto/mssdk_seed.go` | msToken / get_seed 请求构造与响应解析（mssdk 协议） |
| `crypto/mflate/` | mssdk 定制 deflate 压缩（魔改 huffman,与 libmetasec_ov 逐字节对齐） |
| `crypto/sm3.go` `simon.go` | SM3 哈希、Simon 分组密码 |
| `crypto/ttencrypt.go` | TTEncrypt 请求体包装（device_register 用） |
| `crypto/ttdevice/` | device_register 的 protobuf 定义 |
| `native/` | 调用流程：设备注册 → get_token/msToken → 签名 detail 请求 |

## 工作流程

全部请求只打 TikTok 官方域名，无任何第三方解析服务：

1. `POST log.tiktokv.com/service/2/device_register/` — TTEncrypt 包装 + 签名，产出受信 `device_id` / `install_id`，进程内缓存复用
2. `get_seed` / `get_token` — 拉取 msToken 动态种子与设备 token
3. `POST api22-normal-c-alisg.tiktokv.com/aweme/v1/multi/aweme/detail/` — X-Gorgon / X-Khronos / X-Ladon / X-Argus 四件套签名，TLS 指纹走 OkHttp（bogdanfinn/tls-client），返回 `RawItemDetail`（含无水印播放直链）

## 对齐版本

- TikTok Android **33.2.5**（versionCode 2023302050），对应 `libmetasec_ov.so` 同版
- 设备档：Mi 9T Pro / Android 11，参数集中在 `crypto/signconfig.go` 的 `DefaultDeviceProfile`，换设备/升版本只改这一处
- 离线单测内嵌真机抓包校验向量，逐字节复现签名输出；`oracle_calibrate_test.go` 在无 oracle 文件时自动 skip

## 快速开始

```bash
go run ./cmd/demo <视频数字ID>
```

作为库调用：

```go
item, err := native.FetchViaNativeAppAPI(ctx, "7300000000000000000")
```

环境变量（可选）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `TIKTOK_PROXY_URL` | 空(直连) | 出站代理，区域由出口 IP 决定 |
| `TIKTOK_REQUEST_TIMEOUT` | 15 | 请求超时（秒） |

## 测试

```bash
go test ./...
```

均为离线测试：签名向量复现、mflate golden 对拍、TTDevice protobuf 编解码，不请求网络。

## 目录结构

```
crypto/      签名算法核心(各 header 算法 + mflate + 设备档)
native/      Android 路径调用流程(注册/token/detail)
parseerr/    业务错误码
models/      共享数据模型
proxyctx/    出站代理上下文
config/      最小配置(代理/超时)
cmd/demo/    最小演示 CLI
```

## 免责声明

本项目仅供学习与安全研究用途。使用者应遵守 TikTok 服务条款及所在地法律法规，对任何使用方式自行承担责任。TikTok 协议升级可能导致算法失效，本项目不承诺持续可用。

## License

[MIT](LICENSE)
