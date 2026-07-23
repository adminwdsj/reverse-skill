---
name: mitv-airkan
description: Discovers Xiaomi/Mi TVs and uses the local Mi TV Assistant Airkan HTTP protocol to pair with an on-screen code, install APKs without ADB, list apps, and launch packages. Use when the user mentions 小米电视助手, Mi TV Assistant, Airkan, phoneAppInstallV2, ports 6095/9095, or installing an APK on a Xiaomi TV with ADB disabled.
---

# 小米电视 Airkan 本地管理

## ACTION REQUIRED（读完后立刻执行）

1. `NOW`：读取 `../field-journal/precedent-auth.md`，确认目标是用户明确指定的本地设备。
2. `NOW`：确认任务命中“小米电视助手本地协议 / 无 ADB 安装 APK”。
3. `NEXT`：读取 `../tool-index.md`，确认 `python3` 与 `python-cryptography` 可用。
4. `NEXT`：缺依赖时只调用 `../scripts/bootstrap-reverse.sh python-cryptography` 或 Windows 对应脚本，不猜路径、不另造安装流程。
5. `ACT`：从仓库根目录运行 `python3 skills/mitv-airkan/scripts/mitv_airkan.py doctor`，随后进入下方工作流。

## 适用范围

本 Skill 处理局域网内、由用户控制的小米电视或小米盒子：发现电视助手服务，完成屏幕六位码配对，通过 `9095/phoneAppInstallV2` 安装单体 APK，经 `6095` 查询和启动应用。

不处理 APK Bundle（`.apkm`、`.xapk`、拆分 APK）直接上传。必须先转为设备兼容的单体 APK，或改走已启用的 ADB 安装链路。

## 语言行为契约

- 内部推理、工具选择与阶段控制使用 English。
- 用户可见消息、报告与下一步菜单默认使用中文。
- 标签采用“中文 / English”，例如“已验证事实 / Verified facts”。

## 工具依赖

| 工具 | 必需 | 用途 | 自动安装 |
|---|---|---|---|
| Python 3.9+ | 是 | CLI 与 HTTP 流程 | 由平台文档安装 |
| `cryptography` | 是 | RSA、AES-CBC 与 DER 密钥 | `python-cryptography` capability |
| ADB | 否 | 仅作备用安装通道 | `adb` capability |

## 快速开始

```bash
python3 skills/mitv-airkan/scripts/mitv_airkan.py doctor
python3 skills/mitv-airkan/scripts/mitv_airkan.py discover --cidr 192.168.1.0/24
python3 skills/mitv-airkan/scripts/mitv_airkan.py auth-request --host 192.168.1.50
python3 skills/mitv-airkan/scripts/mitv_airkan.py auth-complete --code ABC123
python3 skills/mitv-airkan/scripts/mitv_airkan.py install /path/to/app.apk
python3 skills/mitv-airkan/scripts/mitv_airkan.py apps --filter package-or-name
python3 skills/mitv-airkan/scripts/mitv_airkan.py launch com.example.tv
```

认证状态默认保存在 `~/.config/mitv-airkan/state.json`，目录权限为 `0700`、文件权限为 `0600`。可用 `MITV_AIRKAN_STATE` 或 `--state` 改路径。不得把状态文件、验证码、电视 IP、MAC、设备 ID 或密钥提交到仓库。

## 工作流

### 阶段 1：发现与兼容性确认

1. 运行 `discover`，或在已知地址上运行 `info --host <TV_IP>`。
2. MUST 确认 `6095` 控制服务和 `9095` 安装服务均在线。
3. 安装流媒体应用前 MUST 核对 Android 最低版本、CPU ABI、单体/拆分包格式与 DRM 认证。能安装不等于能播放高清内容。

阶段结束后向用户提供：继续配对、导出当前信息、改用 ADB、暂停四个选项。

### 阶段 2：屏幕码配对

1. 运行 `auth-request --host <TV_IP>`。
2. 让用户只提供电视当前显示的最新六位码；旧码不可复用。
3. 运行 `auth-complete --code <CODE>`。
4. 运行 `doctor`，确认状态文件私有且设备端口在线。

协议易错点必须由 CLI 处理：1024 字节扩展区仅填前 1000 字节，执行 10000 次 HMAC-SHA256；Base64 用 `$` 替代 `=`；配对使用 BouncyCastle 兼容的裸 RSA；`device_id` 是本地公钥文本的 MD5。

阶段结束后向用户提供：安装 APK、列出现有应用、导出脱敏报告、暂停四个选项。

### 阶段 3：安装 APK

1. MUST 校验输入是可读取的单体 `.apk`，不能把 `.apkm` 当 APK 上传。
2. 默认运行 `install <APK>`；CLI 会先用空请求同步 `serial_num`，再上传真实 APK。
3. MUST 以 `HTTP 200` 且 `data_status=200` 作为服务端接收证据。
4. 若返回 `60007`，运行 `sync-serial`，不要重新配对或盲目切回 `6095`。
5. 若返回 `408` 且使用的是 `session=null`，这是未配对会话等待授权，不是已签名安装的成功结果。

阶段结束后向用户提供：验证并启动、安装另一个 APK、导出安装报告、暂停四个选项。

### 阶段 4：验证与启动

1. 用 `apps --filter <package-or-name>` 验证应用已进入电视应用列表。
2. 用 `launch <package>` 启动。
3. MUST 保存服务端返回值；`status=0` 是控制接口接受启动请求的证据。
4. 对 Netflix、Prime Video 等 DRM 应用，明确区分“已安装/可启动”与“登录、播放、分辨率认证已验证”。

阶段结束后向用户提供：继续做播放验证、安装其他应用、生成报告、结束四个选项。

## 按需自举（On-Demand Bootstrap）

Linux/macOS：

```bash
bash skills/scripts/bootstrap-reverse.sh python-cryptography
```

Windows：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File skills\scripts\bootstrap-reverse.ps1 -Capability @('python-cryptography')
```

自举失败两次后 MUST 停止重试，输出平台、Python 路径、完整错误和 `python3 -m pip install cryptography` 手动方案。

## 路由上下文

- 上游入口：`../routing.md` 的“小米电视助手 / Airkan / 无 ADB 安装 APK”。
- 下游出口：APK 本身需要分析时进入 `../apk-reverse/`；拆分包处理或 ADB 安装也进入 `../apk-reverse/`。
- 同级关联：`../firmware-pentest/` 用于电视固件与 IoT 服务分析。
- 协议细节：见 `references/protocol.md`。

## 任务完成自检（声称完成前 MUST 通过）

- [ ] 已实际运行发现、配对、安装、查询或启动中用户要求的步骤。
- [ ] 已基于 `tool-index` 使用真实 Python 路径，缺依赖时走 bootstrap。
- [ ] 已用返回码和应用列表提供可复现证据。
- [ ] 未把真实 IP、验证码、MAC、设备 ID、私钥、公钥或状态文件写入仓库。
- [ ] 已区分 APK 安装成功与 DRM/高清播放认证。
- [ ] 新经验已按 `field-journal/anonymization.md` 脱敏回写。
