# Z·SWITCH (zcode-switch)

**简体中文** ｜ [English](README.en.md)

Tauri 2 桌面工具：在多个 ZCode 账号之间一键切换，自动显示额度，并内嵌本地 API 网关。只换登录身份——项目、会话、设置全部共用不动。

![screenshot](docs/screenshot.png)

## 功能

- **保存 / 切换账号**：一键切换登录身份；切换前自动保全当前登录，绝不丢号；设备身份跟账号走，远程控制中继密钥跨切换保活
- **添加账号**：工具内 OAuth 登录新号（BigModel / z.ai 双入口），全程不动当前登录
- **额度展示**：账号行内联显示套餐额度与重置时间，多套餐分组
- **活动领取**：可领套餐一键领取；「自动领取」开关（默认关）定时自动检测并领取，手动操作优先
- **Z·GATEWAY 本地 API 网关**（融合 [zcode-api/ZCode Proxy](https://github.com/TriDefender/zcode-api)，详见下文）
- **加密导入导出**：`.zsb` 捆绑包，PBKDF2(100k) + AES-256-GCM 口令加密
- **中英双语**：设置里一键切换 中文 / English，主窗、托盘、错误提示、CLI 输出全覆盖；首次运行按系统语言自动选择
- **托盘 / 开机自启 / CLI 自动化**

## Z·GATEWAY 本地 API 网关

在设置里打开「启用 API 网关」后，Z·SWITCH 会在本机 `127.0.0.1:8317` 起一个 OpenAI / Anthropic 兼容接口，
把**账号库里的全部账号**作为上游凭据池——Claude Code、Codex（OpenAI 兼容客户端）、Cherry Studio、Cline 等
工具改一下 Base URL 就能把 GLM 套餐用起来。协议实现移植自 ZCode Proxy。

### 与单账号代理的区别（融合价值）

- **多账号池调度**：所有可用账号自动轮询（round-robin）；401 / 402 / 429 / 5xx / 网络错误自动故障转移到下一个账号，并按失败类别冷却（如 401 冷却 5 分钟、429 冷却 30 秒），不浪费限额
- **每账号独立设备指纹**：请求携带各账号自己的虚拟 `device_mid`（Z·SWITCH 的账号隔离能力），而不是共享一个身份
- **凭据零配置**：账号保存/登录后自动入池（优先 coding-plan API Key，其次 start-plan JWT），无需再登录一遍

### 端点与接入

| 端点 | 说明 |
|------|------|
| `POST /v1/chat/completions` | OpenAI Chat Completions 兼容（流式/非流式，SSE 自动双向翻译） |
| `POST /v1/messages` | Anthropic Messages 原生透传（Claude Code 直接接） |
| `GET /v1/models` | GLM 模型目录（OpenAI 格式） |
| `GET /health`、`GET /gw/status` | 健康检查 / 账号池状态 |

```bash
# Claude Code
export ANTHROPIC_BASE_URL=http://127.0.0.1:8317
export ANTHROPIC_AUTH_TOKEN=sk-anything   # 设置了访问密钥则填同值，否则任意
export ANTHROPIC_MODEL=glm-5.3

# OpenAI 兼容工具
Base URL: http://127.0.0.1:8317/v1
```

### 协议兼容层（移植自 ZCode Proxy）

- 请求伪装：完整的 ZCode 桌面客户端身份头（`ZCode/{ver} ai-sdk/anthropic` UA、`X-Platform`、`X-ZCode-Agent` 等）与 trace 头
- **动态端点路由**：拉取 `agent/configs` 的官方映射表，把 coding-plan 请求重写到 `zcode.z.ai/api/v1/ultra[-zai]`（fail-open）
- **Client Signing V4**：coding-plan 签名网关开启时自动完成 Ed25519 握手 + PoW 签名（含 401 VERIFY 重试阶梯与永久 bypass），全程 fail-open
- **start-plan 系统提示词注入**：按官方客户端的 3 块结构组装 system blocks + currentDate 上下文前缀，否则网关 3012 拒绝
- **GLM-5.3 推理参数兼容**：`reasoning_effort` 映射到 `output_config.effort` + 配对 `thinking.budget_tokens`，自动删除与 thinking 冲突的采样参数
- **缓存与元数据**：按官方客户端规则重排 `cache_control` 断点、注入 `metadata.user_id`
- 可选访问密钥（`Authorization` / `x-api-key`，恒定时间比较），CORS 全放开

主界面有网关状态卡：运行状态、端点地址（一键复制）、账号池健康度（每账号成功/失败计数与冷却状态）。

请求日志窗口按条记录账号、状态、耗时与重试次数，支持按账号筛选、一键导出（CSV / JSONL）。
验证链路的遥测（预解轮次、救援、票据等待）默认不记——它每几秒一条心跳，会把请求日志冲掉；
排查时在设置里打开 **debug 日志**即可看到全链路，开关即时生效。

> 尚未移植：Responses API（`/v1/responses`）、闲时通道 `/async/*`。

## 安全设计

- **本地优先**：所有数据在本地，无遥测、无远端存储；额度查询直连官方接口
- **WebView CSP**：`script-src` 基线为 `'self'`；为官方活动的网页组件放行了最小范围的第三方脚本与图片来源，界面事件不依赖动态执行、走白名单式分发
- **防丢号**：切换前自动保全未入库登录；文件写入走临时文件 + 原子 rename
- **路径穿越防护**：账号 id 白名单（`[A-Za-z0-9-]`），删除/读取均不可逃出账号库目录
- **加密导出**：PBKDF2-HMAC-SHA256（100k 迭代）+ AES-256-GCM，随机 salt/nonce；错密码即失败，无明文痕迹
- **凭据只在本地解密**：凭据解密仅用于显示用户名/邮箱；导出文件凭口令加密

## CLI

```
zcode-switch.exe --cli state|list
zcode-switch.exe --cli quota [--id <账号id>]
zcode-switch.exe --cli claim-preview [--id <账号id>]
zcode-switch.exe --cli capture [--name 名称]
zcode-switch.exe --cli switch --id <id> [--force] [--restart|--no-restart] [--hot <bool>|--no-hot]
zcode-switch.exe --cli kill
zcode-switch.exe --cli export --id <id> --out <a.zsb>
zcode-switch.exe --cli export-all --out <all.zsb>
zcode-switch.exe --cli import --file <file.zsb>
zcode-switch.exe --cli rename|delete|update|behavior|setpath|launch
zcode-switch.exe --cli --lang en state              # 英文输出（--lang 空格传值、可置于任意位置；默认跟 GUI 语言/系统语言）
```

CLI 密码（export / import）：优先环境变量 `ZSW_PASSWORD`（不出现在进程列表和命令历史），也可 `--password <密码>`。

## 常见问题

### macOS 弹出「麦克风 / 辅助功能 / 录屏」权限询问？

全部拒绝即可，不影响任何功能。
应用内嵌的登录等网页由系统 WebView 渲染，网页发起的请求会被透传为应用的系统权限询问；应用本体与其内嵌网页均未使用这三项能力。

## 构建

```bash
npm install
npm run tauri dev      # 开发（HMR）
npm run tauri build    # NSIS 安装包
```

Windows 优先（路径探测 / 进程管理 / 托盘均为 Win32 语义）。

## License

[MIT](./LICENSE)
