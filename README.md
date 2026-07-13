# Mochi Hosting 自动续期

针对 [Mochi Hosting](https://hosting.aida0710.work/)（`hosting.aida0710.work`）的 GitHub Actions 自动续期脚本。

## 续期是什么？

不是付费合同续期，而是调用官方接口：

```http
POST /api/servers/{id}/extend-uptime
```

用来延长服务器 **无玩家自动停止** 相关的 uptime / クレジット。  
官网说明：长时间无玩家时会自动停服；在面板点延长，或由本脚本调用同一接口。

## 功能

- 邮箱 + 密码登录（Better Auth）
- OIDC PKCE 获取 Bearer Token
- 支持 `MOCHI_REFRESH_TOKEN` 直接刷新（推荐）
- **默认续期账号下全部服务器**
- 可选 Telegram 通知
- GitHub Actions 定时运行

## 本地运行

```bash
pip install -r requirements.txt

export MOCHI_EMAIL="you@example.com"
export MOCHI_PASSWORD="your_password"
# 可选
export TELEGRAM_BOT_TOKEN="..."
export TELEGRAM_CHAT_ID="..."

python renew.py
```

成功后若生成了 `refresh_token.local.txt`，可把内容设为 GitHub Secret `MOCHI_REFRESH_TOKEN`，后续可少走登录流程。

## GitHub 部署

1. 新建仓库，把本目录文件推上去（需你自己操作）
2. **Settings → Secrets and variables → Actions** 添加：

| Secret | 必填 | 说明 |
|--------|------|------|
| `MOCHI_EMAIL` | 是* | 登录邮箱 |
| `MOCHI_PASSWORD` | 是* | 登录密码 |
| `MOCHI_REFRESH_TOKEN` | 否 | 有则优先用，更稳 |
| `MOCHI_SERVER_IDS` | 否 | 逗号分隔 ID；**空=全部** |
| `TELEGRAM_BOT_TOKEN` | 否 | TG 机器人 |
| `TELEGRAM_CHAT_ID` | 否 | TG 聊天 ID |

\* 若只配了 `MOCHI_REFRESH_TOKEN`，可不配邮箱密码。

3. 打开 **Actions → 🍡 Mochi Hosting 自动续期 → Run workflow** 手动测一次  
4. 默认定时：每 6 小时（UTC）

## 环境变量（高级）

| 变量 | 默认 |
|------|------|
| `MOCHI_AUTH_BASE` | `https://auth.aida0710.work/api/auth` |
| `MOCHI_API_BASE` | `https://hosting.aida0710.work/api` |
| `MOCHI_CLIENT_ID` | `mochi-portal` |
| `MOCHI_REDIRECT_URI` | `https://hosting.aida0710.work/auth/callback` |

## 注意

- 请遵守 Mochi Hosting 服务条款，合理使用自动脚本
- 不要把密码、`refresh_token.local.txt` 提交进 Git
- 若 OIDC 授权页改版导致拿不到 code，把 Actions 日志发出来再改

## 文件

```
mochi-renew/
├── renew.py
├── requirements.txt
├── README.md
├── time.txt                 # Actions 保活用（运行后生成）
└── .github/workflows/main.yml
```
