#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mochi Hosting (hosting.aida0710.work) 自动续期脚本

续期含义: POST /api/servers/{id}/extend-uptime
延长「无玩家自动停止」相关的 uptime / クレジット，不是合同付费续期。

认证:
1. 优先使用 Secrets 中的 MOCHI_REFRESH_TOKEN 刷新 access_token
2. 否则邮箱 + 密码登录 Better Auth，再走 OIDC PKCE 拿 token
3. 对账号下全部服务器调用 extend-uptime
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import requests

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

AUTH_BASE = os.getenv("MOCHI_AUTH_BASE", "https://auth.aida0710.work/api/auth").rstrip("/")
API_BASE = os.getenv("MOCHI_API_BASE", "https://hosting.aida0710.work/api").rstrip("/")
PORTAL_ORIGIN = os.getenv("MOCHI_PORTAL_ORIGIN", "https://hosting.aida0710.work").rstrip("/")
CLIENT_ID = os.getenv("MOCHI_CLIENT_ID", "mochi-portal")
REDIRECT_URI = os.getenv(
    "MOCHI_REDIRECT_URI", f"{PORTAL_ORIGIN}/auth/callback"
)
SCOPE = os.getenv("MOCHI_SCOPE", "openid profile email offline_access")

# 登录: 邮箱 + 密码
MOCHI_EMAIL = os.getenv("MOCHI_EMAIL") or os.getenv("MOCHI_USERNAME") or ""
MOCHI_PASSWORD = os.getenv("MOCHI_PASSWORD") or ""

# 可选: 已有 refresh_token，跳过账密登录
MOCHI_REFRESH_TOKEN = os.getenv("MOCHI_REFRESH_TOKEN") or ""

# 可选: 只续指定 ID（逗号分隔）；空 = 全部服务器
MOCHI_SERVER_IDS = os.getenv("MOCHI_SERVER_IDS", "").strip()

# Telegram（可选）
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or ""
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or ""

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 MochiRenew/1.0"
)

BEIJING = timezone(timedelta(hours=8))


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

def now_beijing() -> str:
    return datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(msg, flush=True)


def pkce_pair() -> tuple[str, str]:
    """返回 (code_verifier, code_challenge S256)"""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def random_state() -> str:
    return secrets.token_urlsafe(24)


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

class TelegramNotifier:
    def __init__(self, bot_token: str = "", chat_id: str = ""):
        self.bot_token = bot_token or TELEGRAM_BOT_TOKEN
        self.chat_id = chat_id or TELEGRAM_CHAT_ID
        self.enabled = bool(self.bot_token and self.chat_id)
        if not self.enabled:
            log("ℹ️ Telegram 未配置，跳过推送")

    def send(self, text: str, parse_mode: str = "HTML") -> bool:
        if not self.enabled:
            return False
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            r = requests.post(
                url,
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True,
                },
                timeout=REQUEST_TIMEOUT,
            )
            data = r.json()
            if data.get("ok"):
                log("✅ Telegram 发送成功")
                return True
            log(f"❌ Telegram 发送失败: {data.get('description')}")
            return False
        except Exception as e:
            log(f"❌ Telegram 异常: {e}")
            return False


# ---------------------------------------------------------------------------
# Mochi Auth + API
# ---------------------------------------------------------------------------

class MochiClient:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/plain, */*",
            }
        )
        self.access_token: str | None = None
        self.refresh_token: str | None = MOCHI_REFRESH_TOKEN or None
        self.id_token: str | None = None

    # ---- token 管理 ----

    def _set_tokens(self, payload: dict[str, Any]) -> None:
        if payload.get("access_token"):
            self.access_token = payload["access_token"]
        if payload.get("refresh_token"):
            self.refresh_token = payload["refresh_token"]
        if payload.get("id_token"):
            self.id_token = payload["id_token"]
        log("✅ 已取得 access_token")
        if self.refresh_token:
            # 不完整打印，只提示有 token
            log(f"ℹ️ refresh_token 已就绪 (len={len(self.refresh_token)})")
            log("💡 可将 refresh_token 存为 GitHub Secret: MOCHI_REFRESH_TOKEN 以减少登录次数")

    def refresh_access_token(self) -> bool:
        if not self.refresh_token:
            return False
        log("🔄 使用 refresh_token 刷新 access_token...")
        try:
            r = self.session.post(
                f"{AUTH_BASE}/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": CLIENT_ID,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=REQUEST_TIMEOUT,
            )
            if not r.ok:
                log(f"⚠️ refresh 失败 HTTP {r.status_code}: {r.text[:300]}")
                return False
            self._set_tokens(r.json())
            return bool(self.access_token)
        except Exception as e:
            log(f"⚠️ refresh 异常: {e}")
            return False

    def login_with_password(self, email: str, password: str) -> bool:
        """Better Auth 邮箱登录，建立 session cookie。"""
        log(f"🔐 邮箱登录: {email}")
        try:
            r = self.session.post(
                f"{AUTH_BASE}/sign-in/email",
                json={"email": email, "password": password},
                headers={"Content-Type": "application/json", "Origin": PORTAL_ORIGIN},
                timeout=REQUEST_TIMEOUT,
            )
            # better-auth 成功常见 200；也可能 2xx 带 user
            if r.status_code >= 400:
                log(f"❌ 登录失败 HTTP {r.status_code}: {r.text[:400]}")
                return False
            body = {}
            try:
                body = r.json()
            except Exception:
                pass
            if isinstance(body, dict) and body.get("error"):
                log(f"❌ 登录失败: {body.get('error') or body}")
                return False
            # 检查是否有 session cookie
            cookies = self.session.cookies.get_dict()
            log(f"✅ 登录响应 OK，cookies: {list(cookies.keys()) or '(无，可能靠 header)'}")
            return True
        except Exception as e:
            log(f"❌ 登录异常: {e}")
            return False

    def obtain_token_via_pkce(self) -> bool:
        """
        已有 auth session 的前提下，走 OIDC authorization_code + PKCE。
        """
        log("🎫 开始 OIDC PKCE 授权码流程...")
        verifier, challenge = pkce_pair()
        state = random_state()
        nonce = random_state()

        params = {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPE,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "nonce": nonce,
        }
        authorize_url = f"{AUTH_BASE}/oauth2/authorize?{urlencode(params)}"

        try:
            code = self._follow_authorize_for_code(authorize_url, state)
            if not code:
                log("❌ 未能从授权流程拿到 code")
                return False

            log("🔁 用 code 换 token...")
            r = self.session.post(
                f"{AUTH_BASE}/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "client_id": CLIENT_ID,
                    "code_verifier": verifier,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=REQUEST_TIMEOUT,
            )
            if not r.ok:
                log(f"❌ token 交换失败 HTTP {r.status_code}: {r.text[:400]}")
                return False
            self._set_tokens(r.json())
            return bool(self.access_token)
        except Exception as e:
            log(f"❌ PKCE 授权异常: {e}")
            return False

    def _follow_authorize_for_code(self, url: str, expected_state: str) -> str | None:
        """跟随 3xx，直到 redirect_uri 带 code，或页面表单/链接含 code。"""
        current = url
        for hop in range(12):
            r = self.session.get(
                current,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Referer": PORTAL_ORIGIN + "/",
                },
            )
            loc = r.headers.get("Location") or r.headers.get("location")
            log(f"  ↳ hop{hop}: HTTP {r.status_code} loc={'(none)' if not loc else loc[:120]}")

            # 直接检查当前最终 URL（有些实现 200 到 callback）
            code = self._extract_code(r.url, expected_state)
            if code:
                return code

            if loc:
                # 相对路径
                if loc.startswith("/"):
                    parsed = urlparse(current)
                    loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                code = self._extract_code(loc, expected_state)
                if code:
                    return code
                # 还在 auth 域则继续跟
                current = loc
                continue

            # 200 HTML：可能有 meta refresh / 表单 / 继续按钮
            if r.status_code == 200 and r.text:
                m = re.search(
                    r'url=([^"\'>\s]+)|href=["\']([^"\']*code=[^"\']+)["\']',
                    r.text,
                    re.I,
                )
                if m:
                    candidate = m.group(1) or m.group(2)
                    candidate = candidate.replace("&amp;", "&")
                    if candidate.startswith("/"):
                        parsed = urlparse(current)
                        candidate = f"{parsed.scheme}://{parsed.netloc}{candidate}"
                    code = self._extract_code(candidate, expected_state)
                    if code:
                        return code
                    current = candidate
                    continue

                # consent 页面：尝试提交同意表单
                if re.search(r'name=["\']consent["\']|同意|Authorize|許可', r.text, re.I):
                    log("  ↳ 检测到可能的授权确认页，尝试自动同意...")
                    action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, re.I)
                    post_url = current
                    if action:
                        act = action.group(1)
                        if act.startswith("/"):
                            parsed = urlparse(current)
                            post_url = f"{parsed.scheme}://{parsed.netloc}{act}"
                        elif act.startswith("http"):
                            post_url = act
                    r2 = self.session.post(
                        post_url,
                        data={"consent": "true", "accept": "true", "authorize": "true"},
                        allow_redirects=False,
                        timeout=REQUEST_TIMEOUT,
                    )
                    loc2 = r2.headers.get("Location") or ""
                    log(f"  ↳ consent POST -> HTTP {r2.status_code} loc={loc2[:120]}")
                    if loc2:
                        if loc2.startswith("/"):
                            parsed = urlparse(post_url)
                            loc2 = f"{parsed.scheme}://{parsed.netloc}{loc2}"
                        code = self._extract_code(loc2, expected_state)
                        if code:
                            return code
                        current = loc2
                        continue

            log(f"❌ 授权流程中断，status={r.status_code}, body[:200]={r.text[:200]!r}")
            return None

        log("❌ 授权跳转次数过多")
        return None

    def _extract_code(self, url: str, expected_state: str) -> str | None:
        if not url or "code=" not in url:
            return None
        # 必须是我们的 redirect 或至少带 code
        qs = parse_qs(urlparse(url).query)
        code = (qs.get("code") or [None])[0]
        state = (qs.get("state") or [None])[0]
        if not code:
            return None
        if state and state != expected_state:
            log(f"⚠️ state 不匹配: got={state} expected={expected_state}（仍尝试使用 code）")
        log("✅ 已拿到 authorization code")
        return code

    def ensure_auth(self) -> bool:
        if self.refresh_token and self.refresh_access_token():
            return True
        if not MOCHI_EMAIL or not MOCHI_PASSWORD:
            log("❌ 未配置 MOCHI_EMAIL / MOCHI_PASSWORD，且 refresh 失败")
            return False
        if not self.login_with_password(MOCHI_EMAIL, MOCHI_PASSWORD):
            return False
        return self.obtain_token_via_pkce()

    # ---- API ----

    def _api(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> requests.Response:
        if not self.access_token:
            raise RuntimeError("no access_token")
        headers = kwargs.pop("headers", {})
        headers = {
            **headers,
            "Authorization": f"Bearer {self.access_token}",
        }
        url = f"{API_BASE}{path}"
        return self.session.request(
            method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
        )

    def list_servers(self) -> list[dict[str, Any]]:
        log("📋 获取服务器列表...")
        r = self._api("GET", "/servers")
        if r.status_code == 401:
            log("⚠️ 401，尝试 refresh 后重试...")
            if self.refresh_access_token():
                r = self._api("GET", "/servers")
        if not r.ok:
            raise RuntimeError(f"list servers failed: {r.status_code} {r.text[:300]}")
        data = r.json()
        # 兼容 array 或 {servers:[]}
        if isinstance(data, list):
            servers = data
        elif isinstance(data, dict):
            servers = data.get("servers") or data.get("data") or data.get("items") or []
        else:
            servers = []
        log(f"✅ 共 {len(servers)} 台服务器")
        return servers

    def extend_uptime(self, server_id: str) -> tuple[bool, str]:
        r = self._api("POST", f"/servers/{server_id}/extend-uptime")
        if r.status_code == 401:
            if self.refresh_access_token():
                r = self._api("POST", f"/servers/{server_id}/extend-uptime")
        if r.ok:
            try:
                body = r.json()
                return True, json.dumps(body, ensure_ascii=False)[:200]
            except Exception:
                return True, r.text[:200] or "ok"
        try:
            err = r.json()
            msg = err.get("error") or err.get("message") or r.text[:200]
        except Exception:
            msg = r.text[:200]
        return False, f"HTTP {r.status_code}: {msg}"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def filter_servers(servers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not MOCHI_SERVER_IDS:
        return servers
    wanted = {x.strip() for x in MOCHI_SERVER_IDS.split(",") if x.strip()}
    out = []
    for s in servers:
        sid = str(s.get("id") or s.get("serverId") or "")
        if sid in wanted:
            out.append(s)
    return out


def server_label(s: dict[str, Any]) -> str:
    name = s.get("name") or s.get("serverName") or "?"
    sid = s.get("id") or s.get("serverId") or "?"
    status = s.get("status") or "?"
    return f"{name} ({sid}) [{status}]"


def build_report(
    results: list[tuple[str, bool, str]],
    ok_count: int,
    fail_count: int,
) -> str:
    lines = [
        f"**最后运行时间**: `{now_beijing()}`",
        "",
        "**运行结果**:",
        f"- 成功: {ok_count}",
        f"- 失败: {fail_count}",
        "",
    ]
    for label, ok, detail in results:
        mark = "✅" if ok else "❌"
        lines.append(f"- {mark} `{label}` — {detail}")
    return "\n".join(lines) + "\n"


def build_tg_message(
    results: list[tuple[str, bool, str]],
    ok_count: int,
    fail_count: int,
) -> str:
    msg = (
        f"<b>🍡 Mochi Hosting 续期通知</b>\n\n"
        f"🕐 时间: <code>{now_beijing()}</code>\n"
        f"📊 成功: <b>{ok_count}</b> / 失败: <b>{fail_count}</b>\n\n"
    )
    for label, ok, detail in results:
        mark = "✅" if ok else "❌"
        safe = (
            detail.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        msg += f"{mark} <code>{label}</code>\n   {safe}\n"
    return msg


def main() -> int:
    log("=" * 60)
    log("Mochi Hosting 自动续期 (extend-uptime)")
    log(f"时间: {now_beijing()}")
    log(f"API: {API_BASE}")
    log(f"Auth: {AUTH_BASE}")
    log("=" * 60)

    if not MOCHI_REFRESH_TOKEN and (not MOCHI_EMAIL or not MOCHI_PASSWORD):
        log("❌ 请设置 MOCHI_EMAIL + MOCHI_PASSWORD，或设置 MOCHI_REFRESH_TOKEN")
        return 1

    client = MochiClient()
    tg = TelegramNotifier()

    if not client.ensure_auth():
        tg.send(
            f"<b>🍡 Mochi 续期失败</b>\n\n"
            f"🕐 <code>{now_beijing()}</code>\n"
            f"❌ 认证失败，请检查邮箱密码或 refresh_token"
        )
        return 1

    try:
        servers = client.list_servers()
    except Exception as e:
        log(f"❌ 获取服务器列表失败: {e}")
        tg.send(
            f"<b>🍡 Mochi 续期失败</b>\n\n"
            f"🕐 <code>{now_beijing()}</code>\n"
            f"❌ 获取服务器列表失败: {e}"
        )
        return 1

    targets = filter_servers(servers)
    if not targets:
        log("⚠️ 没有可续期的服务器")
        report = build_report([], 0, 0) + "\n(无服务器)\n"
        with open("report-notify.md", "w", encoding="utf-8") as f:
            f.write(report)
        tg.send(
            f"<b>🍡 Mochi 续期</b>\n\n"
            f"🕐 <code>{now_beijing()}</code>\n"
            f"⚠️ 账号下没有服务器"
        )
        return 0

    results: list[tuple[str, bool, str]] = []
    ok_count = 0
    fail_count = 0

    for s in targets:
        sid = str(s.get("id") or s.get("serverId") or "")
        label = server_label(s)
        if not sid:
            results.append((label, False, "缺少 server id"))
            fail_count += 1
            continue
        log(f"🔄 续期: {label}")
        ok, detail = client.extend_uptime(sid)
        if ok:
            log(f"  ✅ {detail}")
            ok_count += 1
        else:
            log(f"  ❌ {detail}")
            fail_count += 1
        results.append((label, ok, detail))
        time.sleep(0.5)

    report = build_report(results, ok_count, fail_count)
    with open("report-notify.md", "w", encoding="utf-8") as f:
        f.write(report)
    log("📝 已写入 report-notify.md")
    log(report)

    # 若拿到了新的 refresh_token，写本地文件方便用户拷贝（不要提交到 git）
    if client.refresh_token and not MOCHI_REFRESH_TOKEN:
        try:
            with open("refresh_token.local.txt", "w", encoding="utf-8") as f:
                f.write(client.refresh_token)
            log("💾 已保存 refresh_token.local.txt（请勿提交到 Git）")
        except Exception:
            pass

    tg.send(build_tg_message(results, ok_count, fail_count))

    if fail_count and not ok_count:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
