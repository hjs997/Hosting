#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mochi Hosting (hosting.aida0710.work) 自动续期脚本

续期: POST /api/servers/{id}/extend-uptime

认证优先级:
1. MOCHI_REFRESH_TOKEN 刷新 access_token（推荐，GitHub Actions 必用此方式）
2. 邮箱密码 + Cloudflare Turnstile
   - 可选 CAPSOLVER_API_KEY / TWOCAPTCHA_API_KEY 自动打码
   - 或 USE_PLAYWRIGHT=true 浏览器登录（本机有头模式可过人机；GHA 无头常被拦）
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
AUTH_ORIGIN = os.getenv("MOCHI_AUTH_ORIGIN", "https://auth.aida0710.work").rstrip("/")
API_BASE = os.getenv("MOCHI_API_BASE", "https://hosting.aida0710.work/api").rstrip("/")
PORTAL_ORIGIN = os.getenv("MOCHI_PORTAL_ORIGIN", "https://hosting.aida0710.work").rstrip("/")
CLIENT_ID = os.getenv("MOCHI_CLIENT_ID", "mochi-portal")
REDIRECT_URI = os.getenv("MOCHI_REDIRECT_URI", f"{PORTAL_ORIGIN}/auth/callback")
SCOPE = os.getenv("MOCHI_SCOPE", "openid profile email offline_access")

# Cloudflare Turnstile sitekey（从前端 bundle 提取）
TURNSTILE_SITEKEY = os.getenv("MOCHI_TURNSTILE_SITEKEY", "0x4AAAAAADoOCldXe7KNqkm2")

def _clean_secret(v: str | None) -> str:
    """去掉首尾空白、引号、Bearer 前缀（粘贴 Secret 时常见）。"""
    if not v:
        return ""
    s = v.strip().strip('"').strip("'").strip()
    if s.lower().startswith("bearer "):
        s = s[7:].strip()
    # 去掉误粘贴的换行
    s = re.sub(r"\s+", "", s)
    return s


MOCHI_EMAIL = os.getenv("MOCHI_EMAIL") or os.getenv("MOCHI_USERNAME") or ""
MOCHI_PASSWORD = os.getenv("MOCHI_PASSWORD") or ""
MOCHI_REFRESH_TOKEN = _clean_secret(os.getenv("MOCHI_REFRESH_TOKEN"))
# 可选：浏览器 Network 里 Authorization: Bearer eyJ... 整段 JWT（有过期时间）
MOCHI_ID_TOKEN = _clean_secret(os.getenv("MOCHI_ID_TOKEN") or os.getenv("MOCHI_BEARER_TOKEN"))
MOCHI_SERVER_IDS = os.getenv("MOCHI_SERVER_IDS", "").strip()

# 打码平台（任选其一）
CAPSOLVER_API_KEY = os.getenv("CAPSOLVER_API_KEY") or ""
TWOCAPTCHA_API_KEY = os.getenv("TWOCAPTCHA_API_KEY") or os.getenv("2CAPTCHA_API_KEY") or ""

# Playwright
USE_PLAYWRIGHT = os.getenv("USE_PLAYWRIGHT", "").lower() in ("1", "true", "yes")
IS_GITHUB_ACTIONS = os.getenv("GITHUB_ACTIONS") == "true"
USE_HEADLESS = os.getenv("USE_HEADLESS", "true" if IS_GITHUB_ACTIONS else "false").lower() == "true"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN") or ""
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID") or ""

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36 MochiRenew/1.1"
)

BEIJING = timezone(timedelta(hours=8))
OIDC_RT_KEY = "oidc_rt"


def now_beijing() -> str:
    return datetime.now(BEIJING).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str) -> None:
    print(msg, flush=True)


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def random_state() -> str:
    return secrets.token_urlsafe(24)


def is_jwt(token: str | None) -> bool:
    """JWT 形如 xxx.yyy.zzz（两段点），长度通常 > 100。"""
    if not token or token.count(".") < 2:
        return False
    return len(token) >= 80


def token_help_text() -> str:
    return """
❌ 当前 Secret 里的 token 无效（长度约 32，且不是 JWT）。

官网 API 需要 Authorization: Bearer <id_token>
id_token 是很长的 JWT，一般以 eyJ 开头，长度常常 300+，不是 32 位短串。

========== 请按这个在浏览器里取（不用装 Python）==========

【方法 A · 推荐，复制正在用的 Bearer】
1. 浏览器登录 https://hosting.aida0710.work/dashboard
2. 按 F12 → Network（网络）
3. 刷新页面，点任意一条请求 URL 含 /api/servers 或 /api/
4. 右侧 Headers → Request Headers → Authorization
5. 复制 Bearer 后面整段（以 eyJ 开头的超长字符串）
6. GitHub Secrets 新增/更新：
   - 名字: MOCHI_ID_TOKEN
   - 值: 刚才整段 JWT（不要带 Bearer 前缀，不要截断）

注意: id_token 会过期（通常几小时内）。过期后重新复制一次。
若要长期自动跑，需要正确的 oidc_rt（方法 B）。

【方法 B · localStorage 的 oidc_rt】
1. 登录后 F12 → Console（控制台）粘贴回车:
   (() => { const v=localStorage.getItem('oidc_rt'); console.log('len=', v&&v.length); console.log(v); Object.keys(localStorage).forEach(k=>console.log(k, (localStorage.getItem(k)||'').length)); })()
2. 看 oidc_rt 的 len：
   - 若只有 20~40：说明不是可用的 OIDC refresh，别用
   - 若很长：整段复制到 Secret MOCHI_REFRESH_TOKEN
3. 正确的 refresh 刷新后应出现 id_token（JWT），日志会显示 id_token=300+ 

【方法 C · 打码 + 邮箱密码】
配置 CAPSOLVER_API_KEY 或 TWOCAPTCHA_API_KEY + MOCHI_EMAIL/PASSWORD
""".strip()


def captcha_help_text() -> str:
    return token_help_text()


# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------

class TelegramNotifier:
    def __init__(self) -> None:
        self.bot_token = TELEGRAM_BOT_TOKEN
        self.chat_id = TELEGRAM_CHAT_ID
        self.enabled = bool(self.bot_token and self.chat_id)
        if not self.enabled:
            log("ℹ️ Telegram 未配置，跳过推送")

    def send(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{self.bot_token}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                },
                timeout=REQUEST_TIMEOUT,
            )
            data = r.json()
            if data.get("ok"):
                log("✅ Telegram 发送成功")
                return True
            log(f"❌ Telegram 失败: {data.get('description')}")
            return False
        except Exception as e:
            log(f"❌ Telegram 异常: {e}")
            return False


# ---------------------------------------------------------------------------
# Turnstile 打码
# ---------------------------------------------------------------------------

def solve_turnstile(page_url: str) -> str | None:
    if CAPSOLVER_API_KEY:
        return _solve_turnstile_capsolver(page_url)
    if TWOCAPTCHA_API_KEY:
        return _solve_turnstile_2captcha(page_url)
    return None


def _solve_turnstile_capsolver(page_url: str) -> str | None:
    log("🧩 CapSolver 求解 Turnstile...")
    try:
        create = requests.post(
            "https://api.capsolver.com/createTask",
            json={
                "clientKey": CAPSOLVER_API_KEY,
                "task": {
                    "type": "AntiTurnstileTaskProxyLess",
                    "websiteURL": page_url,
                    "websiteKey": TURNSTILE_SITEKEY,
                },
            },
            timeout=60,
        ).json()
        if create.get("errorId"):
            log(f"❌ CapSolver createTask: {create}")
            return None
        task_id = create.get("taskId")
        for _ in range(60):
            time.sleep(2)
            res = requests.post(
                "https://api.capsolver.com/getTaskResult",
                json={"clientKey": CAPSOLVER_API_KEY, "taskId": task_id},
                timeout=30,
            ).json()
            if res.get("status") == "ready":
                token = (res.get("solution") or {}).get("token")
                if token:
                    log("✅ CapSolver 拿到 captcha token")
                    return token
                break
            if res.get("errorId"):
                log(f"❌ CapSolver result: {res}")
                return None
        log("❌ CapSolver 超时")
        return None
    except Exception as e:
        log(f"❌ CapSolver 异常: {e}")
        return None


def _solve_turnstile_2captcha(page_url: str) -> str | None:
    log("🧩 2Captcha 求解 Turnstile...")
    try:
        r = requests.post(
            "https://2captcha.com/in.php",
            data={
                "key": TWOCAPTCHA_API_KEY,
                "method": "turnstile",
                "sitekey": TURNSTILE_SITEKEY,
                "pageurl": page_url,
                "json": 1,
            },
            timeout=60,
        ).json()
        if r.get("status") != 1:
            log(f"❌ 2Captcha in.php: {r}")
            return None
        req_id = r["request"]
        for _ in range(60):
            time.sleep(3)
            res = requests.get(
                "https://2captcha.com/res.php",
                params={
                    "key": TWOCAPTCHA_API_KEY,
                    "action": "get",
                    "id": req_id,
                    "json": 1,
                },
                timeout=30,
            ).json()
            if res.get("status") == 1:
                log("✅ 2Captcha 拿到 captcha token")
                return res.get("request")
            if res.get("request") != "CAPCHA_NOT_READY":
                log(f"❌ 2Captcha res: {res}")
                return None
        log("❌ 2Captcha 超时")
        return None
    except Exception as e:
        log(f"❌ 2Captcha 异常: {e}")
        return None


# ---------------------------------------------------------------------------
# Mochi client
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

    @property
    def api_bearer(self) -> str | None:
        """
        门户前端 getToken() 返回 id_token（JWT）。
        优先 JWT 形态的 id_token，其次 JWT 形态的 access_token。
        """
        if is_jwt(self.id_token):
            return self.id_token
        if is_jwt(self.access_token):
            return self.access_token
        return self.id_token or self.access_token

    def _set_tokens(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            log(f"⚠️ token 响应不是 JSON 对象: {type(payload)}")
            return

        log(f"ℹ️ token 响应字段: {list(payload.keys())}")

        if payload.get("access_token"):
            self.access_token = str(payload["access_token"]).strip()
        if payload.get("refresh_token"):
            self.refresh_token = str(payload["refresh_token"]).strip()
        if payload.get("id_token"):
            self.id_token = str(payload["id_token"]).strip()

        # 有的实现把 token 放在 data/token 里
        if not self.access_token and payload.get("token"):
            self.access_token = str(payload["token"]).strip()

        log(
            "✅ token 长度: "
            f"id_token={len(self.id_token or '')}(jwt={is_jwt(self.id_token)}) "
            f"access_token={len(self.access_token or '')}(jwt={is_jwt(self.access_token)}) "
            f"refresh_token={len(self.refresh_token or '')}"
        )
        if self.id_token and is_jwt(self.id_token):
            log("✅ 将使用 id_token (JWT) 作为 API Bearer")
        elif self.access_token and is_jwt(self.access_token):
            log("✅ 无 id_token，将使用 access_token (JWT)")
        else:
            log("⚠️ 没有 JWT 形态的 token，API 大概率会 401")

    def save_refresh_token_file(self) -> None:
        if not self.refresh_token:
            return
        try:
            with open("refresh_token.local.txt", "w", encoding="utf-8") as f:
                f.write(self.refresh_token)
            log("💾 已写入 refresh_token.local.txt（勿提交 Git；可设为 Secret MOCHI_REFRESH_TOKEN）")
        except Exception as e:
            log(f"⚠️ 写 refresh_token 文件失败: {e}")

    def refresh_access_token(self) -> bool:
        if not self.refresh_token:
            return False

        rt = self.refresh_token
        log(f"🔄 使用 refresh_token 刷新 (len={len(rt)}, jwt={is_jwt(rt)})...")
        if len(rt) < 40 and not is_jwt(rt):
            log("⚠️ refresh_token 过短，通常不是 OIDC 的 oidc_rt，刷新后也很难拿到 id_token")

        try:
            r = self.session.post(
                f"{AUTH_BASE}/oauth2/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": rt,
                    "client_id": CLIENT_ID,
                    "scope": SCOPE,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "Origin": PORTAL_ORIGIN,
                },
                timeout=REQUEST_TIMEOUT,
            )
            if not r.ok:
                log(f"⚠️ refresh 失败 HTTP {r.status_code}: {r.text[:300]}")
                return False
            try:
                body = r.json()
            except Exception:
                log(f"⚠️ refresh 响应非 JSON: {r.text[:300]}")
                return False

            self._set_tokens(body)

            # 刷新成功但没有 JWT → 视为失败，避免假成功
            if not is_jwt(self.id_token) and not is_jwt(self.access_token):
                log("❌ 刷新结果没有 JWT（id_token/access_token 都不是 eyJ... 长串）")
                log(token_help_text())
                return False

            if body.get("refresh_token") and body["refresh_token"] != rt:
                log("ℹ️ refresh_token 已轮换，请把 refresh_token.local.txt 更新到 Secret")
                self.save_refresh_token_file()
            return True
        except Exception as e:
            log(f"⚠️ refresh 异常: {e}")
            return False

    def login_with_password(self, email: str, password: str, captcha: str | None) -> bool:
        log(f"🔐 邮箱登录: {email}")
        headers = {
            "Content-Type": "application/json",
            "Origin": AUTH_ORIGIN,
            "Referer": f"{AUTH_ORIGIN}/login",
        }
        if captcha:
            headers["x-captcha-response"] = captcha
            log("🧩 已附带 x-captcha-response")
        try:
            r = self.session.post(
                f"{AUTH_BASE}/sign-in/email",
                json={"email": email, "password": password},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if r.status_code >= 400:
                text = r.text[:500]
                log(f"❌ 登录失败 HTTP {r.status_code}: {text}")
                if "CAPTCHA" in text.upper() or "MISSING_RESPONSE" in text:
                    log(captcha_help_text())
                return False
            body: dict[str, Any] = {}
            try:
                body = r.json()
            except Exception:
                pass
            if isinstance(body, dict) and body.get("error"):
                log(f"❌ 登录失败: {body}")
                return False
            log(f"✅ 登录 OK，cookies={list(self.session.cookies.get_dict().keys())}")
            return True
        except Exception as e:
            log(f"❌ 登录异常: {e}")
            return False

    def obtain_token_via_pkce(self) -> bool:
        log("🎫 OIDC PKCE 授权码流程...")
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
                log("❌ 未拿到 authorization code")
                return False
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
            return bool(self.api_bearer)
        except Exception as e:
            log(f"❌ PKCE 异常: {e}")
            return False

    def _follow_authorize_for_code(self, url: str, expected_state: str) -> str | None:
        current = url
        for hop in range(12):
            r = self.session.get(
                current,
                allow_redirects=False,
                timeout=REQUEST_TIMEOUT,
                headers={
                    "Accept": "text/html,application/xhtml+xml,*/*",
                    "Referer": PORTAL_ORIGIN + "/",
                },
            )
            loc = r.headers.get("Location") or r.headers.get("location")
            log(f"  ↳ hop{hop}: HTTP {r.status_code} loc={(loc or '')[:120]}")

            code = self._extract_code(r.url, expected_state)
            if code:
                return code
            if loc:
                if loc.startswith("/"):
                    p = urlparse(current)
                    loc = f"{p.scheme}://{p.netloc}{loc}"
                code = self._extract_code(loc, expected_state)
                if code:
                    return code
                current = loc
                continue

            if r.status_code == 200 and r.text:
                m = re.search(
                    r'url=([^"\'>\s]+)|href=["\']([^"\']*code=[^"\']+)["\']',
                    r.text,
                    re.I,
                )
                if m:
                    candidate = (m.group(1) or m.group(2)).replace("&amp;", "&")
                    if candidate.startswith("/"):
                        p = urlparse(current)
                        candidate = f"{p.scheme}://{p.netloc}{candidate}"
                    code = self._extract_code(candidate, expected_state)
                    if code:
                        return code
                    current = candidate
                    continue
            log(f"❌ 授权中断 status={r.status_code} body[:180]={r.text[:180]!r}")
            return None
        return None

    def _extract_code(self, url: str, expected_state: str) -> str | None:
        if not url or "code=" not in url:
            return None
        qs = parse_qs(urlparse(url).query)
        code = (qs.get("code") or [None])[0]
        state = (qs.get("state") or [None])[0]
        if not code:
            return None
        if state and state != expected_state:
            log(f"⚠️ state 不匹配，仍使用 code")
        log("✅ 已拿到 authorization code")
        return code

    def login_via_playwright(self) -> bool:
        """浏览器登录门户，从 localStorage 取 oidc_rt 再 refresh。"""
        log(f"🌐 Playwright 登录 (headless={USE_HEADLESS})...")
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            log("❌ 未安装 playwright。执行: pip install playwright && playwright install chromium")
            return False

        email = MOCHI_EMAIL
        password = MOCHI_PASSWORD
        if not email or not password:
            log("❌ Playwright 登录需要 MOCHI_EMAIL / MOCHI_PASSWORD")
            return False

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=USE_HEADLESS,
                    args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
                )
                context = browser.new_context(
                    locale="ja-JP",
                    user_agent=USER_AGENT,
                    viewport={"width": 1280, "height": 800},
                )
                page = context.new_page()

                # 从门户入口走完整 OIDC
                page.goto(f"{PORTAL_ORIGIN}/dashboard", wait_until="domcontentloaded", timeout=60000)
                page.wait_for_timeout(1500)

                # 可能已在 auth 登录页，或需点登录
                if "auth.aida0710.work" not in page.url and "login" not in page.url:
                    for sel in (
                        "a[href*='login']",
                        "button:has-text('ログイン')",
                        "a:has-text('ログイン')",
                        "button:has-text('登录')",
                        "a:has-text('Login')",
                    ):
                        try:
                            if page.locator(sel).count():
                                page.locator(sel).first.click(timeout=3000)
                                break
                        except Exception:
                            pass

                page.wait_for_timeout(2000)
                # 等登录表单
                # auth 页: email/username + password
                email_sel = 'input[type="email"], input[name="email"], input[autocomplete="username"], input[name="username"]'
                pass_sel = 'input[type="password"], input[name="password"]'
                try:
                    page.wait_for_selector(email_sel, timeout=20000)
                except Exception:
                    log(f"❌ 未找到登录框，当前 URL: {page.url}")
                    page.screenshot(path="mochi_login_fail.png", full_page=True)
                    browser.close()
                    return False

                page.fill(email_sel, email)
                page.fill(pass_sel, password)
                log("📝 已填邮箱密码，等待 Turnstile...")

                # 等待 turnstile 完成（有 token 后前端才允许提交）
                # 无头环境可能一直等不到
                wait_ms = 90000 if not USE_HEADLESS else 45000
                page.wait_for_timeout(3000)

                # 点登录
                clicked = False
                for sel in (
                    'button[type="submit"]',
                    "button:has-text('ログイン')",
                    "button:has-text('登录')",
                    "button:has-text('Sign in')",
                    "button:has-text('Log in')",
                ):
                    try:
                        loc = page.locator(sel)
                        if loc.count():
                            loc.first.click(timeout=5000)
                            clicked = True
                            break
                    except Exception:
                        continue
                if not clicked:
                    page.keyboard.press("Enter")

                # 等跳回门户并出现 refresh token
                deadline = time.time() + (wait_ms / 1000)
                rt = None
                while time.time() < deadline:
                    try:
                        if PORTAL_ORIGIN in page.url:
                            rt = page.evaluate(f"() => localStorage.getItem('{OIDC_RT_KEY}')")
                            if rt:
                                break
                    except Exception:
                        pass
                    page.wait_for_timeout(1000)

                if not rt:
                    # 再扫一遍 storage
                    try:
                        rt = page.evaluate(
                            """() => {
                              for (const k of Object.keys(localStorage)) {
                                if (k.includes('oidc') || k.includes('refresh') || k.includes('rt')) {
                                  const v = localStorage.getItem(k);
                                  if (v && v.length > 20) return v;
                                }
                              }
                              return localStorage.getItem('oidc_rt');
                            }"""
                        )
                    except Exception:
                        pass

                page.screenshot(path="mochi_after_login.png", full_page=True)
                final_url = page.url
                browser.close()

                if not rt:
                    log(f"❌ Playwright 未拿到 refresh_token，URL={final_url}")
                    log("   无头模式常被 Turnstile 拦截，请本机 USE_HEADLESS=false 再跑，或配置打码/Refresh Token")
                    log(captcha_help_text())
                    return False

                self.refresh_token = rt
                log("✅ Playwright 已拿到 refresh_token")
                self.save_refresh_token_file()
                return self.refresh_access_token()
        except Exception as e:
            log(f"❌ Playwright 异常: {e}")
            return False

    def ensure_auth(self) -> bool:
        # 0) 直接使用浏览器复制的 id_token / Bearer JWT
        if MOCHI_ID_TOKEN:
            log(f"🔑 使用 MOCHI_ID_TOKEN (len={len(MOCHI_ID_TOKEN)}, jwt={is_jwt(MOCHI_ID_TOKEN)})")
            if not is_jwt(MOCHI_ID_TOKEN):
                log("❌ MOCHI_ID_TOKEN 不是 JWT（应以 eyJ 开头、含两个点、很长）")
                log(token_help_text())
                return False
            self.id_token = MOCHI_ID_TOKEN
            return True

        # 1) refresh → 必须拿到 JWT
        if self.refresh_token:
            if self.refresh_access_token():
                return True
            log("⚠️ refresh 路径失败，尝试其它登录方式...")

        has_password = bool(MOCHI_EMAIL and MOCHI_PASSWORD)
        has_solver = bool(CAPSOLVER_API_KEY or TWOCAPTCHA_API_KEY)

        # 2) 密码 + 打码
        if has_password and has_solver:
            captcha = solve_turnstile(f"{AUTH_ORIGIN}/login")
            if captcha and self.login_with_password(MOCHI_EMAIL, MOCHI_PASSWORD, captcha):
                if self.obtain_token_via_pkce():
                    if is_jwt(self.api_bearer):
                        self.save_refresh_token_file()
                        return True
                    log("❌ PKCE 完成后仍无 JWT")

        # 3) Playwright
        use_pw = USE_PLAYWRIGHT or (has_password and not IS_GITHUB_ACTIONS and not has_solver)
        if has_password and use_pw:
            if self.login_via_playwright() and is_jwt(self.api_bearer):
                return True

        # 4) 纯密码（预计失败）
        if has_password and not has_solver and not self.refresh_token:
            log("⚠️ 尝试无验证码密码登录（预计失败）...")
            if self.login_with_password(MOCHI_EMAIL, MOCHI_PASSWORD, None):
                if self.obtain_token_via_pkce() and is_jwt(self.api_bearer):
                    self.save_refresh_token_file()
                    return True

        log(token_help_text())
        return False

    def _api(
        self,
        method: str,
        path: str,
        bearer: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        token = bearer or self.api_bearer
        if not token:
            raise RuntimeError("no bearer token (need id_token or access_token)")
        headers = {
            **kwargs.pop("headers", {}),
            "Authorization": f"Bearer {token}",
        }
        return self.session.request(
            method,
            f"{API_BASE}{path}",
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            **kwargs,
        )

    def _api_with_fallback(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """
        优先 id_token；若 401 再试 access_token；仍 401 则 refresh 后重试。
        """
        candidates: list[str] = []
        if self.id_token:
            candidates.append(self.id_token)
        if self.access_token and self.access_token not in candidates:
            candidates.append(self.access_token)

        last: requests.Response | None = None
        for i, tok in enumerate(candidates):
            kind = "id_token" if tok == self.id_token else "access_token"
            r = self._api(method, path, bearer=tok, **kwargs)
            last = r
            if r.status_code != 401:
                if i > 0:
                    log(f"ℹ️ 使用 {kind} 调用成功")
                return r
            log(f"⚠️ {kind} 返回 401，尝试其它 token...")

        if self.refresh_access_token():
            r = self._api(method, path, **kwargs)
            return r

        if last is None:
            raise RuntimeError("no token to call API")
        return last

    def list_servers(self) -> list[dict[str, Any]]:
        log("📋 获取服务器列表...")
        r = self._api_with_fallback("GET", "/servers")
        if not r.ok:
            raise RuntimeError(f"list servers failed: {r.status_code} {r.text[:300]}")
        data = r.json()
        if isinstance(data, list):
            servers = data
        elif isinstance(data, dict):
            servers = data.get("servers") or data.get("data") or data.get("items") or []
        else:
            servers = []
        log(f"✅ 共 {len(servers)} 台服务器")
        return servers

    def extend_uptime(self, server_id: str) -> tuple[bool, str]:
        r = self._api_with_fallback("POST", f"/servers/{server_id}/extend-uptime")
        if r.ok:
            try:
                return True, json.dumps(r.json(), ensure_ascii=False)[:200]
            except Exception:
                return True, (r.text[:200] or "ok")
        try:
            err = r.json()
            msg = err.get("error") or err.get("message") or r.text[:200]
        except Exception:
            msg = r.text[:200]
        return False, f"HTTP {r.status_code}: {msg}"


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
    name = s.get("name") or "?"
    sid = s.get("id") or s.get("serverId") or "?"
    status = s.get("status") or "?"
    return f"{name} ({sid}) [{status}]"


def build_report(results: list[tuple[str, bool, str]], ok_count: int, fail_count: int) -> str:
    lines = [
        f"**最后运行时间**: `{now_beijing()}`",
        "",
        f"**成功**: {ok_count}  **失败**: {fail_count}",
        "",
    ]
    for label, ok, detail in results:
        lines.append(f"- {'✅' if ok else '❌'} `{label}` — {detail}")
    return "\n".join(lines) + "\n"


def build_tg(results: list[tuple[str, bool, str]], ok_count: int, fail_count: int) -> str:
    msg = (
        f"<b>🍡 Mochi Hosting 续期</b>\n\n"
        f"🕐 <code>{now_beijing()}</code>\n"
        f"📊 成功 {ok_count} / 失败 {fail_count}\n\n"
    )
    for label, ok, detail in results:
        safe = detail.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        msg += f"{'✅' if ok else '❌'} <code>{label}</code>\n   {safe}\n"
    return msg


def main() -> int:
    log("=" * 60)
    log("Mochi Hosting 自动续期 (extend-uptime)")
    log(f"时间: {now_beijing()}")
    log(f"API: {API_BASE}")
    log(f"Auth: {AUTH_BASE}")
    log(f"有 refresh_token: {bool(MOCHI_REFRESH_TOKEN)}")
    log(f"打码: capsolver={bool(CAPSOLVER_API_KEY)} 2captcha={bool(TWOCAPTCHA_API_KEY)}")
    log(f"Playwright: use={USE_PLAYWRIGHT} headless={USE_HEADLESS} gha={IS_GITHUB_ACTIONS}")
    log("=" * 60)

    if not MOCHI_ID_TOKEN and not MOCHI_REFRESH_TOKEN and not (MOCHI_EMAIL and MOCHI_PASSWORD):
        log("❌ 请配置 MOCHI_ID_TOKEN，或 MOCHI_REFRESH_TOKEN，或 邮箱密码+打码")
        log(token_help_text())
        return 1

    if MOCHI_REFRESH_TOKEN and len(MOCHI_REFRESH_TOKEN) < 40:
        log(
            f"⚠️ MOCHI_REFRESH_TOKEN 长度只有 {len(MOCHI_REFRESH_TOKEN)}，"
            "很像复制错了（正确 oidc_rt 通常更长）"
        )

    client = MochiClient()
    tg = TelegramNotifier()

    if not client.ensure_auth():
        tg.send(
            f"<b>🍡 Mochi 续期失败</b>\n\n"
            f"🕐 <code>{now_beijing()}</code>\n"
            f"❌ 认证失败（多半是 Turnstile）。请配置 MOCHI_REFRESH_TOKEN。"
        )
        return 1

    try:
        servers = client.list_servers()
    except Exception as e:
        log(f"❌ 获取服务器列表失败: {e}")
        tg.send(
            f"<b>🍡 Mochi 续期失败</b>\n\n"
            f"🕐 <code>{now_beijing()}</code>\n"
            f"❌ 列表失败: {e}"
        )
        return 1

    targets = filter_servers(servers)
    if not targets:
        log("⚠️ 没有服务器")
        with open("report-notify.md", "w", encoding="utf-8") as f:
            f.write(build_report([], 0, 0) + "\n(无服务器)\n")
        tg.send(f"<b>🍡 Mochi 续期</b>\n\n🕐 <code>{now_beijing()}</code>\n⚠️ 无服务器")
        return 0

    results: list[tuple[str, bool, str]] = []
    ok_count = fail_count = 0
    for s in targets:
        sid = str(s.get("id") or s.get("serverId") or "")
        label = server_label(s)
        if not sid:
            results.append((label, False, "缺少 id"))
            fail_count += 1
            continue
        log(f"🔄 续期: {label}")
        ok, detail = client.extend_uptime(sid)
        log(f"  {'✅' if ok else '❌'} {detail}")
        results.append((label, ok, detail))
        if ok:
            ok_count += 1
        else:
            fail_count += 1
        time.sleep(0.5)

    report = build_report(results, ok_count, fail_count)
    with open("report-notify.md", "w", encoding="utf-8") as f:
        f.write(report)
    log("📝 report-notify.md 已写入")
    log(report)
    client.save_refresh_token_file()
    tg.send(build_tg(results, ok_count, fail_count))
    return 1 if fail_count and not ok_count else 0


if __name__ == "__main__":
    sys.exit(main())
