#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GLaDOS 自动签到 —— 浏览器版（应对 Cloudflare Turnstile）

背景
----
2026-11-13 起 GLaDOS 的 /api/user/checkin 强制 Turnstile 校验。纯 requests
提交一律返回：

    Cloudflare verification failed. Nothing was recorded — please retry.

（服务端形如 {"code":4,"reason":"turnstile","message":"..."}）

思路
----
Turnstile token 只能由真实浏览器在低风险 IP 上现场签发，且 SDK 必须由
官方页面自己加载（自插 script 会被页面的 CSP 拦掉 -> no-sdk）。

因此本脚本不自己实现协议，而是：
  1. 启动真实 Chromium（patchright 反检测分支），注入 Cookie 打开签到页
  2. 定位页面自带的 "Checkin" 按钮并点击
  3. 监听 POST /api/user/checkin 的响应拿到结果
  4. 若弹出交互式 Turnstile，自动点击其 checkbox
  5. 用同源 fetch 补查积分/剩余天数，并按阈值兑换

环境变量
--------
  COOKIES        必填。多账号用 ||| 或换行分隔（与 checkin.py 一致）
  EXCHANGE_PLAN  可选。plan100 / plan200 / plan500，默认关闭
  HEADLESS       默认 0（有头，配 xvfb），1 = 无头
  DEBUG_SHOT     默认 1，失败时截图到 debug/
  ACCOUNT_DELAY  账号间隔秒数，默认 4
  ALLOW_FAIL     默认 0；设 1 则全部失败时也返回 0（不刷红叉）

退出码
------
  0  至少一个账号签到成功/已签到
  1  全部失败
  2  配置或环境错误
"""

from __future__ import annotations

import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from patchright.sync_api import sync_playwright  # 反检测分支，优先
    ENGINE = "patchright"
except ImportError:
    try:
        from playwright.sync_api import sync_playwright
        ENGINE = "playwright"
    except ImportError:
        print("[FATAL] 需要 patchright 或 playwright：pip install patchright",
              file=sys.stderr)
        raise SystemExit(2)

CHECKIN_URL = "https://glados.cloud/console/checkin"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

# 官方页面上实测的兑换档位（2026-11-16 截图确认）
EXCHANGE_PLANS = {
    "plan100": {"points": 100, "days": 10},
    "plan200": {"points": 200, "days": 30},
    "plan500": {"points": 500, "days": 100},
}

# 在页面加载前注入：记录前端提交签到请求时的真实 body（含 tsState / turnstile 字段）
JS_HOOK = r"""
window.__wbPosts = [];
(function () {
  const orig = window.fetch;
  window.fetch = function () {
    try {
      const a = arguments;
      const u = a[0] && (a[0].url || a[0]);
      const o = a[1] || {};
      if (String(u).indexOf('/api/user/checkin') >= 0 &&
          String(o.method || 'GET').toUpperCase() === 'POST') {
        window.__wbPosts.push({ url: String(u), body: o.body || null });
      }
    } catch (e) {}
    return orig.apply(this, arguments);
  };
})();
"""

# 同源查询：积分 / 剩余天数 / 邮箱
JS_QUERY = r"""
async () => {
  const out = {};
  try {
    const a = await fetch('/api/user/status', {credentials:'include'});
    const j = await a.json();
    const d = j.data || j;
    out.days  = (d.leftDays !== undefined) ? d.leftDays : null;
    out.email = d.email || null;
  } catch (e) { out.statusErr = String(e); }
  try {
    const b = await fetch('/api/user/points', {credentials:'include'});
    const j2 = await b.json();
    out.points = (j2.points !== undefined) ? j2.points
               : ((j2.data && j2.data.points !== undefined) ? j2.data.points : null);
  } catch (e) { out.pointsErr = String(e); }
  return out;
}
"""

JS_EXCHANGE = r"""
async (plan) => {
  try {
    const r = await fetch('/api/user/exchange', {
      method: 'POST', credentials: 'include',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'planType=' + encodeURIComponent(plan)
    });
    return await r.json();
  } catch (e) { return { error: String(e) }; }
}
"""


# ---------------------------------------------------------------------------
# Cookie 工具
# ---------------------------------------------------------------------------
_SESS_KEY_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9_.-]+):sess$")
_SIG_KEY_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9_.-]+):sess\.sig$")


def normalize_cookie(cookie: str) -> str:
    c = (cookie or "").strip()
    while len(c) >= 2 and c[0] == c[-1] and c[0] in ('"', "'"):
        c = c[1:-1].strip()
    if c.lower().startswith("cookie:"):
        c = c[len("cookie:"):].strip()
    return c


def split_cookies(raw: str) -> List[str]:
    return [c for c in (normalize_cookie(p) for p in re.split(r"\|\|\||[&\n]", raw or "")) if c]


def validate_cookie(cookie: str):
    c = normalize_cookie(cookie)
    if not c:
        return False, "Cookie 为空"
    groups: Dict[str, Dict[str, bool]] = {}
    for part in c.split(";"):
        key = part.strip().split("=", 1)[0].strip()
        if not key:
            continue
        m = _SIG_KEY_RE.match(key)
        if m:
            groups.setdefault(m.group("prefix"), {}).setdefault("sig", True)
            continue
        m = _SESS_KEY_RE.match(key)
        if m:
            groups.setdefault(m.group("prefix"), {}).setdefault("sess", True)
    for prefix, flags in groups.items():
        if flags.get("sess") and flags.get("sig"):
            return True, prefix
    return False, "缺少成对的 <前缀>:sess 与 <前缀>:sess.sig"


def to_playwright_cookies(cookie: str) -> List[Dict[str, Any]]:
    out = []
    for part in normalize_cookie(cookie).split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        name, value = name.strip(), value.strip()
        if not name:
            continue
        out.append({
            "name": name, "value": value,
            "domain": ".glados.cloud", "path": "/",
            "secure": True, "httpOnly": name.endswith(":sess"),
            "sameSite": "Lax",
        })
    return out


def mask_email(email: Optional[str]) -> str:
    if not email or "@" not in email:
        return email or "-"
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        return local[0] + "***@" + domain
    return local[:2] + "***@" + domain


def log(msg: str) -> None:
    print(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} | {msg}", flush=True)


# ---------------------------------------------------------------------------
# 点击页面按钮完成签到
# ---------------------------------------------------------------------------
BUTTON_SELECTORS = [
    'button:has-text("Checkin")',
    'button:has-text("Check in")',
    'button:has-text("签到")',
    'a:has-text("Checkin")',
]

ALREADY_RE = re.compile(r"checked\s*in|已签到|已完成", re.I)


def find_checkin_button(page):
    """在页面上找签到按钮；返回 (locator, label) 或 (None, '')。"""
    for sel in BUTTON_SELECTORS:
        try:
            loc = page.locator(sel)
            n = loc.count()
            for i in range(n):
                el = loc.nth(i)
                try:
                    if not el.is_visible():
                        continue
                    label = (el.inner_text(timeout=2000) or "").strip()
                except Exception:
                    continue
                # 排除 "Checked in" 之外误匹配到的导航项
                if label:
                    return el, label
        except Exception:
            continue
    return None, ""


def try_click_turnstile(page) -> str:
    """
    尝试通过 Turnstile 的交互式 checkbox。

    appearance="interaction-only" 的 widget 是右上角浮层。Playwright 可跨域
    操作 iframe（浏览器进程层面，不受同源策略限制），因此优先 iframe 内语义
    点击，其次页面坐标精确点击（checkbox 在 widget 左侧约 16px、垂直居中）。

    返回命中的方式描述，未命中返回空串（便于日志诊断）。
    """
    for fr in page.frames:
        if "challenges.cloudflare.com" not in (fr.url or ""):
            continue
        # 1) iframe 内语义选择器
        for sel in ('input[type="checkbox"]', '[role="checkbox"]',
                    '#challenge-stage input', 'label'):
            try:
                loc = fr.locator(sel).first
                if loc.count() > 0:
                    loc.click(timeout=1200, force=True)
                    return f"frame:{sel}"
            except Exception:
                continue
        # 2) iframe 内坐标（body 可能很小，force 跳过可操作性检查）
        for pos in ((22, 28), (28, 32)):
            try:
                fr.click("body", position={"x": pos[0], "y": pos[1]},
                         timeout=1000, force=True)
                return f"frame-xy:{pos}"
            except Exception:
                continue

    # 3) 页面坐标兜底：iframe 外框左上 + 16px 处即 checkbox
    try:
        el = page.query_selector('iframe[src*="challenges.cloudflare.com"]')
        if el:
            bb = el.bounding_box()
            if bb and bb.get("width"):
                page.mouse.click(bb["x"] + 16, bb["y"] + bb["height"] / 2)
                return f"page-xy:{int(bb['x']+16)},{int(bb['y']+bb['height']/2)}"
    except Exception:
        pass
    return ""


def do_checkin(page, index: int) -> Dict[str, Any]:
    captured: Dict[str, Any] = {}
    errors: List[str] = []

    def on_response(resp):
        try:
            if "/api/user/checkin" in resp.url and resp.request.method == "POST":
                captured["resp"] = resp
        except Exception:
            pass

    def on_failed(req):
        try:
            if "/api/user/checkin" in req.url:
                errors.append(f"{req.failure}")
        except Exception:
            pass

    page.on("response", on_response)
    page.on("requestfailed", on_failed)

    btn, label = find_checkin_button(page)
    if btn is None:
        return {"ok": False, "stage": "no-button", "message": "页面上未找到 Checkin 按钮"}

    log(f"  账号 {index} 找到按钮: {label!r}")
    if ALREADY_RE.search(label):
        return {"ok": True, "stage": "already", "message": f"按钮显示 {label!r}"}

    try:
        btn.scroll_into_view_if_needed(timeout=5000)
        btn.click(timeout=20000)
        log(f"  账号 {index} 已点击，等待结果...")
    except Exception as e:
        return {"ok": False, "stage": "click-fail", "message": f"{type(e).__name__}: {e}"}

    deadline = time.time() + 90
    ts_attempts = 0
    hits: List[str] = []
    while time.time() < deadline:
        if captured.get("resp") is not None:
            break
        # 交互式 Turnstile：高频重试（前端可能只等 2.5s 就放弃提交）
        if ts_attempts < 40:
            how = try_click_turnstile(page)
            if how:
                ts_attempts += 1
                if len(hits) < 3:
                    hits.append(how)
                if ts_attempts in (1, 5, 15, 30):
                    log(f"  账号 {index} Turnstile 点击 x{ts_attempts} ({how})")
        page.wait_for_timeout(250)

    resp = captured.get("resp")
    if resp is None:
        msg = "未捕获到签到请求"
        if errors:
            msg += f"（请求失败: {errors[0]}）"
        return {"ok": False, "stage": "timeout", "message": msg}

    try:
        j = resp.json()
    except Exception:
        try:
            body = resp.text()[:200]
        except Exception:
            body = "<无响应体>"
        return {"ok": False, "stage": "non-json", "message": body}

    code = j.get("code")
    reason = j.get("reason")
    message = j.get("message") or ""
    ok = code in (0, 1)
    rec = {
        "ok": ok,
        "stage": "done" if ok else f"reject:{reason or code}",
        "code": code,
        "message": message,
        "result": j,
        "ts_hits": hits,
    }
    # 诊断：读出前端真正提交的 body，判断 turnstile 字段是否存在、tsState 是什么
    try:
        posts = page.evaluate("window.__wbPosts || []")
        if posts:
            import json as _json
            raw = posts[-1].get("body") or ""
            rec["post_body"] = str(raw)[:300]
            try:
                b = _json.loads(raw)
                rec["ts_state"] = b.get("tsState")
                rec["has_turnstile"] = bool(b.get("turnstile"))
            except Exception:
                pass
    except Exception:
        pass
    if reason == "turnstile":
        rec["message"] = message or "Turnstile 校验未通过"
    return rec


# ---------------------------------------------------------------------------
# 单账号
# ---------------------------------------------------------------------------
def checkin_account(browser, cookie: str, index: int, total: int,
                    plan: Optional[str], shot_dir: str) -> Dict[str, Any]:
    ok_fmt, prefix = validate_cookie(cookie)
    rec: Dict[str, Any] = {
        "index": index, "prefix": prefix if ok_fmt else "-",
        "ok": False, "stage": "init", "message": "",
        "points": None, "days": None, "exchange": None, "email": None,
    }
    if not ok_fmt:
        rec["stage"] = "cookie-invalid"
        rec["message"] = prefix
        log(f"账号 {index}/{total} Cookie 结构不合法：{prefix}")
        return rec

    log(f"账号 {index}/{total} 启动会话 (前缀 {prefix})...")
    ctx = None
    try:
        ctx = browser.new_context(
            user_agent=UA, locale="zh-CN", timezone_id="Asia/Shanghai",
            viewport={"width": 1366, "height": 900},
            extra_http_headers={"accept-language": "zh-CN,zh;q=0.9,en;q=0.8"},
        )
        ctx.add_init_script(JS_HOOK)
        ctx.add_cookies(to_playwright_cookies(cookie))
        page = ctx.new_page()
        page.goto(CHECKIN_URL, wait_until="domcontentloaded", timeout=60000)

        # 等前端渲染出签到面板（有按钮即视为就绪）
        ready = False
        for _ in range(30):
            if find_checkin_button(page)[0] is not None:
                ready = True
                break
            page.wait_for_timeout(500)
        if not ready:
            page.wait_for_timeout(3000)  # 再给一次机会
            ready = find_checkin_button(page)[0] is not None

        if not ready:
            rec["stage"] = "page-not-ready"
            rec["message"] = "页面未渲染出签到面板（可能 Cookie 失效或页面改版）"
        else:
            r = do_checkin(page, index)
            rec.update({
                "ok": bool(r.get("ok")),
                "stage": r.get("stage") or "done",
                "message": r.get("message") or "",
                "result": r.get("result"),
                "ts_state": r.get("ts_state"),
                "has_turnstile": r.get("has_turnstile"),
                "ts_hits": r.get("ts_hits"),
                "post_body": r.get("post_body"),
            })
            if r.get("ts_state") is not None or r.get("has_turnstile") is not None:
                log(f"  账号 {index} 前端提交: tsState={r.get('ts_state')} "
                    f"turnstile字段={'有' if r.get('has_turnstile') else '无'} "
                    f"点击方式={r.get('ts_hits')}")

            # 同源补查积分/天数（不依赖 UI 文本）
            try:
                q = page.evaluate(JS_QUERY)
                rec["points"] = q.get("points")
                rec["days"] = q.get("days")
                rec["email"] = mask_email(q.get("email"))
            except Exception as e:
                log(f"  账号 {index} 查询失败: {type(e).__name__}")

            # 可选兑换（达阈值才执行，一次性消耗）
            if plan:
                need = EXCHANGE_PLANS[plan]["points"]
                pts = rec.get("points")
                if pts is None:
                    rec["exchange"] = {"skipped": True, "reason": "points-unknown"}
                elif int(float(pts)) < need:
                    rec["exchange"] = {"skipped": True,
                                       "reason": f"{pts}/{need} 积分不足"}
                else:
                    try:
                        rec["exchange"] = page.evaluate(JS_EXCHANGE, plan)
                        log(f"  账号 {index} 兑换结果: {rec['exchange']}")
                    except Exception as e:
                        rec["exchange"] = {"error": f"{type(e).__name__}: {e}"}

        # 失败留证
        if not rec["ok"] and os.getenv("DEBUG_SHOT", "1") == "1":
            try:
                os.makedirs(shot_dir, exist_ok=True)
                p = os.path.join(shot_dir, f"fail_{index}.png")
                page.screenshot(path=p)
                log(f"  账号 {index} 截图: {p}")
            except Exception:
                pass

    except Exception as e:
        rec["stage"] = "exception"
        rec["message"] = f"{type(e).__name__}: {e}"
        log(f"账号 {index} 异常: {rec['message']}")
    finally:
        if ctx is not None:
            try:
                ctx.close()
            except Exception:
                pass
    return rec


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    cookies = split_cookies(os.getenv("COOKIES", ""))
    if not cookies:
        log("[FATAL] 未配置 COOKIES")
        return 2

    # 调试用：只跑前 N 个账号
    limit = int(os.getenv("LIMIT_ACCOUNTS", "0") or 0)
    if limit > 0:
        cookies = cookies[:limit]
        log(f"[DEBUG] LIMIT_ACCOUNTS={limit}，仅处理前 {len(cookies)} 个账号")

    plan = (os.getenv("EXCHANGE_PLAN") or os.getenv("GLADOS_EXCHANGE_PLAN") or "").strip()
    if plan and plan not in EXCHANGE_PLANS:
        log(f"[WARN] EXCHANGE_PLAN={plan} 不合法，已忽略")
        plan = None

    headless = os.getenv("HEADLESS", "0") == "1"
    delay = float(os.getenv("ACCOUNT_DELAY", "4"))
    shot_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug")

    log(f"引擎={ENGINE} headless={headless} 账号数={len(cookies)} 兑换={'开启' if plan else '关闭'}")

    records: List[Dict[str, Any]] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=headless,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--lang=zh-CN",
            ],
        )
        try:
            for i, ck in enumerate(cookies, 1):
                records.append(checkin_account(browser, ck, i, len(cookies), plan, shot_dir))
                if i < len(cookies) and delay > 0:
                    time.sleep(delay)
        finally:
            try:
                browser.close()
            except Exception:
                pass

    # ---------------- 汇总 ----------------
    print("\n" + "=" * 66)
    ok_cnt = 0
    for r in records:
        if r["ok"]:
            ok_cnt += 1
        flag = "OK  " if r["ok"] else "FAIL"
        pts = f"{r['points']} 分" if r["points"] is not None else "-"
        dys = f"{r['days']} 天" if r["days"] is not None else "-"
        ex = ""
        e = r.get("exchange")
        if isinstance(e, dict):
            if e.get("skipped"):
                ex = f" | 兑换跳过({e.get('reason')})"
            elif e.get("code") == 0:
                ex = " | 兑换成功"
            elif e.get("error"):
                ex = " | 兑换异常"
            elif e.get("code") is not None:
                ex = f" | 兑换失败({str(e.get('message'))[:30]})"
        print(f"[{flag}] #{r['index']} {r.get('email') or '-'} | {pts} | {dys} | "
              f"{r['stage']}{ex}")
        if not r["ok"] and r.get("message"):
            print(f"        {r['message'][:160]}")
        if r.get("ts_state") is not None or r.get("has_turnstile") is not None:
            print(f"        tsState={r.get('ts_state')} | "
                  f"turnstile={'有' if r.get('has_turnstile') else '无'} | "
                  f"点击={r.get('ts_hits')}")
    print("=" * 66)
    log(f"成功 {ok_cnt}/{len(records)}")

    # ---------------- 推送（复用 checkin.py 的实现） ----------------
    try:
        from checkin import push_all  # noqa: WPS433
        lines = []
        for r in records:
            mark = "✅" if r["ok"] else "❌"
            pts = f"{r['points']}分" if r["points"] is not None else "-"
            dys = f"{r['days']}天" if r["days"] is not None else "-"
            lines.append(f"{mark} #{r['index']} {r.get('email') or '-'} | {pts} | {dys} | {r['stage']}")
        ok_ch, total_ch = push_all(f"GLaDOS 签到 {ok_cnt}/{len(records)} 成功", "\n".join(lines))
        log(f"推送完成 {ok_ch}/{total_ch}")
    except Exception as e:  # noqa: BLE001
        log(f"推送跳过: {type(e).__name__}: {e}")

    if ok_cnt == 0:
        if os.getenv("ALLOW_FAIL", "0") == "1":
            log("ALLOW_FAIL=1，退出码置 0")
            return 0
        log("全部账号签到失败")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
