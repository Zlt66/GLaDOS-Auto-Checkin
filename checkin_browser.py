#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GLaDOS 自动签到 —— 浏览器版（应对 Cloudflare Turnstile）

背景
----
2026-11-13 起，GLaDOS 的 /api/user/checkin 新增 Cloudflare Turnstile 人机验证。
纯 HTTP（requests）无法生成 turnstile token，签到一律返回：

    Cloudflare verification failed. Nothing was recorded — please retry.

服务端该响应形如 {"code":4,"reason":"turnstile","message":"..."}。

修复思路
--------
不点 UI 按钮（选择器易变），而是在已登录的浏览器页面上下文里直接执行
官方前端的完整协议（2026-11-16 从 https://glados.cloud 前端 bundle 逆向得出）：

  1. GET  /api/user/checkin/challenge
         -> { code:0, nonce:<str>, ttl:<ms>, turnstile:<sitekey> }
  2. window.turnstile.render(box, {
         sitekey, action:"checkin", cData:nonce, appearance:"interaction-only" })
         -> token（低风险静默通过，高风险时才弹交互）
  3. 等待 >= 2500ms（服务端校验 challenge 生成到提交的时间差）
  4. proof = sha256(nonce + "." + "glados-observe-v1")   # 小写 hex
  5. POST /api/user/checkin
         { token:"glados.cloud", nonce, proof, tsState, turnstile:<token> }

缺 turnstile 字段 => 服务端返回 reason:"turnstile"，即上面那句报错。

环境变量
--------
  COOKIES        必填。多账号用 ||| 或换行分隔（与 checkin.py 一致）
                 格式：gld:sess=xxx; gld:sess.sig=yyy
  EXCHANGE_PLAN  可选。plan100 / plan200 / plan500；仅在页面内兑换，默认关闭
  HEADLESS       默认 0。0 = 有头（配 xvfb），1 = 无头
  DEBUG_SHOT     默认 1。失败时截图到 debug/
  ACCOUNT_DELAY  账号间隔秒数，默认 4，避免同 IP 短时高频

退出码
------
  0  至少一个账号签到成功（或已签到）
  1  全部失败
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
        print("[FATAL] 需要 patchright 或 playwright。安装：pip install patchright",
              file=sys.stderr)
        raise SystemExit(2)

CHECKIN_URL = "https://glados.cloud/console/checkin"
ORIGIN = "https://glados.cloud"
PROOF_SUFFIX = "glados-observe-v1"   # 前端 bundle 中字符码混淆还原所得
TURNSTILE_SDK = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

EXCHANGE_PLANS = {
    "plan100": {"points": 100, "days": 10},
    "plan200": {"points": 200, "days": 25},
    "plan500": {"points": 500, "days": 70},
}

# ---------------------------------------------------------------------------
# 页面内执行的签到逻辑（不 await，把结果写进 window.__wb，由 Python 侧轮询）
# ---------------------------------------------------------------------------
JS_BOOT = r"""
(args) => {
  const suffix = args.suffix;
  const plan   = args.plan || null;
  window.__wb = { done: false, ok: false, stage: 'init', log: [], result: null,
                  points: null, days: null, exchange: null };

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const push  = s => { try { window.__wb.log.push(s); } catch(e){} };

  (async () => {
    const W = window.__wb;
    try {
      // 0) 确保 Turnstile SDK 就绪
      if (!window.turnstile) {
        await new Promise((res, rej) => {
          const s = document.createElement('script');
          s.src = args.sdk; s.async = true;
          s.onload = res;
          s.onerror = () => rej(new Error('sdk-load-failed'));
          document.head.appendChild(s);
          setTimeout(() => rej(new Error('sdk-timeout')), 25000);
        }).catch(e => push('sdk:' + e.message));
      }
      if (!window.turnstile) { W.stage = 'no-sdk'; W.done = true; return; }
      push('sdk-ready');

      // 1) 取 challenge
      const cr = await fetch('/api/user/checkin/challenge',
                             { credentials:'include', headers:{accept:'application/json'} });
      const cj = await cr.json();
      W.challenge = cj;
      if (cj.code !== 0) { W.stage = 'challenge-fail'; W.done = true; return; }
      const nonce   = cj.nonce || (cj.data && cj.data.nonce);
      const sitekey = cj.turnstile || (cj.data && cj.data.turnstile);
      if (!nonce || !sitekey) { W.stage = 'challenge-malformed'; W.done = true; return; }
      push('challenge-ok');

      // 2) 渲染 Turnstile 换 token（interaction-only：低风险静默通过）
      const box = document.createElement('div');
      box.id = '__wb_ts_box';
      box.style.cssText = 'position:fixed;left:8px;top:8px;z-index:2147483647';
      document.body.appendChild(box);

      W.tsToken = null;
      try {
        window.turnstile.render(box, {
          sitekey: sitekey,
          action: 'checkin',
          cData: nonce,
          appearance: 'interaction-only',
          theme: 'light',
          callback: t => { W.tsToken = t; push('ts-token'); },
          'error-callback': e => push('ts-error:' + (e || '')),
          'timeout-callback': () => push('ts-timeout'),
        });
      } catch (e) {
        push('ts-render-throw:' + e.message);
      }
      W.stage = 'waiting-turnstile';

      // 最多等 50 秒；期间 Python 侧会尝试点击交互式 checkbox
      const t0 = Date.now();
      while (!W.tsToken && Date.now() - t0 < 50000) { await sleep(400); }
      if (!W.tsToken) { W.stage = 'turnstile-timeout'; W.done = true; return; }
      push('turnstile-got');

      // 3) 服务端要求 challenge 生成后至少 2500ms
      await sleep(2600);

      // 4) proof = sha256(nonce + "." + suffix)
      const buf = await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(nonce + '.' + suffix));
      const proof = Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      // 5) 提交
      const pr = await fetch('/api/user/checkin', {
        method: 'POST', credentials: 'include',
        headers: { 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({
          token: location.hostname,   // 官方前端即 window.location.hostname
          nonce, proof, tsState: 'ok', turnstile: W.tsToken
        })
      });
      const pj = await pr.json();
      W.result = pj;
      W.ok  = (pj.code === 0) || (pj.code === 1);
      W.stage = W.ok ? 'done' : ('server-reject:' + (pj.reason || pj.code));
      push('posted');

      // 6) 附带查询积分与剩余天数（便于推送内容）
      try {
        const sr = await fetch('/api/user/status', {credentials:'include'});
        const sj = await sr.json();
        const d = sj.data || sj;
        W.days = (d.leftDays !== undefined) ? d.leftDays : null;
        if (d.email) W.email = d.email;
      } catch (e) {}
      try {
        const qr = await fetch('/api/user/points', {credentials:'include'});
        const qj = await qr.json();
        W.points = (qj.points !== undefined) ? qj.points
                 : (qj.data && qj.data.points !== undefined ? qj.data.points : null);
      } catch (e) {}

      // 7) 可选：积分兑换（一次性消耗，仅在达阈值时执行）
      if (plan) {
        const need = args.needPoints;
        if (W.points !== null && Number(W.points) >= need) {
          try {
            const er = await fetch('/api/user/exchange', {
              method: 'POST', credentials: 'include',
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body: 'planType=' + encodeURIComponent(plan)
            });
            W.exchange = await er.json();
            push('exchanged');
          } catch (e) { W.exchange = { error: String(e) }; }
        } else {
          W.exchange = { skipped: true, reason: 'below-threshold' };
        }
      }
    } catch (e) {
      W.stage = 'exception:' + (e && e.message ? e.message : String(e));
    } finally {
      window.__wb.done = true;
    }
  })();
}
"""


# ---------------------------------------------------------------------------
# Cookie 工具（与 checkin.py 的语义保持一致：前缀无关、只认结构）
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
    out = []
    for part in re.split(r"\|\|\||[&\n]", raw or ""):
        c = normalize_cookie(part)
        if c:
            out.append(c)
    return out


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
# 单账号签到
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

    log(f"账号 {index}/{total} 启动浏览器会话 (前缀 {prefix})...")
    ctx = None
    try:
        ctx = browser.new_context(
            user_agent=UA,
            locale="zh-CN",
            timezone_id="Asia/Shanghai",
            viewport={"width": 1366, "height": 900},
            extra_http_headers={
                "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
                "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24"',
            },
        )
        ctx.add_cookies(to_playwright_cookies(cookie))
        page = ctx.new_page()
        page.goto(CHECKIN_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(1500)

        need_points = EXCHANGE_PLANS[plan]["points"] if plan else 0
        page.evaluate(JS_BOOT, {
            "suffix": PROOF_SUFFIX,
            "sdk": TURNSTILE_SDK,
            "plan": plan,
            "needPoints": need_points,
        })

        # 轮询状态；期间尝试点击交互式 Turnstile checkbox（跨域 iframe，只能点坐标）
        clicked = False
        deadline = time.time() + 75
        last_stage = ""
        while time.time() < deadline:
            st = page.evaluate("window.__wb")
            if st:
                if st.get("stage") != last_stage:
                    last_stage = st.get("stage") or ""
                    log(f"  账号 {index} 阶段: {last_stage}")
                if st.get("done"):
                    rec.update({
                        "ok": bool(st.get("ok")),
                        "stage": st.get("stage") or "done",
                        "points": st.get("points"),
                        "days": st.get("days"),
                        "exchange": st.get("exchange"),
                        "email": mask_email(st.get("email")),
                        "result": st.get("result"),
                        "log": st.get("log"),
                    })
                    break
                # 等待 turnstile 时，尝试点一次 widget（多数情况静默通过，不需要）
                if st.get("stage") == "waiting-turnstile" and not clicked:
                    try:
                        el = page.query_selector('iframe[src*="challenges.cloudflare.com"]')
                        if el:
                            b = el.bounding_box()
                            if b:
                                page.mouse.click(b["x"] + 30, b["y"] + b["height"] / 2)
                                clicked = True
                                log(f"  账号 {index} 检测到交互式验证，已尝试点击")
                    except Exception:
                        pass
            page.wait_for_timeout(500)
        else:
            rec["stage"] = "poll-timeout"

        # 失败时留证据
        if not rec["ok"] and os.getenv("DEBUG_SHOT", "1") == "1":
            try:
                os.makedirs(shot_dir, exist_ok=True)
                p = os.path.join(shot_dir, f"fail_{index}.png")
                page.screenshot(path=p, full_page=False)
                log(f"  账号 {index} 失败截图: {p}")
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


def main() -> int:
    raw = os.getenv("COOKIES", "")
    cookies = split_cookies(raw)
    if not cookies:
        log("[FATAL] 未配置 COOKIES")
        return 2

    plan = (os.getenv("EXCHANGE_PLAN") or os.getenv("GLADOS_EXCHANGE_PLAN") or "").strip()
    if plan and plan not in EXCHANGE_PLANS:
        log(f"[WARN] EXCHANGE_PLAN={plan} 不合法，已忽略（可选 plan100/plan200/plan500）")
        plan = None

    headless = os.getenv("HEADLESS", "0") == "1"
    shot_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug")
    delay = float(os.getenv("ACCOUNT_DELAY", "4"))

    log(f"引擎={ENGINE}  headless={headless}  账号数={len(cookies)}  兑换计划={plan or '关闭'}")

    records: List[Dict[str, Any]] = []
    with sync_playwright() as p:
        launch_kwargs = {
            "headless": headless,
            "args": [
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-features=IsolateOrigins,site-per-process",
                "--lang=zh-CN",
            ],
        }
        browser = p.chromium.launch(**launch_kwargs)
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
    print("\n" + "=" * 62)
    ok_cnt = 0
    for r in records:
        if r["ok"]:
            ok_cnt += 1
        flag = "OK  " if r["ok"] else "FAIL"
        pts = f"{r['points']} 积分" if r["points"] is not None else "-"
        days = f"{r['days']} 天" if r["days"] is not None else "-"
        ex = ""
        if r.get("exchange"):
            e = r["exchange"]
            if isinstance(e, dict) and e.get("skipped"):
                ex = " | 兑换跳过"
            elif isinstance(e, dict) and e.get("code") == 0:
                ex = " | 兑换成功"
            elif isinstance(e, dict) and e.get("error"):
                ex = " | 兑换异常"
            else:
                ex = " | 兑换:" + str(e.get("message", e))[:40]
        print(f"[{flag}] #{r['index']} {r.get('email') or '-'} | {pts} | {days} | "
              f"阶段={r['stage']}{ex}")
        if not r["ok"] and r.get("message"):
            print(f"        原因: {r['message']}")
    print("=" * 62)
    log(f"成功 {ok_cnt}/{len(records)}")

    # ---------------- 推送（复用 checkin.py 的渠道实现，配置无需改动） ----------------
    try:
        from checkin import push_all  # noqa: WPS433
        lines = []
        for r in records:
            mark = "✅" if r["ok"] else "❌"
            pts = f"{r['points']}分" if r["points"] is not None else "-"
            dys = f"{r['days']}天" if r["days"] is not None else "-"
            lines.append(f"{mark} #{r['index']} {r.get('email') or '-'} | {pts} | {dys} | {r['stage']}")
        title = f"GLaDOS 签到 {ok_cnt}/{len(records)} 成功"
        ok_ch, total_ch = push_all(title, "\n".join(lines))
        log(f"推送完成 {ok_ch}/{total_ch}")
    except Exception as e:  # noqa: BLE001
        log(f"推送跳过: {type(e).__name__}: {e}")

    if ok_cnt == 0:
        # 全部失败：默认返回 1（让 Actions 如实标红）。
        # 若不想每天刷红叉，可在 workflow 里设置 ALLOW_FAIL=1
        if os.getenv("ALLOW_FAIL", "0") == "1":
            log("ALLOW_FAIL=1，退出码强制为 0")
            return 0
        log("全部账号签到失败")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
