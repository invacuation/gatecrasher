#!/usr/bin/env python3
"""Gatecrasher — anti-bot challenge bypass proxy.

FlareSolverr-compatible /v1 API. Handles the following out of the box:
  - DDoS-Guard JS PoW challenges (passive wait)
  - Cloudflare interstitial / Turnstile (click-based)
  - Cloudflare Turnstile standalone widget (click-based)
  - Plain pages (passthrough)

With third-party services:
  - hCaptcha / reCAPTCHA / other visual captchas (requires 2Captcha API key)
  - Residential proxy routing to reduce challenge severity (PROXY_URL env)
"""

import json
import logging
import os
import sys
import time
import threading
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify
from playwright.sync_api import sync_playwright

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("gatecrasher")

app = Flask(__name__)

# ── 3rd-party service config ─────────────────────────────────────────────
CAPTCHA_API_KEY = os.environ.get("CAPTCHA_API_KEY", "")
CAPTCHA_BASE_URL = os.environ.get("CAPTCHA_BASE_URL", "https://2captcha.com")
CAPTCHA_POLL_INTERVAL = 5
CAPTCHA_MAX_POLLS = 60

PROXY_URL = os.environ.get("PROXY_URL", "")
PROXY_USERNAME = os.environ.get("PROXY_USERNAME", "")
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", "")

# ── Challenge detection ──────────────────────────────────────────────────
CHALLENGE_TITLES = ["DDoS-Guard", "Just a moment..."]

# Turnstile constants (ported from Solverr/playwright-captcha)
_TURNSTILE_CHECKBOX_X = 30
_TURNSTILE_CHECKBOX_Y_RATIO = 0.5
_TURNSTILE_POLL_INTERVAL = 0.5
_TURNSTILE_DEADLINE_SECONDS = 30
_WIDGET_MIN_WIDTH = 40
_WIDGET_MIN_HEIGHT = 20
_WIDGET_MAX_HEIGHT = 120

# ── Browser singleton ────────────────────────────────────────────────────
_browser_lock = threading.Lock()
_browser = None
_playwright = None


def get_browser():
    global _browser, _playwright
    with _browser_lock:
        if _browser is None or not _browser.is_connected():
            if _playwright is not None:
                try:
                    _playwright.stop()
                except Exception:
                    pass
            _playwright = sync_playwright().start()
            _browser = _playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-setuid-sandbox",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--disable-blink-features=AutomationControlled",
                ],
            )
        return _browser


# ── Proxy helpers ────────────────────────────────────────────────────────


def _proxy_config() -> dict | None:
    """Build Playwright proxy config from environment variables."""
    if not PROXY_URL:
        return None
    config = {"server": PROXY_URL}
    if PROXY_USERNAME:
        config["username"] = PROXY_USERNAME
    if PROXY_PASSWORD:
        config["password"] = PROXY_PASSWORD
    return config


def _proxy_string_2captcha() -> str | None:
    """Proxy string in 2Captcha format (user:pass@host:port) or None."""
    if not PROXY_URL:
        return None
    parsed = urlparse(PROXY_URL)
    host = parsed.hostname
    port = parsed.port or 3128
    auth = f"{PROXY_USERNAME}:{PROXY_PASSWORD}@" if PROXY_USERNAME else ""
    return f"{auth}{host}:{port}"


# ── Challenge classification ─────────────────────────────────────────────


def _classify_challenge(page) -> str:
    """Detect what kind of challenge the page is showing.

    Returns one of: 'hcaptcha', 'turnstile', 'jspow', 'unknown'.
    """
    try:
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        time.sleep(5)
        html = page.content().lower()

        # hCaptcha (visual puzzle — needs 3rd-party solver)
        if any(marker in html for marker in [
            "hcaptcha.com/1/api.js",
            "h-captcha",
            'data-sitekey="',
            "hcaptcha",
        ]):
            return "hcaptcha"

        # Cloudflare Turnstile (invisible / checkbox)
        if any(marker in html for marker in [
            "challenges.cloudflare.com",
            "cf-turnstile",
            "turnstile",
            "cf_challenge_platform",
            "turnstile-wrapper",
        ]):
            return "turnstile"

        # JS proof-of-work (DDoS-Guard / Cloudflare)
        if "js-challenge" in html or "challenge-platform" in html:
            return "jspow"

        return "unknown"
    except Exception as e:
        log.debug("Challenge detection error: %s", e)
        return "unknown"


# ── Turnstile click-based solving (out of the box) ───────────────────────


def _turnstile_widget_box(page):
    """Measure the Turnstile widget's bounding box for clicking.

    Tries the Turnstile iframe first, then falls back to the container
    around the cf-turnstile-response input.
    """
    try:
        # First try: find the Turnstile iframe
        iframe = page.query_selector('iframe[src*="challenges.cloudflare.com"]')
        if iframe:
            box = iframe.bounding_box()
            if box and box["width"] > _WIDGET_MIN_WIDTH:
                return box

        # Second try: find the wrapper via the hidden input's ancestors
        input_el = page.query_selector('input[name="cf-turnstile-response"]')
        if input_el:
            for depth in (1, 2, 3, 4):
                try:
                    ancestor = input_el.evaluate(
                        f"""el => {{
                            let a = el;
                            for (let i = 0; i < {depth}; i++) {{
                                a = a.parentElement;
                                if (!a) return null;
                            }}
                            const r = a.getBoundingClientRect();
                            return r.width > {_WIDGET_MIN_WIDTH} &&
                                   r.height > {_WIDGET_MIN_HEIGHT} &&
                                   r.height < {_WIDGET_MAX_HEIGHT}
                                   ? {{x: r.x, y: r.y, width: r.width, height: r.height}}
                                   : null;
                        }}"""
                    )
                    if ancestor:
                        return ancestor
                except Exception:
                    continue

        # Third try: #turnstile-wrapper or .cf-turnstile
        for sel in ("#turnstile-wrapper", ".cf-turnstile", "[data-cf-turnstile]"):
            el = page.query_selector(sel)
            if el:
                box = el.bounding_box()
                if box and box["width"] > _WIDGET_MIN_WIDTH:
                    return box

        return None
    except Exception as e:
        log.debug("Widget box detection error: %s", e)
        return None


def _turnstile_has_token(page) -> bool:
    """Check whether the Turnstile hidden input has a token."""
    try:
        token = page.evaluate(
            """() => {
                const el = document.querySelector('input[name="cf-turnstile-response"]');
                return el ? el.value : '';
            }"""
        )
        return bool(token and len(token) > 10)
    except Exception:
        return False


def _solve_turnstile_click(page) -> bool:
    """Click the Turnstile checkbox and wait for verification.

    This works out of the box — no third-party service needed — because
    Turnstile's checkbox is a passive fingerprint check, not a visual puzzle.
    Returns True if the challenge cleared.
    """
    log.info("Solving Turnstile via click...")
    deadline = time.monotonic() + _TURNSTILE_DEADLINE_SECONDS

    while time.monotonic() < deadline:
        # If already verified, we're done
        if _turnstile_has_token(page):
            log.info("Turnstile already verified (token present)")
            return True

        box = _turnstile_widget_box(page)
        if box:
            click_x = box["x"] + _TURNSTILE_CHECKBOX_X
            click_y = box["y"] + box["height"] * _TURNSTILE_CHECKBOX_Y_RATIO
            page.mouse.click(click_x, click_y)
            log.debug("Clicked Turnstile checkbox at (%.0f, %.0f)", click_x, click_y)

        # Wait for verification
        for _ in range(int(_TURNSTILE_DEADLINE_SECONDS / _TURNSTILE_POLL_INTERVAL)):
            if time.monotonic() > deadline:
                break
            if _turnstile_has_token(page):
                log.info("Turnstile verified after click!")
                return True
            time.sleep(_TURNSTILE_POLL_INTERVAL)

    log.warning("Turnstile did not verify within timeout")
    return False


# ── hCaptcha solving (requires 2Captcha) ─────────────────────────────────


def _extract_sitekey(page) -> str | None:
    """Extract the hCaptcha sitekey from the page."""
    try:
        sitekey = page.evaluate(
            """() => {
                const el = document.querySelector('[data-sitekey]');
                return el ? el.getAttribute('data-sitekey') : null;
            }"""
        )
        if sitekey and len(sitekey) > 10:
            log.info("Found hCaptcha sitekey: %s...", sitekey[:12])
            return sitekey
        log.warning("Could not find hCaptcha sitekey")
        return None
    except Exception as e:
        log.error("Error extracting sitekey: %s", e)
        return None


def _solve_hcaptcha(sitekey: str, page_url: str) -> str | None:
    """Solve an hCaptcha via 2Captcha API. Returns the token or None."""
    if not CAPTCHA_API_KEY:
        return None

    proxy_str = _proxy_string_2captcha()

    try:
        data = {
            "key": CAPTCHA_API_KEY,
            "method": "hcaptcha",
            "sitekey": sitekey,
            "pageurl": page_url,
            "json": 1,
        }
        if proxy_str:
            data["proxy"] = proxy_str
            data["proxytype"] = "http"

        resp = requests.post(f"{CAPTCHA_BASE_URL}/in.php", data=data, timeout=30)
        result = resp.json()
        if result.get("status") != 1:
            log.error("2Captcha submit failed: %s", result.get("request", "unknown"))
            return None
        captcha_id = result["request"]
        log.info("2Captcha job submitted (id=%s)", captcha_id)
    except Exception as e:
        log.error("2Captcha submit error: %s", e)
        return None

    for attempt in range(CAPTCHA_MAX_POLLS):
        time.sleep(CAPTCHA_POLL_INTERVAL)
        try:
            resp = requests.get(
                f"{CAPTCHA_BASE_URL}/res.php",
                params={
                    "key": CAPTCHA_API_KEY,
                    "action": "get",
                    "id": captcha_id,
                    "json": 1,
                },
                timeout=30,
            )
            data = resp.json()
            if data.get("status") == 1:
                log.info("hCaptcha solved in ~%ds", (attempt + 1) * CAPTCHA_POLL_INTERVAL)
                return data["request"]
            if data.get("request") != "CAPCHA_NOT_READY":
                log.error("2Captcha error: %s", data.get("request", "unknown"))
                return None
        except Exception as e:
            log.error("2Captcha poll error: %s", e)
            return None

    log.error("2Captcha timed out")
    return None


def _inject_hcaptcha_token(page, token: str) -> bool:
    """Inject an hCaptcha token into the DDoS-Guard page and trigger verification."""
    try:
        page.evaluate(
            f"""() => {{
                try {{
                    if (typeof hcaptcha !== 'undefined') {{
                        const widgets = document.querySelectorAll('[data-hcaptcha-widget-id]');
                        if (widgets.length > 0) {{
                            const wid = widgets[0].getAttribute('data-hcaptcha-widget-id');
                            hcaptcha.setResponse(wid, '{token}');
                        }}
                    }}
                }} catch(e) {{}}

                try {{
                    const input = document.querySelector('textarea[name="h-captcha-response"]');
                    if (input) {{
                        const setter = Object.getOwnPropertyDescriptor(
                            window.HTMLTextAreaElement.prototype, 'value'
                        ).set;
                        setter.call(input, '{token}');
                        input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        input.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                }} catch(e) {{}}

                try {{
                    if (typeof window.callbackHCaptcha === 'function') {{
                        window.callbackHCaptcha();
                    }}
                }} catch(e) {{}}
                return true;
            }}"""
        )
        log.info("hCaptcha token injected")
        return True
    except Exception as e:
        log.error("Token injection failed: %s", e)
        return False


# ── Stealth patches ──────────────────────────────────────────────────────


def _apply_stealth(page):
    """Apply browser fingerprint patches before navigation."""
    page.add_init_script(
        """() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined, configurable: true,
            });
            Object.defineProperty(navigator, 'plugins', {
                get: () => {
                    const arr = [1, 2, 3, 4, 5];
                    arr.item = (i) => arr[i];
                    arr.namedItem = () => null;
                    arr.refresh = () => {};
                    return arr;
                },
                configurable: true,
            });
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
                configurable: true,
            });
            if (window.chrome) {
                window.chrome.runtime = {
                    id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    connect: () => ({}),
                    sendMessage: () => {},
                    onConnect: { addListener: () => {} },
                    onMessage: { addListener: () => {} },
                };
            }
            Object.defineProperty(Navigator.prototype, 'webdriver', {
                get: () => false, configurable: true,
            });
            if (navigator.permissions && navigator.permissions.query) {
                const q = navigator.permissions.query;
                navigator.permissions.query = (p) =>
                    p.name === 'notifications'
                        ? Promise.resolve({ state: 'denied' })
                        : q(p);
            }
        }"""
    )


# ── Core solver ──────────────────────────────────────────────────────────


def solve_challenge(url: str, max_timeout_ms: int = 120000) -> dict:
    """Navigate to a URL, clear any challenge, return the page content.

    Returns a FlareSolverr-compatible response dict.
    """
    browser = get_browser()
    timeout_s = max_timeout_ms / 1000.0
    deadline = time.monotonic() + timeout_s

    context = browser.new_context(
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
        ),
        locale="en-US",
        timezone_id="Europe/London",
        viewport={"width": 1920, "height": 1080},
        proxy=_proxy_config(),
    )
    page = None
    challenge_was_present = False
    solved = False

    try:
        page = context.new_page()
        _apply_stealth(page)

        log.info("Navigating to %s", url)
        page.goto(url, wait_until="domcontentloaded", timeout=max_timeout_ms)
        title = page.title()
        log.info("Page title: %s", title)

        is_challenge = any(t.lower() in title.lower() for t in CHALLENGE_TITLES)

        if is_challenge:
            challenge_was_present = True
            challenge_type = _classify_challenge(page)
            log.info("Challenge type: %s", challenge_type)

            if challenge_type == "turnstile":
                solved = _solve_turnstile_click(page)

            elif challenge_type == "hcaptcha":
                if CAPTCHA_API_KEY:
                    log.info("Solving hCaptcha via 2Captcha...")
                    sitekey = _extract_sitekey(page)
                    if sitekey:
                        token = _solve_hcaptcha(sitekey, url)
                        if token:
                            _inject_hcaptcha_token(page, token)
                            for _ in range(30):
                                if time.monotonic() > deadline:
                                    break
                                time.sleep(2)
                                try:
                                    ct = page.title()
                                    if not any(
                                        t.lower() in ct.lower() for t in CHALLENGE_TITLES
                                    ):
                                        try:
                                            cc = page.content()
                                            if "hcaptcha" not in cc.lower()[:500]:
                                                solved = True
                                                break
                                        except Exception:
                                            solved = True
                                            break
                                except Exception:
                                    time.sleep(1)
                        else:
                            log.warning("2Captcha failed")
                    else:
                        log.warning("No sitekey found")
                else:
                    log.warning("hCaptcha detected but CAPTCHA_API_KEY not set")

            elif challenge_type in ("jspow", "unknown"):
                log.info("Waiting for JS PoW / interstitial challenge to clear...")
                while time.monotonic() < deadline:
                    try:
                        ct = page.title()
                    except Exception:
                        log.info("Challenge cleared (navigation detected)")
                        solved = True
                        break
                    if not any(t.lower() in ct.lower() for t in CHALLENGE_TITLES):
                        log.info("Challenge cleared! Title: %s", ct)
                        solved = True
                        break
                    time.sleep(1)
        else:
            log.info("No challenge detected")

        # Settle and read final content
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        try:
            page_content = page.content()
            final_title = page.title()
            final_url = page.url
        except Exception:
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10000)
                page_content = page.content()
                final_title = page.title()
                final_url = page.url
            except Exception:
                page_content = ""
                final_title = "Navigation error"
                final_url = url

        if challenge_was_present:
            message = "Challenge solved!" if solved else "Challenge still present after solving attempts"
        else:
            message = "Challenge not detected!"

        result = {
            "status": "ok",
            "message": message,
            "solution": {
                "url": final_url,
                "status": 200,
                "cookies": [
                    {
                        "name": c["name"],
                        "value": c["value"],
                        "domain": c.get("domain", ""),
                        "path": c.get("path", "/"),
                        "httpOnly": c.get("httpOnly", False),
                        "secure": c.get("secure", False),
                        "sameSite": c.get("sameSite", "Lax"),
                    }
                    for c in context.cookies()
                ],
                "userAgent": page.evaluate("() => navigator.userAgent"),
                "response": page_content,
                "headers": {},
            },
        }
        return result

    except Exception as e:
        log.error("Error: %s", e)
        return {"status": "error", "message": f"Error: {e}"}
    finally:
        if page:
            try:
                page.close()
            except Exception:
                pass
        context.close()


# ── HTTP routes ──────────────────────────────────────────────────────────


@app.route("/v1", methods=["POST"])
def handle_v1():
    data = request.get_json(force=True)
    cmd = data.get("cmd", "")
    url = data.get("url", "")
    max_timeout = data.get("maxTimeout", 120000)
    log.info("Request: cmd=%s url=%s maxTimeout=%s", cmd, url, max_timeout)
    if cmd == "request.get":
        result = solve_challenge(url, max_timeout)
        result["startTimestamp"] = int(time.time() * 1000)
        result["endTimestamp"] = int(time.time() * 1000)
        result["version"] = "1.0.0"
        return jsonify(result)
    elif cmd == "request.post":
        return jsonify({"status": "error", "message": "POST not supported yet"})
    else:
        return jsonify({"status": "error", "message": f"Unknown command: {cmd}"})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    if CAPTCHA_API_KEY:
        log.info("2Captcha integration ENABLED")
    else:
        log.info("2Captcha DISABLED")
    log.info("Gatecrasher starting — listening on :8191")
    app.run(host="0.0.0.0", port=8191, threaded=False)
