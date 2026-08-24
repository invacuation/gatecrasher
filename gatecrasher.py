#!/usr/bin/env python3
"""Gatecrasher — DDoS-Guard bypass proxy with optional 2Captcha hCaptcha solving.

FlareSolverr-compatible /v1 API. Handles:
  - DDoS-Guard hCaptcha interstitials (via 2Captcha)
  - DDoS-Guard JS PoW challenges (passive wait)
  - Cloudflare Turnstile / JS challenges (passive wait)
  - Plain pages (passthrough)

Set CAPTCHA_API_KEY to enable 2Captcha hCaptcha solving.
"""

import json
import logging
import os
import sys
import time
import threading

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

# 2Captcha config
CAPTCHA_API_KEY = os.environ.get("CAPTCHA_API_KEY", "")
CAPTCHA_BASE_URL = os.environ.get("CAPTCHA_BASE_URL", "https://2captcha.com")
CAPTCHA_POLL_INTERVAL = 5
CAPTCHA_MAX_POLLS = 60

CHALLENGE_TITLES = ["DDoS-Guard", "Just a moment..."]

# Browser singleton (thread-safe)
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


def _classify_challenge(page) -> str:
    """Classify the challenge type by inspecting the page source.

    Returns 'hcaptcha', 'jspow', or 'unknown'.
    """
    try:
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        # Wait for async hCaptcha scripts to load
        time.sleep(5)
        html = page.content().lower()
        # Check for hCaptcha (primary: scripts, iframes, divs)
        if any(marker in html for marker in [
            "hcaptcha.com/1/api.js",
            "h-captcha",
            'data-sitekey="',
            "hcaptcha",
        ]):
            return "hcaptcha"
        if "js-challenge" in html or "challenge-platform" in html:
            return "jspow"
        return "unknown"
    except Exception as e:
        log.debug("Challenge detection error: %s", e)
        return "unknown"


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

    try:
        resp = requests.post(
            f"{CAPTCHA_BASE_URL}/in.php",
            data={
                "key": CAPTCHA_API_KEY,
                "method": "hcaptcha",
                "sitekey": sitekey,
                "pageurl": page_url,
                "json": 1,
            },
            timeout=30,
        )
        data = resp.json()
        if data.get("status") != 1:
            log.error("2Captcha submit failed: %s", data.get("request", "unknown"))
            return None
        captcha_id = data["request"]
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


def _inject_token(page, token: str) -> bool:
    """Inject an hCaptcha token into the DDoS-Guard page and trigger the callback."""
    try:
        # First, check the __ddg3 cookie value
        ddg3 = page.evaluate("""() => {
            const m = document.cookie.match(/__ddg3=([^;]+)/);
            return m ? m[1] : null;
        }""")
        log.info("__ddg3 cookie: %s", ddg3[:20] if ddg3 else "None")

        # Also check navigator.webdriver
        webdriver = page.evaluate("() => navigator.webdriver")
        log.info("navigator.webdriver: %s", webdriver)

        page.evaluate(
            f"""() => {{
                // Set the response via hCaptcha's API
                try {{
                    if (typeof hcaptcha !== 'undefined') {{
                        const widgets = document.querySelectorAll('[data-hcaptcha-widget-id]');
                        if (widgets.length > 0) {{
                            const wid = widgets[0].getAttribute('data-hcaptcha-widget-id');
                            hcaptcha.setResponse(wid, '{token}');
                        }}
                    }}
                }} catch(e) {{ console.log('hcaptcha API error:', e); }}

                // Also set the textarea as fallback
                try {{
                    const input = document.querySelector('textarea[name="h-captcha-response"]');
                    if (input) {{
                        const nativeSetter = Object.getOwnPropertyDescriptor(
                            window.HTMLTextAreaElement.prototype, 'value'
                        ).set;
                        nativeSetter.call(input, '{token}');
                        input.dispatchEvent(new Event('input', {{ bubbles: true }}));
                        input.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }}
                }} catch(e) {{ console.log('textarea error:', e); }}

                // Call the DDoS-Guard's callback function
                try {{
                    if (typeof window.callbackHCaptcha === 'function') {{
                        window.callbackHCaptcha();
                    }}
                }} catch(e) {{ console.log('callback error:', e); }}

                return true;
            }}"""
        )
        log.info("hCaptcha token injected via callbackHCaptcha")
        return True
    except Exception as e:
        log.error("Token injection failed: %s", e)
        return False


def solve_challenge(url: str, max_timeout_ms: int = 120000) -> dict:
    """Navigate to a URL, clear any DDoS-Guard challenge, return the page.

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
    )
    page = None
    challenge_was_present = False
    solved = False

    try:
        page = context.new_page()

        # Apply stealth patches before any navigation
        page.add_init_script("""
        () => {
            // Override navigator.webdriver
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined,
                configurable: true,
            });

            // Override navigator.plugins to have realistic length
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

            // Override navigator.languages
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
                configurable: true,
            });

            // Override chrome.runtime to fake it
            if (window.chrome) {
                window.chrome.runtime = {
                    id: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                    connect: () => ({}),
                    sendMessage: () => {},
                    onConnect: { addListener: () => {} },
                    onMessage: { addListener: () => {} },
                };
            }

            // Remove webdriver from navigator properties
            const originalQuery = window.navigator.__proto__.webdriver;
            Object.defineProperty(Navigator.prototype, 'webdriver', {
                get: () => false,
                configurable: true,
            });

            // Override permissions.query
            if (navigator.permissions && navigator.permissions.query) {
                const originalQuery = navigator.permissions.query;
                navigator.permissions.query = (params) => (
                    params.name === 'notifications' ? Promise.resolve({ state: 'denied' }) : originalQuery(params)
                );
            }
        }
        """)
        log.info("Navigating to %s", url)
        page.goto(url, wait_until="domcontentloaded", timeout=max_timeout_ms)

        title = page.title()
        log.info("Page title: %s", title)

        is_challenge = any(t.lower() in title.lower() for t in CHALLENGE_TITLES)

        if is_challenge:
            challenge_was_present = True
            log.info("DDoS-Guard challenge detected, classifying...")

            challenge_type = _classify_challenge(page)
            log.info("Challenge type: %s", challenge_type)

            if challenge_type == "hcaptcha":
                if CAPTCHA_API_KEY:
                    log.info("Solving hCaptcha via 2Captcha...")
                    sitekey = _extract_sitekey(page)
                    if sitekey:
                        token = _solve_hcaptcha(sitekey, url)
                        if token:
                            _inject_token(page, token)
                            # Wait for the real page to load (not just title change)
                            for _ in range(30):
                                if time.monotonic() > deadline:
                                    break
                                time.sleep(2)
                                try:
                                    current_url = page.url
                                    current_title = page.title()
                                    # Check if we're on the real site (not DDoS-Guard)
                                    if not any(
                                        t.lower() in current_title.lower()
                                        for t in CHALLENGE_TITLES
                                    ):
                                        # Verify the page content is actually the real page
                                        try:
                                            content_check = page.content()
                                            if "hcaptcha" not in content_check.lower()[:500]:
                                                solved = True
                                                log.info("Challenge cleared! Real page loaded: %s", current_title)
                                                break
                                        except Exception:
                                            solved = True
                                            break
                                except Exception:
                                    # Page navigating - this is good, wait for it to settle
                                    time.sleep(1)
                                    pass
                            if solved:
                                log.info("Challenge cleared after hCaptcha solve!")
                            else:
                                log.warning("hCaptcha token injected but challenge didn't clear")
                        else:
                            log.warning("2Captcha failed — challenge unsolvable")
                    else:
                        log.warning("No sitekey found on hCaptcha page")
                else:
                    log.warning("hCaptcha detected but CAPTCHA_API_KEY not set")
                    log.info("Waiting for possible auto-solve...")
                    while time.monotonic() < deadline:
                        try:
                            current_title = page.title()
                        except Exception:
                            solved = True
                            break
                        if not any(
                            t.lower() in current_title.lower() for t in CHALLENGE_TITLES
                        ):
                            solved = True
                            break
                        time.sleep(1)
            else:
                # JS PoW or unknown — wait for it to clear
                log.info("Waiting for JS PoW challenge to clear...")
                while time.monotonic() < deadline:
                    try:
                        current_title = page.title()
                    except Exception:
                        log.info("Challenge cleared! Page navigated to new content")
                        solved = True
                        break
                    if not any(
                        t.lower() in current_title.lower() for t in CHALLENGE_TITLES
                    ):
                        log.info("Challenge cleared! Title: %s", current_title)
                        solved = True
                        break
                    time.sleep(1)
        else:
            log.info("No challenge detected")

        # Let the page settle
        try:
            page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        # Read final page state — handle navigation destroying the old context
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
        log.info("2Captcha DISABLED (CAPTCHA_API_KEY not set)")
    log.info("Gatecrasher starting — listening on :8191")
    app.run(host="0.0.0.0", port=8191, threaded=False)