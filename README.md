# Gatecrasher

**Anti-bot challenge bypass proxy** — a FlareSolverr-compatible API for clearing CDN challenges using Playwright.

## Capabilities

### Out of the box (no third-party services)

| Challenge type | How it works |
|---|---|
| **Cloudflare JS interstitial** ("Just a moment...") | Waits for the proof-of-work to complete and the page to redirect |
| **Cloudflare Turnstile** (passive checkbox) | Clicks the checkbox at the correct coordinates and waits for verification |
| **DDoS-Guard JS PoW** | Waits for the proof-of-work to complete |
| **DDoS-Guard hCaptcha** | Extracts the sitekey and submits to 2Captcha for solving |
| **No challenge** | Returns the page content directly |

### With third-party services

| Service | What it enables | How to set |
|---|---|---|
| **[2Captcha](https://2captcha.com)** (or compatible) API key | Solves visual hCaptcha, reCAPTCHA v2/v3, and other image-based captchas | `CAPTCHA_API_KEY` env var |

> **Why some captchas need a third party:** Visual puzzles (hCaptcha, reCAPTCHA) are designed to be unsolvable by automation — they require either human workers or ML-based solving services. Passive checks like Turnstile's fingerprint and Cloudflare's JS proof-of-work are solvable natively because they test browser environment signals, not visual recognition.

## Quick start

```bash
docker build -t gatecrasher .
docker run -d \
  --name gatecrasher \
  -p 8191:8191 \
  --restart unless-stopped \
  gatecrasher
```

With 2Captcha for visual captcha solving:

```bash
docker run -d \
  --name gatecrasher \
  -p 8191:8191 \
  -e CAPTCHA_API_KEY=your_2captcha_key \
  --restart unless-stopped \
  gatecrasher
```

## Configuration

### Third-party integrations

| Variable | Default | Description |
|---|---|---|
| `CAPTCHA_API_KEY` | — | 2Captcha API key for visual captcha solving |
| `CAPTCHA_BASE_URL` | `https://2captcha.com` | 2Captcha-compatible API endpoint |

### Solver tuning

| Variable | Default | Description |
|---|---|---|
| `CAPTCHA_POLL_INTERVAL` | 5 | Seconds between 2Captcha result polls |
| `CAPTCHA_MAX_POLLS` | 60 | Max poll attempts (5 min ceiling) |

## API

### POST /v1

FlareSolverr-compatible. Accepts a JSON body:

```json
{
  "cmd": "request.get",
  "url": "https://example.com",
  "maxTimeout": 120000
}
```

Response:

```json
{
  "status": "ok",
  "message": "Challenge solved!",
  "solution": {
    "url": "https://example.com",
    "status": 200,
    "cookies": [...],
    "userAgent": "Mozilla/5.0 ...",
    "response": "<!DOCTYPE html>..."
  }
}
```

### GET /health

Returns `{"status": "ok"}`.

## License

MIT
