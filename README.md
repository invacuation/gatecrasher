# Gatecrasher

**DDoS-Guard bypass proxy** — a FlareSolverr-compatible API for clearing DDoS-Guard and Cloudflare challenges using Playwright, with optional 2Captcha integration for hCaptcha interstitials.

## How it works

1. Receives a FlareSolverr-format `request.get` POST at `/v1`
2. Navigates to the target URL with a headless Chromium (Playwright)
3. Detects the challenge type:
   - **hCaptcha** — extracts the sitekey, submits to 2Captcha, injects the token, triggers the callback
   - **JS PoW** — waits for the proof-of-work to complete and the page to redirect
   - **None** — returns the page content directly
4. Returns the cleared page, cookies, and user agent in FlareSolverr's response format

## Quick start

```bash
docker build -t gatecrasher .
docker run -d \
  --name gatecrasher \
  -p 8191:8191 \
  -e CAPTCHA_API_KEY=your_2captcha_key_here \
  --restart unless-stopped \
  gatecrasher
```

## 2Captcha integration

Set `CAPTCHA_API_KEY` to enable automatic hCaptcha solving. Without it, only JS PoW challenges can be bypassed.

Additional environment variables:

| Variable | Default | Description |
|---|---|---|
| `CAPTCHA_API_KEY` | — | 2Captcha API key |
| `CAPTCHA_BASE_URL` | `https://2captcha.com` | 2Captcha-compatible API endpoint |
| `CAPTCHA_POLL_INTERVAL` | 5 | Seconds between result polls |
| `CAPTCHA_MAX_POLLS` | 60 | Max poll attempts (5 min ceiling) |

## Example docker-compose

```yaml
services:
  gatecrasher:
    build: .
    container_name: gatecrasher
    restart: unless-stopped
    ports:
      - "8191:8191"
    environment:
      - CAPTCHA_API_KEY=your_key_here
    networks:
      - your_network
```

## API

### POST /v1

FlareSolverr-compatible. Example:

```json
{
  "cmd": "request.get",
  "url": "https://example.com",
  "maxTimeout": 120000
}
```

Returns the standard FlareSolverr response shape with `solution.response`, `solution.cookies`, and `solution.userAgent`.

### GET /health

Returns `{"status": "ok"}`.

## License

MIT