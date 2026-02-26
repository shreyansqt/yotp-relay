# yotp-relay

Open source OTP relay server for [yotp](https://yotp.app) — forwards OTPs from Android to macOS through the cloud.

Runs as a [Cloudflare Worker](https://workers.cloudflare.com/) with [Ably](https://ably.com/) for real-time messaging.

## How it works

1. **Android** receives an SMS with an OTP
2. Android sends the encrypted OTP to the relay via Ably pub/sub
3. **macOS** receives it, decrypts, copies to clipboard + shows notification

The relay server issues scoped Ably tokens so devices can communicate. It never sees your OTP codes — messages are **end-to-end encrypted** with AES-256-GCM using a key that only your paired devices know.

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/token` | POST | Issue a scoped Ably token for a paired channel |
| `/pair-status` | POST | Check if a pairing is still active |
| `/unpair` | POST | Remove a pairing |

## Self-hosting

### Prerequisites

- [Cloudflare account](https://dash.cloudflare.com/sign-up) (free tier works)
- [Ably account](https://ably.com/) (free tier: 6M messages/month)
- [Node.js](https://nodejs.org/) 18+

### Setup

1. **Clone and install**

```bash
git clone https://github.com/shreyansqt/yotp-relay.git
cd yotp-relay
npm install
```

2. **Create KV namespaces**

```bash
npx wrangler kv namespace create RATE_LIMIT
npx wrangler kv namespace create PAIRING
```

Copy the IDs into `wrangler.json`.

3. **Set your Ably API key**

```bash
npx wrangler secret put ABLY_API_KEY
# Paste your Ably API key when prompted
```

4. **Deploy**

```bash
npm run deploy
```

5. **Point your yotp apps to your relay**

Update the relay URL in both the Android and macOS apps to your worker URL (e.g. `https://yotp-relay.your-subdomain.workers.dev`).

### Local development

```bash
# Create .dev.vars with your Ably key
echo 'ABLY_API_KEY=your-key-here' > .dev.vars

npm run dev
```

## Rate limits

- 20 requests/minute per IP
- 10 requests/minute per pair ID

## Authentication

Requests are signed with HMAC-SHA256 using the pair's encryption key. The server validates signature presence and format but cannot verify the signature itself (it doesn't have the encryption key — by design).

## License

MIT
