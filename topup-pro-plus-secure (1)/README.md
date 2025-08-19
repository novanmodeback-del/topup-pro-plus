# TopUp PRO PLUS SECURE

Security upgrades:
- OTP stored hashed (bcrypt), single-use, 5-minute expiry.
- OTP verify attempt limits (3 attempts -> block 10 minutes)
- Login & OTP attempts logged to DB and logs/attempts.log via winston.
- Admin IP whitelist support via ADMIN_IP_WHITELIST env (comma-separated).
- WhatsApp template send on paid webhook (uses WA_TEMPLATE_NAME or text fallback).

Quickstart:
1. Node 18+
2. cp .env.example .env and fill credentials (SMTP, WA if needed)
3. npm install
4. npm run dev
5. Admin login -> receive OTP via email -> verify -> access admin panel.

Notes:
- This is a demo. Further hardening recommended before production: HTTPS, CSP, HSTS, helmet tuning, audit logs to external service.
