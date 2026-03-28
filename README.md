<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/5c2418de-2c8a-4d8d-9a04-3dd2f49fd302

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Backend + Redis (Recommended)

Use this when you want cached risk responses (`cached`) and production-like behavior.

1. Start Redis:
   `docker compose -f docker-compose.redis.yml up -d`
2. Start backend API:
   `cd backend && py -m uvicorn main:app --host 127.0.0.1 --port 8000`
3. Confirm health:
   `http://127.0.0.1:8000/health`

Expected health output should include:
- `"database": "connected"`
- `"redis": "connected"`

If Redis is down, risk scoring still works, but repeated calls return fresh `completed` results instead of `cached`.

## Advanced Reporting & Export

Backend reporting supports detailed security analytics, CSV/PDF export, compliance formatting, scheduling, and email delivery.

Core endpoints:
- `GET /api/generate-report`
- `GET /api/export-csv`
- `GET /api/export-pdf`

Custom report filters:
- `severity=LOW|MEDIUM|HIGH|CRITICAL`
- `start_time=<ISO8601>`
- `end_time=<ISO8601>`
- `compliance_mode=true|false`
- `compliance_standard=SOC2|ISO`

Advanced endpoints:
- `POST /api/report-schedules` (daily/weekly scheduled reports)
- `GET /api/report-schedules` (list schedules)
- `POST /api/report-schedules/run` (execute due schedules)
- `POST /api/report-email` (send CSV/PDF report to admin email)
- `POST /api/report-alert/critical?event_type=<event>` (trigger critical-event report)

Dashboard integration:
- Reports page includes `Download CSV` and `Download PDF` buttons
- Includes severity/time/compliance filters
- Includes schedule and email actions
