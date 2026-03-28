
🌐 CloudGuard – Cloud Misconfiguration Security Extension

CloudGuard is a prevention-first, real-time cloud security solution designed to detect and mitigate misconfiguration risks across multi-cloud environments such as AWS, Microsoft Azure, and Google Cloud Platform.

In modern cloud systems, the majority of security breaches occur due to misconfigurations rather than sophisticated attacks. CloudGuard addresses this critical challenge by providing a continuous monitoring and auto-healing security framework that operates directly within the user’s workflow.

🚀 Key Features
🔍 Automatic Activation
Seamlessly activates when users access cloud platforms (AWS, Azure, GCP)
🛡️ Safe Configuration Baseline
Captures and maintains a secure reference state to detect configuration drift
⚡ Real-Time Monitoring
Continuously tracks configuration changes and user activities
🧠 Hybrid Detection Engine
Combines:
Rule-based detection (CIS Benchmarks)
Machine Learning (Random Forest)
User Behavior Analysis
📊 Risk Scoring System (1–100)
Prioritizes vulnerabilities based on severity and impact
🚨 Real-Time Alerts
Instant notifications for risky configurations and suspicious activities
🔄 Auto-Remediation & Rollback
Automatically fixes issues or restores the system to a secure baseline
👨‍💼 Admin Governance Control
Requires approval for critical actions to ensure secure operations
📈 Interactive Dashboard & Reports
Visualizes threats, trends, and generates CSV/PDF reports for auditing
🧠 Core Idea

CloudGuard transforms cloud security from:

❌ Reactive Detection (after damage)
➡️ Proactive Prevention & Auto-Healing Security

🛠️ Tech Stack
Frontend (Extension): JavaScript, HTML, CSS (Chrome Extension – Manifest V3)
Dashboard: React.js, Tailwind CSS
Backend: Python, FastAPI
Machine Learning: Scikit-learn (Random Forest)
Database: MongoDB / PostgreSQL
Cloud APIs: AWS (Boto3), Azure, GCP
🎯 Use Cases
Enterprises managing multi-cloud environments
DevOps and cloud security teams
Startups using cloud-native infrastructure
Government and public sector cloud systems

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
