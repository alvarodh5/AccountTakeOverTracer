# Account Takeover Tracer — SOC Dashboard (live from Sola MCP)

A local SOC dashboard that correlates **Okta** identity signals with **GitHub**
code-access risk to detect account takeovers. Every value, chart and finding is
pulled **live from the Sola MCP** at request time — there is no static data file.

## What it shows
- **Risk score + verdict** derived from real signals.
- **MFA fatigue** detection (3+ failed MFA pushes → success within 10 min).
- **Flagged logins** (new country / impossible travel) from the Okta System Log.
- **GitHub access risk**: public repos and collaborators with WRITE/ADMIN.
- **Charts**: auth outcomes, top Okta event types, activity by source IP/geo
  (foreign IPs highlighted in red).
- **Detection coverage** with live hit counts + **MITRE ATT&CK** techniques observed.

## How the data flows
```
Browser ──/api/incident──> server.py ──OAuth client_credentials──> auth.sola.security
                                   └──JSON-RPC (execute_sql)──────> api.sola.security/mcp
                                                                     └─> Okta + GitHub tables
```

## Setup
1. Copy `.env.sample` to `.env` and fill in your Sola credentials:
   ```
   SOLA_CLIENT_ID=...
   SOLA_CLIENT_SECRET=...
   ```
   (Generate in Sola: Settings → Privacy and Security → Personal Tokens.)
2. Run:
   ```
   python3 server.py
   ```
3. Open http://localhost:8765

Requires Python 3 and `certifi` (already present on this machine). No other deps;
Chart.js is vendored locally (`chart.umd.min.js`) so it works offline.

## Security
- `.env` is gitignored. **Rotate the client secret** if it was ever shared.
- The MCP connection is read-only (SELECT queries only).
