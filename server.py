#!/usr/bin/env python3
"""
Account Takeover Tracer — local SOC dashboard.

All data is pulled LIVE from the Sola MCP (https://api.sola.security/mcp) using
OAuth client-credentials. There is NO hand-authored data file: every number,
chart and finding on the dashboard is the result of a SQL query executed against
your Sola app data at request time.

Run:
  python3 server.py            # -> http://localhost:8765

Credentials are read from (in order):
  1. env vars SOLA_CLIENT_ID / SOLA_CLIENT_SECRET
  2. sola_secrets.json  ({"client_id": "...", "client_secret": "..."})
"""

import json
import os
import ssl
import time
import base64
import http.server
import socketserver
import urllib.request
import urllib.parse
from pathlib import Path


def _ssl_context():
    """Build an SSL context that works on macOS (Python ships without system certs)."""
    if os.environ.get("SOLA_INSECURE_SSL") == "1":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


SSL_CTX = _ssl_context()

PORT = int(os.environ.get("PORT", "8765"))
ROOT = Path(__file__).parent
TOKEN_URL = "https://auth.sola.security/oauth/token"
MCP_URL = "https://api.sola.security/mcp"

_token_cache = {"access_token": None, "exp": 0}
_app_cache = {"id": None, "name": None, "queries": 0, "alerts": 0, "sources": 0}


# --------------------------------------------------------------------------- #
#  Credentials + OAuth                                                         #
# --------------------------------------------------------------------------- #
def _load_dotenv():
    """Load KEY=VALUE pairs from a local .env into os.environ (no override)."""
    f = ROOT / ".env"
    if not f.exists():
        return
    for line in f.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _creds():
    _load_dotenv()
    cid = os.environ.get("SOLA_CLIENT_ID")
    csec = os.environ.get("SOLA_CLIENT_SECRET")
    if cid and csec:
        return cid, csec
    raise RuntimeError("Missing Sola credentials — set SOLA_CLIENT_ID / SOLA_CLIENT_SECRET in .env")


def _jwt_exp(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
    except Exception:
        return 0


def get_token():
    now = time.time()
    if _token_cache["access_token"] and _token_cache["exp"] - 60 > now:
        return _token_cache["access_token"]
    cid, csec = _creds()
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": cid,
        "client_secret": csec,
        "scope": "openid profile email",
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30, context=SSL_CTX) as r:
        tok = json.loads(r.read())["access_token"]
    _token_cache["access_token"] = tok
    _token_cache["exp"] = _jwt_exp(tok) or (now + 3000)
    return tok


# --------------------------------------------------------------------------- #
#  MCP transport (Streamable HTTP + SSE)                                       #
# --------------------------------------------------------------------------- #
def _parse_sse(body):
    """Return the JSON-RPC result object from an SSE/JSON body."""
    chunks = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            chunks.append(line[5:].strip())
    raw = "".join(chunks) if chunks else body.strip()
    obj = json.loads(raw)
    if "error" in obj:
        raise RuntimeError(f"MCP error: {obj['error']}")
    return obj.get("result", {})


def mcp_call(method, params, _id=1):
    req = urllib.request.Request(
        MCP_URL,
        data=json.dumps({"jsonrpc": "2.0", "id": _id, "method": method, "params": params}).encode(),
        headers={
            "Authorization": f"Bearer {get_token()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
    )
    with urllib.request.urlopen(req, timeout=60, context=SSL_CTX) as r:
        return _parse_sse(r.read().decode())


def _structured(res):
    if res.get("structuredContent"):
        return res["structuredContent"]
    return json.loads(res["content"][0]["text"])


def sql(query):
    """Run read-only SQL via the MCP and return a list of row dicts."""
    sc = _structured(mcp_call("tools/call", {"name": "execute_sql", "arguments": {"sql": query}}))
    cols = [c["name"] for c in sc.get("columns", [])]
    return [dict(zip(cols, row)) for row in sc.get("rows", [])]


def load_app_meta():
    if _app_cache["id"]:
        return _app_cache
    sc = _structured(mcp_call("tools/call", {"name": "list_apps", "arguments": {}}))
    app = sc["apps"][0]
    _app_cache["id"], _app_cache["name"] = app["id"], app["name"]
    dsc = _structured(mcp_call("tools/call", {"name": "get_app_details", "arguments": {"app_id": app["id"]}}))
    _app_cache["queries"] = len(dsc.get("queries", []))
    _app_cache["alerts"] = len(dsc.get("monitor_rules", []))
    _app_cache["sources"] = len(dsc.get("vendors", {})) + len(dsc.get("connectors", []))
    return _app_cache


# --------------------------------------------------------------------------- #
#  Live detection queries  (every value on the dashboard comes from these)     #
# --------------------------------------------------------------------------- #
Q = {
    "mfa_fatigue": """
        WITH f AS (
          SELECT actor_alternate_id AS user_email, actor_display_name AS name,
                 client_ip_address AS ip,
                 client_geographical_context->>'city' AS city,
                 client_geographical_context->>'country' AS country,
                 published AS t
          FROM okta_system_log
          WHERE event_type='user.authentication.auth_via_mfa' AND outcome_result <> 'SUCCESS'
        ),
        s AS (
          SELECT actor_alternate_id AS user_email, published AS t
          FROM okta_system_log
          WHERE event_type='user.authentication.auth_via_mfa' AND outcome_result='SUCCESS'
        ),
        joined AS (
          SELECT f.user_email, f.name, f.ip, f.city, f.country, f.t AS fail_t,
                 MIN(s.t) AS success_t
          FROM f JOIN s ON s.user_email=f.user_email AND s.t > f.t AND s.t <= f.t + INTERVAL '10 minutes'
          GROUP BY f.user_email, f.name, f.ip, f.city, f.country, f.t
        )
        SELECT user_email, name, ip, city, country,
               COUNT(*) AS failures, MIN(fail_t) AS first_fail,
               MAX(fail_t) AS last_fail, MIN(success_t) AS success_after
        FROM joined
        GROUP BY user_email, name, ip, city, country
        HAVING COUNT(*) >= 3
        ORDER BY failures DESC
    """,
    "failed_mfa": """
        SELECT actor_alternate_id AS user_email, published AS t,
               client_ip_address AS ip,
               client_geographical_context->>'city' AS city,
               client_geographical_context->>'country' AS country
        FROM okta_system_log
        WHERE event_type='user.authentication.auth_via_mfa' AND outcome_result <> 'SUCCESS'
        ORDER BY published DESC LIMIT 25
    """,
    "public_repos": """
        SELECT name_with_owner AS repo, owner_login, visibility, pushed_at
        FROM github_owned_repository
        WHERE visibility='PUBLIC'
        ORDER BY pushed_at DESC
    """,
    "all_repos": """
        SELECT name_with_owner AS repo, owner_login, visibility, is_private, pushed_at
        FROM github_owned_repository
        ORDER BY (visibility='PUBLIC') DESC, name_with_owner
    """,
    "elevated_collabs": """
        SELECT rc.repository_full_name AS repo, rc.user_login AS collaborator,
               rc.permission, rc.affiliation, r.visibility
        FROM github_repository_collaborator rc
        LEFT JOIN github_owned_repository r ON r.name_with_owner = rc.repository_full_name
        WHERE rc.permission IN ('WRITE','ADMIN','MAINTAIN')
        ORDER BY CASE rc.permission WHEN 'ADMIN' THEN 0 WHEN 'MAINTAIN' THEN 1 ELSE 2 END,
                 rc.repository_full_name
    """,
    "behavioral": """
        SELECT actor_alternate_id AS user_email, published AS t, event_type, outcome_result,
               client_ip_address AS ip,
               client_geographical_context->>'country' AS country,
               (debug_context_debug_data->>'behaviors' ILIKE '%New Country=POSITIVE%') AS new_country,
               (debug_context_debug_data->>'behaviors' ILIKE '%Velocity=POSITIVE%') AS impossible_travel,
               (debug_context_debug_data->>'behaviors' ILIKE '%New IP=POSITIVE%') AS new_ip,
               (debug_context_debug_data->>'behaviors' ILIKE '%New Device=POSITIVE%') AS new_device
        FROM okta_system_log
        WHERE event_type IN ('user.session.start','user.authentication.sso','user.authentication.auth_via_mfa')
          AND actor_alternate_id IS NOT NULL
        ORDER BY published DESC LIMIT 30
    """,
    "auth_outcomes": """
        SELECT
          SUM(CASE WHEN outcome_result='SUCCESS' THEN 1 ELSE 0 END) AS success,
          SUM(CASE WHEN outcome_result='FAILURE' THEN 1 ELSE 0 END) AS failure,
          SUM(CASE WHEN outcome_result NOT IN ('SUCCESS','FAILURE') THEN 1 ELSE 0 END) AS other
        FROM okta_system_log
    """,
    "event_types": """
        SELECT event_type AS type, COUNT(*) AS n
        FROM okta_system_log GROUP BY event_type ORDER BY n DESC LIMIT 8
    """,
    "top_ips": """
        SELECT client_ip_address AS ip,
               client_geographical_context->>'city' AS city,
               client_geographical_context->>'country' AS country,
               COUNT(*) AS n
        FROM okta_system_log WHERE client_ip_address IS NOT NULL
        GROUP BY 1,2,3 ORDER BY n DESC LIMIT 8
    """,
    "totals": """
        SELECT
          (SELECT COUNT(*) FROM okta_system_log) AS okta_events,
          (SELECT COUNT(*) FROM okta_user) AS okta_users,
          (SELECT COUNT(*) FROM github_owned_repository) AS repos,
          (SELECT COUNT(*) FROM github_repository_collaborator) AS collaborators
    """,
    "collab_by_perm": """
        SELECT permission, COUNT(*) AS n
        FROM github_repository_collaborator
        GROUP BY permission ORDER BY n DESC
    """,
    "repo_visibility": """
        SELECT visibility, COUNT(*) AS n
        FROM github_owned_repository
        GROUP BY visibility ORDER BY n DESC
    """,
    "by_country": """
        SELECT client_geographical_context->>'country' AS country, COUNT(*) AS n
        FROM okta_system_log
        WHERE client_geographical_context->>'country' IS NOT NULL
        GROUP BY 1 ORDER BY n DESC LIMIT 8
    """,
}


def build_payload():
    meta = load_app_meta()
    out = {}
    for key, query in Q.items():
        try:
            out[key] = sql(query)
        except Exception as e:
            out[key] = {"error": str(e)}

    def rows(k):
        return out[k] if isinstance(out.get(k), list) else []

    fatigue = rows("mfa_fatigue")
    pub = rows("public_repos")
    elev = rows("elevated_collabs")
    failed = rows("failed_mfa")
    behav = rows("behavioral")
    ao = (rows("auth_outcomes") or [{}])[0] if rows("auth_outcomes") else {}
    tot = (rows("totals") or [{}])[0] if rows("totals") else {}

    behav_flags = [b for b in behav if b.get("new_country") or b.get("impossible_travel")]

    # Risk score derived strictly from real signals
    score = 0
    score += 35 if fatigue else 0
    score += 25 * min(len(pub), 2)
    score += 12 * min(len(elev), 3)
    score += 15 if behav_flags else 0
    score += min(int(ao.get("failure") or 0), 10)
    score = min(score, 100)
    level = "CRITICAL" if score >= 75 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"

    reasons = []
    if fatigue:
        reasons.append(f"{len(fatigue)} user(s) hit the MFA-fatigue pattern (3+ failures then success in 10 min)")
    if pub:
        reasons.append(f"{len(pub)} PUBLIC repository(ies) exposed")
    if elev:
        reasons.append(f"{len(elev)} collaborator(s) with WRITE/ADMIN access")
    if behav_flags:
        reasons.append(f"{len(behav_flags)} login(s) flagged new-country / impossible-travel")
    if not reasons:
        reasons.append("No high-risk signals in the current data")

    mitre = []
    if fatigue or int(ao.get("failure") or 0) > 0:
        mitre.append({"id": "T1621", "name": "MFA Request Generation", "tactic": "Credential Access"})
    if behav_flags:
        mitre.append({"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"})
    if elev:
        mitre.append({"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"})
    if pub:
        mitre.append({"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"})

    coverage = [
        {"name": "Okta MFA Fatigue (3+ fails → success)", "hits": len(fatigue)},
        {"name": "Failed MFA events", "hits": len(failed)},
        {"name": "Public repositories exposed", "hits": len(pub)},
        {"name": "Collaborators with WRITE/ADMIN", "hits": len(elev)},
        {"name": "Logins flagged new-country / velocity", "hits": len(behav_flags)},
    ]

    return {
        "app": {"id": meta["id"], "name": meta["name"]},
        "data_mode": "live",
        "kpis": {
            "risk_score": score, "risk_level": level,
            "okta_events": tot.get("okta_events", 0),
            "okta_users": tot.get("okta_users", 0),
            "repos": tot.get("repos", 0),
            "public_repos": len(pub),
            "elevated_collabs": len(elev),
            "auth_success": ao.get("success", 0),
            "auth_failure": ao.get("failure", 0),
            "queries_armed": meta["queries"],
            "alerts_armed": meta["alerts"],
            "data_sources": meta["sources"],
            "mfa_fatigue_users": len(fatigue),
        },
        "verdict": {"level": level, "score": score, "reasons": reasons},
        "mfa_fatigue": fatigue,
        "failed_mfa": failed,
        "public_repos": pub,
        "all_repos": rows("all_repos"),
        "elevated_collabs": elev,
        "behavioral": behav,
        "charts": {
            "auth_outcomes": ao,
            "event_types": rows("event_types"),
            "top_ips": rows("top_ips"),
            "collab_by_perm": rows("collab_by_perm"),
            "repo_visibility": rows("repo_visibility"),
            "by_country": rows("by_country"),
        },
        "detection_coverage": coverage,
        "mitre": mitre,
    }


# --------------------------------------------------------------------------- #
#  HTTP server                                                                 #
# --------------------------------------------------------------------------- #
class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path.split("?")[0] == "/api/incident":
            try:
                payload = json.dumps(build_payload()).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
            return
        return super().do_GET()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("\n  Account Takeover Tracer — LIVE from Sola MCP")
        print(f"  -> http://localhost:{PORT}\n")
        httpd.serve_forever()
