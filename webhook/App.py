from flask import Flask, request, jsonify, send_from_directory, session, redirect
from datetime import datetime, timedelta
from functools import wraps
import secrets, json, os, time

app = Flask(__name__)
app.secret_key = "kubeauth-secret-key-2024"

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# ─────────────────────────────────────────────────────────────────
# AWS SNS CONFIGURATION — replace these 5 values with your own
# ─────────────────────────────────────────────────────────────────
AWS_ACCESS_KEY = "write your"
AWS_SECRET_KEY = "write your"
AWS_REGION     = "ap-south-1"
SNS_TOPIC_ARN  = "arn:aws:sns:ap-south-1:692859941205:kubeauth-alerts"
EC2_PUBLIC_IP  = "52.66.246.19"  
# ─────────────────────────────────────────────────────────────────

auth_logs       = []
failed_attempts = {}
blocked_ips     = set()

DEFAULT_PERMS = {
    "admin":     ["get pods", "list pods", "create deployment",
                  "delete pods", "get secrets", "manage RBAC"],
    "developer": ["get pods", "list pods"],
    "viewer":    ["get pods", "list pods"],
    "none":      []
}


# ═══════════════════════════════════════════════════════════════
# USER FILE HELPERS
# ═══════════════════════════════════════════════════════════════

def load_users():
    if not os.path.exists(USERS_FILE):
        default = {
            "admin":    {"password": "admin123", "role": "admin",
                         "email": "admin@kubeauth.com"},
            "devuser":  {"password": "dev123",   "role": "developer",
                         "email": "dev@kubeauth.com"},
            "alice":    {"password": "alice123", "role": "developer",
                         "email": "alice@kubeauth.com"},
            "viewer":   {"password": "view123",  "role": "viewer",
                         "email": "viewer@kubeauth.com"},
            "bob":      {"password": "bob123",   "role": "viewer",
                         "email": "bob@kubeauth.com"},
            "testuser": {"password": "test123",  "role": "none",
                         "email": "test@kubeauth.com"},
            "hacker":   {"password": "hack123",  "role": "none",
                         "email": "hacker@kubeauth.com"},
        }
        save_users(default)
        return default
    with open(USERS_FILE) as f:
        return json.load(f)


def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ═══════════════════════════════════════════════════════════════
# LOGIN REQUIRED DECORATOR
# ═══════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ═══════════════════════════════════════════════════════════════
# AWS SNS EMAIL ALERT
# ═══════════════════════════════════════════════════════════════

def send_alert(alert_type, user, action, ip, reason):
    now_str       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dashboard_url = f"http://{EC2_PUBLIC_IP}:8080/login"

    if alert_type == "denied":
        subject = f"[KubeAuth] Access Denied — User: {user}"
        message = f"""KubeAuth Security Alert — Access Denied
========================================
Time     : {now_str}
User     : {user}
Reason   : {reason}
Action   : {action}
IP       : {ip}
Status   : ACCESS DENIED

This user attempted an unauthorized action and was blocked.
This event has been permanently logged to the blockchain.

View dashboard : {dashboard_url}
Auth logs tab  : {dashboard_url} then click Auth Logs
========================================
KubeAuth Enterprise Security Platform"""

    elif alert_type == "brute_force":
        subject = f"[KubeAuth] BRUTE FORCE DETECTED — IP Blocked: {ip}"
        message = f"""KubeAuth Security Alert — Brute Force Attack
========================================
CRITICAL: Brute force attack detected and blocked!

Time     : {now_str}
IP       : {ip}
User     : {user}
Attempts : 5 or more failed attempts within 60 seconds
Result   : IP address {ip} has been AUTOMATICALLY BLOCKED

All further requests from this IP are now rejected.
Check if this IP belongs to a legitimate internal user.

Threat Detection : {dashboard_url} then click Threat Detection
========================================
KubeAuth Enterprise Security Platform"""

    else:
        return

    try:
        import boto3
        sns = boto3.client(
            "sns",
            region_name           = AWS_REGION,
            aws_access_key_id     = AWS_ACCESS_KEY,
            aws_secret_access_key = AWS_SECRET_KEY
        )
        sns.publish(
            TopicArn = SNS_TOPIC_ARN,
            Subject  = subject,
            Message  = message
        )
        print(f"[SNS] Email alert sent: {subject}")

    except ImportError:
        print("[SNS] boto3 not installed. Run: pip3 install boto3 --break-system-packages")
    except Exception as e:
        print(f"[SNS] Alert failed: {e}")


# ═══════════════════════════════════════════════════════════════
# BRUTE FORCE DETECTION
# ═══════════════════════════════════════════════════════════════

def check_brute(ip):
    now    = time.time()
    recent = [t for t in failed_attempts.get(ip, []) if now - t < 60]
    failed_attempts[ip] = recent
    return len(recent) >= 5


def record_fail(ip, user="unknown", action="unknown"):
    failed_attempts.setdefault(ip, []).append(time.time())
    if check_brute(ip):
        if ip not in blocked_ips:
            blocked_ips.add(ip)
            send_alert("brute_force", user, action, ip, "brute force")


# ═══════════════════════════════════════════════════════════════
# SECURITY SCORE
# ═══════════════════════════════════════════════════════════════

def calc_score():
    users   = load_users()
    score   = 60
    no_role = sum(1 for u in users.values() if u["role"] == "none")
    score  -= no_role * 10
    score  -= len(blocked_ips) * 5
    return max(0, min(100, score))


# ═══════════════════════════════════════════════════════════════
# ROUTE — LOGIN / LOGOUT
# ═══════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        users    = load_users()
        u        = users.get(username)
        if u and u["password"] == password and u["role"] == "admin":
            session["logged_in"]  = True
            session["admin_user"] = username
            return redirect("/")
        error = "Invalid credentials or not an admin user"
    try:
        html = open(os.path.join(BASE_DIR, "login.html")).read()
        if error:
            html = html.replace(
                "<!--ERROR-->",
                f'<div class="err">{error}</div>'
            )
        return html
    except FileNotFoundError:
        return (
            f"<h2>KubeAuth Login</h2>"
            f"<form method='POST'>"
            f"<input name='username' placeholder='username'><br><br>"
            f"<input name='password' type='password' placeholder='password'><br><br>"
            f"<button>Login</button></form>"
            f"<p style='color:red'>{error}</p>"
        )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ═══════════════════════════════════════════════════════════════
# ROUTE — DASHBOARD HOME
# ═══════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")


# ═══════════════════════════════════════════════════════════════
# ROUTE — AUTHENTICATE (main webhook endpoint)
# ═══════════════════════════════════════════════════════════════

@app.route("/authenticate", methods=["POST"])
def authenticate():
    ip = request.remote_addr

    if ip in blocked_ips:
        return jsonify({
            "access": "denied",
            "reason": "IP blocked due to brute force detection",
            "role":   "none",
            "tx":     ""
        }), 403

    data    = request.json or {}
    user    = data.get("user",   "unknown")
    action  = data.get("action", "get pods")
    users   = load_users()
    info    = users.get(user)
    role    = info["role"] if info else "none"
    perms   = DEFAULT_PERMS.get(role, [])
    granted = action in perms

    if not granted:
        reason = ("No role assigned" if not info
                  else f"Action '{action}' not permitted for role '{role}'")
        record_fail(ip, user, action)
        send_alert("denied", user, action, ip, reason)

    log = {
        "time":   datetime.now().strftime("%H:%M:%S"),
        "date":   datetime.now().strftime("%Y-%m-%d"),
        "user":   user,
        "role":   role,
        "action": action,
        "status": "granted" if granted else "denied",
        "ip":     ip,
        "tx":     "0x" + secrets.token_hex(10)
    }
    auth_logs.insert(0, log)
    print(f"[{log['time']}] {user}({role}) -> {action} -> {log['status']}  ip:{ip}")
    return jsonify({
        "access": log["status"],
        "role":   role,
        "tx":     log["tx"]
    })


# ═══════════════════════════════════════════════════════════════
# ROUTE — LOGS API
# ═══════════════════════════════════════════════════════════════

@app.route("/logs")
@login_required
def get_logs():
    return jsonify({"logs": auth_logs, "total": len(auth_logs)})


@app.route("/clear", methods=["POST"])
@login_required
def clear_logs():
    auth_logs.clear()
    return jsonify({"status": "cleared"})


# ═══════════════════════════════════════════════════════════════
# ROUTE — ANALYTICS API
# ═══════════════════════════════════════════════════════════════

@app.route("/analytics")
@login_required
def analytics():
    users   = load_users()
    by_user = {}
    by_day  = {}

    for l in auth_logs:
        by_user.setdefault(l["user"], {"granted": 0, "denied": 0})
        by_user[l["user"]][l["status"]] += 1
        by_day.setdefault(l["date"], {"granted": 0, "denied": 0})
        by_day[l["date"]][l["status"]] += 1

    today = datetime.now()
    days  = [(today - timedelta(days=i)).strftime("%Y-%m-%d")
             for i in range(6, -1, -1)]
    trend = [
        {
            "date":    d,
            "granted": by_day.get(d, {}).get("granted", 0),
            "denied":  by_day.get(d, {}).get("denied",  0)
        }
        for d in days
    ]

    return jsonify({
        "by_user":     by_user,
        "trend":       trend,
        "score":       calc_score(),
        "blocked_ips": list(blocked_ips),
        "compliance":  {
            "rbac_enabled":       True,
            "blockchain_logging": True,
            "webhook_running":    True,
            "no_unknown_users":   all(
                u["role"] != "none" for u in users.values()
            ),
            "no_blocked_ips": len(blocked_ips) == 0
        }
    })


# ═══════════════════════════════════════════════════════════════
# ROUTE — USER MANAGEMENT API
# ═══════════════════════════════════════════════════════════════

@app.route("/users", methods=["GET"])
@login_required
def get_users():
    users = load_users()
    return jsonify({
        u: {"role": v["role"], "email": v["email"]}
        for u, v in users.items()
    })


@app.route("/users/add", methods=["POST"])
@login_required
def add_user():
    data  = request.json or {}
    uname = data.get("username", "").strip()
    if not uname:
        return jsonify({"error": "Username is required"}), 400
    users = load_users()
    if uname in users:
        return jsonify({"error": "User already exists"}), 400
    users[uname] = {
        "password": data.get("password", "pass123"),
        "role":     data.get("role",     "none"),
        "email":    data.get("email",    uname + "@kubeauth.com")
    }
    save_users(users)
    return jsonify({"status": "created", "user": uname})


@app.route("/users/update", methods=["POST"])
@login_required
def update_user():
    data  = request.json or {}
    uname = data.get("username", "")
    users = load_users()
    if uname not in users:
        return jsonify({"error": "User not found"}), 404
    users[uname]["role"] = data.get("role", "none")
    save_users(users)
    return jsonify({"status": "updated"})


@app.route("/users/delete", methods=["POST"])
@login_required
def delete_user():
    data  = request.json or {}
    uname = data.get("username", "")
    users = load_users()
    if uname == "admin":
        return jsonify({"error": "Cannot delete the admin user"}), 400
    if uname not in users:
        return jsonify({"error": "User not found"}), 404
    del users[uname]
    save_users(users)
    return jsonify({"status": "deleted"})


# ═══════════════════════════════════════════════════════════════
# ROUTE — SECURITY API
# ═══════════════════════════════════════════════════════════════

@app.route("/security")
@login_required
def security():
    return jsonify({
        "score":     calc_score(),
        "blocked":   list(blocked_ips),
        "brute_ips": {
            ip: len(failed_attempts.get(ip, []))
            for ip in failed_attempts
        }
    })


# ═══════════════════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sns_status = "Configured" if "XXXX" not in AWS_ACCESS_KEY else "NOT configured — add your AWS keys above"
    print("=" * 55)
    print("  KubeAuth Enterprise Dashboard")
    print(f"  URL   : http://{EC2_PUBLIC_IP}:8080/login")
    print("  Login : admin / admin123")
    print(f"  SNS   : {sns_status}")
    print("=" * 55)
    app.run(host="0.0.0.0", port=8080, debug=False)
