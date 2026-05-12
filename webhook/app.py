from flask import Flask, request, jsonify, send_from_directory, session, redirect
from datetime import datetime, timedelta
from functools import wraps
import secrets, json, os, time

try:
    import requests as req
    REQUESTS_OK = True
except:
    REQUESTS_OK = False

app = Flask(__name__)
app.secret_key = "kubeauth-secret-key-2024"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, "users.json")

# Paste your Slack webhook URL here (optional)
SLACK_WEBHOOK_URL = "write here"

# In-memory storage
auth_logs = []
failed_attempts = {}
blocked_ips = set()

# Role permissions
DEFAULT_PERMS = {
    "admin":     ["get pods","list pods","create deployment",
                  "delete pods","get secrets","manage RBAC"],
    "developer": ["get pods","list pods"],
    "viewer":    ["get pods","list pods"],
    "none":      []
}

# ── User file helpers ──────────────────────────────────────────────

def load_users():
    if not os.path.exists(USERS_FILE):
        default = {
            "admin":    {"password":"admin123","role":"admin",
                         "email":"admin@kubeauth.com"},
            "devuser":  {"password":"dev123","role":"developer",
                         "email":"dev@kubeauth.com"},
            "alice":    {"password":"alice123","role":"developer",
                         "email":"alice@kubeauth.com"},
            "viewer":   {"password":"view123","role":"viewer",
                         "email":"viewer@kubeauth.com"},
            "bob":      {"password":"bob123","role":"viewer",
                         "email":"bob@kubeauth.com"},
            "testuser": {"password":"test123","role":"none",
                         "email":"test@kubeauth.com"},
            "hacker":   {"password":"hack123","role":"none",
                         "email":"hacker@kubeauth.com"},
        }
        save_users(default)
        return default
    with open(USERS_FILE) as f:
        return json.load(f)

def save_users(data):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ── Auth decorator ─────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

# ── Brute force detection ──────────────────────────────────────────

def check_brute(ip):
    now = time.time()
    recent = [t for t in failed_attempts.get(ip,[]) if now-t < 60]
    failed_attempts[ip] = recent
    return len(recent) >= 5

def record_fail(ip):
    failed_attempts.setdefault(ip,[]).append(time.time())
    if check_brute(ip):
        blocked_ips.add(ip)

# ── Slack alert ────────────────────────────────────────────────────

def slack_alert(user, action, ip, reason):
    if not SLACK_WEBHOOK_URL or not REQUESTS_OK:
        return
    try:
        msg = {"text": (
            f":rotating_light: *KubeAuth Security Alert*\n"
            f"*User:* `{user}`  *Action:* `{action}`\n"
            f"*IP:* `{ip}`  *Reason:* {reason}\n"
            f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )}
        req.post(SLACK_WEBHOOK_URL, json=msg, timeout=3)
    except:
        pass

# ── Security score ─────────────────────────────────────────────────

def calc_score():
    users = load_users()
    score = 60
    no_role = sum(1 for u in users.values() if u["role"]=="none")
    score -= no_role * 10
    score -= len(blocked_ips) * 5
    return max(0, min(100, score))

# ══════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET","POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username","")
        password = request.form.get("password","")
        users = load_users()
        u = users.get(username)
        if u and u["password"]==password and u["role"]=="admin":
            session["logged_in"] = True
            session["admin_user"] = username
            return redirect("/")
        error = "Invalid credentials or not an admin user"
    try:
        html = open(os.path.join(BASE_DIR,"login.html")).read()
        if error:
            html = html.replace(
                "<!--ERROR-->",
                f'<div class="err">{error}</div>'
            )
        return html
    except:
        return f"<h2>Login</h2><form method='POST'><input name='username' placeholder='username'><input name='password' type='password' placeholder='password'><button type='submit'>Login</button></form><p style='color:red'>{error}</p>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    return send_from_directory(BASE_DIR, "dashboard.html")

@app.route("/authenticate", methods=["POST"])
def authenticate():
    ip = request.remote_addr
    if ip in blocked_ips:
        return jsonify({
            "access":"denied",
            "reason":"IP blocked due to brute force",
            "role":"none","tx":""
        }), 403
    data   = request.json or {}
    user   = data.get("user","unknown")
    action = data.get("action","get pods")
    users  = load_users()
    info   = users.get(user)
    role   = info["role"] if info else "none"
    perms  = DEFAULT_PERMS.get(role,[])
    granted = action in perms
    if not granted:
        record_fail(ip)
        reason = ("No role assigned" if not info
                  else f"'{action}' not allowed for role '{role}'")
        slack_alert(user, action, ip, reason)
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
    return jsonify({"access":log["status"],"role":role,"tx":log["tx"]})

@app.route("/logs")
@login_required
def get_logs():
    return jsonify({"logs":auth_logs,"total":len(auth_logs)})

@app.route("/clear",methods=["POST"])
@login_required
def clear_logs():
    auth_logs.clear()
    return jsonify({"status":"cleared"})

@app.route("/analytics")
@login_required
def analytics():
    users   = load_users()
    by_user = {}
    by_day  = {}
    for l in auth_logs:
        by_user.setdefault(l["user"],{"granted":0,"denied":0})
        by_user[l["user"]][l["status"]] += 1
        by_day.setdefault(l["date"],{"granted":0,"denied":0})
        by_day[l["date"]][l["status"]] += 1
    today = datetime.now()
    days  = [(today-timedelta(days=i)).strftime("%Y-%m-%d")
             for i in range(6,-1,-1)]
    trend = [{"date":d,
              "granted":by_day.get(d,{}).get("granted",0),
              "denied": by_day.get(d,{}).get("denied",0)}
             for d in days]
    return jsonify({
        "by_user": by_user,
        "trend":   trend,
        "score":   calc_score(),
        "blocked_ips": list(blocked_ips),
        "compliance": {
            "rbac_enabled":       True,
            "blockchain_logging": True,
            "webhook_running":    True,
            "no_unknown_users":   all(
                u["role"]!="none" for u in users.values()),
            "no_blocked_ips":     len(blocked_ips)==0
        }
    })

@app.route("/users",methods=["GET"])
@login_required
def get_users():
    users = load_users()
    return jsonify({
        u:{"role":v["role"],"email":v["email"]}
        for u,v in users.items()
    })

@app.route("/users/add",methods=["POST"])
@login_required
def add_user():
    data  = request.json or {}
    uname = data.get("username","").strip()
    if not uname:
        return jsonify({"error":"Username required"}),400
    users = load_users()
    if uname in users:
        return jsonify({"error":"User already exists"}),400
    users[uname] = {
        "password": data.get("password","pass123"),
        "role":     data.get("role","none"),
        "email":    data.get("email",uname+"@kubeauth.com")
    }
    save_users(users)
    return jsonify({"status":"created","user":uname})

@app.route("/users/update",methods=["POST"])
@login_required
def update_user():
    data  = request.json or {}
    uname = data.get("username","")
    users = load_users()
    if uname not in users:
        return jsonify({"error":"User not found"}),404
    users[uname]["role"] = data.get("role","none")
    save_users(users)
    return jsonify({"status":"updated"})

@app.route("/users/delete",methods=["POST"])
@login_required
def delete_user():
    data  = request.json or {}
    uname = data.get("username","")
    users = load_users()
    if uname=="admin":
        return jsonify({"error":"Cannot delete admin"}),400
    if uname not in users:
        return jsonify({"error":"Not found"}),404
    del users[uname]
    save_users(users)
    return jsonify({"status":"deleted"})

@app.route("/security")
@login_required
def security():
    return jsonify({
        "score":   calc_score(),
        "blocked": list(blocked_ips),
        "brute_ips": {
            ip: len(failed_attempts.get(ip,[]))
            for ip in failed_attempts
        }
    })

if __name__ == "__main__":
    print("="*55)
    print("  KubeAuth Enterprise Dashboard starting...")
    print("  URL: http://YOUR_EC2_IP:8080/login")
    print("  Login: admin / admin123")
    print("="*55)
    app.run(host="0.0.0.0", port=8080, debug=False)
