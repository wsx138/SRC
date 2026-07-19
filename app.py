import time
import threading
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# ---------- 登录失败次数限制（防暴力破解）----------
MAX_FAILED_ATTEMPTS = 5       # 最大失败次数
BLOCK_DURATION = 15 * 60      # 封禁时长（秒）：15 分钟
CLEANUP_INTERVAL = 10 * 60    # 清理过期记录的间隔（秒）

_failed_logins = {}            # {ip: {"count": int, "first_fail": timestamp}}
_lock = threading.Lock()


def _cleanup_expired():
    """清理超过封禁时长的过期记录"""
    now = time.time()
    with _lock:
        expired = [ip for ip, rec in _failed_logins.items()
                   if now - rec["first_fail"] > BLOCK_DURATION]
        for ip in expired:
            del _failed_logins[ip]


def is_blocked(ip: str) -> bool:
    """检查 IP 是否被封禁"""
    _cleanup_expired()
    with _lock:
        rec = _failed_logins.get(ip)
        if rec and rec["count"] >= MAX_FAILED_ATTEMPTS:
            if time.time() - rec["first_fail"] <= BLOCK_DURATION:
                return True
    return False


def record_failed_attempt(ip: str):
    """记录一次登录失败"""
    now = time.time()
    with _lock:
        rec = _failed_logins.get(ip)
        if rec and now - rec["first_fail"] <= BLOCK_DURATION:
            rec["count"] += 1
        else:
            _failed_logins[ip] = {"count": 1, "first_fail": now}


def clear_failed_attempts(ip: str):
    """登录成功后清除该 IP 的失败记录"""
    with _lock:
        _failed_logins.pop(ip, None)

# ---------- 预设用户（密码已哈希存储，不再明文）----------
# 实际项目中应从数据库加载，此处为演示用内存字典
_INITIAL_USERS = [
    {"username": "admin", "password": "Admin@2025#Secure", "role": "admin",
     "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    {"username": "alice", "password": "Alice@2025#Secure", "role": "user",
     "email": "alice@example.com", "phone": "13900139001", "balance": 100},
]

USERS = {}
for u in _INITIAL_USERS:
    user_data = dict(u)
    # 密码经过 werkzeug 哈希处理后存储，不保留明文
    user_data["password"] = generate_password_hash(user_data["password"])
    USERS[user_data["username"]] = user_data


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        client_ip = request.remote_addr

        # 检查是否已被封禁
        if is_blocked(client_ip):
            remaining = BLOCK_DURATION - int(time.time() - _failed_logins[client_ip]["first_fail"])
            minutes = max(1, remaining // 60)
            return render_template("login.html",
                                   error=f"登录失败次数过多，请 {minutes} 分钟后重试")

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            clear_failed_attempts(client_ip)
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            record_failed_attempt(client_ip)
            rec = _failed_logins.get(client_ip, {"count": 0})
            remaining = max(0, MAX_FAILED_ATTEMPTS - rec["count"])
            if remaining > 0:
                msg = f"用户名或密码错误，还可尝试 {remaining} 次"
            else:
                msg = f"登录失败次数过多，请 15 分钟后重试"
            return render_template("login.html", error=msg)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
