import os
import secrets
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 使用环境变量或随机生成密钥，避免硬编码
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# Session 安全配置
app.config.update(
    SESSION_COOKIE_SECURE=True,    # 仅通过 HTTPS 传输 Cookie
    SESSION_COOKIE_HTTPONLY=True,  # 禁止 JavaScript 访问 Cookie
    SESSION_COOKIE_SAMESITE="Lax",
)

# 添加安全响应头
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


# ---------- 预设用户（密码已哈希存储，不再明文）----------
# 实际项目中应从数据库加载，此处为演示用内存字典
_DEFAULT_USERS = [
    {"username": "admin", "password": "Admin@2025#Secure", "role": "admin",
     "email": "admin@example.com", "phone": "13800138000", "balance": 99999},
    {"username": "alice", "password": "Alice@2025#Secure", "role": "user",
     "email": "alice@example.com", "phone": "13900139001", "balance": 100},
]

USERS = {}
for u in _DEFAULT_USERS:
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

        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    # 生产环境中 debug 应设为 False
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
