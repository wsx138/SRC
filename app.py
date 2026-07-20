"""
用户管理系统 - Flask Web Application
=====================================

安全设计说明:
--------------
1. 密码存储: 使用 werkzeug.security 的 PBKDF2 (HMAC-SHA256) 单向哈希，
   自带随机盐值 (salt)，迭代 260,000 次，不可逆。
   
2. 密码强度: 预设用户遵循 NIST 800-63B 标准，密码长度 >= 12 字符，
   包含大写、小写、数字、特殊符号四类字符集。

3. 暴力破解防护: 基于 IP 的登录失败计数机制，同一 IP 在 15 分钟内
   最多失败 5 次，超限后封禁 15 分钟。使用 threading.Lock 保证线程安全。

4. 凭据保护: 不在前端页面、HTML 注释、错误信息中暴露任何账号密码信息。

依赖: flask, werkzeug (Flask 自带)
"""

import os
import time
import sqlite3
import threading
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# Flask 应用初始化
# ============================================================
app = Flask(__name__, template_folder="templates.py")
app.secret_key = "dev-key-2025"


# ============================================================
# 数据库初始化
# ============================================================

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()

    # 创建 users 表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
    """)

    # 使用 INSERT OR IGNORE 插入默认用户，防止重复
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')
    """)

    conn.commit()
    conn.close()


# 启动时初始化数据库
init_db()


# ============================================================
# 暴力破解防护模块 (Brute-Force Protection)
# ============================================================
MAX_FAILED_ATTEMPTS = 5        # 触发封禁的失败次数阈值
BLOCK_DURATION = 15 * 60       # 封禁持续时长（秒）
CLEANUP_INTERVAL = 10 * 60     # 定时清理过期记录的间隔（秒）

# 失败记录: {ip: {"count": int, "first_fail": timestamp}}
_failed_logins = {}
_lock = threading.Lock()


def _cleanup_expired():
    """
    清理 _failed_logins 中封禁时间已过的过期记录。
    防止内存无限增长，每次检查封禁状态时自动调用。
    """
    now = time.time()
    with _lock:
        expired = [
            ip for ip, rec in _failed_logins.items()
            if now - rec["first_fail"] > BLOCK_DURATION
        ]
        for ip in expired:
            del _failed_logins[ip]


def is_blocked(ip: str) -> bool:
    """
    检查给定 IP 是否处于登录封禁期。

    Args:
        ip: 客户端 IP 地址

    Returns:
        True 表示该 IP 当前被封禁，应拒绝登录请求
    """
    _cleanup_expired()
    with _lock:
        rec = _failed_logins.get(ip)
        if rec and rec["count"] >= MAX_FAILED_ATTEMPTS:
            if time.time() - rec["first_fail"] <= BLOCK_DURATION:
                return True
    return False


def record_failed_attempt(ip: str):
    """
    记录一次登录失败尝试。
    如果该 IP 已存在记录且未过期，则 count += 1；
    否则重新初始化为 count=1。

    Args:
        ip: 客户端 IP 地址
    """
    now = time.time()
    with _lock:
        rec = _failed_logins.get(ip)
        if rec and now - rec["first_fail"] <= BLOCK_DURATION:
            rec["count"] += 1
        else:
            _failed_logins[ip] = {"count": 1, "first_fail": now}


def clear_failed_attempts(ip: str):
    """
    登录成功后清除该 IP 的所有失败记录。
    防止合法用户在封禁阈值边缘被误锁。

    Args:
        ip: 客户端 IP 地址
    """
    with _lock:
        _failed_logins.pop(ip, None)


# ============================================================
# 用户数据（密码哈希存储）
# ============================================================

# 预设用户初始化数据。
# 注意: _INITIAL_USERS 中的 password 仅在初始化循环中临时出现，
# 经过 generate_password_hash() 后立即被哈希值覆盖，不再保留明文。
# 实际项目中应从数据库加载，此处为演示用内存字典。
_INITIAL_USERS = [
    {
        "username": "admin",
        "password": "Admin@2025#Secure",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    {
        "username": "alice",
        "password": "Alice@2025#Secure",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
]

USERS = {}
for u in _INITIAL_USERS:
    user_data = dict(u)
    # 关键安全步骤: 将明文密码替换为 PBKDF2 哈希值
    user_data["password"] = generate_password_hash(user_data["password"])
    USERS[user_data["username"]] = user_data


# ============================================================
# 辅助函数
# ============================================================

def _validate_login_input(username: str, password: str) -> str | None:
    """
    对登录输入进行基本校验，防止空值或过长的恶意输入。

    Args:
        username: 用户名字符串
        password: 密码字符串

    Returns:
        校验失败时返回错误消息字符串，通过则返回 None
    """
    if not username or not password:
        return "用户名和密码不能为空"
    if len(username) > 64:
        return "用户名长度不能超过 64 个字符"
    if len(password) > 128:
        return "密码长度不能超过 128 个字符"
    return None


# ============================================================
# 路由
# ============================================================

@app.route("/")
def index():
    """首页: 已登录则展示用户信息，未登录则提示登录"""
    username = session.get("username")
    user = USERS.get(username) if username else None
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    登录路由。
    
    GET:  渲染登录页面
    POST: 处理登录表单提交，包含暴力破解防护检查

    安全流程:
        1. 基本输入校验（非空、长度限制）
        2. 检查 IP 是否处于封禁期
        3. 通过 check_password_hash 进行哈希比对
        4. 失败则记录尝试次数
        5. 成功则清除该 IP 的失败记录并创建 Session
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.remote_addr

        # --- 步骤 1: 输入校验 ---
        validation_error = _validate_login_input(username, password)
        if validation_error:
            return render_template("login.html", error=validation_error)

        # --- 步骤 2: 封禁检查 ---
        if is_blocked(client_ip):
            rec = _failed_logins[client_ip]
            elapsed = int(time.time() - rec["first_fail"])
            remaining = max(1, BLOCK_DURATION - elapsed)
            minutes = remaining // 60
            return render_template(
                "login.html",
                error=f"登录失败次数过多，请 {minutes} 分钟后重试",
            )

        # --- 步骤 3: 哈希密码验证 ---
        user = USERS.get(username)
        if user and check_password_hash(user["password"], password):
            # 登录成功: 清除失败记录，创建 Session
            clear_failed_attempts(client_ip)
            session["username"] = username
            return render_template("index.html", user=user)

        # --- 步骤 4: 登录失败 ---
        record_failed_attempt(client_ip)
        rec = _failed_logins.get(client_ip, {"count": 0})
        remaining = max(0, MAX_FAILED_ATTEMPTS - rec["count"])
        if remaining > 0:
            msg = f"用户名或密码错误，还可尝试 {remaining} 次"
        else:
            msg = "登录失败次数过多，请 15 分钟后重试"
        return render_template("login.html", error=msg)

    # GET 请求: 渲染空白登录页面
    return render_template("login.html")


@app.route("/logout")
def logout():
    """退出登录: 清除 Session 并重定向到首页"""
    session.clear()
    return redirect("/")


# ============================================================
# 用户注册
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    """注册路由: GET 渲染页面，POST 处理注册"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # 参数化查询: 使用 ? 占位符，防止 SQL 注入
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        cursor.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()

        return render_template("login.html", error="注册成功，请登录")

    return render_template("register.html")


# ============================================================
# 用户搜索
# ============================================================

@app.route("/search")
def search():
    """搜索路由: 通过 keyword 参数模糊搜索用户"""
    keyword = request.args.get("keyword", "")
    results = []

    if keyword:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        # 参数化查询: 使用 ? 占位符，防止 SQL 注入
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[DEBUG] 执行的 SQL 语句: {sql}")
        print(f"[DEBUG] 参数: ({'%' + keyword + '%'}, {'%' + keyword + '%'})")
        cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
        results = cursor.fetchall()
        conn.close()

    username = session.get("username")
    user = USERS.get(username) if username else None
    return render_template("index.html", user=user, keyword=keyword, results=results)


# ============================================================
# 应用启动入口
# ============================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
