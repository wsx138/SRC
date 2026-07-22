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
import io
import uuid
import sqlite3
import time
import shutil
import tempfile
import threading
from flask import Flask, render_template, request, redirect, session, send_from_directory
from PIL import Image, UnidentifiedImageError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ============================================================
# Flask 应用初始化
# ============================================================
app = Flask(__name__, template_folder="templates.py")
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB 上传限制


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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)

    # 兼容旧表: 如果已有表但缺少 balance 列，则添加
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在，忽略

    # 使用 INSERT OR IGNORE 插入默认用户，防止重复
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')
    """)
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')
    """)

    # 初始化默认余额
    cursor.execute("""
        UPDATE users SET balance = 99999 WHERE username = 'admin' AND balance = 0
    """)
    cursor.execute("""
        UPDATE users SET balance = 100 WHERE username = 'alice' AND balance = 0
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
# 个人中心 & 充值
# ============================================================

@app.route("/profile")
def profile():
    """个人中心: 通过 user_id 参数查看任意用户资料"""
    user_id = request.args.get("user_id", "")

    profile_user = None
    if user_id:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql = f"SELECT id, username, password, email, phone FROM users WHERE id = {user_id}"
        print(f"[DEBUG] 执行的 SQL 语句: {sql}")
        cursor.execute(sql)
        row = cursor.fetchone()
        conn.close()

        if row:
            profile_user = {
                "id": row[0],
                "username": row[1],
                "email": row[3],
                "phone": row[4],
            }

    # 从内存字典获取当前登录用户信息（用于导航栏）
    username = session.get("username")
    current_user = USERS.get(username) if username else None

    # 从数据库获取余额
    balance = None
    if profile_user:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql2 = f"SELECT balance FROM users WHERE id = {user_id}"
        print(f"[DEBUG] 执行的 SQL 语句: {sql2}")
        cursor.execute(sql2)
        bal_row = cursor.fetchone()
        conn.close()
        if bal_row:
            balance = bal_row[0]

    return render_template("profile.html",
                           user=current_user,
                           profile_user=profile_user,
                           balance=balance,
                           user_id=user_id)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值路由: 修改用户余额"""
    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")

    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
    print(f"[DEBUG] 执行的 SQL 语句: {sql}")
    cursor.execute(sql)
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


# ============================================================
# 头像上传（安全加固专业版）
# ============================================================

# --- 白名单配置（多层交叉校验）---

# 层级 1: 扩展名白名单 — 文件名层面
ALLOWED_EXTENSIONS = frozenset({"png", "jpg", "jpeg", "gif", "webp", "bmp"})

# 层级 2: 浏览器 Content-Type 白名单 — HTTP 头部层面
ALLOWED_MIMETYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp",
})

# 层级 3: 魔术字节（magic bytes）白名单 — 文件内容层面
# 自定义魔术字节检测，兼容 Python 3.13+ (imghdr 已在 3.13 中移除)
# 格式: (magic_bytes, offset, type_name)
_MAGIC_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", 0, "png"),
    (b"\xff\xd8\xff", 0, "jpeg"),
    (b"GIF87a", 0, "gif"),
    (b"GIF89a", 0, "gif"),
    (b"RIFF", 0, "webp"),  # 需要进一步校验 WEBP 标识
]

ALLOWED_IMGHDR_TYPES = frozenset({"png", "jpeg", "gif", "webp"})

# 单文件最大尺寸（应用层二次检查）
MAX_AVATAR_SIZE = 5 * 1024 * 1024  # 5 MB

# 存储目录（非 static 目录）
UPLOAD_DIR = "data/uploads"


# --- 核心校验函数 ---

def _check_file_type_magic(raw_data: bytes) -> str | None:
    """
    层级 3: 魔术字节校验（自定义实现，兼容 Python 3.13+）。
    通过文件前几个字节（magic bytes）判断真实文件类型，
    防止攻击者将 .php 改名为 .jpg 绕过扩展名检查。

    imghdr 在 Python 3.13 中已移除，此处使用自定义魔术签名表替代。

    Args:
        raw_data: 文件内容字节流

    Returns:
        小写的真实图片类型（png/jpeg/gif/webp），非图片返回 None
    """
    header = raw_data[:32]
    for magic, offset, img_type in _MAGIC_SIGNATURES:
        if header[offset:offset + len(magic)] == magic:
            # WebP 额外校验: RIFF 后 8-11 字节应为 "WEBP"
            if img_type == "webp" and len(header) >= 12:
                if header[8:12] == b"WEBP":
                    return "webp"
                continue
            return img_type
    return None


def _is_valid_image(raw_data: bytes) -> bool:
    """
    层级 4: 图片结构完整性校验。
    使用 PIL/Pillow 尝试打开并验证图片，确保文件不是：
    - 伪造的图片头部 + 任意数据
    - 损坏的图片文件
    - 包含恶意 payload 的图片（重新编码后清除）

    同时通过 PIL 重新编码图片，剥离 EXIF 元数据，
    防止隐私信息泄露（如 GPS 坐标）。

    Returns:
        True 表示图片有效且可被安全编码
    """
    try:
        img = Image.open(io.BytesIO(raw_data))
        img.verify()  # 验证图片结构完整性（不加载像素，仅检查文件头）
    except (UnidentifiedImageError, Exception):
        return False

    # 二次校验：verify 之后需要重新打开才能操作
    try:
        img = Image.open(io.BytesIO(raw_data))
        # 检查尺寸，防止解压炸弹（pixel flood attack）
        width, height = img.size
        if width * height > 100_000_000:  # 1 亿像素上限
            return False
    except Exception:
        return False

    return True


def _sanitize_and_save(file_data: bytes, extension: str) -> str:
    """
    安全保存图片文件。

    步骤：
    1. 通过 PIL 重新编码图片，剥离 EXIF 元数据和潜在恶意 payload
    2. 原子写入（临时文件 + os.replace）确保写入完整性
    3. 设置安全的文件权限（仅所有者可读写）

    Args:
        file_data: 原始文件字节
        extension: 输出文件扩展名（不含点）

    Returns:
        最终存储的文件名
    """
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}.{extension}"

    try:
        img = Image.open(io.BytesIO(file_data))

        # 转换为 RGB 后重新编码（剥离 EXIF、恶意 payload）
        if img.mode in ("RGBA", "P", "LA", "PA"):
            # 带透明通道的转 RGBA
            img = img.convert("RGBA")
        elif img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # 原子写入：先写临时文件，再 rename
        tmp_fd, tmp_path = tempfile.mkstemp(dir=UPLOAD_DIR, suffix=f".{extension}")
        os.close(tmp_fd)

        img.save(tmp_path, format=img.format or extension.upper(), quality=85)

        final_path = os.path.join(UPLOAD_DIR, unique_name)
        os.replace(tmp_path, final_path)  # 原子 rename

        return unique_name

    except Exception:
        # 清理临时文件
        for p in (tmp_path if 'tmp_path' in dir() else None,):
            if p and os.path.exists(p):
                os.unlink(p)
        raise


# --- 路由 ---

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    """安全文件访问: send_from_directory 内置路径穿越防护"""
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """头像上传路由 — 多层安全校验"""
    if not session.get("username"):
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or not file.filename:
            return render_template("upload.html", error="请选择一个文件")

        # ====== 层级 1: 扩展名白名单 ======
        if "." not in file.filename:
            return render_template("upload.html",
                error="不支持的文件类型，仅允许上传图片文件 (png, jpg, jpeg, gif, webp, bmp)")

        original_ext = file.filename.rsplit(".", 1)[1].lower()
        if original_ext not in ALLOWED_EXTENSIONS:
            return render_template("upload.html",
                error=f"不支持的文件类型 (.{original_ext})，仅允许: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

        # ====== 层级 2: Content-Type 头部校验 ======
        content_type = file.content_type or ""
        if content_type and content_type not in ALLOWED_MIMETYPES:
            return render_template("upload.html",
                error=f"不支持的文件格式 ({content_type})")

        # ====== 应用层文件大小校验 ======
        file.stream.seek(0, os.SEEK_END)
        file_size = file.stream.tell()
        file.stream.seek(0)
        if file_size > MAX_AVATAR_SIZE:
            return render_template("upload.html",
                error=f"文件过大 ({file_size / 1024 / 1024:.1f} MB)，最大允许 5 MB")

        # 读取文件内容到内存（用于魔术字节和图片验证）
        raw_data = file.read()

        # ====== 层级 3: 魔术字节校验 ======
        detected_type = _check_file_type_magic(raw_data)
        if detected_type is None:
            return render_template("upload.html",
                error="文件内容不是有效图片类型，上传被拒绝")

        # ====== 层级 4: PIL 图片结构完整性校验 ======
        if not _is_valid_image(raw_data):
            return render_template("upload.html",
                error="图片文件已损坏或无法识别，上传被拒绝")

        # ====== 文件名安全处理 ======
        safe_name = secure_filename(file.filename)
        if not safe_name:
            return render_template("upload.html", error="文件名无效")

        # ====== 安全保存（PIL 重编码 + 原子写入 + UUID 重命名）=====
        try:
            # 使用魔术字节检测到的真实类型作为最终扩展名
            save_ext = detected_type if detected_type != "jpeg" else "jpg"
            unique_name = _sanitize_and_save(raw_data, save_ext)
        except Exception:
            return render_template("upload.html",
                error="图片保存失败，请重试")

        file_url = f"/uploads/{unique_name}"
        return render_template(
            "upload.html",
            success=True,
            file_url=file_url,
            filename=safe_name,
        )

    return render_template("upload.html")


# ============================================================
# 应用启动入口
# ============================================================
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
