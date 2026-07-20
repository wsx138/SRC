# SQL 注入漏洞修复报告

## 基本信息

| 项目 | 详情 |
|------|------|
| **项目名称** | 用户管理系统 (Flask Web Application) |
| **漏洞类型** | SQL 注入 (SQL Injection) |
| **CWE 编号** | CWE-89 |
| **OWASP 映射** | A03:2021 – Injection |
| **代码仓库** | https://github.com/wsx138/SRC |
| **修复日期** | 2026-07-20 |

---

## 一、漏洞概述

### 受影响功能

| 路由 | 漏洞位置 | 根本原因 |
|------|---------|---------|
| `/register` | `app.py` 注册路由 | f-string 拼接 INSERT 语句 |
| `/search` | `app.py` 搜索路由 | f-string 拼接 SELECT 语句 |

### 漏洞原理

用户输入通过 **f-string 字符串拼接** 直接嵌入 SQL 语句，单引号 `'` 可打破字符串边界，改变 SQL 语法结构。

```python
# 修复前 — 搜索功能
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"

# 修复前 — 注册功能
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

---

## 二、修复方案

### 采用参数化查询（Parameterized Query）

将 f-string 字符串拼接替换为 **SQLite 参数化查询**（`?` 占位符 + 参数元组），使 SQL 引擎将用户输入**仅作为数据值处理**，而非 SQL 代码执行。

**核心原理**：参数化查询在 SQL 解析阶段就将 `?` 占位符标记为"数据位置"，用户输入在 SQL 编译后才被填入，永远不会被当作 SQL 关键字或操作符解析。

### 修复对比

#### 搜索功能

```python
# 修复前 — f-string 拼接
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
cursor.execute(sql)

# 修复后 — 参数化查询
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
cursor.execute(sql, (f"%{keyword}%", f"%{keyword}%"))
```

**关键细节**：`%` 通配符在参数值中拼接（`f"%{keyword}%"`），而非在 SQL 模板中拼接。参数值中的 `%` 被 SQLite 当作 LIKE 通配符正常处理，不会破坏 SQL 结构。

#### 注册功能

```python
# 修复前 — f-string 拼接
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
cursor.execute(sql)

# 修复后 — 参数化查询
sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
cursor.execute(sql, (username, password, email, phone))
```

---

## 三、修复验证

修复后对全部 4 个 POC 进行了重测，结果如下：

| POC | 攻击类型 | 修复前 | 修复后 |
|-----|---------|--------|--------|
| POC 1 | UNION 注入（`' UNION SELECT 1,…--`） | ✅ 成功（伪造数据出现） | ❌ 已失效（无搜索结果） |
| POC 2 | OR 万能条件（`' OR '1'='1`） | ✅ 成功（返回全部用户） | ❌ 已失效（无搜索结果） |
| POC 3 | 注册注入（用户名含 `', …)--`） | ✅ 成功（创建 hacker 用户） | ❌ 已失效（用户名被当作字面字符串存储） |
| POC 4 | UNION 提取密码（`' UNION SELECT …,password…--`） | ✅ 成功（admi123/alice2025 泄露） | ❌ 已失效（无搜索结果） |

### POC 3 详述：注册注入已被参数化

修复后注册注入 payload `hacker2', 'pass2', 'evil@x.com', '666')--` 被原样存储为用户名：

| ID | 用户名 | 邮箱 | 手机 |
|----|--------|------|------|
| 12 | `hacker2', 'pass2', 'evil@x.com', '666')--` | evil@x.com | 666 |

用户名完整包含了注入 payload 的原始字符串，证明 SQL 注入未执行，payload 被当作普通文本数据存储。

---

## 四、为什么参数化查询可以防止 SQL 注入

```
用户输入: ' OR '1'='1

【f-string 拼接】
SELECT * FROM users WHERE username LIKE '%' OR '1'='1%' ...
                                    ^^^^^^^^^^^^^^ ← SQL 语法被改写！

【参数化查询】
SQL 模板:   SELECT * FROM users WHERE username LIKE ? OR email LIKE ?
参数值:     ("%' OR '1'='1%", "%' OR '1'='1%")
                                          ↑
                      单引号在参数值中是普通字符，不参与 SQL 解析
                      SQL 引擎将其当作字面搜索关键词处理
```

SQLite/MySQL/PostgreSQL 在参数化查询中的执行流程：
1. **预编译**：解析 SQL 模板，确定 `?` 占位符位置
2. **绑定参数**：将参数值填入已编译的 SQL 执行计划
3. **执行**：参数值仅在数据层面生效，不会重新解析

---

## 五、修复代码变更清单

| 文件 | 行号 | 变更 |
|------|------|------|
| `app.py` | ~300 | 注册：f-string → `?` 占位符 + 参数元组 |
| `app.py` | ~325 | 搜索：f-string → `?` 占位符 + 参数元组 |

---

## 六、总结

通过将 2 处 f-string SQL 拼接替换为参数化查询，彻底消除了 SQL 注入漏洞。修复后：

- 4 个注入 POC 全部失效
- 正常注册和搜索功能不受影响
- 用户输入中即使包含 SQL 关键字/特殊字符也不会影响 SQL 语义
- 代码可读性和维护性均有提升

---

*报告生成时间: 2026-07-20*
