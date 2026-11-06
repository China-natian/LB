#!/usr/bin/env bash
# Build-time and post-pull contract check for the worker image.
set -uo pipefail

fail=0
ok() { printf 'ok: %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

require() {
    if command -v "$1" >/dev/null 2>&1; then ok "$1"; else bad "missing $1"; fi
}

for tool in \
    nmap masscan onego zombie spray setcap getcap \
    skills codex claude pi playwright-cli \
    rg fd jq websocat \
    nxc netexec crackmapexec certipy \
    kubectl subfinder dnsx adidnsdump \
    impacket-secretsdump secretsdump.py ntlmrelayx.py psexec.py \
    bloodyad coercer chisel naabu nuclei katana dalfox \
    dirsearch feroxbuster nikto jadx \
    python3 pip3 javac8 java8 mvn \
    aws tccli git curl wget unzip sudo; do
    require "$tool"
done

if nmap --version >/dev/null 2>&1; then ok "nmap executes"; else bad "nmap cannot execute"; fi
if masscan --version >/dev/null 2>&1; then ok "masscan executes"; else bad "masscan cannot execute"; fi
if onego --version >/dev/null 2>&1; then ok "onego executes"; else bad "onego cannot execute"; fi

for binary in /usr/lib/nmap/nmap "$(readlink -f "$(command -v masscan 2>/dev/null)" 2>/dev/null)"; do
    [ -n "$binary" ] && [ -f "$binary" ] || continue
    caps="$(getcap "$binary" 2>/dev/null || true)"
    case "$caps" in
        *cap_net_raw*) ok "caps $binary" ;;
        *) bad "missing cap_net_raw on $binary ($caps)" ;;
    esac
    case "$caps" in
        *cap_net_admin*) bad "cap_net_admin still set on $binary" ;;
    esac
done

if python3 -c 'import pwn, pymongo, redis, pymysql' >/dev/null 2>&1; then
    ok "python offensive modules"
else
    bad "python offensive modules import failed"
fi

if sudo -n true >/dev/null 2>&1; then ok "passwordless sudo"; else bad "passwordless sudo unavailable"; fi
if [ -w "$HOME" ]; then ok "home writable"; else bad "home not writable: $HOME"; fi
if [ -d /home/kali/skills ] && [ -w /home/kali/skills ]; then
    ok "skills directory writable"
else
    bad "skills directory missing or not writable"
fi
if skills list >/dev/null 2>&1; then ok "skills CLI"; else bad "skills CLI failed"; fi

if [ "$fail" -ne 0 ]; then
    echo "worker image smoke test failed" >&2
    exit 1
fi
echo "worker image smoke test passed"
