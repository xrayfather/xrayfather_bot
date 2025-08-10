#!/usr/bin/env bash
# setup_hardening.sh
# Debian/Ubuntu hardening: create user + SSH key login + disable passwords + set SSH port + UFW allow only SSH & Xray
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  sudo ./setup_hardening.sh -u <username> -k "<public_ssh_key>" [-x <port>[,<port>...]]... [-p <ssh_port>]

Options:
  -u   Username to allow SSH login (will be created if absent)
  -k   OpenSSH public key line (e.g. 'ssh-ed25519 AAAA... user@bot')
  -x   Xray port(s). May be passed multiple times or as comma/space-separated list, e.g.:
       -x 443 -x 8443    OR    -x "443,8443 10000"
  -p   SSH port to set (if omitted, a random free port will be chosen, avoiding Xray ports)

Examples:
  sudo ./setup_hardening.sh -u deploy -k "ssh-ed25519 AAAA... user@bot" -x 443
  sudo ./setup_hardening.sh -u deploy -k "ssh-rsa AAAA... user@bot" -x "443,8443" -p 55222
EOF
}

# ---------- parse args ----------
NEW_USER=""
PUBKEY=""
declare -a XRAY_PORTS=()
SSH_PORT=""

while getopts ":u:k:x:p:h" opt; do
  case "$opt" in
    u) NEW_USER="$OPTARG" ;;
    k) PUBKEY="$OPTARG" ;;
    x) XRAY_PORTS+=("$OPTARG") ;;
    p) SSH_PORT="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 1 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
  esac
done

if [[ -z "$NEW_USER" || -z "$PUBKEY" ]]; then
  echo "❌ Параметры -u и -k обязательны." >&2
  usage
  exit 1
fi

# ---------- helpers ----------
is_valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnu | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -qx "$port" || return 1
  else
    netstat -ltnu 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -qx "$port" || return 1
  fi
}

contains() {
  local needle="$1"; shift
  for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done
  return 1
}

random_ssh_port() {
  local port
  while :; do
    port=$(shuf -i 1025-65000 -n 1)
    contains "$port" "${XRAY_PORTS_FLAT[@]}" && continue
    port_in_use "$port" && continue
    echo "$port"; return 0
  done
}

set_sshd_option() {
  local key="$1" value="$2" file="/etc/ssh/sshd_config"
  if grep -qE "^[#[:space:]]*${key}\b" "$file"; then
    sed -i "s~^[#[:space:]]*${key}\b.*~${key} ${value}~g" "$file"
  else
    echo "${key} ${value}" >> "$file"
  fi
}

# ---------- flatten XRAY_PORTS ----------
if ((${#XRAY_PORTS[@]} > 0)); then
  tmp=()
  for item in "${XRAY_PORTS[@]}"; do
    # поддерживаем "443,8443 10000"
    IFS=', ' read -r -a parts <<< "$item"
    for p in "${parts[@]}"; do
      [[ -n "$p" ]] && tmp+=("$p")
    done
  done
  XRAY_PORTS=("${tmp[@]}")
fi
# Уникализируем и валидируем
declare -A seen=()
XRAY_PORTS_FLAT=()
for p in "${XRAY_PORTS[@]:-}"; do
  [[ -z "$p" ]] && continue
  if ! is_valid_port "$p"; then
    echo "❌ Некорректный Xray порт: $p" >&2; exit 1
  fi
  if [[ -z "${seen[$p]:-}" ]]; then
    XRAY_PORTS_FLAT+=("$p")
    seen[$p]=1
  fi
done

if [[ -n "$SSH_PORT" ]] && ! is_valid_port "$SSH_PORT"; then
  echo "❌ Некорректный SSH порт: $SSH_PORT" >&2; exit 1
fi

# ---------- OS check & packages ----------
if ! command -v apt-get >/dev/null 2>&1; then
  echo "❌ Скрипт рассчитан на Debian/Ubuntu (apt)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends sudo ufw openssh-server net-tools iproute2

# ---------- user & ssh key ----------
if ! id -u "$NEW_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

USER_HOME="$(getent passwd "$NEW_USER" | cut -d: -f6)"
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
touch "$AUTH_KEYS"
# добавляем ключ, если строки нет
grep -qxF "$PUBKEY" "$AUTH_KEYS" || echo "$PUBKEY" >> "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
chown -R "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh"

# ---------- sshd config ----------
SSHD_CFG="/etc/ssh/sshd_config"
if [[ ! -f /etc/ssh/sshd_config.backup_hardening ]]; then
  cp "$SSHD_CFG" /etc/ssh/sshd_config.backup_hardening
fi

set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "PermitRootLogin" "no"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitEmptyPasswords" "no"
# при желании можно ограничить вход только новым пользователем:
# set_sshd_option "AllowUsers" "$NEW_USER"

# ---------- SSH port ----------
if [[ -z "${SSH_PORT:-}" ]]; then
  SSH_PORT="$(random_ssh_port)"
else
  if contains "$SSH_PORT" "${XRAY_PORTS_FLAT[@]:-}"; then
    echo "❌ SSH порт ($SSH_PORT) не может совпадать с Xray портом." >&2
    exit 1
  fi
  if port_in_use "$SSH_PORT"; then
    echo "❌ SSH порт $SSH_PORT уже занят." >&2
    exit 1
  fi
fi
set_sshd_option "Port" "$SSH_PORT"

# ---------- validate sshd config ----------
if ! sshd -t 2>/tmp/sshd_check.err; then
  echo "❌ Ошибка проверки sshd_config:" >&2
  cat /tmp/sshd_check.err >&2
  echo "↩️ Восстанавливаю бэкап sshd_config..."
  cp /etc/ssh/sshd_config.backup_hardening "$SSHD_CFG"
  exit 1
fi

# ---------- UFW rules ----------
# ⚠️ Жёсткий вариант: сбросить все правила и открыть только нужное
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing

# SSH (только TCP)
ufw allow "${SSH_PORT}"/tcp

# Xray: TCP+UDP для каждого указанного порта
for p in "${XRAY_PORTS_FLAT[@]:-}"; do
  ufw allow "${p}"/tcp
  ufw allow "${p}"/udp
done

ufw --force enable

# ---------- ensure /run/sshd exists ----------
if [ ! -d /run/sshd ]; then
  mkdir -p /run/sshd
  chmod 0755 /run/sshd
  chown root:root /run/sshd
fi

# ---------- restart ssh ----------
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart ssh || systemctl restart sshd || true
else
  service ssh restart || service sshd restart || true
fi

echo
echo "✅ Готово!"
echo "Пользователь:   $NEW_USER"
echo "SSH порт:       $SSH_PORT"
if ((${#XRAY_PORTS_FLAT[@]:-0} > 0)); then
  echo "Xray порты:     ${XRAY_PORTS_FLAT[*]} (TCP+UDP разрешены)"
else
  echo "Xray порты:     не заданы"
fi
echo
echo "Подключение:    ssh -p $SSH_PORT $NEW_USER@<server_ip>"
