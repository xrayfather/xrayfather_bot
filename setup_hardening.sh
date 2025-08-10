#!/usr/bin/env bash
# setup_hardening.sh
# Debian/Ubuntu: user + SSH keys + disable passwords + random/explicit SSH port + UFW only SSH & Xray
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./setup_hardening.sh -u <username> -k "<public_ssh_key>" [-x <xray_port> ...] [-p <ssh_port>]

  -u   Имя создаваемого/существующего пользователя для SSH-входа
  -k   Публичный SSH-ключ (строка как для authorized_keys)
  -x   Xray порт (можно указывать несколько флагом -x или одной строкой "443,8443,10000")
  -p   (опц.) Порт SSH; если не указан — будет выбран случайный (≠ Xray и не занятый)

Примеры:
  sudo ./setup_hardening.sh -u deploy -k "ssh-ed25519 AAAA..." -x 443
  sudo ./setup_hardening.sh -u deploy -k "ssh-rsa AAAA..." -x "443,8443" -x 10000 -p 55222
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

if [[ $EUID -ne 0 ]]; then
  echo "Запустите с правами root (sudo)." >&2
  exit 1
fi

if [[ -z "$NEW_USER" || -z "$PUBKEY" ]]; then
  echo "Параметры -u и -k обязательны." >&2
  usage
  exit 1
fi

# Разворачиваем возможные списки в -x "443,8443 10000"
if ((${#XRAY_PORTS[@]} > 0)); then
  tmp=()
  for item in "${XRAY_PORTS[@]}"; do
    # заменим запятую и пробел на пробел, затем разнесём
    IFS=', ' read -r -a parts <<< "$item"
    for p in "${parts[@]}"; do
      [[ -n "$p" ]] && tmp+=("$p")
    done
  done
  XRAY_PORTS=("${tmp[@]}")
fi

# Валидация портов
is_valid_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
for p in "${XRAY_PORTS[@]}"; do
  if ! is_valid_port "$p"; then
    echo "Некорректный Xray порт: $p" >&2
    exit 1
  fi
done
if [[ -n "$SSH_PORT" ]] && ! is_valid_port "$SSH_PORT"; then
  echo "Некорректный SSH порт: $SSH_PORT" >&2
  exit 1
fi

# ---------- helpers ----------
port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnu | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -qx "$port"
  else
    netstat -ltnu 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -qx "$port"
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
    contains "$port" "${XRAY_PORTS[@]}" && continue
    port_in_use "$port" && continue
    echo "$port"; return 0
  done
}

# ---------- OS check ----------
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Скрипт рассчитан на Debian/Ubuntu (apt). apt-get не найден." >&2
  exit 1
fi

# ---------- packages ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends sudo ufw openssh-server

# ---------- user & key ----------
if ! id -u "$NEW_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

USER_HOME="$(getent passwd "$NEW_USER" | cut -d: -f6)"
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
touch "$AUTH_KEYS"
# Добавляем ключ, если такого нет (строгое сравнение строки)
grep -qxF "$PUBKEY" "$AUTH_KEYS" || echo "$PUBKEY" >> "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"
chown -R "$NEW_USER:$NEW_USER" "$USER_HOME/.ssh"

# ---------- sshd config ----------
SSHD_CFG="/etc/ssh/sshd_config"
if [[ ! -f /etc/ssh/sshd_config.backup_hardening ]]; then
  cp "$SSHD_CFG" /etc/ssh/sshd_config.backup_hardening
fi

set_sshd_option() {
  local key="$1" value="$2"
  if grep -qE "^[#\s]*${key}\b" "$SSHD_CFG"; then
    sed -i "s~^[#\s]*${key}\b.*~${key} ${value}~g" "$SSHD_CFG"
  else
    echo "${key} ${value}" >> "$SSHD_CFG"
  fi
}

set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "PermitRootLogin" "no"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitEmptyPasswords" "no"
# Разрешить вход только указанному пользователю (по желанию):
# set_sshd_option "AllowUsers" "$NEW_USER"

# ---------- SSH port ----------
if [[ -z "$SSH_PORT" ]]; then
  SSH_PORT="$(random_ssh_port)"
else
  # проверим конфликт с XRAY портами и занятость
  if contains "$SSH_PORT" "${XRAY_PORTS[@]}"; then
    echo "SSH порт ($SSH_PORT) не может совпадать с Xray портом." >&2
    exit 1
  fi
  if port_in_use "$SSH_PORT"; then
    echo "SSH порт $SSH_PORT уже занят." >&2
    exit 1
  fi
fi

set_sshd_option "Port" "$SSH_PORT"

# ---------- check sshd config ----------
if ! sshd -t 2>/tmp/sshd_check.err; then
  echo "Ошибка проверки sshd:"
  cat /tmp/sshd_check.err >&2
  echo "Восстановление бэкапа sshd_config..."
  cp /etc/ssh/sshd_config.backup_hardening "$SSHD_CFG"
  exit 1
fi

# ---------- UFW ----------
# Оставляем только SSH и Xray (сбросим правила)
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp
# Для Xray — откроем TCP и UDP для каждого порта
for p in "${XRAY_PORTS[@]}"; do
  ufw allow "${p}"/tcp
  ufw allow "${p}"/udp
done
ufw --force enable

# ---------- restart ssh ----------
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart ssh || systemctl restart sshd || true
else
  service ssh restart || service sshd restart || true
fi

echo
echo "Готово ✅"
echo "Пользователь:  $NEW_USER"
echo "SSH порт:      $SSH_PORT"
if ((${#XRAY_PORTS[@]} > 0)); then
  echo "Xray порты:    ${XRAY_PORTS[*]} (TCP+UDP разрешены)"
else
  echo "Xray порты:    не заданы (ничего не открывалось)"
fi
echo
echo "Подключение:   ssh -p $SSH_PORT $NEW_USER@<server_ip>"
