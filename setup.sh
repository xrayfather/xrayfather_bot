#!/usr/bin/env bash
# setup_hardening.sh
# Debian/Ubuntu hardening: user + SSH keys + disable passwords + random SSH port + UFW allow only SSH & Xray
set -euo pipefail

# ---------- args & usage ----------
usage() {
  cat <<EOF
Usage: sudo $0 -u <username> -k "<public_ssh_key>" -x <xray_port> [-p <ssh_port>]

  -u   Имя нового пользователя (или существующего)
  -k   Публичный SSH ключ (строкой, как в authorized_keys)
  -x   Порт Xray (будет открыт TCP и UDP)
  -p   (опц.) Порт SSH. Если не указан — сгенерируется случайный ( != xray_port, не занят )

Пример:
  sudo $0 -u deploy -k "ssh-ed25519 AAAA... user@host" -x 443
  sudo $0 -u deploy -k "ssh-rsa AAAA... user@host" -x 8443 -p 55222
EOF
}

NEW_USER=""
PUBKEY=""
XRAY_PORT=""
SSH_PORT=""

while getopts ":u:k:x:p:h" opt; do
  case "$opt" in
    u) NEW_USER="$OPTARG" ;;
    k) PUBKEY="$OPTARG" ;;
    x) XRAY_PORT="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG" >&2; usage; exit 1 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Запустите скрипт с правами root (sudo)." >&2
  exit 1
fi

if [[ -z "${NEW_USER}" || -z "${PUBKEY}" || -z "${XRAY_PORT}" ]]; then
  echo "Необходимо указать -u, -k и -x." >&2
  usage
  exit 1
fi

if ! [[ "${XRAY_PORT}" =~ ^[0-9]{1,5}$ ]] || (( XRAY_PORT < 1 || XRAY_PORT > 65535 )); then
  echo "Некорректный xray_port: ${XRAY_PORT}" >&2
  exit 1
fi

# ---------- helpers ----------
port_in_use() {
  local p="$1"
  # проверим TCP и UDP листенеры
  if command -v ss >/dev/null 2>&1; then
    ss -ltnu | awk '{print $5}' | sed 's/.*://g' | grep -qx "${p}" && return 0 || return 1
  else
    # fallback: netstat
    netstat -ltnu 2>/dev/null | awk '{print $4}' | sed 's/.*://g' | grep -qx "${p}" && return 0 || return 1
  fi
}

random_ssh_port() {
  local p
  while :; do
    p=$(shuf -i 1025-65000 -n 1)
    [[ "${p}" -eq "${XRAY_PORT}" ]] && continue
    port_in_use "${p}" && continue
    echo "${p}"
    return 0
  done
}

# ---------- system info ----------
if ! command -v apt-get >/dev/null 2>&1; then
  echo "Этот скрипт рассчитан на Debian/Ubuntu (apt). На вашей системе apt не найден." >&2
  exit 1
fi

# ---------- updates & packages ----------
echo "[1/7] Обновление пакетов..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends sudo ufw openssh-server

# ---------- user & ssh key ----------
echo "[2/7] Создание пользователя '${NEW_USER}' (если нет) и настройка SSH ключа..."
if ! id -u "${NEW_USER}" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "${NEW_USER}"
fi
usermod -aG sudo "${NEW_USER}"

USER_HOME="$(getent passwd "${NEW_USER}" | cut -d: -f6)"
mkdir -p "${USER_HOME}/.ssh"
chmod 700 "${USER_HOME}/.ssh"
AUTH_KEYS="${USER_HOME}/.ssh/authorized_keys"

# добавим ключ, если его ещё нет
touch "${AUTH_KEYS}"
grep -qxF "${PUBKEY}" "${AUTH_KEYS}" || echo "${PUBKEY}" >> "${AUTH_KEYS}"
chmod 600 "${AUTH_KEYS}"
chown -R "${NEW_USER}:${NEW_USER}" "${USER_HOME}/.ssh"

# ---------- sshd config ----------
echo "[3/7] Настройка sshd (запрет пароля, запрет root, включение ключей)..."
SSHD_CFG="/etc/ssh/sshd_config"

# делаем бэкап один раз
if [[ ! -f /etc/ssh/sshd_config.backup_hardening ]]; then
  cp "${SSHD_CFG}" /etc/ssh/sshd_config.backup_hardening
fi

set_sshd_option() {
  local key="$1"
  local value="$2"
  if grep -qE "^[#\s]*${key}\b" "${SSHD_CFG}"; then
    sed -i "s~^[#\s]*${key}\b.*~${key} ${value}~g" "${SSHD_CFG}"
  else
    echo "${key} ${value}" >> "${SSHD_CFG}"
  fi
}

set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "PermitRootLogin" "no"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitEmptyPasswords" "no"
# Разрешим вход только указанному пользователю (опционально; раскомментируйте при желании):
# set_sshd_option "AllowUsers" "${NEW_USER}"

# ---------- SSH port ----------
if [[ -z "${SSH_PORT}" ]]; then
  SSH_PORT="$(random_ssh_port)"
fi
if ! [[ "${SSH_PORT}" =~ ^[0-9]{1,5}$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
  echo "Некорректный ssh_port: ${SSH_PORT}" >&2
  exit 1
fi
if [[ "${SSH_PORT}" -eq "${XRAY_PORT}" ]]; then
  echo "ssh_port не может совпадать с xray_port." >&2
  exit 1
fi

echo "[4/7] Установка SSH порта: ${SSH_PORT}"
set_sshd_option "Port" "${SSH_PORT}"

# Проверим конфиг перед перезагрузкой
echo "[5/7] Проверка конфига sshd..."
if ! sshd -t 2>/tmp/sshd_check.err; then
  echo "Ошибка проверки sshd:"; cat /tmp/sshd_check.err >&2
  echo "Восстанавливаю бэкап sshd_config..."
  cp /etc/ssh/sshd_config.backup_hardening "${SSHD_CFG}"
  exit 1
fi

# ---------- firewall (UFW) ----------
echo "[6/7] Настройка UFW (разрешаем только SSH и Xray)..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow "${SSH_PORT}"/tcp
ufw allow "${XRAY_PORT}"/tcp
ufw allow "${XRAY_PORT}"/udp
ufw --force enable

# ---------- restart ssh ----------
echo "[7/7] Перезапуск sshd..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart ssh || systemctl restart sshd || true
else
  service ssh restart || service sshd restart || true
fi

# сохраним подсказку
echo "${SSH_PORT}" >/etc/ssh/sshd_port.conf

echo
echo "Готово ✅"
echo "Пользователь:  ${NEW_USER}"
echo "SSH порт:      ${SSH_PORT}"
echo "Xray порт:     ${XRAY_PORT} (TCP+UDP разрешены)"
echo
echo "Важно: Подключайтесь по SSH на новый порт: ssh -p ${SSH_PORT} ${NEW_USER}@<server_ip>"
