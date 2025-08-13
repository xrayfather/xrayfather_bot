#!/usr/bin/env bash
# setup_hardening.sh — безопасная настройка SSH с откатом
set -Eeuo pipefail

# ========= ЛОГИ =========
TS="$(date +'%Y%m%d-%H%M%S')"
LOG="/var/log/xrayfather/setup-${TS}.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
log() { echo "[$(date +'%F %T')] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

# ========= АРГУМЕНТЫ =========
USERNAME=""; PASSWORD=""; PUBLIC_KEY=""; SSH_PORT=""
usage() {
  cat <<EOF
Usage: $0 --username USER --password PASS --public-key "ssh-ed25519 AAA..." --ssh-port PORT

Пример:
  $0 --username tg_123 --password 'S3cureP@ss' --public-key 'ssh-ed25519 AAAAC3...' --ssh-port 30522
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --username) USERNAME="$2"; shift 2;;
    --password) PASSWORD="$2"; shift 2;;
    --public-key) PUBLIC_KEY="$2"; shift 2;;
    --ssh-port) SSH_PORT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) die "Неизвестный аргумент: $1";;
  esac
done
[[ -n "$USERNAME" && -n "$PASSWORD" && -n "$PUBLIC_KEY" && -n "$SSH_PORT" ]] || { usage; exit 1; }

# ========= ПРОВЕРКИ =========
[[ "$(id -u)" -eq 0 ]] || die "Запустите от root."
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Некорректное имя пользователя: $USERNAME"
[[ "$SSH_PORT" =~ ^[0-9]{2,5}$ ]] || die "Некорректный порт: $SSH_PORT"
(( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) || die "Рекомендуется порт 1024–65535."
command -v sshd >/dev/null 2>&1 || die "Не найден sshd (openssh-server). Установите: apt-get update && apt-get install -y openssh-server"
if ss -tln | awk '{print $4}' | grep -Eq ":(^|.*:)${SSH_PORT}\$"; then
  die "Порт ${SSH_PORT} уже занят."
fi

# ========= ОТКАТ =========
ROLLBACK_CMDS=()
push_rollback() { ROLLBACK_CMDS+=("$*"); }
run_rollback() {
  log "Запуск отката… (${#ROLLBACK_CMDS[@]} шагов)"
  for (( idx=${#ROLLBACK_CMDS[@]}-1 ; idx>=0 ; idx-- )); do
    log "Откат: ${ROLLBACK_CMDS[$idx]}"
    bash -c "${ROLLBACK_CMDS[$idx]}" || log "Откат шага не удался: ${ROLLBACK_CMDS[$idx]}"
  done
}
on_error() {
  local ec=$?
  echo
  log "Произошла ошибка (код $ec). Лог: $LOG"
  run_rollback
  exit "$ec"
}
trap on_error ERR

# ========= ОБЁРТКИ ДЛЯ SSH-СЕРВИСА =========
SSH_MGR=""        # systemd | sysv | openrc
SSH_SERVICE=""    # ssh.service / sshd.service / snap.openssh.sshd.service / (для SysV/OpenRC) имя скрипта
SSH_SOCKET=""

detect_ssh_mgr() {
  if command -v systemctl >/dev/null 2>&1 && systemctl >/dev/null 2>&1; then
    SSH_MGR="systemd"
    SSH_SERVICE="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
      | awk '{print $1}' \
      | grep -E '^(sshd|ssh|snap\.openssh\.sshd)\.service$' -m1 || true)"
    SSH_SOCKET="$(systemctl list-unit-files --type=socket --no-legend 2>/dev/null \
      | awk '{print $1}' \
      | grep -E '^ssh\.socket$' -m1 || true)"
    if [[ -z "$SSH_SERVICE" && -n "$SSH_SOCKET" ]]; then
      if systemctl list-unit-files | awk '{print $1}' | grep -qx 'ssh\.service'; then
        SSH_SERVICE="ssh.service"
      fi
    fi
  else
    if command -v rc-service >/dev/null 2>&1; then
      SSH_MGR="openrc"
      if rc-service -l | grep -qx 'sshd'; then SSH_SERVICE="sshd"
      elif rc-service -l | grep -qx 'ssh'; then SSH_SERVICE="ssh"; fi
    elif command -v service >/dev/null 2>&1 || ls /etc/init.d/* >/dev/null 2>&1; then
      SSH_MGR="sysv"
      if [[ -x /etc/init.d/sshd ]]; then SSH_SERVICE="sshd"
      elif [[ -x /etc/init.d/ssh ]]; then SSH_SERVICE="ssh"; fi
    fi
  fi
}
svc_enable() {
  case "$SSH_MGR" in
    systemd) [[ -n "$SSH_SERVICE" ]] && systemctl enable "$SSH_SERVICE" || true;;
    openrc)  rc-update add "${SSH_SERVICE:-sshd}" default || true;;
    sysv)    true;;
  esac
}
svc_disable_socket_if_needed() {
  if [[ "$SSH_MGR" == "systemd" && -n "$SSH_SOCKET" ]]; then
    if systemctl is-active --quiet "$SSH_SOCKET" || systemctl is-enabled --quiet "$SSH_SOCKET"; then
      log "Отключаю ${SSH_SOCKET} (socket-activation)…"
      systemctl stop "$SSH_SOCKET" || true
      systemctl disable "$SSH_SOCKET" || true
      push_rollback "systemctl enable '$SSH_SOCKET' || true; systemctl start '$SSH_SOCKET' || true"
    fi
  fi
}
svc_restart() {
  case "$SSH_MGR" in
    systemd)
      local unit="${SSH_SERVICE:-ssh.service}"
      systemctl daemon-reload || true
      systemctl restart "$unit"
      ;;
    openrc)  rc-service "${SSH_SERVICE:-sshd}" restart ;;
    sysv)    service "${SSH_SERVICE:-ssh}" restart ;;
    *)       die "Не удалось определить менеджер сервисов SSH." ;;
  esac
}
svc_detect_or_die() {
  detect_ssh_mgr
  if [[ "$SSH_MGR" == "systemd" ]]; then
    if [[ -z "$SSH_SERVICE" && -z "$SSH_SOCKET" ]]; then
      die "Не найден ни ssh/sshd сервис, ни ssh.socket в systemd. Установите openssh-server."
    fi
  else
    [[ -n "$SSH_SERVICE" ]] || die "Не найден сервис SSH для ${SSH_MGR}. Установите openssh-server."
  fi
  log "Обнаружено: менеджер=${SSH_MGR}, сервис=${SSH_SERVICE:-<none>}, socket=${SSH_SOCKET:-<none>}"
}
svc_detect_or_die
svc_disable_socket_if_needed
svc_enable || true

# ========= БЭКАП КОНФИГА =========
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.${TS}"
cp -a "$SSHD_CONFIG" "$BACKUP"
push_rollback "cp -a '$BACKUP' '$SSHD_CONFIG' && (command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true) && true"
log "Сделан бэкап: $BACKUP"

# ========= ПОЛЬЗОВАТЕЛЬ =========
USER_CREATED="no"
if id -u "$USERNAME" >/dev/null 2>&1; then
  log "Пользователь $USERNAME уже существует — пропускаю создание."
else
  log "Создаю пользователя $USERNAME…"
  useradd -m -s /bin/bash "$USERNAME"
  USER_CREATED="yes"
  push_rollback "userdel -r '$USERNAME' || true"
fi
log "Устанавливаю пароль (не пишется в лог)…"
echo "${USERNAME}:${PASSWORD}" | chpasswd
log "Добавляю $USERNAME в группу sudo…"
if ! id -nG "$USERNAME" | tr ' ' '\n' | grep -qx "sudo"; then
  usermod -aG sudo "$USERNAME"
  push_rollback "gpasswd -d '$USERNAME' 'sudo' || true"
fi

# ========= КЛЮЧИ =========
log "Добавляю публичный ключ…"
USER_HOME="$(getent passwd "$USERNAME" | cut -d: -f6)"
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
touch "$AUTH_KEYS"
grep -qxF "$PUBLIC_KEY" "$AUTH_KEYS" || echo "$PUBLIC_KEY" >> "$AUTH_KEYS"
chown -R "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
chmod 600 "$AUTH_KEYS"

# ========= FIREWALL: УСТАНОВКА И НАСТРОЙКА =========
FIREWALL_UNDO_NEW=""
FIREWALL_UNDO_22=""

# Установим ufw, если отсутствует и есть apt-get
if ! command -v ufw >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    log "UFW не установлен — устанавливаю…"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get install -y ufw >/dev/null
  else
    log "UFW не установлен и apt-get не найден — пропускаю установку."
  fi
fi

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "^Status: active"; then
  log "UFW активен — разрешаю ${SSH_PORT}/tcp"
  ufw allow "${SSH_PORT}/tcp" || true
  FIREWALL_UNDO_NEW="ufw delete allow ${SSH_PORT}/tcp || true"
  push_rollback "$FIREWALL_UNDO_NEW"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  log "firewalld активен — разрешаю ${SSH_PORT}/tcp"
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" || true
  firewall-cmd --reload || true
  FIREWALL_UNDO_NEW="firewall-cmd --permanent --remove-port='${SSH_PORT}/tcp' || true; firewall-cmd --reload || true"
  push_rollback "$FIREWALL_UNDO_NEW"
else
  if command -v ufw >/dev/null 2>&1; then
    log "UFW установлен, но не активен — правила пропущены (не включаем автоматически)."
  else
    log "Файрвол не обнаружен или не активен — правила пропущены."
  fi
fi

# ========= ХЕЛПЕР: РАНТАЙМ-КАТАЛОГ SSHD =========
ensure_sshd_runtime_dir() {
  for d in /run/sshd /var/run/sshd; do
    if [[ ! -d "$d" ]]; then
      mkdir -p "$d"
      chown root:root "$d"
      chmod 0755 "$d"
      log "Создан runtime‑каталог $d"
    fi
  done
}

# ========= РЕДАКТОР sshd_config =========
set_sshd_option() {
  local key="$1"; shift
  local val="$*"
  if grep -qE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONFIG"; then
    awk -v K="$key" -v V="$val" '
      BEGIN{printed=0}
      /^[[:space:]]*Match[[:space:]]/ && printed==0 { print K" "V; printed=1 }
      {print}
      END{if(printed==0) print K" "V}
    ' "$SSHD_CONFIG" | sed -E "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/# &/" > "${SSHD_CONFIG}.tmp"
  else
    sed -E "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/# &/" "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    echo "${key} ${val}" >> "${SSHD_CONFIG}.tmp"
  fi
  mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
}

# ========= ШАГИ 3–5 (хардeнинг и добавление порта) =========
log "Харденинг: отключаю пароли и root, включаю pubkey…"
set_sshd_option "PasswordAuthentication" "no"
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "UsePAM" "yes"
set_sshd_option "PubkeyAuthentication" "yes"
set_sshd_option "PermitRootLogin" "no"

if ! grep -qE "^[[:space:]]*Port[[:space:]]+${SSH_PORT}\b" "$SSHD_CONFIG"; then
  log "Добавляю Port ${SSH_PORT}…"
  if grep -qE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONFIG"; then
    awk -v VAL="${SSH_PORT}" '
      BEGIN{printed=0}
      /^[[:space:]]*Match[[:space:]]/ && printed==0 { print "Port "VAL; printed=1 }
      {print}
      END{if(printed==0) print "Port "VAL}
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
  else
    echo "Port ${SSH_PORT}" >> "$SSHD_CONFIG"
  fi
else
  log "Port ${SSH_PORT} уже есть."
fi

# ========= ВАЛИДАЦИЯ И РЕСТАРТ (шаг 6) =========
log "Проверяю конфигурацию sshd…"
ensure_sshd_runtime_dir
sshd -t -f "$SSHD_CONFIG"
log "Перезапускаю SSH…"
svc_restart

# ========= ПРОВЕРКА ВХОДА ПО КЛЮЧУ НА НОВОМ ПОРТУ (шаг 7) =========
log "Генерирую временный ключ для проверки…"
TMPKEY="/root/.xrayfather_tmp_sshkey_${TS}"
ssh-keygen -t ed25519 -N '' -f "$TMPKEY" >/dev/null
trap 'rm -f "$TMPKEY" "$TMPKEY.pub" || true' EXIT
cat "${TMPKEY}.pub" >> "$AUTH_KEYS"
chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

log "Пробую вход ${USERNAME}@127.0.0.1:${SSH_PORT} по ключу…"
if ssh -p "$SSH_PORT" -i "$TMPKEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 "${USERNAME}@127.0.0.1" true; then
  log "Успех: вход по ключу на новом порту работает."
else
  die "Не удалось войти по ключу на новом порту."
fi

# Удаляем временный ключ
TMP_PUB_LINE="$(cat "${TMPKEY}.pub")"
sed -i "\#${TMP_PUB_LINE//\//\\/}#d" "$AUTH_KEYS"

# ========= ОТКЛЮЧАЕМ 22 И ФИНАЛЬНЫЙ РЕСТАРТ (шаг 8) =========
if grep -qE "^[[:space:]]*Port[[:space:]]+22\b" "$SSHD_CONFIG"; then
  log "Комментирую Port 22…"
  sed -E -i "s/^([[:space:]]*)Port[[:space:]]+22\b/\1# Port 22 (disabled ${TS})/" "$SSHD_CONFIG"
else
  log "Явный Port 22 не найден (возможно значение по умолчанию) — продолжаю."
fi

# Закрываем 22 в firewall
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "^Status: active"; then
  if ufw status | grep -qE '22/tcp[[:space:]]+ALLOW'; then
    log "UFW: удаляю allow 22/tcp…"
    ufw delete allow 22/tcp || true
    FIREWALL_UNDO_22="ufw allow 22/tcp || true"
    push_rollback "$FIREWALL_UNDO_22"
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  if firewall-cmd --list-ports | tr ' ' '\n' | grep -qx "22/tcp"; then
    log "firewalld: удаляю 22/tcp…"
    firewall-cmd --permanent --remove-port="22/tcp" || true
    firewall-cmd --reload || true
    FIREWALL_UNDO_22="firewall-cmd --permanent --add-port='22/tcp' || true; firewall-cmd --reload || true"
    push_rollback "$FIREWALL_UNDO_22"
  fi
fi

log "Повторная проверка sshd…"
ensure_sshd_runtime_dir
sshd -t -f "$SSHD_CONFIG"
log "Финальный рестарт SSH…"
svc_restart

# ========= ФИНАЛЬНАЯ ПРОВЕРКА ПОРТА =========
if ss -tln | awk '{print $4}' | grep -Eq ":(^|.*:)${SSH_PORT}\$"; then
  log "Готово: ssh слушает ${SSH_PORT}. Лог: $LOG"
else
  die "После финального рестарта порт ${SSH_PORT} не слушает."
fi

exit 0
