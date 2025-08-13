#!/usr/bin/env bash
set -Eeuo pipefail

# ====== Конфиг логирования ======
TS="$(date +'%Y%m%d-%H%M%S')"
LOG="/var/log/xrayfather/setup-${TS}.log"
mkdir -p "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

# ====== Утилиты ======
die() { echo "[ERROR] $*" >&2; exit 1; }
log() { echo "[$(date +'%F %T')] $*"; }

# ====== Парсинг аргументов ======
USERNAME=""
PASSWORD=""
PUBLIC_KEY=""
SSH_PORT=""

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

# ====== Предварительные проверки ======
[[ "$(id -u)" -eq 0 ]] || die "Запустите от root."

[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "Некорректное имя пользователя: $USERNAME"
[[ "$SSH_PORT" =~ ^[0-9]{2,5}$ ]] || die "Некорректный порт: $SSH_PORT"
(( SSH_PORT >= 1024 && SSH_PORT <= 65535 )) || die "Рекомендуется порт 1024–65535."

command -v sshd >/dev/null 2>&1 || die "Не найден sshd (openssh-server). Установите: apt-get update && apt-get install -y openssh-server"

if ss -tln | awk '{print $4}' | grep -Eq ":(^|.*:)${SSH_PORT}\$"; then
  die "Порт ${SSH_PORT} уже занят."
fi

# ====== Определение менеджера сервисов и обертки ======
SSH_MGR=""        # systemd | sysv | openrc
SSH_SERVICE=""    # sshd | ssh | snap.openssh.sshd | (для SysV/OpenRC) имя скрипта
SSH_SOCKET=""

detect_ssh_mgr() {
  if command -v systemctl >/dev/null 2>&1 && systemctl >/dev/null 2>&1; then
    SSH_MGR="systemd"
    # Найдём сервис среди известных имён
    SSH_SERVICE="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null \
      | awk '{print $1}' \
      | grep -E '^(sshd|ssh|snap\.openssh\.sshd)\.service$' -m1 || true)"
    # socket?
    SSH_SOCKET="$(systemctl list-unit-files --type=socket --no-legend 2>/dev/null \
      | awk '{print $1}' \
      | grep -E '^ssh\.socket$' -m1 || true)"

    # Если нет явного сервиса, но есть сокет — большинство Ubuntu всё равно имеют ssh.service.
    if [[ -z "$SSH_SERVICE" && -n "$SSH_SOCKET" ]]; then
      # Попробуем угадать как 'ssh.service' — часто он есть, просто disabled.
      if systemctl list-unit-files | awk '{print $1}' | grep -qx 'ssh\.service'; then
        SSH_SERVICE="ssh.service"
      fi
    fi
  else
    # non-systemd
    if command -v rc-service >/dev/null 2>&1; then
      SSH_MGR="openrc"
      # Обычно сервис называется sshd
      if rc-service -l | grep -qx 'sshd'; then
        SSH_SERVICE="sshd"
      elif rc-service -l | grep -qx 'ssh'; then
        SSH_SERVICE="ssh"
      fi
    elif command -v service >/dev/null 2>&1 || ls /etc/init.d/* >/dev/null 2>&1; then
      SSH_MGR="sysv"
      if [[ -x /etc/init.d/sshd ]]; then SSH_SERVICE="sshd"
      elif [[ -x /etc/init.d/ssh ]]; then SSH_SERVICE="ssh"
      fi
    fi
  fi
}

svc_is_active() {
  case "$SSH_MGR" in
    systemd)
      systemctl is-active --quiet "${SSH_SERVICE:-ssh.service}"
      ;;
    openrc)
      rc-service "${SSH_SERVICE:-sshd}" status >/dev/null 2>&1
      ;;
    sysv)
      service "${SSH_SERVICE:-ssh}" status >/dev/null 2>&1
      ;;
  esac
}

svc_enable() {
  case "$SSH_MGR" in
    systemd)
      [[ -n "$SSH_SERVICE" ]] && systemctl enable "$SSH_SERVICE" || true
      ;;
    openrc)
      rc-update add "${SSH_SERVICE:-sshd}" default || true
      ;;
    sysv)
      # В SysV оставим как есть
      true
      ;;
  esac
}

svc_disable_socket_if_needed() {
  # Для systemd: если активен socket — выключим его, чтобы нормально работать с несколькими Port
  if [[ "$SSH_MGR" == "systemd" && -n "$SSH_SOCKET" ]]; then
    if systemctl is-active --quiet "$SSH_SOCKET" || systemctl is-enabled --quiet "$SSH_SOCKET"; then
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
    openrc)
      rc-service "${SSH_SERVICE:-sshd}" restart
      ;;
    sysv)
      service "${SSH_SERVICE:-ssh}" restart
      ;;
    *)
      die "Не удалось определить менеджер сервисов SSH."
      ;;
  esac
}

svc_detect_or_die() {
  detect_ssh_mgr
  if [[ "$SSH_MGR" == "systemd" ]]; then
    if [[ -z "$SSH_SERVICE" && -z "$SSH_SOCKET" ]]; then
      die "Не найден ни ssh/sshd сервис, ни ssh.socket в systemd. Установите openssh-server."
    fi
  else
    if [[ -z "$SSH_SERVICE" ]]; then
      die "Не найден сервис SSH для ${SSH_MGR}. Установите openssh-server."
    fi
  fi
  log "Обнаружено: менеджер=${SSH_MGR}, сервис=${SSH_SERVICE:-<none>}, socket=${SSH_SOCKET:-<none>}"
}

# Вызов детектора + при необходимости выключаем socket-активацию
svc_detect_or_die
svc_disable_socket_if_needed
svc_enable || true

# ====== Стек отката ======
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

# ====== Бэкап sshd_config ======
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.${TS}"
cp -a "$SSHD_CONFIG" "$BACKUP"
push_rollback "cp -a '$BACKUP' '$SSHD_CONFIG' && svc_restart || true"
log "Сделан бэкап: $BACKUP"

# ====== Отключение ssh.socket (если активен) ======
if [[ "$SSH_SOCKET_ACTIVE" == "yes" ]]; then
  log "Обнаружен активный ssh.socket — отключаем и включаем ${SSHD_UNIT}.service"
  systemctl stop ssh.socket || true
  systemctl disable ssh.socket || true
  push_rollback "systemctl enable ssh.socket || true; systemctl start ssh.socket || true"
  systemctl enable "${SSHD_UNIT}.service"
fi

# ====== Создание пользователя и ключей ======
USER_CREATED="no"
if id -u "$USERNAME" >/dev/null 2>&1; then
  log "Пользователь $USERNAME уже существует — пропускаю создание."
else
  log "Создаю пользователя $USERNAME…"
  useradd -m -s /bin/bash "$USERNAME"
  USER_CREATED="yes"
  push_rollback "userdel -r '$USERNAME' || true"
fi

log "Выдаю пароль пользователю (скрыто в логе)…"
echo "${USERNAME}:${PASSWORD}" | chpasswd

log "Добавляю $USERNAME в группу sudo…"
if ! id -nG "$USERNAME" | tr ' ' '\n' | grep -qx "sudo"; then
  usermod -aG sudo "$USERNAME"
  push_rollback "gpasswd -d '$USERNAME' 'sudo' || true"
fi

log "Настраиваю ~/.ssh и authorized_keys…"
USER_HOME="$(getent passwd "$USERNAME" | cut -d: -f6)"
mkdir -p "$USER_HOME/.ssh"
chmod 700 "$USER_HOME/.ssh"
AUTH_KEYS="$USER_HOME/.ssh/authorized_keys"
touch "$AUTH_KEYS"
grep -qxF "$PUBLIC_KEY" "$AUTH_KEYS" || echo "$PUBLIC_KEY" >> "$AUTH_KEYS"
chown -R "$USERNAME:$USERNAME" "$USER_HOME/.ssh"
chmod 600 "$AUTH_KEYS"

# ====== Настройка firewall (если есть) для нового порта ======
FIREWALL_ACTION_22=""
FIREWALL_ACTION_NEW=""
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "^Status: active"; then
  log "UFW активен — разрешаю порт ${SSH_PORT}/tcp"
  ufw allow "${SSH_PORT}/tcp" || true
  FIREWALL_ACTION_NEW="ufw delete allow ${SSH_PORT}/tcp || true"
  push_rollback "$FIREWALL_ACTION_NEW"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  log "firewalld активен — разрешаю порт ${SSH_PORT}/tcp"
  firewall-cmd --permanent --add-port="${SSH_PORT}/tcp" || true
  firewall-cmd --reload || true
  FIREWALL_ACTION_NEW="firewall-cmd --permanent --remove-port='${SSH_PORT}/tcp' || true; firewall-cmd --reload || true"
  push_rollback "$FIREWALL_ACTION_NEW"
else
  log "Файрвол не обнаружен или не активен — пропускаю правила."
fi

# ====== Шаги 3–5: Хардениг SSH и добавление порта ======
# Helper: безопасно установить/заменить директиву (до любых Match)
set_sshd_option() {
  local key="$1"; shift
  local val="$*"
  # Удаляем существующие строки с ключом вне Match-блоков (грубое, но практичное)
  # и добавляем новую директиву перед первым Match (или в конец)
  if grep -qE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONFIG"; then
    awk -v K="$key" -v V="$val" '
      BEGIN{printed=0}
      /^[[:space:]]*Match[[:space:]]/ && printed==0 {
        print K" "V
        printed=1
      }
      {print}
      END{if(printed==0) print K" "V}
    ' "$SSHD_CONFIG" | sed -E "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/# &/" > "${SSHD_CONFIG}.tmp"
  else
    # Нет Match — закомментим старые и добавим в конец
    sed -E "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/# &/" "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    echo "${key} ${val}" >> "${SSHD_CONFIG}.tmp"
  fi
  mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
}

# 3. Запрещаем парольную аутентификацию
log "Устанавливаю PasswordAuthentication no…"
set_sshd_option "PasswordAuthentication" "no"

# Дополнительно «страховочные» параметры
set_sshd_option "ChallengeResponseAuthentication" "no"
set_sshd_option "UsePAM" "yes"
set_sshd_option "PubkeyAuthentication" "yes"

# 4. Запрет логина root
log "Устанавливаю PermitRootLogin no…"
set_sshd_option "PermitRootLogin" "no"

# 5. Добавление нового SSH-порта, сохраняя 22 до проверки
if ! grep -qE "^[[:space:]]*Port[[:space:]]+${SSH_PORT}\b" "$SSHD_CONFIG"; then
  log "Добавляю Port ${SSH_PORT}…"
  # Добавим директиву Port (допускается несколько)
  if grep -qE '^[[:space:]]*Match[[:space:]]' "$SSHD_CONFIG"; then
    # Вставим перед Match
    awk -v VAL="${SSH_PORT}" '
      BEGIN{printed=0}
      /^[[:space:]]*Match[[:space:]]/ && printed==0 {
        print "Port "VAL
        printed=1
      }
      {print}
      END{if(printed==0) print "Port "VAL}
    ' "$SSHD_CONFIG" > "${SSHD_CONFIG}.tmp"
    mv "${SSHD_CONFIG}.tmp" "$SSHD_CONFIG"
  else
    echo "Port ${SSH_PORT}" >> "$SSHD_CONFIG"
  fi
else
  log "Port ${SSH_PORT} уже присутствует в конфиге."
fi

# ====== Валидация и рестарт SSH (шаг 6) ======
log "Проверяю конфигурацию sshd…"
sshd -t -f "$SSHD_CONFIG"

log "Перезапускаю сервис ${SSHD_UNIT}.service…"
svc_restart

# ====== Шаг 7: Проверка входа по ключу на новом порту (локально) ======
log "Генерирую временную пару ключей для проверки логина…"
TMPKEY="/root/.xrayfather_tmp_sshkey_${TS}"
ssh-keygen -t ed25519 -N '' -f "$TMPKEY" >/dev/null
trap 'rm -f "$TMPKEY" "$TMPKEY.pub" || true' EXIT

# Добавим временный публичный ключ в authorized_keys
cat "${TMPKEY}.pub" >> "$AUTH_KEYS"
# На случай строгих прав — ещё раз корректно выставим владельца и права
chown "$USERNAME:$USERNAME" "$AUTH_KEYS"
chmod 600 "$AUTH_KEYS"

log "Пробую подключиться к ${USERNAME}@127.0.0.1:${SSH_PORT} по ключу…"
# Важные опции: BatchMode, StrictHostKeyChecking off, ConnectTimeout
if ssh -p "$SSH_PORT" -i "$TMPKEY" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 "${USERNAME}@127.0.0.1" true; then
  log "Успех: вход по ключу на новом порту работает."
else
  die "Не удалось войти по ключу на новом порту. Прерываю."
fi

# Удаляем временный ключ из authorized_keys
log "Удаляю временный проверочный ключ из authorized_keys…"
TMP_PUB_LINE="$(cat "${TMPKEY}.pub")"
sed -i "\#${TMP_PUB_LINE//\//\\/}#d" "$AUTH_KEYS"

# ====== Шаг 8: Удаляем порт 22 и рестартуем ещё раз ======
if grep -qE "^[[:space:]]*Port[[:space:]]+22\b" "$SSHD_CONFIG"; then
  log "Отключаю Port 22 в конфиге…"
  # Закомментируем все явные 'Port 22'
  sed -E -i "s/^([[:space:]]*)Port[[:space:]]+22\b/\1# Port 22 (disabled ${TS})/" "$SSHD_CONFIG"
else
  log "Явная директива Port 22 не найдена — возможно использовалось значение по умолчанию. Продолжаю."
fi

# Закрываем 22 в firewall (если ранее был открыт)
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "^Status: active"; then
  if ufw status | grep -qE '22/tcp[[:space:]]+ALLOW'; then
    log "UFW: убираю разрешение 22/tcp…"
    ufw delete allow 22/tcp || true
    FIREWALL_ACTION_22="ufw allow 22/tcp || true"
    push_rollback "$FIREWALL_ACTION_22"
  fi
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  if firewall-cmd --list-ports | tr ' ' '\n' | grep -qx "22/tcp"; then
    log "firewalld: удаляю 22/tcp…"
    firewall-cmd --permanent --remove-port="22/tcp" || true
    firewall-cmd --reload || true
    FIREWALL_ACTION_22="firewall-cmd --permanent --add-port='22/tcp' || true; firewall-cmd --reload || true"
    push_rollback "$FIREWALL_ACTION_22"
  fi
fi

log "Повторная проверка конфига sshd…"
sshd -t -f "$SSHD_CONFIG"

log "Финальный перезапуск ${SSHD_UNIT}.service…"
svc_restart

# Финальная проверка, что порт слушает
if ss -tln | awk '{print $4}' | grep -Eq ":(^|.*:)${SSH_PORT}\$"; then
  log "Порт ${SSH_PORT} слушает. Хардениг завершён успешно."
else
  die "После финального рестарта порт ${SSH_PORT} не слушает."
fi

log "Готово. Лог: $LOG"
exit 0
