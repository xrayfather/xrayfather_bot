#!/usr/bin/env bash
set -euo pipefail

# ========================
# xrayfather hardening v2
# с поддержкой ssh.socket
# ========================

# --- Настройки/переменные ---
STATE_DIR="/var/lib/xrayfather"
STATE_FILE="$STATE_DIR/state"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN_FILE="$DROPIN_DIR/xrayfather.conf"
SOCKET_OVERRIDE_DIR="/etc/systemd/system/ssh.socket.d"
SOCKET_OVERRIDE_FILE="$SOCKET_OVERRIDE_DIR/override.conf"

NEW_USER=""
PUBKEY=""
XRAY_PORTS="443"
SSH_PORT=""
NO_UFW=false
TWO_PHASE=false
FINALIZE=false
UNDO=false

# --- Утилиты ---
log()  { echo -e "[+] $*"; }
err()  { echo -e "[!] $*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

state_add() { mkdir -p "$STATE_DIR"; grep -qxF "$1" "$STATE_FILE" 2>/dev/null || echo "$1" >> "$STATE_FILE"; }
state_has() { grep -qxF "$1" "$STATE_FILE" 2>/dev/null; }
state_del() { sed -i.bak "/^$(printf '%s' "$1" | sed 's/[^^]/[&]/g; s/\^/\\^/g')\$/d" "$STATE_FILE" 2>/dev/null || true; }

# --- Парсинг аргументов ---
usage() {
  cat <<EOF
Usage:
  $0 -u <user> -k <pubkey> -x <ports_csv> -p <ssh_port> [--no-ufw] [--two-phase] [--finalize] [--undo]

Flags:
  -u, --user        Имя НОВОГО пользователя (будет создан)
  -k, --pubkey      Публичный ключ OpenSSH (строка ssh-ed25519 ...)
  -x, --xray-ports  CSV порты Xray (по умолчанию: 443)
  -p, --ssh-port    Новый порт SSH
      --no-ufw      Не трогать UFW
      --two-phase   Фаза-1 (оставить 22 и новый порт)
      --finalize    Финализация (оставить только новый порт, убрать OpenSSH/22)
      --undo        Откат ключевых изменений (по возможности)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user)         NEW_USER="$2"; shift 2 ;;
    -k|--pubkey)       PUBKEY="$2"; shift 2 ;;
    -x|--xray-ports)   XRAY_PORTS="$2"; shift 2 ;;
    -p|--ssh-port)     SSH_PORT="$2"; shift 2 ;;
    --no-ufw)          NO_UFW=true; shift ;;
    --two-phase)       TWO_PHASE=true; shift ;;
    --finalize)        FINALIZE=true; shift ;;
    --undo)            UNDO=true; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) err "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

# --- Вспомогательные функции ---

ensure_packages() {
  if have apt-get; then
    log "Обновляю индекс пакетов (apt-get update)..."
    DEBIAN_FRONTEND=noninteractive apt-get update -y || true
    $NO_UFW || apt-get install -y ufw || true
  elif have dnf; then
    $NO_UFW || dnf install -y ufw || true
  elif have yum; then
    $NO_UFW || yum install -y ufw || true
  fi
}

ensure_user() {
  [[ -n "$NEW_USER" ]] || die "Не задан --user"
  if id -u "$NEW_USER" >/dev/null 2>&1; then
    log "Пользователь $NEW_USER уже существует"
  else
    log "Создаю пользователя $NEW_USER (без пароля) и добавляю в sudo"
    useradd -m -s /bin/bash -G sudo "$NEW_USER"
    passwd -l "$NEW_USER" || true
    state_add "user_created:$NEW_USER"
  fi

  local sshdir="/home/$NEW_USER/.ssh"
  mkdir -p "$sshdir"
  chmod 700 "$sshdir"
  local ak="$sshdir/authorized_keys"
  if [[ -n "$PUBKEY" ]]; then
    if ! grep -qxF "$PUBKEY" "$ak" 2>/dev/null; then
      printf "%s\n" "$PUBKEY" >> "$ak"
      log "Добавил публичный ключ в authorized_keys"
    else
      log "Публичный ключ уже в authorized_keys"
    fi
  fi
  chmod 600 "$ak" 2>/dev/null || true
  chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER"
}

ensure_ufw_phase1() {
  $NO_UFW && { log "UFW пропущен (--no-ufw)"; return; }
  have ufw || { log "UFW не установлен — пропускаю"; return; }

  log "UFW: разрешаю SSH 22/tcp (фаза-1) и новый порт $SSH_PORT/tcp"
  ufw allow 22/tcp || true
  ufw allow "${SSH_PORT}/tcp" || true
  IFS=, read -r -a arr <<< "$XRAY_PORTS"
  for p in "${arr[@]}"; do
    [[ -n "$p" ]] && ufw allow "${p}/tcp" || true
  done
  yes | ufw enable >/dev/null 2>&1 || true
  state_add "ufw_phase1:$SSH_PORT:$XRAY_PORTS"
}

ensure_ufw_finalize() {
  $NO_UFW && { log "UFW пропущен (--no-ufw)"; return; }
  have ufw || { log "UFW не установлен — пропускаю"; return; }

  log "UFW: оставляю только новый SSH-порт ${SSH_PORT}/tcp и Xray-порты; удаляю OpenSSH (22)"
  ufw delete allow OpenSSH >/dev/null 2>&1 || ufw delete allow 22/tcp >/dev/null 2>&1 || true
  ufw allow "${SSH_PORT}/tcp" || true
  IFS=, read -r -a arr <<< "$XRAY_PORTS"
  for p in "${arr[@]}"; do
    [[ -n "$p" ]] && ufw allow "${p}/tcp" || true
  done
  yes | ufw enable >/dev/null 2>&1 || true
  state_add "ufw_finalized:$SSH_PORT:$XRAY_PORTS"
}

ensure_include_at_top() {
  # Гарантируем Include до любых Match
  if ! grep -q '^[[:space:]]*Include[[:space:]]\+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
    log "Добавляю Include в начало /etc/ssh/sshd_config"
    sed -i "1i Include /etc/ssh/sshd_config.d/*.conf" /etc/ssh/sshd_config
  else
    # перенос наверх (на случай, если Include ниже Match)
    awk '
      BEGIN { printed=0 }
      NR==1 { print "Include /etc/ssh/sshd_config.d/*.conf"; next }
      /^[[:space:]]*Include[[:space:]]+\/etc\/ssh\/sshd_config\.d\/\*\.conf$/ { next }
      { print }
    ' /etc/ssh/sshd_config | tee /etc/ssh/sshd_config >/dev/null
  fi
}

write_dropin_phase1() {
  mkdir -p "$DROPIN_DIR"
  cat > "$DROPIN_FILE" <<EOF
# Managed by xrayfather (phase1)
Port 22
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes
EOF
  state_add "sshd_dropin_phase1"
}

write_dropin_finalize() {
  mkdir -p "$DROPIN_DIR"
  cat > "$DROPIN_FILE" <<EOF
# Managed by xrayfather (finalize)
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes
EOF
  state_add "sshd_dropin_finalized"
}

socket_override_phase1() {
  mkdir -p "$SOCKET_OVERRIDE_DIR"
  cat > "$SOCKET_OVERRIDE_FILE" <<EOF
[Socket]
ListenStream=
ListenStream=22
ListenStream=${SSH_PORT}
EOF
  state_add "socket_phase1"
}

socket_override_finalize() {
  mkdir -p "$SOCKET_OVERRIDE_DIR"
  cat > "$SOCKET_OVERRIDE_FILE" <<EOF
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
  state_add "socket_finalized"
}

restart_ssh_units() {
  if systemctl is-active --quiet ssh.socket; then
    log "Режим socket activation: перезапускаю ssh.socket"
    systemctl daemon-reload
    systemctl restart ssh.socket
  else
    log "Классический режим sshd: проверяю конфиг и перезапускаю службу"
    sshd -t
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
  fi
}

configure_ssh_phase1() {
  [[ -n "$SSH_PORT" ]] || die "Не задан --ssh-port"
  if systemctl is-active --quiet ssh.socket; then
    socket_override_phase1
  else
    ensure_include_at_top
    write_dropin_phase1
  fi
  restart_ssh_units
}

configure_ssh_finalize() {
  [[ -n "$SSH_PORT" ]] || die "Не задан --ssh-port"
  if systemctl is-active --quiet ssh.socket; then
    socket_override_finalize
  else
    ensure_include_at_top
    write_dropin_finalize
  fi
  restart_ssh_units
}

show_listen() {
  log "Открытые порты ssh:"
  ss -tlnp | awk 'NR==1 || $4 ~ /:22$|:'"$SSH_PORT"'$/'
}

rollback() {
  err "Запущен откат (--undo)"

  # Удаляем drop-in
  if [[ -f "$DROPIN_FILE" ]]; then
    rm -f "$DROPIN_FILE" && log "Удалил $DROPIN_FILE"
  fi

  # Удаляем override для сокета
  if [[ -f "$SOCKET_OVERRIDE_FILE" ]]; then
    rm -f "$SOCKET_OVERRIDE_FILE" && log "Удалил $SOCKET_OVERRIDE_FILE"
  fi

  # Перезапуск соответствующей сущности
  if systemctl is-active --quiet ssh.socket; then
    systemctl daemon-reload
    systemctl restart ssh.socket || true
  else
    sshd -t || true
    systemctl restart sshd 2>/dev/null || systemctl restart ssh || true
  fi

  # UFW: попытаемся вернуть OpenSSH и убрать новый порт
  if have ufw; then
    ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null 2>&1 || true
    if [[ -n "${SSH_PORT:-}" ]]; then
      ufw delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    fi
  fi

  # Пользователя НЕ удаляем специально (чтобы не потерять доступ)
  log "Откат завершён (учти: пользователь и ключи не тронуты)"
  exit 0
}

# --- Валидация входа ---
if $UNDO; then
  rollback
fi

if $FINALIZE; then
  [[ -n "$SSH_PORT" ]] || die "Для --finalize требуется --ssh-port"
else
  # phase1/oneshot
  [[ -n "$NEW_USER" ]] || die "Требуется --user"
  [[ -n "$PUBKEY"  ]] || die "Требуется --pubkey"
  [[ -n "$SSH_PORT" ]] || die "Требуется --ssh-port"
fi

# --- Основной поток ---
ensure_packages

if $FINALIZE; then
  # Только финализация портов/ufw
  configure_ssh_finalize
  ensure_ufw_finalize
  show_listen
  log "Finalize завершён."
  exit 0
fi

# ФАЗА-1 или One-shot (если TWO_PHASE=false, ports будут финальными)
ensure_user

if $TWO_PHASE; then
  configure_ssh_phase1
  ensure_ufw_phase1
  show_listen
  log "Фаза-1 завершена. Проверь вход по ключу на новом порту и затем запусти --finalize."
else
  # One-shot: сразу финальные настройки (только новый порт)
  configure_ssh_finalize
  ensure_ufw_finalize
  show_listen
  log "Однопроходная настройка завершена."
fi
