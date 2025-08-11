#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Config / Args =====
STATE_DIR="/var/lib/xrayfather"
LOG_DIR="/var/log/xrayfather"
STATE_FILE="$STATE_DIR/state.steps"
LOG_FILE="$LOG_DIR/setup-$(date +%Y%m%d-%H%M%S).log"

USER_NAME=""
PUBKEY=""
XRAY_PORTS=""
SSH_PORT=""
NO_UFW=0
UNDO=0

usage() {
  cat <<EOF
Usage: $0 -u <user> -k <pubkey> -x <ports_csv> -p <ssh_port> [--no-ufw] [--undo]
  -u    системный пользователь для SSH
  -k    публичный ключ (OpenSSH)
  -x    порты Xray через запятую (напр. 443,8443)
  -p    новый SSH порт
  --no-ufw  не трогать UFW
  --undo    выполнить полный откат согласно state-файлу
EOF
}

# простейший логгер
log() { echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE" >&2; }

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    log "Нужны права root."
    exit 1
  fi
}

parse_args() {
  while (( "$#" )); do
    case "$1" in
      -u) USER_NAME="$2"; shift 2 ;;
      -k) PUBKEY="$2"; shift 2 ;;
      -x) XRAY_PORTS="$2"; shift 2 ;;
      -p) SSH_PORT="$2"; shift 2 ;;
      --no-ufw) NO_UFW=1; shift ;;
      --undo) UNDO=1; shift ;;
      -h|--help) usage; exit 0 ;;
      *) log "Неизвестный аргумент: $1"; usage; exit 1 ;;
    esac
  done

  if [[ $UNDO -eq 0 ]]; then
    [[ -n "$USER_NAME" && -n "$PUBKEY" && -n "$XRAY_PORTS" && -n "$SSH_PORT" ]] || {
      usage; exit 1;
    }
  fi
}

# ===== State helpers =====
state_init() {
  mkdir -p "$STATE_DIR" "$LOG_DIR"
  touch "$STATE_FILE"
}
state_add() { echo "$1" >> "$STATE_FILE"; }
state_read_reverse() { tac "$STATE_FILE" 2>/dev/null || tail -r "$STATE_FILE"; }
state_clear() { : > "$STATE_FILE"; }

# ===== Rollback =====
rollback() {
  log "⚠️ Ошибка. Запуск автоматического отката..."
  if [[ ! -s "$STATE_FILE" ]]; then
    log "Нет шагов для отката."
    return
  fi
  while read -r STEP; do
    case "$STEP" in
      user_created:*)       _=${STEP#user_created:}; userdel -r -f "$_" 2>/dev/null || true; log "UNDO user $_";;
      ssh_key_installed:*)  USER=${STEP#ssh_key_installed:}; rm -f "/home/$USER/.ssh/authorized_keys" 2>/dev/null || true; log "UNDO authkey $USER";;
      ufw_installed)        apt-get remove -y ufw >/dev/null 2>&1 || true; log "UNDO ufw install";;
      ufw_rules_applied:*)  IFS=',' read -r -a ports <<< "${STEP#ufw_rules_applied:}"
                            for p in "${ports[@]}"; do ufw delete allow "$p" 2>/dev/null || true; done
                            ufw delete allow "OpenSSH" 2>/dev/null || true
                            log "UNDO ufw rules";;
      ssh_port_changed:*)   OLD=${STEP#ssh_port_changed:}; sed -i "s/^#\?Port .*/Port ${OLD}/" /etc/ssh/sshd_config || true
                            systemctl reload ssh || systemctl reload sshd || true
                            log "UNDO ssh port -> $OLD";;
      ssh_pwd_disabled)     sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
                            systemctl reload ssh || systemctl reload sshd || true
                            log "UNDO disable password";;
      root_ssh_disabled)    sed -i 's/^PermitRootLogin no/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config || true
                            systemctl reload ssh || systemctl reload sshd || true
                            log "UNDO root ssh disable";;
      *)
        log "Неизвестный шаг для UNDO: $STEP"
      ;;
    esac
  done < <(state_read_reverse)
  state_clear
  log "✅ Откат завершён."
}

trap 'rc=$?; [[ $UNDO -eq 0 ]] && rollback; exit $rc' ERR

# ===== Steps (do + record) =====
step_create_user() {
  if id "$USER_NAME" &>/dev/null; then
    log "Пользователь $USER_NAME уже существует — пропускаю."
  else
    adduser --disabled-password --gecos "" "$USER_NAME"
    usermod -aG sudo "$USER_NAME"
    state_add "user_created:$USER_NAME"
    log "Создан пользователь $USER_NAME"
  fi
}

step_install_key() {
  install -d -m 700 -o "$USER_NAME" -g "$USER_NAME" "/home/$USER_NAME/.ssh"
  printf '%s\n' "$PUBKEY" > "/home/$USER_NAME/.ssh/authorized_keys"
  chown "$USER_NAME:$USER_NAME" "/home/$USER_NAME/.ssh/authorized_keys"
  chmod 600 "/home/$USER_NAME/.ssh/authorized_keys"
  state_add "ssh_key_installed:$USER_NAME"
  log "Добавлен публичный ключ для $USER_NAME"
}

step_setup_ufw() {
  [[ $NO_UFW -eq 1 ]] && { log "UFW пропущен по флагу"; return; }
  if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y ufw
    state_add "ufw_installed"
    log "Установлен UFW"
  fi

  ufw allow OpenSSH || true
  IFS=',' read -r -a ports <<< "$XRAY_PORTS"
  for p in "${ports[@]}"; do ufw allow "$p"; done
  ufw --force enable
  state_add "ufw_rules_applied:$XRAY_PORTS"
  log "UFW: разрешены OpenSSH и порты ${XRAY_PORTS}"
}

# Двухфазная смена порта: валидируем конфиг и доступность
step_change_ssh_port() {
  local old_port new_port conf="/etc/ssh/sshd_config"
  old_port=$(ss -tlnp | awk '/sshd/ {print $4}' | sed -n 's/.*:\([0-9]\+\)$/\1/p' | head -n1)
  new_port="$SSH_PORT"

  # правим конфиг безопасно
  if grep -qE '^#?Port ' "$conf"; then
    sed -i "s/^#\?Port .*/Port ${new_port}/" "$conf"
  else
    echo "Port ${new_port}" >> "$conf"
  fi

  # проверка синтаксиса (если доступна)
  if command -v sshd >/dev/null 2>&1; then
    sshd -t
  fi

  # мягкая перезагрузка
  systemctl reload ssh || systemctl reload sshd

  # проверяем, что локально порт слушается
  sleep 0.5
  ss -tln | grep -q ":${new_port} " || { log "Новый порт ${new_port} не слушает"; return 1; }

  # записываем шаг только когда убедились
  state_add "ssh_port_changed:${old_port}"
  log "SSH порт изменён: ${old_port} -> ${new_port}"
}

step_harden_ssh() {
  local conf="/etc/ssh/sshd_config"
  # запрещаем парольный вход, только ключ
  if grep -q '^PasswordAuthentication ' "$conf"; then
    sed -i 's/^PasswordAuthentication .*/PasswordAuthentication no/' "$conf"
  else
    echo "PasswordAuthentication no" >> "$conf"
  fi
  systemctl reload ssh || systemctl reload sshd
  state_add "ssh_pwd_disabled"
  log "Отключена аутентификация по паролю"

  # запрещаем root по SSH (оставляем prohibit-password — опционально замени на no)
  if grep -q '^PermitRootLogin ' "$conf"; then
    sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' "$conf"
  else
    echo "PermitRootLogin no" >> "$conf"
  fi
  systemctl reload ssh || systemctl reload sshd
  state_add "root_ssh_disabled"
  log "Отключён SSH-доступ для root"
}

# заглушка под установку/настройку Xray — расширишь своей логикой
step_prepare_xray_ports() {
  # Здесь можно пробросить порты в iptables/nftables, если не UFW
  log "XRAY порты подготовлены: ${XRAY_PORTS}"
}

# ===== Main =====
main() {
  ensure_root
  parse_args "$@"
  state_init
  log "Старт. Лог: $LOG_FILE"

  if [[ $UNDO -eq 1 ]]; then
    rollback
    exit 0
  fi

  # порядок шагов имеет значение
  step_create_user
  step_install_key
  step_setup_ufw
  step_prepare_xray_ports
  step_change_ssh_port
  step_harden_ssh

  log "✅ Готово. Шаги записаны в $STATE_FILE"
}

main "$@"
