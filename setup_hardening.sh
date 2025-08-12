#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================
# Helpers & globals
# ==============================
LOG_TAG="[xrayfather]"
STATE_DIR="/var/lib/xrayfather"
STATE_FILE="$STATE_DIR/state"
SSHD_DIR="/etc/ssh/sshd_config.d"
DROPIN="$SSHD_DIR/xrayfather.conf"

log(){ echo -e "${LOG_TAG} $*"; }
die(){ echo -e "${LOG_TAG} ERROR: $*" >&2; exit 1; }

state_add(){ mkdir -p "$STATE_DIR"; echo "$1" >> "$STATE_FILE"; }
state_has(){ [[ -f "$STATE_FILE" ]] && grep -q "^$1$" "$STATE_FILE"; }
state_clear(){ : > "$STATE_FILE"; }
state_get(){ [[ -f "$STATE_FILE" ]] && cat "$STATE_FILE" || true; }

have_cmd(){ command -v "$1" >/dev/null 2>&1; }

require_root(){
  [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)."
}

ensure_sshd_dropin_dir(){
  mkdir -p "$SSHD_DIR"; chmod 755 "$SSHD_DIR"
}

# ==============================
# Args
# ==============================
USER_NAME=""
PUB_KEY=""
XRAY_PORTS=""
SSH_PORT=""
NO_UFW=false
UNDO=false
TWO_PHASE=false
FINALIZE=false

usage(){
cat <<EOF
Usage:
  $0 -u <user> -k <pubkey> -x <ports_csv> -p <ssh_port> [--no-ufw] [--two-phase]
  $0 --finalize -p <ssh_port>
  $0 --undo

Flags:
  -u, --user           Имя нового пользователя (будет создан при необходимости)
  -k, --pubkey         Публичный ключ OpenSSH (строка "ssh-ed25519 ..." или "ssh-rsa ...")
  -x, --xray-ports     Список портов Xray через запятую, напр. "443,8443"
  -p, --ssh-port       Новый порт SSH (например 22422)
      --no-ufw         Не трогать UFW
      --two-phase      Фаза 1: оставить 22 и новый порт одновременно, чтобы проверить доступ
      --finalize       Фаза 2: удалить 22 и правило OpenSSH, оставить только новый порт
      --undo           Откат изменений, записанных в стейте

Примеры:
  Однопроходный (сразу на новый порт):
    sudo bash $0 -u tg_123 -k "ssh-ed25519 AAAA... user@bot" -x "443" -p 22422

  Двухфазный:
    sudo bash $0 -u tg_123 -k "ssh-ed25519 AAAA... user@bot" -x "443" -p 22422 --two-phase
    # проверить вход по новому порту, затем
    sudo bash $0 --finalize -p 22422

  Откат:
    sudo bash $0 --undo
EOF
}

# parse
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user)       USER_NAME="$2"; shift 2 ;;
    -k|--pubkey)     PUB_KEY="$2"; shift 2 ;;
    -x|--xray-ports) XRAY_PORTS="$2"; shift 2 ;;
    -p|--ssh-port)   SSH_PORT="$2"; shift 2 ;;
    --no-ufw)        NO_UFW=true; shift ;;
    --undo)          UNDO=true; shift ;;
    --two-phase)     TWO_PHASE=true; shift ;;
    --finalize)      FINALIZE=true; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

require_root

# ==============================
# Rollback
# ==============================
rollback(){
  log "ROLLBACK: started"
  # UFW: вернуть OpenSSH если удаляли
  if state_has "ufw_openssh_deleted"; then
    if have_cmd ufw; then
      ufw allow OpenSSH || true
      log "ROLLBACK: UFW OpenSSH rule restored"
    fi
  fi

  # UFW: удалить добавленные правила (SSH_PORT/XRAY) если записаны
  if state_has "ufw_rules_applied"; then
    if have_cmd ufw; then
      # читаем список из стейта
      # формат хранения: ufw_rules_applied:ssh:<port>,xray:<csv>
      while IFS= read -r line; do
        [[ "$line" == ufw_rules_applied:* ]] || continue
        rules="${line#ufw_rules_applied:}"
        IFS=',' read -r -a items <<< "$rules"
        for item in "${items[@]}"; do
          case "$item" in
            ssh:*)   p="${item#ssh:}"; [[ -n "$p" ]] && ufw delete allow "$p"/tcp || true ;;
            xray:*)  csv="${item#xray:}"; IFS=';' read -r -a xp <<< "$csv"
                     for q in "${xp[@]}"; do [[ -n "$q" ]] && ufw delete allow "$q"/tcp || true; done ;;
          esac
        done
      done < "$STATE_FILE"
      log "ROLLBACK: UFW custom rules removed"
    fi
  fi

  # SSHD drop-in
  if state_has "sshd_dropin_written"; then
    rm -f "$DROPIN" || true
    if have_cmd systemctl; then systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    else service ssh restart 2>/dev/null || true
    fi
    log "ROLLBACK: drop-in removed, ssh restarted"
  fi

  # authorized_keys cleanup if we created user
  if state_has "user_created:${USER_NAME:-}"; then
    # Осторожно: не удаляем пользователя автоматически; только чистим ключ, если нужно.
    : # no-op, оставим пользователя
  fi

  log "ROLLBACK: done"
}

# ==============================
# Steps
# ==============================
step_update_packages(){
  # необязательный шаг: обновление индексов, если apt есть
  if have_cmd apt-get; then
    apt-get update -y || true
  fi
}

step_create_user_and_key(){
  [[ -z "$USER_NAME" || -z "$PUB_KEY" ]] && return 0

  if id "$USER_NAME" &>/dev/null; then
    log "User $USER_NAME exists"
  else
    if have_cmd adduser; then
      adduser --disabled-password --gecos "" "$USER_NAME"
    else
      useradd -m -s /bin/bash "$USER_NAME"
    fi
    usermod -aG sudo "$USER_NAME" || true
    state_add "user_created:${USER_NAME}"
    log "User $USER_NAME created and added to sudo"
  fi

  local ssh_dir="/home/$USER_NAME/.ssh"
  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  echo "$PUB_KEY" > "$ssh_dir/authorized_keys"
  chmod 600 "$ssh_dir/authorized_keys"
  chown -R "$USER_NAME:$USER_NAME" "$ssh_dir"
  state_add "authorized_keys_set:${USER_NAME}"
  log "authorized_keys set for $USER_NAME"
}

step_setup_ufw(){
  $NO_UFW && { log "UFW disabled by flag"; return; }

  if ! have_cmd ufw; then
    if have_cmd apt-get; then
      apt-get install -y ufw
    else
      die "ufw not installed and no apt-get available"
    fi
  fi

  ufw allow OpenSSH || true

  # Разрешаем новый SSH порт заранее
  if [[ -n "$SSH_PORT" ]]; then
    ufw allow "$SSH_PORT"/tcp || true
  fi

  # Разрешаем Xray порты
  local ports_csv=""
  if [[ -n "$XRAY_PORTS" ]]; then
    IFS=',' read -r -a ports <<< "$XRAY_PORTS"
    for p in "${ports[@]}"; do
      [[ -n "$p" ]] || continue
      ufw allow "$p"/tcp || true
      ports_csv="${ports_csv:+$ports_csv;}$p"
    done
  fi

  ufw --force enable
  state_add "ufw_rules_applied:ssh:${SSH_PORT:-};xray:${ports_csv}"
  log "UFW: allow OpenSSH, SSH=$SSH_PORT, XRAY=$XRAY_PORTS"
}

write_sshd_dropin(){
  ensure_sshd_dropin_dir
  {
    echo "# Managed by xrayfather"
    if $TWO_PHASE && ! $FINALIZE; then
      echo "Port 22"
      [[ -n "$SSH_PORT" ]] && echo "Port $SSH_PORT"
    else
      [[ -n "$SSH_PORT" ]] && echo "Port $SSH_PORT"
    fi
    echo "PermitRootLogin no"
    echo "PasswordAuthentication no"
    echo "PubkeyAuthentication yes"
    echo "KbdInteractiveAuthentication no"
    echo "ChallengeResponseAuthentication no"
    # Можно усилить:
    # echo "AuthenticationMethods publickey"
    # echo "UsePAM yes"
  } > "$DROPIN"
  chmod 644 "$DROPIN"
  state_add "sshd_dropin_written"
  log "sshd drop-in written to $DROPIN"
}

restart_sshd(){
  if have_cmd systemctl; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || die "failed to restart ssh(d)"
  else
    service ssh restart 2>/dev/null || die "failed to restart ssh service"
  fi
  log "sshd restarted"
}

verify_sshd_listens(){
  [[ -n "$SSH_PORT" ]] || return 0
  if have_cmd ss; then
    ss -tln | grep -q ":$SSH_PORT " || die "sshd does not listen on $SSH_PORT"
  elif have_cmd netstat; then
    netstat -tln | grep -q ":$SSH_PORT " || die "sshd does not listen on $SSH_PORT"
  else
    log "No ss/netstat, skip listen check"
  fi
  log "sshd listens on $SSH_PORT (local check)"
}

step_configure_sshd(){
  write_sshd_dropin
  restart_sshd
  verify_sshd_listens
}

step_finalize_two_phase(){
  # Выполняется если:
  #  - обычный однопроходный (TWO_PHASE=false): надо удалить OpenSSH правило
  #  - двухфазный finalize (FINALIZE=true): удалить 22 и правило OpenSSH
  if $TWO_PHASE && ! $FINALIZE; then
    log "Two-phase phase1 complete. Verify SSH on new port $SSH_PORT, then run with --finalize."
    return 0
  fi

  # Переписываем drop-in без порта 22
  ensure_sshd_dropin_dir
  {
    echo "# Managed by xrayfather (finalized)"
    [[ -n "$SSH_PORT" ]] && echo "Port $SSH_PORT"
    echo "PermitRootLogin no"
    echo "PasswordAuthentication no"
    echo "PubkeyAuthentication yes"
    echo "KbdInteractiveAuthentication no"
    echo "ChallengeResponseAuthentication no"
  } > "$DROPIN"
  chmod 644 "$DROPIN"
  restart_sshd
  verify_sshd_listens
  state_add "sshd_finalized"
  log "Finalized: Port 22 removed from sshd"

  if ! $NO_UFW; then
    # удалить профиль OpenSSH (обычно 22/tcp)
    if ufw status | grep -q "OpenSSH"; then
      ufw delete allow OpenSSH || true
    else
      ufw delete allow 22/tcp || true
    fi
    state_add "ufw_openssh_deleted"
    log "UFW: OpenSSH rule removed"
  fi
}

# ==============================
# Main flows
# ==============================
do_undo(){
  [[ -f "$STATE_FILE" ]] || { log "Nothing to undo (state empty)"; exit 0; }
  rollback
  rm -f "$STATE_FILE"
  log "UNDO complete"
}

main_setup(){
  # валидируем обязательные только для setup/phase1:
  if $FINALIZE; then
    [[ -n "$SSH_PORT" ]] || die "--finalize requires -p/--ssh-port"
  else
    [[ -n "$USER_NAME" ]] || die "Missing -u/--user"
    [[ -n "$PUB_KEY"  ]] || die "Missing -k/--pubkey"
    [[ -n "$SSH_PORT" ]] || die "Missing -p/--ssh-port"
    # XRAY_PORTS может быть пустым (не запрещаем)
  fi

  trap 'rollback; exit 1' ERR

  if $FINALIZE; then
    # фаза 2 только
    step_finalize_two_phase
    log "Finalize done."
    exit 0
  fi

  step_update_packages
  step_create_user_and_key
  step_setup_ufw
  step_configure_sshd
  step_finalize_two_phase

  log "Setup complete."
}

# ==============================
# Entry
# ==============================
if $UNDO; then
  do_undo
else
  main_setup
fi
