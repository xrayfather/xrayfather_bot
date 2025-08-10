#!/bin/bash
set -euo pipefail

# ==============================
# Отмена изменений setup_hardening.sh
# ==============================

# Получаем параметры
while getopts "u:x:p:" opt; do
  case $opt in
    u) USERNAME="$OPTARG" ;;
    x) XRAY_PORTS="$OPTARG" ;; # через запятую
    p) SSH_PORT="$OPTARG" ;;
    *) echo "Использование: sudo $0 -u <username> -x <xray_ports> -p <ssh_port>"; exit 1 ;;
  esac
done

if [[ -z "${USERNAME:-}" || -z "${SSH_PORT:-}" ]]; then
  echo "❌ Параметры -u и -p обязательны."
  exit 1
fi

echo "🔄 Откат изменений для пользователя: $USERNAME, SSH порт: $SSH_PORT, XRAY порты: ${XRAY_PORTS:-<нет>}"

# 1. Вернуть SSH порт на 22
echo "▶ Восстанавливаю порт SSH на 22..."
sudo sed -i "s/^#\?Port .*/Port 22/" /etc/ssh/sshd_config

# 2. Включить вход root по паролю
echo "▶ Разрешаю root вход..."
sudo sed -i "s/^#\?PermitRootLogin .*/PermitRootLogin yes/" /etc/ssh/sshd_config

# 3. Включить парольный вход для всех пользователей
echo "▶ Разрешаю парольную аутентификацию..."
sudo sed -i "s/^#\?PasswordAuthentication .*/PasswordAuthentication yes/" /etc/ssh/sshd_config

# 4. Удалить созданного пользователя
if id "$USERNAME" &>/dev/null; then
    echo "▶ Удаляю пользователя $USERNAME..."
    sudo deluser --remove-home "$USERNAME"
else
    echo "ℹ Пользователь $USERNAME не найден."
fi

# 5. Сбросить правила UFW
if command -v ufw >/dev/null 2>&1; then
    echo "▶ Сбрасываю UFW..."
    sudo ufw --force reset
    sudo ufw allow 22/tcp
    sudo ufw default allow incoming
    sudo ufw default allow outgoing
    sudo ufw disable
else
    echo "ℹ UFW не установлен, пропускаю."
fi

# 6. Перезапустить SSH
echo "▶ Перезапускаю SSH..."
if systemctl is-active ssh >/dev/null 2>&1; then
    sudo systemctl restart ssh
elif systemctl is-active sshd >/dev/null 2>&1; then
    sudo systemctl restart sshd
fi

echo "✅ Откат завершён!"
