#!/bin/bash

# Zivpn UDP Module + Telegram Bot Installer (FIXED)
# Creator: Zahid Islam (fixed by assistant)
# Notes: fixes for DB schema, admin notify, vpn config update, create account flow

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}=== Zivpn UDP VPN + Telegram Bot Installer (Fixed) ===${NC}"
echo ""

VPN_PASSWORDS=()

print_status() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }

install_dependencies() {
  print_status "Updating system and installing dependencies..."
  apt-get update && apt-get upgrade -y
  apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw jq netcat-openbsd sqlite3
}

collect_configuration() {
  echo -e "${YELLOW}=== Basic Configuration ===${NC}"
  SERVER_IP=$(curl -4 ifconfig.me 2>/dev/null || curl -4 icanhazip.com 2>/dev/null || echo "")
  if [ -z "$SERVER_IP" ]; then
    read -p "Enter Your Server IP: " SERVER_IP
  else
    echo "Detected Server IP: $SERVER_IP"
    read -p "Press Enter to use this IP or enter different IP: " CUSTOM_IP
    if [ -n "$CUSTOM_IP" ]; then SERVER_IP="$CUSTOM_IP"; fi
  fi

  echo ""
  read -p "Enter Your Hostname (e.g., jvpn.shop) (leave empty to use IP): " SERVER_HOSTNAME

  echo ""
  read -p "Enter Admin Token (default: admin123): " ADMIN_TOKEN
  ADMIN_TOKEN=${ADMIN_TOKEN:-admin123}

  read -p "Enter Admin IDs (comma separated Telegram numeric IDs, e.g. 12345678,87654321): " ADMIN_IDS

  echo ""
  echo -e "${YELLOW}=== VPN Passwords ===${NC}"
  read -p "Enter VPN passwords separated by commas (Press enter for Default 'zi'): " vpn_passwords_input
  if [ -n "$vpn_passwords_input" ]; then
    IFS=',' read -r -a VPN_PASSWORDS <<< "$vpn_passwords_input"
  else
    VPN_PASSWORDS=("zi")
  fi

  echo "VPN Passwords set to: ${VPN_PASSWORDS[*]}"

  echo ""
  echo -e "${YELLOW}=== Payment Configuration ===${NC}"
  read -p "Enter Bank Name: " BANK_NAME
  read -p "Enter Bank Number: " BANK_ACCOUNT
  read -p "Enter Account Holder Name: " ACCOUNT_NAME

  echo ""
  echo "Upload QR code image to imgbb/imgur/postimages and paste direct link."
  read -p "Enter Bank QR Image Link (Direct URL, optional): " QR_IMAGE_URL
}

install_udp_vpn() {
  print_status "Installing Zivpn UDP VPN..."
  systemctl stop zivpn.service 2>/dev/null || true

  wget -q -O /usr/local/bin/zivpn https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 || true
  if [ -f /usr/local/bin/zivpn ]; then
    chmod +x /usr/local/bin/zivpn
  else
    print_error "Failed to download zivpn binary. Please check the URL or network."
  fi

  mkdir -p /etc/zivpn

  print_status "Generating SSL certificates..."
  openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" >/dev/null 2>&1 || true

  # Build config array
  config_array="["
  for ((i=0;i<${#VPN_PASSWORDS[@]};i++)); do
    config_array="${config_array}\"${VPN_PASSWORDS[i]}\""
    if [ $i -lt $((${#VPN_PASSWORDS[@]}-1)) ]; then
      config_array="${config_array},"
    fi
  done
  config_array="${config_array}]"

  cat > /etc/zivpn/config.json <<EOF
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": $config_array
  }
}
EOF

  # Validate JSON
  if python3 -m json.tool /etc/zivpn/config.json > /dev/null 2>&1; then
    print_success "Config.json created and valid"
  else
    print_error "Config.json invalid after write — showing content for debug:"
    cat /etc/zivpn/config.json
  fi

  # systemd service
  cat > /etc/systemd/system/zivpn.service <<EOF
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

  sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
  sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

  systemctl daemon-reload
  systemctl enable zivpn.service 2>/dev/null || true
  systemctl restart zivpn.service 2>/dev/null || true

  sleep 2
  if systemctl is-active --quiet zivpn.service; then
    print_success "Zivpn UDP VPN service is running!"
  else
    print_error "Zivpn service failed to start. Last 20 lines of journal:"
    journalctl -u zivpn.service -n 20 --no-pager || true
  fi

  # Firewall nat for a broad UDP port range -> DNAT to 5667
  interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 2>/dev/null || echo "eth0")
  iptables -t nat -F 2>/dev/null || true
  iptables -t nat -X 2>/dev/null || true
  iptables -t nat -A PREROUTING -i $interface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || true

  # UFW
  ufw --force reset 2>/dev/null || true
  echo "y" | ufw --force enable 2>/dev/null || true
  ufw allow 6000:19999/udp >/dev/null 2>&1 || true
  ufw allow 5667/udp >/dev/null 2>&1 || true
  ufw allow 22/tcp >/dev/null 2>&1 || true

  print_success "Zivpn UDP VPN installed (or updated)."
  echo ""
  echo -e "${YELLOW}=== VPN Configuration ===${NC}"
  echo "Server Address: ${SERVER_HOSTNAME:-$SERVER_IP}"
  echo "VPN Port: 5667"
  echo "VPN Passwords: ${VPN_PASSWORDS[*]}"
  echo "Config file: /etc/zivpn/config.json"
  echo ""
}

install_telegram_bot() {
  print_status "Installing Telegram Bot..."
  mkdir -p /opt/zivpn-bot
  cd /opt/zivpn-bot

  python3 -m venv venv
  source venv/bin/activate

  pip install --upgrade pip >/dev/null 2>&1 || true
  pip install python-telegram-bot==20.3 python-dotenv pillow qrcode cryptography >/dev/null 2>&1 || true

  echo ""
  echo -e "${YELLOW}=== Telegram Bot Configuration ===${NC}"
  read -p "Enter Bot Token from @BotFather: " BOT_TOKEN

  # Create bot files
  create_bot_files
  create_systemd_service

  # Initialize database
  source venv/bin/activate
  python3 - <<PY
from database import Database
db = Database('zivpn.db')
print("Database initialized")
PY

  systemctl daemon-reload
  systemctl enable zivpn-bot.service 2>/dev/null || true
  systemctl restart zivpn-bot.service 2>/dev/null || true

  sleep 2
  if systemctl is-active --quiet zivpn-bot.service; then
    print_success "Telegram Bot installed and running!"
  else
    print_error "Bot service failed to start. Check logs:"
    journalctl -u zivpn-bot.service -n 20 --no-pager || true
  fi

  echo -e "${YELLOW}Bot configuration saved to: /opt/zivpn-bot/.env${NC}"
}

create_bot_files() {
  # Determine SERVER_ADDRESS
  if [ -n "${SERVER_HOSTNAME:-}" ]; then
    SERVER_ADDRESS="$SERVER_HOSTNAME"
  else
    SERVER_ADDRESS="$SERVER_IP"
  fi

  cat > /opt/zivpn-bot/config.py <<'PYCONF'
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    BOT_TOKEN = os.getenv("BOT_TOKEN", "")
    # parse ADMIN_IDS robustly
    _admin_raw = os.getenv("ADMIN_IDS", "").strip()
    if _admin_raw:
        try:
            ADMIN_IDS = [int(x.strip()) for x in _admin_raw.split(",") if x.strip()]
        except:
            ADMIN_IDS = []
    else:
        ADMIN_IDS = []

    ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")
    DB_NAME = "zivpn.db"
    SERVER_ADDRESS = os.getenv("SERVER_ADDRESS", "your-server.com")
    SERVER_PORT = os.getenv("SERVER_PORT", "5667")

    BANK_ACCOUNT = os.getenv("BANK_ACCOUNT", "1234567890")
    BANK_NAME = os.getenv("BANK_NAME", "Bank Name")
    ACCOUNT_NAME = os.getenv("ACCOUNT_NAME", "Account Name")
    QR_IMAGE_URL = os.getenv("QR_IMAGE_URL", "")

    VPN_CONFIG_PATH = "/etc/zivpn/config.json"
    MAX_DEVICES = 1
    CURRENCY = "THB"

    @staticmethod
    def is_admin(user_id):
        return user_id in Config.ADMIN_IDS

    @staticmethod
    def get_admin_unlimited_credit():
        return 999999
PYCONF

  # Database - fixed schema + functions
  cat > /opt/zivpn-bot/database.py <<'PYDB'
import sqlite3
import json
from datetime import datetime, timedelta
import subprocess
from config import Config
import os

class Database:
    def __init__(self, db_name="zivpn.db"):
        self.db_path = db_name
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.create_tables()

    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                credit INTEGER DEFAULT 0,
                join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin INTEGER DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                vpn_username TEXT,
                vpn_password TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expire_date TIMESTAMP,
                device_hash TEXT,
                is_active INTEGER DEFAULT 1,
                UNIQUE(vpn_username, vpn_password),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                amount INTEGER,
                screenshot TEXT,
                status TEXT DEFAULT 'pending',
                admin_id INTEGER,
                admin_note TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_date TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER,
                device_hash TEXT UNIQUE,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (account_id) REFERENCES accounts (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS renew_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER,
                user_id INTEGER,
                old_expire_date TIMESTAMP,
                new_expire_date TIMESTAMP,
                renew_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                days_added INTEGER,
                FOREIGN KEY (account_id) REFERENCES accounts (id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        self.conn.commit()

    def get_user(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        return cursor.fetchone()

    def create_user(self, user_id, username, is_admin=False):
        cursor = self.conn.cursor()
        try:
            cursor.execute('INSERT OR IGNORE INTO users (user_id, username, is_admin) VALUES (?, ?, ?)', (user_id, username, int(is_admin)))
            self.conn.commit()
            return True
        except Exception as e:
            return False

    def update_credit(self, user_id, amount):
        cursor = self.conn.cursor()
        cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
        self.conn.commit()
        return True

    def get_credit(self, user_id):
        if Config.is_admin(user_id):
            return Config.get_admin_unlimited_credit()
        cursor = self.conn.cursor()
        cursor.execute('SELECT credit FROM users WHERE user_id = ?', (user_id,))
        res = cursor.fetchone()
        return res['credit'] if res else 0

    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, is_active FROM accounts WHERE vpn_username = ? AND vpn_password = ?', (username, password))
        existing = cursor.fetchone()
        if existing:
            if existing['is_active']:
                return False, "This account already exists and is active."
            else:
                expire_date = datetime.now() + timedelta(days=days)
                cursor.execute('UPDATE accounts SET is_active = 1, expire_date = ? WHERE id = ?', (expire_date, existing['id']))
                success = self.update_vpn_config(password)
                if not success:
                    return False, "Failed to update VPN configuration"
                self.conn.commit()
                return True, "Account reactivated successfully"

        expire_date = datetime.now() + timedelta(days=days)
        try:
            cursor.execute('INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date) VALUES (?, ?, ?, ?)', (user_id, username, password, expire_date))
            success = self.update_vpn_config(password)
            if not success:
                # rollback if vpn config update failed
                self.conn.rollback()
                return False, "Failed to update VPN configuration (check /etc/zivpn/config.json permissions)"
            self.conn.commit()
            return True, "Account created successfully"
        except Exception as e:
            return False, str(e)

    def update_vpn_config(self, password):
        try:
            path = Config.VPN_CONFIG_PATH
            # backup
            if os.path.exists(path):
                with open(path, 'r') as f:
                    content = f.read()
                with open(path + '.backup', 'w') as fb:
                    fb.write(content)

            # load or create
            if os.path.exists(path):
                with open(path, 'r') as f:
                    config = json.load(f)
            else:
                config = {
                    "listen": ":5667",
                    "cert": "/etc/zivpn/zivpn.crt",
                    "key": "/etc/zivpn/zivpn.key",
                    "obfs": "",
                    "auth": {"mode": "passwords", "config": []}
                }

            if 'auth' not in config:
                config['auth'] = {"mode": "passwords", "config": []}
            if 'config' not in config['auth']:
                config['auth']['config'] = []

            if password not in config['auth']['config']:
                config['auth']['config'].append(password)

            with open(path, 'w') as f:
                json.dump(config, f, indent=2)

            # restart service
            try:
                result = subprocess.run(['systemctl', 'restart', 'zivpn.service'], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    return True
                else:
                    print("DEBUG: systemctl restart zivpn failed:", result.stderr)
                    return False
            except Exception as e:
                print("DEBUG: Error restarting zivpn:", e)
                return False
        except FileNotFoundError:
            print("DEBUG: config file not found:", Config.VPN_CONFIG_PATH)
            return False
        except json.JSONDecodeError as e:
            print("DEBUG: JSON decode error in vpn config:", e)
            return False
        except Exception as e:
            print("DEBUG: Unexpected error updating vpn config:", e)
            return False

    def get_user_accounts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, vpn_username, vpn_password, expire_date, is_active FROM accounts WHERE user_id = ? ORDER BY is_active DESC, expire_date DESC', (user_id,))
        return cursor.fetchall()

    def get_account_by_password(self, user_id, password):
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, vpn_username, expire_date, is_active FROM accounts WHERE user_id = ? AND vpn_password = ? AND is_active = 1', (user_id, password))
        return cursor.fetchone()

    def renew_account(self, account_id, days):
        cursor = self.conn.cursor()
        cursor.execute('SELECT expire_date FROM accounts WHERE id = ?', (account_id,))
        res = cursor.fetchone()
        if not res:
            return False, "Account not found"

        now = datetime.now()
        old_expire = res['expire_date']
        if isinstance(old_expire, str):
            try:
                old_expire_dt = datetime.fromisoformat(old_expire)
            except:
                old_expire_dt = now
        else:
            old_expire_dt = old_expire

        if old_expire_dt > now:
            new_expire = old_expire_dt + timedelta(days=days)
        else:
            new_expire = now + timedelta(days=days)

        cursor.execute('UPDATE accounts SET expire_date = ?, is_active = 1 WHERE id = ?', (new_expire, account_id))
        # record renew history
        user_id = self.get_account_user(account_id)
        cursor.execute('INSERT INTO renew_history (account_id, user_id, old_expire_date, new_expire_date, days_added) VALUES (?, ?, ?, ?, ?)', (account_id, user_id, old_expire_dt, new_expire, days))
        self.conn.commit()
        return True, new_expire

    def get_account_user(self, account_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id FROM accounts WHERE id = ?', (account_id,))
        r = cursor.fetchone()
        return r['user_id'] if r else None

    def create_payment(self, user_id, amount, screenshot=None):
        cursor = self.conn.cursor()
        cursor.execute('INSERT INTO payments (user_id, amount, screenshot, status) VALUES (?, ?, ?, "pending")', (user_id, amount, screenshot))
        self.conn.commit()
        return cursor.lastrowid

    def get_pending_payments(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT p.*, u.username FROM payments p JOIN users u ON p.user_id = u.user_id WHERE p.status = "pending" ORDER BY p.created_date ASC')
        return cursor.fetchall()

    def approve_payment(self, payment_id, admin_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id, amount FROM payments WHERE id = ? AND status = ?', (payment_id, 'pending'))
        payment = cursor.fetchone()
        if payment:
            user_id = payment['user_id']
            amount = payment['amount']
            cursor.execute('UPDATE payments SET status = "approved", admin_id = ?, approved_date = CURRENT_TIMESTAMP WHERE id = ?', (admin_id, payment_id))
            cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
            self.conn.commit()
            return True, amount, user_id
        return False, 0, None

    def reject_payment(self, payment_id, admin_id, note=""):
        cursor = self.conn.cursor()
        cursor.execute('UPDATE payments SET status = "rejected", admin_id = ?, admin_note = ? WHERE id = ? AND status = ?', (admin_id, note, payment_id, 'pending'))
        self.conn.commit()
        return cursor.rowcount > 0

    def get_all_users(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT u.user_id, u.username, u.credit, COUNT(a.id) as account_count, u.join_date, u.is_admin
            FROM users u LEFT JOIN accounts a ON u.user_id = a.user_id
            GROUP BY u.user_id ORDER BY u.join_date DESC
        ''')
        return cursor.fetchall()

    def get_total_users(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) as cnt FROM users')
        return cursor.fetchone()['cnt']

    def get_active_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) as cnt FROM accounts WHERE is_active = 1')
        return cursor.fetchone()['cnt']

    def get_all_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT a.id, a.vpn_username, a.vpn_password, a.expire_date, a.is_active, u.user_id, u.username
            FROM accounts a JOIN users u ON a.user_id = u.user_id ORDER BY a.expire_date DESC
        ''')
        return cursor.fetchall()

    def get_payment_stats(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT status, COUNT(*) as cnt, SUM(amount) as total FROM payments GROUP BY status')
        return cursor.fetchall()
PYDB

  # Bot code (fixed key parts)
  cat > /opt/zivpn-bot/bot.py <<'PYBOT'
import logging, os, qrcode
from io import BytesIO
from datetime import datetime, timedelta
import json, sys
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes, ConversationHandler

from config import Config
from database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TOPUP_AMOUNT, PAYMENT_PROOF = range(2)
CREATE_USERNAME, CREATE_PASSWORD, SELECT_PLAN = range(2,5)
RENEW_PASSWORD, RENEW_SELECT_PLAN = range(5,7)
ADMIN_PANEL, ADMIN_ACTION, REJECT_REASON = range(7,10)

class ZivpnBot:
    def __init__(self):
        if not Config.BOT_TOKEN:
            logger.error("BOT_TOKEN not set in environment. Exiting.")
            sys.exit(1)
        self.db = Database(Config.DB_NAME)
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()

    def setup_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(MessageHandler(filters.Regex('^💳 Top-up Credit$'), self.topup_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^🆕 Create Account$'), self.create_account_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^🔄 Renew Account$'), self.renew_account_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^💰 Check Credit$'), self.check_credit_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^👤 My Accounts$'), self.my_accounts_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^👑 Admin Panel$'), self.admin_panel_keyboard))
        self.application.add_handler(MessageHandler(filters.Regex('^🏠 Main Menu$'), self.back_to_menu_keyboard))

        # callbacks
        self.application.add_handler(CallbackQueryHandler(self.topup_amount, pattern='^topup_amount$'))
        self.application.add_handler(CallbackQueryHandler(self.select_amount, pattern='^amount_'))
        self.application.add_handler(CallbackQueryHandler(self.upload_payment_proof, pattern='^upload_proof$'))
        self.application.add_handler(CallbackQueryHandler(self.create_account_input, pattern='^create_account_input$'))
        self.application.add_handler(CallbackQueryHandler(self.select_plan, pattern='^plan_'))
        self.application.add_handler(CallbackQueryHandler(self.renew_account_input, pattern='^renew_account_input$'))
        self.application.add_handler(CallbackQueryHandler(self.select_renew_plan, pattern='^renew_plan_'))
        self.application.add_handler(CallbackQueryHandler(self.admin_menu, pattern='^admin_menu$'))
        self.application.add_handler(CallbackQueryHandler(self.admin_action, pattern='^admin_'))
        self.application.add_handler(CallbackQueryHandler(self.handle_admin_action, pattern='^action_'))
        self.application.add_handler(CallbackQueryHandler(self.back_to_menu, pattern='^back$'))
        self.application.add_handler(CallbackQueryHandler(self.cancel, pattern='^cancel$'))

        topup_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.topup_amount, pattern='^topup_amount$')],
            states={TOPUP_AMOUNT:[CallbackQueryHandler(self.select_amount, pattern='^amount_')], PAYMENT_PROOF:[MessageHandler(filters.PHOTO, self.receive_payment_proof)]},
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )

        create_account_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.create_account_input, pattern='^create_account_input$')],
            states={CREATE_USERNAME:[MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_username)], CREATE_PASSWORD:[MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_password)], SELECT_PLAN:[CallbackQueryHandler(self.select_plan, pattern='^plan_')]},
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )

        renew_account_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.renew_account_input, pattern='^renew_account_input$')],
            states={RENEW_PASSWORD:[MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_renew_password)], RENEW_SELECT_PLAN:[CallbackQueryHandler(self.select_renew_plan, pattern='^renew_plan_')]},
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )

        admin_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.admin_menu, pattern='^admin_menu$')],
            states={ADMIN_PANEL:[CallbackQueryHandler(self.admin_action, pattern='^admin_')], ADMIN_ACTION:[CallbackQueryHandler(self.handle_admin_action, pattern='^action_')], REJECT_REASON:[MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_reject_reason)]},
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )

        self.application.add_handler(topup_conv)
        self.application.add_handler(create_account_conv)
        self.application.add_handler(renew_account_conv)
        self.application.add_handler(admin_conv)

        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_message))

    def get_keyboard_menu(self, user_id):
        is_admin = Config.is_admin(user_id)
        if is_admin:
            keyboard = [[KeyboardButton("💳 Top-up Credit"), KeyboardButton("🆕 Create Account")],
                        [KeyboardButton("🔄 Renew Account"), KeyboardButton("💰 Check Credit")],
                        [KeyboardButton("👤 My Accounts"), KeyboardButton("👑 Admin Panel")],
                        [KeyboardButton("🏠 Main Menu")]]
        else:
            keyboard = [[KeyboardButton("💳 Top-up Credit"), KeyboardButton("🆕 Create Account")],
                        [KeyboardButton("🔄 Renew Account"), KeyboardButton("💰 Check Credit")],
                        [KeyboardButton("👤 My Accounts"), KeyboardButton("🏠 Main Menu")]]
        return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        user_id = user.id
        if context.user_data:
            context.user_data.clear()
        is_admin = Config.is_admin(user_id)
        self.db.create_user(user_id, user.username or user.first_name, is_admin)
        reply_markup = self.get_keyboard_menu(user_id)
        credit = self.db.get_credit(user_id)
        credit_display = "∞ (Admin)" if is_admin else f"{credit} {Config.CURRENCY}"
        welcome_text = f"🌟 Welcome to ZIVPN VPN Service!\n\n📊 Your Credit: {credit_display}\n🌐 Server: {Config.SERVER_ADDRESS}\n🔌 Port: {Config.SERVER_PORT}\n"
        await update.message.reply_text(welcome_text, reply_markup=reply_markup)

    async def handle_text_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("Please use the menu buttons below to navigate.", reply_markup=self.get_keyboard_menu(update.effective_user.id))

    async def topup_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        keyboard = [[InlineKeyboardButton("50 THB", callback_data='amount_50'), InlineKeyboardButton("100 THB", callback_data='amount_100'), InlineKeyboardButton("150 THB", callback_data='amount_150')],
                    [InlineKeyboardButton("200 THB", callback_data='amount_200'), InlineKeyboardButton("300 THB", callback_data='amount_300'), InlineKeyboardButton("500 THB", callback_data='amount_500')],
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Select top-up amount:", reply_markup=reply_markup)

    async def create_account_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        if not Config.is_admin(user_id) and credit < 50:
            await update.message.reply_text(f"❌ Insufficient credit!\nYour credit: {credit} {Config.CURRENCY}\nMinimum required: 50 {Config.CURRENCY}")
            return
        keyboard = [[InlineKeyboardButton("Start Creating Account", callback_data='create_account_input')],[InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await update.message.reply_text("Click the button below to start creating your VPN account:", reply_markup=InlineKeyboardMarkup(keyboard))

    async def renew_account_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        if not Config.is_admin(user_id) and credit < 50:
            await update.message.reply_text(f"❌ Insufficient credit!\nYour credit: {credit} {Config.CURRENCY}\nMinimum required: 50 {Config.CURRENCY}")
            return
        keyboard = [[InlineKeyboardButton("Start Renew Account", callback_data='renew_account_input')],[InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await update.message.reply_text("Click the button below to renew your VPN account:", reply_markup=InlineKeyboardMarkup(keyboard))

    async def check_credit_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        credit_display = "∞ (Admin)" if Config.is_admin(user_id) else f"{self.db.get_credit(user_id)} {Config.CURRENCY}"
        await update.message.reply_text(f"💰 Your Credit: {credit_display}")

    async def my_accounts_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        accounts = self.db.get_user_accounts(user_id)
        if not accounts:
            await update.message.reply_text("You don't have any accounts yet.")
            return
        text = "📋 Your Accounts:\n\n"
        for account in accounts:
            account_id = account['id']
            username = account['vpn_username']
            password = account['vpn_password']
            expire_date = account['expire_date']
            is_active = account['is_active']
            status = "✅ Active" if is_active else "❌ Expired"
            text += f"👤 Username: `{username}`\n🔑 Password: `{password}`\n📅 Expire: {expire_date}\n📊 Status: {status}\n" + "─"*20 + "\n"
        await update.message.reply_text(text, parse_mode='Markdown')

    async def admin_panel_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if not Config.is_admin(user_id):
            await update.message.reply_text("❌ Access denied!")
            return
        keyboard = [[InlineKeyboardButton("👥 User List", callback_data='admin_users')],
                    [InlineKeyboardButton("📊 Payment Requests", callback_data='admin_payments')],
                    [InlineKeyboardButton("🔐 All Access List", callback_data='admin_access_list')],
                    [InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await update.message.reply_text("👑 Admin Panel\n\nSelect an option:", reply_markup=InlineKeyboardMarkup(keyboard))

    async def back_to_menu_keyboard(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        reply_markup = self.get_keyboard_menu(user.id)
        credit = self.db.get_credit(user.id)
        credit_display = "∞ (Admin)" if Config.is_admin(user.id) else f"{credit} {Config.CURRENCY}"
        welcome_text = f"🏠 Main Menu\n\n📊 Your Credit: {credit_display}\n🌐 Server: {Config.SERVER_ADDRESS}"
        await update.message.reply_text(welcome_text, reply_markup=reply_markup)

    async def back_to_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = update.effective_user
        reply_markup = self.get_keyboard_menu(user.id)
        await query.edit_message_text("Returned to main menu.", reply_markup=reply_markup)

    async def topup_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        keyboard = [[InlineKeyboardButton("50 THB", callback_data='amount_50'), InlineKeyboardButton("100 THB", callback_data='amount_100'), InlineKeyboardButton("150 THB", callback_data='amount_150')],
                    [InlineKeyboardButton("200 THB", callback_data='amount_200'), InlineKeyboardButton("300 THB", callback_data='amount_300'), InlineKeyboardButton("500 THB", callback_data='amount_500')],
                    [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await query.edit_message_text("Select top-up amount:", reply_markup=InlineKeyboardMarkup(keyboard))
        return TOPUP_AMOUNT

    async def select_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        amount = int(query.data.split('_')[1])
        context.user_data['topup_amount'] = amount

        # show QR
        try:
            if Config.QR_IMAGE_URL and Config.QR_IMAGE_URL.startswith('http'):
                await query.message.reply_photo(photo=Config.QR_IMAGE_URL, caption=f"Scan QR code to pay {amount} {Config.CURRENCY}")
            else:
                qr = qrcode.QRCode(version=1, box_size=10, border=4)
                qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
                qr.make(fit=True)
                img = qr.make_image()
                bio = BytesIO()
                img.save(bio, 'PNG')
                bio.seek(0)
                await query.message.reply_photo(photo=bio)
        except Exception as e:
            logger.error("Failed to send QR:", e)

        payment_info = f"💰 Payment Information:\n\n🏦 Bank: {Config.BANK_NAME}\n📞 Account: {Config.BANK_ACCOUNT}\n👤 Name: {Config.ACCOUNT_NAME}\n💵 Amount: {amount} {Config.CURRENCY}\n\nPlease transfer the exact amount and upload screenshot as proof."
        await query.message.reply_text(payment_info)

        keyboard = [[InlineKeyboardButton("📸 Upload Payment Proof", callback_data='upload_proof')],[InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await query.message.reply_text("After payment, click the button below to upload screenshot:", reply_markup=InlineKeyboardMarkup(keyboard))
        return PAYMENT_PROOF

    async def upload_payment_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await query.message.reply_text("📸 Please send the payment screenshot now:")
        return PAYMENT_PROOF

    async def receive_payment_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        user_id = user.id
        amount = context.user_data.get('topup_amount', 0)
        if Config.is_admin(user_id):
            await update.message.reply_text("✅ You are an admin! Credit has been added automatically.")
            self.db.update_credit(user_id, amount)
            await update.message.reply_text(f"Added {amount} {Config.CURRENCY} to your account.")
            return ConversationHandler.END

        photo = update.message.photo[-1]
        file_id = photo.file_id
        payment_id = self.db.create_payment(user_id, amount, file_id)

        await update.message.reply_text(f"✅ Payment proof received!\nAmount: {amount} {Config.CURRENCY}\nPayment ID: #{payment_id}\nPlease wait for admin approval.")

        # Notify admins
        if not Config.ADMIN_IDS:
            # fallback: notify the user (or print log)
            logger.warning("No ADMIN_IDS configured - payment pending but no admin to notify.")
            return ConversationHandler.END

        for admin_id in Config.ADMIN_IDS:
            try:
                caption = (f"📥 New Payment Request!\n👤 User: @{user.username or user.first_name}\n🆔 User ID: {user_id}\n💰 Amount: {amount} {Config.CURRENCY}\n🆔 Payment ID: #{payment_id}\n🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                keyboard = [[InlineKeyboardButton(f"✅ Approve #{payment_id}", callback_data=f"action_approve_{payment_id}"),
                             InlineKeyboardButton(f"❌ Reject #{payment_id}", callback_data=f"action_reject_{payment_id}")]]
                await self.application.bot.send_photo(chat_id=admin_id, photo=file_id, caption=caption, reply_markup=InlineKeyboardMarkup(keyboard))
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")

        return ConversationHandler.END

    async def create_account_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        if not Config.is_admin(user_id) and credit < 50:
            await query.edit_message_text(f"❌ Insufficient credit!\nYour credit: {credit} {Config.CURRENCY}\nMinimum required: 50 {Config.CURRENCY}")
            return ConversationHandler.END
        await query.edit_message_text("Please enter your desired VPN username (min 3 characters):")
        return CREATE_USERNAME

    async def get_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        username = update.message.text.strip()
        if len(username) < 3:
            await update.message.reply_text("Username must be at least 3 characters. Please try again:")
            return CREATE_USERNAME
        context.user_data['vpn_username'] = username
        await update.message.reply_text("Now enter your desired VPN password (min 4 characters):")
        return CREATE_PASSWORD

    async def get_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        if len(password) < 4:
            await update.message.reply_text("Password must be at least 4 characters. Please try again:")
            return CREATE_PASSWORD
        context.user_data['vpn_password'] = password
        user_id = update.effective_user.id

        if Config.is_admin(user_id):
            keyboard = [[InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')],
                        [InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')],
                        [InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')],
                        [InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        else:
            credit = self.db.get_credit(user_id)
            keyboard = []
            if credit >= 50: keyboard.append([InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')])
            if credit >= 100: keyboard.append([InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')])
            if credit >= 150: keyboard.append([InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')])
            keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data='back')])

        await update.message.reply_text("Select subscription plan:", reply_markup=InlineKeyboardMarkup(keyboard))
        return SELECT_PLAN

    async def select_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        days = int(query.data.split('_')[1])
        # cost calculation: 50 THB for 30 days
        cost = days * 50 // 30
        user_id = update.effective_user.id
        username = context.user_data.get('vpn_username')
        password = context.user_data.get('vpn_password')

        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                return ConversationHandler.END

        success, message = self.db.create_account(user_id, username, password, days)
        if success:
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            expire_date = (datetime.now() + timedelta(days=days)).strftime('%Y-%m-%d')
            account_info = f"✅ Account Created Successfully!\n\n🔧 Server: `{Config.SERVER_ADDRESS}`\n🔌 Port: `{Config.SERVER_PORT}`\n👤 Username: `{username}`\n🔑 Password: `{password}`\n📅 Expire Date: {expire_date}\n"
            await query.edit_message_text(account_info, parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ Error: {message}")
        return ConversationHandler.END

    async def renew_account_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        if not Config.is_admin(user_id) and credit < 50:
            await query.edit_message_text(f"❌ Insufficient credit!\nYour credit: {credit} {Config.CURRENCY}\nMinimum required: 50 {Config.CURRENCY}")
            return ConversationHandler.END
        await query.edit_message_text("Please enter your existing VPN password to renew:")
        return RENEW_PASSWORD

    async def get_renew_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        user_id = update.effective_user.id
        account = self.db.get_account_by_password(user_id, password)
        if not account:
            await update.message.reply_text("❌ Account not found or doesn't belong to you. Please try again:")
            return RENEW_PASSWORD
        account_id = account['id']
        context.user_data['renew_account_id'] = account_id
        context.user_data['renew_password'] = password
        # plans
        if Config.is_admin(user_id):
            keyboard = [[InlineKeyboardButton("30 Days - 50 THB", callback_data='renew_plan_30')],[InlineKeyboardButton("60 Days - 100 THB", callback_data='renew_plan_60')],[InlineKeyboardButton("90 Days - 150 THB", callback_data='renew_plan_90')],[InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        else:
            credit = self.db.get_credit(user_id)
            keyboard = []
            if credit >= 50: keyboard.append([InlineKeyboardButton("30 Days - 50 THB", callback_data='renew_plan_30')])
            if credit >= 100: keyboard.append([InlineKeyboardButton("60 Days - 100 THB", callback_data='renew_plan_60')])
            if credit >= 150: keyboard.append([InlineKeyboardButton("90 Days - 150 THB", callback_data='renew_plan_90')])
            keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data='back')])
        await update.message.reply_text(f"Account found: {account['vpn_username']}\nCurrent expiry: {account['expire_date']}\n\nSelect renewal plan:", reply_markup=InlineKeyboardMarkup(keyboard))
        return RENEW_SELECT_PLAN

    async def select_renew_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        days = int(query.data.split('_')[2])
        cost = days * 50 // 30
        user_id = update.effective_user.id
        account_id = context.user_data.get('renew_account_id')
        password = context.user_data.get('renew_password')
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                return ConversationHandler.END
        success, new_expire = self.db.renew_account(account_id, days)
        if success:
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            await query.edit_message_text(f"✅ Account Renewed Successfully!\n\n🔧 Server: `{Config.SERVER_ADDRESS}`\n🔌 Port: `{Config.SERVER_PORT}`\n🔑 Password: `{password}`\n📅 New Expire Date: {new_expire.strftime('%Y-%m-%d')}\n", parse_mode='Markdown')
        else:
            await query.edit_message_text("❌ Error renewing account")
        return ConversationHandler.END

    async def admin_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user_id = update.effective_user.id
        if not Config.is_admin(user_id):
            await query.edit_message_text("❌ Access denied!")
            return ConversationHandler.END
        keyboard = [[InlineKeyboardButton("👥 User List", callback_data='admin_users')],[InlineKeyboardButton("📊 Payment Requests", callback_data='admin_payments')],[InlineKeyboardButton("🔐 All Access List", callback_data='admin_access_list')],[InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],[InlineKeyboardButton("🏠 Main Menu", callback_data='back')]]
        await query.edit_message_text("👑 Admin Panel\n\nSelect an option:", reply_markup=InlineKeyboardMarkup(keyboard))
        return ADMIN_PANEL

    async def admin_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        action = query.data
        if action == 'admin_users':
            users = self.db.get_all_users()
            text = "No users found." if not users else "👥 User List:\n\n"
            if users:
                for u in users:
                    is_admin = "👑" if u['is_admin'] else "👤"
                    credit = "∞" if Config.is_admin(u['user_id']) else f"{u['credit']} {Config.CURRENCY}"
                    text += f"{is_admin} ID: {u['user_id']}\nUsername: {u['username'] or 'N/A'}\nCredit: {credit}\nAccounts: {u['account_count']}\nJoined: {u['join_date']}\n" + "─"*20 + "\n"
            await query.edit_message_text(text[:4000], reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
        elif action == 'admin_payments':
            payments = self.db.get_pending_payments()
            if not payments:
                await query.edit_message_text("No pending payments.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
            else:
                text = "📊 Pending Payments:\n\n"
                for p in payments:
                    text += f"🆔 Payment ID: #{p['id']}\n👤 User: @{p['username'] or 'N/A'} ({p['user_id']})\n💰 Amount: {p['amount']} {Config.CURRENCY}\n📅 Date: {p['created_date']}\n" + "─"*20 + "\n"
                await query.edit_message_text(text[:4000], reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
        elif action == 'admin_access_list':
            accounts = self.db.get_all_accounts()
            if not accounts:
                await query.edit_message_text("No accounts found.", reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
            else:
                text = "🔐 All Access List:\n\n"
                for a in accounts:
                    status = "✅" if a['is_active'] else "❌"
                    text += f"ID: {a['id']}\nUser: @{a['username'] or a['user_id']} ({a['user_id']})\nVPN User: `{a['vpn_username']}`\nVPN Pass: `{a['vpn_password']}`\nExpire: {a['expire_date']}\nStatus: {status}\n" + "─"*20 + "\n"
                await query.edit_message_text(text[:4000], parse_mode='Markdown', reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
        elif action == 'admin_stats':
            total_users = self.db.get_total_users()
            active_accounts = self.db.get_active_accounts()
            all_accounts = self.db.get_all_accounts()
            payment_stats = self.db.get_payment_stats()
            total_pending = total_approved = total_rejected = total_approved_amount = 0
            for stat in payment_stats:
                if stat['status'] == 'pending': total_pending = stat['cnt']
                elif stat['status'] == 'approved': total_approved = stat['cnt']; total_approved_amount = stat['total'] or 0
                elif stat['status'] == 'rejected': total_rejected = stat['cnt']
            text = f"📈 System Statistics:\n\n👥 Total Users: {total_users}\n🔧 Active Accounts: {active_accounts}\n🔐 Total Accounts: {len(all_accounts) if all_accounts else 0}\n\n💳 Payment Statistics:\n⏳ Pending: {total_pending}\n✅ Approved: {total_approved} (Total: {total_approved_amount or 0} {Config.CURRENCY})\n❌ Rejected: {total_rejected}\n\n👑 Admin Users: {len(Config.ADMIN_IDS)}\n🌐 Server: {Config.SERVER_ADDRESS}\n🔌 VPN Port: {Config.SERVER_PORT}\n💵 Currency: {Config.CURRENCY}\n"
            await query.edit_message_text(text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]))
        return ADMIN_PANEL

    async def handle_admin_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        admin_id = update.effective_user.id
        if query.data.startswith('action_approve_'):
            payment_id = int(query.data.split('_')[2])
            success, amount, user_id = self.db.approve_payment(payment_id, admin_id)
            if success:
                try:
                    await self.application.bot.send_message(user_id, f"✅ Payment Approved!\nPayment ID: #{payment_id}\nAmount: {amount} {Config.CURRENCY}\nApproved by: @{update.effective_user.username or update.effective_user.first_name}\nYour credit has been updated.")
                except Exception as e:
                    logger.error("Failed to notify user:", e)
                await query.edit_message_text(f"✅ Payment #{payment_id} approved! User notified.")
            else:
                await query.edit_message_text(f"❌ Failed to approve payment #{payment_id}")
        elif query.data.startswith('action_reject_'):
            payment_id = int(query.data.split('_')[2])
            context.user_data['reject_payment_id'] = payment_id
            context.user_data['reject_admin_id'] = admin_id
            await query.message.reply_text(f"Please enter reason for rejecting payment #{payment_id}:")
            return REJECT_REASON
        return ConversationHandler.END

    async def handle_reject_reason(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        reason = update.message.text
        payment_id = context.user_data.get('reject_payment_id')
        admin_id = context.user_data.get('reject_admin_id')
        if payment_id and admin_id:
            success = self.db.reject_payment(payment_id, admin_id, reason)
            if success:
                cursor = self.db.conn.cursor()
                cursor.execute('SELECT user_id FROM payments WHERE id = ?', (payment_id,))
                res = cursor.fetchone()
                if res:
                    user_id = res['user_id']
                    try:
                        await self.application.bot.send_message(user_id, f"❌ Payment Rejected\nPayment ID: #{payment_id}\nReason: {reason}\nPlease contact admin for more information.")
                    except Exception as e:
                        logger.error("Failed to notify user:", e)
                await update.message.reply_text(f"✅ Payment #{payment_id} rejected with reason.")
            else:
                await update.message.reply_text(f"❌ Failed to reject payment #{payment_id}")
            context.user_data.pop('reject_payment_id', None)
            context.user_data.pop('reject_admin_id', None)
        return ConversationHandler.END

    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        user = update.effective_user
        reply_markup = self.get_keyboard_menu(user.id)
        await query.edit_message_text("Operation cancelled. Use the menu buttons below:", reply_markup=reply_markup)
        return ConversationHandler.END

    def run(self):
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    bot = ZivpnBot()
    bot.run()
PYBOT

  # requirements
  cat > /opt/zivpn-bot/requirements.txt <<'REQ'
python-telegram-bot==20.3
python-dotenv==1.0.0
Pillow==10.0.0
qrcode==7.4.2
cryptography==41.0.5
REQ

  # .env
  cat > /opt/zivpn-bot/.env <<EOF
BOT_TOKEN=${BOT_TOKEN}
ADMIN_IDS=${ADMIN_IDS}
ADMIN_TOKEN=${ADMIN_TOKEN}
SERVER_ADDRESS=${SERVER_ADDRESS}
SERVER_PORT=5667
BANK_ACCOUNT=${BANK_ACCOUNT}
BANK_NAME=${BANK_NAME}
ACCOUNT_NAME=${ACCOUNT_NAME}
QR_IMAGE_URL=${QR_IMAGE_URL}
CURRENCY=THB
EOF

  # Ensure proper permissions
  chown -R root:root /opt/zivpn-bot || true
  chmod -R 750 /opt/zivpn-bot || true
}

create_systemd_service() {
  cat > /etc/systemd/system/zivpn-bot.service <<EOF
[Unit]
Description=Zivpn Telegram Bot
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zivpn-bot
Environment="PATH=/opt/zivpn-bot/venv/bin"
ExecStart=/opt/zivpn-bot/venv/bin/python3 bot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

fix_vpn_config() {
  print_status "Checking and fixing VPN configuration..."
  if [ -f /etc/zivpn/config.json ]; then
    if python3 -m json.tool /etc/zivpn/config.json > /dev/null 2>&1; then
      print_success "VPN config.json is valid"
      print_status "Current passwords in config:"
      python3 - <<PY
import json
try:
    with open('/etc/zivpn/config.json','r') as f:
        cfg = json.load(f)
    print(cfg.get('auth',{}).get('config','[]'))
except Exception as e:
    print("Error reading config:",e)
PY
    else
      print_error "VPN config.json invalid JSON - rebuilding using provided VPN_PASSWORDS"
      cp /etc/zivpn/config.json /etc/zivpn/config.json.backup || true
      config_array="["
      for ((i=0;i<${#VPN_PASSWORDS[@]};i++)); do
        config_array="${config_array}\"${VPN_PASSWORDS[i]}\""
        if [ $i -lt $((${#VPN_PASSWORDS[@]}-1)) ]; then
          config_array="${config_array},"
        fi
      done
      config_array="${config_array}]"
      cat > /etc/zivpn/config.json <<EOF
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": $config_array
  }
}
EOF
      print_success "Rebuilt config.json"
    fi
  else
    print_error "VPN config.json not found - creating new one"
    config_array="["
    for ((i=0;i<${#VPN_PASSWORDS[@]};i++)); do
      config_array="${config_array}\"${VPN_PASSWORDS[i]}\""
      if [ $i -lt $((${#VPN_PASSWORDS[@]}-1)) ]; then
        config_array="${config_array},"
      fi
    done
    config_array="${config_array}]"
    cat > /etc/zivpn/config.json <<EOF
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": $config_array
  }
}
EOF
    print_success "Created config.json"
  fi

  print_status "Restarting zivpn.service..."
  systemctl restart zivpn.service || true
  sleep 2
  if systemctl is-active --quiet zivpn.service; then
    print_success "VPN service restarted successfully"
  else
    print_error "VPN service failed to restart - check journal"
    journalctl -u zivpn.service -n 20 --no-pager || true
  fi
}

main_installation() {
  install_dependencies
  collect_configuration
  install_udp_vpn

  echo -e "\n${YELLOW}=== Telegram Bot Installation ===${NC}"
  read -p "Do you want to install the Telegram Bot? (y/n): " install_bot_choice
  if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
    install_telegram_bot
  else
    print_status "Skipping Telegram Bot installation..."
  fi

  fix_vpn_config

  echo -e "\n${GREEN}✅ Installation Complete!${NC}\n"
  echo -e "${YELLOW}Summary:${NC}"
  echo "Server: ${SERVER_HOSTNAME:-$SERVER_IP}"
  echo "VPN Port: 5667"
  echo "VPN Passwords: ${VPN_PASSWORDS[*]}"
  echo "Admin Token: ${ADMIN_TOKEN}"
  echo "Admin IDs: ${ADMIN_IDS}"
  if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
    echo "Telegram Bot: Installed (/opt/zivpn-bot)"
  else
    echo "Telegram Bot: Skipped"
  fi

  echo -e "\nService status (zivpn):"
  systemctl status zivpn.service --no-pager || true
  if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
    echo -e "\nService status (zivpn-bot):"
    systemctl status zivpn-bot.service --no-pager || true
  fi
}

if [[ $EUID -ne 0 ]]; then
  print_error "This script must be run as root"
  exit 1
fi

main_installation
