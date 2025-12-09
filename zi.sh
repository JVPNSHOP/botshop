#!/bin/bash

# Zivpn UDP Module + Telegram Bot Installer
# Creator: Zahid Islam
# Fixed Version: Added Config Fix + Payment System

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Zivpn UDP VPN + Telegram Bot Installer ===${NC}"
echo -e "${YELLOW}Creator: Zahid Islam${NC}"
echo ""

# Global variables
VPN_PASSWORDS=()

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Function to install dependencies
install_dependencies() {
    print_status "Updating system and installing dependencies..."
    apt-get update && apt-get upgrade -y
    apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw jq
}

# Function to collect configuration
collect_configuration() {
    echo -e "${YELLOW}=== Basic Configuration ===${NC}"
    echo ""
    
    # Get server IP
    SERVER_IP=$(curl -4 ifconfig.me 2>/dev/null || curl -4 icanhazip.com 2>/dev/null || echo "")
    if [ -z "$SERVER_IP" ]; then
        read -p "Enter Your Server IP: " SERVER_IP
    else
        echo "Detected Server IP: $SERVER_IP"
        read -p "Press Enter to use this IP or enter different IP: " CUSTOM_IP
        if [ -n "$CUSTOM_IP" ]; then
            SERVER_IP="$CUSTOM_IP"
        fi
    fi
    
    # Get hostname
    echo ""
    read -p "Enter Your Hostname (e.g., jvpn.shop): " SERVER_HOSTNAME
    
    # Get admin configuration
    echo ""
    read -p "Enter Admin Token (default: admin123): " ADMIN_TOKEN
    ADMIN_TOKEN=${ADMIN_TOKEN:-admin123}
    
    read -p "Enter Admin IDs (comma separated): " ADMIN_IDS
    
    # Get VPN passwords
    echo ""
    echo -e "${YELLOW}=== VPN Passwords ===${NC}"
    read -p "Enter VPN passwords separated by commas (Press enter for Default 'zi'): " vpn_passwords_input
    
    if [ -n "$vpn_passwords_input" ]; then
        IFS=',' read -r -a VPN_PASSWORDS <<< "$vpn_passwords_input"
    else
        VPN_PASSWORDS=("zi")
    fi
    
    echo "VPN Passwords set to: ${VPN_PASSWORDS[*]}"
    
    # Get payment information
    echo ""
    echo -e "${YELLOW}=== Payment Configuration ===${NC}"
    read -p "Enter Bank Name: " BANK_NAME
    read -p "Enter Bank Number: " BANK_ACCOUNT
    read -p "Enter Account Holder Name: " ACCOUNT_NAME
    
    echo ""
    echo "Upload QR code image to:"
    echo "1. https://imgbb.com"
    echo "2. https://imgur.com"
    echo "3. https://postimages.org"
    echo ""
    read -p "Enter Bank QR Image Link (Direct URL): " QR_IMAGE_URL
}

# Function to install UDP VPN
install_udp_vpn() {
    print_status "Installing Zivpn UDP VPN..."
    
    # Stop existing service
    systemctl stop zivpn.service 2>/dev/null
    
    # Download UDP binary
    wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn -q
    chmod +x /usr/local/bin/zivpn
    
    # Create config directory
    mkdir -p /etc/zivpn
    
    # Generate certificates
    print_status "Generating SSL certificates..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
        -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"
    
    # Create config.json with VPN passwords
    print_status "Creating config.json with VPN passwords..."
    
    # Create JSON array from VPN passwords
    config_array="["
    for ((i=0; i<${#VPN_PASSWORDS[@]}; i++)); do
        config_array="${config_array}\"${VPN_PASSWORDS[i]}\""
        if [ $i -lt $((${#VPN_PASSWORDS[@]}-1)) ]; then
            config_array="${config_array},"
        fi
    done
    config_array="${config_array}]"
    
    # Create config.json
    cat <<EOF > /etc/zivpn/config.json
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
    
    print_status "Config.json created with passwords: ${VPN_PASSWORDS[*]}"
    
    # Create systemd service
    cat <<EOF > /etc/systemd/system/zivpn.service
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
    
    # Optimize network settings
    sysctl -w net.core.rmem_max=16777216 2>/dev/null
    sysctl -w net.core.wmem_max=16777216 2>/dev/null
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service
    
    # Check if service is running
    if systemctl is-active --quiet zivpn.service; then
        print_success "Zivpn UDP VPN service is running!"
    else
        print_error "Zivpn service failed to start. Checking logs..."
        journalctl -u zivpn.service -n 20 --no-pager
    fi
    
    # Configure firewall
    print_status "Configuring firewall..."
    interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 2>/dev/null || echo "eth0")
    iptables -t nat -A PREROUTING -i $interface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null
    ufw allow 6000:19999/udp 2>/dev/null
    ufw allow 5667/udp 2>/dev/null
    echo "y" | ufw --force enable 2>/dev/null
    
    print_success "Zivpn UDP VPN installed successfully!"
    
    # Show configuration
    echo -e "${YELLOW}=== VPN Configuration ===${NC}"
    echo "Server Address: ${SERVER_HOSTNAME:-$SERVER_IP}"
    echo "VPN Port: 5667"
    echo "VPN Passwords: ${VPN_PASSWORDS[*]}"
    echo "Config file: /etc/zivpn/config.json"
    echo ""
    
    # Test authentication
    print_status "Testing VPN configuration..."
    if [ -f /etc/zivpn/config.json ]; then
        echo "Config.json content:"
        cat /etc/zivpn/config.json
        echo ""
        
        # Verify password is in config
        for password in "${VPN_PASSWORDS[@]}"; do
            if grep -q "\"$password\"" /etc/zivpn/config.json; then
                print_success "Password '$password' found in config.json"
            else
                print_error "Password '$password' NOT found in config.json"
            fi
        done
    fi
}

# Function to install Telegram Bot
install_telegram_bot() {
    print_status "Installing Telegram Bot..."
    
    # Create bot directory
    mkdir -p /opt/zivpn-bot
    cd /opt/zivpn-bot
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python dependencies
    pip install python-telegram-bot==20.3 python-dotenv pillow qrcode cryptography
    
    # Get bot token
    echo ""
    echo -e "${YELLOW}=== Telegram Bot Configuration ===${NC}"
    read -p "Enter Bot Token from @BotFather: " BOT_TOKEN
    
    # Create bot files
    create_bot_files
    create_systemd_service
    
    # Initialize database
    cd /opt/zivpn-bot
    source venv/bin/activate
    python3 -c "
from database import Database
db = Database('zivpn.db')
print('Database initialized successfully')
"
    
    # Start bot service
    systemctl daemon-reload
    systemctl enable zivpn-bot.service
    systemctl start zivpn-bot.service
    
    # Check bot status
    sleep 2
    if systemctl is-active --quiet zivpn-bot.service; then
        print_success "Telegram Bot installed and running!"
    else
        print_error "Bot service failed to start. Checking logs..."
        journalctl -u zivpn-bot.service -n 20 --no-pager
    fi
    
    echo -e "${YELLOW}Bot configuration saved to: /opt/zivpn-bot/.env${NC}"
}

# Function to create bot files
create_bot_files() {
    # Use hostname if provided, otherwise use IP
    if [ -n "$SERVER_HOSTNAME" ]; then
        SERVER_ADDRESS="$SERVER_HOSTNAME"
    else
        SERVER_ADDRESS="$SERVER_IP"
    fi
    
    # Create config.py
    cat << 'EOF' > /opt/zivpn-bot/config.py
import os
import json
from dotenv import load_dotenv

load_dotenv()

class Config:
    BOT_TOKEN = os.getenv("BOT_TOKEN", "")
    ADMIN_IDS = [int(id.strip()) for id in os.getenv("ADMIN_IDS", "").split(",") if id.strip()]
    ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")
    DB_NAME = "zivpn.db"
    SERVER_ADDRESS = os.getenv("SERVER_ADDRESS", "your-server.com")
    SERVER_PORT = os.getenv("SERVER_PORT", "5667")
    
    # Payment Configuration
    BANK_ACCOUNT = os.getenv("BANK_ACCOUNT", "1234567890")
    BANK_NAME = os.getenv("BANK_NAME", "Bank Name")
    ACCOUNT_NAME = os.getenv("ACCOUNT_NAME", "Account Name")
    QR_IMAGE_URL = os.getenv("QR_IMAGE_URL", "")
    
    VPN_CONFIG_PATH = "/etc/zivpn/config.json"
    MAX_DEVICES = 1
    CURRENCY = "THB"
    
    # Admin unlimited credit feature
    @staticmethod
    def is_admin(user_id):
        return user_id in Config.ADMIN_IDS
    
    @staticmethod
    def get_admin_unlimited_credit():
        return 999999  # Unlimited credit for admin
EOF

    # Create database.py with improved payment system
    cat << 'EOF' > /opt/zivpn-bot/database.py
import sqlite3
import json
from datetime import datetime, timedelta
import hashlib
from config import Config

class Database:
    def __init__(self, db_name="zivpn.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                credit INTEGER DEFAULT 0,
                join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0
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
                is_active BOOLEAN DEFAULT 1,
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
            cursor.execute('INSERT OR IGNORE INTO users (user_id, username, is_admin) VALUES (?, ?, ?)', (user_id, username, is_admin))
            self.conn.commit()
            return True
        except:
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
        result = cursor.fetchone()
        return result[0] if result else 0
    
    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        
        # Check if account already exists
        cursor.execute('SELECT id, is_active FROM accounts WHERE vpn_username = ? AND vpn_password = ?', (username, password))
        existing = cursor.fetchone()
        
        if existing:
            account_id, is_active = existing
            if is_active:
                return False, "This account is already active. Please use renew instead."
            else:
                # Reactivate expired account
                expire_date = datetime.now() + timedelta(days=days)
                cursor.execute('UPDATE accounts SET is_active = 1, expire_date = ? WHERE id = ?', (expire_date, account_id))
                self.update_vpn_config(password)
                self.conn.commit()
                return True, "Account reactivated successfully"
        
        expire_date = datetime.now() + timedelta(days=days)
        
        try:
            cursor.execute('''
                INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, password, expire_date))
            
            # Update VPN config
            self.update_vpn_config(password)
            
            self.conn.commit()
            return True, "Account created successfully"
        except Exception as e:
            return False, str(e)
    
    def update_vpn_config(self, password):
        """Update VPN config file with new password"""
        try:
            with open(Config.VPN_CONFIG_PATH, 'r') as f:
                config = json.load(f)
            
            # Ensure auth.config exists
            if 'auth' not in config:
                config['auth'] = {"mode": "passwords", "config": []}
            if 'config' not in config['auth']:
                config['auth']['config'] = []
            
            # Add password if not exists
            if password not in config['auth']['config']:
                config['auth']['config'].append(password)
                
                with open(Config.VPN_CONFIG_PATH, 'w') as f:
                    json.dump(config, f, indent=2)
                
                # Restart VPN service
                import subprocess
                result = subprocess.run(['systemctl', 'restart', 'zivpn.service'], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"Warning: Failed to restart VPN service: {result.stderr}")
        except Exception as e:
            print(f"Error updating VPN config: {e}")
    
    def get_user_accounts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, vpn_username, vpn_password, expire_date, is_active 
            FROM accounts WHERE user_id = ? ORDER BY is_active DESC, expire_date DESC
        ''', (user_id,))
        return cursor.fetchall()
    
    def get_account_by_password(self, user_id, password):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, vpn_username, expire_date, is_active 
            FROM accounts WHERE user_id = ? AND vpn_password = ? AND is_active = 1
        ''', (user_id, password))
        return cursor.fetchone()
    
    def renew_account(self, account_id, days):
        cursor = self.conn.cursor()
        
        # Get current expiry
        cursor.execute('SELECT expire_date FROM accounts WHERE id = ?', (account_id,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Account not found"
        
        old_expire = datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S') if isinstance(result[0], str) else result[0]
        now = datetime.now()
        
        # Check if account is still active
        if old_expire > now:
            # Account is still active, extend from current expiry
            new_expire = old_expire + timedelta(days=days)
        else:
            # Account has expired, renew from now
            new_expire = now + timedelta(days=days)
        
        # Update account
        cursor.execute('UPDATE accounts SET expire_date = ?, is_active = 1 WHERE id = ?', (new_expire, account_id))
        
        # Add to renew history
        cursor.execute('''
            INSERT INTO renew_history (account_id, user_id, old_expire_date, new_expire_date, days_added)
            VALUES (?, ?, ?, ?, ?)
        ''', (account_id, self.get_account_user(account_id), old_expire, new_expire, days))
        
        self.conn.commit()
        return True, new_expire
    
    def get_account_user(self, account_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id FROM accounts WHERE id = ?', (account_id,))
        result = cursor.fetchone()
        return result[0] if result else None
    
    def create_payment(self, user_id, amount, screenshot=None):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO payments (user_id, amount, screenshot, status)
            VALUES (?, ?, ?, 'pending')
        ''', (user_id, amount, screenshot))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_pending_payments(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT p.*, u.username 
            FROM payments p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.status = 'pending'
            ORDER BY p.created_date ASC
        ''')
        return cursor.fetchall()
    
    def approve_payment(self, payment_id, admin_id):
        cursor = self.conn.cursor()
        
        # Get payment details
        cursor.execute('SELECT user_id, amount FROM payments WHERE id = ? AND status = ?', (payment_id, 'pending'))
        payment = cursor.fetchone()
        
        if payment:
            user_id, amount = payment
            
            # Update payment status
            cursor.execute('''
                UPDATE payments 
                SET status = 'approved', 
                    admin_id = ?,
                    approved_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, payment_id))
            
            # Add credit to user
            cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
            
            self.conn.commit()
            return True, amount, user_id
        return False, 0, None
    
    def reject_payment(self, payment_id, admin_id, note=""):
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE payments 
            SET status = 'rejected', 
                admin_id = ?,
                admin_note = ?
            WHERE id = ? AND status = 'pending'
        ''', (admin_id, note, payment_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def get_all_users(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT u.user_id, u.username, u.credit, 
                   COUNT(a.id) as account_count,
                   u.join_date, u.is_admin
            FROM users u
            LEFT JOIN accounts a ON u.user_id = a.user_id
            GROUP BY u.user_id
            ORDER BY u.join_date DESC
        ''')
        return cursor.fetchall()
    
    def get_total_users(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users')
        return cursor.fetchone()[0]
    
    def get_active_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM accounts WHERE is_active = 1')
        return cursor.fetchone()[0]
    
    def get_all_accounts(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT a.id, a.vpn_username, a.vpn_password, a.expire_date, a.is_active,
                   u.user_id, u.username
            FROM accounts a
            JOIN users u ON a.user_id = u.user_id
            ORDER BY a.expire_date DESC
        ''')
        return cursor.fetchall()
    
    def get_payment_stats(self):
        cursor = self.conn.cursor()
        cursor.execute('SELECT status, COUNT(*), SUM(amount) FROM payments GROUP BY status')
        return cursor.fetchall()
EOF

    # Create bot.py with complete payment system
    cat << 'EOF' > /opt/zivpn-bot/bot.py
import logging
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)
import qrcode
from io import BytesIO
from datetime import datetime, timedelta
import json

from config import Config
from database import Database

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
TOPUP_AMOUNT, PAYMENT_PROOF = range(2)
CREATE_USERNAME, CREATE_PASSWORD, SELECT_PLAN = range(2, 5)
RENEW_PASSWORD, RENEW_SELECT_PLAN = range(5, 7)
ADMIN_PANEL, ADMIN_ACTION = range(7, 9)

class ZivpnBot:
    def __init__(self):
        self.db = Database(Config.DB_NAME)
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        # Start command handler
        self.application.add_handler(CommandHandler("start", self.start_command))
        
        # Main menu button handlers
        self.application.add_handler(CallbackQueryHandler(self.topup_start, pattern='^topup$'))
        self.application.add_handler(CallbackQueryHandler(self.create_account_start, pattern='^create_account$'))
        self.application.add_handler(CallbackQueryHandler(self.renew_account_start, pattern='^renew_account$'))
        self.application.add_handler(CallbackQueryHandler(self.check_credit, pattern='^check_credit$'))
        self.application.add_handler(CallbackQueryHandler(self.my_accounts, pattern='^my_accounts$'))
        self.application.add_handler(CallbackQueryHandler(self.admin_panel, pattern='^admin_panel$'))
        self.application.add_handler(CallbackQueryHandler(self.back_to_menu, pattern='^back$'))
        
        # Payment proof upload handler
        self.application.add_handler(CallbackQueryHandler(self.upload_payment_proof, pattern='^upload_proof$'))
        
        # Conversation handlers
        topup_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.topup_amount, pattern='^topup_amount$')],
            states={
                TOPUP_AMOUNT: [CallbackQueryHandler(self.select_amount, pattern='^amount_')],
                PAYMENT_PROOF: [MessageHandler(filters.PHOTO, self.receive_payment_proof)]
            },
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )
        
        create_account_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.create_account_input, pattern='^create_account_input$')],
            states={
                CREATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_username)],
                CREATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_password)],
                SELECT_PLAN: [CallbackQueryHandler(self.select_plan, pattern='^plan_')]
            },
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )
        
        renew_account_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.renew_account_input, pattern='^renew_account_input$')],
            states={
                RENEW_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_renew_password)],
                RENEW_SELECT_PLAN: [CallbackQueryHandler(self.select_renew_plan, pattern='^renew_plan_')]
            },
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )
        
        admin_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.admin_menu, pattern='^admin_menu$')],
            states={
                ADMIN_PANEL: [CallbackQueryHandler(self.admin_action, pattern='^admin_')],
                ADMIN_ACTION: [CallbackQueryHandler(self.handle_admin_action, pattern='^action_')]
            },
            fallbacks=[CallbackQueryHandler(self.cancel, pattern='^cancel$')]
        )
        
        self.application.add_handler(topup_conv)
        self.application.add_handler(create_account_conv)
        self.application.add_handler(renew_account_conv)
        self.application.add_handler(admin_conv)
        
        # Cancel handler
        self.application.add_handler(CallbackQueryHandler(self.cancel_handler, pattern='^cancel$'))
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        user_id = user.id
        
        # Clear any existing conversation state
        if context.user_data:
            context.user_data.clear()
        
        is_admin = Config.is_admin(user_id)
        self.db.create_user(user_id, user.username or user.first_name, is_admin)
        
        await self.show_main_menu(update, context, user_id, is_admin)
    
    async def show_main_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, is_admin: bool):
        """Show main menu with buttons"""
        keyboard = [
            [InlineKeyboardButton("💳 Top-up Credit", callback_data='topup_amount')],
            [InlineKeyboardButton("🆕 Create Account", callback_data='create_account_input')],
            [InlineKeyboardButton("🔄 Renew Account", callback_data='renew_account_input')],
            [InlineKeyboardButton("💰 Check Credit", callback_data='check_credit')],
            [InlineKeyboardButton("👤 My Accounts", callback_data='my_accounts')],
        ]
        
        if is_admin:
            keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data='admin_menu')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        credit = self.db.get_credit(user_id)
        if is_admin:
            credit_display = "∞ (Admin)"
        else:
            credit_display = f"{credit} {Config.CURRENCY}"
        
        welcome_text = f"""
🌟 Welcome to ZIVPN VPN Service! 🌟

📊 Your Credit: {credit_display}
🌐 Server: {Config.SERVER_ADDRESS}
🔌 Port: {Config.SERVER_PORT}
💵 Currency: {Config.CURRENCY}

Choose an option:
"""
        
        if update.callback_query:
            query = update.callback_query
            await query.answer()
            await query.edit_message_text(welcome_text, reply_markup=reply_markup)
        else:
            await update.message.reply_text(welcome_text, reply_markup=reply_markup)
    
    async def back_to_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user = update.effective_user
        user_id = user.id
        is_admin = Config.is_admin(user_id)
        
        await self.show_main_menu(update, context, user_id, is_admin)
    
    async def topup_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        keyboard = [
            [
                InlineKeyboardButton("50 THB", callback_data='amount_50'),
                InlineKeyboardButton("100 THB", callback_data='amount_100'),
                InlineKeyboardButton("150 THB", callback_data='amount_150')
            ],
            [
                InlineKeyboardButton("200 THB", callback_data='amount_200'),
                InlineKeyboardButton("300 THB", callback_data='amount_300'),
                InlineKeyboardButton("500 THB", callback_data='amount_500')
            ],
            [InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text("Select top-up amount:", reply_markup=reply_markup)
        return TOPUP_AMOUNT
    
    async def topup_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        return await self.topup_start(update, context)
    
    async def select_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        amount = int(query.data.split('_')[1])
        context.user_data['topup_amount'] = amount
        
        # If QR image URL is provided, use it
        if Config.QR_IMAGE_URL and Config.QR_IMAGE_URL.startswith('http'):
            try:
                await query.message.reply_photo(
                    photo=Config.QR_IMAGE_URL,
                    caption=f"Scan QR code to pay {amount} {Config.CURRENCY}"
                )
            except:
                # Fallback to generated QR
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                bio = BytesIO()
                img.save(bio, 'PNG')
                bio.seek(0)
                await query.message.reply_photo(photo=bio)
        else:
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            bio = BytesIO()
            img.save(bio, 'PNG')
            bio.seek(0)
            await query.message.reply_photo(photo=bio)
        
        payment_info = f"""
💰 Payment Information:

🏦 Bank: {Config.BANK_NAME}
📞 Account: {Config.BANK_ACCOUNT}
👤 Name: {Config.ACCOUNT_NAME}
💵 Amount: {amount} {Config.CURRENCY}

Please transfer the exact amount and upload screenshot as proof.
"""
        
        await query.message.reply_text(payment_info)
        
        keyboard = [
            [InlineKeyboardButton("📸 Upload Payment Proof", callback_data='upload_proof')],
            [InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.message.reply_text(
            "After payment, click the button below to upload screenshot:",
            reply_markup=reply_markup
        )
        
        return PAYMENT_PROOF
    
    async def upload_payment_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle upload payment proof button click"""
        query = update.callback_query
        await query.answer()
        
        await query.message.reply_text("📸 Please send the payment screenshot now:")
        return PAYMENT_PROOF
    
    async def receive_payment_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        amount = context.user_data.get('topup_amount', 0)
        
        # Check if user is admin (admins don't need to pay)
        if Config.is_admin(user_id):
            await update.message.reply_text(
                "✅ You are an admin! Credit has been added automatically."
            )
            
            # Add credit for admin (though they already have unlimited)
            self.db.update_credit(user_id, amount)
            
            # Notify
            await update.message.reply_text(
                f"Added {amount} {Config.CURRENCY} to your account."
            )
            
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await update.message.reply_text("Return to menu:", reply_markup=reply_markup)
            return ConversationHandler.END
        
        # Get the photo
        photo = update.message.photo[-1]
        file_id = photo.file_id
        
        # Save payment record
        payment_id = self.db.create_payment(user_id, amount, file_id)
        
        await update.message.reply_text(
            f"✅ Payment proof received!\n"
            f"Amount: {amount} {Config.CURRENCY}\n"
            f"Payment ID: #{payment_id}\n\n"
            f"Please wait for admin approval."
        )
        
        # Notify all admins
        for admin_id in Config.ADMIN_IDS:
            try:
                await self.application.bot.send_message(
                    admin_id,
                    f"📥 New Payment Request!\n"
                    f"User: @{update.effective_user.username or user_id}\n"
                    f"Amount: {amount} {Config.CURRENCY}\n"
                    f"Payment ID: #{payment_id}\n"
                    f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Return to menu:", reply_markup=reply_markup)
        return ConversationHandler.END
    
    async def my_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user's accounts"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        accounts = self.db.get_user_accounts(user_id)
        
        if not accounts:
            await query.edit_message_text("You don't have any accounts yet.")
            return
        
        text = "📋 Your Accounts:\n\n"
        for account in accounts:
            account_id, username, password, expire_date, is_active = account
            status = "✅ Active" if is_active else "❌ Expired"
            text += f"👤 Username: `{username}`\n"
            text += f"🔑 Password: `{password}`\n"
            text += f"📅 Expire: {expire_date}\n"
            text += f"📊 Status: {status}\n"
            text += "─" * 20 + "\n"
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(text, parse_mode='Markdown', reply_markup=reply_markup)
    
    async def create_account_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if not Config.is_admin(user_id) and credit < 50:
            await query.edit_message_text(
                f"❌ Insufficient credit!\n"
                f"Your credit: {credit} {Config.CURRENCY}\n"
                f"Minimum required: 50 {Config.CURRENCY}"
            )
            
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
            return ConversationHandler.END
        
        await query.edit_message_text(
            "Please enter your desired VPN username:"
        )
        
        return CREATE_USERNAME
    
    async def create_account_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        return await self.create_account_start(update, context)
    
    async def get_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        username = update.message.text.strip()
        
        if len(username) < 3:
            await update.message.reply_text("Username must be at least 3 characters. Please try again:")
            return CREATE_USERNAME
        
        context.user_data['vpn_username'] = username
        
        await update.message.reply_text(
            "Now enter your desired VPN password (min 4 characters):"
        )
        
        return CREATE_PASSWORD
    
    async def get_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        
        if len(password) < 4:
            await update.message.reply_text("Password must be at least 4 characters. Please try again:")
            return CREATE_PASSWORD
        
        context.user_data['vpn_password'] = password
        
        user_id = update.effective_user.id
        
        # For admin, show all plans
        if Config.is_admin(user_id):
            keyboard = [
                [InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')],
                [InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')],
                [InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')],
                [InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]
            ]
        else:
            credit = self.db.get_credit(user_id)
            keyboard = []
            
            if credit >= 50:
                keyboard.append([InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')])
            
            if credit >= 100:
                keyboard.append([InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')])
            
            if credit >= 150:
                keyboard.append([InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')])
            
            keyboard.append([InlineKeyboardButton("🔙 Back to Menu", callback_data='back')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "Select subscription plan:",
            reply_markup=reply_markup
        )
        
        return SELECT_PLAN
    
    async def select_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        days = int(query.data.split('_')[1])
        cost = days * 50 // 30  # 50 THB for 30 days
        
        user_id = update.effective_user.id
        username = context.user_data.get('vpn_username')
        password = context.user_data.get('vpn_password')
        
        # For non-admin users, check credit
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                
                keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
                return ConversationHandler.END
        
        # Create account
        success, message = self.db.create_account(user_id, username, password, days)
        
        if success:
            # Deduct credit (not for admin)
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            
            # Get account details
            expire_date = datetime.now() + timedelta(days=days)
            
            account_info = f"""
✅ Account Created Successfully!

🔧 **Server Details:**
🌐 Server: `{Config.SERVER_ADDRESS}`
🔌 Port: `{Config.SERVER_PORT}`
👤 Username: `{username}`
🔑 Password: `{password}`
📅 Expire Date: {expire_date.strftime('%Y-%m-%d')}
🔒 Max Devices: 1

⚠️ Note: Only first device can connect.
"""
            await query.edit_message_text(account_info, parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ Error: {message}")
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
        return ConversationHandler.END
    
    async def renew_account_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if not Config.is_admin(user_id) and credit < 50:
            await query.edit_message_text(
                f"❌ Insufficient credit!\n"
                f"Your credit: {credit} {Config.CURRENCY}\n"
                f"Minimum required: 50 {Config.CURRENCY}"
            )
            
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
            return ConversationHandler.END
        
        await query.edit_message_text(
            "Please enter your existing VPN password to renew:"
        )
        
        return RENEW_PASSWORD
    
    async def renew_account_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        return await self.renew_account_start(update, context)
    
    async def get_renew_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        user_id = update.effective_user.id
        
        # Check if account exists and belongs to user
        account = self.db.get_account_by_password(user_id, password)
        
        if not account:
            await update.message.reply_text("❌ Account not found or doesn't belong to you. Please try again:")
            return RENEW_PASSWORD
        
        account_id, username, expire_date, is_active = account
        
        # Check if account is active
        if not is_active:
            await update.message.reply_text("❌ This account is not active. Please use create account instead.")
            return ConversationHandler.END
        
        context.user_data['renew_account_id'] = account_id
        context.user_data['renew_password'] = password
        
        # Show plan options
        if Config.is_admin(user_id):
            keyboard = [
                [InlineKeyboardButton("30 Days - 50 THB", callback_data='renew_plan_30')],
                [InlineKeyboardButton("60 Days - 100 THB", callback_data='renew_plan_60')],
                [InlineKeyboardButton("90 Days - 150 THB", callback_data='renew_plan_90')],
                [InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]
            ]
        else:
            credit = self.db.get_credit(user_id)
            keyboard = []
            
            if credit >= 50:
                keyboard.append([InlineKeyboardButton("30 Days - 50 THB", callback_data='renew_plan_30')])
            
            if credit >= 100:
                keyboard.append([InlineKeyboardButton("60 Days - 100 THB", callback_data='renew_plan_60')])
            
            if credit >= 150:
                keyboard.append([InlineKeyboardButton("90 Days - 150 THB", callback_data='renew_plan_90')])
            
            keyboard.append([InlineKeyboardButton("🔙 Back to Menu", callback_data='back')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            f"Account found: {username}\nCurrent expiry: {expire_date}\n\nSelect renewal plan:",
            reply_markup=reply_markup
        )
        
        return RENEW_SELECT_PLAN
    
    async def select_renew_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        days = int(query.data.split('_')[2])
        cost = days * 50 // 30  # 50 THB for 30 days
        
        user_id = update.effective_user.id
        account_id = context.user_data.get('renew_account_id')
        password = context.user_data.get('renew_password')
        
        # For non-admin users, check credit
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                
                keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
                return ConversationHandler.END
        
        # Renew account
        success, new_expire = self.db.renew_account(account_id, days)
        
        if success:
            # Deduct credit (not for admin)
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            
            account_info = f"""
✅ Account Renewed Successfully!

🔧 **Server Details:**
🌐 Server: `{Config.SERVER_ADDRESS}`
🔌 Port: `{Config.SERVER_PORT}`
🔑 Password: `{password}`
📅 New Expire Date: {new_expire.strftime('%Y-%m-%d')}
🔄 Days Added: {days}

⚠️ Your account has been extended.
"""
            await query.edit_message_text(account_info, parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ Error renewing account")
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
        return ConversationHandler.END
    
    async def check_credit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        
        if Config.is_admin(user_id):
            credit_display = "∞ (Admin)"
        else:
            credit = self.db.get_credit(user_id)
            credit_display = f"{credit} {Config.CURRENCY}"
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(f"💰 Your Credit: {credit_display}", reply_markup=reply_markup)
    
    async def admin_panel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        
        if not Config.is_admin(user_id):
            await query.edit_message_text("❌ Access denied!")
            
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.message.reply_text("Return to menu:", reply_markup=reply_markup)
            return ConversationHandler.END
        
        keyboard = [
            [InlineKeyboardButton("👥 User List", callback_data='admin_users')],
            [InlineKeyboardButton("📊 Payment Requests", callback_data='admin_payments')],
            [InlineKeyboardButton("🔐 All Access List", callback_data='admin_access_list')],
            [InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],
            [InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "👑 Admin Panel (Unlimited Credit Enabled)\n\nSelect an option:",
            reply_markup=reply_markup
        )
        
        return ADMIN_PANEL
    
    async def admin_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        return await self.admin_panel(update, context)
    
    async def admin_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        action = query.data
        
        if action == 'admin_users':
            users = self.db.get_all_users()
            
            if not users:
                text = "No users found."
            else:
                text = "👥 User List:\n\n"
                for user in users:
                    is_admin = "👑" if user[5] else "👤"
                    credit = "∞" if Config.is_admin(user[0]) else f"{user[2]} {Config.CURRENCY}"
                    
                    text += f"{is_admin} ID: {user[0]}\n"
                    text += f"Username: {user[1] or 'N/A'}\n"
                    text += f"Credit: {credit}\n"
                    text += f"Accounts: {user[3]}\n"
                    text += f"Joined: {user[4]}\n"
                    text += "─" * 20 + "\n"
            
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text[:4000], reply_markup=reply_markup)
            
        elif action == 'admin_payments':
            payments = self.db.get_pending_payments()
            
            if not payments:
                text = "No pending payments."
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup)
            else:
                text = "📊 Pending Payments:\n\n"
                keyboard = []
                
                for payment in payments:
                    payment_id, user_id, amount, screenshot, status, admin_id, note, created_date, approved_date, username = payment
                    
                    text += f"🆔 Payment ID: #{payment_id}\n"
                    text += f"👤 User: @{username or 'N/A'} ({user_id})\n"
                    text += f"💰 Amount: {amount} {Config.CURRENCY}\n"
                    text += f"📅 Date: {created_date}\n"
                    
                    # Create approve and reject buttons
                    approve_callback = f"action_approve_{payment_id}"
                    reject_callback = f"action_reject_{payment_id}"
                    
                    keyboard.append([
                        InlineKeyboardButton(f"✅ Approve #{payment_id}", callback_data=approve_callback),
                        InlineKeyboardButton(f"❌ Reject #{payment_id}", callback_data=reject_callback)
                    ])
                    
                    text += "─" * 20 + "\n"
                
                keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='admin_menu')])
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text[:4000], reply_markup=reply_markup)
                return ADMIN_ACTION
            
        elif action == 'admin_access_list':
            accounts = self.db.get_all_accounts()
            
            if not accounts:
                text = "No accounts found."
            else:
                text = "🔐 All Access List:\n\n"
                for account in accounts:
                    account_id, vpn_user, vpn_pass, expire_date, is_active, user_id, username = account
                    status = "✅" if is_active else "❌"
                    
                    text += f"ID: {account_id}\n"
                    text += f"User: @{username or user_id} ({user_id})\n"
                    text += f"VPN User: `{vpn_user}`\n"
                    text += f"VPN Pass: `{vpn_pass}`\n"
                    text += f"Expire: {expire_date}\n"
                    text += f"Status: {status}\n"
                    text += "─" * 20 + "\n"
            
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text[:4000], parse_mode='Markdown', reply_markup=reply_markup)
            
        elif action == 'admin_stats':
            total_users = self.db.get_total_users()
            active_accounts = self.db.get_active_accounts()
            all_accounts = self.db.get_all_accounts()
            payment_stats = self.db.get_payment_stats()
            
            # Calculate payment statistics
            total_pending = 0
            total_approved = 0
            total_rejected = 0
            
            for stat in payment_stats:
                status, count, amount = stat
                if status == 'pending':
                    total_pending = count
                elif status == 'approved':
                    total_approved = count
                    total_approved_amount = amount or 0
                elif status == 'rejected':
                    total_rejected = count
            
            text = f"""
📈 System Statistics:

👥 Total Users: {total_users}
🔧 Active Accounts: {active_accounts}
🔐 Total Accounts: {len(all_accounts) if all_accounts else 0}

💳 Payment Statistics:
⏳ Pending: {total_pending}
✅ Approved: {total_approved} (Total: {total_approved_amount or 0} {Config.CURRENCY})
❌ Rejected: {total_rejected}

👑 Admin Users: {len(Config.ADMIN_IDS)}
🌐 Server: {Config.SERVER_ADDRESS}
🔌 VPN Port: {Config.SERVER_PORT}
💵 Currency: {Config.CURRENCY}
"""
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_menu')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text, reply_markup=reply_markup)
        
        return ADMIN_PANEL
    
    async def handle_admin_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        admin_id = update.effective_user.id
        admin_name = update.effective_user.username or update.effective_user.first_name
        
        if query.data.startswith('action_approve_'):
            payment_id = int(query.data.split('_')[2])
            
            # Approve payment
            success, amount, user_id = self.db.approve_payment(payment_id, admin_id)
            
            if success:
                # Notify user
                try:
                    await self.application.bot.send_message(
                        user_id,
                        f"✅ Payment Approved!\n"
                        f"Payment ID: #{payment_id}\n"
                        f"Amount: {amount} {Config.CURRENCY}\n"
                        f"Approved by: @{admin_name}\n"
                        f"Your credit has been updated."
                    )
                except Exception as e:
                    logger.error(f"Failed to notify user {user_id}: {e}")
                
                await query.edit_message_text(f"✅ Payment #{payment_id} approved! User notified.")
            else:
                await query.edit_message_text(f"❌ Failed to approve payment #{payment_id}")
        
        elif query.data.startswith('action_reject_'):
            payment_id = int(query.data.split('_')[2])
            
            # Ask for rejection reason
            context.user_data['reject_payment_id'] = payment_id
            context.user_data['reject_admin_id'] = admin_id
            
            await query.message.reply_text(
                f"Please enter reason for rejecting payment #{payment_id}:"
            )
            return ADMIN_ACTION
        
        # Handle rejection with reason
        if 'reject_payment_id' in context.user_data and update.message:
            payment_id = context.user_data['reject_payment_id']
            admin_id = context.user_data['reject_admin_id']
            reason = update.message.text
            
            # Reject payment
            success = self.db.reject_payment(payment_id, admin_id, reason)
            
            if success:
                # Get user_id from payment
                cursor = self.db.conn.cursor()
                cursor.execute('SELECT user_id FROM payments WHERE id = ?', (payment_id,))
                result = cursor.fetchone()
                
                if result:
                    user_id = result[0]
                    # Notify user
                    try:
                        await self.application.bot.send_message(
                            user_id,
                            f"❌ Payment Rejected\n"
                            f"Payment ID: #{payment_id}\n"
                            f"Reason: {reason}\n"
                            f"Please contact admin for more information."
                        )
                    except Exception as e:
                        logger.error(f"Failed to notify user {user_id}: {e}")
                
                await update.message.reply_text(f"✅ Payment #{payment_id} rejected with reason.")
            else:
                await update.message.reply_text(f"❌ Failed to reject payment #{payment_id}")
            
            # Clean up
            context.user_data.pop('reject_payment_id', None)
            context.user_data.pop('reject_admin_id', None)
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Admin Panel", callback_data='admin_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        if update.callback_query:
            await query.message.reply_text("Return to admin panel:", reply_markup=reply_markup)
        else:
            await update.message.reply_text("Return to admin panel:", reply_markup=reply_markup)
        
        return ConversationHandler.END
    
    async def cancel_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user = update.effective_user
        user_id = user.id
        is_admin = Config.is_admin(user_id)
        
        await self.show_main_menu(update, context, user_id, is_admin)
        return ConversationHandler.END
    
    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        user = update.effective_user
        user_id = user.id
        is_admin = Config.is_admin(user_id)
        
        await self.show_main_menu(update, context, user_id, is_admin)
        return ConversationHandler.END
    
    def run(self):
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == '__main__':
    bot = ZivpnBot()
    bot.run()
EOF

    # Create requirements.txt
    cat << 'EOF' > /opt/zivpn-bot/requirements.txt
python-telegram-bot==20.3
python-dotenv==1.0.0
Pillow==10.0.0
qrcode==7.4.2
cryptography==41.0.5
EOF

    # Create .env file with all configurations
    cat > /opt/zivpn-bot/.env << EOF
# Bot Configuration
BOT_TOKEN=$BOT_TOKEN
ADMIN_IDS=$ADMIN_IDS
ADMIN_TOKEN=$ADMIN_TOKEN

# Server Configuration
SERVER_ADDRESS=$SERVER_ADDRESS
SERVER_PORT=5667

# Payment Configuration
BANK_ACCOUNT=$BANK_ACCOUNT
BANK_NAME=$BANK_NAME
ACCOUNT_NAME=$ACCOUNT_NAME
QR_IMAGE_URL=$QR_IMAGE_URL

# System Configuration
CURRENCY=THB
EOF
}

# Function to create systemd service for bot
create_systemd_service() {
    cat > /etc/systemd/system/zivpn-bot.service << EOF
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

# Main installation function
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
    
    # Cleanup
    rm -f zi.* 2>/dev/null
    
    echo -e "\n${GREEN}=========================================${NC}"
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    
    echo -e "\n${YELLOW}=== Installation Summary ===${NC}"
    echo -e "Zivpn UDP VPN: ${GREEN}Installed${NC}"
    echo -e "Server Address: ${GREEN}${SERVER_HOSTNAME:-$SERVER_IP}${NC}"
    echo -e "VPN Passwords: ${GREEN}${VPN_PASSWORDS[*]}${NC}"
    echo -e "Admin Token: ${GREEN}$ADMIN_TOKEN${NC}"
    echo -e "Admin IDs: ${GREEN}$ADMIN_IDS${NC}"
    echo -e "Telegram Bot: $( [[ "$install_bot_choice" =~ ^[Yy]$ ]] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Skipped${NC}" )"
    
    echo -e "\n${YELLOW}=== Service Status ===${NC}"
    systemctl status zivpn.service --no-pager
    
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo ""
        systemctl status zivpn-bot.service --no-pager
    fi
    
    echo -e "\n${YELLOW}=== Bot Features ===${NC}"
    echo -e "💳 Top-up Credit Button (with ✅❌ buttons)"
    echo -e "🆕 Create Account Button" 
    echo -e "🔄 Renew Account Button"
    echo -e "👤 My Accounts Button"
    echo -e "💰 Check Credit Button"
    echo -e "👑 Admin Panel with Payment Approve/Reject"
    echo -e "🔐 All Access List"
    echo -e "📈 Statistics"
    echo -e "🏦 Bank: $BANK_NAME"
    echo -e "💳 Account: $BANK_ACCOUNT"
    echo -e "👤 Account Name: $ACCOUNT_NAME"
    
    if [ -n "$QR_IMAGE_URL" ]; then
        echo -e "📷 QR Code: Enabled"
    fi
    
    echo -e "\n${GREEN}=== Important Notes ===${NC}"
    echo -e "1. VPN Config: /etc/zivpn/config.json"
    echo -e "2. Bot Directory: /opt/zivpn-bot"
    echo -e "3. Bot Config: /opt/zivpn-bot/.env"
    echo -e "4. Database: /opt/zivpn-bot/zivpn.db"
    
    # Troubleshooting guide
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo -e "\n${YELLOW}=== If Bot Doesn't Work ===${NC}"
        echo -e "1. Check bot status: systemctl status zivpn-bot.service"
        echo -e "2. View bot logs: journalctl -u zivpn-bot.service -f"
        echo -e "3. Check bot token: nano /opt/zivpn-bot/.env"
        echo -e "4. Restart bot: systemctl restart zivpn-bot.service"
        echo -e "5. Test VPN: Use password '${VPN_PASSWORDS[0]}' to connect"
    fi
    
    echo -e "\n${GREEN}=== Testing VPN Connection ===${NC}"
    echo -e "Server: ${SERVER_HOSTNAME:-$SERVER_IP}:5667"
    echo -e "Password: ${VPN_PASSWORDS[0]}"
    echo -e "Use any UDP client to connect"
}

# Run installation
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

main_installation
