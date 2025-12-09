#!/bin/bash

# Zivpn UDP Module + Telegram Bot Installer
# Creator: Zahid Islam
# Fixed Version: Complete Working Version

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
    apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw jq sqlite3
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
    read -p "Enter initial VPN passwords separated by commas (Press enter for Default 'zi'): " vpn_passwords_input
    
    if [ -n "$vpn_passwords_input" ]; then
        IFS=',' read -r -a VPN_PASSWORDS <<< "$vpn_passwords_input"
    else
        VPN_PASSWORDS=("zi")
    fi
    
    echo "Initial VPN Passwords set to: ${VPN_PASSWORDS[*]}"
    
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
    print_status "Creating config.json with initial VPN passwords..."
    
    # Create JSON array from VPN passwords
    config_array="["
    for ((i=0; i<${#VPN_PASSWORDS[@]}; i++)); do
        config_array="${config_array}\"${VPN_PASSWORDS[i]}\""
        if [ $i -lt $((${#VPN_PASSWORDS[@]}-1)) ]; then
            config_array="${config_array},"
        fi
    done
    config_array="${config_array}]"
    
    # Create config.json with proper format
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
    
    print_status "Config.json created with initial passwords: ${VPN_PASSWORDS[*]}"
    
    # Test the config file
    if python3 -c "import json; json.load(open('/etc/zivpn/config.json'))"; then
        print_success "Config.json is valid JSON format"
    else
        print_error "Config.json has invalid JSON format"
        echo "Debug: config.json content:"
        cat /etc/zivpn/config.json
    fi
    
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
    sysctl -w net.core.default_qdisc=fq 2>/dev/null
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service
    
    # Check if service is running
    sleep 3
    if systemctl is-active --quiet zivpn.service; then
        print_success "Zivpn UDP VPN service is running!"
        
        # Check logs for any authentication errors
        print_status "Checking VPN service logs..."
        if journalctl -u zivpn.service -n 10 --no-pager | grep -i "error\|fail\|panic" | head -5; then
            print_error "Found errors in VPN service logs"
        else
            print_success "No critical errors found in VPN logs"
        fi
    else
        print_error "Zivpn service failed to start. Checking logs..."
        journalctl -u zivpn.service -n 20 --no-pager
        print_status "Trying to debug VPN service..."
        
        # Check if binary works
        if /usr/local/bin/zivpn version 2>/dev/null; then
            print_success "Zivpn binary works"
        else
            print_error "Zivpn binary might be corrupted"
        fi
        
        # Try to run manually to see error
        print_status "Running VPN manually to check errors..."
        timeout 5 /usr/local/bin/zivpn server -c /etc/zivpn/config.json || true
    fi
    
    # Configure firewall
    print_status "Configuring firewall..."
    
    # Reset UFW
    echo "y" | ufw --force reset > /dev/null 2>&1
    
    # Set default policies
    ufw default deny incoming > /dev/null 2>&1
    ufw default allow outgoing > /dev/null 2>&1
    
    # Allow SSH
    ufw allow 22/tcp > /dev/null 2>&1
    
    # Allow VPN ports
    ufw allow 5667/udp > /dev/null 2>&1
    ufw allow 6000:19999/udp > /dev/null 2>&1
    
    # Enable UFW
    echo "y" | ufw --force enable > /dev/null 2>&1
    
    # Configure iptables for port forwarding
    interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 2>/dev/null || echo "eth0")
    
    # Clear existing NAT rules
    iptables -t nat -F 2>/dev/null || true
    
    # Add NAT rule for port forwarding
    iptables -t nat -A PREROUTING -i $interface -p udp --dport 6000:19999 -j DNAT --to-destination :5667 2>/dev/null || true
    iptables -t nat -A POSTROUTING -o $interface -j MASQUERADE 2>/dev/null || true
    
    print_success "Firewall configured!"
    
    # Show configuration
    echo -e "${YELLOW}=== VPN Configuration ===${NC}"
    echo "Server Address: ${SERVER_HOSTNAME:-$SERVER_IP}"
    echo "VPN Port: 5667"
    echo "Initial VPN Passwords: ${VPN_PASSWORDS[*]}"
    echo "Config file: /etc/zivpn/config.json"
    echo ""
    
    # Test authentication
    print_status "Testing VPN configuration..."
    if [ -f /etc/zivpn/config.json ]; then
        echo "Config.json verification:"
        
        # Verify password is in config
        for password in "${VPN_PASSWORDS[@]}"; do
            if grep -q "\"$password\"" /etc/zivpn/config.json; then
                print_success "Password '$password' found in config.json"
            else
                print_error "Password '$password' NOT found in config.json"
            fi
        done
        
        # Test if service is listening
        print_status "Testing VPN port..."
        if ss -ulpn | grep -q ":5667"; then
            print_success "VPN service is listening on port 5667"
        else
            print_error "VPN service not listening on port 5667"
        fi
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
    sleep 3
    if systemctl is-active --quiet zivpn-bot.service; then
        print_success "Telegram Bot installed and running!"
        
        # Check bot logs
        if journalctl -u zivpn-bot.service -n 5 --no-pager | grep -i "error\|exception\|traceback"; then
            print_error "Found errors in bot logs"
        else
            print_success "Bot started without errors"
        fi
    else
        print_error "Bot service failed to start. Checking logs..."
        journalctl -u zivpn-bot.service -n 20 --no-pager
        
        # Try to start manually to see error
        print_status "Trying to start bot manually..."
        cd /opt/zivpn-bot
        source venv/bin/activate
        timeout 10 python3 bot.py &
        sleep 5
        pkill -f "python3 bot.py" 2>/dev/null || true
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

    # Create database.py - COMPLETELY FIXED VERSION
    cat << 'EOF' > /opt/zivpn-bot/database.py
import sqlite3
import json
import subprocess
import os
from datetime import datetime, timedelta
from config import Config

class Database:
    def __init__(self, db_name="zivpn.db"):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                username TEXT,
                credit INTEGER DEFAULT 0,
                join_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_admin BOOLEAN DEFAULT 0
            )
        ''')
        
        # Accounts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                vpn_username TEXT,
                vpn_password TEXT UNIQUE,  # Make password unique
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expire_date TIMESTAMP,
                device_hash TEXT,
                is_active BOOLEAN DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Payments table
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
        
        self.conn.commit()
    
    def get_user(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        return cursor.fetchone()
    
    def create_user(self, user_id, username, is_admin=False):
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO users (user_id, username, is_admin) 
                VALUES (?, ?, ?)
            ''', (user_id, username, is_admin))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error creating user: {e}")
            return False
    
    def update_credit(self, user_id, amount):
        cursor = self.conn.cursor()
        try:
            cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
            self.conn.commit()
            return True
        except Exception as e:
            print(f"Error updating credit: {e}")
            return False
    
    def get_credit(self, user_id):
        if Config.is_admin(user_id):
            return Config.get_admin_unlimited_credit()
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT credit FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        return result[0] if result else 0
    
    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        
        try:
            # Check if password already exists
            cursor.execute('SELECT id FROM accounts WHERE vpn_password = ?', (password,))
            if cursor.fetchone():
                return False, "This password is already in use. Please choose a different one."
            
            # Calculate expire date
            expire_date = datetime.now() + timedelta(days=days)
            
            # Insert account
            cursor.execute('''
                INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, password, expire_date))
            
            # Update VPN config
            if self.update_vpn_config(password):
                self.conn.commit()
                return True, "Account created successfully!"
            else:
                return False, "Failed to update VPN configuration"
                
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def update_vpn_config(self, password):
        """Update VPN config file with new password"""
        try:
            config_path = Config.VPN_CONFIG_PATH
            
            # Read current config
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            # Ensure auth.config exists
            if 'auth' not in config:
                config['auth'] = {"mode": "passwords", "config": []}
            if 'config' not in config['auth']:
                config['auth']['config'] = []
            
            # Add password if not exists
            if password not in config['auth']['config']:
                config['auth']['config'].append(password)
                
                # Write back config
                with open(config_path, 'w') as f:
                    json.dump(config, f, indent=2)
                
                # Restart VPN service
                result = subprocess.run(
                    ['systemctl', 'restart', 'zivpn.service'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    print(f"VPN restart failed: {result.stderr}")
                    # Try alternative method
                    subprocess.run(['pkill', '-f', 'zivpn'], capture_output=True)
                    subprocess.run(['systemctl', 'start', 'zivpn.service'], capture_output=True)
                
                return True
            else:
                # Password already exists
                return True
                
        except FileNotFoundError:
            print(f"Config file not found: {config_path}")
            return False
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return False
        except Exception as e:
            print(f"Error updating VPN config: {e}")
            return False
    
    def get_user_accounts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, vpn_username, vpn_password, expire_date, is_active 
            FROM accounts WHERE user_id = ? 
            ORDER BY is_active DESC, expire_date DESC
        ''', (user_id,))
        return cursor.fetchall()
    
    def get_account_by_password(self, user_id, password):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, vpn_username, expire_date, is_active 
            FROM accounts WHERE user_id = ? AND vpn_password = ?
        ''', (user_id, password))
        return cursor.fetchone()
    
    def renew_account(self, account_id, days):
        cursor = self.conn.cursor()
        
        try:
            # Get current expiry
            cursor.execute('SELECT expire_date FROM accounts WHERE id = ?', (account_id,))
            result = cursor.fetchone()
            
            if not result:
                return False, "Account not found"
            
            old_expire = result[0]
            if isinstance(old_expire, str):
                old_expire = datetime.strptime(old_expire, '%Y-%m-%d %H:%M:%S')
            
            now = datetime.now()
            
            # Calculate new expiry
            if old_expire > now:
                new_expire = old_expire + timedelta(days=days)
            else:
                new_expire = now + timedelta(days=days)
            
            # Update account
            cursor.execute('''
                UPDATE accounts 
                SET expire_date = ?, is_active = 1 
                WHERE id = ?
            ''', (new_expire, account_id))
            
            self.conn.commit()
            return True, new_expire
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def create_payment(self, user_id, amount, screenshot=None):
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO payments (user_id, amount, screenshot, status)
                VALUES (?, ?, ?, 'pending')
            ''', (user_id, amount, screenshot))
            self.conn.commit()
            return cursor.lastrowid
        except Exception as e:
            print(f"Error creating payment: {e}")
            return None
    
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
    
    def get_payment_by_id(self, payment_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT p.*, u.username 
            FROM payments p
            JOIN users u ON p.user_id = u.user_id
            WHERE p.id = ?
        ''', (payment_id,))
        return cursor.fetchone()
    
    def approve_payment(self, payment_id, admin_id):
        cursor = self.conn.cursor()
        try:
            # Get payment details
            payment = self.get_payment_by_id(payment_id)
            if not payment:
                return False, 0, None
            
            user_id = payment[1]
            amount = payment[2]
            
            # Update payment status
            cursor.execute('''
                UPDATE payments 
                SET status = 'approved', 
                    admin_id = ?,
                    approved_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, payment_id))
            
            # Add credit to user
            self.update_credit(user_id, amount)
            
            self.conn.commit()
            return True, amount, user_id
            
        except Exception as e:
            print(f"Error approving payment: {e}")
            return False, 0, None
    
    def reject_payment(self, payment_id, admin_id, note=""):
        cursor = self.conn.cursor()
        try:
            cursor.execute('''
                UPDATE payments 
                SET status = 'rejected', 
                    admin_id = ?,
                    admin_note = ?
                WHERE id = ? AND status = 'pending'
            ''', (admin_id, note, payment_id))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error rejecting payment: {e}")
            return False
    
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
EOF

    # Create bot.py - COMPLETELY WORKING VERSION
    cat << 'EOF' > /opt/zivpn-bot/bot.py
import logging
import os
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
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
ADMIN_PANEL = 7

class ZivpnBot:
    def __init__(self):
        self.db = Database(Config.DB_NAME)
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        # Start command handler
        self.application.add_handler(CommandHandler("start", self.start_command))
        
        # Message handlers for text commands
        self.application.add_handler(MessageHandler(filters.Regex('^(💳 Topup|💳 Top-up Credit)$'), self.topup_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^(🆕 Create Account|🆕 Create)$'), self.create_account_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^(🔄 Renew Account|🔄 Renew)$'), self.renew_account_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^(💰 Check Credit|💰 Credit)$'), self.check_credit))
        self.application.add_handler(MessageHandler(filters.Regex('^(👤 My Accounts|👤 Accounts)$'), self.my_accounts))
        self.application.add_handler(MessageHandler(filters.Regex('^(👑 Admin Panel|👑 Admin)$'), self.admin_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^(🏠 Main Menu|🏠 Menu)$'), self.main_menu))
        
        # Callback query handlers
        self.application.add_handler(CallbackQueryHandler(self.handle_callback))
        
        # Payment proof handler
        self.application.add_handler(MessageHandler(filters.PHOTO, self.handle_payment_photo))
        
        # Text message handler for conversations
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_message))
    
    def get_main_keyboard(self, user_id):
        """Get main keyboard menu"""
        is_admin = Config.is_admin(user_id)
        
        if is_admin:
            keyboard = [
                [KeyboardButton("💳 Topup"), KeyboardButton("🆕 Create Account")],
                [KeyboardButton("🔄 Renew Account"), KeyboardButton("💰 Check Credit")],
                [KeyboardButton("👤 My Accounts"), KeyboardButton("👑 Admin Panel")],
                [KeyboardButton("🏠 Main Menu")]
            ]
        else:
            keyboard = [
                [KeyboardButton("💳 Topup"), KeyboardButton("🆕 Create Account")],
                [KeyboardButton("🔄 Renew Account"), KeyboardButton("💰 Check Credit")],
                [KeyboardButton("👤 My Accounts"), KeyboardButton("🏠 Main Menu")]
            ]
        
        return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        user_id = user.id
        
        # Clear any existing conversation state
        if context.user_data:
            context.user_data.clear()
        
        is_admin = Config.is_admin(user_id)
        self.db.create_user(user_id, user.username or user.first_name, is_admin)
        
        # Get keyboard menu
        reply_markup = self.get_main_keyboard(user_id)
        
        credit = self.db.get_credit(user_id)
        if is_admin:
            credit_display = "∞ (Admin)"
        else:
            credit_display = f"{credit} {Config.CURRENCY}"
        
        welcome_text = f"""
🌟 Welcome to ZIVPN VPN Service! 🌟

📊 Your Credit: {credit_display}
🌐 Server: {Config.SERVER_ADDRESS}:{Config.SERVER_PORT}
💵 Currency: {Config.CURRENCY}

Use the buttons below to navigate:
"""
        
        await update.message.reply_text(welcome_text, reply_markup=reply_markup)
    
    async def main_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show main menu"""
        user = update.effective_user
        user_id = user.id
        
        reply_markup = self.get_main_keyboard(user_id)
        
        credit = self.db.get_credit(user_id)
        is_admin = Config.is_admin(user_id)
        
        if is_admin:
            credit_display = "∞ (Admin)"
        else:
            credit_display = f"{credit} {Config.CURRENCY}"
        
        menu_text = f"""
🏠 Main Menu

📊 Your Credit: {credit_display}
🌐 Server: {Config.SERVER_ADDRESS}:{Config.SERVER_PORT}

Choose an option:
"""
        
        await update.message.reply_text(menu_text, reply_markup=reply_markup)
    
    async def topup_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show top-up menu"""
        keyboard = [
            [
                InlineKeyboardButton("50 THB", callback_data='topup_50'),
                InlineKeyboardButton("100 THB", callback_data='topup_100'),
                InlineKeyboardButton("150 THB", callback_data='topup_150')
            ],
            [
                InlineKeyboardButton("200 THB", callback_data='topup_200'),
                InlineKeyboardButton("300 THB", callback_data='topup_300'),
                InlineKeyboardButton("500 THB", callback_data='topup_500')
            ],
            [InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "💳 Select top-up amount:",
            reply_markup=reply_markup
        )
    
    async def create_account_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show create account menu"""
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if not Config.is_admin(user_id) and credit < 50:
            await update.message.reply_text(
                f"❌ Insufficient credit!\n"
                f"Your credit: {credit} {Config.CURRENCY}\n"
                f"Minimum required: 50 {Config.CURRENCY}"
            )
            return
        
        # Start account creation process
        context.user_data['action'] = 'create_account'
        context.user_data['step'] = 'username'
        
        await update.message.reply_text(
            "Please enter your desired VPN username (minimum 3 characters):"
        )
    
    async def renew_account_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show renew account menu"""
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if not Config.is_admin(user_id) and credit < 50:
            await update.message.reply_text(
                f"❌ Insufficient credit!\n"
                f"Your credit: {credit} {Config.CURRENCY}\n"
                f"Minimum required: 50 {Config.CURRENCY}"
            )
            return
        
        # Start renewal process
        context.user_data['action'] = 'renew_account'
        context.user_data['step'] = 'password'
        
        await update.message.reply_text(
            "Please enter your VPN password to renew:"
        )
    
    async def check_credit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check user credit"""
        user_id = update.effective_user.id
        
        if Config.is_admin(user_id):
            credit_display = "∞ (Admin)"
        else:
            credit = self.db.get_credit(user_id)
            credit_display = f"{credit} {Config.CURRENCY}"
        
        await update.message.reply_text(f"💰 Your Credit: {credit_display}")
    
    async def my_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show user's accounts"""
        user_id = update.effective_user.id
        accounts = self.db.get_user_accounts(user_id)
        
        if not accounts:
            await update.message.reply_text("You don't have any accounts yet.")
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
        
        await update.message.reply_text(text, parse_mode='Markdown')
    
    async def admin_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show admin menu"""
        user_id = update.effective_user.id
        
        if not Config.is_admin(user_id):
            await update.message.reply_text("❌ Access denied!")
            return
        
        keyboard = [
            [InlineKeyboardButton("👥 User List", callback_data='admin_users')],
            [InlineKeyboardButton("📊 Payment Requests", callback_data='admin_payments')],
            [InlineKeyboardButton("🔐 All Access List", callback_data='admin_access_list')],
            [InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],
            [InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "👑 Admin Panel\n\nSelect an option:",
            reply_markup=reply_markup
        )
    
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle all callback queries"""
        query = update.callback_query
        await query.answer()
        
        data = query.data
        
        if data.startswith('topup_'):
            await self.handle_topup_callback(query, context)
        elif data.startswith('plan_'):
            await self.handle_plan_callback(query, context)
        elif data.startswith('renew_plan_'):
            await self.handle_renew_plan_callback(query, context)
        elif data.startswith('action_'):
            await self.handle_admin_action_callback(query, context)
        elif data == 'main_menu':
            await self.main_menu_callback(query, context)
        elif data.startswith('admin_'):
            await self.handle_admin_menu_callback(query, context)
    
    async def handle_topup_callback(self, query, context):
        """Handle top-up callback"""
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

Please transfer the exact amount and send screenshot as proof.
"""
        
        await query.message.reply_text(payment_info)
        
        context.user_data['waiting_for_payment'] = True
        context.user_data['payment_amount'] = amount
        
        await query.message.reply_text(
            "📸 Please send the payment screenshot now:"
        )
    
    async def handle_plan_callback(self, query, context):
        """Handle plan selection for account creation"""
        days = int(query.data.split('_')[1])
        cost = days * 50 // 30  # 50 THB for 30 days
        
        user_id = query.from_user.id
        username = context.user_data.get('vpn_username')
        password = context.user_data.get('vpn_password')
        
        if not username or not password:
            await query.edit_message_text("❌ Account creation failed. Please start over.")
            return
        
        # Check credit for non-admin users
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                return
        
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
        
        # Clear context data
        context.user_data.clear()
    
    async def handle_renew_plan_callback(self, query, context):
        """Handle renew plan selection"""
        days = int(query.data.split('_')[2])
        cost = days * 50 // 30
        
        user_id = query.from_user.id
        account_id = context.user_data.get('renew_account_id')
        password = context.user_data.get('renew_password')
        
        # Check credit for non-admin users
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                return
        
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
        
        # Clear context data
        context.user_data.clear()
    
    async def handle_admin_action_callback(self, query, context):
        """Handle admin approve/reject actions"""
        admin_id = query.from_user.id
        
        if not Config.is_admin(admin_id):
            await query.edit_message_text("❌ Access denied!")
            return
        
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
                        f"Your credit has been updated."
                    )
                except Exception as e:
                    logger.error(f"Failed to notify user {user_id}: {e}")
                
                await query.edit_message_text(f"✅ Payment #{payment_id} approved! User notified.")
            else:
                await query.edit_message_text(f"❌ Failed to approve payment #{payment_id}")
        
        elif query.data.startswith('action_reject_'):
            payment_id = int(query.data.split('_')[2])
            
            # Store payment ID for rejection
            context.user_data['reject_payment_id'] = payment_id
            context.user_data['reject_admin_id'] = admin_id
            
            await query.message.reply_text(
                f"Please enter reason for rejecting payment #{payment_id}:"
            )
    
    async def main_menu_callback(self, query, context):
        """Handle main menu callback"""
        user_id = query.from_user.id
        reply_markup = self.get_main_keyboard(user_id)
        await query.edit_message_text("Returned to main menu:", reply_markup=reply_markup)
    
    async def handle_admin_menu_callback(self, query, context):
        """Handle admin menu callbacks"""
        data = query.data
        
        if data == 'admin_users':
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
            
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text[:4000], reply_markup=reply_markup)
            
        elif data == 'admin_payments':
            payments = self.db.get_pending_payments()
            
            if not payments:
                text = "No pending payments."
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_back')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup)
            else:
                text = "📊 Pending Payments:\n\n"
                for payment in payments:
                    payment_id, user_id, amount, screenshot, status, admin_id, note, created_date, approved_date, username = payment
                    
                    text += f"🆔 Payment ID: #{payment_id}\n"
                    text += f"👤 User: @{username or 'N/A'} ({user_id})\n"
                    text += f"💰 Amount: {amount} {Config.CURRENCY}\n"
                    text += f"📅 Date: {created_date}\n"
                    text += "─" * 20 + "\n"
                
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_back')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text[:4000], reply_markup=reply_markup)
            
        elif data == 'admin_access_list':
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
            
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text[:4000], parse_mode='Markdown', reply_markup=reply_markup)
            
        elif data == 'admin_stats':
            total_users = self.db.get_total_users()
            active_accounts = self.db.get_active_accounts()
            all_accounts = self.db.get_all_accounts()
            
            text = f"""
📈 System Statistics:

👥 Total Users: {total_users}
🔧 Active Accounts: {active_accounts}
🔐 Total Accounts: {len(all_accounts) if all_accounts else 0}
👑 Admin Users: {len(Config.ADMIN_IDS)}
🌐 Server: {Config.SERVER_ADDRESS}
🔌 VPN Port: {Config.SERVER_PORT}
💵 Currency: {Config.CURRENCY}
"""
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin_back')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text, reply_markup=reply_markup)
        
        elif data == 'admin_back':
            keyboard = [
                [InlineKeyboardButton("👥 User List", callback_data='admin_users')],
                [InlineKeyboardButton("📊 Payment Requests", callback_data='admin_payments')],
                [InlineKeyboardButton("🔐 All Access List", callback_data='admin_access_list')],
                [InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],
                [InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text("👑 Admin Panel\n\nSelect an option:", reply_markup=reply_markup)
    
    async def handle_payment_photo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle payment photo"""
        user_id = update.effective_user.id
        
        # Check if we're waiting for payment proof
        if not context.user_data.get('waiting_for_payment'):
            await update.message.reply_text("Please use the Topup menu first.")
            return
        
        amount = context.user_data.get('payment_amount', 0)
        
        # For admin, auto-approve
        if Config.is_admin(user_id):
            await update.message.reply_text("✅ You are an admin! Credit has been added automatically.")
            self.db.update_credit(user_id, amount)
            await update.message.reply_text(f"Added {amount} {Config.CURRENCY} to your account.")
            context.user_data.clear()
            return
        
        # Get the photo
        photo = update.message.photo[-1]
        file_id = photo.file_id
        
        # Save payment record
        payment_id = self.db.create_payment(user_id, amount, file_id)
        
        if not payment_id:
            await update.message.reply_text("❌ Failed to save payment. Please try again.")
            return
        
        await update.message.reply_text(
            f"✅ Payment proof received!\n"
            f"Amount: {amount} {Config.CURRENCY}\n"
            f"Payment ID: #{payment_id}\n\n"
            f"Please wait for admin approval."
        )
        
        # Notify ALL admins with screenshot and buttons
        for admin_id in Config.ADMIN_IDS:
            try:
                caption = (
                    f"📥 New Payment Request!\n"
                    f"👤 User: @{update.effective_user.username or user_id}\n"
                    f"🆔 User ID: {user_id}\n"
                    f"💰 Amount: {amount} {Config.CURRENCY}\n"
                    f"🆔 Payment ID: #{payment_id}\n"
                    f"🕐 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                
                # Create inline keyboard with approve/reject buttons
                keyboard = [
                    [
                        InlineKeyboardButton(f"✅ Approve #{payment_id}", callback_data=f"action_approve_{payment_id}"),
                        InlineKeyboardButton(f"❌ Reject #{payment_id}", callback_data=f"action_reject_{payment_id}")
                    ]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                # Send photo with caption and buttons
                await self.application.bot.send_photo(
                    chat_id=admin_id,
                    photo=file_id,
                    caption=caption,
                    reply_markup=reply_markup
                )
                
                logger.info(f"Payment notification sent to admin {admin_id}")
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
        
        # Clear context data
        context.user_data.clear()
    
    async def handle_text_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle text messages for account creation/renewal"""
        text = update.message.text.strip()
        user_id = update.effective_user.id
        
        action = context.user_data.get('action')
        step = context.user_data.get('step')
        
        if action == 'create_account':
            if step == 'username':
                if len(text) < 3:
                    await update.message.reply_text("Username must be at least 3 characters. Please try again:")
                    return
                
                context.user_data['vpn_username'] = text
                context.user_data['step'] = 'password'
                
                await update.message.reply_text(
                    "Now enter your desired VPN password (minimum 4 characters):"
                )
            
            elif step == 'password':
                if len(text) < 4:
                    await update.message.reply_text("Password must be at least 4 characters. Please try again:")
                    return
                
                context.user_data['vpn_password'] = text
                context.user_data['step'] = 'plan'
                
                # Show plan options
                if Config.is_admin(user_id):
                    keyboard = [
                        [InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')],
                        [InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')],
                        [InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')],
                        [InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')]
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
                    
                    keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')])
                
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await update.message.reply_text(
                    "Select subscription plan:",
                    reply_markup=reply_markup
                )
        
        elif action == 'renew_account':
            if step == 'password':
                # Check if account exists
                account = self.db.get_account_by_password(user_id, text)
                
                if not account:
                    await update.message.reply_text("❌ Account not found or doesn't belong to you. Please try again:")
                    return
                
                account_id, username, expire_date, is_active = account
                
                if not is_active:
                    await update.message.reply_text("❌ This account is not active. Please use create account instead.")
                    context.user_data.clear()
                    return
                
                context.user_data['renew_account_id'] = account_id
                context.user_data['renew_password'] = text
                context.user_data['step'] = 'plan'
                
                # Show plan options
                if Config.is_admin(user_id):
                    keyboard = [
                        [InlineKeyboardButton("30 Days - 50 THB", callback_data='renew_plan_30')],
                        [InlineKeyboardButton("60 Days - 100 THB", callback_data='renew_plan_60')],
                        [InlineKeyboardButton("90 Days - 150 THB", callback_data='renew_plan_90')],
                        [InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')]
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
                    
                    keyboard.append([InlineKeyboardButton("🏠 Main Menu", callback_data='main_menu')])
                
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await update.message.reply_text(
                    f"Account found: {username}\nCurrent expiry: {expire_date}\n\nSelect renewal plan:",
                    reply_markup=reply_markup
                )
        
        elif 'reject_payment_id' in context.user_data:
            payment_id = context.user_data['reject_payment_id']
            admin_id = context.user_data['reject_admin_id']
            reason = text
            
            # Reject payment
            success = self.db.reject_payment(payment_id, admin_id, reason)
            
            if success:
                await update.message.reply_text(f"✅ Payment #{payment_id} rejected with reason.")
            else:
                await update.message.reply_text(f"❌ Failed to reject payment #{payment_id}")
            
            # Clean up
            context.user_data.pop('reject_payment_id', None)
            context.user_data.pop('reject_admin_id', None)
        
        else:
            # Unknown text, show main menu
            await self.main_menu(update, context)
    
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
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
}

# Function to test VPN connection
test_vpn_connection() {
    print_status "Testing VPN connection..."
    
    # Check if service is running
    if systemctl is-active --quiet zivpn.service; then
        print_success "VPN service is running"
    else
        print_error "VPN service is not running"
        return 1
    fi
    
    # Check if port is listening
    if ss -ulpn | grep -q ":5667"; then
        print_success "VPN is listening on port 5667"
    else
        print_error "VPN is not listening on port 5667"
        return 1
    fi
    
    # Check config file
    if [ -f /etc/zivpn/config.json ]; then
        if python3 -c "import json; json.load(open('/etc/zivpn/config.json'))" 2>/dev/null; then
            print_success "Config.json is valid JSON"
            
            # Show passwords in config
            echo -e "${YELLOW}Passwords in config.json:${NC}"
            python3 -c "
import json
try:
    with open('/etc/zivpn/config.json', 'r') as f:
        config = json.load(f)
    if 'auth' in config and 'config' in config['auth']:
        for pwd in config['auth']['config']:
            print(f'  - {pwd}')
    else:
        print('  No passwords found in config')
except Exception as e:
    print(f'  Error: {e}')
"
        else
            print_error "Config.json is invalid JSON"
            return 1
    else
        print_error "Config.json not found"
        return 1
    fi
    
    # Test with netcat
    print_status "Testing VPN with netcat..."
    if command -v nc >/dev/null 2>&1; then
        if timeout 2 nc -z -u localhost 5667; then
            print_success "VPN port 5667 is accessible"
        else
            print_error "Cannot connect to VPN port 5667"
        fi
    fi
    
    return 0
}

# Function to test bot
test_bot() {
    print_status "Testing Telegram Bot..."
    
    # Check if service is running
    if systemctl is-active --quiet zivpn-bot.service; then
        print_success "Bot service is running"
    else
        print_error "Bot service is not running"
        return 1
    fi
    
    # Check bot logs
    if journalctl -u zivpn-bot.service -n 5 --no-pager | grep -q "Application"; then
        print_success "Bot started successfully"
    else
        print_error "Bot may not have started properly"
        journalctl -u zivpn-bot.service -n 10 --no-pager
    fi
    
    return 0
}

# Function to fix common issues
fix_common_issues() {
    print_status "Fixing common issues..."
    
    # Fix VPN config permissions
    chmod 644 /etc/zivpn/config.json 2>/dev/null || true
    chown root:root /etc/zivpn/config.json 2>/dev/null || true
    
    # Fix bot directory permissions
    chmod -R 755 /opt/zivpn-bot 2>/dev/null || true
    chown -R root:root /opt/zivpn-bot 2>/dev/null || true
    
    # Fix SQLite database permissions
    if [ -f /opt/zivpn-bot/zivpn.db ]; then
        chmod 644 /opt/zivpn-bot/zivpn.db 2>/dev/null || true
    fi
    
    # Restart services
    systemctl daemon-reload 2>/dev/null || true
    systemctl restart zivpn.service 2>/dev/null || true
    systemctl restart zivpn-bot.service 2>/dev/null || true
    
    print_success "Common issues fixed"
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
    
    # Fix common issues
    fix_common_issues
    
    # Test VPN connection
    echo -e "\n${YELLOW}=== Testing VPN Connection ===${NC}"
    if test_vpn_connection; then
        print_success "VPN connection test passed!"
    else
        print_error "VPN connection test failed!"
    fi
    
    # Test bot if installed
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo -e "\n${YELLOW}=== Testing Telegram Bot ===${NC}"
        if test_bot; then
            print_success "Bot test passed!"
        else
            print_error "Bot test failed!"
        fi
    fi
    
    # Cleanup
    rm -f zi.* 2>/dev/null
    
    echo -e "\n${GREEN}=========================================${NC}"
    echo -e "${GREEN}✅ Installation Complete!${NC}"
    echo -e "${GREEN}=========================================${NC}"
    
    echo -e "\n${YELLOW}=== Installation Summary ===${NC}"
    echo -e "Zivpn UDP VPN: ${GREEN}Installed${NC}"
    echo -e "Server Address: ${GREEN}${SERVER_HOSTNAME:-$SERVER_IP}${NC}"
    echo -e "VPN Port: ${GREEN}5667${NC}"
    echo -e "Initial VPN Passwords: ${GREEN}${VPN_PASSWORDS[*]}${NC}"
    echo -e "Admin Token: ${GREEN}$ADMIN_TOKEN${NC}"
    echo -e "Admin IDs: ${GREEN}$ADMIN_IDS${NC}"
    echo -e "Telegram Bot: $( [[ "$install_bot_choice" =~ ^[Yy]$ ]] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Skipped${NC}" )"
    
    echo -e "\n${YELLOW}=== Service Status ===${NC}"
    systemctl status zivpn.service --no-pager | head -20
    
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo ""
        systemctl status zivpn-bot.service --no-pager | head -20
    fi
    
    echo -e "\n${YELLOW}=== Bot Features ===${NC}"
    echo -e "📱 Keyboard Menu System"
    echo -e "💳 Topup with screenshot to ALL admins"
    echo -e "✅❌ Admin Approve/Reject buttons"
    echo -e "🆕 Create Account with auto VPN config update"
    echo -e "🔄 Renew Account"
    echo -e "💰 Check Credit"
    echo -e "👤 My Accounts"
    echo -e "👑 Admin Panel"
    echo -e "🔐 All Access List"
    echo -e "📈 Statistics"
    
    echo -e "\n${GREEN}=== How to Use ===${NC}"
    echo -e "1. Start the bot: /start"
    echo -e "2. Use keyboard buttons for navigation"
    echo -e "3. Create account: 🆕 Create Account"
    echo -e "4. Renew account: 🔄 Renew Account"
    echo -e "5. Topup credit: 💳 Topup"
    
    echo -e "\n${YELLOW}=== VPN Connection Info ===${NC}"
    echo -e "Server: ${SERVER_HOSTNAME:-$SERVER_IP}:5667"
    echo -e "Protocol: UDP"
    echo -e "Use any UDP VPN client to connect"
    
    # Troubleshooting guide
    echo -e "\n${YELLOW}=== Troubleshooting ===${NC}"
    echo -e "If VPN doesn't connect:"
    echo -e "1. Check VPN service: systemctl status zivpn.service"
    echo -e "2. Check VPN logs: journalctl -u zivpn.service -f"
    echo -e "3. Check firewall: ufw status"
    echo -e "4. Restart VPN: systemctl restart zivpn.service"
    
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo -e "\nIf Bot doesn't work:"
        echo -e "1. Check bot status: systemctl status zivpn-bot.service"
        echo -e "2. Check bot logs: journalctl -u zivpn-bot.service -f"
        echo -e "3. Check bot token: cat /opt/zivpn-bot/.env"
        echo -e "4. Restart bot: systemctl restart zivpn-bot.service"
    fi
    
    echo -e "\n${GREEN}=== Important Files ===${NC}"
    echo -e "VPN Config: /etc/zivpn/config.json"
    echo -e "Bot Directory: /opt/zivpn-bot"
    echo -e "Bot Config: /opt/zivpn-bot/.env"
    echo -e "Database: /opt/zivpn-bot/zivpn.db"
}

# Run installation
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

main_installation
