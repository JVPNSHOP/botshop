#!/bin/bash

# install_zivpn_bot_fixed.sh
# Zivpn UDP Module + Telegram Bot Installer (Fixed version)
# Creator: Zahid Islam (original)
# Fixes by: ChatGPT — Adds /start command support + callback pattern fixes + service wiring

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Zivpn UDP VPN + Telegram Bot Installer (Fixed) ===${NC}"
echo -e "${YELLOW}Creator: Zahid Islam (original)${NC}"
echo ""

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
    apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw iptables
}

# Function to install UDP VPN
install_udp_vpn() {
    print_status "Installing Zivpn UDP VPN..."
    
    # Stop existing service if exists
    if systemctl is-active --quiet zivpn.service 2>/dev/null; then
        systemctl stop zivpn.service || true
    fi

    # Download UDP binary (ensure the URL exists on your side; change if necessary)
    wget -q -O /usr/local/bin/zivpn "https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64" || true
    if [ -f /usr/local/bin/zivpn ]; then
        chmod +x /usr/local/bin/zivpn
    else
        print_error "Failed to download zivpn binary; continuing but service may fail. Please check the URL."
    fi

    # Create config directory and default config if missing
    mkdir -p /etc/zivpn
    if [ ! -f /etc/zivpn/config.json ]; then
        cat > /etc/zivpn/config.json <<'EOF'
{
  "listen": ":5667",
  "config": ["zi"]
}
EOF
    fi

    # Generate certificates (overwrite)
    print_status "Generating SSL certificates..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Zivpn/OU=IT/CN=zivpn" \
        -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt" 2>/dev/null || true

    # Configure passwords (from earlier read; default will be 'zi' if not provided)
    echo -e "${YELLOW}=== ZIVPN UDP Passwords ===${NC}"
    read -p "Enter passwords separated by commas (Press enter for Default 'zi'): " input_config || true

    if [ -n "${input_config-}" ]; then
        IFS=',' read -r -a config <<< "$input_config"
        if [ ${#config[@]} -eq 1 ]; then
            config+=(${config[0]})
        fi
    else
        config=("zi")
    fi

    new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"
    # Replace config array in config.json (fallback to writing new if replace fails)
    if grep -q '"config"' /etc/zivpn/config.json 2>/dev/null; then
        sed -i -E "s/\"config\": ?\[[[:space:]]*([^\]]*)\]/${new_config_str}/g" /etc/zivpn/config.json || true
    else
        # Append to file
        jq ".config = $(printf '["%s"]' "${config[0]}")" /etc/zivpn/config.json >/tmp/zivpn_conf.json 2>/dev/null || true
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

    # Optimize network settings (temporary; to persist, add to /etc/sysctl.conf)
    sysctl -w net.core.rmem_max=16777216 2>/dev/null || true
    sysctl -w net.core.wmem_max=16777216 2>/dev/null || true

    # Enable and start service (may fail if binary missing)
    systemctl daemon-reload
    systemctl enable zivpn.service || true
    systemctl start zivpn.service || true

    # Configure firewall (map a range example)
    interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || true)
    if [ -n "$interface" ]; then
        iptables -t nat -A PREROUTING -i "$interface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
    fi
    ufw allow 6000:19999/udp || true
    ufw allow 5667/udp || true
    ufw --force enable || true

    print_success "Zivpn UDP VPN installed (or attempted). Check systemctl status for details."
}

# Function to collect configuration
collect_configuration() {
    echo -e "${YELLOW}=== Basic Configuration ===${NC}"
    echo ""

    # Get server IP
    SERVER_IP=$(curl -4 -s ifconfig.me || curl -4 -s icanhazip.com || echo "")
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
    read -p "Enter Your Hostname (e.g., jvpn.shop) [optional]: " SERVER_HOSTNAME || true

    # Get admin configuration
    echo ""
    read -p "Enter Admin Token (default: admin123): " ADMIN_TOKEN || true
    ADMIN_TOKEN=${ADMIN_TOKEN:-admin123}

    read -p "Enter Admin IDs (comma separated, e.g. 12345678,87654321): " ADMIN_IDS || true

    # Get payment information
    echo ""
    echo -e "${YELLOW}=== Payment Configuration ===${NC}"
    read -p "Enter Bank Name: " BANK_NAME || true
    read -p "Enter Bank Number: " BANK_ACCOUNT || true
    read -p "Enter Account Holder Name: " ACCOUNT_NAME || true

    echo ""
    echo "Upload QR code image to one of these (get direct image URL):"
    echo "1. https://imgbb.com"
    echo "2. https://imgur.com"
    echo "3. https://postimages.org"
    echo ""
    read -p "Enter Bank QR Image Link (Direct URL) [optional]: " QR_IMAGE_URL || true
}

# Function to install Telegram Bot
install_telegram_bot() {
    print_status "Installing Telegram Bot..."

    # Ensure variables exist
    if [ -z "${BOT_TOKEN-}" ]; then
        echo ""
        echo -e "${YELLOW}=== Telegram Bot Configuration ===${NC}"
        read -p "Enter Bot Token from @BotFather: " BOT_TOKEN
    fi

    # Create bot directory
    mkdir -p /opt/zivpn-bot
    chown root:root /opt/zivpn-bot
    cd /opt/zivpn-bot

    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate

    # Install Python dependencies
    pip install --upgrade pip
    pip install python-telegram-bot==20.3 python-dotenv pillow qrcode cryptography

    # Create bot files
    create_bot_files
    create_systemd_service

    # Initialize database (run via python -c to create DB)
    cd /opt/zivpn-bot
    source venv/bin/activate
    python3 - <<PY
from database import Database
db = Database('zivpn.db')
print('Database initialized successfully')
PY

    # Start bot service
    systemctl daemon-reload
    systemctl enable zivpn-bot.service || true
    systemctl restart zivpn-bot.service || true

    print_success "Telegram Bot installed (or attempted). Check systemctl status for details."
    echo -e "${YELLOW}Bot configuration saved to: /opt/zivpn-bot/.env${NC}"
}

# Function to create bot files
create_bot_files() {
    # Use hostname if provided, otherwise use IP
    if [ -n "${SERVER_HOSTNAME-}" ]; then
        SERVER_ADDRESS="$SERVER_HOSTNAME"
    else
        SERVER_ADDRESS="$SERVER_IP"
    fi

    # Create config.py
    cat << 'EOF' > /opt/zivpn-bot/config.py
import os
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

    # Create database.py
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
                vpn_username TEXT UNIQUE,
                vpn_password TEXT,
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expire_date TIMESTAMP,
                device_hash TEXT,
                is_active BOOLEAN DEFAULT 1,
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
    
    def get_credit(self, user_id):
        if Config.is_admin(user_id):
            return Config.get_admin_unlimited_credit()
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT credit FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        return result[0] if result else 0
    
    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        expire_date = datetime.now() + timedelta(days=days)
        
        cursor.execute('SELECT id FROM accounts WHERE vpn_username = ?', (username,))
        if cursor.fetchone():
            return False, "Username already exists"
        
        try:
            cursor.execute('''
                INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, password, expire_date))
            
            # Update VPN config
            try:
                with open('/etc/zivpn/config.json', 'r') as f:
                    config = json.load(f)
                if password not in config.get("config", []):
                    config["config"].append(password)
                    with open('/etc/zivpn/config.json', 'w') as f:
                        json.dump(config, f, indent=2)
                    import subprocess
                    subprocess.run(['systemctl', 'restart', 'zivpn.service'], capture_output=True)
            except:
                pass
            
            self.conn.commit()
            return True, "Account created successfully"
        except Exception as e:
            return False, str(e)
    
    def get_user_accounts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT vpn_username, vpn_password, expire_date, is_active 
            FROM accounts WHERE user_id = ?
        ''', (user_id,))
        return cursor.fetchall()
    
    def create_payment(self, user_id, amount, screenshot=None):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO payments (user_id, amount, screenshot)
            VALUES (?, ?, ?)
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
        ''')
        return cursor.fetchall()
    
    def approve_payment(self, payment_id, admin_id):
        cursor = self.conn.cursor()
        cursor.execute('SELECT user_id, amount FROM payments WHERE id = ?', (payment_id,))
        payment = cursor.fetchone()
        
        if payment:
            user_id, amount = payment
            cursor.execute('''
                UPDATE payments 
                SET status = 'approved', 
                    admin_id = ?,
                    approved_date = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (admin_id, payment_id))
            cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
            self.conn.commit()
            return True
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
EOF

    # Create bot.py - Simplified with only button menu, fixed handlers
    cat << 'EOF' > /opt/zivpn-bot/bot.py
import logging
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CallbackQueryHandler, CommandHandler,
    MessageHandler, filters, ContextTypes, ConversationHandler
)
import qrcode
from io import BytesIO
from datetime import datetime, timedelta

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
ADMIN_PANEL, ADMIN_ACTION = range(5, 7)

class ZivpnBot:
    def __init__(self):
        self.db = Database(Config.DB_NAME)
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        # Support /start command
        self.application.add_handler(CommandHandler('start', self.start))

        # Callback handlers for menu actions (patterns must match callback_data)
        self.application.add_handler(CallbackQueryHandler(self.topup_start, pattern='^topup_amount$'))
        self.application.add_handler(CallbackQueryHandler(self.create_account_start, pattern='^create_account_input$'))
        self.application.add_handler(CallbackQueryHandler(self.check_credit, pattern='^check_credit$'))
        self.application.add_handler(CallbackQueryHandler(self.admin_panel, pattern='^admin_menu$'))
        self.application.add_handler(CallbackQueryHandler(self.back_to_menu, pattern='^back$'))

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
        self.application.add_handler(admin_conv)

        # General handler for unknown callbacks (optional)
        self.application.add_handler(CallbackQueryHandler(self.generic_callback))

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        # Support both /start message and callback query
        query = update.callback_query
        if query:
            await query.answer()
            user = update.effective_user
            chat_id = query.message.chat_id
            from_callback = True
        else:
            user = update.effective_user
            chat_id = update.effective_chat.id if update.effective_chat else user.id
            from_callback = False

        user_id = user.id
        is_admin = Config.is_admin(user_id)
        self.db.create_user(user_id, user.username or user.first_name, is_admin)

        # Create main menu buttons
        keyboard = [
            [InlineKeyboardButton("💳 Top-up Credit", callback_data='topup_amount')],
            [InlineKeyboardButton("🆕 Create Account", callback_data='create_account_input')],
            [InlineKeyboardButton("💰 Check Credit", callback_data='check_credit')],
        ]

        if is_admin:
            keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data='admin_menu')])

        reply_markup = InlineKeyboardMarkup(keyboard)

        credit = self.db.get_credit(user_id)
        credit_display = "∞ (Admin)" if is_admin else f"{credit} {Config.CURRENCY}"

        welcome_text = f"""
🌟 Welcome to ZIVPN VPN Service! 🌟

📊 Your Credit: {credit_display}
🌐 Server: {Config.SERVER_ADDRESS}
💵 Currency: {Config.CURRENCY}

Choose an option:
"""
        if from_callback:
            try:
                await query.edit_message_text(welcome_text, reply_markup=reply_markup)
            except:
                await context.bot.send_message(chat_id, welcome_text, reply_markup=reply_markup)
        else:
            await context.bot.send_message(chat_id, welcome_text, reply_markup=reply_markup)

    async def generic_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        # Unknown callback_data: show menu
        await self.start(update, context)

    async def back_to_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await self.start(update, context)

    async def topup_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()

        keyboard = [
            [
                InlineKeyboardButton("50 THB", callback_data='amount_50'),
                InlineKeyboardButton("100 THB", callback_data='amount_100'),
                InlineKeyboardButton("150 THB", callback_data='amount_150')
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
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                bio = BytesIO()
                img.save(bio, 'PNG')
                bio.seek(0)
                await query.message.reply_photo(photo=bio)
        else:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            bio = BytesIO()
            img.save(bio, 'PNG')
            bio.seek(0)
            await query.message.reply_photo(photo=bio)

        payment_info = f"""
💰 Payment Information (THB):

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
        if not update.message.photo:
            await update.message.reply_text("❌ No photo found. Please send the payment screenshot as a photo.")
            return PAYMENT_PROOF

        photo = update.message.photo[-1]
        file_id = photo.file_id

        # Save payment record
        payment_id = self.db.create_payment(user_id, amount, file_id)

        await update.message.reply_text(
            f"✅ Payment proof received!\n"
            f"Amount: {amount} {Config.CURRENCY}\n"
            f"Payment ID: {payment_id}\n\n"
            f"Please wait for admin approval."
        )

        # Notify admins
        for admin_id in Config.ADMIN_IDS:
            try:
                await self.application.bot.send_message(
                    admin_id,
                    f"📥 New Payment Request!\n"
                    f"User: @{update.effective_user.username or user_id}\n"
                    f"Amount: {amount} {Config.CURRENCY}\n"
                    f"Payment ID: {payment_id}"
                )
            except:
                pass

        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='back')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await update.message.reply_text("Return to menu:", reply_markup=reply_markup)
        return ConversationHandler.END

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
            "Now enter your desired VPN password:"
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

🔧 Server Details:
🌐 Server: {Config.SERVER_ADDRESS}
🔌 Port: {Config.SERVER_PORT}
👤 Username: {username}
🔑 Password: {password}
📅 Expire Date: {expire_date.strftime('%Y-%m-%d')}
🔒 Max Devices: 1

⚠️ Note: Only first device can connect.
"""
            await query.edit_message_text(account_info)
        else:
            await query.edit_message_text(f"❌ Error: {message}")

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
                    text += f"ID: {payment[0]}\n"
                    text += f"User: {payment[8] or payment[1]}\n"
                    text += f"Amount: {payment[3]} {Config.CURRENCY}\n"
                    text += f"Date: {payment[7]}\n"

                    callback_data = f"action_approve_{payment[0]}"
                    keyboard.append([InlineKeyboardButton(f"✅ Approve Payment {payment[0]}", callback_data=callback_data)])

                    text += "─" * 20 + "\n"

                keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='admin_menu')])
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text[:4000], reply_markup=reply_markup)
                return ADMIN_ACTION

        elif action == 'admin_stats':
            total_users = self.db.get_total_users()
            active_accounts = self.db.get_active_accounts()

            text = f"""
📈 System Statistics:

👥 Total Users: {total_users}
🔧 Active Accounts: {active_accounts}
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

        if query.data.startswith('action_approve_'):
            payment_id = int(query.data.split('_')[2])
            admin_id = update.effective_user.id

            success = self.db.approve_payment(payment_id, admin_id)

            if success:
                await query.edit_message_text(f"✅ Payment {payment_id} approved!")
            else:
                await query.edit_message_text(f"❌ Failed to approve payment!")

        keyboard = [[InlineKeyboardButton("🔙 Back to Admin Panel", callback_data='admin_menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Return to admin panel:", reply_markup=reply_markup)
        return ConversationHandler.END

    async def cancel_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await self.start(update, context)
        return ConversationHandler.END

    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        await self.start(update, context)
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
BOT_TOKEN=${BOT_TOKEN}
ADMIN_IDS=${ADMIN_IDS}
ADMIN_TOKEN=${ADMIN_TOKEN}

# Server Configuration
SERVER_ADDRESS=${SERVER_ADDRESS}
SERVER_PORT=5667

# Payment Configuration
BANK_ACCOUNT=${BANK_ACCOUNT}
BANK_NAME=${BANK_NAME}
ACCOUNT_NAME=${ACCOUNT_NAME}
QR_IMAGE_URL=${QR_IMAGE_URL}

# System Configuration
CURRENCY=THB
EOF

    # Make sure permissions are correct
    chown -R root:root /opt/zivpn-bot
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
ExecStart=/opt/zivpn-bot/venv/bin/python3 /opt/zivpn-bot/bot.py
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
    read -p "Do you want to install the Telegram Bot? (y/n): " install_bot_choice || true

    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        install_telegram_bot
    else
        print_status "Skipping Telegram Bot installation..."
    fi

    # Cleanup
    rm -f zi.* 2>/dev/null || true

    echo -e "\n${GREEN}=========================================${NC}"
    echo -e "${GREEN}✅ Installation Attempt Finished${NC}"
    echo -e "${GREEN}=========================================${NC}"

    echo -e "\n${YELLOW}=== Installation Summary ===${NC}"
    echo -e "Zivpn UDP VPN: ${GREEN}Installed/Attempted${NC}"
    echo -e "Server Address: ${GREEN}${SERVER_ADDRESS}${NC}"
    echo -e "Admin Token: ${GREEN}${ADMIN_TOKEN}${NC}"
    echo -e "Admin IDs: ${GREEN}${ADMIN_IDS}${NC}"
    echo -e "Telegram Bot: $( [[ "$install_bot_choice" =~ ^[Yy]$ ]] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Skipped${NC}" )"

    echo -e "\n${YELLOW}=== Service Status ===${NC}"
    echo -e "${BLUE}zivpn.service:${NC}"
    systemctl status zivpn.service --no-pager || true

    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}zivpn-bot.service:${NC}"
        systemctl status zivpn-bot.service --no-pager || true
    fi

    echo -e "\n${YELLOW}=== Bot Features ===${NC}"
    echo -e "💳 Top-up Credit Button"
    echo -e "🆕 Create Account Button"
    echo -e "💰 Check Credit Button"
    echo -e "👑 Admin Panel Button"
    echo -e "🏦 Bank: ${BANK_NAME}"
    echo -e "💳 Account: ${BANK_ACCOUNT}"
    echo -e "👤 Account Name: ${ACCOUNT_NAME}"

    if [ -n "${QR_IMAGE_URL-}" ]; then
        echo -e "📷 QR Code: Enabled"
    fi

    echo -e "\n${GREEN}=== Done ===${NC}"
}

# Run installation
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

main_installation
