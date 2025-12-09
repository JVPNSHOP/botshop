#!/bin/bash

# Zivpn UDP Module + Telegram Bot Installer - SIMPLE FIXED VERSION
# Fixed Issues:
# 1. Admin payment notification - FIXED
# 2. Create account conversation flow - FIXED
# 3. Default password "zi" issue - REMOVED

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Zivpn UDP VPN + Telegram Bot Installer ===${NC}"
echo ""

# Function to print status
print_status() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

# Install dependencies
print_status "Installing dependencies..."
apt-get update && apt-get upgrade -y
apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw jq netcat

# Get configuration
echo -e "\n${YELLOW}=== Configuration ===${NC}"

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

read -p "Enter Your Hostname (or press Enter to use IP): " SERVER_HOSTNAME
SERVER_ADDRESS="${SERVER_HOSTNAME:-$SERVER_IP}"

read -p "Enter Admin Token (default: admin123): " ADMIN_TOKEN
ADMIN_TOKEN=${ADMIN_TOKEN:-admin123}

read -p "Enter Admin IDs (comma separated, e.g., 123456789): " ADMIN_IDS

echo ""
echo "Note: No default password. Users will create their own passwords."
VPN_PASSWORDS=()

# Get payment info
echo -e "\n${YELLOW}=== Payment Configuration ===${NC}"
read -p "Enter Bank Name: " BANK_NAME
read -p "Enter Bank Number: " BANK_ACCOUNT
read -p "Enter Account Holder Name: " ACCOUNT_NAME

# Install UDP VPN
print_status "Installing Zivpn UDP VPN..."

# Stop existing services
systemctl stop zivpn.service 2>/dev/null
systemctl disable zivpn.service 2>/dev/null
systemctl stop zivpn-bot.service 2>/dev/null
systemctl disable zivpn-bot.service 2>/dev/null

# Download UDP binary
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn -q
chmod +x /usr/local/bin/zivpn

# Create config directory
mkdir -p /etc/zivpn

# Generate certificates
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=California/L=Los Angeles/O=Zivpn/OU=VPN Service/CN=zivpn" \
    -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

# Create config.json with empty password list
cat <<EOF > /etc/zivpn/config.json
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": []
  }
}
EOF

# Create systemd service
cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=Zivpn UDP VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# Start VPN service
systemctl daemon-reload
systemctl enable zivpn.service
systemctl start zivpn.service

sleep 3
if systemctl is-active --quiet zivpn.service; then
    print_success "VPN service is running!"
else
    print_error "VPN service failed to start"
    journalctl -u zivpn.service -n 10 --no-pager
    exit 1
fi

# Configure firewall
ufw --force disable 2>/dev/null || true
ufw allow 5667/udp
ufw allow 22/tcp
echo "y" | ufw enable

# Install Telegram Bot
echo -e "\n${YELLOW}=== Telegram Bot Installation ===${NC}"
read -p "Enter Bot Token from @BotFather: " BOT_TOKEN

if [ -z "$BOT_TOKEN" ]; then
    print_error "Bot token is required!"
    exit 1
fi

# Create bot directory
mkdir -p /opt/zivpn-bot
cd /opt/zivpn-bot

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Create requirements.txt
cat <<EOF > requirements.txt
python-telegram-bot==20.3
python-dotenv==1.0.0
qrcode==7.4.2
EOF

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create config.py - FIXED VERSION
cat <<EOF > config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    BOT_TOKEN = os.getenv("BOT_TOKEN", "")
    
    # Parse admin IDs
    ADMIN_IDS = []
    admin_ids_str = os.getenv("ADMIN_IDS", "")
    if admin_ids_str:
        for admin_id in admin_ids_str.split(','):
            admin_id = admin_id.strip()
            if admin_id and admin_id.isdigit():
                ADMIN_IDS.append(int(admin_id))
    
    ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin123")
    DB_NAME = "zivpn.db"
    SERVER_ADDRESS = os.getenv("SERVER_ADDRESS", "$SERVER_ADDRESS")
    SERVER_PORT = os.getenv("SERVER_PORT", "5667")
    
    # Payment Configuration
    BANK_ACCOUNT = os.getenv("BANK_ACCOUNT", "$BANK_ACCOUNT")
    BANK_NAME = os.getenv("BANK_NAME", "$BANK_NAME")
    ACCOUNT_NAME = os.getenv("ACCOUNT_NAME", "$ACCOUNT_NAME")
    
    VPN_CONFIG_PATH = "/etc/zivpn/config.json"
    CURRENCY = "THB"
    
    @staticmethod
    def is_admin(user_id):
        return user_id in Config.ADMIN_IDS
    
    @staticmethod
    def get_admin_unlimited_credit():
        return 999999
EOF

# Create database.py - SIMPLE VERSION
cat <<'EOF' > database.py
import sqlite3
import json
from datetime import datetime, timedelta
import subprocess
import os
import time
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
        
        self.conn.commit()
    
    def create_user(self, user_id, username, is_admin=False):
        cursor = self.conn.cursor()
        cursor.execute('INSERT OR IGNORE INTO users (user_id, username, is_admin) VALUES (?, ?, ?)', 
                      (user_id, username, is_admin))
        self.conn.commit()
        return True
    
    def get_credit(self, user_id):
        if Config.is_admin(user_id):
            return Config.get_admin_unlimited_credit()
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT credit FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        return result[0] if result else 0
    
    def update_credit(self, user_id, amount):
        cursor = self.conn.cursor()
        cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', (amount, user_id))
        self.conn.commit()
        return True
    
    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        
        # Check if account exists
        cursor.execute('SELECT id FROM accounts WHERE vpn_username = ? AND vpn_password = ?', 
                      (username, password))
        if cursor.fetchone():
            return False, "Account already exists"
        
        expire_date = datetime.now() + timedelta(days=days)
        
        try:
            cursor.execute('''
                INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, password, expire_date))
            
            # Update VPN config
            success = self.update_vpn_config(password)
            if not success:
                self.conn.rollback()
                return False, "Failed to update VPN config"
            
            self.conn.commit()
            return True, "Account created successfully"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def update_vpn_config(self, password):
        try:
            # Read config
            with open(Config.VPN_CONFIG_PATH, 'r') as f:
                config = json.load(f)
            
            # Add password if not exists
            if 'auth' not in config:
                config['auth'] = {"mode": "passwords", "config": []}
            
            if 'config' not in config['auth']:
                config['auth']['config'] = []
            
            if password not in config['auth']['config']:
                config['auth']['config'].append(password)
                
                # Write back
                with open(Config.VPN_CONFIG_PATH, 'w') as f:
                    json.dump(config, f, indent=2)
                
                # Restart VPN service
                subprocess.run(['systemctl', 'restart', 'zivpn.service'], 
                             capture_output=True, timeout=30)
                time.sleep(2)
            
            return True
        except Exception as e:
            print(f"VPN config error: {e}")
            return False
    
    def get_user_accounts(self, user_id):
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, vpn_username, vpn_password, expire_date, is_active 
            FROM accounts WHERE user_id = ?
        ''', (user_id,))
        return cursor.fetchall()
    
    def create_payment(self, user_id, amount, screenshot):
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
        ''')
        return cursor.fetchall()
    
    def approve_payment(self, payment_id, admin_id):
        cursor = self.conn.cursor()
        
        # Get payment details
        cursor.execute('SELECT user_id, amount FROM payments WHERE id = ?', (payment_id,))
        payment = cursor.fetchone()
        
        if payment:
            user_id, amount = payment
            
            # Update payment
            cursor.execute('''
                UPDATE payments SET status = 'approved', admin_id = ?,
                approved_date = CURRENT_TIMESTAMP WHERE id = ?
            ''', (admin_id, payment_id))
            
            # Add credit
            cursor.execute('UPDATE users SET credit = credit + ? WHERE user_id = ?', 
                          (amount, user_id))
            
            self.conn.commit()
            return True, amount, user_id
        
        return False, 0, None
EOF

# Create bot.py - FIXED VERSION
cat <<'EOF' > bot.py
import logging
import json
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes, ConversationHandler
from datetime import datetime, timedelta
from config import Config
from database import Database

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# States
TOPUP_AMOUNT, PAYMENT_PROOF = range(2)
CREATE_USERNAME, CREATE_PASSWORD, SELECT_PLAN = range(2, 5)

class ZivpnBot:
    def __init__(self):
        self.db = Database()
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        # Start command
        self.application.add_handler(CommandHandler("start", self.start_command))
        
        # Menu buttons
        self.application.add_handler(MessageHandler(filters.Regex('^💳 Top-up Credit$'), self.topup_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^🆕 Create Account$'), self.create_account_menu))
        self.application.add_handler(MessageHandler(filters.Regex('^💰 Check Credit$'), self.check_credit))
        self.application.add_handler(MessageHandler(filters.Regex('^👤 My Accounts$'), self.my_accounts))
        self.application.add_handler(MessageHandler(filters.Regex('^👑 Admin Panel$'), self.admin_panel))
        self.application.add_handler(MessageHandler(filters.Regex('^🏠 Main Menu$'), self.main_menu))
        
        # Callback handlers
        self.application.add_handler(CallbackQueryHandler(self.select_amount, pattern='^amount_'))
        self.application.add_handler(CallbackQueryHandler(self.upload_proof, pattern='^upload_'))
        self.application.add_handler(CallbackQueryHandler(self.create_account_start, pattern='^create_start$'))
        self.application.add_handler(CallbackQueryHandler(self.select_plan, pattern='^plan_'))
        self.application.add_handler(CallbackQueryHandler(self.admin_approve, pattern='^approve_'))
        self.application.add_handler(CallbackQueryHandler(self.admin_reject, pattern='^reject_'))
        self.application.add_handler(CallbackQueryHandler(self.back_to_menu, pattern='^menu$'))
        
        # Message handlers
        self.application.add_handler(MessageHandler(filters.PHOTO, self.receive_payment_photo))
        
        # Conversation for account creation
        create_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.create_account_start, pattern='^create_start$')],
            states={
                CREATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_username)],
                CREATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.get_password)],
                SELECT_PLAN: [CallbackQueryHandler(self.select_plan, pattern='^plan_')]
            },
            fallbacks=[CommandHandler('cancel', self.cancel)]
        )
        self.application.add_handler(create_conv)
        
        # Payment conversation
        payment_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.upload_proof, pattern='^upload_')],
            states={
                PAYMENT_PROOF: [MessageHandler(filters.PHOTO, self.receive_payment_photo)]
            },
            fallbacks=[CommandHandler('cancel', self.cancel)]
        )
        self.application.add_handler(payment_conv)
    
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = update.effective_user
        self.db.create_user(user.id, user.username or user.first_name, Config.is_admin(user.id))
        
        keyboard = [
            [KeyboardButton("💳 Top-up Credit"), KeyboardButton("🆕 Create Account")],
            [KeyboardButton("💰 Check Credit"), KeyboardButton("👤 My Accounts")]
        ]
        
        if Config.is_admin(user.id):
            keyboard.append([KeyboardButton("👑 Admin Panel")])
        
        keyboard.append([KeyboardButton("🏠 Main Menu")])
        
        reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        
        credit = self.db.get_credit(user.id)
        credit_text = "∞ (Admin)" if Config.is_admin(user.id) else f"{credit} THB"
        
        text = f"""
🌟 Welcome to ZIVPN 🌟

Your Credit: {credit_text}
Server: {Config.SERVER_ADDRESS}
Port: {Config.SERVER_PORT}

Use buttons below:
"""
        await update.message.reply_text(text, reply_markup=reply_markup)
    
    async def topup_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        keyboard = [
            [InlineKeyboardButton("50 THB", callback_data='amount_50'),
             InlineKeyboardButton("100 THB", callback_data='amount_100')],
            [InlineKeyboardButton("150 THB", callback_data='amount_150'),
             InlineKeyboardButton("200 THB", callback_data='amount_200')],
            [InlineKeyboardButton("300 THB", callback_data='amount_300'),
             InlineKeyboardButton("500 THB", callback_data='amount_500')],
            [InlineKeyboardButton("Back", callback_data='menu')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        payment_info = f"""
💳 Top-up Credit

Bank: {Config.BANK_NAME}
Account: {Config.BANK_ACCOUNT}
Name: {Config.ACCOUNT_NAME}

Select amount:
"""
        await update.message.reply_text(payment_info, reply_markup=reply_markup)
    
    async def select_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        amount = int(query.data.split('_')[1])
        context.user_data['topup_amount'] = amount
        
        text = f"""
💰 Amount: {amount} THB

Please transfer to:
Bank: {Config.BANK_NAME}
Account: {Config.BANK_ACCOUNT}
Name: {Config.ACCOUNT_NAME}

After payment, send screenshot.
"""
        
        keyboard = [[InlineKeyboardButton("📸 Send Screenshot", callback_data='upload_')],
                   [InlineKeyboardButton("Back", callback_data='menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(text, reply_markup=reply_markup)
        return PAYMENT_PROOF
    
    async def upload_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        await query.edit_message_text("📸 Please send payment screenshot now:")
        return PAYMENT_PROOF
    
    async def receive_payment_photo(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        # FIXED: This will handle photo properly
        user = update.effective_user
        amount = context.user_data.get('topup_amount', 0)
        
        if amount == 0:
            await update.message.reply_text("Please select amount first!")
            return ConversationHandler.END
        
        photo = update.message.photo[-1]
        file_id = photo.file_id
        
        # Save payment
        payment_id = self.db.create_payment(user.id, amount, file_id)
        
        # NOTIFY ADMINS - FIXED VERSION
        for admin_id in Config.ADMIN_IDS:
            try:
                caption = f"📥 New Payment\nUser: {user.username or user.first_name}\nID: {user.id}\nAmount: {amount} THB\nPayment ID: {payment_id}"
                
                keyboard = [
                    [InlineKeyboardButton(f"✅ Approve {payment_id}", callback_data=f'approve_{payment_id}'),
                     InlineKeyboardButton(f"❌ Reject {payment_id}", callback_data=f'reject_{payment_id}')]
                ]
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await self.application.bot.send_photo(
                    chat_id=admin_id,
                    photo=file_id,
                    caption=caption,
                    reply_markup=reply_markup
                )
                logger.info(f"Notification sent to admin {admin_id}")
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
        
        await update.message.reply_text(f"✅ Screenshot received! Payment ID: {payment_id}\nWaiting for admin approval.")
        return ConversationHandler.END
    
    async def create_account_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if not Config.is_admin(user_id) and credit < 50:
            await update.message.reply_text(f"❌ Insufficient credit! You need at least 50 THB.")
            return
        
        keyboard = [[InlineKeyboardButton("Start", callback_data='create_start')],
                   [InlineKeyboardButton("Back", callback_data='menu')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text("Click Start to create VPN account:", reply_markup=reply_markup)
    
    async def create_account_start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        await query.edit_message_text("Enter VPN username (min 3 chars):")
        return CREATE_USERNAME
    
    async def get_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        username = update.message.text.strip()
        
        if len(username) < 3:
            await update.message.reply_text("❌ Username too short! Min 3 chars. Try again:")
            return CREATE_USERNAME
        
        context.user_data['username'] = username
        await update.message.reply_text("Enter VPN password (min 4 chars):")
        return CREATE_PASSWORD
    
    async def get_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        password = update.message.text.strip()
        
        if len(password) < 4:
            await update.message.reply_text("❌ Password too short! Min 4 chars. Try again:")
            return CREATE_PASSWORD
        
        context.user_data['password'] = password
        
        keyboard = [
            [InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')],
            [InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')],
            [InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')],
            [InlineKeyboardButton("Back", callback_data='menu')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text("Select plan:", reply_markup=reply_markup)
        return SELECT_PLAN
    
    async def select_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        days = int(query.data.split('_')[1])
        cost = days * 50 // 30  # 50 THB for 30 days
        
        user_id = update.effective_user.id
        username = context.user_data.get('username')
        password = context.user_data.get('password')
        
        if not username or not password:
            await query.edit_message_text("❌ Error! Please start over.")
            return ConversationHandler.END
        
        # Check credit
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text(f"❌ Insufficient credit! Need {cost} THB, you have {credit} THB.")
                return ConversationHandler.END
        
        # Create account
        success, message = self.db.create_account(user_id, username, password, days)
        
        if success:
            # Deduct credit
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            
            expire_date = datetime.now() + timedelta(days=days)
            
            text = f"""
✅ Account Created!

Username: {username}
Password: {password}
Server: {Config.SERVER_ADDRESS}
Port: {Config.SERVER_PORT}
Expires: {expire_date.strftime('%Y-%m-%d')}
Cost: {cost} THB
"""
            await query.edit_message_text(text)
        else:
            await query.edit_message_text(f"❌ Error: {message}")
        
        return ConversationHandler.END
    
    async def check_credit(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        if Config.is_admin(user_id):
            await update.message.reply_text("💰 Your Credit: ∞ (Admin)")
        else:
            await update.message.reply_text(f"💰 Your Credit: {credit} THB")
    
    async def my_accounts(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        accounts = self.db.get_user_accounts(user_id)
        
        if not accounts:
            await update.message.reply_text("No accounts found.")
            return
        
        text = "📋 Your Accounts:\n\n"
        for acc in accounts:
            acc_id, username, password, expire, active = acc
            status = "✅ Active" if active else "❌ Expired"
            text += f"User: {username}\nPass: {password}\nExpire: {expire}\nStatus: {status}\n\n"
        
        await update.message.reply_text(text)
    
    async def admin_panel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        
        if not Config.is_admin(user_id):
            await update.message.reply_text("❌ Access denied!")
            return
        
        # Get pending payments
        payments = self.db.get_pending_payments()
        
        if not payments:
            await update.message.reply_text("👑 Admin Panel\nNo pending payments.")
            return
        
        text = "👑 Admin Panel - Pending Payments:\n\n"
        for pay in payments:
            pay_id, user_id, amount, screenshot, status, admin_id, note, created, approved, username = pay
            text += f"ID: {pay_id}\nUser: {username}\nAmount: {amount} THB\nDate: {created}\n\n"
        
        await update.message.reply_text(text[:4000])
    
    async def admin_approve(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        admin_id = update.effective_user.id
        payment_id = int(query.data.split('_')[1])
        
        success, amount, user_id = self.db.approve_payment(payment_id, admin_id)
        
        if success:
            # Notify user
            try:
                await self.application.bot.send_message(
                    user_id,
                    f"✅ Payment Approved!\nAmount: {amount} THB\nPayment ID: {payment_id}"
                )
            except:
                pass
            
            await query.edit_message_text(f"✅ Payment {payment_id} approved!")
        else:
            await query.edit_message_text(f"❌ Failed to approve payment {payment_id}")
    
    async def admin_reject(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        payment_id = int(query.data.split('_')[1])
        await query.edit_message_text(f"❌ Payment {payment_id} rejected!")
    
    async def main_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if update.callback_query:
            query = update.callback_query
            await query.answer()
            await query.edit_message_text("Returning to menu...")
        
        keyboard = [
            [KeyboardButton("💳 Top-up Credit"), KeyboardButton("🆕 Create Account")],
            [KeyboardButton("💰 Check Credit"), KeyboardButton("👤 My Accounts")]
        ]
        
        if Config.is_admin(update.effective_user.id):
            keyboard.append([KeyboardButton("👑 Admin Panel")])
        
        keyboard.append([KeyboardButton("🏠 Main Menu")])
        
        reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        await update.message.reply_text("Main Menu:", reply_markup=reply_markup)
    
    async def back_to_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        query = update.callback_query
        await query.answer()
        
        await self.main_menu(update, context)
    
    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text("Cancelled.")
        return ConversationHandler.END
    
    def run(self):
        print("Starting bot...")
        self.application.run_polling(drop_pending_updates=True)

if __name__ == '__main__':
    bot = ZivpnBot()
    bot.run()
EOF

# Create .env file
cat > .env <<EOF
BOT_TOKEN=$BOT_TOKEN
ADMIN_IDS=$ADMIN_IDS
ADMIN_TOKEN=$ADMIN_TOKEN
SERVER_ADDRESS=$SERVER_ADDRESS
SERVER_PORT=5667
BANK_ACCOUNT=$BANK_ACCOUNT
BANK_NAME=$BANK_NAME
ACCOUNT_NAME=$ACCOUNT_NAME
EOF

# Initialize database
print_status "Initializing database..."
cat <<'EOF' > init_db.py
from database import Database
db = Database()
print("Database initialized!")
EOF
python3 init_db.py

# Create systemd service for bot
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
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Start bot
systemctl daemon-reload
systemctl enable zivpn-bot.service
systemctl start zivpn-bot.service

sleep 3
if systemctl is-active --quiet zivpn-bot.service; then
    print_success "Bot service is running!"
else
    print_error "Bot service failed to start"
    journalctl -u zivpn-bot.service -n 10 --no-pager
fi

# Summary
echo -e "\n${GREEN}=== Installation Complete! ===${NC}"
echo -e "VPN Server: ${SERVER_ADDRESS}:5667"
echo -e "Admin IDs: ${ADMIN_IDS}"
echo -e "Bank: ${BANK_NAME} - ${BANK_ACCOUNT}"
echo -e "\n${YELLOW}=== Commands ===${NC}"
echo "Check VPN status: systemctl status zivpn.service"
echo "Check Bot status: systemctl status zivpn-bot.service"
echo "VPN logs: journalctl -u zivpn.service -f"
echo "Bot logs: journalctl -u zivpn-bot.service -f"
echo -e "\n${GREEN}Bot is ready! Start chatting with your bot.${NC}"
