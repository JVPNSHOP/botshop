#!/bin/bash

# Zivpn UDP Module + Telegram Bot Installer
# Creator: Zahid Islam
# Fixed Version: Authentication + Bot Button Issues

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Zivpn UDP VPN + Telegram Bot Installer ===${NC}"
echo -e "${YELLOW}Creator: Zahid Islam${NC}"
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
    apt-get install -y python3 python3-pip python3-venv git wget curl openssl ufw jq
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
    cat << 'EOF' > /etc/zivpn/config.json
{
  "listen": ":5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "timeout": 60,
  "resolver": "1.1.1.1",
  "log_level": "info",
  "stats": {
    "listen": "127.0.0.1:9000"
  },
  "config": ["zi"]
}
EOF
    
    # Generate certificates
    print_status "Generating SSL certificates..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
        -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"
    
    # Configure passwords
    echo -e "${YELLOW}=== ZIVPN UDP Passwords ===${NC}"
    read -p "Enter passwords separated by commas (Press enter for Default 'zi'): " input_config
    
    if [ -n "$input_config" ]; then
        IFS=',' read -r -a config <<< "$input_config"
        if [ ${#config[@]} -eq 1 ]; then
            config+=(${config[0]})
        fi
    else
        config=("zi")
    fi
    
    # Update config.json with passwords
    echo "["$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')"]" | jq . > /tmp/passwords.json
    jq --argjson pass "$(cat /tmp/passwords.json)" '.config = $pass' /etc/zivpn/config.json > /tmp/config.json
    mv /tmp/config.json /etc/zivpn/config.json
    
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
    sysctl -w net.ipv4.ip_forward=1 2>/dev/null
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service
    
    # Configure firewall
    if command -v ufw &> /dev/null; then
        ufw allow 6000:19999/udp
        ufw allow 5667/udp
        ufw allow 22/tcp
        ufw --force enable
    fi
    
    # Add iptables rules
    iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
    iptables -t nat -A OUTPUT -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667
    
    print_success "Zivpn UDP VPN installed successfully!"
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
    read -p "Enter Your Hostname (e.g., jvpn.shop, press Enter to use IP): " SERVER_HOSTNAME
    
    # Get admin configuration
    echo ""
    read -p "Enter Admin Token (default: admin123): " ADMIN_TOKEN
    ADMIN_TOKEN=${ADMIN_TOKEN:-admin123}
    
    read -p "Enter Admin IDs (comma separated, e.g., 123456789,987654321): " ADMIN_IDS
    
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
    read -p "Enter Bank QR Image Link (Direct URL, press Enter to skip): " QR_IMAGE_URL
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
    
    print_success "Telegram Bot installed successfully!"
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

    # Create database.py with VPN password management
    cat << 'EOF' > /opt/zivpn-bot/database.py
import sqlite3
import json
from datetime import datetime, timedelta
import hashlib
import subprocess
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
    
    def add_password_to_vpn_config(self, password):
        """Add password to VPN config.json and restart service"""
        try:
            with open(Config.VPN_CONFIG_PATH, 'r') as f:
                config = json.load(f)
            
            # Check if password already exists
            if password in config.get("config", []):
                return True
            
            # Add new password
            config["config"].append(password)
            
            # Save config
            with open(Config.VPN_CONFIG_PATH, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Restart VPN service
            subprocess.run(['systemctl', 'restart', 'zivpn.service'], 
                         capture_output=True, text=True)
            return True
        except Exception as e:
            print(f"Error updating VPN config: {e}")
            return False
    
    def create_account(self, user_id, username, password, days):
        cursor = self.conn.cursor()
        expire_date = datetime.now() + timedelta(days=days)
        
        # Check if username already exists
        cursor.execute('SELECT id FROM accounts WHERE vpn_username = ?', (username,))
        if cursor.fetchone():
            return False, "Username already exists"
        
        try:
            # First add password to VPN config
            if not self.add_password_to_vpn_config(password):
                return False, "Failed to update VPN configuration"
            
            # Then create account in database
            cursor.execute('''
                INSERT INTO accounts (user_id, vpn_username, vpn_password, expire_date)
                VALUES (?, ?, ?, ?)
            ''', (user_id, username, password, expire_date))
            
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

    # Create bot.py - FIXED VERSION
    cat << 'EOF' > /opt/zivpn-bot/bot.py
#!/usr/bin/env python3
import logging
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

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Conversation states
SELECT_AMOUNT, UPLOAD_PROOF = range(2)
INPUT_USERNAME, INPUT_PASSWORD, SELECT_PLAN = range(2, 5)
ADMIN_MENU, ADMIN_ACTION = range(5, 7)

class ZivpnBot:
    def __init__(self):
        self.db = Database(Config.DB_NAME)
        self.application = Application.builder().token(Config.BOT_TOKEN).build()
        self.setup_handlers()
    
    def setup_handlers(self):
        """Setup all handlers"""
        # Basic commands
        self.application.add_handler(CommandHandler("start", self.start))
        self.application.add_handler(CommandHandler("menu", self.menu))
        self.application.add_handler(CommandHandler("help", self.help))
        
        # Menu callbacks
        self.application.add_handler(CallbackQueryHandler(self.topup_menu, pattern='^topup$'))
        self.application.add_handler(CallbackQueryHandler(self.create_account_menu, pattern='^create$'))
        self.application.add_handler(CallbackQueryHandler(self.check_credit_callback, pattern='^check_credit$'))
        self.application.add_handler(CallbackQueryHandler(self.admin_menu_callback, pattern='^admin$'))
        self.application.add_handler(CallbackQueryHandler(self.back_to_main, pattern='^main$'))
        
        # Top-up conversation
        topup_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.select_amount, pattern='^amount_')],
            states={
                SELECT_AMOUNT: [CallbackQueryHandler(self.process_amount, pattern='^pay_')],
                UPLOAD_PROOF: [MessageHandler(filters.PHOTO, self.upload_proof)]
            },
            fallbacks=[
                CommandHandler("cancel", self.cancel),
                CallbackQueryHandler(self.cancel, pattern='^cancel$')
            ]
        )
        
        # Create account conversation
        create_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.input_username, pattern='^start_create$')],
            states={
                INPUT_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.process_username)],
                INPUT_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, self.process_password)],
                SELECT_PLAN: [CallbackQueryHandler(self.process_plan, pattern='^plan_')]
            },
            fallbacks=[
                CommandHandler("cancel", self.cancel),
                CallbackQueryHandler(self.cancel, pattern='^cancel$')
            ]
        )
        
        # Admin conversation
        admin_conv = ConversationHandler(
            entry_points=[CallbackQueryHandler(self.admin_menu, pattern='^admin_menu$')],
            states={
                ADMIN_MENU: [CallbackQueryHandler(self.admin_actions, pattern='^admin_')],
                ADMIN_ACTION: [CallbackQueryHandler(self.process_admin_action, pattern='^action_')]
            },
            fallbacks=[
                CommandHandler("cancel", self.cancel),
                CallbackQueryHandler(self.cancel, pattern='^cancel$')
            ]
        )
        
        self.application.add_handler(topup_conv)
        self.application.add_handler(create_conv)
        self.application.add_handler(admin_conv)
        
        # Other callbacks
        self.application.add_handler(CallbackQueryHandler(self.handle_callback))
    
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        user = update.effective_user
        user_id = user.id
        
        # Clear any existing conversation data
        if context.user_data:
            context.user_data.clear()
        
        # Create user in database
        is_admin = Config.is_admin(user_id)
        self.db.create_user(user_id, user.username or user.first_name, is_admin)
        
        await self.show_main_menu(update, context, user_id, is_admin)
    
    async def menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /menu command"""
        user = update.effective_user
        user_id = user.id
        
        # Clear conversation data
        if context.user_data:
            context.user_data.clear()
        
        is_admin = Config.is_admin(user_id)
        await self.show_main_menu(update, context, user_id, is_admin)
    
    async def help(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_text = """
🤖 *ZIVPN Bot Commands:*

/start - Start the bot
/menu - Show main menu
/help - Show this help message
/cancel - Cancel current operation

📱 *Main Features:*
1. 💳 Top-up Credit
2. 🆕 Create VPN Account
3. 💰 Check Credit Balance
4. 👑 Admin Panel (for admins)

🌐 *Server Info:*
• Server: `{server}`
• Port: `{port}`
• Max Devices: 1
        """.format(server=Config.SERVER_ADDRESS, port=Config.SERVER_PORT)
        
        await update.message.reply_text(help_text, parse_mode='Markdown')
    
    async def cancel(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Cancel any ongoing operation"""
        user = update.effective_user
        user_id = user.id
        
        # Clear conversation data
        if context.user_data:
            context.user_data.clear()
        
        is_admin = Config.is_admin(user_id)
        
        # Send cancellation message
        if update.callback_query:
            await update.callback_query.answer()
            await update.callback_query.edit_message_text("❌ Operation cancelled.")
        elif update.message:
            await update.message.reply_text("❌ Operation cancelled.")
        
        # Return to main menu
        await self.show_main_menu(update, context, user_id, is_admin)
        return ConversationHandler.END
    
    async def show_main_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE, user_id: int, is_admin: bool):
        """Show main menu"""
        keyboard = [
            [InlineKeyboardButton("💳 Top-up Credit", callback_data='topup')],
            [InlineKeyboardButton("🆕 Create Account", callback_data='create')],
            [InlineKeyboardButton("💰 Check Credit", callback_data='check_credit')],
        ]
        
        if is_admin:
            keyboard.append([InlineKeyboardButton("👑 Admin Panel", callback_data='admin')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        credit = self.db.get_credit(user_id)
        if is_admin:
            credit_display = "∞ (Admin)"
        else:
            credit_display = f"{credit} {Config.CURRENCY}"
        
        welcome_text = f"""
🌟 *Welcome to ZIVPN VPN Service!* 🌟

📊 *Your Credit:* `{credit_display}`
🌐 *Server:* `{Config.SERVER_ADDRESS}:{Config.SERVER_PORT}`
💵 *Currency:* {Config.CURRENCY}

*Choose an option:*
        """
        
        try:
            if update.callback_query:
                await update.callback_query.edit_message_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')
            else:
                await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode='Markdown')
        except Exception as e:
            logger.error(f"Error showing main menu: {e}")
    
    async def back_to_main(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Back to main menu"""
        query = update.callback_query
        await query.answer()
        
        user = update.effective_user
        user_id = user.id
        
        # Clear conversation data
        if context.user_data:
            context.user_data.clear()
        
        is_admin = Config.is_admin(user_id)
        await self.show_main_menu(update, context, user_id, is_admin)
    
    async def topup_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show top-up menu"""
        query = update.callback_query
        await query.answer()
        
        # Clear any existing data
        if context.user_data:
            context.user_data.clear()
        
        keyboard = [
            [
                InlineKeyboardButton("50 THB", callback_data='amount_50'),
                InlineKeyboardButton("100 THB", callback_data='amount_100')
            ],
            [
                InlineKeyboardButton("150 THB", callback_data='amount_150'),
                InlineKeyboardButton("200 THB", callback_data='amount_200')
            ],
            [InlineKeyboardButton("🔙 Back to Menu", callback_data='main')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "💳 *Select Top-up Amount:*\n\n"
            "Choose the amount you want to top-up:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def select_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Select amount for top-up"""
        query = update.callback_query
        await query.answer()
        
        # Get selected amount
        amount = int(query.data.split('_')[1])
        context.user_data['amount'] = amount
        
        # Check if user is admin (admins don't need to pay)
        user_id = update.effective_user.id
        if Config.is_admin(user_id):
            # Auto-approve for admin
            self.db.update_credit(user_id, amount)
            await query.edit_message_text(
                f"✅ *Admin Top-up Successful!*\n\n"
                f"Added {amount} {Config.CURRENCY} to your account.",
                parse_mode='Markdown'
            )
            return ConversationHandler.END
        
        # Show payment information
        payment_info = f"""
💰 *Payment Information ({Config.CURRENCY}):*

🏦 *Bank:* {Config.BANK_NAME}
💳 *Account:* {Config.BANK_ACCOUNT}
👤 *Name:* {Config.ACCOUNT_NAME}
💵 *Amount:* {amount} {Config.CURRENCY}

*Please transfer the exact amount.*
        """
        
        # Show QR code if available
        if Config.QR_IMAGE_URL and Config.QR_IMAGE_URL.startswith('http'):
            try:
                await query.message.reply_photo(
                    photo=Config.QR_IMAGE_URL,
                    caption=f"Scan QR code to pay {amount} {Config.CURRENCY}"
                )
            except:
                # Generate QR code
                qr = qrcode.QRCode(version=1, box_size=10, border=5)
                qr.add_data(f"banktransfer:{Config.BANK_ACCOUNT}:{amount}")
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                bio = BytesIO()
                img.save(bio, 'PNG')
                bio.seek(0)
                await query.message.reply_photo(
                    photo=bio,
                    caption=f"Scan QR code to pay {amount} {Config.CURRENCY}"
                )
        
        await query.edit_message_text(payment_info, parse_mode='Markdown')
        
        keyboard = [
            [InlineKeyboardButton("✅ I Have Paid", callback_data=f'pay_{amount}')],
            [InlineKeyboardButton("🔙 Cancel", callback_data='cancel')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.message.reply_text(
            "Click 'I Have Paid' after making payment, then upload screenshot:",
            reply_markup=reply_markup
        )
        
        return SELECT_AMOUNT
    
    async def process_amount(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process payment confirmation"""
        query = update.callback_query
        await query.answer()
        
        amount = context.user_data.get('amount', 0)
        
        await query.edit_message_text(
            f"📸 *Upload Payment Proof*\n\n"
            f"Please send the payment screenshot for {amount} {Config.CURRENCY}.\n\n"
            f"Or click /cancel to cancel.",
            parse_mode='Markdown'
        )
        
        return UPLOAD_PROOF
    
    async def upload_proof(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle payment proof upload"""
        user_id = update.effective_user.id
        amount = context.user_data.get('amount', 0)
        
        # Get the photo
        photo = update.message.photo[-1]
        file_id = photo.file_id
        
        # Save payment record
        payment_id = self.db.create_payment(user_id, amount, file_id)
        
        await update.message.reply_text(
            f"✅ *Payment Proof Received!*\n\n"
            f"*Amount:* {amount} {Config.CURRENCY}\n"
            f"*Payment ID:* {payment_id}\n\n"
            f"Please wait for admin approval.",
            parse_mode='Markdown'
        )
        
        # Notify admins
        for admin_id in Config.ADMIN_IDS:
            try:
                await self.application.bot.send_message(
                    admin_id,
                    f"📥 *New Payment Request!*\n\n"
                    f"*User:* @{update.effective_user.username or user_id}\n"
                    f"*Amount:* {amount} {Config.CURRENCY}\n"
                    f"*Payment ID:* {payment_id}\n\n"
                    f"Check with /admin",
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Failed to notify admin {admin_id}: {e}")
        
        # Clear conversation data
        context.user_data.clear()
        
        await self.menu(update, context)
        return ConversationHandler.END
    
    async def create_account_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Show create account menu"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        # Check credit
        if not Config.is_admin(user_id) and credit < 50:
            await query.edit_message_text(
                f"❌ *Insufficient Credit!*\n\n"
                f"Your credit: {credit} {Config.CURRENCY}\n"
                f"Minimum required: 50 {Config.CURRENCY}\n\n"
                f"Please top-up first.",
                parse_mode='Markdown'
            )
            return
        
        await query.edit_message_text(
            "🆕 *Create VPN Account*\n\n"
            "Please enter your desired VPN username (3-15 characters, letters and numbers only):",
            parse_mode='Markdown'
        )
        
        return INPUT_USERNAME
    
    async def input_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Start username input"""
        return await self.create_account_menu(update, context)
    
    async def process_username(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process username input"""
        username = update.message.text.strip()
        
        # Validate username
        if len(username) < 3 or len(username) > 15:
            await update.message.reply_text(
                "❌ Username must be 3-15 characters.\n"
                "Please enter again:"
            )
            return INPUT_USERNAME
        
        if not username.isalnum():
            await update.message.reply_text(
                "❌ Username can only contain letters and numbers.\n"
                "Please enter again:"
            )
            return INPUT_USERNAME
        
        context.user_data['username'] = username
        
        await update.message.reply_text(
            "Now enter your desired VPN password (4-20 characters):"
        )
        
        return INPUT_PASSWORD
    
    async def process_password(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process password input"""
        password = update.message.text.strip()
        
        # Validate password
        if len(password) < 4 or len(password) > 20:
            await update.message.reply_text(
                "❌ Password must be 4-20 characters.\n"
                "Please enter again:"
            )
            return INPUT_PASSWORD
        
        context.user_data['password'] = password
        
        # Show plan selection
        user_id = update.effective_user.id
        credit = self.db.get_credit(user_id)
        
        keyboard = []
        
        if Config.is_admin(user_id) or credit >= 50:
            keyboard.append([InlineKeyboardButton("30 Days - 50 THB", callback_data='plan_30')])
        
        if Config.is_admin(user_id) or credit >= 100:
            keyboard.append([InlineKeyboardButton("60 Days - 100 THB", callback_data='plan_60')])
        
        if Config.is_admin(user_id) or credit >= 150:
            keyboard.append([InlineKeyboardButton("90 Days - 150 THB", callback_data='plan_90')])
        
        keyboard.append([InlineKeyboardButton("🔙 Cancel", callback_data='cancel')])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await update.message.reply_text(
            "Select subscription plan:",
            reply_markup=reply_markup
        )
        
        return SELECT_PLAN
    
    async def process_plan(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process plan selection"""
        query = update.callback_query
        await query.answer()
        
        days = int(query.data.split('_')[1])
        cost = (days // 30) * 50  # 50 THB per 30 days
        
        user_id = update.effective_user.id
        username = context.user_data.get('username')
        password = context.user_data.get('password')
        
        # Check credit for non-admin users
        if not Config.is_admin(user_id):
            credit = self.db.get_credit(user_id)
            if credit < cost:
                await query.edit_message_text("❌ Insufficient credit!")
                return ConversationHandler.END
        
        # Create account
        success, message = self.db.create_account(user_id, username, password, days)
        
        if success:
            # Deduct credit (not for admin)
            if not Config.is_admin(user_id):
                self.db.update_credit(user_id, -cost)
            
            # Calculate expire date
            expire_date = datetime.now() + timedelta(days=days)
            
            account_info = f"""
✅ *Account Created Successfully!*

*Server Details:*
🌐 *Server:* `{Config.SERVER_ADDRESS}`
🔌 *Port:* `{Config.SERVER_PORT}`
👤 *Username:* `{username}`
🔑 *Password:* `{password}`
📅 *Expire Date:* {expire_date.strftime('%Y-%m-%d')}
🔒 *Max Devices:* 1

*Connection Instructions:*
1. Download VPN client
2. Use above credentials
3. Connect to server

⚠️ *Note:* Only first device can connect.
            """
            
            await query.edit_message_text(account_info, parse_mode='Markdown')
        else:
            await query.edit_message_text(f"❌ Error: {message}")
        
        # Clear conversation data
        context.user_data.clear()
        
        return ConversationHandler.END
    
    async def check_credit_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Check credit callback"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        
        if Config.is_admin(user_id):
            credit_display = "∞ (Admin)"
        else:
            credit = self.db.get_credit(user_id)
            credit_display = f"{credit} {Config.CURRENCY}"
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data='main')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            f"💰 *Your Credit:* {credit_display}",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def admin_menu_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Admin menu callback"""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        
        if not Config.is_admin(user_id):
            await query.edit_message_text("❌ Access denied!")
            return
        
        keyboard = [
            [InlineKeyboardButton("👥 View Users", callback_data='admin_users')],
            [InlineKeyboardButton("📊 Pending Payments", callback_data='admin_payments')],
            [InlineKeyboardButton("📈 Statistics", callback_data='admin_stats')],
            [InlineKeyboardButton("🔙 Back to Menu", callback_data='main')]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "👑 *Admin Panel*\n\nSelect an option:",
            reply_markup=reply_markup,
            parse_mode='Markdown'
        )
    
    async def admin_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Admin menu entry point"""
        return await self.admin_menu_callback(update, context)
    
    async def admin_actions(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle admin actions"""
        query = update.callback_query
        await query.answer()
        
        action = query.data
        
        if action == 'admin_users':
            users = self.db.get_all_users()
            
            if not users:
                text = "No users found."
            else:
                text = "👥 *User List:*\n\n"
                for user in users:
                    user_id, username, credit, account_count, join_date, is_admin = user
                    
                    admin_badge = "👑" if is_admin else "👤"
                    credit_display = "∞" if is_admin else f"{credit} {Config.CURRENCY}"
                    
                    text += f"{admin_badge} *ID:* {user_id}\n"
                    text += f"*Username:* {username or 'N/A'}\n"
                    text += f"*Credit:* {credit_display}\n"
                    text += f"*Accounts:* {account_count}\n"
                    text += f"*Joined:* {join_date}\n"
                    text += "─" * 20 + "\n"
            
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(text[:4000], reply_markup=reply_markup, parse_mode='Markdown')
        
        elif action == 'admin_payments':
            payments = self.db.get_pending_payments()
            
            if not payments:
                text = "No pending payments."
                keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin')]]
                reply_markup = InlineKeyboardMarkup(keyboard)
                await query.edit_message_text(text, reply_markup=reply_markup)
            else:
                text = "📊 *Pending Payments:*\n\n"
                keyboard = []
                
                for payment in payments:
                    payment_id, user_id, amount, screenshot, status, admin_id, admin_note, created_date, approved_date, username = payment
                    
                    text += f"*ID:* {payment_id}\n"
                    text += f"*User:* {username or user_id}\n"
                    text += f"*Amount:* {amount} {Config.CURRENCY}\n"
                    text += f"*Date:* {created_date}\n"
                    
                    callback_data = f"action_approve_{payment_id}"
                    keyboard.append([InlineKeyboardButton(f"✅ Approve #{payment_id}", callback_data=callback_data)])
                    
                    text += "─" * 20 + "\n"
                
                keyboard.append([InlineKeyboardButton("🔙 Back", callback_data='admin')])
                reply_markup = InlineKeyboardMarkup(keyboard)
                
                await query.edit_message_text(text[:4000], reply_markup=reply_markup, parse_mode='Markdown')
                return ADMIN_ACTION
        
        elif action == 'admin_stats':
            total_users = self.db.get_total_users()
            active_accounts = self.db.get_active_accounts()
            
            text = f"""
📈 *System Statistics:*

👥 *Total Users:* {total_users}
🔧 *Active Accounts:* {active_accounts}
👑 *Admin Users:* {len(Config.ADMIN_IDS)}
🌐 *Server:* {Config.SERVER_ADDRESS}
🔌 *VPN Port:* {Config.SERVER_PORT}
💵 *Currency:* {Config.CURRENCY}
"""
            keyboard = [[InlineKeyboardButton("🔙 Back", callback_data='admin')]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.edit_message_text(text, reply_markup=reply_markup, parse_mode='Markdown')
        
        return ADMIN_MENU
    
    async def process_admin_action(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Process admin actions"""
        query = update.callback_query
        await query.answer()
        
        if query.data.startswith('action_approve_'):
            payment_id = int(query.data.split('_')[2])
            admin_id = update.effective_user.id
            
            success = self.db.approve_payment(payment_id, admin_id)
            
            if success:
                await query.edit_message_text(f"✅ Payment #{payment_id} approved!")
            else:
                await query.edit_message_text(f"❌ Failed to approve payment!")
        
        keyboard = [[InlineKeyboardButton("🔙 Back to Admin", callback_data='admin')]]
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.message.reply_text("Return:", reply_markup=reply_markup)
        return ConversationHandler.END
    
    async def handle_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle other callbacks"""
        query = update.callback_query
        await query.answer()
        
        # Handle unknown callbacks
        await query.edit_message_text("Unknown command. Use /menu to return to main menu.")
    
    def run(self):
        """Run the bot"""
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

    # Create .env file
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
After=network.target zivpn.service
Requires=zivpn.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/zivpn-bot
Environment="PATH=/opt/zivpn-bot/venv/bin"
ExecStart=/opt/zivpn-bot/venv/bin/python3 bot.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

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
    echo -e "Server Address: ${GREEN}$SERVER_ADDRESS${NC}"
    echo -e "Server Port: ${GREEN}5667${NC}"
    echo -e "VPN Passwords: ${GREEN}Added to config.json${NC}"
    echo -e "Admin Token: ${GREEN}$ADMIN_TOKEN${NC}"
    echo -e "Admin IDs: ${GREEN}$ADMIN_IDS${NC}"
    echo -e "Telegram Bot: $( [[ "$install_bot_choice" =~ ^[Yy]$ ]] && echo "${GREEN}Installed${NC}" || echo "${YELLOW}Skipped${NC}" )"
    
    echo -e "\n${YELLOW}=== Service Status ===${NC}"
    systemctl status zivpn.service --no-pager
    
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo ""
        systemctl status zivpn-bot.service --no-pager
    fi
    
    echo -e "\n${YELLOW}=== VPN Configuration ===${NC}"
    echo -e "🌐 Server: $SERVER_ADDRESS"
    echo -e "🔌 Port: 5667"
    echo -e "📡 UDP Ports: 6000-19999"
    echo -e "🔑 Passwords: Check /etc/zivpn/config.json"
    
    echo -e "\n${YELLOW}=== Bot Features ===${NC}"
    echo -e "💳 Top-up Credit System"
    echo -e "🆕 Auto VPN Account Creation"
    echo -e "💰 Credit Balance Check"
    echo -e "👑 Admin Panel with Unlimited Credit"
    echo -e "🏦 Bank: $BANK_NAME"
    echo -e "💳 Account: $BANK_ACCOUNT"
    echo -e "👤 Account Name: $ACCOUNT_NAME"
    
    if [ -n "$QR_IMAGE_URL" ]; then
        echo -e "📷 QR Code: Enabled"
    fi
    
    echo -e "\n${GREEN}=== Important Notes ===${NC}"
    echo -e "1. VPN passwords are automatically added when creating accounts"
    echo -e "2. Make sure ports 6000-19999/udp are open in firewall"
    echo -e "3. Admin users have unlimited credit"
    echo -e "4. Use /menu command in bot to access main menu"
    
    if [[ "$install_bot_choice" =~ ^[Yy]$ ]]; then
        echo -e "\n${YELLOW}=== Bot Troubleshooting ===${NC}"
        echo -e "1. Check bot status: systemctl status zivpn-bot.service"
        echo -e "2. View bot logs: journalctl -u zivpn-bot.service -f"
        echo -e "3. Check VPN status: systemctl status zivpn.service"
        echo -e "4. Restart services: systemctl restart zivpn.service zivpn-bot.service"
    fi
    
    echo -e "\n${GREEN}=== Installation completed successfully! ===${NC}"
}

# Run installation
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

main_installation
