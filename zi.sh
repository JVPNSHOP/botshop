#!/usr/bin/env bash

# install_zivpn_full_fix.sh
# Full ZIVPN + Telegram bot installer + Auto-Expire monitor (safer behavior)
# - ZIVPN UDP server on 0.0.0.0:5667
# - BROAD_DNAT (UDP 1-65535 -> 5667) for IP-only clients
# - Telegram bot with credit, topup, create/renew/delete account
# - Create Account now has ✅ Add Account / ❌ Cancel confirmation
# - ZIVPN password list atomic update + debounced service restart
# - Monitor: detect multi-device -> update accounts.used_devices + notify owner/admin
#   (DOES NOT auto-remove password nor restart service)
# - Admin Panel shows Active device count; Admin Delete triggers removal + debounced restart

set -euo pipefail

############################
# CONFIG
############################
# If BROAD_DNAT=true the script will DNAT all incoming UDP ports (1:65535) to local 5667.
BROAD_DNAT=true

ZIVPN_BIN=/usr/local/bin/zivpn
ZIVPN_ETC=/etc/zivpn
ZIVPN_SYSTEMD=/etc/systemd/system/zivpn.service

BOT_DIR=/opt/zivpn_bot
BOT_SERVICE=/etc/systemd/system/zivpn-bot.service
BOT_VENV=$BOT_DIR/venv
BOT_PY=$BOT_DIR/bot.py

BOT_CONFIG=$ZIVPN_ETC/bot_config.json
ACCOUNTS_JSON=$ZIVPN_ETC/accounts.json
USERS_JSON=$ZIVPN_ETC/users.json
TOPUPS_JSON=$ZIVPN_ETC/topups.json
ZIVPN_CONFIG=$ZIVPN_ETC/config.json

MONITOR_PY=$BOT_DIR/monitor_auth.py
MONITOR_SERVICE=/etc/systemd/system/zivpn-monitor.service

mkdir -p "$ZIVPN_ETC"
mkdir -p "$BOT_DIR"

export DEBIAN_FRONTEND=noninteractive

echo -e "\n=== Updating packages ==="
apt-get update -y
apt-get upgrade -y

echo -e "\n=== Stop existing services (if any) ==="
systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
systemctl stop zivpn-bot.service 1>/dev/null 2>/dev/null || true
systemctl stop zivpn-monitor.service 1>/dev/null 2>/dev/null || true

echo -e "\n=== Downloading ZIVPN binary (if available) ==="
ZIVPN_RELEASE_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
if curl -fsSL "$ZIVPN_RELEASE_URL" -o "$ZIVPN_BIN"; then
    chmod +x "$ZIVPN_BIN"
    echo "zivpn installed to $ZIVPN_BIN"
else
    echo "Warning: failed to download zivpn binary (continuing if $ZIVPN_BIN already exists)"
fi

############################
# CERT / KEY
############################
if [ ! -f "$ZIVPN_ETC/zivpn.key" ] || [ ! -f "$ZIVPN_ETC/zivpn.crt" ]; then
    echo "Generating self-signed cert/key for ZIVPN..."
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=ZIVPN/OU=IT/CN=zivpn" \
        -keyout "$ZIVPN_ETC/zivpn.key" -out "$ZIVPN_ETC/zivpn.crt" 1>/dev/null 2>/dev/null || true
fi

chmod 600 "$ZIVPN_ETC/zivpn.key" || true
chmod 644 "$ZIVPN_ETC/zivpn.crt" || true

############################
# ZIVPN CONFIG
############################
if [ ! -f "$ZIVPN_CONFIG" ]; then
    cat > "$ZIVPN_CONFIG" <<JSON
{
  "listen": "0.0.0.0:5667",
  "cert": "/etc/zivpn/zivpn.crt",
  "key": "/etc/zivpn/zivpn.key",
  "obfs": "",
  "auth": {
    "mode": "passwords",
    "config": [
      "zi"
    ]
  }
}
JSON
    echo "Created default $ZIVPN_CONFIG"
else
    echo "Patching existing $ZIVPN_CONFIG"
    # force listen
    if grep -q '"listen"' "$ZIVPN_CONFIG"; then
        sed -i 's/"listen"[[:space:]]:[[:space:]]".*"/"listen": "0.0.0.0:5667"/' "$ZIVPN_CONFIG" || true
    fi
    # ensure cert/key/obfs/auth.mode/config
    if ! grep -q '"cert"' "$ZIVPN_CONFIG"; then
        sed -i '1s#^{#{\n "cert": "/etc/zivpn/zivpn.crt",#' "$ZIVPN_CONFIG" || true
    fi
    if ! grep -q '"key"' "$ZIVPN_CONFIG"; then
        sed -i '1s#^{#{\n "key": "/etc/zivpn/zivpn.key",#' "$ZIVPN_CONFIG" || true
    fi
    if ! grep -q '"obfs"' "$ZIVPN_CONFIG"; then
        sed -i '1s#^{#{\n "obfs": "",#' "$ZIVPN_CONFIG" || true
    fi
    if ! grep -q '"auth"' "$ZIVPN_CONFIG"; then
        # append minimal auth
        sed -i 's#}$#,\n "auth": {"mode":"passwords","config":["zi"]}\n}#' "$ZIVPN_CONFIG" || true
    fi
fi

############################
# SYSTEMD UNIT
############################
cat > "$ZIVPN_SYSTEMD" <<'SERVICE'
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
SERVICE

systemctl daemon-reload
systemctl enable zivpn.service
systemctl restart zivpn.service || systemctl start zivpn.service || true

############################
# NETWORK / IPTABLES
############################
INET_IF=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1 || echo "eth0")
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")

if [ -z "$SERVER_IP" ]; then
    echo "Warning: couldn't detect server IP automatically. You'll be prompted later in bot setup."
fi

echo -e "\n=== Configuring iptables NAT rules ==="
# clear PREROUTING rules (only table, not whole iptables)
iptables -t nat -F PREROUTING 2>/dev/null || true

# default DNAT range 6000:19999 -> 5667
iptables -t nat -A PREROUTING -i "$INET_IF" -p udp --dport 6000:19999 -j DNAT --to-destination "$SERVER_IP":5667 1>/dev/null 2>/dev/null || true

# optional BROAD DNAT for IP-only clients
if [ "$BROAD_DNAT" = true ]; then
    echo "Adding BROAD DNAT: udp 1-65535 -> ${SERVER_IP}:5667"
    iptables -t nat -C PREROUTING -i "$INET_IF" -p udp --dport 1:65535 -j DNAT --to-destination "$SERVER_IP":5667 2>/dev/null || \
    iptables -t nat -A PREROUTING -i "$INET_IF" -p udp --dport 1:65535 -j DNAT --to-destination "$SERVER_IP":5667 1>/dev/null 2>/dev/null || true
fi

# masquerade
iptables -t nat -C POSTROUTING -o "$INET_IF" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$INET_IF" -j MASQUERADE 1>/dev/null 2>/dev/null || true

# ufw ports
ufw allow 5667/udp || true
ufw allow 6000:19999/udp || true

if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save 1>/dev/null 2>/dev/null || true
fi

echo -e "\n=== ZIVPN basic setup done ==="

############################
# BOT SETUP
############################
echo -e "\n--- Telegram Bot Setup ---"
echo "Please enter the following details:"
echo ""

read -rp "Enter Your Server IP Address (public IP) [press Enter to accept detected $SERVER_IP]: " INPUT_SERVER_IP
if [ -n "$INPUT_SERVER_IP" ]; then
    SERVER_IP="$INPUT_SERVER_IP"
fi

read -rp "Enter Hostname (e.g., jvpn.com) [optional]: " HOSTNAME
read -rp "Enter Admin Bot Token (from BotFather): " BOT_TOKEN
read -rp "Enter Admin Telegram ID (numeric): " ADMIN_ID
read -rp "Enter Bank Name: " BANK_NAME
read -rp "Enter Bank Account Number: " BANK_NUMBER
read -rp "Enter Account Holder Name: " BANK_HOLDER
read -rp "Enter QR Code Link (optional): " QR_LINK

cat > "$BOT_CONFIG" <<JSON
{
  "bot_token": "${BOT_TOKEN}",
  "admin_id": ${ADMIN_ID},
  "hostname": "${HOSTNAME}",
  "server_ip": "${SERVER_IP}",
  "bank_name": "${BANK_NAME}",
  "bank_number": "${BANK_NUMBER}",
  "bank_holder": "${BANK_HOLDER}",
  "qr_link": "${QR_LINK}"
}
JSON

for f in "$ACCOUNTS_JSON" "$USERS_JSON" "$TOPUPS_JSON"; do
    [ -f "$f" ] || echo "[]" > "$f"
done

############################
# BOT PYTHON CODE (updated: atomic writes, debounce restart, Active device count)
############################
cat > "$BOT_PY" <<'PY'
#!/usr/bin/env python3
"""
ZIVPN Telegram Bot (with safer monitor interaction)
- atomic file writes
- debounced zivpn restart
- admin panel shows Active Devices (from accounts.used_devices)
- admin delete triggers password removal + debounced restart
"""
import json, logging, os, time, datetime, uuid, socket, subprocess, traceback, tempfile
from functools import wraps

from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton,
    ReplyKeyboardMarkup, ReplyKeyboardRemove
)
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes,
    filters, CallbackQueryHandler, ConversationHandler
)

BASE_ETC = "/etc/zivpn"
BOT_CONFIG = os.path.join(BASE_ETC, "bot_config.json")
ACCOUNTS = os.path.join(BASE_ETC, "accounts.json")
USERS = os.path.join(BASE_ETC, "users.json")
TOPUPS = os.path.join(BASE_ETC, "topups.json")
ZIVPN_CONFIG = os.path.join(BASE_ETC, "config.json")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ---------- Helpers: atomic write & safe load ----------
def read_json(path, fallback):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return fallback

def write_json_atomic(path, obj):
    dirn = os.path.dirname(path) or "/tmp"
    fd, tmp = tempfile.mkstemp(prefix="tmpjson_", dir=dirn)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception as e:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

# ---------- Debounced restart ----------
_last_restart = 0
def restart_zivpn_debounced(min_interval=3):
    global _last_restart
    now = time.time()
    if now - _last_restart < min_interval:
        log.info("debounced restart suppressed")
        return
    _last_restart = now
    try:
        subprocess.run(["systemctl", "restart", "zivpn.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        log.info("zivpn.service restarted (debounced)")
    except Exception as e:
        log.error("failed debounced restart: %s", e)

def reload_zivpn():
    restart_zivpn_debounced()

def add_password_to_zivpn(password: str):
    """Add password to ZIVPN auth.config and restart service (debounced)."""
    try:
        zcfg = read_json(ZIVPN_CONFIG, {})
        auth = zcfg.get("auth")
        if not isinstance(auth, dict):
            auth = {}
            zcfg["auth"] = auth
        auth.setdefault("mode", "passwords")
        cfg_list = auth.get("config")
        if not isinstance(cfg_list, list):
            cfg_list = []
            auth["config"] = cfg_list
        if password not in cfg_list:
            cfg_list.append(password)
        write_json_atomic(ZIVPN_CONFIG, zcfg)
        restart_zivpn_debounced()
        log.info("password added and restart requested (debounced)")
    except Exception as e:
        log.error("Failed updating ZIVPN config: %s", e)

def remove_password_from_zivpn(password: str):
    """Remove password from ZIVPN auth.config and restart service (debounced)."""
    try:
        zcfg = read_json(ZIVPN_CONFIG, {})
        auth = zcfg.get("auth")
        if not isinstance(auth, dict):
            return
        cfg_list = auth.get("config")
        if not isinstance(cfg_list, list):
            return
        if password in cfg_list:
            cfg_list.remove(password)
            auth["config"] = cfg_list
            zcfg["auth"] = auth
            write_json_atomic(ZIVPN_CONFIG, zcfg)
            restart_zivpn_debounced()
            log.info("password removed and restart requested (debounced)")
    except Exception as e:
        log.error("Failed to cleanup ZIVPN config: %s", e)

def ensure_admin_unlimited():
    """Make admin user always have unlimited credit."""
    cfg = read_json(BOT_CONFIG, {})
    try:
        ADMIN_ID_LOCAL = int(cfg.get("admin_id", 0) or 0)
    except Exception:
        ADMIN_ID_LOCAL = 0
    if not ADMIN_ID_LOCAL:
        return
    users = read_json(USERS, [])
    changed = False
    found = False
    for u in users:
        if u.get("id") == ADMIN_ID_LOCAL:
            found = True
            if u.get("credit") != 999999:
                u["credit"] = 999999
                changed = True
    if not found:
        users.append({"id": ADMIN_ID_LOCAL, "username": "", "credit": 999999})
        changed = True
    if changed:
        write_json_atomic(USERS, users)

def admin_only(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE):
        cfg = read_json(BOT_CONFIG, {})
        try:
            ADMIN_ID_LOCAL = int(cfg.get("admin_id", 0) or 0)
        except Exception:
            ADMIN_ID_LOCAL = 0
        uid = update.effective_user.id if update.effective_user else None
        if uid != ADMIN_ID_LOCAL:
            if update.message:
                await update.message.reply_text("❌ You are not authorized to use that.")
            elif update.callback_query:
                await update.callback_query.answer("Unauthorized", show_alert=True)
            return
        return await func(update, context)
    return wrapped

# Conversation states
(CREATE_USERNAME, CREATE_PASSWORD, CHOOSE_DURATION, CONFIRM_CREATE) = range(4)

# Load initial config
cfg = read_json(BOT_CONFIG, {})
try:
    ADMIN_ID = int(cfg.get("admin_id", 0) or 0)
except Exception:
    ADMIN_ID = 0

BOT_TOKEN = cfg.get("bot_token", "")
HOSTNAME = cfg.get("hostname", "")
SERVER_IP = cfg.get("server_ip", "")
BANK_NAME = cfg.get("bank_name", "")
BANK_NUMBER = cfg.get("bank_number", "")
BANK_HOLDER = cfg.get("bank_holder", "")
QR_LINK = cfg.get("qr_link", "")

if not SERVER_IP:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        SERVER_IP = s.getsockname()[0]
        s.close()
    except Exception:
        SERVER_IP = "YOUR_SERVER_IP"

# Note text (1 device only)
WARNING_NOTE = (
    "⚠️ သတိပြုရန်\n"
    "အကောင့်တစ်ခုသည် ဖုန်းတစ်လုံးအတွက်သာ အသုံးပြုရပါသည်။\n"
    "တကယ်လို့ ဖုန်းတစ်လုံးထက် ပိုချိတ်မိလို့ ပျက်သွားပါက\n"
    "သုံးစွဲသူ၏ တာဝန် ဖြစ်ပြီး Admin ၌ တာဝန်မရှိပါ။"
)

def account_status_info(expiry_ts):
    try:
        now = int(time.time())
        if expiry_ts <= now:
            return ("🔴 Offline", 0)
        days_left = int((expiry_ts - now) / 86400)
        if days_left <= 5:
            return ("🟠 5 Days Left", days_left)
        return ("🟢 Online", days_left)
    except Exception:
        return ("🔴 Offline", 0)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    users = read_json(USERS, [])
    existing = next((u for u in users if u["id"] == user.id), None)
    if not existing:
        credit = 999999 if user.id == ADMIN_ID else 0
        users.append({"id": user.id, "username": user.username or "", "credit": credit})
        write_json_atomic(USERS, users)
    elif user.id == ADMIN_ID and existing.get("credit") != 999999:
        existing["credit"] = 999999
        write_json_atomic(USERS, users)

    text = f"👋 Hello {user.first_name}! Welcome to {HOSTNAME} ZIVPN Bot.\nChoose an option:"
    await update.message.reply_text(text, reply_markup=main_menu_kb())

def main_menu_kb():
    kb = [
        [KeyboardButton("💳 Top-up Credit"), KeyboardButton("👤 Create Account")],
        [KeyboardButton("💰 My Credit"), KeyboardButton("🗂 My Accounts")],
        [KeyboardButton("🔁 Renew Account"), KeyboardButton("🛠 Admin Panel")],
        [KeyboardButton("📶 SIM & PACKAGE")]
    ]
    return ReplyKeyboardMarkup(kb, resize_keyboard=True)

def topup_amount_kb():
    kb = [
        [InlineKeyboardButton("💸 50", callback_data="top50"),
         InlineKeyboardButton("💸 100", callback_data="top100"),
         InlineKeyboardButton("💸 150", callback_data="top150")],
        [InlineKeyboardButton("❌ Cancel", callback_data="top_cancel")]
    ]
    return InlineKeyboardMarkup(kb)

def durations_kb(credit):
    buttons = []
    if credit >= 50:
        buttons.append(InlineKeyboardButton("30 days (50) 📅", callback_data="dur30"))
    if credit >= 100:
        buttons.append(InlineKeyboardButton("60 days (100) 📅", callback_data="dur60"))
    if credit >= 150:
        buttons.append(InlineKeyboardButton("90 days (150) 📅", callback_data="dur90"))
    buttons.append(InlineKeyboardButton("❌ Cancel", callback_data="cancel_create"))
    return InlineKeyboardMarkup([[b] for b in buttons])

# ---------- SIM & PACKAGE ----------
async def sim_package_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "DTAC SIM\n"
        "11730#\n"
        "ဖုန်းဘေလ် 30 ဘတ်ထည့်စမတ်ပါ။\n\n"
        "AIS SIM \n"
        "7777067#\n"
        "ဖုန်းဘေလ် 35 ဘတ်ထည့်စမတ်ပါ။\n\n"
        "Back to menu: press any menu button."
    )
    await update.message.reply_text(text, reply_markup=main_menu_kb())

# ---------- My Credit ----------
async def my_credit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    if u:
        credit = u.get("credit", 0)
        await update.message.reply_text(f"💰 Your credit: {credit} Ks", reply_markup=main_menu_kb())
    else:
        await update.message.reply_text("❌ You are not registered.", reply_markup=main_menu_kb())

# ---------- Topup handlers ----------
async def topup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Choose amount to top-up:", reply_markup=topup_amount_kb())

async def topup_button_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    if data == "top_cancel":
        await query.edit_message_text("❌ Cancelled top-up.", reply_markup=main_menu_kb())
        return
    amount_map = {"top50": 50, "top100": 100, "top150": 150}
    amount = amount_map.get(data, 0)
    if amount == 0:
        await query.edit_message_text("Unknown option.")
        return
    topups = read_json(TOPUPS, [])
    tid = str(uuid.uuid4())
    topups.append({
        "id": tid,
        "user_id": query.from_user.id,
        "amount": amount,
        "status": "pending",
        "created_at": int(time.time())
    })
    write_json_atomic(TOPUPS, topups)
    text = (
        f"💳 Please transfer {amount} Ks to:\n\n"
        f"🏦 Bank: {BANK_NAME}\n"
        f"🔢 Number: {BANK_NUMBER}\n"
        f"👤 Holder: {BANK_HOLDER}\n\n"
        f"After transfer, press the button below to upload screenshot."
    )
    kb = [[InlineKeyboardButton("⬆️ Upload transfer screenshot", callback_data=f"upload_{tid}")]]
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(kb))
    if QR_LINK:
        try:
            await context.bot.send_photo(chat_id=query.from_user.id, photo=QR_LINK,
                                         caption="📷 Scan this QR to pay")
        except Exception:
            pass

async def upload_callback_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if not query.data.startswith("upload_"):
        await query.edit_message_text("Invalid upload request.")
        return
    tid = query.data.split("_", 1)[1]
    context.user_data["awaiting_upload_for"] = tid
    await query.edit_message_text(
        "📸 Please send photo of your bank transfer (screenshot). It will be forwarded to admin for approval."
    )

async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "awaiting_upload_for" not in context.user_data:
        await update.message.reply_text("To top-up press 💳 Top-up Credit from the menu.")
        return
    tid = context.user_data.pop("awaiting_upload_for")
    topups = read_json(TOPUPS, [])
    t = next((x for x in topups if x["id"] == tid), None)
    if not t:
        await update.message.reply_text("Top-up session not found.")
        return
    photo = update.message.photo[-1]
    file_id = photo.file_id
    t["photo_file_id"] = file_id
    write_json_atomic(TOPUPS, topups)

    caption = (
        f"🧾 Top-up request\n"
        f"User: {update.effective_user.id} ({update.effective_user.full_name})\n"
        f"Amount: {t['amount']} Ks\n"
        f"ID: {tid}"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Approve", callback_data=f"approve_{tid}"),
         InlineKeyboardButton("🚫 Deny", callback_data=f"deny_{tid}")],
        [InlineKeyboardButton("♾ Give Unlimited", callback_data=f"unlimited_{t['user_id']}")]
    ])
    await context.bot.send_photo(chat_id=ADMIN_ID, photo=file_id, caption=caption, reply_markup=kb)
    await update.message.reply_text(
        "✅ Screenshot sent to admin. You will be notified when approved/denied.",
        reply_markup=main_menu_kb()
    )

async def admin_topup_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("❌ Unauthorized.")
        return
    data = query.data
    if data.startswith("approve_"):
        tid = data.split("_", 1)[1]
        topups = read_json(TOPUPS, [])
        t = next((x for x in topups if x["id"] == tid), None)
        if not t:
            await query.edit_message_text("Top-up not found.")
            return
        t["status"] = "approved"
        t["approved_by"] = ADMIN_ID
        t["approved_at"] = int(time.time())
        users = read_json(USERS, [])
        u = next((x for x in users if x["id"] == t["user_id"]), None)
        if not u:
            users.append({"id": t["user_id"], "username": "", "credit": t["amount"]})
        else:
            u["credit"] = u.get("credit", 0) + t["amount"]
        write_json_atomic(USERS, users)
        write_json_atomic(TOPUPS, topups)
        await context.bot.send_message(
            chat_id=t["user_id"],
            text=f"✅ Your top-up of {t['amount']} Ks has been approved. Your credit was updated.",
            reply_markup=main_menu_kb()
        )
        await query.edit_message_caption(
            caption=(query.message.caption or "") + "\n\n✅ Approved by admin.",
            reply_markup=None
        )
    elif data.startswith("deny_"):
        tid = data.split("_", 1)[1]
        topups = read_json(TOPUPS, [])
        t = next((x for x in topups if x["id"] == tid), None)
        if not t:
            await query.edit_message_text("Top-up not found.")
            return
        t["status"] = "denied"
        t["approved_by"] = ADMIN_ID
        t["approved_at"] = int(time.time())
        write_json_atomic(TOPUPS, topups)
        await context.bot.send_message(
            chat_id=t["user_id"],
            text=f"❌ Your top-up of {t['amount']} Ks was denied by admin.",
            reply_markup=main_menu_kb()
        )
        await query.edit_message_caption(
            caption=(query.message.caption or "") + "\n\n❌ Denied by admin.",
            reply_markup=None
        )
    elif data.startswith("unlimited_"):
        uid = int(data.split("_", 1)[1])
        users = read_json(USERS, [])
        u = next((x for x in users if x["id"] == uid), None)
        if not u:
            users.append({"id": uid, "username": "", "credit": 999999})
        else:
            u["credit"] = 999999
        write_json_atomic(USERS, users)
        await context.bot.send_message(
            chat_id=uid, text="♾ Admin granted you unlimited credit.",
            reply_markup=main_menu_kb()
        )
        await query.edit_message_caption(
            caption=(query.message.caption or "") + "\n\n♾ Given Unlimited credit.",
            reply_markup=None
        )

# ---------- Create Account with Add/Cancel ----------
async def create_account_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Please send desired username:",
        reply_markup=ReplyKeyboardRemove()
    )
    return CREATE_USERNAME

async def create_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["create_username"] = update.message.text.strip()
    await update.message.reply_text("Now send desired password:")
    return CREATE_PASSWORD

async def create_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upass = update.message.text.strip()
    context.user_data["create_password"] = upass

    users = read_json(USERS, [])
    uid = update.effective_user.id
    u = next((x for x in users if x["id"] == uid), None)
    credit = u.get("credit", 0) if u else 0
    if uid == ADMIN_ID:
        credit = 999999  # admin auto unlimited
    if credit < 50:
        await update.message.reply_text(
            "❌ Need at least 50 Ks credit to create account.",
            reply_markup=main_menu_kb()
        )
        return ConversationHandler.END
    await update.message.reply_text(
        "Choose duration based on your credit:",
        reply_markup=durations_kb(credit)
    )
    return CHOOSE_DURATION

async def create_duration_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id

    if data == "cancel_create":
        await query.edit_message_text("❌ Cancelled account creation.", reply_markup=main_menu_kb())
        return ConversationHandler.END

    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    credit = u.get("credit", 0) if u else 0
    if uid == ADMIN_ID:
        credit = 999999

    mapping = {"dur30": (30, 50), "dur60": (60, 100), "dur90": (90, 150)}
    if data not in mapping:
        await query.edit_message_text("Invalid option.", reply_markup=main_menu_kb())
        return ConversationHandler.END

    days, cost = mapping[data]
    if credit < cost:
        await query.edit_message_text(
            "❌ Insufficient credit for that duration.",
            reply_markup=main_menu_kb()
        )
        return ConversationHandler.END

    uname = context.user_data.get("create_username", "")
    upass = context.user_data.get("create_password", "")
    if not uname or not upass:
        await query.edit_message_text("Session error, please try again.", reply_markup=main_menu_kb())
        return ConversationHandler.END

    now = int(time.time())
    expiry_ts = now + days * 24 * 3600
    expiry_str = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")

    # Save pending info for confirmation
    context.user_data["pending_account"] = {
        "username": uname,
        "password": upass,
        "days": days,
        "cost": cost,
        "expiry_ts": expiry_ts
    }

    summary = (
        "📋 *Confirm New Account*\n\n"
        f"👤 *Username:* `{uname}`\n"
        f"🔐 *Password:* `{upass}`\n"
        f"⏳ *Days:* `{days}`\n"
        f"💰 *Cost:* `{cost}` Ks\n"
        f"📅 *Expired Date:* `{expiry_str}`\n\n"
        "✅ Press *Add Account* to save, or ❌ Cancel."
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("✅ Add Account", callback_data="create_confirm_add")],
        [InlineKeyboardButton("❌ Cancel", callback_data="create_confirm_cancel")]
    ])
    await query.edit_message_text(summary, parse_mode="Markdown", reply_markup=kb)
    return CONFIRM_CREATE

async def create_confirm_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id

    pending = context.user_data.get("pending_account")
    if not pending:
        await query.edit_message_text("Session expired, please try again.", reply_markup=main_menu_kb())
        return ConversationHandler.END

    if data == "create_confirm_cancel":
        context.user_data.pop("pending_account", None)
        await query.edit_message_text("❌ Account creation cancelled.", reply_markup=main_menu_kb())
        return ConversationHandler.END

    # create_confirm_add
    uname = pending["username"]
    upass = pending["password"]
    days = pending["days"]
    cost = pending["cost"]
    expiry_ts = pending["expiry_ts"]

    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    if not u:
        u = {"id": uid, "username": "", "credit": 0}
        users.append(u)

    if uid == ADMIN_ID:
        u["credit"] = 999999

    if uid != ADMIN_ID and u.get("credit", 0) < cost:
        await query.edit_message_text(
            "❌ Not enough credit now. Maybe you used it already.",
            reply_markup=main_menu_kb()
        )
        context.user_data.pop("pending_account", None)
        write_json_atomic(USERS, users)
        return ConversationHandler.END

    # Deduct credit for normal user; admin free
    if uid != ADMIN_ID:
        u["credit"] -= cost
        write_json_atomic(USERS, users)

    # Save account
    accounts = read_json(ACCOUNTS, [])
    account_id = str(uuid.uuid4())
    account = {
        "id": account_id,
        "username": uname,
        "password": upass,
        "created_by": uid,
        "created_at": int(time.time()),
        "expiry": expiry_ts,
        "days": days,
        "bound_device_id": None,
        "used_devices": []
    }
    accounts.append(account)
    write_json_atomic(ACCOUNTS, accounts)

    # Update ZIVPN config: auth.config list + restart (debounced)
    add_password_to_zivpn(upass)

    # Final messages
    expiry_str = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
    status_text, days_left = account_status_info(expiry_ts)
    days_left_text = f"{days_left} day(s)" if days_left >= 0 else "0 day(s)"

    success_msg = (
        "✅ *Create Account Successfully*\n\n"
        f"📡 *IP Address:* `{SERVER_IP}`\n"
        f"🌐 *Hostname:* `{HOSTNAME}`\n"
        f"👤 *Username:* `{uname}`\n"
        f"🔐 *Password:* `{upass}`\n"
        f"📅 *Expired Date:* `{expiry_str}`\n"
        f"📊 *Status:* {status_text}\n"
        f"⏳ *Days left:* `{days_left_text}`\n"
        f"⏳ *Days:* `{days}`\n"
        f"💰 *Cost:* `{cost}` Ks\n\n"
        f"{WARNING_NOTE}"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🔄 Renew", callback_data=f"user_renew_{account_id}"),
         InlineKeyboardButton("🗑 Delete", callback_data=f"user_delete_{account_id}")],
        [InlineKeyboardButton("📋 My Accounts", callback_data="my_accounts_list")]
    ])
    await query.edit_message_text(success_msg, parse_mode="Markdown", reply_markup=kb)
    await context.bot.send_message(
        chat_id=uid,
        text="Choose an option from the menu below:",
        reply_markup=main_menu_kb()
    )
    await context.bot.send_message(
        chat_id=ADMIN_ID,
        text=f"📝 New account created by {uid}\n👤 {uname}\n⏳ {days} days\n📅 Expires: {expiry_str}"
    )
    context.user_data.pop("pending_account", None)
    context.user_data.pop("create_username", None)
    context.user_data.pop("create_password", None)
    return ConversationHandler.END

# ---------- Bind device & multi-device handling (user command) ----------
async def bind_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    parts = update.message.text.strip().split()
    if len(parts) < 2:
        await update.message.reply_text("Usage: /bind <device_id>")
        return
    device_id = parts[1]
    uid = update.effective_user.id
    accounts = read_json(ACCOUNTS, [])
    # find the account owned by this user (existing behavior: first account)
    acc = next((a for a in accounts if a["created_by"] == uid), None)
    if not acc:
        await update.message.reply_text("❌ No account found.")
        return

    # normalize used_devices list
    used = acc.setdefault("used_devices", [])
    # If no bound_device_id yet -> bind normally
    if not acc.get("bound_device_id"):
        acc["bound_device_id"] = device_id
        used.append({"device_id": device_id, "bound_at": int(time.time())})
        write_json_atomic(ACCOUNTS, accounts)
        await update.message.reply_text("✅ Device bound successfully.", reply_markup=main_menu_kb())
        return

    # If same device is binding again -> acknowledge
    if acc.get("bound_device_id") == device_id:
        await update.message.reply_text("✅ This device already bound.", reply_markup=main_menu_kb())
        return

    # If different device tries to bind (second device) -> record and notify owner/admin
    used.append({"device_id": device_id, "bound_at": int(time.time())})
    acc["used_devices"] = used
    write_json_atomic(ACCOUNTS, accounts)
    # Notify the user and the admin (do NOT auto-expire)
    await update.message.reply_text(
        "⚠️ Detected binding from an additional device. Admin will be notified to review. "
        "If you believe this is unauthorized, contact admin.",
        reply_markup=main_menu_kb()
    )
    try:
        await context.bot.send_message(
            chat_id=ADMIN_ID,
            text=(
                f"⚠️ Multi-device bind detected for account `{acc.get('username')}` (owner {uid}).\n"
                f"Device ID: {device_id}\n"
                "No automatic expiry done — please review in Admin Panel."
            )
        )
    except Exception:
        pass

# ---------- My accounts ----------
async def my_accounts_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    accounts = read_json(ACCOUNTS, [])
    my_accounts = [a for a in accounts if a.get("created_by") == uid]
    if not my_accounts:
        await update.message.reply_text("📭 You have no accounts.", reply_markup=main_menu_kb())
        return

    await update.message.reply_text("📋 Your Accounts:", reply_markup=main_menu_kb())
    for a in my_accounts:
        exp = datetime.datetime.utcfromtimestamp(a["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
        status_text, days_left = account_status_info(a.get("expiry", 0))
        days_left_text = f"{days_left} day(s)" if days_left >= 0 else "0 day(s)"
        used = a.get("used_devices", [])
        # count devices (support both dict and string formats)
        unique = set()
        for d in used:
            if isinstance(d, dict):
                if d.get("device_id"):
                    unique.add(d.get("device_id"))
                elif d.get("ip"):
                    unique.add(d.get("ip"))
            else:
                unique.add(str(d))
        active_count = len(unique)

        txt = (
            "📦 *Account Card*\n\n"
            f"📡 *Server IP:* `{SERVER_IP}`\n"
            f"🌐 *Server Host:* `{HOSTNAME}`\n"
            f"👤 *Username:* `{a['username']}`\n"
            f"🔐 *Password:* `{a['password']}`\n"
            f"📅 *Expired Date:* `{exp}`\n"
            f"📊 *Status:* {status_text}\n"
            f"🔎 *Active Devices:* `{active_count}`\n"
            f"⏳ *Days left:* `{days_left_text}`\n"
            f"⏳ *Days:* `{a.get('days', 0)}`\n"
        )
        if a.get("bound_device_id"):
            txt += f"📱 *Bound Device:* `{a['bound_device_id']}`\n"
        txt += f"\n{WARNING_NOTE}"

        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Renew", callback_data=f"user_renew_{a['id']}"),
             InlineKeyboardButton("🗑 Delete", callback_data=f"user_delete_{a['id']}")],
            [InlineKeyboardButton("👁 View Details", callback_data=f"user_view_{a['id']}")]
        ])
        await update.message.reply_text(txt, parse_mode="Markdown", reply_markup=kb)

async def user_account_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id
    accounts = read_json(ACCOUNTS, [])

    if data.startswith("user_view_"):
        aid = data.split("_", 2)[2]
        a = next((x for x in accounts if x["id"] == aid and x["created_by"] == uid), None)
        if not a:
            await query.edit_message_text("❌ Account not found or not yours.")
            return
        exp = datetime.datetime.utcfromtimestamp(a["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
        status_text, days_left = account_status_info(a.get("expiry", 0))
        days_left_text = f"{days_left} day(s)" if days_left >= 0 else "0 day(s)"
        used = a.get("used_devices", [])
        unique = set()
        for d in used:
            if isinstance(d, dict):
                unique.add(d.get("device_id") or d.get("ip") or "")
            else:
                unique.add(str(d))
        active_count = len([x for x in unique if x])

        txt = (
            "📋 *Account Details*\n\n"
            f"📡 *IP Address:* `{SERVER_IP}`\n"
            f"🌐 *Hostname:* `{HOSTNAME}`\n"
            f"👤 *Username:* `{a['username']}`\n"
            f"🔐 *Password:* `{a['password']}`\n"
            f"📅 *Expiry:* `{exp}`\n"
            f"📊 *Status:* {status_text}\n"
            f"🔎 *Active Devices:* `{active_count}`\n"
            f"⏳ *Days left:* `{days_left_text}`\n"
            f"⏳ *Days:* `{a.get('days', 0)}`\n"
            f"📱 *Bound Device:* `{a.get('bound_device_id', 'None')}`\n"
            f"🆔 *Account ID:* `{a['id']}`\n\n"
            f"{WARNING_NOTE}"
        )
        kb = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔄 Renew", callback_data=f"user_renew_{a['id']}"),
             InlineKeyboardButton("🗑 Delete", callback_data=f"user_delete_{a['id']}")],
            [InlineKeyboardButton("🔙 Back to My Accounts", callback_data="my_accounts_list")]
        ])
        await query.edit_message_text(txt, parse_mode="Markdown", reply_markup=kb)
    elif data.startswith("user_delete_"):
        aid = data.split("_", 2)[2]
        idx = next((i for i, x in enumerate(accounts) if x["id"] == aid and x["created_by"] == uid), None)
        if idx is None:
            await query.edit_message_text("❌ Account not found or not yours.")
            return
        acc = accounts.pop(idx)
        write_json_atomic(ACCOUNTS, accounts)
        # clean zivpn config (user-triggered delete) via remove_password_from_zivpn (debounced restart)
        remove_password_from_zivpn(acc["password"])
        await query.edit_message_text("✅ Account deleted successfully.")
        await context.bot.send_message(
            chat_id=uid,
            text="Account deleted. Choose an option from the menu below:",
            reply_markup=main_menu_kb()
        )
    elif data.startswith("user_renew_"):
        aid = data.split("_", 2)[2]
        users = read_json(USERS, [])
        u = next((x for x in users if x["id"] == uid), None)
        credit = u.get("credit", 0) if u else 0
        if uid == ADMIN_ID:
            credit = 999999
        if credit < 50:
            await query.edit_message_text(
                "❌ Not enough credit to renew. Top-up first.",
                reply_markup=main_menu_kb()
            )
            return
        kb = []
        if credit >= 50:
            kb.append([InlineKeyboardButton("30 days (50) 📅", callback_data=f"user_renew_choose_{aid}_30")])
        if credit >= 100:
            kb.append([InlineKeyboardButton("60 days (100) 📅", callback_data=f"user_renew_choose_{aid}_60")])
        if credit >= 150:
            kb.append([InlineKeyboardButton("90 days (150) 📅", callback_data=f"user_renew_choose_{aid}_90")])
        kb.append([InlineKeyboardButton("❌ Cancel", callback_data="cancel_create")])
        await query.edit_message_text("⏳ Choose duration for renewal:", reply_markup=InlineKeyboardMarkup(kb))
    elif data == "my_accounts_list":
        await my_accounts_cmd(update, context)

async def user_renew_choose_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    parts = data.split("_")
    if len(parts) != 5:
        await query.edit_message_text("❌ Invalid data format.")
        return
    aid = parts[3]
    try:
        days = int(parts[4])
    except ValueError:
        await query.edit_message_text("❌ Invalid data.")
        return
    uid = query.from_user.id
    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    credit = u.get("credit", 0) if u else 0
    if uid == ADMIN_ID:
        credit = 999999
    cost_map = {30: 50, 60: 100, 90: 150}
    cost = cost_map.get(days)
    if cost is None:
        await query.edit_message_text("❌ Invalid duration.")
        return
    if uid != ADMIN_ID and credit < cost:
        await query.edit_message_text("❌ Insufficient credit.", reply_markup=main_menu_kb())
        return
    if uid != ADMIN_ID:
        u["credit"] = credit - cost
        write_json_atomic(USERS, users)
    accounts = read_json(ACCOUNTS, [])
    acc = next((a for a in accounts if a["id"] == aid and a["created_by"] == uid), None)
    if not acc:
        await query.edit_message_text("❌ Account not found.")
        return
    now = int(time.time())
    current_expiry = acc.get("expiry", now)
    if current_expiry < now:
        current_expiry = now
    acc["expiry"] = current_expiry + days * 24 * 3600
    acc["days"] = acc.get("days", 0) + days
    write_json_atomic(ACCOUNTS, accounts)
    new_exp = datetime.datetime.utcfromtimestamp(acc["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"✅ Account Renewed Successfully\n\n"
        f"👤 Username: {acc['username']}\n"
        f"➕ Added Days: {days}\n"
        f"💰 Cost: {cost} Ks\n"
        f"📅 New Expiry: {new_exp}\n"
        f"💰 Remaining Credit: {u.get('credit', '♾') if uid != ADMIN_ID else '♾ Unlimited'} Ks\n\n"
        f"{WARNING_NOTE}"
    )
    await query.edit_message_text(msg, parse_mode="Markdown")
    await context.bot.send_message(
        chat_id=uid,
        text="Account renewed. Choose an option from the menu below:",
        reply_markup=main_menu_kb()
    )

# ---------- Admin panel & admin callback router ----------
@admin_only
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    accounts = read_json(ACCOUNTS, [])
    users = read_json(USERS, [])
    topups = read_json(TOPUPS, [])
    total_users = len(users)
    total_accounts = len(accounts)
    total_credit = sum(u.get("credit", 0) for u in users if u.get("id") != ADMIN_ID)
    text = (
        "🛠 Admin Panel\n\n"
        f"📡 Server IP: {SERVER_IP}\n"
        f"🌐 Hostname: {HOSTNAME}\n"
        f"👥 Users: {total_users}\n"
        f"📁 Accounts: {total_accounts}\n"
        f"💰 Total Credit (Users): {total_credit} Ks\n\n"
        f"🏦 Bank: {BANK_NAME}\n"
        f"🔢 Number: {BANK_NUMBER}\n"
        f"👤 Holder: {BANK_HOLDER}\n"
        f"📷 QR: {QR_LINK if QR_LINK else 'Not set'}\n"
        f"🆔 Admin ID: {ADMIN_ID}"
    )
    kb = [
        [InlineKeyboardButton("👥 User List", callback_data="admin_list_users"),
         InlineKeyboardButton("📁 Account List", callback_data="admin_list_accounts")],
        [InlineKeyboardButton("🧾 Pending Topups", callback_data="admin_pending_topups"),
         InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")],
        [InlineKeyboardButton("📣 Send Notification", callback_data="admin_notify")]
    ]
    await update.message.reply_text(text, parse_mode="Markdown",
                                    reply_markup=InlineKeyboardMarkup(kb))

async def admin_cb_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("❌ Unauthorized.")
        return
    data = query.data
    if data == "admin_list_users":
        users = read_json(USERS, [])
        if not users:
            await query.edit_message_text("📭 No users.")
            return
        lines = []
        for i, u in enumerate(users, 1):
            label_credit = "♾ Unlimited" if u.get("id") == ADMIN_ID or u.get("credit", 0) >= 999999 else f"{u.get('credit', 0)} Ks"
            lines.append(
                f"{i}. 👤 ID: {u['id']} | 💰 {label_credit} | "
                f"🏷️ Username: @{u.get('username', 'N/A')}"
            )
        await query.edit_message_text("👥 User List:\n\n" + "\n".join(lines),
                                      parse_mode="Markdown")
    elif data == "admin_list_accounts":
        accounts = read_json(ACCOUNTS, [])
        if not accounts:
            await query.edit_message_text("📭 No accounts.")
            return
        await query.edit_message_text(f"📁 Total Accounts: {len(accounts)}")
        for a in accounts:
            exp = datetime.datetime.utcfromtimestamp(a["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
            status_text, days_left = account_status_info(a.get("expiry", 0))
            # active device count from used_devices
            used = a.get("used_devices", [])
            unique_ips = set()
            unique_devices = set()
            for d in used:
                if isinstance(d, dict):
                    if d.get("ip"):
                        unique_ips.add(d.get("ip"))
                    if d.get("device_id"):
                        unique_devices.add(d.get("device_id"))
                else:
                    unique_ips.add(str(d))
            active_count = max(len(unique_ips), len(unique_devices))

            txt = (
                "📦 Account Card (Admin)\n\n"
                f"📡 Server IP: {SERVER_IP}\n"
                f"🌐 Server Host: {HOSTNAME}\n"
                f"👤 Username: {a['username']}\n"
                f"🔐 Password: {a['password']}\n"
                f"📅 Expired Date: {exp}\n"
                f"📊 Status: {status_text}\n"
                f"🔎 Active Devices: {active_count}\n"
                f"⏳ Days left: {days_left}\n"
                f"⏳ Days: {a.get('days', 0)}\n"
                f"👤 Owner Telegram ID: {a.get('created_by')}\n"
                f"📱 Bound Device: {a.get('bound_device_id', 'None')}\n"
            )
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("🔄 Admin Custom Date",
                                      callback_data=f"admin_renew_custom_{a['id']}")],
                [InlineKeyboardButton("🗑 Admin Delete",
                                      callback_data=f"admin_delete_{a['id']}")]
            ])
            await context.bot.send_message(
                chat_id=ADMIN_ID,
                text=txt,
                parse_mode="Markdown",
                reply_markup=kb
            )
    elif data == "admin_pending_topups":
        topups = read_json(TOPUPS, [])
        pending = [t for t in topups if t.get("status") == "pending"]
        if not pending:
            await query.edit_message_text("✅ No pending topups.")
            return
        await query.edit_message_text(f"📤 Sending {len(pending)} pending topups to admin...")
        for t in pending:
            text = (
                "🧾 Topup Request\n\n"
                f"🆔 ID: {t['id']}\n"
                f"👤 User ID: {t['user_id']}\n"
                f"💰 Amount: {t['amount']} Ks\n"
                f"⏰ Created: "
                f"{datetime.datetime.fromtimestamp(t['created_at']).strftime('%Y-%m-%d %H:%M:%S')}"
            )
            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("✅ Approve", callback_data=f"approve_{t['id']}"),
                 InlineKeyboardButton("🚫 Deny", callback_data=f"deny_{t['id']}")],
                [InlineKeyboardButton("♾ Give Unlimited",
                                      callback_data=f"unlimited_{t['user_id']}")]
            ])
            if t.get("photo_file_id"):
                await context.bot.send_photo(chat_id=ADMIN_ID, photo=t["photo_file_id"],
                                            caption=text, parse_mode="Markdown",
                                            reply_markup=kb)
            else:
                await context.bot.send_message(chat_id=ADMIN_ID, text=text,
                                              parse_mode="Markdown", reply_markup=kb)
    elif data == "admin_stats":
        accounts = read_json(ACCOUNTS, [])
        users = read_json(USERS, [])
        topups = read_json(TOPUPS, [])
        total_users = len(users)
        total_accounts = len(accounts)
        total_credit = sum(u.get("credit", 0) for u in users if u.get("id") != ADMIN_ID)
        now = time.time()
        active_accounts = sum(1 for a in accounts if a.get("expiry", 0) > now)
        expired_accounts = sum(1 for a in accounts if a.get("expiry", 0) <= now)
        approved_topups = sum(1 for t in topups if t.get("status") == "approved")
        pending_topups = sum(1 for t in topups if t.get("status") == "pending")
        denied_topups = sum(1 for t in topups if t.get("status") == "denied")
        text = (
            "📊 Statistics\n\n"
            f"👥 Total Users: {total_users}\n"
            f"📁 Total Accounts: {total_accounts}\n"
            f"✅ Active Accounts: {active_accounts}\n"
            f"❌ Expired Accounts: {expired_accounts}\n"
            f"💰 Total Credit (Users): {total_credit} Ks\n\n"
            "🧾 Topups:\n"
            f" ✅ Approved: {approved_topups}\n"
            f" ⏳ Pending: {pending_topups}\n"
            f" ❌ Denied: {denied_topups}"
        )
        await query.edit_message_text(text, parse_mode="Markdown")
    elif data.startswith("admin_delete_"):
        aid = data.split("_", 2)[2]
        accounts = read_json(ACCOUNTS, [])
        idx = next((i for i, x in enumerate(accounts) if x["id"] == aid), None)
        if idx is None:
            await query.edit_message_text("❌ Account not found.")
            return
        acc = accounts.pop(idx)
        write_json_atomic(ACCOUNTS, accounts)
        # remove password from config and restart (debounced)
        remove_password_from_zivpn(acc["password"])
        await query.edit_message_text("✅ Admin deleted account and removed password (restart debounced).")
    elif data.startswith("admin_renew_custom_"):
        aid = data.split("_", 3)[3]
        context.user_data["admin_custom_exp_aid"] = aid
        await query.edit_message_text(
            "📅 Admin: Send new expiry date for this account in format YYYY-MM-DD (e.g. 2025-12-31).",
            parse_mode="Markdown"
        )
    elif data == "admin_notify":
        # start admin notify flow
        context.user_data["admin_notify_state"] = "awaiting_target"
        await query.edit_message_text("📣 Send Notification\n\nPlease reply to me (send a message) with all or a numeric user id to select target. Then send the message content in the next message.")

# ---------- Admin notify message flow (handled in text handler) ----------
async def notify_cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("📣 Send Notification — send 'all' or the numeric user id to target.")
    context.user_data["admin_notify_state"] = "awaiting_target"
    return

async def notify_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data.pop("admin_notify_state", None)
    context.user_data.pop("admin_notify_target", None)
    await update.message.reply_text("❌ Notification cancelled.", reply_markup=main_menu_kb())
    return

async def admin_notify_text_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if uid != ADMIN_ID:
        return
    state = context.user_data.get("admin_notify_state")
    if not state:
        return  # not in notify flow
    text = update.message.text.strip()
    if state == "awaiting_target":
        target = text.lower()
        if target != "all":
            try:
                target = int(text)
            except Exception:
                await update.message.reply_text("❌ Invalid target. Send 'all' or a numeric user id.")
                return
        context.user_data["admin_notify_target"] = target
        context.user_data["admin_notify_state"] = "awaiting_message"
        await update.message.reply_text("✍️ Now send the message you want to deliver to the target(s).")
        return
    if state == "awaiting_message":
        msg = text
        target = context.user_data.get("admin_notify_target")
        # Confirm & send
        if target == "all":
            users = read_json(USERS, [])
            cnt = 0
            for u in users:
                try:
                    await context.bot.send_message(chat_id=u.get("id"), text=f"📣 Admin message:\n\n{msg}")
                    cnt += 1
                except Exception:
                    pass
            await update.message.reply_text(f"✅ Sent message to {cnt} users.")
        else:
            try:
                await context.bot.send_message(chat_id=target, text=f"📣 Admin message:\n\n{msg}")
                await update.message.reply_text(f"✅ Sent message to {target}.")
            except Exception as e:
                await update.message.reply_text(f"❌ Failed to send to {target}: {e}")
        # cleanup
        context.user_data.pop("admin_notify_state", None)
        context.user_data.pop("admin_notify_target", None)
        return

# ---------- Text menu handler (handles admin notify state, SIM, etc.) ----------
async def text_menu_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # admin notify flow handler first
    uid = update.effective_user.id
    if uid == ADMIN_ID and context.user_data.get("admin_notify_state"):
        return await admin_notify_text_handler(update, context)

    txt = update.message.text.strip()
    # Admin custom expiry input
    if uid == ADMIN_ID and context.user_data.get("admin_custom_exp_aid"):
        aid = context.user_data.get("admin_custom_exp_aid")
        date_str = txt
        try:
            dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            expiry_ts = int(dt.replace(hour=23, minute=59, second=59).timestamp())
        except ValueError:
            await update.message.reply_text(
                "❌ Invalid date format. Use YYYY-MM-DD (e.g. 2025-12-31)."
            )
            return
        accounts = read_json(ACCOUNTS, [])
        acc = next((a for a in accounts if a["id"] == aid), None)
        if not acc:
            await update.message.reply_text("❌ Account not found.")
            context.user_data.pop("admin_custom_exp_aid", None)
            return
        acc["expiry"] = expiry_ts
        created_at = acc.get("created_at", int(time.time()))
        if expiry_ts > created_at:
            acc["days"] = int((expiry_ts - created_at) / 86400)
        write_json_atomic(ACCOUNTS, accounts)
        new_exp = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
        await update.message.reply_text(
            f"✅ Admin updated expiry for `{acc['username']}` to `{new_exp}`.",
            parse_mode="Markdown",
            reply_markup=main_menu_kb()
        )
        context.user_data.pop("admin_custom_exp_aid", None)
        return

    # SIM menu
    if txt in ["📶 SIM & PACKAGE", "SIM & PACKAGE", "sim & package"]:
        return await sim_package_cmd(update, context)

    if txt in ["💳 Top-up Credit", "top-up", "topup", "Top-up"]:
        return await topup_command(update, context)
    elif txt in ["👤 Create Account", "create account", "Create Account"]:
        return await create_account_cmd(update, context)
    elif txt in ["💰 My Credit", "my credit", "My Credit"]:
        return await my_credit(update, context)
    elif txt in ["🗂 My Accounts", "my accounts", "My Accounts"]:
        return await my_accounts_cmd(update, context)
    elif txt in ["🔁 Renew Account", "renew account", "Renew Account"]:
        return await my_accounts_cmd(update, context)
    elif txt in ["🛠 Admin Panel", "admin panel", "Admin Panel"]:
        return await admin_panel(update, context)
    else:
        await update.message.reply_text("Please use the menu buttons.", reply_markup=main_menu_kb())

async def cancel_conversation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("❌ Operation cancelled.", reply_markup=main_menu_kb())
    return ConversationHandler.END

def main():
    if not BOT_TOKEN:
        print("❌ Bot token not configured.")
        return

    ensure_admin_unlimited()
    app = ApplicationBuilder().token(BOT_TOKEN).concurrent_updates(True).build()

    conv = ConversationHandler(
        entry_points=[
            CommandHandler("create", create_account_cmd),
            MessageHandler(filters.Regex(r"^(?i)(create account|👤 Create Account)$"), create_account_cmd)
        ],
        states={
            CREATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_username)],
            CREATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_password)],
            CHOOSE_DURATION: [CallbackQueryHandler(
                create_duration_cb, pattern=r"^(dur30|dur60|dur90|cancel_create)$"
            )],
            CONFIRM_CREATE: [CallbackQueryHandler(
                create_confirm_cb, pattern=r"^create_confirm_(add|cancel)$"
            )]
        },
        fallbacks=[CommandHandler("cancel", cancel_conversation)],
        per_user=True,
        per_chat=True
    )
    app.add_handler(conv)
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("menu", start))
    app.add_handler(CommandHandler("credit", my_credit))
    app.add_handler(CommandHandler("bind", bind_device_cmd))
    app.add_handler(CommandHandler("accounts", my_accounts_cmd))
    app.add_handler(CommandHandler("admin", admin_panel))
    app.add_handler(CommandHandler("notify", notify_cmd_start))
    app.add_handler(CommandHandler("cancel", cancel_conversation))
    app.add_handler(CallbackQueryHandler(topup_button_cb, pattern=r"^(top50|top100|top150|top_cancel)$"))
    app.add_handler(CallbackQueryHandler(upload_callback_cb, pattern=r"^upload_"))
    app.add_handler(CallbackQueryHandler(admin_topup_cb, pattern=r"^(approve_|deny_|unlimited_)"))
    app.add_handler(CallbackQueryHandler(admin_cb_router, pattern=r"^admin_"))
    app.add_handler(CallbackQueryHandler(user_account_cb, pattern=r"^(user_view_|user_delete_|user_renew_|my_accounts_list)"))
    app.add_handler(CallbackQueryHandler(user_renew_choose_cb, pattern=r"^user_renew_choose_"))
    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_menu_handler))

    print("🤖 Bot starting...")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

chmod +x "$BOT_PY" || true

############################
# MONITOR PYTHON (updated: record used_devices + notify, no immediate password removal)
############################
cat > "$MONITOR_PY" <<'PY'
#!/usr/bin/env python3
"""
Monitor ZIVPN journalctl output for 'client connected' events.
When same 'id' (password/username) is seen from >1 distinct addr within GRACE_WINDOW,
do NOT auto-remove the password. Instead:

update /etc/zivpn/accounts.json used_devices list (ip/device info)

notify admin and account owners via Telegram bot (if configured)

do not restart zivpn.service or modify config.json automatically
This reduces false positives and avoids restart storms.
"""
import subprocess, json, re, time, os, sys, urllib.request, urllib.parse, traceback, tempfile
from collections import defaultdict, deque

ACCOUNTS_JSON = "/etc/zivpn/accounts.json"
ZIVPN_CONFIG = "/etc/zivpn/config.json"
BOT_CONFIG = "/etc/zivpn/bot_config.json"

# regex to find JSON object after 'client connected'
RE_CLIENT = re.compile(r"client connected\s*({.*})")

# GRACE_WINDOW: seconds window to consider multi-source as sharing (increased to reduce false positives)
GRACE_WINDOW = 30

# Use deque per id to keep recent (ip, ts) and compute unique ips in window
seen = defaultdict(lambda: deque())  # id -> deque of (ip, ts)
notified = {}  # pid -> timestamp until which notifications are suppressed (throttle)

# notification throttle (seconds) to avoid spamming admin/owners repeatedly
NOTIFY_THROTTLE = 60 * 60  # 1 hour

def read_json(path, fallback):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return fallback

def write_json_atomic(path, obj):
    dirn = os.path.dirname(path) or "/tmp"
    fd, tmp = tempfile.mkstemp(prefix="tmpjson_", dir=dirn)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise

def notify_telegram(chat_id, text):
    cfg = read_json(BOT_CONFIG, {})
    token = cfg.get("bot_token")
    if not token or not chat_id:
        print("notify_telegram skipped: no token or chat_id")
        return False
    try:
        data = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
        data_enc = urllib.parse.urlencode(data).encode()
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        req = urllib.request.Request(url, data=data_enc)
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        return True
    except Exception as e:
        print("notify error:", e)
        return False

def process_line(line):
    m = RE_CLIENT.search(line)
    if not m:
        return
    try:
        js = m.group(1)
        obj = json.loads(js)
        addr = obj.get("addr")
        pid = obj.get("id")
        if not pid or not addr:
            return
        ip = addr.split(":")[0]
        now = int(time.time())
        dq = seen[pid]
        # purge outdated entries older than GRACE_WINDOW
        while dq and now - dq[0][1] > GRACE_WINDOW:
            dq.popleft()
        dq.append((ip, now))
        unique_ips = {e[0] for e in dq}
        print(f"[monitor] pid={pid} recent_ips={unique_ips}")

        if len(unique_ips) > 1:
            # throttle repeated notifications per pid until
            until = notified.get(pid, 0)
            if now < until:
                print(f"[monitor] pid={pid} recently notified, skip")
                return
            # set next allowed notify time
            notified[pid] = now + NOTIFY_THROTTLE
            print(f"[monitor] multi-source detected for pid={pid} -> record devices and notify admin/owners")
            try:
                accounts = read_json(ACCOUNTS_JSON, [])
                changed = False
                owners = set()
                for a in accounts:
                    if a.get("password") == pid:
                        owners.add(a.get("created_by"))
                        used = a.get("used_devices", [])
                        existing_ips = {d.get("ip") for d in used if isinstance(d, dict) and d.get("ip")}
                        for uip in unique_ips:
                            if uip not in existing_ips:
                                used.append({"ip": uip, "first_seen": now, "last_seen": now})
                                changed = True
                            else:
                                # update last_seen for that ip
                                for d in used:
                                    if d.get("ip") == uip:
                                        d["last_seen"] = now
                                        changed = True
                        a["used_devices"] = used
                if changed:
                    write_json_atomic(ACCOUNTS_JSON, accounts)
                # prepare notification messages
                cfg = read_json(BOT_CONFIG, {})
                admin = cfg.get("admin_id")
                admin_msg = (
                    f"⚠️ Auto-detect: password `{pid}` used from multiple IPs {list(unique_ips)}.\n"
                    "No automatic expiry performed — please review the account(s) in Admin Panel.\n"
                    f"Accounts affected owners: {list(owners)}"
                )
                owner_msg = (
                    "⚠️ သတိပေးချက် — သင့် ZIVPN အကောင့် (password `{}`) ကို အခြား IP ကနေချိတ်ဆက်သုံးနေသည်ကို တွေ့ပါတယ်။\n\n"
                    "အသုံးပြုသူတွေဆက်တိုက် share မလုပ်ပါစေနဲ့။ Admin သည် Admin Panel မှာ ကိစ္စကို စစ်ဆေးနိုင်ပါတယ်။"
                ).format(pid)
                # send admin notification
                if admin:
                    notify_telegram(admin, admin_msg)
                # notify owners
                for o in owners:
                    if o:
                        notify_telegram(o, owner_msg)
            except Exception as e:
                print("monitor update/notify error:", e, traceback.format_exc())
    except Exception as e:
        print("parse/process error", e)

def follow_journal():
    # use journalctl -u zivpn.service -f -o cat for cleaner output
    cmd = ["journalctl", "-u", "zivpn.service", "-f", "-o", "cat"]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in p.stdout:
            if not line:
                continue
            process_line(line.strip())
    except Exception as e:
        print("journal follow crashed", e)
    finally:
        try:
            p.terminate()
        except Exception:
            pass

if __name__ == "__main__":
    # ensure files exist
    for path in (ACCOUNTS_JSON, ZIVPN_CONFIG):
        if not os.path.exists(path):
            print("Required file missing:", path)
    print("Starting monitor... (GRACE_WINDOW = {}s)".format(GRACE_WINDOW))
    # simple restart loop
    while True:
        try:
            follow_journal()
        except Exception as e:
            print("monitor main loop error:", e)
            time.sleep(2)
PY

chmod +x "$MONITOR_PY" || true

############################
# PYTHON / SERVICE SETUP
############################
echo -e "\n=== Installing python & deps ==="
apt-get install -y python3-venv python3-pip curl jq iptables-persistent ufw tcpdump 1>/dev/null 2>/dev/null || true
python3 -m venv "$BOT_VENV" || true
"$BOT_VENV/bin/pip" install --upgrade pip 1>/dev/null 2>/dev/null || true

# PTB used by bot
"$BOT_VENV/bin/pip" install python-telegram-bot==20.5 1>/dev/null 2>/dev/null || true

cat > "$BOT_SERVICE" <<SERVICE
[Unit]
Description=ZIVPN Telegram Bot
After=network.target

[Service]
User=root
WorkingDirectory=$BOT_DIR
ExecStart=$BOT_VENV/bin/python $BOT_PY
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

cat > "$MONITOR_SERVICE" <<SERVICE
[Unit]
Description=ZIVPN Auth Monitor (detect multi-device)
After=network.target zivpn.service

[Service]
User=root
WorkingDirectory=$BOT_DIR
ExecStart=$BOT_VENV/bin/python $MONITOR_PY
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable zivpn-bot.service
systemctl enable zivpn-monitor.service
systemctl restart zivpn-bot.service || systemctl start zivpn-bot.service || true
systemctl restart zivpn-monitor.service || systemctl start zivpn-monitor.service || true

############################
# FINISH
############################
echo -e "\n✅ Install finished successfully!\n"
echo "📋 Important Notes / Checklist:"
echo " 1) ZIVPN listens on 0.0.0.0:5667 (see $ZIVPN_ETC/config.json)"
echo " 2) IP forwarding should be enabled (check: sysctl net.ipv4.ip_forward)"
echo " 3) iptables NAT forwards UDP 6000-19999 -> ${SERVER_IP}:5667"
if [ "$BROAD_DNAT" = true ]; then
    echo " 3b) BROAD DNAT enabled: UDP 1-65535 -> ${SERVER_IP}:5667 (clients can enter only IP)"
fi
echo " 4) UFW opened for 5667 and 6000-19999 UDP (if ufw installed)"
echo
echo "📁 Files created:"
echo " - Bot config: $BOT_CONFIG"
echo " - Users: $USERS_JSON"
echo " - Accounts: $ACCOUNTS_JSON"
echo " - Topups: $TOPUPS_JSON"
echo " - Bot: $BOT_PY"
echo " - Monitor: $MONITOR_PY"
echo
echo "⚙️ Service commands:"
echo " systemctl status zivpn.service"
echo " systemctl restart zivpn.service"
echo " systemctl status zivpn-bot.service"
echo " systemctl restart zivpn-bot.service"
echo " systemctl status zivpn-monitor.service"
echo " systemctl restart zivpn-monitor.service"
echo
if [ "$BROAD_DNAT" = true ]; then
    echo "To remove BROAD DNAT later, you can run:"
    echo " iptables -t nat -D PREROUTING -i $INET_IF -p udp --dport 1:65535 -j DNAT --to-destination ${SERVER_IP}:5667"
    echo
fi
echo "✅ Done."
