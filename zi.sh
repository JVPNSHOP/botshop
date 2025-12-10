#!/usr/bin/env bash
# install_zivpn_full_fix.sh
# Full ZIVPN + Telegram bot installer
# - ZIVPN UDP server on 0.0.0.0:5667
# - BROAD_DNAT (UDP 1-65535 -> 5667) for IP-only clients
# - Telegram bot with credit, topup, create/renew/delete account
# - Create Account now has ✅ Add Account / ❌ Cancel confirmation
# - ZIVPN password list auto update + service auto restart

set -euo pipefail

############################
# CONFIG
############################

# If BROAD_DNAT=true the script will DNAT all incoming UDP ports (1:65535) to local 5667.
# This lets clients that only enter the IP (no :port) still reach the server.
# WARNING: BROAD_DNAT can interfere with other UDP services (DNS, SIP, etc) on the same IP.
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

mkdir -p "$ZIVPN_ETC"
mkdir -p "$BOT_DIR"

export DEBIAN_FRONTEND=noninteractive

echo -e "\n=== Updating packages ==="
apt-get update -y
apt-get upgrade -y

echo -e "\n=== Stop existing services (if any) ==="
systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true
systemctl stop zivpn-bot.service 1>/dev/null 2>/dev/null || true

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

if [ ! -f "$ZIVPN_ETC/config.json" ]; then
  cat > "$ZIVPN_ETC/config.json" <<JSON
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
  echo "Created default $ZIVPN_ETC/config.json"
else
  echo "Patching existing $ZIVPN_ETC/config.json"
  # force listen
  if grep -q '"listen"' "$ZIVPN_ETC/config.json"; then
    sed -i 's/"listen"[[:space:]]*:[[:space:]]*".*"/"listen": "0.0.0.0:5667"/' "$ZIVPN_ETC/config.json" || true
  fi
  # ensure cert/key/obfs/auth.mode/config
  if ! grep -q '"cert"' "$ZIVPN_ETC/config.json"; then
    sed -i '1s#^{#{\n  "cert": "/etc/zivpn/zivpn.crt",#' "$ZIVPN_ETC/config.json" || true
  fi
  if ! grep -q '"key"' "$ZIVPN_ETC/config.json"; then
    sed -i '1s#^{#{\n  "key": "/etc/zivpn/zivpn.key",#' "$ZIVPN_ETC/config.json" || true
  fi
  if ! grep -q '"obfs"' "$ZIVPN_ETC/config.json"; then
    sed -i '1s#^{#{\n  "obfs": "",#' "$ZIVPN_ETC/config.json" || true
  fi
  if ! grep -q '"auth"' "$ZIVPN_ETC/config.json"; then
    # append minimal auth
    sed -i 's#}$#,\n  "auth": {"mode":"passwords","config":["zi"]}\n}#' "$ZIVPN_ETC/config.json" || true
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
# BOT PYTHON CODE
############################

cat > "$BOT_PY" <<'PY'
#!/usr/bin/env python3
# ZIVPN Telegram Bot (with Add Account confirmation + admin custom date + admin unlimited)

import json, logging, os, time, datetime, uuid, socket, subprocess
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

def read_json(path, fallback):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return fallback

def write_json(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

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

def reload_zivpn():
    """Restart ZIVPN service so new passwords work immediately."""
    try:
        subprocess.run(
            ["systemctl", "restart", "zivpn.service"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except Exception as e:
        log.error("Failed to restart ZIVPN service: %s", e)

def add_password_to_zivpn(password: str):
    """Add password to ZIVPN auth.config and restart service."""
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
            write_json(ZIVPN_CONFIG, zcfg)
            reload_zivpn()
    except Exception as e:
        log.error("Failed updating ZIVPN config: %s", e)

def remove_password_from_zivpn(password: str):
    """Remove password from ZIVPN auth.config and restart service."""
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
            write_json(ZIVPN_CONFIG, zcfg)
            reload_zivpn()
    except Exception as e:
        log.error("Failed to cleanup ZIVPN config: %s", e)

def ensure_admin_unlimited():
    """Make admin user always have unlimited credit."""
    if not ADMIN_ID:
        return
    users = read_json(USERS, [])
    changed = False
    found = False
    for u in users:
        if u.get("id") == ADMIN_ID:
            found = True
            if u.get("credit") != 999999:
                u["credit"] = 999999
                changed = True
    if not found:
        users.append({"id": ADMIN_ID, "username": "", "credit": 999999})
        changed = True
    if changed:
        write_json(USERS, users)

def admin_only(func):
    @wraps(func)
    async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id if update.effective_user else None
        if uid != ADMIN_ID:
            if update.message:
                await update.message.reply_text("❌ You are not authorized to use that.")
            elif update.callback_query:
                await update.callback_query.answer("Unauthorized", show_alert=True)
            return
        return await func(update, context)
    return wrapped

# Conversation states
(CREATE_USERNAME, CREATE_PASSWORD, CHOOSE_DURATION, CONFIRM_CREATE) = range(4)

def main_menu_kb():
    kb = [
        [KeyboardButton("💳 Top-up Credit"), KeyboardButton("👤 Create Account")],
        [KeyboardButton("💰 My Credit"), KeyboardButton("🗂 My Accounts")],
        [KeyboardButton("🔁 Renew Account"), KeyboardButton("🛠 Admin Panel")]
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

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    users = read_json(USERS, [])
    existing = next((u for u in users if u["id"] == user.id), None)
    if not existing:
        credit = 999999 if user.id == ADMIN_ID else 0
        users.append({"id": user.id, "username": user.username or "", "credit": credit})
        write_json(USERS, users)
    elif user.id == ADMIN_ID and existing.get("credit") != 999999:
        existing["credit"] = 999999
        write_json(USERS, users)

    text = f"👋 Hello {user.first_name}! Welcome to {HOSTNAME} ZIVPN Bot.\nChoose an option:"
    await update.message.reply_text(text, reply_markup=main_menu_kb())

async def my_credit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    c = u["credit"] if u else 0
    if uid == ADMIN_ID or c >= 999999:
        txt = "💰 Your credit: ♾ Unlimited"
    else:
        txt = f"💰 Your credit: {c} Ks"
    await update.message.reply_text(txt, reply_markup=main_menu_kb())

# ---------- Topup ----------

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
    write_json(TOPUPS, topups)
    text = (
        f"💳 Please transfer *{amount}* Ks to:\n\n"
        f"🏦 Bank: *{BANK_NAME}*\n"
        f"🔢 Number: `{BANK_NUMBER}`\n"
        f"👤 Holder: *{BANK_HOLDER}*\n\n"
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
        "📸 Please send photo of your bank transfer (screenshot). "
        "It will be forwarded to admin for approval."
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
    write_json(TOPUPS, topups)

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
    await context.bot.send_photo(chat_id=ADMIN_ID, photo=file_id,
                                 caption=caption, reply_markup=kb)
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
        write_json(USERS, users)
        write_json(TOPUPS, topups)
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
        write_json(TOPUPS, topups)
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
        write_json(USERS, users)
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
        await query.edit_message_text("❌ Cancelled account creation.",
                                      reply_markup=main_menu_kb())
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
        await query.edit_message_text("Session error, please try again.",
                                      reply_markup=main_menu_kb())
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
        await query.edit_message_text("Session expired, please try again.",
                                      reply_markup=main_menu_kb())
        return ConversationHandler.END

    if data == "create_confirm_cancel":
        context.user_data.pop("pending_account", None)
        await query.edit_message_text("❌ Account creation cancelled.",
                                      reply_markup=main_menu_kb())
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
        write_json(USERS, users)
        return ConversationHandler.END

    # Deduct credit for normal user; admin free
    if uid != ADMIN_ID:
        u["credit"] -= cost
    write_json(USERS, users)

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
    write_json(ACCOUNTS, accounts)

    # Update ZIVPN config: auth.config list + restart
    add_password_to_zivpn(upass)

    # Final messages
    expiry_str = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
    success_msg = (
        "✅ *Create Account Successfully*\n\n"
        f"📡 *IP Address:* `{SERVER_IP}`\n"
        f"🌐 *Hostname:* `{HOSTNAME}`\n"
        f"👤 *Username:* `{uname}`\n"
        f"🔐 *Password:* `{upass}`\n"
        f"📅 *Expired Date:* `{expiry_str}`\n"
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

# ---------- Other features (bind, list accounts, renew, admin panel) ----------

async def bind_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    parts = update.message.text.strip().split()
    if len(parts) < 2:
        await update.message.reply_text("Usage: /bind <device-id>")
        return
    device_id = parts[1]
    uid = update.effective_user.id
    accounts = read_json(ACCOUNTS, [])
    acc = next((a for a in accounts if a["created_by"] == uid), None)
    if not acc:
        await update.message.reply_text("❌ No account found.")
        return
    if acc.get("bound_device_id"):
        if acc["bound_device_id"] == device_id:
            await update.message.reply_text("✅ This device already bound.")
        else:
            await update.message.reply_text("❌ Another device is already bound. Cannot bind.")
        return
    acc["bound_device_id"] = device_id
    acc.setdefault("used_devices", []).append({"device_id": device_id, "bound_at": int(time.time())})
    write_json(ACCOUNTS, accounts)
    await update.message.reply_text("✅ Device bound successfully.", reply_markup=main_menu_kb())

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
        txt = (
            "📦 *Account Card*\n\n"
            f"📡 *Server IP:* `{SERVER_IP}`\n"
            f"🌐 *Server Host:* `{HOSTNAME}`\n"
            f"👤 *Username:* `{a['username']}`\n"
            f"🔐 *Password:* `{a['password']}`\n"
            f"📅 *Expired Date:* `{exp}`\n"
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
        txt = (
            "📋 *Account Details*\n\n"
            f"📡 *IP Address:* `{SERVER_IP}`\n"
            f"🌐 *Hostname:* `{HOSTNAME}`\n"
            f"👤 *Username:* `{a['username']}`\n"
            f"🔐 *Password:* `{a['password']}`\n"
            f"📅 *Expiry:* `{exp}`\n"
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
        idx = next((i for i, x in enumerate(accounts)
                    if x["id"] == aid and x["created_by"] == uid), None)
        if idx is None:
            await query.edit_message_text("❌ Account not found or not yours.")
            return
        acc = accounts.pop(idx)
        write_json(ACCOUNTS, accounts)
        # clean zivpn config
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
            kb.append([InlineKeyboardButton("30 days (50) 📅",
                                            callback_data=f"user_renew_choose_{aid}_30")])
        if credit >= 100:
            kb.append([InlineKeyboardButton("60 days (100) 📅",
                                            callback_data=f"user_renew_choose_{aid}_60")])
        if credit >= 150:
            kb.append([InlineKeyboardButton("90 days (150) 📅",
                                            callback_data=f"user_renew_choose_{aid}_90")])
        kb.append([InlineKeyboardButton("❌ Cancel", callback_data="cancel_create")])
        await query.edit_message_text("⏳ Choose duration for renewal:",
                                      reply_markup=InlineKeyboardMarkup(kb))
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
        write_json(USERS, users)
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
    write_json(ACCOUNTS, accounts)
    new_exp = datetime.datetime.utcfromtimestamp(acc["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"✅ *Account Renewed Successfully*\n\n"
        f"👤 *Username:* `{acc['username']}`\n"
        f"➕ *Added Days:* `{days}`\n"
        f"💰 *Cost:* `{cost}` Ks\n"
        f"📅 *New Expiry:* `{new_exp}`\n"
        f"💰 *Remaining Credit:* `{u.get('credit', '♾') if uid != ADMIN_ID else '♾ Unlimited'}` Ks\n\n"
        f"{WARNING_NOTE}"
    )
    await query.edit_message_text(msg, parse_mode="Markdown")
    await context.bot.send_message(
        chat_id=uid,
        text="Account renewed. Choose an option from the menu below:",
        reply_markup=main_menu_kb()
    )

async def topup_menu_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("💳 Choose amount to top-up:", reply_markup=topup_amount_kb())

@admin_only
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    accounts = read_json(ACCOUNTS, [])
    users = read_json(USERS, [])
    topups = read_json(TOPUPS, [])
    total_users = len(users)
    total_accounts = len(accounts)
    total_credit = sum(u.get("credit", 0) for u in users if u.get("id") != ADMIN_ID)
    text = (
        "🛠 *Admin Panel*\n\n"
        f"📡 *Server IP:* `{SERVER_IP}`\n"
        f"🌐 *Hostname:* `{HOSTNAME}`\n"
        f"👥 *Users:* `{total_users}`\n"
        f"📁 *Accounts:* `{total_accounts}`\n"
        f"💰 *Total Credit (Users):* `{total_credit}` Ks\n\n"
        f"🏦 *Bank:* `{BANK_NAME}`\n"
        f"🔢 *Number:* `{BANK_NUMBER}`\n"
        f"👤 *Holder:* `{BANK_HOLDER}`\n"
        f"📷 *QR:* `{QR_LINK if QR_LINK else 'Not set'}`\n"
        f"🆔 *Admin ID:* `{ADMIN_ID}`"
    )
    kb = [
        [InlineKeyboardButton("👥 User List", callback_data="admin_list_users"),
         InlineKeyboardButton("📁 Account List", callback_data="admin_list_accounts")],
        [InlineKeyboardButton("🧾 Pending Topups", callback_data="admin_pending_topups"),
         InlineKeyboardButton("📊 Statistics", callback_data="admin_stats")]
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
                f"{i}. 👤 ID: `{u['id']}` | 💰 {label_credit} | "
                f"🏷️ Username: @{u.get('username', 'N/A')}"
            )
        await query.edit_message_text("👥 *User List:*\n\n" + "\n".join(lines),
                                      parse_mode="Markdown")
    elif data == "admin_list_accounts":
        accounts = read_json(ACCOUNTS, [])
        if not accounts:
            await query.edit_message_text("📭 No accounts.")
            return
        await query.edit_message_text(f"📁 Total Accounts: {len(accounts)}")
        for a in accounts:
            exp = datetime.datetime.utcfromtimestamp(a["expiry"]).strftime("%Y-%m-%d %H:%M:%S")
            txt = (
                "📦 *Account Card (Admin)*\n\n"
                f"📡 *Server IP:* `{SERVER_IP}`\n"
                f"🌐 *Server Host:* `{HOSTNAME}`\n"
                f"👤 *Username:* `{a['username']}`\n"
                f"🔐 *Password:* `{a['password']}`\n"
                f"📅 *Expired Date:* `{exp}`\n"
                f"⏳ *Days:* `{a.get('days', 0)}`\n"
                f"👤 *Owner Telegram ID:* `{a.get('created_by')}`\n"
                f"📱 *Bound Device:* `{a.get('bound_device_id', 'None')}`\n"
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
                "🧾 *Topup Request*\n\n"
                f"🆔 *ID:* `{t['id']}`\n"
                f"👤 *User ID:* `{t['user_id']}`\n"
                f"💰 *Amount:* `{t['amount']}` Ks\n"
                f"⏰ *Created:* "
                f"`{datetime.datetime.fromtimestamp(t['created_at']).strftime('%Y-%m-%d %H:%M:%S')}`"
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
            "📊 *Statistics*\n\n"
            f"👥 *Total Users:* `{total_users}`\n"
            f"📁 *Total Accounts:* `{total_accounts}`\n"
            f"✅ *Active Accounts:* `{active_accounts}`\n"
            f"❌ *Expired Accounts:* `{expired_accounts}`\n"
            f"💰 *Total Credit (Users):* `{total_credit}` Ks\n\n"
            "🧾 *Topups:*\n"
            f"  ✅ Approved: `{approved_topups}`\n"
            f"  ⏳ Pending: `{pending_topups}`\n"
            f"  ❌ Denied: `{denied_topups}`"
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
        write_json(ACCOUNTS, accounts)
        remove_password_from_zivpn(acc["password"])
        await query.edit_message_text("✅ Admin deleted account.")
    elif data.startswith("admin_renew_custom_"):
        aid = data.split("_", 3)[3]
        context.user_data["admin_custom_exp_aid"] = aid
        await query.edit_message_text(
            "📅 Admin: Send new expiry date for this account in format *YYYY-MM-DD* (e.g. 2025-12-31).",
            parse_mode="Markdown"
        )

async def text_menu_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip()
    uid = update.effective_user.id

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
        write_json(ACCOUNTS, accounts)
        new_exp = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
        await update.message.reply_text(
            f"✅ Admin updated expiry for `{acc['username']}` to `{new_exp}`.",
            parse_mode="Markdown",
            reply_markup=main_menu_kb()
        )
        context.user_data.pop("admin_custom_exp_aid", None)
        return

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
        await update.message.reply_text(
            "Please use the menu buttons.",
            reply_markup=main_menu_kb()
        )

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
            MessageHandler(filters.Regex(r"^(?i)(create account|👤 Create Account)$"),
                           create_account_cmd)
        ],
        states={
            CREATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_username)],
            CREATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_password)],
            CHOOSE_DURATION: [CallbackQueryHandler(
                create_duration_cb,
                pattern=r"^(dur30|dur60|dur90|cancel_create)$"
            )],
            CONFIRM_CREATE: [CallbackQueryHandler(
                create_confirm_cb,
                pattern=r"^create_confirm_(add|cancel)$"
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
    app.add_handler(CommandHandler("cancel", cancel_conversation))

    app.add_handler(CallbackQueryHandler(topup_button_cb,
                                         pattern=r"^(top50|top100|top150|top_cancel)$"))
    app.add_handler(CallbackQueryHandler(upload_callback_cb, pattern=r"^upload_"))
    app.add_handler(CallbackQueryHandler(admin_topup_cb,
                                         pattern=r"^(approve_|deny_|unlimited_)"))
    app.add_handler(CallbackQueryHandler(admin_cb_router, pattern=r"^admin_"))
    app.add_handler(CallbackQueryHandler(user_account_cb,
                                         pattern=r"^(user_view_|user_delete_|user_renew_|my_accounts_list)"))
    app.add_handler(CallbackQueryHandler(user_renew_choose_cb,
                                         pattern=r"^user_renew_choose_"))
    app.add_handler(CallbackQueryHandler(topup_menu_cb, pattern=r"^topup_menu$"))

    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_menu_handler))

    print("🤖 Bot starting...")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

chmod +x "$BOT_PY" || true

############################
# PYTHON / SERVICE
############################

echo -e "\n=== Installing python & deps ==="
apt-get install -y python3-venv python3-pip curl jq iptables-persistent ufw tcpdump 1>/dev/null 2>/dev/null || true
python3 -m venv "$BOT_VENV"
"$BOT_VENV/bin/pip" install --upgrade pip 1>/dev/null 2>/dev/null || true
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

systemctl daemon-reload
systemctl enable zivpn-bot.service
systemctl restart zivpn-bot.service || systemctl start zivpn-bot.service || true

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
echo "  - Bot config: $BOT_CONFIG"
echo "  - Users:      $USERS_JSON"
echo "  - Accounts:   $ACCOUNTS_JSON"
echo "  - Topups:     $TOPUPS_JSON"
echo
echo "⚙️ Service commands:"
echo "  systemctl status zivpn.service"
echo "  systemctl restart zivpn.service"
echo "  systemctl status zivpn-bot.service"
echo "  systemctl restart zivpn-bot.service"
echo
if [ "$BROAD_DNAT" = true ]; then
  echo "To remove BROAD DNAT later, you can run:"
  echo "  iptables -t nat -D PREROUTING -i $INET_IF -p udp --dport 1:65535 -j DNAT --to-destination ${SERVER_IP}:5667"
  echo
fi
echo "✅ Done."
