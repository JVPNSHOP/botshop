#!/usr/bin/env bash
# install_zivpn_bot_fixed.sh
# ZIVPN UDP Installer + Telegram Bot installer (fixed: duration callback + QR shown as image)
# Run as root: sudo bash install_zivpn_bot_fixed.sh
set -euo pipefail

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

echo -e "\n=== Updating server packages ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

echo -e "\n=== Stopping existing zivpn.service (if any) ==="
systemctl stop zivpn.service 1>/dev/null 2>/dev/null || true

echo -e "\n=== Downloading ZIVPN UDP binary ==="
ZIVPN_RELEASE_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
if curl -fsSL "$ZIVPN_RELEASE_URL" -o "$ZIVPN_BIN"; then
  chmod +x "$ZIVPN_BIN"
  echo "zivpn installed to $ZIVPN_BIN"
else
  echo "Warning: failed to download zivpn binary from $ZIVPN_RELEASE_URL"
fi

if [ ! -f "$ZIVPN_ETC/config.json" ]; then
cat > "$ZIVPN_ETC/config.json" <<'JSON'
{
  "listen": ":5667",
  "config": ["zi"]
}
JSON
fi

echo -e "\n=== Creating self-signed cert (if not present) ==="
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
  -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
  -keyout "$ZIVPN_ETC/zivpn.key" -out "$ZIVPN_ETC/zivpn.crt" 1>/dev/null 2>/dev/null || true

sysctl -w net.core.rmem_max=16777216 1>/dev/null 2>/dev/null || true
sysctl -w net.core.wmem_max=16777216 1>/dev/null 2>/dev/null || true

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
systemctl start zivpn.service || true

INET_IF=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1 || echo "eth0")
iptables -t nat -A PREROUTING -i "$INET_IF" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 1>/dev/null 2>/dev/null || true
ufw allow 6000:19999/udp || true
ufw allow 5667/udp || true

echo -e "\n=== ZIVPN installed ==="

echo -e "\n--- Telegram Bot Setup ---"
read -rp "Enter Telegram Bot Token (BotFather token): " BOT_TOKEN
read -rp "Enter Admin Telegram ID (numeric): " ADMIN_ID
read -rp "Enter Hostname (server name): " HOSTNAME
read -rp "Enter Bank Name: " BANK_NAME
read -rp "Enter Bank Number: " BANK_NUMBER
read -rp "Enter Bank Holder Name: " BANK_HOLDER
read -rp "Enter QR Code Link (image URL) or leave empty: " QR_LINK

cat > "$BOT_CONFIG" <<JSON
{
  "bot_token": "${BOT_TOKEN}",
  "admin_id": ${ADMIN_ID},
  "hostname": "${HOSTNAME}",
  "bank_name": "${BANK_NAME}",
  "bank_number": "${BANK_NUMBER}",
  "bank_holder": "${BANK_HOLDER}",
  "qr_link": "${QR_LINK}"
}
JSON

for f in "$ACCOUNTS_JSON" "$USERS_JSON" "$TOPUPS_JSON"; do
  if [ ! -f "$f" ]; then
    echo "[]" > "$f"
  fi
done

cat > "$BOT_PY" <<'PY'
#!/usr/bin/env python3
# bot.py - ZIVPN Telegram Bot (fixed duration callback + QR image)
import json, logging, os, time, datetime, uuid
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
ADMIN_ID = int(cfg.get("admin_id", 0))
BOT_TOKEN = cfg.get("bot_token", "")
HOSTNAME = cfg.get("hostname", "")
BANK_NAME = cfg.get("bank_name", "")
BANK_NUMBER = cfg.get("bank_number", "")
BANK_HOLDER = cfg.get("bank_holder", "")
QR_LINK = cfg.get("qr_link", "")

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

(CHOOSING, TOPUP_AMOUNT, WAITING_UPLOAD, CREATE_USERNAME, CREATE_PASSWORD, CHOOSE_DURATION) = range(6)

def main_menu_kb():
    kb = [
        [KeyboardButton("Top-up Credit"), KeyboardButton("Create Account")],
        [KeyboardButton("My Credit"), KeyboardButton("Admin Panel")]
    ]
    return ReplyKeyboardMarkup(kb, resize_keyboard=True, one_time_keyboard=False)

def topup_amount_kb():
    kb = [
        [InlineKeyboardButton("50", callback_data="top50"),
         InlineKeyboardButton("100", callback_data="top100"),
         InlineKeyboardButton("150", callback_data="top150")],
        [InlineKeyboardButton("Cancel", callback_data="top_cancel")]
    ]
    return InlineKeyboardMarkup(kb)

def durations_kb(available_credit):
    buttons = []
    if available_credit >= 50:
        buttons.append(InlineKeyboardButton("30 days (50)", callback_data="dur30"))
    if available_credit >= 100:
        buttons.append(InlineKeyboardButton("60 days (100)", callback_data="dur60"))
    if available_credit >= 150:
        buttons.append(InlineKeyboardButton("90 days (150)", callback_data="dur90"))
    buttons.append(InlineKeyboardButton("Cancel", callback_data="cancel_create"))
    return InlineKeyboardMarkup([[b] for b in buttons])

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    users = read_json(USERS, [])
    found = next((u for u in users if u["id"] == user.id), None)
    if not found:
        users.append({"id": user.id, "username": user.username or "", "credit": 0})
        write_json(USERS, users)
    await update.message.reply_text(
        f"Hello {user.first_name}! Welcome to {HOSTNAME} ZIVPN Bot.\nChoose an option:",
        reply_markup=main_menu_kb()
    )

async def my_credit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    users = read_json(USERS, [])
    u = next((x for x in users if x["id"] == uid), None)
    c = u["credit"] if u else 0
    await update.message.reply_text(f"Your credit: {c}")

# TOPUP FLOW
async def topup_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Choose an amount to top-up:", reply_markup=topup_amount_kb())

async def topup_button_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    if data == "top_cancel":
        await query.edit_message_text("Cancelled top-up.")
        return
    amount = {"top50":50,"top100":100,"top150":150}.get(data,0)
    if amount == 0:
        await query.edit_message_text("Unknown option.")
        return
    topups = read_json(TOPUPS, [])
    tid = str(uuid.uuid4())
    topups.append({"id":tid,"user_id":query.from_user.id,"amount":amount,"status":"pending","created_at":int(time.time())})
    write_json(TOPUPS, topups)
    text = (f"Please transfer *{amount}* to:\n\nBank: {BANK_NAME}\nNumber: `{BANK_NUMBER}`\nHolder: {BANK_HOLDER}\n\nAfter transfer, upload the transfer screenshot using the button below.")
    keyboard = [[InlineKeyboardButton("Upload Transfer Screenshot", callback_data=f"upload_{tid}")]]
    await query.edit_message_text(text, parse_mode="Markdown", reply_markup=InlineKeyboardMarkup(keyboard))
    # If QR image link provided, send it as an image so user sees QR directly:
    if QR_LINK:
        try:
            await context.bot.send_photo(chat_id=query.from_user.id, photo=QR_LINK, caption="Scan QR to pay")
        except Exception as e:
            # fallback: ignore send photo error (maybe non-image URL)
            pass

async def upload_callback_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    if not data.startswith("upload_"):
        await query.edit_message_text("Invalid upload request.")
        return
    tid = data.split("_",1)[1]
    context.user_data["awaiting_upload_for"] = tid
    await query.edit_message_text("Please send a photo of your bank transfer (screenshot). It will be forwarded to admin for approval.")

async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if "awaiting_upload_for" not in context.user_data:
        await update.message.reply_text("To top-up press Top-up Credit in the menu.")
        return
    tid = context.user_data.pop("awaiting_upload_for")
    topups = read_json(TOPUPS, [])
    t = next((x for x in topups if x["id"]==tid), None)
    if not t:
        await update.message.reply_text("Top-up session not found.")
        return
    photo = update.message.photo[-1]
    file_id = photo.file_id
    t["photo_file_id"] = file_id
    write_json(TOPUPS, topups)
    caption = f"Top-up request:\nUser: {update.effective_user.id} ({update.effective_user.full_name})\nAmount: {t['amount']}\nTid: {tid}"
    keyboard = InlineKeyboardMarkup([[InlineKeyboardButton("Approve", callback_data=f"approve_{tid}"), InlineKeyboardButton("Deny", callback_data=f"deny_{tid}")]])
    await context.bot.send_photo(chat_id=ADMIN_ID, photo=file_id, caption=caption, reply_markup=keyboard)
    await update.message.reply_text("Payment screenshot sent to admin for review. You will be notified when approved.")

async def admin_topup_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("Unauthorized.")
        return
    data = query.data
    tid = data.split("_",1)[1] if "_" in data else None
    if not tid:
        await query.edit_message_text("Bad data.")
        return
    topups = read_json(TOPUPS, [])
    t = next((x for x in topups if x["id"]==tid), None)
    if not t:
        await query.edit_message_text("Top-up not found.")
        return
    if data.startswith("approve_"):
        t["status"]="approved"; t["approved_by"]=ADMIN_ID; t["approved_at"]=int(time.time())
        users = read_json(USERS, [])
        u = next((x for x in users if x["id"]==t["user_id"]), None)
        if not u:
            users.append({"id":t["user_id"], "username":"", "credit": t["amount"]})
        else:
            u["credit"] = u.get("credit",0) + t["amount"]
        write_json(USERS, users)
        write_json(TOPUPS, topups)
        await context.bot.send_message(chat_id=t["user_id"], text=f"✅ Your top-up of {t['amount']} has been approved. Your credit has been updated.")
        await query.edit_message_caption(caption=(query.message.caption or "") + "\n\n✅ Approved by admin.", reply_markup=None)
    else:
        t["status"]="denied"; t["approved_by"]=ADMIN_ID; t["approved_at"]=int(time.time())
        write_json(TOPUPS, topups)
        await context.bot.send_message(chat_id=t["user_id"], text=f"❌ Your top-up of {t['amount']} was denied by admin.")
        await query.edit_message_caption(caption=(query.message.caption or "") + "\n\n❌ Denied by admin.", reply_markup=None)

# CREATE ACCOUNT flow (ConversationHandler)
async def create_account_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Please send desired username:", reply_markup=ReplyKeyboardRemove())
    return CREATE_USERNAME

async def create_username(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uname = update.message.text.strip()
    context.user_data["create_username"] = uname
    await update.message.reply_text("Now send desired password:")
    return CREATE_PASSWORD

async def create_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    upass = update.message.text.strip()
    context.user_data["create_password"] = upass
    users = read_json(USERS, [])
    uid = update.effective_user.id
    u = next((x for x in users if x["id"]==uid), None)
    credit = u.get("credit",0) if u else 0
    if credit < 50:
        await update.message.reply_text("You need at least 50 credit to create an account.", reply_markup=main_menu_kb())
        return ConversationHandler.END
    await update.message.reply_text("Choose duration based on your credit:", reply_markup=durations_kb(credit))
    # stay in conversation state CHOOSE_DURATION and wait for callback queries dur30/dur60/dur90
    return CHOOSE_DURATION

async def create_duration_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    uid = query.from_user.id
    users = read_json(USERS, [])
    u = next((x for x in users if x["id"]==uid), None)
    credit = u.get("credit",0) if u else 0
    if data == "cancel_create":
        await query.edit_message_text("Cancelled account creation.", reply_markup=main_menu_kb())
        return ConversationHandler.END
    mapping = {"dur30":(30,50), "dur60":(60,100), "dur90":(90,150)}
    if data not in mapping:
        await query.edit_message_text("Invalid option.", reply_markup=main_menu_kb())
        return ConversationHandler.END
    days, cost = mapping[data]
    if credit < cost:
        await query.edit_message_text("Insufficient credit for that duration.", reply_markup=main_menu_kb())
        return ConversationHandler.END
    # deduct credit
    u["credit"] = credit - cost
    write_json(USERS, users)
    # create account
    accounts = read_json(ACCOUNTS, [])
    uname = context.user_data.get("create_username")
    upass = context.user_data.get("create_password")
    expiry_ts = int(time.time()) + days*24*3600
    account = {"id":str(uuid.uuid4()), "username":uname, "password":upass, "created_by":uid, "created_at":int(time.time()), "expiry":expiry_ts, "days":days, "bound_device_id":None, "used_devices":[]}
    accounts.append(account)
    write_json(ACCOUNTS, accounts)
    # append password to zivpn config
    try:
        zcfg = read_json(ZIVPN_CONFIG, {})
        if "config" not in zcfg: zcfg["config"] = ["zi"]
        if upass not in zcfg["config"]:
            zcfg["config"].append(upass)
            write_json(ZIVPN_CONFIG, zcfg)
    except Exception as e:
        log.error("Failed updating ZIVPN config: %s", e)
    expiry_str = datetime.datetime.utcfromtimestamp(expiry_ts).strftime("%Y-%m-%d")
    server_ip = os.getenv("SERVER_IP","")
    if not server_ip:
        try:
            import socket
            server_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            server_ip = "your_server_ip"
    msg = (f"✅ Account created!\n\nServer: {server_ip}\nUsername: {uname}\nPassword: {upass}\nExpiry: {expiry_str}\nDays: {days}\n\nNote: This account is restricted to 1 device. Use /bind <device-id> from your first device to bind it.")
    # edit the previous message (the duration selection) to show result
    await query.edit_message_text(msg, reply_markup=main_menu_kb())
    await context.bot.send_message(chat_id=ADMIN_ID, text=f"New account created by {uid}\nUsername: {uname}\nExpiry: {expiry_str}\nDays: {days}")
    return ConversationHandler.END

async def bind_device_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    parts = update.message.text.strip().split()
    if len(parts) < 2:
        await update.message.reply_text("Usage: /bind <device-id>")
        return
    device_id = parts[1]
    uid = update.effective_user.id
    accounts = read_json(ACCOUNTS, [])
    acc = next((a for a in accounts if a["created_by"]==uid), None)
    if not acc:
        await update.message.reply_text("You have no account created by you to bind.")
        return
    if acc.get("bound_device_id"):
        if acc["bound_device_id"] == device_id:
            await update.message.reply_text("This device is already bound to your account.")
        else:
            await update.message.reply_text("An active device is already bound. You cannot bind another device.")
        return
    acc["bound_device_id"] = device_id
    acc.setdefault("used_devices", []).append({"device_id": device_id, "bound_at": int(time.time())})
    write_json(ACCOUNTS, accounts)
    await update.message.reply_text("✅ Device bound successfully. Only this device will be allowed to use the account.")

@admin_only
async def admin_panel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    accounts = read_json(ACCOUNTS, [])
    users = read_json(USERS, [])
    topups = read_json(TOPUPS, [])
    total_users = len(users)
    total_accounts = len(accounts)
    total_credit = sum(u.get("credit",0) for u in users)
    text = (f"Admin Panel\n\nTotal users: {total_users}\nTotal accounts: {total_accounts}\nTotal credit (sum): {total_credit}\n\nBank: {BANK_NAME}\nNumber: {BANK_NUMBER}\nHolder: {BANK_HOLDER}\nQR Link: {QR_LINK}\nHostname: {HOSTNAME}\nAdmin ID: {ADMIN_ID}")
    kb = [[InlineKeyboardButton("List Users", callback_data="admin_list_users"), InlineKeyboardButton("List Accounts", callback_data="admin_list_accounts")],[InlineKeyboardButton("Pending Topups", callback_data="admin_pending_topups")]]
    await update.message.reply_text(text, reply_markup=InlineKeyboardMarkup(kb))

async def admin_cb_router(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("Unauthorized.")
        return
    data = query.data
    if data == "admin_list_users":
        users = read_json(USERS, [])
        text = "Users:\n" + "\n".join([f"{u['id']} - credit: {u.get('credit',0)}" for u in users]) or "No users."
        await query.edit_message_text(text)
    elif data == "admin_list_accounts":
        accounts = read_json(ACCOUNTS, [])
        lines = []
        for a in accounts:
            exp = datetime.datetime.utcfromtimestamp(a['expiry']).strftime("%Y-%m-%d")
            lines.append(f"{a['username']} by {a['created_by']} exp:{exp} bound:{a.get('bound_device_id')}")
        await query.edit_message_text("Accounts:\n" + ("\n".join(lines) or "No accounts."))
    elif data == "admin_pending_topups":
        topups = read_json(TOPUPS, [])
        pend = [t for t in topups if t.get("status")=="pending"]
        if not pend:
            await query.edit_message_text("No pending topups.")
            return
        for t in pend:
            text = f"Topup {t['id']} user:{t['user_id']} amount:{t['amount']}"
            if t.get("photo_file_id"):
                await context.bot.send_photo(chat_id=ADMIN_ID, photo=t['photo_file_id'], caption=text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Approve", callback_data=f"approve_{t['id']}"), InlineKeyboardButton("Deny", callback_data=f"deny_{t['id']}")]]))
            else:
                await context.bot.send_message(chat_id=ADMIN_ID, text=text, reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Approve", callback_data=f"approve_{t['id']}"), InlineKeyboardButton("Deny", callback_data=f"deny_{t['id']}")]]))

async def renew_cb(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id != ADMIN_ID:
        await query.edit_message_text("Unauthorized.")
        return
    data = query.data
    if not data.startswith("renew_"):
        await query.edit_message_text("Unknown action.")
        return
    parts = data.split("_")
    if len(parts) < 3:
        await query.edit_message_text("Bad renew data.")
        return
    aid = parts[1]; days = int(parts[2])
    accounts = read_json(ACCOUNTS, [])
    acc = next((a for a in accounts if a["id"]==aid), None)
    if not acc:
        await query.edit_message_text("Account not found.")
        return
    acc["expiry"] = acc.get("expiry", int(time.time())) + days*24*3600
    write_json(ACCOUNTS, accounts)
    await query.edit_message_text(f"Renewed account {acc['username']} by {days} days.")

async def text_menu_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    txt = update.message.text.strip().lower()
    if txt in ("top-up credit","topup","top-up","💳"):
        return await topup_command(update, context)
    if txt in ("create account","👤"):
        return await create_account_cmd(update, context)
    if txt in ("my credit","💰"):
        return await my_credit(update, context)
    if txt in ("admin panel","🛠"):
        return await admin_panel(update, context)
    await update.message.reply_text("Choose an option:", reply_markup=main_menu_kb())

def main():
    if not BOT_TOKEN:
        print("Bot token not configured in", BOT_CONFIG)
        return
    app = ApplicationBuilder().token(BOT_TOKEN).concurrent_updates(True).build()

    # Conversation handler for create account: NOTE we register the duration callback pattern specifically
    conv = ConversationHandler(
        entry_points=[CommandHandler("create", create_account_cmd), MessageHandler(filters.Regex("(?i)^create account$"), create_account_cmd)],
        states={
            CREATE_USERNAME: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_username)],
            CREATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, create_password)],
            # IMPORTANT: CHOOSE_DURATION accepts CallbackQueryHandler with strict pattern
            CHOOSE_DURATION: [CallbackQueryHandler(create_duration_cb, pattern="^(dur30|dur60|dur90|cancel_create)$")]
        },
        fallbacks=[],
        per_user=True
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("menu", start))
    app.add_handler(CommandHandler("credit", my_credit))
    app.add_handler(CommandHandler("bind", bind_device_cmd))

    # Add conversation handler (handles create account flow and its duration callbacks)
    app.add_handler(conv)

    # Topup callbacks
    app.add_handler(CallbackQueryHandler(topup_button_cb, pattern="^top(50|100|150|_cancel)?"))
    app.add_handler(CallbackQueryHandler(upload_callback_cb, pattern="^upload_"))
    app.add_handler(CallbackQueryHandler(admin_topup_cb, pattern="^(approve_|deny_)"))
    app.add_handler(CallbackQueryHandler(admin_cb_router, pattern="^admin_"))
    app.add_handler(CallbackQueryHandler(renew_cb, pattern="^renew_"))

    app.add_handler(MessageHandler(filters.PHOTO, photo_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, text_menu_handler))

    print("Bot started...")
    app.run_polling()

if __name__ == "__main__":
    main()
PY

chmod +x "$BOT_PY"

echo -e "\n=== Installing Python & dependencies ==="
apt-get install -y python3-venv python3-pip curl 1>/dev/null 2>/dev/null || true
python3 -m venv "$BOT_VENV"
"$BOT_VENV/bin/pip" install --upgrade pip 1>/dev/null 2>/dev/null || true
"$BOT_VENV/bin/pip" install python-telegram-bot==20.5 1>/dev/null 2>/dev/null || true

cat > "$BOT_SERVICE" <<SERVICE
[Unit]
Description=ZIVPN Telegram Bot (fixed)
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
systemctl start zivpn-bot.service || true

echo -e "\nInstall finished."
echo "Bot config: $BOT_CONFIG"
echo "Users: $USERS_JSON"
echo "Accounts: $ACCOUNTS_JSON"
echo "Topups: $TOPUPS_JSON"
echo "Use: systemctl [status|restart] zivpn-bot.service"
