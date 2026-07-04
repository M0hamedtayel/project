import asyncio
import json
import os
import re
import sys
from datetime import UTC, datetime

from telethon import TelegramClient

# ============================================
# TELEGRAM API CONFIG
# ============================================

api_id = 
api_hash = ""

BOT_USERNAME = ""
BASE_DIR = "def-bot"

DOWNLOADS_DIR = f"{BASE_DIR}/downloads"
RAW_DIR = f"{BASE_DIR}/raw"
PARSED_DIR = f"{BASE_DIR}/parsed"
SESSION_DIR = f"{BASE_DIR}/sessions"

os.makedirs(DOWNLOADS_DIR, exist_ok=True)
os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs(PARSED_DIR, exist_ok=True)
os.makedirs(SESSION_DIR, exist_ok=True)

client = TelegramClient(
    f"{SESSION_DIR}/main",
    api_id,
    api_hash,
)

# =========================
# ASSET DETECTION
# =========================

def is_url(asset):
    return asset.startswith("http://") or asset.startswith("https://")


def is_domain(asset):
    domain_regex = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return re.match(domain_regex, asset)


def is_email(asset):
    return re.match(r"[^@]+@[^@]+\.[^@]+", asset)


def is_username(asset):
    if asset.isdigit():
        return False

    if " " in asset:
        return False

    if "." in asset:
        return False

    return True


def detect_type(asset):
    if is_email(asset):
        return "email"
    elif is_url(asset):
        return "url"
    elif is_domain(asset):
        return "domain"
    elif is_username(asset):
        return "username"
    else:
        return "keyword"


# =========================
# BUILD COMMANDS
# =========================

def build_commands(asset, asset_type):
    commands = []

    if asset_type == "email":
        commands.append(f"/e {asset}")
    elif asset_type == "username":
        commands.append(f"/u {asset}")
    elif asset_type == "url":
        commands.append(f"/q {asset}")
    elif asset_type == "domain":
        commands.append(f"/q {asset}")
        commands.append(f"/k {asset}")
    elif asset_type == "keyword":
        commands.append(f"/k {asset}")

    return commands


# =========================
# CLEAN TEXT
# =========================

def clean_text(text):
    lines = text.splitlines()
    cleaned = []

    skip_words = [
        "author",
        "t.me/",
        "returned",
        "time:",
        "耗时",
        "返回",
        "作者",
        "━━━━━━━━",
        "📦",
        "🥵",
        "🔊",
        "Deleted message",
    ]

    for line in lines:
        line = line.strip()

        if not line:
            continue

        should_skip = False
        for word in skip_words:
            if word.lower() in line.lower():
                should_skip = True
                break

        if should_skip:
            continue

        cleaned.append(line)

    return "\n".join(cleaned)


# =========================
# PARSE RESULTS
# =========================

def parse_results(text):
    entries = []
    current = {}

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        if "Host:" in line or "主机:" in line:
            value = line.split(":", 1)[1].strip()
            current["host"] = value

        elif "URL:" in line or "网址:" in line:
            value = line.split(":", 1)[1].strip()
            current["url"] = value

        elif "User:" in line or "账户:" in line:
            value = line.split(":", 1)[1].strip()
            current["username"] = value

        elif "Pass:" in line or "密码:" in line:
            value = line.split(":", 1)[1].strip()
            current["password"] = value
            entries.append(current)
            current = {}

    return entries


# =========================
# SAVE JSON
# =========================

def save_json(asset, asset_type, parsed_data):
    filename = asset.replace("/", "_")

    output = {
        "asset": asset,
        "asset_type": asset_type,
        "searched_at": datetime.now(UTC).isoformat(),
        "provider": BOT_USERNAME,
        "results": parsed_data,
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{PARSED_DIR}/{filename}_{timestamp}.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=4)

    print("\n[+] Parsed JSON saved:")
    print(path)
    return path

# =========================
# TEST LOCAL FILES
# =========================

async def test_parse_local(path):
    if os.path.isdir(path):
        files = [
            os.path.join(path, f)
            for f in os.listdir(path)
            if f.lower().endswith((".txt", ".log"))
        ]
    else:
        files = [path]

    if not files:
        print("[-] No files found to process.")
        return

    for file in files:
        print(f"\n[+] Testing parse on: {file}")

        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            cleaned = clean_text(content)
            parsed = parse_results(cleaned)

            print(f"[+] Found {len(parsed)} results.")

            if parsed:
                asset_name = os.path.basename(file).split("_")[0]

                json_path = save_json(
                    asset_name,
                    "test_local",
                    parsed,
                )

                print("[+] Launching indexer...")

                os.system(
                    f'"{sys.executable}" elastic-indexer-d.py "{json_path}"'
                )

            else:
                print("[-] No valid entries found.")

        except Exception as e:
            print(f"[-] Error processing {file}: {e}")
# =========================
# PROCESS ASSET
# =========================

async def process_asset(asset):
    asset_type = detect_type(asset)
    commands = build_commands(asset, asset_type)

    print(f"\n[+] Asset: {asset}")
    print(f"[+] Type: {asset_type}")

    all_results = []
    all_raw_texts = []
    processed_ids = set()

    for command in commands:
        print("\n[+] Sending:")
        print(command)

        sent_message = await client.send_message(BOT_USERNAME, command)

        print("\n[+] Waiting for bot response...")

        messages_found = []

        for _ in range(60):
            messages = await client.get_messages(BOT_USERNAME, limit=15)

            for msg in messages:
                if msg.id <= sent_message.id:
                    continue

                if msg.media:
                    if msg.id not in processed_ids:
                        print(f"\n[+] File response detected: {msg.id}")
                        processed_ids.add(msg.id)
                        messages_found.append(msg)

                elif msg.message:
                    text = msg.message.lower()
                    if asset.lower() in text:
                        print(f"\n[+] Text response detected: {msg.id}")
                        if msg.id not in processed_ids:
                            processed_ids.add(msg.id)
                            messages_found.append(msg)

            if messages_found:
                break

            await asyncio.sleep(2)

        if not messages_found:
            print("\n[-] No response received.")

            try:
                await client.delete_messages(BOT_USERNAME, sent_message.id)
            except Exception:
                pass

            continue

        for message in messages_found:
            if message.media:
                print("\n[+] Downloading file...")

                downloaded_file = await client.download_media(
                    message,
                    file=DOWNLOADS_DIR,
                )

                print(downloaded_file)

                try:
                    with open(
                        downloaded_file,
                        "r",
                        encoding="utf-8",
                        errors="ignore",
                    ) as f:
                        raw_text = f.read()
                except Exception as e:
                    print(e)
                    continue
            else:
                raw_text = message.message

            all_raw_texts.append(raw_text)

            try:
                await client.delete_messages(BOT_USERNAME, message.id)
            except Exception:
                pass

            cleaned = clean_text(raw_text)
            parsed = parse_results(cleaned)
            all_results.extend(parsed)

        try:
            await client.delete_messages(BOT_USERNAME, sent_message.id)
        except Exception:
            pass

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_asset = asset.replace("/", "_")

    raw_file = f"{RAW_DIR}/{safe_asset}_{timestamp}.txt"

    with open(raw_file, "w", encoding="utf-8") as f:
        f.write("\n\n".join(all_raw_texts))

    print(f"\n[+] Raw saved: {raw_file}")

    json_path = save_json(asset, asset_type, all_results)

    os.system(
        f'"{sys.executable}" elastic-indexer-d.py "{json_path}"'
    )


# =========================
# MAIN
# =========================

async def main():
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("python telegram-worker-d.py asset")
        print("python telegram-worker-d.py --test path/to/file_or_directory")
        return

    # Test mode
    if sys.argv[1] == "--test":
        if len(sys.argv) < 3:
            print("Usage:")
            print("python telegram-worker-d.py --test path")
            return

        await test_parse_local(sys.argv[2])
        return

    asset = " ".join(sys.argv[1:]).strip()

    await client.start()
    print("\n[+] Telegram connected.")

    await process_asset(asset)

    await client.disconnect()
if __name__ == "__main__":
    asyncio.run(main())
