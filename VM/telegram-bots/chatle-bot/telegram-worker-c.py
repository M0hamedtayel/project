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

BOT_USERNAME = os.getenv("BOT_USERNAME", "")

# Add the usernames of the nodes that respond in the group
EXPECTED_NODES = [""]

BASE_DIR = "chatle-bot"

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


def detect_type(asset):
    if is_url(asset):
        return "url"
    elif is_domain(asset):
        return "domain"
    else:
        return None  # rejected


# =========================
# BUILD COMMANDS
# =========================

def build_commands(asset):
    return [f"/alldb {asset}"]


# =========================
# UTILS & NORMALIZATION
# =========================

def normalize_host(h):
    """Clean and normalize host/URL string."""
    if not h: return ""
    h = h.strip().rstrip("/")
    if "://" in h:
        parts = h.split("://", 1)
        return f"{parts[0].lower()}://{parts[1]}"
    return h.lower()

def is_valid_host(h):
    """Strict validation for hosts, domains, and URIs."""
    h = h.lower().strip()
    if not h or len(h) < 3: return False

    # Known Protocols
    if h.startswith(("http://", "https://", "android://", "ftp://", "ssh://", "mongodb://", "mysql://")):
        return True

    # IPv4 / IPv6
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", h): return True
    if "[" in h and "]" in h: return True

    # Package Names / Domains
    if "." in h:
        if any(c.isalpha() for c in h):
            if not all(c in "0123456789.- " for c in h):
                return True
    return False


# =========================
# TREE-FORMAT PARSER (host:/path:/user:/pass:)
# =========================
# Handles the bot's structured tree output:
#   ┣━ host: "www.ebook.bsu.edu.eg"
#   ┣━ path: ""
#   ┣━ user: "30303272201339"
#   ┗━ pass: "sayedali11"

def parse_tree_format(text):
    entries = []
    seen = set()
    current = {}

    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue

        m = re.search(r'host:\s*"([^"]*)"', s)
        if m:
            # If a previous block never flushed, drop it (incomplete)
            current = {"host": m.group(1)}
            continue
        m = re.search(r'path:\s*"([^"]*)"', s)
        if m:
            current["path"] = m.group(1)
            continue
        m = re.search(r'user:\s*"([^"]*)"', s)
        if m:
            current["username"] = m.group(1)
            continue
        m = re.search(r'pass:\s*"([^"]*)"', s)
        if m:
            current["password"] = m.group(1)
            # 'pass:' is the last field of a block → flush entry
            if all(k in current for k in ("host", "username", "password")):
                host = current["host"].strip()
                path = current.get("path", "").strip()
                user = current["username"].strip()
                pwd = current["password"].strip()
                if host and user and pwd:
                    # Strip stray advertising/junk that bleeds into pass values
                    # e.g. "amira12345 ┃ @txt_aliens Free ULP / Logs"
                    if "┃" in pwd:
                        pwd = pwd.split("┃", 1)[0].strip()
                    full_host = f"{host}/{path}" if path else host
                    full_host = normalize_host(full_host)
                    key = f"{full_host}|{user.lower()}|{pwd.lower()}"
                    if key not in seen:
                        seen.add(key)
                        entries.append({
                            "host": full_host,
                            "username": user,
                            "password": pwd,
                            "format": "TREE"
                        })
            current = {}
            continue

    return entries


# =========================
# BUFFER-FORMAT PARSER
# =========================
# Handles buffer: lines like:
#   buffer: "https://bsu.edu.eg:khaled2015:2015*2018"
#   buffer: "bsu.edu.eg/umisswf/UI/LoginPage.aspx:amira:amira21486"
# Format: URL_or_domain[/path]:user:pass

def parse_buffer_format(text):
    entries = []
    seen = set()

    for line in text.splitlines():
        m = re.search(r'buffer:\s*"([^"]*)"', line)
        if not m:
            continue
        buf = m.group(1).strip()
        if not buf:
            continue

        host_full, user, pwd = _split_buffer(buf)
        if not host_full or not user or not pwd:
            continue

        # Strip stray advertising that bleeds into pass
        if "┃" in pwd:
            pwd = pwd.split("┃", 1)[0].strip()

        host_full = normalize_host(host_full)
        key = f"{host_full}|{user.lower()}|{pwd.lower()}"
        if key in seen:
            continue
        seen.add(key)
        entries.append({
            "host": host_full,
            "username": user,
            "password": pwd,
            "format": "BUFFER"
           
        })

    return entries


def _split_buffer(buf):
    """
    Split a buffer string 'URL_or_domain[/path]:user:pass' into 3 parts.
    Carefully handles URLs with ports/paths (colons inside host:port).
    Strategy: the user:pass are always the LAST two colon-separated segments.
    """
    if buf.count(":") < 2:
        return (None, None, None)

    # Split from the right: last segment = password, second-to-last = user
    parts = buf.rsplit(":", 2)
    if len(parts) != 3:
        return (None, None, None)
    host_full, user, pwd = parts[0].strip(), parts[1].strip(), parts[2].strip()
    return (host_full, user, pwd)


# =========================
# COMBINED PARSE RESULTS
# =========================

def parse_results(text):
    """Combined parser: tree format + buffer format + deduplication."""
    entries = []
    seen = set()

    for e in parse_tree_format(text) + parse_buffer_format(text):
        key = f"{e['host']}|{e['username'].lower()}|{e['password'].lower()}"
        if key not in seen:
            seen.add(key)
            entries.append(e)

    # Collect any lines that look like junk/noise for debugging
    unparsed_lines = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        # Skip known structural lines
        if any(k in s for k in ["host:", "path:", "user:", "pass:", "buffer:",
                                 "URLSEARCH", "Message:", "━", "┃", "┣", "┗", "Root"]):
            continue
        # Skip numeric-only index lines like "[0]", "[1]"
        if re.fullmatch(r"\[\d+\]", s):
            continue
        # Skip standalone brackets
        if re.fullmatch(r"[\[\]\d]+", s):
            continue
        unparsed_lines.append(s)

    return entries, unparsed_lines


# =========================
# SAVE JSON
# =========================

def save_json(asset, asset_type, parsed_data, unparsed_lines=None):
    filename = asset.replace("/", "_")

    output = {
        "asset": asset,
        "asset_type": asset_type,
        "searched_at": datetime.now(UTC).isoformat(),
        "provider": BOT_USERNAME,
        "results_count": len(parsed_data),
        "results": parsed_data,
        "unparsed_lines": unparsed_lines or []
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{PARSED_DIR}/{filename}_{timestamp}.json"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=4)

    print(f"\n[+] Parsed JSON saved: {path} ({len(parsed_data)} results)")
    return path


# =========================
# TEST LOCAL FILES
# =========================

async def test_parse_local(path):
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path)
                 if f.lower().endswith((".txt", ".log"))]
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

            parsed, unparsed = parse_results(content)
            print(f"[+] Found {len(parsed)} results, {len(unparsed)} unparsed lines.")

            if parsed:
                asset_name = os.path.basename(file).split("_")[0]
                json_path = save_json(asset_name, "test_local", parsed, unparsed)

                print(f"[+] Launching indexer...")
                os.system(f'"{sys.executable}" elastic-indexer-c.py "{json_path}"')
            else:
                print("[-] No valid entries found in this file.")
        except Exception as e:
            print(f"[-] Error processing {file}: {e}")


# =========================
# PROCESS ASSET
# =========================

# Status / control messages the bot sends before/around the file
STATUS_KEYWORDS = [
    "sending file", "📂", "not found", ":(", "query completed",
    "successfully", "✅", "searching", "please wait", "processing",
    "espera", "查询", "搜索", "正在",
]

async def process_asset(asset):
    asset_type = detect_type(asset)
    if asset_type is None:
        print(f"\n[-] Invalid asset: '{asset}'")
        print("[-] Only domains (example.com) or URLs (http(s)://...) are accepted.")
        return

    commands = build_commands(asset)

    print(f"\n[+] Asset: {asset}")
    print(f"[+] Type: {asset_type}")

    all_results = []
    all_unparsed = []
    all_raw_texts = []
    processed_ids = set()
    responded_nodes = set()

    expected_lower = [n.lower().replace("@", "") for n in EXPECTED_NODES]

    for command in commands:
        print("\n[+] Sending:")
        print(command)

        sent_message = await client.send_message(BOT_USERNAME, command)

        print(f"\n[+] Waiting for responses from nodes ({len(EXPECTED_NODES)} expected)...")

        max_wait = 120
        last_new_response_time = 0
        query_done = False      # set when we see "✅ Query completed" or receive a file
        not_found = False       # set when we see "Not found :("
        received_file = False   # set when a file attachment is downloaded

        for i in range(max_wait):
            messages = await client.get_messages(BOT_USERNAME, limit=30)

            for msg in messages:
                if msg.id <= sent_message.id or msg.id in processed_ids:
                    continue

                sender = await msg.get_sender()
                sender_username = getattr(sender, 'username', '') or ''
                sender_username = sender_username.lower()

                is_from_node = sender_username in expected_lower or not expected_lower

                if not is_from_node:
                    continue

                # Check for "Espera" rate-limit message
                if msg.message and "espera" in msg.message.lower():
                    match = re.search(r"(\d+\.?\d*)\s*s", msg.message.lower())
                    if match:
                        wait_time = float(match.group(1))
                        print(f"\n[!] Rate limit detected: {msg.message.strip()}")
                        print(f"[!] Waiting {wait_time}s as requested...")
                        await asyncio.sleep(wait_time + 1)
                        try:
                            await client.delete_messages(BOT_USERNAME, msg.id)
                        except:
                            pass
                        processed_ids.add(msg.id)
                        continue

                is_file = bool(msg.media)
                msg_text = (msg.message or "").strip()

                # ---- Detect "Not found :(" ----
                if msg_text and ("not found" in msg_text.lower() or ":(" in msg_text):
                    print(f"\n[!] Bot says: Not found — '{msg_text[:80]}'")
                    not_found = True
                    processed_ids.add(msg.id)
                    try:
                        await client.delete_messages(BOT_USERNAME, msg.id)
                    except:
                        pass
                    continue

                # ---- Detect status messages ("Sending file ... 📂", "✅ Query completed...") ----
                is_status = False
                if msg_text and not is_file:
                    msg_lower = msg_text.lower()
                    if any(k.lower() in msg_lower for k in STATUS_KEYWORDS):
                        print(f"[*] Status: {msg_text[:80]}")
                        is_status = True
                        processed_ids.add(msg.id)
                        if "completed" in msg_lower or "✅" in msg_text or "successfully" in msg_lower:
                            query_done = True
                        try:
                            await client.delete_messages(BOT_USERNAME, msg.id)
                        except:
                            pass
                        continue

                # ---- File response ----
                if is_file:
                    print(f"\n[+] Response detected from node: @{sender_username or 'unknown'}")
                    print(f"[+] Downloading file: {msg.id}")
                    processed_ids.add(msg.id)
                    if sender_username:
                        responded_nodes.add(sender_username)
                    last_new_response_time = i
                    received_file = True

                    downloaded_file = await client.download_media(msg, file=DOWNLOADS_DIR)
                    raw_text = ""
                    try:
                        with open(downloaded_file, "r", encoding="utf-8") as f:
                            raw_text = f.read()
                    except UnicodeDecodeError:
                        with open(downloaded_file, "r", encoding="utf-8", errors="ignore") as f:
                            raw_text = f.read()
                    except Exception as e:
                        print(f"[-] Error reading file: {e}")
                        raw_text = ""

                    if raw_text:
                        all_raw_texts.append(raw_text)
                        parsed, unparsed = parse_results(raw_text)
                        print(f"[+] Parsed {len(parsed)} entries from file, {len(unparsed)} lines unknown.")
                        all_results.extend(parsed)
                        all_unparsed.extend(unparsed)

                    try:
                        await client.delete_messages(BOT_USERNAME, msg.id)
                    except:
                        pass
                    continue

                # ---- Text response with actual data (no file) ----
                # Only treat as data if it contains credential-like content, not just chatter
                if msg_text and not is_status:
                    # Check if it looks like a data dump (has host:/user:/pass: or buffer:)
                    has_data = any(k in msg_text for k in
                                   ["host:", "user:", "pass:", "buffer:", "URLSEARCH"])
                    if has_data:
                        print(f"\n[+] Response detected from node: @{sender_username or 'unknown'}")
                        processed_ids.add(msg.id)
                        if sender_username:
                            responded_nodes.add(sender_username)
                        last_new_response_time = i

                        all_raw_texts.append(msg_text)
                        parsed, unparsed = parse_results(msg_text)
                        print(f"[+] Parsed {len(parsed)} entries from text, {len(unparsed)} lines unknown.")
                        all_results.extend(parsed)
                        all_unparsed.extend(unparsed)

                        try:
                            await client.delete_messages(BOT_USERNAME, msg.id)
                        except:
                            pass
                        continue
                    else:
                        # Just chatter — skip without processing
                        processed_ids.add(msg.id)
                        try:
                            await client.delete_messages(BOT_USERNAME, msg.id)
                        except:
                            pass
                        continue

            # ---- Break conditions ----

            # 1. "Not found" → stop waiting
            if not_found:
                print("\n[+] Query finished: not found.")
                break

            # 2. Got a file AND saw "Query completed successfully!" → done
            if received_file and query_done:
                # small grace period for trailing messages
                await asyncio.sleep(2)
                print(f"\n[+] Query completed successfully. Proceeding with {len(all_results)} results.")
                break

            # 3. Got a file but no completion message yet → keep waiting a bit
            if received_file and (i - last_new_response_time > 15):
                print(f"\n[+] File received, no more messages. Proceeding with {len(all_results)} results.")
                break

            # 4. All expected nodes responded
            if expected_lower and responded_nodes.issuperset(set(expected_lower)):
                await asyncio.sleep(2)
                print(f"[+] All nodes ({len(responded_nodes)}) answered. Continuing...")
                break

            # 5. Safety timeout: no new response for a while
            if i - last_new_response_time > 20 and len(processed_ids) > 0:
                print(f"[+] No new responses for a while. Proceeding with {len(responded_nodes)} nodes.")
                break

            await asyncio.sleep(2)

        if not processed_ids:
            print("\n[-] No response received from any node.")
            return

        if not_found:
            print("\n[-] No results: not found.")
            return

        try:
            await client.delete_messages(BOT_USERNAME, sent_message.id)
        except Exception:
            pass

    if not all_raw_texts:
        print("\n[-] No data collected to save.")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_asset = asset.replace("/", "_")

    raw_file = f"{RAW_DIR}/{safe_asset}_{timestamp}.txt"
    with open(raw_file, "w", encoding="utf-8") as f:
        f.write("\n\n".join(all_raw_texts))
    print(f"\n[+] Raw saved: {raw_file}")

    json_path = save_json(asset, asset_type, all_results, all_unparsed)

    print(f"[+] Launching indexer for {len(all_results)} total results...")
    os.system(
        f'"{sys.executable}" elastic-indexer-c.py "{json_path}"'
    )


# =========================
# MAIN
# =========================

async def main():
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("python3 telegram-worker-c.py <domain_or_url>")
        print("python3 telegram-worker-c.py --test path/to/file_or_dir")
        print("\nNote: only domains (example.com) and URLs (http(s)://...) are accepted.")
        return

    # Check for test mode
    if sys.argv[1] == "--test" and len(sys.argv) > 2:
        path = sys.argv[2]
        await test_parse_local(path)
        return

    asset = " ".join(sys.argv[1:]).strip()

    # Validate input: only domains or URLs accepted
    if detect_type(asset) is None:
        print(f"\n[-] Invalid asset: '{asset}'")
        print("[-] Only domains (example.com) or URLs (http(s)://...) are accepted.")
        return

    await client.start()
    print("\n[+] Telegram connected.")

    await process_asset(asset)

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
