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
EXPECTED_NODES = ["", "", ""] 

BASE_DIR = "busc-bot"

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

def build_commands(asset):
    return [f"/b {asset}"]


# =========================
# CLEAN TEXT
# =========================

def clean_text(text):
    lines = text.splitlines()
    cleaned = []

    skip_words = [
        "author", "t.me/", "returned", "time:", "耗时", "返回", "作者", "Deleted message",
        "REPORTE DE BÚSQUEDA", "RESULTADOS", "BUSCADOR PRO",
        "ID de consulta", "Usuario", "Consulta", "Duración", "Fuentes leídas", "Generado", "Resultados",
    ]

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # separators
        if re.fullmatch(r"[=\-_/\\|. ]{4,}", line):
            continue

        # source labels
        if re.match(r"^\[\d+\]", line):
            continue

        # ascii art
        if len(re.findall(r"[\\/_|]", line)) >= 3:
            continue

        if any(word.lower() in line.lower() for word in skip_words):
            continue

        cleaned.append(line)

    return "\n".join(cleaned)


# =========================
# UTILS & NORMALIZATION
# =========================

def normalize_host(h):
    """Clean and normalize host/URL string."""
    if not h: return ""
    h = h.strip().rstrip("/")
    # If it's a domain/URL, lower properly
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
        # Must contain at least one alpha char to be a domain (not 1.2.3)
        if any(c.isalpha() for c in h):
            # Avoid picking metadata or separators
            if not all(c in "0123456789.- " for c in h):
                return True
    return False

def get_symbol_ratio(line):
    """Detects ASCII art or separators based on non-alphanumeric ratio."""
    if not line: return 0
    # Characters common in ASCII art or banners
    symbols = set(r"\/|_=-#*+`~:. ")
    count = sum(1 for c in line if c in symbols)
    return count / len(line)

# =========================
# CLEAN TEXT
# =========================

def clean_text(text):
    """Filters out known headers, banners, and heavy ASCII junk."""
    lines = text.splitlines()
    cleaned = []
    
    skip_keywords = [
        "REPORTE DE BÚSQUEDA", "BUSCADOR PRO", "ID de consulta", 
        "Usuario", "Consulta", "Duración", "Fuentes leídas", 
        "Generado", "Resultados", "returned in", "Time taken",
        "Author", "t.me/", "🐂 fuente"
    ]

    for line in lines:
        line_strip = line.strip()
        if not line_strip: continue
        
        # 1. Skip if ratio is too high (Decorations/ASCII Art)
        if len(line_strip) > 10 and get_symbol_ratio(line_strip) > 0.8:
            continue
            
        # 2. Skip obvious metadata/headers
        if any(k.lower() in line_strip.lower() for k in skip_keywords):
            continue
            
        cleaned.append(line_strip)
        
    return "\n".join(cleaned)

# =========================
# CANDIDATE ENGINE & SCORING
# =========================

def score_candidate(h, u, p):
    """Assigns a confidence score to a potential match."""
    score = 0
    if not h or not u or not p: return 0
    
    # Host Score
    h_low = h.lower()
    if h_low.startswith(("https://", "android://")): score += 55
    elif h_low.startswith("http://"): score += 50
    elif is_valid_host(h): score += 40
    
    if "/" in h and not h.endswith("://"): score += 10 # Path presence
    
    # User Score
    if "@" in u and "." in u: score += 20 # Email
    elif re.match(r"^\+?\d{7,15}$", u): score += 15 # Phone
    elif u.isalnum(): score += 10
    
    # Password Score
    if len(p) >= 6: score += 10
    if any(c.isdigit() for c in p) and any(c.isalpha() for c in p): score += 10

    return score

def generate_candidates(line):
    """Generates multiple interpretations for a single line."""
    candidates = []
    
    # Format F: TAB
    if "\t" in line:
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) >= 3:
            candidates.append({"host": parts[0], "user": parts[1], "pass": parts[2], "format": "TAB_SEP"})

    # Format G, J, K: Whitespace
    parts_ws = line.split()
    if len(parts_ws) == 3:
        candidates.append({"host": parts_ws[0], "user": parts_ws[1], "pass": parts_ws[2], "format": "SPACE_SEP"})
    elif len(parts_ws) >= 2:
        # Case: url user:pass
        for i in range(len(parts_ws)-1):
            if ":" in parts_ws[i+1]:
                u, p = parts_ws[i+1].rsplit(":", 1)
                candidates.append({"host": parts_ws[i], "user": u, "pass": p, "format": "URL_SPACE_USERPASS"})

    # Format A, B, C, D, E, I, L: Colon-based
    # We generate multiple splits if there are many colons
    if line.count(":") >= 2:
        parts_c = line.split(":")
        
        # A/B/I: host:user:pass (last two are creds)
        try:
            h, u, p = line.rsplit(":", 2)
            candidates.append({"host": h, "user": u, "pass": p, "format": "COLON_HUP"})
        except: pass
        
        # D/E/L: user:pass:url (first two are creds)
        try:
            u, p, h = line.split(":", 2)
            candidates.append({"host": h, "user": u, "pass": p, "format": "COLON_UPH"})
        except: pass

        # C: host:port:user:pass (4 parts)
        if len(parts_c) >= 4:
            try:
                # Assuming host:port is the first two
                h_port = ":".join(parts_c[:2])
                candidates.append({"host": h_port, "user": parts_c[2], "pass": parts_c[3], "format": "COLON_HPUP"})
            except: pass

    return candidates

# =========================
# PARSE RESULTS
# =========================

def parse_results(text):
    """Refactored parsing pipeline."""
    entries = []
    seen = set()
    unparsed_lines = []
    current_label_data = {}
    
    cleaned_content = clean_text(text)
    lines = cleaned_content.splitlines()

    for line in lines:
        line = line.strip()
        if not line: continue

        # --- 1. Label Format Engine (Format H) ---
        is_label = False
        if any(k in line for k in ["Host:", "URL:", "网址:", "主机:"]):
            current_label_data["host"] = line.split(":", 1)[1].strip()
            is_label = True
        elif any(k in line for k in ["User:", "Login:", "Account:", "账户:", "账号:"]):
            current_label_data["username"] = line.split(":", 1)[1].strip()
            is_label = True
        elif any(k in line for k in ["Pass:", "Password:", "密碼:", "密码:"]):
            current_label_data["password"] = line.split(":", 1)[1].strip()
            is_label = True
            if current_label_data.get("host") and current_label_data.get("username") and current_label_data.get("password"):
                h = normalize_host(current_label_data["host"])
                u = current_label_data["username"]
                p = current_label_data["password"]
                entries.append({"host": h, "username": u, "password": p, "format": "LABEL", "confidence": 100})
                current_label_data = {}
        if is_label: continue

        # --- 2. Candidate Pipeline ---
        candidates = generate_candidates(line)
        best_candidate = None
        max_score = -1

        for cand in candidates:
            score = score_candidate(cand["host"], cand["user"], cand["pass"])
            if score > max_score:
                max_score = score
                best_candidate = cand

        # --- 3. Selection & Normalization ---
        if best_candidate and max_score >= 30: # Threshold for validity
            norm_h = normalize_host(best_candidate["host"])
            u = best_candidate["user"]
            p = best_candidate["pass"]
            
            # --- 4. Deduplication ---
            key = f"{norm_h}|{u.lower()}|{p.lower()}"
            if key not in seen:
                seen.add(key)
                entries.append({
                    "host": norm_h,
                    "username": u,
                    "password": p,
                    "format": best_candidate["format"],
                    "confidence": max_score
                })
        else:
            # --- 5. Unknown Lines ---
            unparsed_lines.append(line)

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


# =========================# TEST LOCAL FILES
# =========================

async def test_parse_local(path):
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".txt") or f.endswith(".log")]
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
                # Use filename as asset name for testing
                asset_name = os.path.basename(file).split("_")[0]
                json_path = save_json(asset_name, "test_local", parsed, unparsed)
                
                print(f"[+] Launching indexer...")
                os.system(f'"{sys.executable}" elastic-indexer-b.py "{json_path}"')
            else:
                print("[-] No valid entries found in this file.")
        except Exception as e:
            print(f"[-] Error processing {file}: {e}")


# =========================# PROCESS ASSET
# =========================

async def process_asset(asset):
    asset_type = detect_type(asset)
    commands = build_commands(asset)

    print(f"\n[+] Asset: {asset}")
    print(f"[+] Type: {asset_type}")

    all_results = []
    all_unparsed = []
    all_raw_texts = []
    processed_ids = set()
    responded_nodes = set()

    # Create a mapping for easier sender ID/username check
    expected_lower = [n.lower().replace("@", "") for n in EXPECTED_NODES]

    for command in commands:
        print("\n[+] Sending:")
        print(command)

        sent_message = await client.send_message(BOT_USERNAME, command)

        print(f"\n[+] Waiting for responses from nodes ({len(EXPECTED_NODES)} expected)...")

        # Total wait time: 120 iterations * 2s = 240s
        max_wait = 120
        last_new_response_time = 0
        
        for i in range(max_wait):
            messages = await client.get_messages(BOT_USERNAME, limit=30)
            
            for msg in messages:
                if msg.id <= sent_message.id or msg.id in processed_ids:
                    continue

                # Identify sender
                sender = await msg.get_sender()
                sender_username = getattr(sender, 'username', '') or ''
                sender_username = sender_username.lower()

                # Determine if this response is from one of our expected nodes
                is_from_node = sender_username in expected_lower or not expected_lower

                # Check for "Espera" message to handle rate limiting
                if msg.message and "espera" in msg.message.lower():
                    # Look for time like 0.8s, 1.5s, 5s
                    match = re.search(r"(\d+\.?\d*)\s*s", msg.message.lower())
                    if match:
                        wait_time = float(match.group(1))
                        print(f"\n[!] Rate limit detected: {msg.message.strip()}")
                        print(f"[!] Waiting {wait_time}s as requested...")
                        await asyncio.sleep(wait_time + 1) # Add 1s buffer
                        # After waiting, we don't count this as a final response, still waiting for data
                        try:
                            await client.delete_messages(BOT_USERNAME, msg.id)
                        except:
                            pass
                        continue

                # Check if it's a file or text response
                is_file = bool(msg.media)
                is_target_text = msg.message and asset.lower() in msg.message.lower()

                if is_from_node and (is_file or is_target_text):
                    print(f"\n[+] Response detected from node: @{sender_username or 'unknown'}")
                    processed_ids.add(msg.id)
                    if sender_username:
                        responded_nodes.add(sender_username)
                    
                    last_new_response_time = i

                    if is_file:
                        print(f"[+] Downloading file: {msg.id}")
                        downloaded_file = await client.download_media(msg, file=DOWNLOADS_DIR)
                        raw_text = ""
                        try:
                            # Try reading as UTF-8 first
                            with open(downloaded_file, "r", encoding="utf-8") as f:
                                raw_text = f.read()
                        except UnicodeDecodeError:
                            # If it fails, try with errors='ignore'
                            with open(downloaded_file, "r", encoding="utf-8", errors="ignore") as f:
                                raw_text = f.read()
                        except Exception as e:
                            print(f"[-] Error reading file: {e}")
                            raw_text = ""
                    else:
                        raw_text = msg.message

                    if raw_text:
                        all_raw_texts.append(raw_text)
                        parsed, unparsed = parse_results(raw_text)
                        print(f"[+] Parsed {len(parsed)} entries from this response, {len(unparsed)} lines unknown.")
                        all_results.extend(parsed)
                        all_unparsed.extend(unparsed)

                    try:
                        await client.delete_messages(BOT_USERNAME, msg.id)
                    except:
                        pass

            # Smart break logic:
            # 1. We got all expected nodes
            if expected_lower and responded_nodes.issuperset(set(expected_lower)):
                # Double check if any messages are still pending for 1 more second
                await asyncio.sleep(2)
                print(f"[+] All nodes ({len(responded_nodes)}) answered. Continuing...")
                break
            
            # 2. Safety timeout: If we haven't seen anything new for 30 seconds AND we have some results
            if i - last_new_response_time > 15 and len(processed_ids) > 0:
                print(f"[+] No new responses for a while. Proceeding with {len(responded_nodes)} nodes.")
                break

            await asyncio.sleep(2)
                
        if not processed_ids:
            print("\n[-] No response received from any node.")
            return

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

    json_path = save_json(asset, asset_type, all_results, all_unparsed)

    print(f"[+] Launching indexer for {len(all_results)} total results...")
    os.system(
        f'"{sys.executable}" elastic-indexer-b.py "{json_path}"'
    )

    if not all_raw_texts:
        print("\n[-] No data collected to save.")
        return


# =========================
# MAIN
# =========================

async def main():
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("python3 telegram-worker-b.py asset")
        print("python3 telegram-worker-b.py --test path/to/file_or_dir")
        return

    # Check for test mode
    if sys.argv[1] == "--test" and len(sys.argv) > 2:
        path = sys.argv[2]
        await test_parse_local(path)
        return

    asset = " ".join(sys.argv[1:]).strip()

    await client.start()
    print("\n[+] Telegram connected.")

    await process_asset(asset)

    await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
