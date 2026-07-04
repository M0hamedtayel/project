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

BASE_DIR = "ak-bot"

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
    return [f"/s {asset}"]


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
        "Author", "t.me/", "🐂 fuente",
        "正在查询", "查询结果", "开通会员", "条。", "开会员联系",
        "查询", "等待", "搜索中",
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
# CSV PARSER
# =========================

def _is_port_like(s):
    """Check if string looks like a port number, optionally with trailing path."""
    s = s.strip()
    if s.isdigit():
        return True
    if re.match(r"^\d{2,5}(/\w*)?$", s):
        return True
    return False

def _fix_url(url):
    """Fix common URL issues in bot CSV exports."""
    # Remove double protocol: https://http:// -> https://
    match = re.match(r"^(https?://)(https?://)(.*)", url)
    while match:
        url = match.group(1) + match.group(3)
        match = re.match(r"^(https?://)(https?://)(.*)", url)
    return url

def _extract_csv_credentials(line):
    """
    Smart CSV credential extractor.
    Handles these messy formats from bot CSV exports:
      Standard:     URL,user,pass
      Comma-port:  http://domain,PORT/,user              (comma instead of colon for port)
      Comma-port:  http://domain,82/rm,admin:078125722    (comma port + merged user:pass)
      Glued-port:  https://domainPORT,user,pass           (port glued to domain, no separator)
      Double-proto: https://http://domain/...,user,pass  (double protocol prefix)
      Merged-cred: URL,port/path,user:pass               (user:pass merged in one field)
      Trailing-slash: URL:PORT/,user,pass                (URL ends with / then comma)
      Missing-pass: URL,port,user                         (no password field)
    Returns (host, username, password) or None.
    """
    parts = line.split(",")
    if len(parts) < 3:
        return None

    first = parts[0].strip()

    # ---------- Is the first field a URL? ----------
    if not first.startswith(("http://", "https://", "ftp://", "android://")):
        # Non-URL CSV: treat first 3 fields as host/user/pass
        if len(parts) >= 3 and parts[1].strip() and parts[2].strip():
            return (parts[0].strip(), parts[1].strip(), parts[2].strip())
        return None

    # ---------- URL first field ----------

    # Detect comma-port: when parts[1] is a port number (with optional /path)
    # e.g. "http://wellmart.com.tw,81/,charles"     → 4 parts, parts[1]="81/"
    # e.g. "http://wellmart.com.tw,82/rm,admin"      → 4 parts, parts[1]="82/rm"
    if len(parts) >= 4 and _is_port_like(parts[1]):
        url_raw = parts[0].strip()
        url_fixed = _fix_url(url_raw)
        port_str = parts[1].strip().rstrip("/")  # "81/" → "81", "82/rm" → "82/rm"
        # Reconstruct URL with proper colon-port
        url_fixed = url_fixed.rstrip("/") + ":" + port_str

        # Credentials start after the port field
        cred_parts = parts[2:]
        if len(cred_parts) >= 2:
            user = cred_parts[0].strip()
            passw = ",".join(cred_parts[1:]).strip()
        elif len(cred_parts) == 1:
            return None  # Only user, no password — skip
        else:
            return None

        if user and passw:
            # Handle user:pass merged in password
            if ":" in passw and not passw.startswith("http") and "@" not in passw.split(":")[0]:
                u2, p2 = passw.rsplit(":", 1)
                if u2 and p2:
                    return (url_fixed, u2, p2)
            return (url_fixed, user, passw)
        return None

    # 3 fields: standard URL,user,pass OR URL,port,user (comma-port with 3 fields) OR glued port
    if len(parts) == 3:
        url = _fix_url(parts[0].strip())

        # Check for glued port: wellmart.com.tw82
        match = re.search(r"(https?://[\w.-]+)(\d{2,5})(/?.*)?$", url)
        if match:
            domain_base = match.group(1)
            port_num = match.group(2)
            rest_path = match.group(3) or ""
            url = f"{domain_base}:{port_num}{rest_path}"

        p1 = parts[1].strip()
        p2 = parts[2].strip()

        # Sub-case A: parts[1] is port-like → URL,port,user (no password)
        # e.g. "http://wellmart.com.tw,81/,charles" — but this would be 4 parts if trailing /
        # e.g. "http://wellmart.com.tw,81,charles" — 3 parts
        if _is_port_like(p1):
            port_str = p1.rstrip("/")
            url = url.rstrip("/") + ":" + port_str
            # p2 might be user:pass merged
            if ":" in p2 and not p2.startswith("http") and "@" not in p2.split(":")[0]:
                u2, pw2 = p2.rsplit(":", 1)
                if u2 and pw2:
                    return (url, u2, pw2)
            if p2:
                return (url, p2, "NO_PASS")

        # Sub-case B: standard URL,user,pass
        # Handle merged user:pass in password field
        if ":" in p2 and "@" not in p2.split(":")[0]:
            u2, pw2 = p2.rsplit(":", 1)
            if u2 and pw2:
                return (url, u2, pw2)

        if p1 and p2:
            return (url, p1, p2)

    # 5+ fields: fallback — last two are user,pass
    if len(parts) >= 5:
        passw = parts[-1].strip()
        user = parts[-2].strip()
        url = ",".join(parts[:-2]).strip()
        url = _fix_url(url)
        if user and passw:
            return (url, user, passw)

    return None


def parse_csv_file(file_path):
    entries = []
    seen = set()
    unparsed_lines = []

    with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip header row
        lower_line = line.lower()
        if any(h in lower_line for h in ["url,email", "url,username", "url,password", "网址", "主机"]):
            continue

        result = _extract_csv_credentials(line)

        if result:
            host, username, password = result
            host = normalize_host(host)

            if not host or not username or not password:
                unparsed_lines.append(line)
                continue

            key = f"{host}|{username.lower()}|{password.lower()}"
            if key in seen:
                continue

            seen.add(key)
            entries.append({
                "host": host,
                "username": username,
                "password": password,
                "format": "CSV"
            })
        else:
            unparsed_lines.append(line)

    return entries, unparsed_lines
# =========================
# CANDIDATE ENGINE
# =========================



def generate_candidates(line):
    """Generates multiple interpretations for a single line."""
    candidates = []
    
    # Format F: TAB
    if "\t" in line:
        parts = [p.strip() for p in line.split("\t") if p.strip()]
        if len(parts) >= 3:
            candidates.append({"host": parts[0], "user": parts[1], "pass": parts[2], "format": "TAB_SEP"})

    # Format CSV-like: comma-separated with URL first
    # e.g. "http://newagewellmart.com/login,cpkumar@yahoo.com,work4punno"
    # e.g. "https://wellmart.com.tw:81/,charles,580828maruco"
    # Don't let colon-based splitting break these lines
    if "," in line:
        parts = line.split(",")
        if len(parts) >= 3:
            first = parts[0].strip()
            if first.startswith(("http://", "https://", "ftp://", "android://")):
                # Use the smart CSV extractor for URL+comma lines
                result = _extract_csv_credentials(line)
                if result:
                    h, u, p = result
                    candidates.append({"host": h, "user": u, "pass": p, "format": "CSV_STYLE"})
                # Don't fall through to colon-based splitting for URL lines
                return candidates

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
    # Only apply if line does NOT contain a URL (URLs have too many colons from http://)
    if line.count(":") >= 2 and not re.search(r"https?://", line):
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
                entries.append({"host": h, "username": u, "password": p, "format": "LABEL"})
                current_label_data = {}
        if is_label: continue

        # --- 2. Candidate Pipeline ---
        candidates = generate_candidates(line)
        best_candidate = None
        

        for cand in candidates:
            
            if is_valid_host(cand["host"]) and cand["user"] and cand["pass"]:
                
                best_candidate = cand
                break

        # --- 3. Selection & Normalization ---
        if best_candidate: # Threshold for validity
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
                    "format": best_candidate["format"]
                   
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
        files = [
    os.path.join(path, f)
    for f in os.listdir(path)
    if f.lower().endswith((".txt", ".log", ".csv"))
]
    else:
        files = [path]
    
    if not files:
        print("[-] No files found to process.")
        return

    for file in files:
        print(f"\n[+] Testing parse on: {file}")
        try:
            if file.lower().endswith(".csv"):
                parsed, unparsed = parse_csv_file(file)
            else:
                with open(file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                parsed, unparsed = parse_results(content)
            print(f"[+] Found {len(parsed)} results, {len(unparsed)} unparsed lines.")
            
            if parsed:
                # Use filename as asset name for testing
                asset_name = os.path.basename(file).split("_")[0]
                json_path = save_json(asset_name, "test_local", parsed, unparsed)
                
                print(f"[+] Launching indexer...")
                os.system(f'"{sys.executable}" elastic-indexer-a.py "{json_path}"')
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

                # Skip "querying..." status messages (e.g. "正在查询：wellmart.com")
                is_status_msg = False
                if msg.message and not is_file:
                    status_keywords = [
                        "正在查询", "查询中", "查询结果", "开通会员", "条",
                        "searching", "querying", "results", "found",
                    ]
                    # If the message ONLY contains status info and no actual data lines, skip it
                    msg_lower = msg.message.strip().lower()
                    if any(k in msg_lower for k in status_keywords):
                        # Check if it's purely a status line (short, no real credentials)
                        lines_in_msg = [l.strip() for l in msg.message.splitlines() if l.strip()]
                        has_real_data = any(
                            (":" in l and l.count(":") >= 2 and "@" not in l[:5]) or ("\t" in l)
                            for l in lines_in_msg
                        )
                        if not has_real_data:
                            is_status_msg = True
                            print(f"[*] Skipping status message: {msg.message.strip()[:80]}")
                            try:
                                await client.delete_messages(BOT_USERNAME, msg.id)
                            except:
                                pass
                            processed_ids.add(msg.id)
                            continue

                # For text responses, verify it contains actual credential data
                is_target_text = False
                if msg.message and not is_file and not is_status_msg:
                    msg_lower = msg.message.lower()
                    if asset.lower() in msg_lower:
                        # Verify it has actual credential-like content
                        lines_in_msg = msg.message.splitlines()
                        cred_lines = 0
                        for ml in lines_in_msg:
                            ml = ml.strip()
                            if not ml:
                                continue
                            # Check for credential patterns: has separators, @, or tab
                            if any(k in ml for k in ["Host:", "URL:", "User:", "Pass:", "密码:", "账号:"]):
                                cred_lines += 1
                            elif ml.count(":") >= 2 or ml.count(",") >= 2 or "\t" in ml:
                                cred_lines += 1
                        if cred_lines >= 1:
                            is_target_text = True

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
                            with open(downloaded_file, "r", encoding="utf-8") as f:
                                raw_text = f.read()
                        except UnicodeDecodeError:
                            with open(downloaded_file, "r", encoding="utf-8", errors="ignore") as f:
                                raw_text = f.read()
                        except Exception as e:
                            print(f"[-] Error reading file: {e}")
                            raw_text = ""
                        
                        # If the file is a CSV, use CSV parser
                        file_ext = os.path.splitext(downloaded_file or "")[1].lower()
                        if file_ext == ".csv":
                            print(f"[+] CSV file detected, using CSV parser...")
                            parsed, unparsed = parse_csv_file(downloaded_file)
                        else:
                            parsed, unparsed = parse_results(raw_text)
                    else:
                        raw_text = msg.message
                        parsed, unparsed = parse_results(raw_text)

                    if is_file:
                        all_raw_texts.append(raw_text)
                    else:
                        all_raw_texts.append(msg.message)

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
        f'"{sys.executable}" elastic-indexer-a.py "{json_path}"'
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
        print("python3 telegram-worker-a.py asset")
        print("python3 telegram-worker-a.py --test path/to/file_or_dir")
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
