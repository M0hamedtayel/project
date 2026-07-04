# Dark Web Monitor — Crawler Service
## Graduation Project Presentation

---

# Table of Contents

1. Project Overview
2. The Problem
3. Solution Architecture
4. Tech Stack
5. Features Deep Dive
6. Code Architecture
7. Challenges & Solutions
8. Results
9. Future Work
10. Q&A

---

# 1. Project Overview

## What is Dark Web Monitor?

A **Python-based automated crawler** that monitors dark web forums for threat intelligence data.

**Goal:** Continuously scrape thread metadata and first-post content from both clearnet and .onion forums, store results in MongoDB, and flag threads containing leaked/breached data.

**Key Capabilities:**
- Crawls all categories and all pages of target forums
- Handles both clearnet and Tor-based .onion sites
- Anti-detection and proxy rotation
- Deduplication to avoid redundant downloads
- Keyword-based leak detection

---

# 2. The Problem

## Why This Project Exists

| Challenge | Impact |
|---|---|
| **Dark web forums contain threat intelligence** | Organizations need this data for security |
| **Manual monitoring is slow and impractical** | One human can only check a few forums per day |
| **Anti-bot protections** | Cloudflare, rate limits, IP bans block automation |
| **Two different environments** | Clearnet (HTTP) vs .onion (Tor SOCKS5) |
| **Data must be searchable** | Raw HTML is useless without structured storage |

**The gap:** No affordable, automated tool exists that handles both environments, bypasses protections, and provides structured, deduplicated data.

---

# 3. Solution Architecture

## How It Works

```
main.py (Entry Point)
  │
  ├── ensure_indexes()          # MongoDB index creation
  ├── get_all_active_forums()   # Load forums from DB
  │
  └── run_crawler(forum)        # Per-forum crawl
        │
        └── Crawler.run()
              │
              ├── fetch index page → extract categories
              │
              └── _crawl_category(url)
                    ├── Page 1: extract threads
                    │     └── [for each thread]
                    │           ├── check dedup_hash → SKIP if exists
                    │           ├── fetch thread page
                    │           ├── extract first post
                    │           └── save to MongoDB
                    ├── has_next_page() → Page 2, 3, ...
                    └── stop when no more pages
```

**Key Design:** Abstract base class with concrete implementations for clearnet and .onion.

---

# 4. Tech Stack

## Technologies Used

| Component | Technology | Why |
|---|---|---|
| **Language** | Python 3.14 | Fast prototyping, rich ecosystem |
| **Web scraping** | Scrapling | Built-in Cloudflare bypass + HTML parser |
| **Browser automation** | Playwright | Required for .onion sites with JS rendering |
| **Database** | MongoDB 8.2 | Flexible schema, unique index dedup |
| **Tor control** | Stem | Automatic circuit renewal for .onion |
| **API/Dashboard** | FastAPI + Uvicorn | Async API with WebSocket real-time updates |

---

# 5. Features Deep Dive

## Feature 1: Dual Crawler System

### Clearnet Crawler (`crawlers/clearnet.py`)

Uses **StealthyFetcher** from Scrapling with:
- TLS fingerprint impersonation (`impersonate="chrome"`)
- Cloudflare Turnstile bypass
- Proxy rotation via `proxies.txt`

### Onion Crawler (`crawlers/onion.py`)

Uses **Playwright + Tor SOCKS5 proxy**:
- Launches Chromium through Tor circuit
- **Automatic circuit renewal** every 10 requests
- 90-second timeout for slow .onion pages

### Code — Base Class (`crawlers/base.py`)

```python
class BaseCrawler(ABC):
    @abstractmethod
    def fetch_page(self, url: str):
        pass

    @abstractmethod
    def extract_categories(self, page) -> list[str]:
        pass

    @abstractmethod
    def extract_threads_from_listing(self, page) -> list[dict]:
        pass

    def fetch_with_retry(self, url: str):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                self._request_count += 1
                page = self.fetch_page(url)
                time.sleep(REQUEST_DELAY)
                return page
            except Exception:
                if attempt < MAX_RETRIES:
                    time.sleep(REQUEST_DELAY)
        return None
```

**Why abstract?** Each crawler type (clearnet/onion/darkforums) implements the same interface but uses different fetching mechanisms.

---

## Feature 2: Full Coverage — All Categories + All Pages

### Category Extraction (`clearnet.py`)

```python
def extract_categories(self, page) -> list[str]:
    cats = []
    for table in page.css("table.forums__bit"):
        for a in table.css("a[href*='Forum-']"):
            href = a.attrib.get("href", "")
            if href:
                cats.append(self._abs_url(href))
    return list(dict.fromkeys(cats))  # dedup
```

### Pagination (`crawlers/base.py`)

```python
def _crawl_category(self, cat_url: str):
    page = self.fetch_with_retry(cat_url)
    page_num = 0
    while page_num < self.max_pages:
        page_num += 1
        threads = self.extract_threads_from_listing(page)
        # ... process each thread ...
        next_url = self.has_next_page(page)
        if not next_url:
            break
        page = self.fetch_with_retry(next_url)
```

**Result:** Crawls **234 threads** across **8 sections** of BreachForums in a single run.

---

## Feature 3: Deduplication — Two-Layer Protection

### The Problem

Forums reuse thread titles, and re-running the crawler would re-download everything.

### The Solution

**Layer 1 — SHA256 Hash** (`utils/dedup.py`):

```python
def compute_dedup_hash(title: str, forum_id: int) -> str:
    raw = f"{title.lower().strip()}|{forum_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
```

**Layer 2 — URL uniqueness** in MongoDB:

```python
db.threads.create_index("dedup_hash", unique=True, sparse=True)
db.threads.create_index("url", unique=True, sparse=True)
```

### Check Before Fetching (`crawlers/base.py`)

```python
def _crawl_category(self, cat_url: str):
    threads = self.extract_threads_from_listing(page)
    for thread in threads:
        dedup_hash = compute_dedup_hash(thread["title"], self.forum_id)
        if thread_exists_by_hash(dedup_hash):
            logger.info("[DUPLICATE] %s", thread["title"][:60])
            continue  # SKIP — already crawled
        # Fetch thread page, extract content, save
```

**Result:** Running the crawler twice adds **zero duplicates**.

---

## Feature 4: Proxy Rotation

### How It Works

1. **Load proxies** from `proxies.txt` at startup
2. **Test each proxy** — keep only working ones
3. **Rotate** through proxies using a circular iterator

### Code (`utils/proxy_rotator.py`)

```python
class SimpleProxyRotator:
    def __init__(self, proxies: list[str]):
        self.proxies = proxies
        self._cycle = cycle(proxies)

    def get_proxy(self) -> str:
        return next(self._cycle)
```

### Fallback Strategy

```
proxies.txt → all fail → StealthyFetcher (direct connection)
```

### Configuration (`.env`)

```env
# Single proxy override (takes priority over proxies.txt)
PROXY_URL=

# Or use the pool in proxies.txt
# FORMAT: ip:port or http://ip:port or socks5://ip:port
```

---

## Feature 5: MongoDB Storage

### Three Collections

**forums** — Target forums to crawl:
```json
{
  "name": "BreachForums - Databases",
  "base_url": "https://breachforums.rs/Forum-Databases",
  "forum_type": "clearnet",
  "is_active": true
}
```

**threads** — Scraped data (unique on `dedup_hash`):
```json
{
  "forum_id": ObjectId,
  "url": "https://breachforums.rs/Thread-Example",
  "dedup_hash": "sha256hex...",
  "title": "Database Sale 2024",
  "author": "seller123",
  "first_post_content": "Full text of the post...",
  "post_date": "Jan 01, 2025, 12:00 PM",
  "source_type": "clearnet",
  "crawled_at": ISODate
}
```

**crawl_logs** — Session audit trail:
```json
{
  "forum_id": ObjectId,
  "started_at": ISODate,
  "finished_at": ISODate,
  "status": "done",
  "threads_found": 123,
  "threads_new": 45
}
```

### Connection (`db/connection.py`)

```python
_client = None
_db = None

def get_db():
    global _client, _db
    if _db is None:
        _client = MongoClient(MONGO_HOST, MONGO_PORT)
        _db = _client[MONGO_DB]
    return _db  # Singleton pattern
```

**Why singleton?** Avoids creating a new connection for every request.

---

## Feature 6: Rate Limiting & Anti-Detection

### Rate Limiting

```python
def fetch_with_retry(self, url: str):
    for attempt in range(1, MAX_RETRIES + 1):
        page = self.fetch_page(url)
        time.sleep(REQUEST_DELAY)  # Fixed delay after EVERY request
        return page
```

| Setting | Default | Purpose |
|---|---|---|
| `REQUEST_DELAY` | 5s | Time between requests |
| `MAX_RETRIES` | 3 | Retry failed requests |
| `PAGE_TIMEOUT` | 90s | Timeout for slow .onion pages |

### Anti-Detection Techniques

| Technique | Implementation |
|---|---|
| Cloudflare bypass | `StealthyFetcher.solve_cloudflare` |
| TLS fingerprint | `Fetcher.impersonate="chrome"` |
| Browser stealth | Canvas noise, WebRTC leak fix |
| IP rotation | Proxy pool + Tor circuit renewal |
| Human-like delay | Fixed 5s between requests |

---

## Feature 7: Tor Integration (Onion Crawler)

### Circuit Renewal (`utils/tor_manager.py`)

```python
def renew_tor_circuit():
    with Controller.from_port(port=TOR_CONTROL_PORT) as ctrl:
        ctrl.authenticate(password=TOR_PASSWORD)
        ctrl.signal(Signal.NEWNYM)
```

### Called Every 10 Requests (`onion.py`)

```python
def fetch_page(self, url: str):
    if self._request_count > 0 and self._request_count % 10 == 0:
        renew_tor_circuit()
        time.sleep(REQUEST_DELAY)
```

### Fetch Flow

```python
with sync_playwright() as p:
    browser = p.chromium.launch(
        proxy={"server": f"socks5://127.0.0.1:{TOR_SOCKS_PORT}"}
    )
    page = browser.new_page()
    page.goto(url, timeout=PAGE_TIMEOUT)
    html = page.content()
    browser.close()
return Selector(html)
```

**Result:** Each .onion crawl has a different Tor identity, reducing ban risk.

---

## Feature 8: Leak Flagging System

### Purpose

After crawling, identify threads that contain **actual leaked/breached data** using keyword matching.

### Workflow

```
python flag_threads.py
         │
         ▼
  For each thread in crawler_db.threads:
      │
      ├── Already in leaks_db? → SKIP (dedup by SHA256 hash)
      │
      ├── Check title + content against keywords.txt
      │
      └── Match? → INSERT into leaks_db.flagged_threads
```

### Keyword Detection (`utils/leak_detector.py`)

```python
def check_thread(title: str, content: str) -> list[str]:
    keywords = load_keywords()
    text = f"{title or ''} {content or ''}"
    return [kw for kw in keywords if _contains_keyword(text, kw)]

def _contains_keyword(text: str, keyword: str) -> bool:
    pattern = re.compile(re.escape(keyword), re.IGNORECASE)
    return bool(pattern.search(text))
```

### Leaks Database (`leaks_db`)

```json
{
  "dedup_hash": "sha256hex...",
  "original_id": ObjectId,
  "title": "Database Sale 2024",
  "matched_keywords": ["database", "leak", "email:pass"],
  "flagged_at": ISODate,
  "reviewed": false
}
```

**Result:** 173 out of 234 threads flagged as potential leaks in the demo.

---

# 6. Code Architecture

## Project Structure

```
crawler/
├── main.py              # Entry point — argparse, threading
├── config.py            # All environment variables
├── init_db.py           # Database seeder
├── flag_threads.py      # Leak flagging script
├── report.py            # Database report tool
├── proxies.txt          # Proxy list
├── keywords.txt         # Leak detection keywords
├── db/
│   ├── connection.py    # MongoDB singleton
│   ├── leaks_connection.py  # Second DB for flagged threads
│   └── queries.py       # All MongoDB operations
├── crawlers/
│   ├── base.py          # Abstract base class
│   ├── clearnet.py      # Clearnet implementation
│   ├── onion.py         # .onion (Tor) implementation
│   └── darkforums.py    # Cookie-based darkforums crawler
├── utils/
│   ├── dedup.py         # SHA256 dedup hash
│   ├── leak_detector.py # Keyword matching
│   ├── tor_manager.py   # Tor circuit renewal
│   └── proxy_rotator.py # Proxy rotation
├── dashboard/
│   ├── server.py        # FastAPI dashboard
│   └── templates/       # Frontend
└── logs/
    └── crawler.log      # Session logs
```

## Design Patterns Used

| Pattern | Where | Purpose |
|---|---|---|
| **Abstract Base Class** | `crawlers/base.py` | Define interface for clearnet/onion |
| **Singleton** | `db/connection.py` | One MongoDB connection per run |
| **Strategy** | `crawlers/` classes | Swap fetching strategy per forum type |
| **Iterator** | `proxy_rotator.py` | Cycle through proxies |

---

# 7. Challenges & Solutions

## Challenge 1: Cloudflare Bypass

**Problem:** Cloudflare Turnstile blocks most automated requests.

**Solution:** Used **Scrapling's StealthyFetcher** which:
- Randomizes browser fingerprints
- Bypasses Cloudflare Turnstile
- Uses TLS impersonation (`impersonate="chrome"`)

```python
from scrapling.fetchers import StealthyFetcher
page = StealthyFetcher.fetch(url, proxy=proxy)
```

## Challenge 2: .onion Sites Are Slow

**Problem:** .onion pages can take 30+ seconds to load, or time out entirely.

**Solution:**
- 90-second page timeout
- Tor circuit renewal every 10 requests
- 3 retry attempts with backoff

```python
page = browser.new_page()
page.goto(url, timeout=PAGE_TIMEOUT)  # 90000ms
```

## Challenge 3: Duplicate Downloads

**Problem:** Re-running the crawler would re-download all threads.

**Solution:** Two-layer deduplication:
1. SHA256 hash of `title + forum_id` (MongoDB unique index)
2. URL uniqueness (MongoDB unique index)

```python
db.threads.create_index("dedup_hash", unique=True, sparse=True)
db.threads.create_index("url", unique=True, sparse=True)
```

## Challenge 4: IP Bans

**Problem:** Forums ban IPs that make too many requests.

**Solution:** Three-layer defense:
1. **Proxy rotation** — cycle through proxy pool
2. **Tor circuit renewal** — new identity every 10 requests
3. **Fixed delay** — 5 seconds between every request

## Challenge 5: Different Forum HTML Structures

**Problem:** Each forum has different HTML, different selectors.

**Solution:** Abstract base class with forum-specific implementations:

```python
class BaseCrawler(ABC):
    @abstractmethod
    def extract_categories(self, page) -> list[str]:
        pass

# ClearnetCrawler uses: table.forums__bit, tr.inline_row
# DarkForumsCrawler uses: table.tborder, span.subject_new
```

## Challenge 6: Real-Time Monitoring

**Problem:** Professor wants to see crawls happening live.

**Solution:** FastAPI dashboard with WebSocket:

```python
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    _event_clients.append(q)
    while True:
        event = await q.get()
        await websocket.send_json(event)
```

---

# 8. Results

## Demo: BreachForums Crawl

**8 sections crawled, 234 threads found, 129 with content:**

| Section | Threads | With Content |
|---|---|---|
| Announcements | 10 | 3 |
| World News | 20 | 17 |
| Databases | 123 | 88 |
| Stealer Logs | 20 | 5 |
| Other Leaks | 21 | 6 |
| Cracked Accounts | 20 | 5 |
| Combolists | 20 | 5 |
| **Total** | **234** | **129** |

## Leak Flagging Results

- **173 threads** flagged as potential leaks
- **Deduplication** prevents duplicate flagging on re-run
- Keywords matched: `database`, `leak`, `breach`, `dump`, `combo`, `email:pass`, etc.

## Dashboard

- **7 tabs**: Overview, Forums, Search, Flagged, Live Feed, Logs, Controls
- **Real-time** updates via WebSocket
- **API endpoints**: 15+ REST endpoints + WebSocket

---

# 9. Future Work

| Feature | Status |
|---|---|
| Leak flagging (keyword) | **DONE** |
| Web dashboard | **DONE** |
| Email extraction from posts | Planned |
| Keyword alerting via API | Planned |
| Distributed crawling | Planned |
| Incremental crawl | Planned |

---

# 10. How to Run

```bash
# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Configure
cp .env.example .env    # Edit MongoDB, Tor settings
nano proxies.txt        # Add proxy list

# Initialize database
python init_db.py

# Run crawler
python main.py --crawler clearnet   # Clearnet only
python main.py --crawler onion      # Onion only
python main.py                      # Both

# Flag leaked data
python flag_threads.py

# Launch dashboard
python run_dashboard.py
# → http://127.0.0.1:8001
```

---

# Thank You

**Project:** Dark Web Monitor — Crawler Service
**Technologies:** Python · Scrapling · Playwright · MongoDB · Tor · FastAPI
**Questions?**

---
