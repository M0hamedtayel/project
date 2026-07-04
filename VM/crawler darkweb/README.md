# Dark Web Monitor — Crawler Service

A Python-based crawler that scrapes thread metadata and first-post content from dark web forums (clearnet and .onion) **plus 18 leak/blog sites** and stores results in MongoDB.

---

## Features

- **Dual crawler**: Clearnet (StealthyFetcher) + .onion (Playwright + Tor SOCKS5)
- **Leak blog crawler**: 18 dedicated crawlers for ransomware leak sites, data leak blogs, and carding shops
- **Full coverage**: Crawls all forum categories, all paginated pages, and all leak blog entries
- **Deduplication**: SHA256(title + forum_id) prevents duplicate threads
- **Smart routing**: `_get_crawler()` auto-selects the correct crawler class per domain
- **Proxy rotation**: Use a pool of proxies to avoid IP bans
- **Rate limiting**: Configurable fixed delay between every request
- **Retry logic**: 3 retry attempts per failed request
- **Tor integration**: Automatic circuit renewal every 10 requests
- **MongoDB storage**: Indexed collections for fast lookups
- **Live Dashboard**: Web-based monitoring UI with real-time feed
- **Leak flagging**: Keyword-based auto-flagging + separate `leaks_db` database

---

## Prerequisites

| Dependency | Version |
|---|---|
| Python | 3.11+ |
| MongoDB | 5.0+ |
| Tor (optional) | For .onion crawling |
| Playwright browsers | `playwright install chromium` |

---

## Installation

```bash
cd crawler

pip install -r requirements.txt

playwright install chromium
```

---

## Configuration

### 1. Environment variables (`.env`)

```env
# MongoDB
MONGO_HOST=localhost
MONGO_PORT=27017
MONGO_DB=crawler_db

# Single proxy for clearnet (optional)
PROXY_URL=

# Tor for .onion crawler (Tor Browser uses 9150/9151)
TOR_SOCKS_PORT=9150
TOR_CONTROL_PORT=9151
TOR_PASSWORD=

# Leaks database (separate DB for flagged threads)
LEAKS_MONGO_HOST=localhost
LEAKS_MONGO_PORT=27017
LEAKS_MONGO_DB=leaks_db

# Breach database (separate DB for breach reports)
BREACH_MONGO_HOST=localhost
BREACH_MONGO_PORT=27017
BREACH_MONGO_DB=breach_db

# Crawler settings
REQUEST_DELAY=3          # seconds between requests
MAX_PAGES=200            # max pages per forum section
MAX_WORKERS=5            # parallel clearnet crawlers
```

### 2. Tor (for .onion crawler)

Install Tor and configure `torrc`:

```
SocksPort 9150
ControlPort 9151
HashedControlPassword <generated_hash>
```

Generate the password hash:
```bash
tor --hash-password yourpassword
```

---

## Database Setup

```bash
python init_db.py
```

This seeds **3 databases**:

| Database | Collections | Purpose |
|---|---|---|
| `crawler_db` | `forums`, `threads`, `crawl_logs` | Main crawl data |
| `leaks_db` | `flagged_threads` | Flagged leak threads (via `flag_threads.py`) |
| `breach_db` | `breach_reports` | Breach report data |

### What gets seeded

`init_db.py` inserts **38 active forums** when the database is empty:

**Traditional forums** (BreachForums, DarkForums, DNA):
- 8 BreachForums categories (clearnet)
- 6 DarkForums categories (clearnet)
- 5 DNA Forum categories (onion)

**18 Leak Blog sites**:

| # | Name | Type | URL |
|---|---|---|---|
| 1 | TIMC Leak List | onion | `http://rzzfi...gmqd.onion` |
| 2 | MONEYMESSAGE Leak Blog | onion | `http://blogvl...aqd.onion` (3 pages via `news.php?page=N`) |
| 3 | BASHE Leak List | onion | `http://bashe...hhyd.onion` (single page) |
| 4 | PLAY NEWS Leak Blog | onion | `http://j75o...gpid.onion` (max 24 pages via `index.php?page=N`) |
| 5 | PEAR Leak List | onion | `http://pear...hdid.onion` (single page) |
| 6 | Nitrogen Ransomware Blog | onion | `http://nitro...gvqd.onion` (single page) |
| 7 | DATA EXPOSURE Terminal | onion | `http://6tdq...6jad.onion` (single page) |
| 8 | File Manager Leaks | onion | `http://t33z...h6id.onion` (single page) |
| 9 | Bjorka Databases | clearnet | `https://netleaks.net` (single page) |
| 10 | CMD Official Auctions | clearnet | `https://cmdofficial.com` (single page) |
| 11 | KRYBIT Leak List | onion | `http://kryb...u2yd.onion` (single page) |
| 12 | BLACKWATER Leak Blog | onion | `http://ejzl...i5id.onion` (single page) |
| 13 | MS13-089 Leak Blog | onion | `http://msle...gvad.onion` (single page) |
| 14 | NSPIRE RaaS Leaks | onion | `http://nspi...dxad.onion` (single page) |
| 15 | 0day Leak List | onion | `http://oday...oqd.onion` (single page) |
| 16 | Atomsilo Leak List | onion | `http://npmh...qd.onion` (single page) |
| 17 | Booba Team Leaks | onion | `http://7t3z...jad.onion` (single page) |
| 18 | CardMafia Leaks | clearnet | `https://cardmafia.net` (single page) |

### Manual forum insert

```python
from db.connection import get_db
from datetime import datetime, timezone

db = get_db()
db.forums.insert_one({
    "name": "My Forum",
    "base_url": "https://example.com/forum",
    "forum_type": "clearnet",
    "is_active": True,
    "last_crawled_at": None,
    "created_at": datetime.now(timezone.utc),
})
```

---

## Usage

```bash
# Crawl all active forums (clearnet + onion + leak blogs)
python main.py

# Crawl clearnet only (BreachForums, DarkForums, clearnet leak blogs)
python main.py --crawler clearnet

# Crawl .onion only (DNA Forum + onion leak blogs)
python main.py --crawler onion
```

### Crawler auto-routing

The `_get_crawler()` function in `main.py` automatically selects:

1. **DarkForums** (domain contains `darkforums`) → `DarkForumsCrawler`
2. **DNA Forum** (domain contains `dna` + `.onion`) → `DnaForumCrawler`
3. **Leak blog** (domain matches `LEAK_BLOG_SITES` map) → dedicated crawler class
4. **Fallback** → `ClearnetCrawler` or `OnionCrawler` based on `forum_type`

**No manual configuration needed** — just add the forum to MongoDB and the router handles it.

### Environment overrides

```bash
set REQUEST_DELAY=10
set MAX_PAGES=5
python main.py --crawler clearnet
```

### Scheduling with cron (Linux)

```bash
# Every 6 hours
0 */6 * * * cd /path/to/crawler && python main.py >> logs/cron.log 2>&1
```

### Scheduling with Task Scheduler (Windows)

Create a task that runs:
```
C:\Users\...\Python314\python.exe C:\path\to\crawler\main.py
```

---

## Project Structure

```
crawler/
├── CLAUDE.md                # Context file for AI assistants
├── README.md                # This file
├── .env                     # Environment configuration
├── requirements.txt         # Python dependencies
├── config.py                # Loads all environment variables
├── init_db.py               # Seeds MongoDB with initial data (38 forums)
├── main.py                  # Entry point with argparse + crawler router
├── report.py                # Database report tool
├── flag_threads.py          # Keyword-based leak flagging
├── run_dashboard.py         # Dashboard launcher
├── proxies.txt              # Proxy list for rotation
├── keywords.txt             # Keywords for leak flagging
├── db/
│   ├── connection.py        # MongoDB connection (singleton)
│   ├── queries.py           # Forum/thread/crawl_log operations
│   └── leaks_connection.py  # Separate connection for leaks_db
├── crawlers/
│   ├── base.py              # Abstract base with pagination + categories
│   ├── clearnet.py          # Clearnet forum implementation
│   ├── onion.py             # .onion (Tor) forum implementation
│   ├── darkforums.py        # DarkForums-specific selectors
│   ├── dnaforum.py          # DNA Forum-specific selectors
│   └── leakblogs.py         # 18 leak blog crawlers + domain map
├── utils/
│   ├── dedup.py             # SHA256 dedup hash computation
│   ├── tor_manager.py       # Tor circuit renewal via Stem
│   ├── proxy_rotator.py     # Proxy list loader + rotation
│   ├── cookie_manager.py    # Cookie file loader for auth
│   └── leak_detector.py     # Leak keyword matching logic
├── notifications/           # (reserved for future API integration)
├── dashboard/
│   ├── server.py            # FastAPI + WebSocket server
│   └── templates/           # HTML templates
└── logs/
    └── crawler.log          # Crawl session logs
```

---

## Architecture

```
main.py
  │
  ├── ensure_indexes()          # MongoDB index creation
  │
  ├── get_all_active_forums()   # Load forums from DB
  │
  └── run_crawler(forum)        # Per-forum crawl
        │
        ├── _get_crawler()      # Auto-route to correct crawler class
        │     ├── darkforums?       → DarkForumsCrawler
        │     ├── dna.onion?        → DnaForumCrawler
        │     ├── match leak blog?  → TIMCCrawler, BjorkaCrawler, etc.
        │     └── fallback          → ClearnetCrawler / OnionCrawler
        │
        └── Crawler.run()
              │
              ├── [Forums] _crawl_category(url)
              │     ├── Page N → extract_threads_from_listing()
              │     │     └── [each thread] check dedup → fetch → save
              │     └── has_next_page() → loop
              │
              └── [Leak blogs] crawl()
                    ├── Page N → extract_entries()
                    │     └── [each entry] check dedup → fetch detail → save
                    └── has_next_page() → loop
```

### Crawl flow: Traditional forums

1. **Start**: Fetch forum index → extract category URLs
2. **Paginate**: For each category, paginate through listing pages
3. **Skip duplicates**: Check `dedup_hash` before fetching
4. **Extract**: Fetch thread → extract title, author, date, first post
5. **Store**: Save to MongoDB

### Crawl flow: Leak blogs

1. **Start**: Fetch leak blog homepage
2. **Extract entries**: Parse blog post cards from the page
3. **Fetch details**: If entry has no content, fetch detail page
4. **Paginate**: Follow `has_next_page()` (e.g., `?page=2`, `news.php?page=2`)
5. **Store**: Same dedup + insert logic

---

## Database Schema

### forums collection
```json
{
  "_id": ObjectId,
  "name": "BreachForums - Databases",
  "base_url": "https://breachforums.rs/Forum-Databases",
  "forum_type": "clearnet",
  "is_active": true,
  "last_crawled_at": null,
  "created_at": ISODate
}
```

### threads collection
```json
{
  "_id": ObjectId,
  "forum_id": ObjectId,
  "url": "https://breachforums.rs/Thread-Example",
  "dedup_hash": "sha256hex...",
  "title": "Example Thread",
  "author": "username",
  "first_post_content": "Full text...",
  "post_date": "Jan 01, 2025, 12:00 PM",
  "source_type": "clearnet",
  "crawled_at": ISODate
}
```

Indexes: `dedup_hash` (unique), `url` (unique), `forum_id`, `crawled_at`

### crawl_logs collection
```json
{
  "_id": ObjectId,
  "forum_id": ObjectId,
  "started_at": ISODate,
  "finished_at": ISODate,
  "status": "done" | "failed" | "running",
  "error_msg": "optional error"
}
```

---

## Leak Flagging System

After crawling, identify threads that contain actual leaked/breached data:

```bash
python flag_threads.py
```

Scans all crawled threads against `keywords.txt` and copies matches to `leaks_db.flagged_threads`. Running multiple times never creates duplicates (unique `dedup_hash` index).

### Keywords

Edit `keywords.txt` (one per line, case-insensitive):
```
database
leak
breach
dump
combo
ssn
...
```

---

## Dashboard

```bash
python run_dashboard.py
```

Open http://127.0.0.1:8001

| Tab | Function |
|---|---|
| **Overview** | Stats cards, forum table with status |
| **Forums** | All forum sections with thread counts |
| **Search** | Full-text search across threads |
| **Flagged** | Browse flagged leak threads |
| **Live Feed** | Real-time crawl events via WebSocket |
| **Logs** | View and filter crawler logs |
| **Controls** | Start/stop crawler, test cookies, view config |

---

## Rate Limiting & Anti-Detection

| Measure | Implementation |
|---|---|
| Request delay | `REQUEST_DELAY` seconds between every request |
| Retry limit | 3 attempts before skipping a URL |
| Browser stealth | `StealthyFetcher` bypasses Cloudflare |
| TLS fingerprinting | `Fetcher` with `impersonate="chrome"` |
| Proxy rotation | Rotate through `proxies.txt` pool |
| Tor circuit renewal | New identity every 10 requests |
| Page timeout | 90s for slow .onion pages |

---

## Testing

```bash
# View database report
python report.py

# Run leak flagging
python flag_threads.py

# Check logs
cat logs/crawler.log

# Quick test a single page
python -c "
from scrapling.fetchers import StealthyFetcher
p = StealthyFetcher.fetch('https://example.com')
print(f'Status: {p.status}, Links: {len(p.css(\"a\"))}')
"
```
