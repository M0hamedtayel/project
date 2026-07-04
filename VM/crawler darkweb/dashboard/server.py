import asyncio
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Thread

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from db.connection import get_db
from db.leaks_connection import get_leaks_db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

app = FastAPI(title="Dark Web Monitor Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
PROJECT_DIR = BASE_DIR.parent
CRAWLER_LOG = PROJECT_DIR / "logs" / "crawler.log"
COOKIES_DIR = PROJECT_DIR / "cookies"

_crawl_process: subprocess.Popen | None = None
_crawl_start_time: float | None = None
_event_clients: list[asyncio.Queue] = []

PYTHON = sys.executable


def _broadcast(event: dict):
    dead = []
    for q in _event_clients:
        try:
            q.put_nowait(event)
        except Exception:
            dead.append(q)
    for q in dead:
        _event_clients.remove(q)


def _read_logs(lines: int = 100, level: str | None = None, search: str | None = None) -> list[dict]:
    if not CRAWLER_LOG.exists():
        return []
    with open(CRAWLER_LOG, encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
    result = []
    for line in all_lines[-500:]:
        line = line.strip()
        parts = line.split(" ", 3)
        if len(parts) < 4:
            continue
        entry = {
            "timestamp": parts[0] + " " + parts[1],
            "level": parts[2].strip("[]"),
            "message": parts[3],
        }
        if level and entry["level"] != level:
            continue
        if search and search.lower() not in entry["message"].lower():
            continue
        result.append(entry)
    return result[-lines:]


# ──── API Routes ────

@app.get("/api/stats")
def get_stats():
    db = get_db()
    ldb = get_leaks_db()

    total_threads = db.threads.count_documents({})
    total_forums = db.forums.count_documents({"is_active": True})
    total_flagged = ldb.flagged_threads.count_documents({}) if ldb is not None else 0
    unreviewed = ldb.flagged_threads.count_documents({"reviewed": False}) if ldb is not None else 0

    last_log = db.crawl_logs.find_one(sort=[("started_at", -1)])
    last_crawl = None
    if last_log:
        last_crawl = last_log.get("started_at")

    running_log = db.crawl_logs.find_one({"status": "running"})
    crawler_running = running_log is not None

    recent = db.threads.count_documents({
        "crawled_at": {"$gte": datetime.now(timezone.utc)}
    }) if False else 0

    return {
        "total_threads": total_threads,
        "total_forums": total_forums,
        "total_flagged": total_flagged,
        "unreviewed": unreviewed,
        "last_crawl": str(last_crawl) if last_crawl else None,
        "crawler_running": crawler_running or (_crawl_process is not None and _crawl_process.poll() is None),
    }


@app.get("/api/forums")
def get_forums():
    db = get_db()
    forums = []
    for f in db.forums.find().sort("name", 1):
        count = db.threads.count_documents({"forum_id": f["_id"]})
        last_log = db.crawl_logs.find_one(
            {"forum_id": f["_id"]}, sort=[("started_at", -1)]
        )
        status = "never"
        last_crawl = None
        if last_log:
            status = last_log.get("status", "?")
            last_crawl = str(last_log.get("started_at")) if last_log.get("started_at") else None

        forums.append({
            "id": str(f["_id"]),
            "name": f["name"],
            "url": f["base_url"],
            "type": f.get("forum_type", "clearnet"),
            "active": f.get("is_active", True),
            "threads": count,
            "status": status,
            "last_crawl": last_crawl,
        })
    return forums


@app.get("/api/threads")
def get_threads(
    q: str = "",
    forum: str = "",
    page: int = 1,
    limit: int = 20,
):
    db = get_db()
    query = {}
    if q:
        escaped = re.escape(q)
        query["$or"] = [
            {"title": {"$regex": escaped, "$options": "i"}},
            {"first_post_content": {"$regex": escaped, "$options": "i"}},
        ]
    if forum:
        from bson import ObjectId
        query["forum_id"] = ObjectId(forum)

    total = db.threads.count_documents(query)
    skip = (page - 1) * limit
    threads = []
    for t in db.threads.find(query).sort("crawled_at", -1).skip(skip).limit(limit):
        threads.append({
            "id": str(t["_id"]),
            "title": t.get("title", "")[:200],
            "author": t.get("author", ""),
            "date": str(t.get("post_date", "")),
            "source": t.get("source_type", ""),
            "forum_id": str(t.get("forum_id", "")),
            "content": t.get("first_post_content", "")[:300],
            "url": t.get("url", ""),
        })
    return {"total": total, "page": page, "threads": threads}


@app.get("/api/flagged")
def get_flagged(q: str = "", reviewed: str = "", page: int = 1, limit: int = 20):
    ldb = get_leaks_db()
    if ldb is None:
        return {"total": 0, "page": page, "threads": []}
    query = {}
    if q:
        escaped = re.escape(q)
        query["$or"] = [
            {"title": {"$regex": escaped, "$options": "i"}},
            {"matched_keywords": {"$regex": escaped, "$options": "i"}},
        ]
    if reviewed == "true":
        query["reviewed"] = True
    elif reviewed == "false":
        query["reviewed"] = False

    total = ldb.flagged_threads.count_documents(query)
    skip = (page - 1) * limit
    threads = []
    for t in ldb.flagged_threads.find(query).sort("flagged_at", -1).skip(skip).limit(limit):
        threads.append({
            "id": str(t["_id"]),
            "title": t.get("title", "")[:200],
            "author": t.get("author", ""),
            "keywords": t.get("matched_keywords", []),
            "reviewed": t.get("reviewed", False),
            "flagged_at": str(t.get("flagged_at", "")),
            "url": t.get("url", ""),
        })
    return {"total": total, "page": page, "threads": threads}


@app.patch("/api/flagged/{thread_id}")
def update_flagged(thread_id: str):
    from bson import ObjectId
    ldb = get_leaks_db()
    if ldb is None:
        raise HTTPException(404, "Leaks DB not configured")
    r = ldb.flagged_threads.update_one(
        {"_id": ObjectId(thread_id)},
        {"$set": {"reviewed": True}},
    )
    if r.modified_count == 0:
        raise HTTPException(404, "Not found")
    return {"ok": True}


@app.post("/api/cookies/test")
def test_cookies(data: dict):
    domain = data.get("domain", "darkforums.su")
    test_url = data.get("test_url", f"https://{domain}/Forum-Databases")

    from utils.cookie_manager import load_cookies
    from scrapling.fetchers import StealthyFetcher

    cookies = load_cookies(domain)
    if not cookies:
        return {"valid": False, "threads": 0, "error": "No cookies file found"}

    try:
        page = StealthyFetcher.fetch(test_url, cookies=cookies, timeout=30000)
        rows = page.css("tr.inline_row")
        return {"valid": len(rows) > 0, "threads": len(rows), "status": page.status}
    except Exception as e:
        return {"valid": False, "threads": 0, "error": str(e)[:100]}


@app.get("/api/logs")
def get_logs(level: str = "", q: str = "", lines: int = 100):
    return {"logs": _read_logs(lines=lines, level=level or None, search=q or None)}


@app.post("/api/crawl/start")
def start_crawl(data: dict):
    global _crawl_process, _crawl_start_time
    if _crawl_process and _crawl_process.poll() is None:
        return {"status": "already_running", "pid": _crawl_process.pid}

    crawler_type = data.get("crawler", "clearnet")
    cmd = [PYTHON, "main.py", "--crawler", crawler_type]

    log_path = PROJECT_DIR / "logs" / "crawler.log"
    with open(log_path, "a") as f:
        f.write(f"\n{'='*50}\nDashboard started crawl at {datetime.now()}\n")

    try:
        _crawl_process = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception as e:
        return {"status": "error", "error": str(e)}

    _crawl_start_time = time.time()

    def _pipe_output(proc):
        try:
            for line in iter(proc.stdout.readline, ""):
                if not line:
                    break
                _broadcast({"type": "crawl_log", "line": line.strip()})
            proc.wait()
        except Exception:
            pass
        _broadcast({"type": "crawl_done", "returncode": proc.returncode})

    Thread(target=_pipe_output, args=(_crawl_process,), daemon=True).start()

    return {"status": "started", "pid": _crawl_process.pid}


@app.post("/api/crawl/stop")
def stop_crawl():
    global _crawl_process, _crawl_start_time
    if _crawl_process and _crawl_process.poll() is None:
        _crawl_process.terminate()
        _crawl_process = None
        _crawl_start_time = None
        _broadcast({"type": "crawl_stopped"})
        return {"status": "stopped"}
    return {"status": "not_running"}


@app.get("/api/crawl/status")
def crawl_status():
    global _crawl_process, _crawl_start_time
    running = _crawl_process is not None and _crawl_process.poll() is None
    uptime = int(time.time() - _crawl_start_time) if running and _crawl_start_time else 0
    return {"running": running, "uptime": uptime}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    q: asyncio.Queue = asyncio.Queue()
    _event_clients.append(q)
    try:
        while True:
            event = await q.get()
            await websocket.send_json(event)
    except Exception:
        pass
    finally:
        if q in _event_clients:
            _event_clients.remove(q)


@app.get("/api/cookies/files")
def list_cookies():
    if not COOKIES_DIR.exists():
        return {"files": []}
    files = []
    for f in sorted(COOKIES_DIR.glob("*.json")):
        if f.name == "make_cookies.py":
            continue
        domain = f.stem.replace("_", ".")
        age = time.time() - f.stat().st_mtime
        files.append({
            "domain": domain,
            "filename": f.name,
            "age_hours": round(age / 3600, 1),
        })
    return {"files": files}


# ──── Serve Frontend ────

@app.get("/", response_class=HTMLResponse)
def index():
    html = (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def run(host="127.0.0.1", port=8001):
    logger.info("Dashboard starting at http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    run()
