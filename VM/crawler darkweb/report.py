from db.connection import get_db

db = get_db()

print("=== FINAL DATABASE REPORT ===")
print()

total = db.threads.count_documents({})
with_c = db.threads.count_documents({"first_post_content": {"$ne": ""}})
print(f"Total threads: {total}")
print(f"With content:  {with_c}")
print()

for f in db.forums.find().sort("name", 1):
    count = db.threads.count_documents({"forum_id": f["_id"]})
    wc = db.threads.count_documents(
        {"forum_id": f["_id"], "first_post_content": {"$ne": ""}}
    )
    print(f"  {f['name']}: {count} threads ({wc} with content)")

print()
print("--- Sample threads with content ---")
for t in db.threads.find({"first_post_content": {"$ne": ""}}).sort("_id", -1).limit(5):
    c = t.get("first_post_content", "")
    print(f'  "{t["title"][:50].strip()}" by {t.get("author", "?")}')
    print(f"    Content: {c[:120].strip()}...")
    print()

print("--- Crawl logs ---")
for log in db.crawl_logs.find().sort("started_at", 1):
    s = log.get("status", "?")
    st = log.get("started_at")
    fn = log.get("finished_at")
    dur = str(fn - st).split(".")[0] if fn else "running"
    print(f"  {s} | {dur}")
