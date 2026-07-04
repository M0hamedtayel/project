from db.connection import get_db, close_connection
from datetime import datetime, timezone


def init_database():
    db = get_db()

    db.forums.create_index("base_url", unique=True)
    db.threads.create_index("dedup_hash", unique=True, sparse=True)
    db.threads.create_index("url", unique=True, sparse=True)
    db.threads.create_index("forum_id")
    db.threads.create_index("crawled_at")
    db.crawl_logs.create_index("forum_id")

    existing = db.forums.count_documents({})
    if existing == 0:
        forums = [
            {
                "name": "TIMC Leak List",
                "base_url": "http://rzzfiwoop67jrxadngcy7nvjm7suwtrjznview63ooowqfsm5sq7gmqd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "MONEYMESSAGE Leak Blog",
                "base_url": "http://blogvl7tjyjvsfthobttze52w36wwiz34hrfcmorgvdzb6hikucb7aqd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "BASHE Leak List",
                "base_url": "http://basheqtvzqwz4vp6ks5lm2ocq7i6tozqgf6vjcasj4ezmsy4bkpshhyd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "PLAY NEWS Leak Blog",
                "base_url": "http://j75o7xvvsm4lpsjhkjvb4wl2q6ajegvabe6oswthuaubbykk4xkzgpid.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "PEAR Leak List",
                "base_url": "http://peargxn3oki34c4savcbcfqofjjwjnnyrlrbszfv6ujlx36mhrh57did.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "Nitrogen Ransomware Blog",
                "base_url": "http://nitrogenczslprh3xyw6lh5xyjvmsz7ciljoqxxknd7uymkfetfhgvqd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "DATA EXPOSURE Terminal",
                "base_url": "http://6tdqqaxftvradka5d2frzgwixis7fmro7rfh4ettzcx7jfapkebe6jad.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "File Manager Leaks",
                "base_url": "http://t33zoj4qwv455fog7qnb2azi5xcdxkixughmmduzbw2rtdgryqfbh6id.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "Bjorka Databases",
                "base_url": "https://netleaks.net",
                "forum_type": "clearnet",
                "is_active": True,
            },
            {
                "name": "CMD Official Auctions",
                "base_url": "https://cmdofficial.com",
                "forum_type": "clearnet",
                "is_active": True,
            },
            {
                "name": "KRYBIT Leak List",
                "base_url": "http://krybitx3fh5krdnhegyp2ob3lhizsaiadturtio3ginf7it5gsdgu2yd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "BLACKWATER Leak Blog",
                "base_url": "http://ejzl7cjxmkx7lzhiqwidmrwtfjv45pkczbc4fnyaut3t7gll3yaiq5id.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "MS13-089 Leak Blog",
                "base_url": "http://msleakjir7pxbe6onlqe5uwgvdmy6nq4mnwfy7ojswbhnleenm77vgad.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "NSPIRE RaaS Leaks",
                "base_url": "http://nspirep7orjq73k2x2fwh2mxgh74vm2now6cdbnnxjk2f5wn34bmdxad.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "0day Leak List",
                "base_url": "http://odaygplp3zhyx7zl45egetl6dzc4reduisnoyym34rjdmaryfaz5doqd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "Atomsilo Leak List",
                "base_url": "http://npmh5ahrgakbniuntyc7io4adm6ietbdbuejrfonowqtyqn24or556qd.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "Booba Team Leaks",
                "base_url": "http://7t3zi3e7ki6iseun77ofqtr6wmbpgnpc2ada6gstcxp54lw6q2zb7jad.onion",
                "forum_type": "onion",
                "is_active": True,
            },
            {
                "name": "CardMafia Leaks",
                "base_url": "https://cardmafia.net",
                "forum_type": "clearnet",
                "is_active": True,
            },
        ]
        for f in forums:
            f["last_crawled_at"] = None
            f["created_at"] = datetime.now(timezone.utc)
        db.forums.insert_many(forums)
        print(f"Inserted {len(forums)} leak blog forums.")
    else:
        print("Forums already exist, skipping seed.")

    print("Database initialized successfully.")
    close_connection()


if __name__ == "__main__":
    init_database()
