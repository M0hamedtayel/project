from db.connection import get_db
import os

db = get_db()

# Deactivate BF
db.forums.update_many(
    {"base_url": {"$regex": r"breachforums\.rs"}},
    {"$set": {"is_active": False}}
)

# Reactivate all DarkForums
db.forums.update_many(
    {"base_url": {"$regex": r"darkforums\.su"}},
    {"$set": {"is_active": True}}
)

print("DarkForums sections active:")
for f in db.forums.find({"is_active": True}).sort("name", 1):
    print(f"  {f['name']}")
