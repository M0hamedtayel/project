from db.connection import get_db
db = get_db()

# Reactivate BreachForums
bf = db.forums.update_many(
    {"base_url": {"$regex": r"breachforums\.rs"}},
    {"$set": {"is_active": True}}
)
print(f"Reactivated {bf.modified_count} BreachForums sections")

# Clean up test files
import os
for f in os.listdir("."):
    if f.startswith("test_forum") or f in ("add_forums.py", "run_df.py"):
        os.remove(f)
        print(f"Removed: {f}")

print("\nActive forums:")
for f in db.forums.find({"is_active": True}).sort("name", 1):
    print(f"  {f['name']}")
