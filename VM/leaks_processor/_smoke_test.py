"""Smoke test for the universal SQL parser against real-world data shapes."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers.sql_dump_parser import (
    split_sql_values, unquote_sql, detect_password_format,
    SQLDumpParser, _RE_INSERT_INTO,
)

print("=" * 70)
print("TEST 1: Value parser against real homzmart admin_user row")
print("=" * 70)
# A simplified version of the real row (trimmed long JSON blob)
row = ("3,'abdullah','hesham','abdallah.hesham@homzmart.com','abdullah',"
	       "'0a23d50a7aaf0f2556228de845087fe5ff042ba39fea2ec42fd85089d762fe34:"
	       "ph1d7Wow31Ny47eziHYsqtCoabdLa6Ou:3_32_2_67108864',"
	       "'2020-03-17 11:47:51','2026-04-30 13:50:10',11502,0,1,NULL,"
	       "'en_US','AKIAxxxxxxxxxxxxxPLACEHOLDER','xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')")
tokens = split_sql_values(row)
print(f"Token count: {len(tokens)}")
for i, t in enumerate(tokens):
    v = unquote_sql(t)
    disp = repr(v)
    print(f"  [{i}] {disp[:90]}")

pw = unquote_sql(tokens[5])
print(f"\nPassword value: {pw}")
print(f"Detected format: {detect_password_format(pw)}")

print("\n" + "=" * 70)
print("TEST 2: Password format detection matrix")
print("=" * 70)
tests = [
    ("Magento Argon2ID hash:salt:ver",
     "0a23d50a7aaf0f2556228de845087fe5ff042ba39fea2ec42fd85089d762fe34:"
     "ph1d7Wow31Ny47eziHYsqtCoabdLa6Ou:3_32_2_67108864"),
    ("bcrypt $2y$08$22chars",        "$2y$08$" + "A"*53),
    ("phpass $P$B + 29 more chars",   "$P$B" + "a"*29),
    ("md5 (32 hex)",                 "5d41402abc4b2a76b9719d911017c592"),
    ("sha1 (40 hex)",                "a"*40),
    ("sha256 (64 hex)",              "a"*64),
    ("Argon2id modular",             "$argon2id$v=19$m=65536,t=3,p=4$abc"),
    ("plaintext",                    "mypassword123"),
    ("empty",                        ""),
    ("NULL",                         "NULL"),
]
all_pass = True
for label, val in tests:
    got = detect_password_format(val)
    ok = got != "plaintext" or label == "plaintext"
    if not ok:
        all_pass = False
    mark = "OK " if ok else "!! "
    print(f"  {mark} {label:32s} -> {got}")

print("\n" + "=" * 70)
print("TEST 3: Full parse of a synthetic multi-table dump")
print("=" * 70)

DUMP = r"""-- MySQL dump
CREATE TABLE `admin_user` (
  `user_id` int NOT NULL AUTO_INCREMENT,
  `firstname` varchar(32) DEFAULT NULL,
  `email` varchar(128) DEFAULT NULL,
  `username` varchar(40) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `amazon_access_key` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`user_id`)
) ENGINE=InnoDB;

INSERT INTO `admin_user` VALUES
(3,'abdullah','abdallah.hesham@homzmart.com','abdullah','0a23d50a7aaf0f2556228de845087fe5ff042ba39fea2ec42fd85089d762fe34:ph1d7Wow31Ny47eziHYsqtCoabdLa6Ou:3_32_2_67108864','AKIAxxxxxxxxxxxxxPLACEHOLDER'),
(4,'content','contentmanagement@homzmart.com','contentmanagement','4fb96a8ec0af3e2ed48582b5a44d98fc1c75522641de6f8072a56e54d2bcf472:25SJqefdbbNYEjWf0JAt4IsoiU7Pjv4z:1',NULL);

CREATE TABLE `sales_order_address` (
  `entity_id` int NOT NULL AUTO_INCREMENT,
  `region` varchar(255) DEFAULT NULL,
  `telephone` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `city` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`entity_id`)
) ENGINE=InnoDB;

INSERT INTO `sales_order_address` VALUES
(57851,'Giza','01115555497','Mohamed.helmy41172@gmail.com','Faesal'),
(57853,'Cairo','01282492829','Nevo_2012@yahoo.com','Maadi');

CREATE TABLE `customer_entity` (
  `entity_id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) DEFAULT NULL,
  `firstname` varchar(255) DEFAULT NULL,
  `lastname` varchar(255) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`entity_id`)
) ENGINE=InnoDB;

INSERT INTO `customer_entity` VALUES
(100,'user1@gmail.com','Ahmed','Ali','$2y$08$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456'),
(101,'user2@gmail.com','Mona','Hassan',NULL);

-- A table that should be ignored (log table, no useful identity)
CREATE TABLE `log_visitor` (
  `visitor_id` bigint NOT NULL,
  PRIMARY KEY (`visitor_id`)
) ENGINE=InnoDB;
INSERT INTO `log_visitor` VALUES (1),(2),(3),(4),(5),(6),(7),(8),(9),(10);

-- A table with NO preceding CREATE (partial dump) — must use positional cols
INSERT INTO `mystery_table` VALUES ('someone@x.com','secret','extra');
"""

import tempfile
with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False, encoding="utf-8") as f:
    f.write(DUMP)
    tmp_path = f.name

parser = SQLDumpParser(tmp_path, "homzmart")
records = list(parser.parse())
os.unlink(tmp_path)

print(f"Total records extracted: {len(records)}")
print(f"Tables seen: {parser.tables_seen}")
print(f"Schemas learned: {list(parser._schema.keys())}")
print()
for r in records:
    src = r.fields.get("_source_table")
    email = r.fields.get("email")
    phone = r.fields.get("telephone") or r.fields.get("phone")
    pwtype = r.fields.get("password_type", "-")
    print(f"  [{src}] email={email!s:40s} phone={phone!s:15s} pwtype={pwtype}")

# Assertions
expected_tables = {"admin_user", "sales_order_address", "customer_entity"}
got_tables = set(parser.tables_seen.keys())
log_present = "log_visitor" in got_tables

print()
print("=" * 70)
print("TEST RESULTS")
print("=" * 70)
checks = [
    ("All 3 identity tables parsed", expected_tables.issubset(got_tables)),
    ("log_visitor was ignored",      not log_present),
    ("Got 2 admin_user rows",        parser.tables_seen.get("admin_user") == 2),
    ("Got 2 sales_order_address",    parser.tables_seen.get("sales_order_address") == 2),
    ("Got 2 customer_entity rows",   parser.tables_seen.get("customer_entity") == 2),
    ("Mystery table (no CREATE) parsed", "mystery_table" in got_tables),
    ("Mystery used positional cols", any(r.fields.get("_source_table")=="mystery_table" and "col_1" in r.fields for r in records)),
    ("Password formats all detected", all_pass),
]
allok = True
for label, ok in checks:
    if not ok:
        allok = False
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}")

print()
print("=" * 70)
print(f"OVERALL: {'ALL TESTS PASSED' if allok else 'SOME TESTS FAILED'}")
print("=" * 70)
sys.exit(0 if allok else 1)
