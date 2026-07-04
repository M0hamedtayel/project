import os
from dotenv import load_dotenv

load_dotenv()

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", 27017))
MONGO_DB = os.getenv("MONGO_DB", "crawler_db")

LEAKS_MONGO_HOST = os.getenv("LEAKS_MONGO_HOST", "localhost")
LEAKS_MONGO_PORT = int(os.getenv("LEAKS_MONGO_PORT", 27017))
LEAKS_MONGO_DB = os.getenv("LEAKS_MONGO_DB", "leaks_db")

PROXY_URL = os.getenv("PROXY_URL")

TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", 9050))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", 9051))
TOR_PASSWORD = os.getenv("TOR_PASSWORD", "")

REQUEST_DELAY = int(os.getenv("REQUEST_DELAY", 5))
MAX_RETRIES = 3
MAX_PAGES = int(os.getenv("MAX_PAGES", 200))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", 5))
PAGE_TIMEOUT = 90000

BREACH_MONGO_HOST = os.getenv("BREACH_MONGO_HOST", "localhost")
BREACH_MONGO_PORT = int(os.getenv("BREACH_MONGO_PORT", 27017))
BREACH_MONGO_DB = os.getenv("BREACH_MONGO_DB", "breach_db")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
