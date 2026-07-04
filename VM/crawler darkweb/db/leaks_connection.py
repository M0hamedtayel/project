from pymongo import MongoClient
from config import LEAKS_MONGO_HOST, LEAKS_MONGO_PORT, LEAKS_MONGO_DB

_client = None
_db = None


def get_leaks_db():
    global _client, _db
    if _db is None:
        _client = MongoClient(LEAKS_MONGO_HOST, LEAKS_MONGO_PORT)
        _db = _client[LEAKS_MONGO_DB]
    return _db


def close_leaks_connection():
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
