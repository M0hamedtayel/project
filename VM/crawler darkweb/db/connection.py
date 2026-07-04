from pymongo import MongoClient
from config import MONGO_HOST, MONGO_PORT, MONGO_DB

_client = None
_db = None


def get_db():
    global _client, _db
    if _db is None:
        _client = MongoClient(MONGO_HOST, MONGO_PORT)
        _db = _client[MONGO_DB]
    return _db


def close_connection():
    global _client, _db
    if _client:
        _client.close()
        _client = None
        _db = None
