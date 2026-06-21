import json
import os
import sqlite3
import time
from typing import Any, Optional


class CacheManager:
    def __init__(self, cache_dir: Optional[str] = None):
        if cache_dir is None:
            cache_dir = os.path.join(os.path.expanduser("~"), ".dep_audit_cache")
        os.makedirs(cache_dir, exist_ok=True)
        self._db_path = os.path.join(cache_dir, "oss_index_cache.db")
        self._ttl = 86400 * 7
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS vulnerabilities (
                    coordinate TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    timestamp REAL NOT NULL
                )"""
            )
            conn.commit()

    def get(self, coordinate: str) -> Optional[dict]:
        with sqlite3.connect(self._db_path) as conn:
            cursor = conn.execute(
                "SELECT response, timestamp FROM vulnerabilities WHERE coordinate = ?",
                (coordinate,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            response_json, timestamp = row
            if time.time() - timestamp > self._ttl:
                conn.execute("DELETE FROM vulnerabilities WHERE coordinate = ?", (coordinate,))
                conn.commit()
                return None
            return json.loads(response_json)

    def set(self, coordinate: str, response: dict):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vulnerabilities (coordinate, response, timestamp) VALUES (?, ?, ?)",
                (coordinate, json.dumps(response), time.time()),
            )
            conn.commit()

    def batch_get(self, coordinates: list) -> dict:
        results = {}
        uncached = []
        for coord in coordinates:
            cached = self.get(coord)
            if cached is not None:
                results[coord] = cached
            else:
                uncached.append(coord)
        return results, uncached

    def batch_set(self, items: dict):
        with sqlite3.connect(self._db_path) as conn:
            for coordinate, response in items.items():
                conn.execute(
                    "INSERT OR REPLACE INTO vulnerabilities (coordinate, response, timestamp) VALUES (?, ?, ?)",
                    (coordinate, json.dumps(response), time.time()),
                )
            conn.commit()

    def clear(self):
        if os.path.exists(self._db_path):
            os.remove(self._db_path)
        self._init_db()
