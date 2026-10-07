"""Short-lived cache for public provider GET responses used by desktop analyses."""
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit
import requests

TTLS = {'stat.ripe.net': 900, 'rdap.org': 3600, 'crt.sh': 3600}


class CachedGet:
    def set_cache(self, path):
        self.cache_path = Path(path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.cache_path) as con:
            con.execute('''CREATE TABLE IF NOT EXISTS responses (
                key TEXT PRIMARY KEY, expires REAL NOT NULL, url TEXT NOT NULL,
                body BLOB NOT NULL, content_type TEXT NOT NULL)''')

    def get(self, url, **kwargs):
        host = urlsplit(url).hostname
        if host not in TTLS or not getattr(self, 'cache_path', None):
            return super().get(url, **kwargs)
        params = kwargs.get('params') or {}
        # Cache only public GETs. Provider tokens must never become keys or stored URLs.
        if kwargs.get('headers') or any('key' in str(k).lower() or 'token' in str(k).lower() for k in params):
            return super().get(url, **kwargs)
        key = hashlib.sha256(json.dumps([url, params], sort_keys=True, default=str).encode()).hexdigest()
        with sqlite3.connect(self.cache_path, timeout=20) as con:
            row = con.execute('SELECT url,body,content_type FROM responses WHERE key=? AND expires>?',
                              (key, time.time())).fetchone()
        if row:
            response = requests.Response()
            response.status_code = 200
            response.url = row[0]
            response._content = row[1]
            response.headers['Content-Type'] = row[2]
            return response
        response = super().get(url, **kwargs)
        if response.status_code == 200 and len(response.content) <= 1024 * 1024:
            with sqlite3.connect(self.cache_path, timeout=20) as con:
                con.execute('INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)',
                            (key, time.time()+TTLS[host], response.url, response.content,
                             response.headers.get('Content-Type','')))
                con.execute('DELETE FROM responses WHERE expires<?', (time.time(),))
        return response
