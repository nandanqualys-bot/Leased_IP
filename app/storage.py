"""Versioned local SQLite store for runs and their evidence."""
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from .engine import slug


def data_dir():
    if os.getenv('EASM_DATA_DIR'):
        return Path(os.environ['EASM_DATA_DIR'])
    if os.name == 'nt':
        return Path(os.getenv('LOCALAPPDATA', Path.home() / 'AppData/Local')) / 'AtlasEASM'
    return Path.home() / '.local/share/AtlasEASM'


class Store:
    def __init__(self, path=None):
        self.path = Path(path) if path else data_dir() / 'atlas.db'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.migrate()

    def connect(self):
        con = sqlite3.connect(self.path, timeout=20)
        con.row_factory = sqlite3.Row
        con.execute('PRAGMA foreign_keys=ON')
        return con

    def migrate(self):
        with self.connect() as con:
            con.executescript('''
                CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS organizations(
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, slug TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS runs(
                    id INTEGER PRIMARY KEY, started TEXT NOT NULL, completed TEXT, status TEXT NOT NULL,
                    targets_json TEXT NOT NULL, error TEXT DEFAULT '');
                CREATE TABLE IF NOT EXISTS run_targets(
                    run_id INTEGER NOT NULL REFERENCES runs(id), org_id INTEGER NOT NULL REFERENCES organizations(id),
                    entity TEXT NOT NULL, domains_json TEXT NOT NULL, known_asns_json TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS results(
                    id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES runs(id),
                    org_id INTEGER NOT NULL REFERENCES organizations(id), ip TEXT NOT NULL, hostname TEXT,
                    status TEXT NOT NULL, included INTEGER NOT NULL, candidate_json TEXT NOT NULL,
                    finding_json TEXT NOT NULL, entity TEXT NOT NULL, domains_json TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_results_run ON results(run_id);
                CREATE INDEX IF NOT EXISTS ix_results_org ON results(org_id);
            ''')
            if not con.execute('SELECT 1 FROM schema_version').fetchone():
                con.execute('INSERT INTO schema_version VALUES (1)')

    def start(self, targets):
        with self.connect() as con:
            cur = con.execute('INSERT INTO runs(started,status,targets_json) VALUES (?,?,?)',
                              (datetime.now(timezone.utc).isoformat(), 'RUNNING', json.dumps(targets)))
            run_id = cur.lastrowid
            for target in targets:
                name = target['parent_organization']
                con.execute('INSERT OR IGNORE INTO organizations(name,slug) VALUES (?,?)', (name, slug(name)))
                org_id = con.execute('SELECT id FROM organizations WHERE name=? COLLATE NOCASE', (name,)).fetchone()[0]
                con.execute('INSERT INTO run_targets VALUES (?,?,?,?,?)', (run_id, org_id, target['target_entity'],
                            json.dumps(target['target_domains']), json.dumps(target.get('known_asns', []))))
            return run_id

    def finish(self, run_id, records, status='COMPLETED', error=''):
        from .credentials import sanitize
        records, error = sanitize(records), sanitize(error)
        with self.connect() as con:
            for r in records:
                org_id = con.execute('SELECT id FROM organizations WHERE name=? COLLATE NOCASE',
                                     (r['organization'],)).fetchone()[0]
                con.execute('''INSERT INTO results(run_id,org_id,ip,hostname,status,included,candidate_json,
                    finding_json,entity,domains_json) VALUES (?,?,?,?,?,?,?,?,?,?)''',
                    (run_id, org_id, r['ip'], r.get('hostname', ''), r['status'], int(r['included']),
                     json.dumps(r['candidate'], default=str), json.dumps(r['finding'], default=str),
                     r['entity'], json.dumps(r['domains'])))
            con.execute('UPDATE runs SET completed=?, status=?, error=? WHERE id=?',
                        (datetime.now(timezone.utc).isoformat(), status, error, run_id))

    def runs(self):
        with self.connect() as con:
            return [dict(r) for r in con.execute('''SELECT runs.*, count(results.id) AS count FROM runs
                LEFT JOIN results ON results.run_id=runs.id GROUP BY runs.id ORDER BY runs.id DESC''')]

    def results(self, run_id):
        with self.connect() as con:
            rows = con.execute('''SELECT results.*, organizations.name AS organization FROM results
                JOIN organizations ON organizations.id=results.org_id WHERE run_id=? ORDER BY results.id''', (run_id,))
            return [{**dict(row), 'candidate': json.loads(row['candidate_json']),
                     'finding': json.loads(row['finding_json']), 'domains': json.loads(row['domains_json'])}
                    for row in rows]

    def targets(self, run_id):
        with self.connect() as con:
            row = con.execute('SELECT targets_json FROM runs WHERE id=?', (run_id,)).fetchone()
            return json.loads(row[0]) if row else []

    def organization_summaries(self):
        """Include completed organizations even when discovery returned no IPs."""
        with self.connect() as con:
            return [dict(row) for row in con.execute('''
                SELECT o.id, o.name, r.id AS run_id, r.completed, r.status,
                    (SELECT count(*) FROM results WHERE run_id=r.id AND org_id=o.id) AS candidates,
                    (SELECT count(*) FROM results WHERE run_id=r.id AND org_id=o.id AND included=1) AS assets
                FROM organizations o JOIN runs r ON r.id=(
                    SELECT max(rt.run_id) FROM run_targets rt JOIN runs rr ON rr.id=rt.run_id
                    WHERE rt.org_id=o.id AND rr.status='COMPLETED') ORDER BY o.name COLLATE NOCASE''')]

    def delete_organization(self, name):
        """Atomically remove one organization, preserving shared runs and global data."""
        with self.connect() as con:
            con.execute('BEGIN IMMEDIATE')
            org = con.execute('SELECT id FROM organizations WHERE name=? COLLATE NOCASE', (name,)).fetchone()
            if org is None:
                return
            org_id = org['id']
            runs = con.execute('''SELECT DISTINCT r.* FROM runs r JOIN run_targets t ON t.run_id=r.id
                                  WHERE t.org_id=?''', (org_id,)).fetchall()
            if any(run['status'] == 'RUNNING' for run in runs):
                raise ValueError('Wait for this organization’s running analyses to finish before deleting it.')
            con.execute('DELETE FROM results WHERE org_id=?', (org_id,))
            con.execute('DELETE FROM run_targets WHERE org_id=?', (org_id,))
            for run in runs:
                remaining = [t for t in json.loads(run['targets_json'])
                             if t['parent_organization'].casefold() != name.casefold()]
                if remaining:
                    con.execute('UPDATE runs SET targets_json=? WHERE id=?', (json.dumps(remaining), run['id']))
                else:
                    con.execute('DELETE FROM runs WHERE id=?', (run['id'],))
            con.execute('DELETE FROM organizations WHERE id=?', (org_id,))
