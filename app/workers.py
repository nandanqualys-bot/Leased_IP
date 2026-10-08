from PySide6.QtCore import QThread, Signal
import logging
import threading
from .engine import analyze
from .storage import Store


class AnalysisWorker(QThread):
    record_ready = Signal(object)
    log_entry = Signal(str)
    progress = Signal(str, int, int, str)
    completed = Signal(int, str, str)

    def __init__(self, db_path, targets, cfg=None):
        super().__init__()
        self.db_path = db_path
        self.targets = targets
        self.cfg = cfg
        self.cancel_requested = False
        self._resume = threading.Event()
        self._resume.set()

    def cancel(self):
        self.cancel_requested = True
        self._resume.set()

    def pause(self):
        self._resume.clear()

    def resume(self):
        self._resume.set()

    def _checkpoint(self):
        self._resume.wait()
        return self.cancel_requested

    def run(self):
        from .credentials import activate
        store = Store(self.db_path)
        from logging.handlers import RotatingFileHandler
        log_path = store.path.parent / 'logs' / 'atlas.log'
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logger = logging.getLogger('atlas.desktop.' + str(store.path.resolve()))
        if not logger.handlers:
            handler = RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        run_id = store.start(self.targets)
        logger.info('Analysis %s started (%s targets)', run_id, len(self.targets))
        self.progress.emit('run', run_id, run_id, self.targets[0]['parent_organization'] if self.targets else '')
        records = []
        status = 'COMPLETED'
        error = ''
        try:
            activate()
            def progress(stage, current, total, item):
                self.progress.emit(stage, current, total, item)
                message = f'INFO {stage.title()} · {current}/{total} · {item}'
                self.log_entry.emit(message)
                logger.info('Analysis %s %s', run_id, message)
            def record_ready(record):
                key = (record['organization'], record['entity'], record['ip'], record['hostname'])
                position = next((i for i,r in enumerate(records) if
                    (r['organization'],r['entity'],r['ip'],r['hostname']) == key), None)
                if position is None: records.append(record)
                else: records[position] = record
                self.record_ready.emit(record)
                message = (f"INFO Discovered {record['ip']} · awaiting verification" if record['status'] == 'PENDING' else
                           f"INFO Candidate {record['ip']} classified {record['status']} · proof generated")
                self.log_entry.emit(message)
                logger.info('Analysis %s %s', run_id, message)
                for source, detail, points in record['finding'].get('evidence', []):
                    self.log_entry.emit(f'DEBUG {source} evidence recorded · {points:+} points')
                if record['status'] in ('ERROR', 'UNVERIFIED'):
                    self.log_entry.emit('WARNING Candidate has insufficient evidence for inclusion')
            analyze(self.targets, progress, self._checkpoint, self.cfg, on_record=record_ready)
            if self.cancel_requested:
                status = 'CANCELLED'
        except Exception as exc:
            status = 'FAILED'
            error = 'Analysis failed. Check provider availability and target configuration.'
            logger.error('Analysis %s failed (%s)', run_id, type(exc).__name__)
            self.log_entry.emit('ERROR ' + error)
        store.finish(run_id, records, status, error)
        logger.info('Analysis %s %s (%s results)', run_id, status, len(records))
        self.log_entry.emit(f'INFO Analysis {status.lower()} · {len(records)} candidates')
        self.completed.emit(run_id, status, error)


class ReverifyWorker(QThread):
    """Verify one saved off-ASN candidate with fresh provider observations."""
    progress = Signal(str, int, int, str)
    completed = Signal(int, str, str)

    def __init__(self, db_path, target, previous, cfg=None):
        super().__init__()
        self.db_path = db_path
        self.target = target
        self.previous = previous
        self.cfg = cfg

    def run(self):
        from .engine import verification, classify, config, canonical_asn, VerificationClient
        from .credentials import activate
        store = Store(self.db_path)
        run_id = store.start([self.target])
        records = []
        status, error = 'COMPLETED', ''
        try:
            activate()
            candidate = dict(self.previous['candidate'])
            self.progress.emit('reverification', 1, 1, candidate['ip'])
            effective_config = self.cfg or config()
            client = VerificationClient(effective_config)
            network = verification.ripe_network(client, candidate['ip'])
            origins = [canonical_asn(str(asn)) for asn in network.get('asns', [])]
            known = {canonical_asn(asn) for asn in self.target.get('known_asns', [])}
            if any(origin in known for origin in origins):
                origin = next(origin for origin in origins if origin in known)
                candidate['origin_asn'] = origin
                finding = {'relationship': 'Known target ASN', 'confidence': 'EXCLUDED',
                           'proof': f"{candidate['ip']} is now originated by {origin}, a known target ASN. Excluded before verification.",
                           'evidence': [('Known ASN', f'Origin {origin} matches target ASN', 0)]}
                classification = 'KNOWN_ASN_EXCLUDED'
            else:
                finding = verification.score_candidate(self.target, candidate, client, effective_config)
                classification = classify(finding)
            records = [{
                'organization': self.target['parent_organization'],
                'entity': self.target['target_entity'],
                'domains': self.target['target_domains'],
                'ip': candidate['ip'], 'hostname': candidate.get('hostname', ''),
                'candidate': candidate, 'finding': finding, 'status': classification,
                'included': classification in ('CONFIRMED_OWNED','CONFIRMED_LEASED','CONFIRMED_OPERATED'),
            }]
        except Exception as exc:
            status, error = 'FAILED', 'Reverification failed. Check provider availability.'
        store.finish(run_id, records, status, error)
        self.completed.emit(run_id, status, error)


class ProviderTestWorker(QThread):
    completed = Signal(str)

    def __init__(self, provider, values, parent=None):
        super().__init__(parent)
        self.provider, self.values = provider, values

    def run(self):
        from .credentials import activate, NAMES
        from .provider_access import ProviderSession
        import os
        try:
            activate()
            values = {n: self.values.get(n) or os.getenv(n, '') for n in NAMES}
            with ProviderSession() as session:
                if self.provider == 'Shodan':
                    if not values['SHODAN_API_KEY']:
                        self.completed.emit('Enter an API key first'); return
                    response = session.get('https://api.shodan.io/api-info',
                        params={'key': values['SHODAN_API_KEY']}, timeout=15)
                else:
                    if not values['CENSYS_API_TOKEN'] or not values['CENSYS_ORG_ID']:
                        self.completed.emit('Enter a token and organization ID first'); return
                    response = session.get('https://api.platform.censys.io/v3/global/asset/host/1.1.1.1',
                        headers={'Authorization':'Bearer '+values['CENSYS_API_TOKEN']},
                        params={'organization_id':values['CENSYS_ORG_ID']}, timeout=15)
                self.completed.emit('Connection verified' if response.status_code == 200 else
                                    f'Provider returned HTTP {response.status_code}; check credentials and account access')
        except Exception:
            self.completed.emit('Connection unavailable; check network and provider access')
        finally:
            self.values.clear()


class ExportWorker(QThread):
    completed = Signal(str, str, str)

    def __init__(self, db_path, run_id, organization, destination, mode, overwrite, parent=None):
        super().__init__(parent)
        self.db_path, self.run_id, self.organization = db_path, run_id, organization
        self.destination, self.mode, self.overwrite = destination, mode, overwrite

    def run(self):
        try:
            from .storage import Store
            from .export import export_results
            snapshot=Store(self.db_path).export_data(self.run_id,self.organization)
            if snapshot is None:
                raise ValueError('The selected analysis was removed or is no longer complete.')
            run,targets,rows=snapshot
            metadata={**run,'targets':targets,'organization':self.organization}
            export_results(rows,self.destination,mode=self.mode,organization=self.organization,
                           overwrite=self.overwrite,metadata=metadata)
            self.completed.emit(self.organization,self.destination,'')
        except FileExistsError:
            self.completed.emit(self.organization,self.destination,'That file already exists. Choose Save As and try again.')
        except PermissionError:
            self.completed.emit(self.organization,self.destination,'The destination is not writable or the workbook is open in another application.')
        except Exception as exc:
            self.completed.emit(self.organization,self.destination,str(exc))
