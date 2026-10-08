from PySide6.QtCore import QThread, Signal
import logging
import threading
from .engine import analyze
from .storage import Store


class AnalysisWorker(QThread):
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
        activate()
        store = Store(self.db_path)
        log_path = store.path.parent / 'atlas.log'
        logger = logging.getLogger('atlas.desktop')
        if not logger.handlers:
            handler = logging.FileHandler(log_path, encoding='utf-8')
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        run_id = store.start(self.targets)
        logger.info('Analysis %s started (%s targets)', run_id, len(self.targets))
        records = []
        status = 'COMPLETED'
        error = ''
        try:
            records = analyze(self.targets, self.progress.emit, self._checkpoint, self.cfg)
            if self.cancel_requested:
                status = 'CANCELLED'
        except Exception as exc:
            status = 'FAILED'
            error = str(exc)
            logger.exception('Analysis %s failed', run_id)
        store.finish(run_id, records, status, error)
        logger.info('Analysis %s %s (%s results)', run_id, status, len(records))
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
        activate()
        store = Store(self.db_path)
        run_id = store.start([self.target])
        records = []
        status, error = 'COMPLETED', ''
        try:
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
            status, error = 'FAILED', str(exc)
        store.finish(run_id, records, status, error)
        self.completed.emit(run_id, status, error)
