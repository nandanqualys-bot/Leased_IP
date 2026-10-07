from PySide6.QtCore import QThread, Signal
import logging
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

    def cancel(self):
        self.cancel_requested = True

    def run(self):
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
            records = analyze(self.targets, self.progress.emit, lambda: self.cancel_requested, self.cfg)
            if self.cancel_requested:
                status = 'CANCELLED'
        except Exception as exc:
            status = 'FAILED'
            error = str(exc)
            logger.exception('Analysis %s failed', run_id)
        store.finish(run_id, records, status, error)
        logger.info('Analysis %s %s (%s results)', run_id, status, len(records))
        self.completed.emit(run_id, status, error)
