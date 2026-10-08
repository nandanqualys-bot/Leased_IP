"""Qt desktop shell, target workflow, history, results, and evidence inspection."""
from __future__ import annotations
import time

from PySide6.QtCore import Qt, QSettings, QTimer, QPropertyAnimation, QEasingCurve, QEvent
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (QMainWindow, QWidget, QFrame, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QFileDialog, QMessageBox, QTabWidget, QFormLayout, QSpinBox,
    QComboBox, QDialog, QProgressBar, QPlainTextEdit,
    QAbstractItemView, QApplication, QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QScrollArea)

from .engine import input_engine, normalize_targets, targets_from_excel, slug
from .storage import Store
from .workers import AnalysisWorker, ReverifyWorker
from .credentials import presence as credential_presence, save as save_credentials
from .export import export_results, filename
from .theme import LIGHT, DARK


def label(text, kind=None):
    widget = QLabel(text)
    if kind: widget.setObjectName(kind)
    widget.setWordWrap(True)
    return widget


def button(text, callback, primary=False):
    widget = SoftButton(text)
    if primary: widget.setObjectName('primary')
    widget.clicked.connect(callback)
    return widget


class SoftButton(QPushButton):
    """Lightweight opacity feedback while the stylesheet handles color and shape."""
    def __init__(self, text):
        super().__init__(text)
        self.setCursor(Qt.PointingHandCursor)
        self.fade = QGraphicsOpacityEffect(self)
        self.fade.setOpacity(1.0)
        self.setGraphicsEffect(self.fade)
        self.fade_animation = None

    def _fade_to(self, value):
        if self.fade_animation:
            self.fade_animation.stop()
        self.fade_animation = QPropertyAnimation(self.fade, b'opacity', self)
        self.fade_animation.setDuration(130)
        self.fade_animation.setStartValue(self.fade.opacity())
        self.fade_animation.setEndValue(value)
        self.fade_animation.start()

    def enterEvent(self, event):
        self._fade_to(0.86)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._fade_to(1.0)
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        self._fade_to(0.7)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        self._fade_to(0.86 if self.underMouse() else 1.0)
        super().mouseReleaseEvent(event)


def card(kind='panel', shadow=False):
    frame = QFrame(); frame.setObjectName(kind)
    if shadow:
        effect = QGraphicsDropShadowEffect(frame)
        effect.setBlurRadius(28); effect.setOffset(0, 8)
        effect.setColor(QColor(25, 45, 68, 22))
        frame.setGraphicsEffect(effect)
    return frame


def metric(title, value='0', note=''):
    frame = card('metricCard', True)
    contents = QVBoxLayout(frame); contents.setContentsMargins(20, 17, 20, 17)
    contents.setSpacing(6)
    contents.addWidget(label(title.upper(), 'eyebrow'))
    number = label(str(value), 'metricValue'); contents.addWidget(number)
    contents.addWidget(label(note, 'muted'))
    return frame, number


def table(columns):
    widget = QTableWidget(0, len(columns))
    widget.setHorizontalHeaderLabels(columns)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.horizontalHeader().setStretchLastSection(True)
    widget.horizontalHeader().setDefaultSectionSize(150)
    widget.verticalHeader().setVisible(False)
    widget.setAlternatingRowColors(True)
    widget.verticalHeader().setDefaultSectionSize(42)
    widget.setShowGrid(False)
    return widget


def fill(widget, rows):
    widget.setSortingEnabled(False)
    widget.setRowCount(len(rows))
    for r, values in enumerate(rows):
        for c, value in enumerate(values):
            item = QTableWidgetItem(str(value if value is not None else ''))
            item.setData(Qt.UserRole, r)
            widget.setItem(r, c, item)
    widget.setSortingEnabled(True)


class DetailDialog(QDialog):
    def __init__(self, row, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{row['ip']} · Evidence")
        self.resize(850, 690)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 22); layout.setSpacing(15)
        finding = row['finding']; candidate = row['candidate']
        layout.addWidget(label('ASSET INTELLIGENCE', 'eyebrow'))
        title = QHBoxLayout(); title.addWidget(label(row['ip'], 'heading'), 1)
        title.addWidget(label(row['status'].replace('_', ' '), 'statusChip'))
        layout.addLayout(title)
        layout.addWidget(label(f"{row['organization']}  ·  {'; '.join(row['domains'])}", 'muted'))
        summary = QHBoxLayout(); summary.setSpacing(12)
        for title, value in (
            ('Why discovered', '; '.join(candidate.get('discovery_sources', [])) + ' · ' + str(row.get('hostname') or '')),
            ('Infrastructure', f"Origin {candidate.get('origin_asn', 'Unknown')} · {finding.get('origin_org', 'Unknown')} · RDAP {finding.get('registered_org', 'Unknown')}"),
            ('Attribution', f"{finding.get('relationship', 'Unverified')} · {finding.get('confidence', 'Unknown')} · score {finding.get('score', '—')} · {'Included' if row['included'] else 'Excluded'}"),
        ):
            box = card('detailCard'); box_layout = QVBoxLayout(box)
            box_layout.setContentsMargins(15, 14, 15, 14)
            box_layout.addWidget(label(title.upper(), 'eyebrow'))
            box_layout.addWidget(label(value)); summary.addWidget(box, 1)
        layout.addLayout(summary)
        layout.addWidget(label('PROOF SUMMARY', 'eyebrow'))
        layout.addWidget(label(finding.get('proof', 'No proof summary available')))
        layout.addWidget(label('Evidence timeline', 'sectionTitle'))
        evidence = table(['Source', 'Observation', 'Points'])
        fill(evidence, finding.get('evidence', []))
        layout.addWidget(evidence, 1)
        actions = QHBoxLayout()
        actions.addWidget(button('Copy IP', lambda: QApplication.clipboard().setText(row['ip'])))
        actions.addStretch(); actions.addWidget(button('Done', self.accept, True))
        layout.addLayout(actions)


class JobCard(QFrame):
    def __init__(self, organization, pause, cancel, logs):
        super().__init__()
        self.setObjectName('metricCard')
        layout = QVBoxLayout(self); layout.setContentsMargins(20, 16, 20, 16)
        title = QHBoxLayout()
        title.addWidget(label(organization, 'sectionTitle'), 1)
        self.status = label('Queued', 'statusChip'); title.addWidget(self.status)
        layout.addLayout(title)
        self.progress = QProgressBar(); self.progress.setRange(0, 100)
        layout.addWidget(self.progress)
        self.metrics = label('Elapsed  0:00     Hostnames  0     Candidates  0     Verified  0', 'muted')
        layout.addWidget(self.metrics)
        actions = QHBoxLayout()
        self.pause_button = button('Pause', pause)
        actions.addWidget(self.pause_button)
        actions.addWidget(button('Cancel', cancel))
        actions.addWidget(button('Logs', logs))
        actions.addStretch(); layout.addLayout(actions)

    def update_metrics(self, elapsed, hostnames, candidates, verified):
        minutes, seconds = divmod(int(elapsed), 60)
        self.metrics.setText(f'Elapsed  {minutes}:{seconds:02d}     Hostnames  {hostnames}     '
                             f'Candidates  {candidates}     Verified  {verified}')


class MainWindow(QMainWindow):
    def __init__(self, store=None):
        super().__init__()
        self.store = store or Store()
        self.settings = QSettings('AtlasEASM', 'Desktop')
        self.current_targets = []
        self.current_run = None
        self.current_rows = []
        self.worker = None
        self.jobs = {}
        self.pending_jobs = []
        self.next_job_id = 1
        self.system_dark = QApplication.palette().color(QPalette.Window).lightness() < 128
        self.setWindowTitle('Atlas EASM · Off-ASN intelligence')
        self.setMinimumSize(980, 620)
        self.resize(1360, 820)
        self._build()
        QApplication.instance().installEventFilter(self)
        self.apply_theme(self.settings.value('theme', 'System'))
        self.refresh()

    def _build(self):
        host = QWidget(); self.setCentralWidget(host)
        horizontal = QHBoxLayout(host); horizontal.setContentsMargins(0,0,0,0)
        sidebar = QFrame(); sidebar.setObjectName('sidebar')
        sidebar.setMinimumWidth(68); sidebar.setMaximumWidth(236)
        self.sidebar = sidebar
        nav = QVBoxLayout(sidebar); nav.setContentsMargins(20,30,20,22); nav.setSpacing(8)
        self.nav_layout = nav
        brand_row = QHBoxLayout()
        self.brand_label = label('◈  ATLAS', 'brand'); brand_row.addWidget(self.brand_label, 1)
        self.collapse_button = button('‹', self.toggle_sidebar)
        self.collapse_button.setToolTip('Collapse sidebar')
        self.collapse_button.setFixedWidth(34); brand_row.addWidget(self.collapse_button)
        nav.addLayout(brand_row)
        self.brand_subtitle = label('EASM  /  INTELLIGENCE', 'eyebrow')
        nav.addWidget(self.brand_subtitle)
        nav.addSpacing(38)
        self.workspace_label = label('WORKSPACE', 'eyebrow')
        nav.addWidget(self.workspace_label)
        self.stack = QStackedWidget()
        pages = [self._dashboard, self._new_analysis, self._results, self._organizations,
                 self._history, self._settings, self._running_jobs, self._evidence_view]
        for method in pages:
            self.stack.addWidget(method())
        self.nav_buttons = []
        self.nav_entries = [('Dashboard', 0, '◈'), ('New Analysis', 1, '+'),
                            ('Running Jobs', 6, '◷'), ('Analysis History', 4, '≡'),
                            ('Assets', 2, '◆'), ('Evidence', 7, '▤'),
                            ('Organizations', 3, '◎'), ('Settings', 5, '⚙')]
        for name, index, icon in self.nav_entries:
            item = button(f'{icon}    {name}', lambda _=False, i=index: self.navigate(i))
            item.setObjectName('navItem'); item.setCursor(Qt.PointingHandCursor)
            item.setToolTip(name)
            self.nav_buttons.append(item); nav.addWidget(item)
        nav.addStretch()
        self.footer_title = label('LOCAL DESKTOP APP', 'eyebrow')
        self.footer_note = label('Private analysis workspace', 'muted')
        nav.addWidget(self.footer_title); nav.addWidget(self.footer_note)
        horizontal.addWidget(sidebar); horizontal.addWidget(self.stack,1)
        self.statusBar().showMessage('Ready')
        self.job_timer = QTimer(self); self.job_timer.timeout.connect(self.update_job_elapsed)
        self.job_timer.start(1000)
        self.navigate(0)

    def navigate(self, index):
        if index == 7:
            self.refresh_evidence()
        self.stack.setCurrentIndex(index)
        for item, (_, page_index, _) in zip(self.nav_buttons, self.nav_entries):
            item.setProperty('active', page_index == index)
            item.style().unpolish(item); item.style().polish(item)
        if index in (0, 3, 4): self.refresh()

    def toggle_sidebar(self):
        collapsed = self.sidebar.maximumWidth() > 100
        target = 68 if collapsed else 236
        self.nav_layout.setContentsMargins(8 if collapsed else 20,30,8 if collapsed else 20,22)
        for item, (name, _, icon) in zip(self.nav_buttons, self.nav_entries):
            item.setText(icon if collapsed else f'{icon}    {name}')
        for widget in (self.brand_label, self.brand_subtitle, self.workspace_label,
                       self.footer_title, self.footer_note):
            widget.setVisible(not collapsed)
        self.collapse_button.setText('›' if collapsed else '‹')
        self.collapse_button.setToolTip('Expand sidebar' if collapsed else 'Collapse sidebar')
        self.sidebar_animation = QPropertyAnimation(self.sidebar, b'maximumWidth', self)
        self.sidebar_animation.setDuration(220)
        self.sidebar_animation.setStartValue(self.sidebar.maximumWidth())
        self.sidebar_animation.setEndValue(target)
        self.sidebar_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.sidebar_animation.start()

    def _page(self, title):
        page = QWidget(); outer = QVBoxLayout(page)
        outer.setContentsMargins(34,30,34,30); outer.setSpacing(18)
        outer.addWidget(label(title, 'heading'))
        return page, outer

    def _dashboard(self):
        page, outer = self._page('Dashboard')
        outer.addWidget(label('A clear view of your external infrastructure, grounded in evidence.', 'muted'))
        hero = card('hero'); hero_layout = QVBoxLayout(hero)
        hero_layout.setContentsMargins(32, 27, 32, 27); hero_layout.setSpacing(10)
        hero_layout.addWidget(label('DISCOVERY WORKSPACE', 'eyebrow'))
        hero_layout.addWidget(label('Find the assets behind the signal.', 'heroTitle'))
        hero_layout.addWidget(label('Discover broadly. Verify independently. Keep only defensible EASM assets.', 'heroText'))
        hero_actions = QHBoxLayout()
        hero_button = button('Start a new analysis  →', lambda: self.navigate(1))
        hero_button.setObjectName('heroAction'); hero_actions.addWidget(hero_button)
        hero_actions.addStretch(); hero_layout.addLayout(hero_actions)
        outer.addWidget(hero)
        metrics = QHBoxLayout(); metrics.setSpacing(14)
        self.dashboard_numbers = []
        for title, note in [('Analyses', 'Historical runs'), ('Candidates', 'Discovered IPs'),
                            ('EASM assets', 'Defensible attribution'), ('Organizations', 'Parent entities')]:
            tile, value = metric(title, '0', note)
            metrics.addWidget(tile); self.dashboard_numbers.append(value)
        outer.addLayout(metrics)
        self.dashboard_summary = label(''); self.dashboard_summary.hide(); outer.addWidget(self.dashboard_summary)
        outer.addWidget(label('Recent analyses', 'sectionTitle'))
        recent_panel = card('panel'); recent_layout = QVBoxLayout(recent_panel)
        recent_layout.setContentsMargins(12, 12, 12, 12)
        self.recent = table(['Run', 'Started', 'Status', 'Candidates']); recent_layout.addWidget(self.recent)
        outer.addWidget(recent_panel, 1)
        self.recent.cellDoubleClicked.connect(lambda r,_: self._open_selected_run(self.recent, r))
        return page

    def _new_analysis(self):
        page, outer = self._page('New analysis')
        outer.setContentsMargins(24, 20, 24, 20); outer.setSpacing(11)
        outer.addWidget(label('Define the organizations and domains you are authorized to assess.', 'muted'))
        outer.addWidget(label('01  /  Target information', 'sectionTitle'))
        form_panel = card('panel')
        form = QFormLayout()
        form.setContentsMargins(18, 14, 18, 14)
        form.setHorizontalSpacing(22); form.setVerticalSpacing(9)
        self.parent_name = QLineEdit(); self.entity = QLineEdit(); self.domain = QLineEdit()
        self.asns = QLineEdit(); self.registrants = QLineEdit()
        for title, widget in [('Parent organization', self.parent_name), ('Target entity', self.entity),
                              ('Target domain(s), ; separated', self.domain), ('Known ASN(s), ; separated', self.asns),
                              ('Registrant names, ; separated', self.registrants)]: form.addRow(title, widget)
        form_panel.setLayout(form); outer.addWidget(form_panel)
        actions = QHBoxLayout()
        actions.addWidget(button('Add target', self.add_manual, True))
        actions.addWidget(button('Import Excel', self.import_excel))
        actions.addWidget(button('Download template', self.template))
        clear = button('Clear Workspace', self.clear_workspace)
        clear.setObjectName('danger'); actions.addWidget(clear)
        actions.addWidget(button('Remove selected', self.remove_target))
        actions.addStretch(); outer.addLayout(actions)
        outer.addWidget(label('02  /  Review targets', 'sectionTitle'))
        self.preview = table(['Parent organization', 'Target entity', 'Domain', 'Known ASNs', 'Registrant names'])
        self.preview.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        outer.addWidget(self.preview,1)
        self.start_button = button('Run analysis', self.start_analysis, True)
        self.progress = QProgressBar(); self.progress.hide()
        self.progress_text = label(''); self.progress_text.hide()
        self.cancel_button = button('Cancel running analysis', self.cancel_analysis)
        self.cancel_button.setObjectName('danger')
        self.cancel_button.hide()
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame); scroll.setWidget(page)
        wrapper = QWidget(); wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0); wrapper_layout.setSpacing(0)
        wrapper_layout.addWidget(scroll, 1)
        footer = card('panel'); footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(24, 8, 24, 8)
        footer_layout.addWidget(self.start_button)
        footer_layout.addWidget(self.progress)
        footer_layout.addWidget(self.progress_text)
        footer_layout.addWidget(self.cancel_button)
        wrapper_layout.addWidget(footer)
        return wrapper

    def add_manual(self):
        row = dict(zip(input_engine.COLUMNS, [self.parent_name.text(), self.entity.text(),
                  self.domain.text(), self.asns.text(), self.registrants.text()]))
        try:
            targets = normalize_targets([row])
            self.current_targets.extend(targets)
            self.show_preview()
            for widget in (self.parent_name, self.entity, self.domain, self.asns, self.registrants): widget.clear()
        except ValueError as exc: QMessageBox.warning(self, 'Invalid target', str(exc))

    def import_excel(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import target workbook', '', 'Excel files (*.xlsx *.xls)')
        if not path: return
        try:
            targets = targets_from_excel(path)
            choice = QMessageBox(self)
            choice.setWindowTitle('Import targets')
            choice.setText(f'How should {len(targets)} imported target(s) enter this workspace?')
            choice.setInformativeText('Historical analyses stay saved in the local database.')
            replace = choice.addButton('Replace Current Workspace', QMessageBox.AcceptRole)
            append = choice.addButton('Append to Workspace', QMessageBox.ActionRole)
            choice.addButton('Cancel', QMessageBox.RejectRole)
            choice.setDefaultButton(replace)
            choice.exec()
            if choice.clickedButton() is replace:
                self.clear_workspace()
                self.current_targets = list(targets)
            elif choice.clickedButton() is append:
                self.current_targets.extend(targets)
            else:
                return
            self.show_preview()
        except Exception as exc: QMessageBox.warning(self, 'Import failed', str(exc))

    def clear_workspace(self):
        self.current_targets = []
        self.show_preview()
        for widget in (self.parent_name, self.entity, self.domain, self.asns, self.registrants):
            widget.clear()
        self.current_run = None
        self.current_rows = []
        self.search.clear()
        self.run_heading.setText('Open an analysis from History to inspect saved results.')
        self.filter_results()
        self.progress.setValue(0)
        self.progress_text.clear()
        self.progress.hide(); self.progress_text.hide(); self.cancel_button.hide()
        self.statusBar().showMessage('Current workspace cleared; saved history is intact')

    def template(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save input template', 'targets_template.xlsx', 'Excel files (*.xlsx)')
        if not path: return
        import pandas as pd
        pd.DataFrame(columns=input_engine.COLUMNS).to_excel(path, index=False)

    def show_preview(self):
        rows = []
        for target in self.current_targets:
            rows.append([target['parent_organization'], target['target_entity'],
                         ';'.join(target['target_domains']), ';'.join(target['known_asns']),
                         ';'.join(target['known_registrant_names'])])
        fill(self.preview, rows)

    def remove_target(self):
        selected = self.preview.currentRow()
        if selected < 0: return
        item = self.preview.item(selected,0)
        index = item.data(Qt.UserRole) if item else selected
        self.current_targets.pop(index); self.show_preview()

    def start_analysis(self):
        if not self.current_targets:
            QMessageBox.information(self, 'No targets', 'Add or import a target first.'); return
        # Revalidate the whole preview so duplicates across separate imports are caught.
        rows = [dict(zip(input_engine.COLUMNS, [t['parent_organization'], t['target_entity'],
                 ';'.join(t['target_domains']), ';'.join(t['known_asns']),
                 ';'.join(t['known_registrant_names'])])) for t in self.current_targets]
        try:
            self.current_targets = normalize_targets(rows)
        except ValueError as exc:
            QMessageBox.warning(self, 'Invalid target list', str(exc)); return
        grouped = {}
        for target in self.current_targets:
            grouped.setdefault(target['parent_organization'].casefold(), []).append(target)
        for targets in grouped.values():
            job_id = self.next_job_id; self.next_job_id += 1
            organization = targets[0]['parent_organization']
            card_widget = JobCard(organization,
                lambda _=False, i=job_id: self.toggle_job_pause(i),
                lambda _=False, i=job_id: self.cancel_job(i),
                lambda _=False, i=job_id: self.show_job_logs(i))
            card_widget.pause_button.setEnabled(False)
            self.jobs_layout.insertWidget(self.jobs_layout.count()-1, card_widget)
            self.jobs[job_id] = {'organization':organization, 'targets':list(targets),
                'card':card_widget, 'status':'Queued', 'worker':None, 'started':None,
                'hostnames':0, 'candidates':0, 'verified':0, 'finished':False}
            self.pending_jobs.append(job_id)
        self.jobs_empty.hide()
        self._pump_jobs()
        self.navigate(6)

    def _pump_jobs(self):
        active = sum(bool(job['worker']) and not job['finished'] for job in self.jobs.values())
        limit = self.workers_spin.value()
        while self.pending_jobs and active < limit:
            job_id = self.pending_jobs.pop(0)
            job = self.jobs[job_id]
            worker = AnalysisWorker(self.store.path, job['targets'], self._runtime_config())
            job['worker'] = worker; job['status'] = 'Running'; job['started'] = time.monotonic()
            job['card'].status.setText('Running')
            job['card'].pause_button.setEnabled(True)
            worker.progress.connect(lambda stage,current,total,item,i=job_id:
                                    self.on_job_progress(i,stage,current,total,item))
            worker.completed.connect(lambda run_id,status,error,i=job_id:
                                     self.on_job_completed(i,run_id,status,error))
            worker.start()
            active += 1

    def on_job_progress(self, job_id, stage, current, total, item):
        job = self.jobs[job_id]
        if stage == 'candidates':
            job['candidates'] += current
            job['hostnames'] += int(item)
        elif stage == 'verified':
            job['verified'] += 1
        if job['candidates']:
            job['card'].progress.setValue(min(95, int(job['verified'] * 100 / job['candidates'])))
        job['card'].update_metrics(time.monotonic()-job['started'],
                                   job['hostnames'],job['candidates'],job['verified'])
        self.statusBar().showMessage(f"{job['organization']} · {stage.title()} · {item}")

    def on_job_completed(self, job_id, run_id, status, error):
        job = self.jobs[job_id]
        job['finished'] = True
        job['status'] = status.title()
        job['run_id'] = run_id
        job['card'].status.setText(job['status'])
        job['card'].progress.setValue(100 if status == 'COMPLETED' else job['card'].progress.value())
        job['card'].pause_button.setEnabled(False)
        self.statusBar().showMessage(f"{job['organization']} · {status.title()}" + (f' · {error}' if error else ''))
        self.refresh(); self._pump_jobs()
        QTimer.singleShot(2500, lambda i=job_id: self._retire_job_card(i))
        if not any(not j['finished'] for j in self.jobs.values()):
            self.open_run(run_id)

    def _retire_job_card(self, job_id):
        job = self.jobs.get(job_id)
        if job and job['finished']:
            job['card'].hide()
            self.jobs_layout.removeWidget(job['card'])
            job['card'].deleteLater()
        self.jobs_empty.setVisible(not any(not j['finished'] for j in self.jobs.values()))

    def toggle_job_pause(self, job_id):
        job = self.jobs[job_id]
        if job['status'] == 'Running':
            job['worker'].pause(); job['status'] = 'Paused'
            job['card'].status.setText('Paused')
            job['card'].pause_button.setText('Resume')
        elif job['status'] == 'Paused':
            job['worker'].resume(); job['status'] = 'Running'
            job['card'].status.setText('Running')
            job['card'].pause_button.setText('Pause')

    def cancel_job(self, job_id):
        job = self.jobs[job_id]
        if job['finished']: return
        if job['worker']:
            job['worker'].cancel()
        else:
            self.pending_jobs.remove(job_id)
            job['finished'] = True
            QTimer.singleShot(2500, lambda i=job_id: self._retire_job_card(i))
        job['status'] = 'Cancelled'; job['card'].status.setText('Cancelled')
        job['card'].pause_button.setEnabled(False)
        self._pump_jobs()

    def update_job_elapsed(self):
        for job in self.jobs.values():
            if job['started'] and not job['finished']:
                job['card'].update_metrics(time.monotonic()-job['started'],
                    job['hostnames'],job['candidates'],job['verified'])

    def show_job_logs(self, job_id):
        log_path = self.store.path.parent / 'atlas.log'
        dialog = QDialog(self); dialog.setWindowTitle(f"{self.jobs[job_id]['organization']} · Logs")
        dialog.resize(720, 480)
        layout = QVBoxLayout(dialog)
        output = QPlainTextEdit(); output.setReadOnly(True)
        output.setPlainText(log_path.read_text(encoding='utf-8')[-12000:] if log_path.exists() else 'No log entries yet.')
        layout.addWidget(output); layout.addWidget(button('Close', dialog.accept))
        dialog.exec()

    def _runtime_config(self):
        from .engine import config
        cfg = config(); cfg['max_workers'] = self.workers_spin.value()
        cfg.setdefault('timeouts', {})['http'] = self.timeout_spin.value()
        cfg['cache_db'] = str(self.store.path.parent / 'easm_cache.db')
        return cfg

    def on_progress(self, stage, current, total, item):
        self.progress.setMaximum(total); self.progress.setValue(current)
        self.progress_text.setText(f'{stage.title()} · target {current}/{total} · {item}')
        self.statusBar().showMessage(self.progress_text.text())

    def cancel_analysis(self):
        if self.worker and self.worker.isRunning():
            self.worker.cancel(); self.progress_text.setText('Stopping after the current network request…')

    def on_completed(self, run_id, status, error):
        self.start_button.setEnabled(True)
        self.progress_text.setText(f'Run {run_id}: {status}' + (f' · {error}' if error else ''))
        self.statusBar().showMessage(self.progress_text.text())
        self.refresh()
        if status == 'FAILED': QMessageBox.warning(self, 'Analysis failed', error)
        self.open_run(run_id)

    def _results(self):
        page, outer = self._page('Assets')
        self.run_heading = label('Open an analysis from Dashboard or History.', 'muted'); outer.addWidget(self.run_heading)
        overview = QHBoxLayout(); overview.setSpacing(14)
        self.result_numbers = []
        for title, note in [('Candidates', 'Observed IPs'), ('EASM assets', 'Included'),
                            ('Shared', 'Infrastructure context'), ('Rejected', 'Needs more evidence')]:
            tile, value = metric(title, '0', note)
            overview.addWidget(tile); self.result_numbers.append(value)
        outer.addLayout(overview)
        self.key_findings = label('Open an analysis to review its main findings.', 'muted')
        outer.addWidget(self.key_findings)
        controls = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText('Search IP, organization, ASN, hostname…')
        self.search.textChanged.connect(self.filter_results); controls.addWidget(self.search,1)
        self.org_filter = QComboBox(); self.org_filter.addItem('All organizations')
        self.org_filter.currentIndexChanged.connect(self.filter_results)
        controls.addWidget(self.org_filter)
        controls.addWidget(button('Export', self.export_current)); outer.addLayout(controls)
        controls.addWidget(button('Reverify selected IP', self.reverify_selected))
        self.tabs = QTabWidget(); self.result_tables = {}
        for title in ('EASM Assets', 'Candidates', 'Shared Infrastructure', 'Rejected', 'Evidence'):
            tab = table(['IP', 'Organization', 'Relationship', 'Provider', 'Confidence', 'Status'])
            for column in range(tab.columnCount()-1):
                width = self.settings.value(f'table/{title}/{column}', None)
                if width is not None: tab.setColumnWidth(column, int(width))
            tab.horizontalHeader().sectionResized.connect(
                lambda column,_old,new,section=title: self.settings.setValue(f'table/{section}/{column}', new))
            tab.cellClicked.connect(lambda row, col, widget=tab: self.open_detail(widget, row))
            tab.cellDoubleClicked.connect(lambda row, col, widget=tab: self.open_detail(widget, row))
            self.result_tables[title] = tab; self.tabs.addTab(tab, title)
        result_body = QHBoxLayout(); result_body.setSpacing(12)
        result_body.addWidget(self.tabs, 1)
        self.inspector = card('panel'); self.inspector.setMinimumWidth(0)
        self.inspector.setMaximumWidth(0); self.inspector.hide()
        inspector_layout = QVBoxLayout(self.inspector)
        inspector_layout.setContentsMargins(18, 16, 18, 16)
        header = QHBoxLayout()
        header.addWidget(label('IP INSPECTOR', 'eyebrow'), 1)
        header.addWidget(button('×', self.close_inspector))
        inspector_layout.addLayout(header)
        self.inspector_ip = label('', 'sectionTitle'); inspector_layout.addWidget(self.inspector_ip)
        self.inspector_status = label('', 'statusChip'); inspector_layout.addWidget(self.inspector_status)
        self.inspector_tabs = QTabWidget()
        proof = QWidget(); proof_layout = QVBoxLayout(proof)
        self.inspector_proof = label(''); proof_layout.addWidget(self.inspector_proof)
        proof_layout.addStretch()
        self.inspector_tabs.addTab(proof, 'Proof')
        evidence_tab = QWidget(); evidence_layout = QVBoxLayout(evidence_tab)
        self.inspector_evidence = QPlainTextEdit(); self.inspector_evidence.setReadOnly(True)
        evidence_layout.addWidget(self.inspector_evidence)
        self.inspector_tabs.addTab(evidence_tab, 'Evidence')
        infrastructure = QWidget(); infra_layout = QVBoxLayout(infrastructure)
        self.inspector_infra = label(''); infra_layout.addWidget(self.inspector_infra)
        infra_layout.addStretch(); self.inspector_tabs.addTab(infrastructure, 'Network')
        timeline = QWidget(); time_layout = QVBoxLayout(timeline)
        self.inspector_timeline = label(''); time_layout.addWidget(self.inspector_timeline)
        time_layout.addStretch(); self.inspector_tabs.addTab(timeline, 'Timeline')
        inspector_layout.addWidget(self.inspector_tabs, 1)
        self.inspector_copy = button('Copy IP', self.copy_inspector_ip)
        inspector_layout.addWidget(self.inspector_copy)
        result_body.addWidget(self.inspector)
        outer.addLayout(result_body, 1)
        self.result_count = label(''); outer.addWidget(self.result_count)
        return page

    def open_run(self, run_id):
        self.current_run = run_id; self.current_rows = self.store.results(run_id)
        self.run_heading.setText(f'Analysis #{run_id} · {len(self.current_rows)} candidate IPs · double-click an IP for evidence')
        included = sum(bool(row['included']) for row in self.current_rows)
        shared = sum(row['status'] == 'SHARED_INFRASTRUCTURE' for row in self.current_rows)
        excluded = len(self.current_rows) - included
        self.key_findings.setText(
            f'Key findings  ·  {included} defensible assets  ·  {shared} shared infrastructure  ·  '
            f'{excluded} candidates excluded or awaiting stronger evidence')
        self.org_filter.blockSignals(True); self.org_filter.clear(); self.org_filter.addItem('All organizations')
        self.org_filter.addItems(sorted({r['organization'] for r in self.current_rows}))
        self.org_filter.blockSignals(False)
        self.tabs.setCurrentIndex(0 if included else 1)
        self.filter_results(); self.navigate(2)

    def filter_results(self, *args):
        if not hasattr(self, 'result_tables'): return
        query = self.search.text().strip().lower()
        organization = self.org_filter.currentText()
        rows = [r for r in self.current_rows if
                (organization == 'All organizations' or organization == r['organization']) and
                (not query or query in ' '.join(map(str,[r['ip'],r['organization'],r['hostname'],
                   r['candidate'].get('origin_asn'), r['status'], r['finding'].get('origin_org')])).lower())]
        groups = {
            'EASM Assets': [r for r in rows if r['included']],
            'Candidates': rows,
            'Shared Infrastructure': [r for r in rows if r['status']=='SHARED_INFRASTRUCTURE'],
            'Rejected': [r for r in rows if not r['included']],
            'Evidence': [r for r in rows if r['finding'].get('evidence')],
        }
        self.visible_rows = groups
        for title, tab in self.result_tables.items():
            group = groups[title]
            fill(tab, [[r['ip'], r['organization'], r['finding'].get('relationship'),
                        r['finding'].get('origin_org') or r['candidate'].get('origin_organization'),
                        r['finding'].get('confidence'), r['status']] for r in group])
            self.tabs.setTabText(list(self.result_tables).index(title), f'{title} ({len(group)})')
        self.result_count.setText(f'{len(rows)} matching candidates · {len(groups["EASM Assets"])} defensible assets')
        for value, count in zip(self.result_numbers, (len(rows), len(groups['EASM Assets']),
                                                len(groups['Shared Infrastructure']), len(groups['Rejected']))):
            value.setText(str(count))

    def open_detail(self, widget, visual_row):
        item = widget.item(visual_row, 0)
        if not item: return
        for name, tab in self.result_tables.items():
            if widget is tab:
                self.show_inspector(self.visible_rows[name][item.data(Qt.UserRole)])
                return

    def show_inspector(self, row):
        if not self.inspector.isVisible():
            self._expanded_column_widths = {
                name: [tab.columnWidth(column) for column in range(tab.columnCount())]
                for name, tab in self.result_tables.items()}
            for tab in self.result_tables.values():
                header = tab.horizontalHeader(); header.blockSignals(True)
                for column, width in enumerate((105, 120, 125, 110, 85, 150)):
                    tab.setColumnWidth(column, width)
                header.blockSignals(False)
        self.inspector_row = row
        finding, candidate = row['finding'], row['candidate']
        self.inspector_ip.setText(row['ip'])
        self.inspector_status.setText(row['status'].replace('_', ' '))
        self.inspector_proof.setText(
            f"{row['organization']} · {'; '.join(row['domains'])}\n\n"
            f"{finding.get('proof') or 'No proof summary available.'}\n\n"
            f"Classification: {finding.get('relationship', 'Unverified')}\n"
            f"Confidence: {finding.get('confidence', 'Unknown')} · Score: {finding.get('score', '—')}\n"
            f"{'Included in EASM' if row['included'] else 'Excluded from EASM'}")
        observations = finding.get('evidence', [])
        self.inspector_evidence.setPlainText('\n\n'.join(
            f'{source}  ·  {points:+} points\n{detail}' for source, detail, points in observations)
            or 'No provider evidence was recorded for this IP.')
        self.inspector_infra.setText(
            f"Current origin ASN\n{finding.get('origin_asn') or candidate.get('origin_asn') or 'Unknown'}\n\n"
            f"Origin provider\n{finding.get('origin_org') or candidate.get('origin_organization') or 'Unknown'}\n\n"
            f"RDAP registration\n{finding.get('registered_org') or 'Not available'}\n\n"
            f"Current DNS hostnames\n{candidate.get('hostname') or 'None observed'}\n\n"
            f"TLS\n{finding.get('tls', {}).get('cn') or 'No matching certificate recorded'}\n\n"
            f"Reverse DNS\n{finding.get('ptr') or 'Not available'}")
        self.inspector_timeline.setText(
            f"First seen\n{candidate.get('first_seen') or 'Not available'}\n\n"
            f"Last seen\n{candidate.get('last_seen') or 'Not available'}\n\n"
            f"Analysis run\n#{row.get('run_id', self.current_run)}\n\n"
            f"Discovery sources\n{'; '.join(candidate.get('discovery_sources', [])) or 'Not available'}")
        self.inspector_tabs.setCurrentIndex(0)
        if self.width() < 1200 and self.sidebar.maximumWidth() > 100:
            self.toggle_sidebar()
        self.inspector.show()
        self.inspector_animation = QPropertyAnimation(self.inspector, b'maximumWidth', self)
        self.inspector_animation.setDuration(230)
        self.inspector_animation.setStartValue(self.inspector.maximumWidth())
        self.inspector_animation.setEndValue(380)
        self.inspector_animation.setEasingCurve(QEasingCurve.OutCubic)
        self.inspector_animation.start()

    def close_inspector(self):
        self.inspector_animation = QPropertyAnimation(self.inspector, b'maximumWidth', self)
        self.inspector_animation.setDuration(180)
        self.inspector_animation.setStartValue(self.inspector.maximumWidth())
        self.inspector_animation.setEndValue(0)
        self.inspector_animation.finished.connect(self.inspector.hide)
        self.inspector_animation.finished.connect(self._restore_result_columns)
        self.inspector_animation.start()

    def _restore_result_columns(self):
        for name, widths in getattr(self, '_expanded_column_widths', {}).items():
            tab = self.result_tables[name]; header = tab.horizontalHeader()
            header.blockSignals(True)
            for column, width in enumerate(widths):
                tab.setColumnWidth(column, width)
            header.blockSignals(False)

    def copy_inspector_ip(self):
        if hasattr(self, 'inspector_row'):
            QApplication.clipboard().setText(self.inspector_row['ip'])

    def export_current(self):
        if not self.current_run: return
        group = self.visible_rows.get('Candidates', [])
        if not group: return
        org = self.org_filter.currentText()
        if org == 'All organizations': org = 'multiple_organizations'
        suggested = filename(org, self.current_run, 'xlsx')
        path, selected = QFileDialog.getSaveFileName(self, 'Export analysis', suggested,
                                                    'Excel workbook (*.xlsx);;JSON (*.json)')
        if not path: return
        try:
            export_results(group, path)
            self.statusBar().showMessage(f'Exported {path}')
        except Exception as exc: QMessageBox.warning(self, 'Export failed', str(exc))

    def reverify_selected(self):
        if self.worker and self.worker.isRunning(): return
        tab = self.tabs.currentWidget()
        selected = tab.currentRow()
        item = tab.item(selected, 0) if selected >= 0 else None
        if item is None:
            QMessageBox.information(self, 'Reverify', 'Select a candidate IP first.'); return
        title = list(self.result_tables)[self.tabs.currentIndex()]
        row = self.visible_rows[title][item.data(Qt.UserRole)]
        if row['status'] == 'KNOWN_ASN_EXCLUDED':
            QMessageBox.information(self, 'Known ASN', 'This IP matched a known target ASN and is excluded before verification.'); return
        target = next((t for t in self.store.targets(self.current_run)
                       if t['parent_organization'].lower() == row['organization'].lower()
                       and t['target_entity'] == row['entity'] and t['target_domains'] == row['domains']), None)
        if target is None:
            QMessageBox.warning(self, 'Reverify', 'The target for this saved IP could not be found.'); return
        self.worker = ReverifyWorker(self.store.path, target, row, self._runtime_config())
        self.worker.progress.connect(self.on_progress)
        self.worker.completed.connect(self.on_completed)
        self.start_button.setEnabled(False)
        self.worker.start()

    def _running_jobs(self):
        page, outer = self._page('Running Jobs')
        outer.addWidget(label('Each organization runs independently. Pause or cancel one without affecting the others.', 'muted'))
        self.jobs_empty = label('No analyses are running. Add targets in New Analysis to begin.', 'muted')
        outer.addWidget(self.jobs_empty)
        scroll = QScrollArea(); scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        container = QWidget(); self.jobs_layout = QVBoxLayout(container)
        self.jobs_layout.setContentsMargins(0, 0, 0, 0)
        self.jobs_layout.setSpacing(12); self.jobs_layout.addStretch()
        scroll.setWidget(container); outer.addWidget(scroll, 1)
        return page

    def _evidence_view(self):
        page, outer = self._page('Evidence')
        self.evidence_heading = label('Open a saved analysis to explore its observations.', 'muted')
        outer.addWidget(self.evidence_heading)
        self.evidence_search = QLineEdit()
        self.evidence_search.setPlaceholderText('Search IP, source or observation…')
        self.evidence_search.textChanged.connect(self.refresh_evidence)
        outer.addWidget(self.evidence_search)
        panel = card('panel'); contents = QVBoxLayout(panel)
        contents.setContentsMargins(10, 10, 10, 10)
        self.evidence_table = table(['IP', 'Source', 'Observation', 'Points'])
        self.evidence_table.cellDoubleClicked.connect(self.open_evidence_detail)
        contents.addWidget(self.evidence_table); outer.addWidget(panel, 1)
        self.evidence_items = []
        return page

    def refresh_evidence(self):
        if not hasattr(self, 'evidence_table'): return
        if self.current_run is None:
            runs = [run for run in self.store.runs() if run['status'] != 'RUNNING']
            if not runs:
                self.evidence_heading.setText('Open a saved analysis to explore its observations.')
                fill(self.evidence_table, []); return
            run_id = runs[0]['id']
        else:
            run_id = self.current_run
        self.evidence_heading.setText(f'Observations from analysis #{run_id}. Double-click a row to inspect the IP.')
        query = self.evidence_search.text().casefold()
        self.evidence_items = []
        for row in self.store.results(run_id):
            for source, detail, points in row['finding'].get('evidence', []):
                if query and query not in f'{row["ip"]} {source} {detail}'.casefold():
                    continue
                self.evidence_items.append((row, source, detail, points))
        fill(self.evidence_table, [[row['ip'], source, detail, points]
                                   for row, source, detail, points in self.evidence_items])

    def open_evidence_detail(self, visual_row, _column):
        item = self.evidence_table.item(visual_row, 0)
        if item is None: return
        row = self.evidence_items[item.data(Qt.UserRole)][0]
        self.open_run(row['run_id'])
        self.show_inspector(row)

    def _organizations(self):
        page, outer = self._page('Organizations')
        outer.addWidget(label('Explore the parent organizations behind your saved analyses.', 'muted'))
        outer.addWidget(label('Organization overview', 'sectionTitle'))
        panel = card('panel'); contents = QVBoxLayout(panel)
        contents.setContentsMargins(12, 12, 12, 12)
        self.organizations_table = table(['Organization', 'Runs', 'Candidates', 'EASM Assets'])
        contents.addWidget(self.organizations_table); outer.addWidget(panel, 1)
        self.organizations_table.cellDoubleClicked.connect(self.open_organization)
        return page

    def open_organization(self, row, col):
        item = self.organizations_table.item(row, 0)
        if not item: return
        org = item.text()
        for run in self.store.runs():
            if any(r['organization'] == org for r in self.store.results(run['id'])):
                self.open_run(run['id']); self.org_filter.setCurrentText(org); return

    def _history(self):
        page, outer = self._page('Analysis history')
        outer.addWidget(label('Reopen, retry or compare previous observations.', 'muted'))
        actions = QHBoxLayout()
        actions.addWidget(button('Retry selected', self.retry_selected, True))
        actions.addWidget(button('Compare two selected runs', self.compare_runs))
        actions.addStretch(); outer.addLayout(actions)
        panel = card('panel'); contents = QVBoxLayout(panel)
        contents.setContentsMargins(12, 12, 12, 12)
        self.history_table = table(['Run', 'Started', 'Completed', 'Status', 'Candidates'])
        self.history_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        contents.addWidget(self.history_table); outer.addWidget(panel, 1)
        self.history_table.cellDoubleClicked.connect(lambda r,_: self._open_selected_run(self.history_table, r))
        return page

    def _open_selected_run(self, widget, visual_row):
        item = widget.item(visual_row,0)
        if item: self.open_run(int(item.text()))

    def retry_selected(self):
        item = self.history_table.item(self.history_table.currentRow(),0)
        if not item: return
        self.current_targets = self.store.targets(int(item.text()))
        self.show_preview(); self.navigate(1)

    def compare_runs(self):
        selected = sorted({item.row() for item in self.history_table.selectedItems()})
        if len(selected) != 2:
            QMessageBox.information(self, 'Compare runs', 'Select two history rows.'); return
        ids = [int(self.history_table.item(row, 0).text()) for row in selected]
        old, new = sorted(ids)
        before = {(r['organization'].lower(), r['ip']): r for r in self.store.results(old)}
        after = {(r['organization'].lower(), r['ip']): r for r in self.store.results(new)}
        changes = []
        for key in sorted(before.keys() | after.keys()):
            previous, current = before.get(key), after.get(key)
            if previous is None: kind = 'NEW'
            elif current is None: kind = 'REMOVED'
            elif previous['status'] != current['status']: kind = 'CHANGED'
            else: continue
            row = current or previous
            changes.append([kind, row['organization'], row['ip'],
                            previous['status'] if previous else '—',
                            current['status'] if current else '—'])
        dialog = QDialog(self); dialog.setWindowTitle(f'Compare runs #{old} → #{new}'); dialog.resize(820, 520)
        layout = QVBoxLayout(dialog)
        layout.addWidget(label(f'{len(changes)} new, removed or changed IP classifications'))
        listing = table(['Change', 'Organization', 'IP', 'Earlier', 'Later'])
        fill(listing, changes); layout.addWidget(listing)
        layout.addWidget(button('Close', dialog.accept))
        dialog.exec()

    def _settings(self):
        page, outer = self._page('Settings')
        outer.addWidget(label('Tune the workspace and connect optional evidence providers.', 'muted'))
        outer.addWidget(label('Appearance & performance', 'sectionTitle'))
        performance = card('panel')
        form = QFormLayout()
        form.setContentsMargins(22, 20, 22, 20); form.setVerticalSpacing(14)
        self.theme_box = QComboBox(); self.theme_box.addItems(['System','Light','Dark'])
        self.theme_box.currentTextChanged.connect(self.apply_theme)
        self.workers_spin = QSpinBox(); self.workers_spin.setRange(1,32); self.workers_spin.setValue(4)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3,120); self.timeout_spin.setValue(15)
        form.addRow('Appearance', self.theme_box)
        form.addRow('Workers', self.workers_spin); form.addRow('HTTP timeout (seconds)', self.timeout_spin)
        performance.setLayout(form); outer.addWidget(performance)
        outer.addWidget(label('Evidence providers', 'sectionTitle'))
        provider_panel = card('panel'); provider_layout = QVBoxLayout(provider_panel)
        provider_layout.setContentsMargins(22, 20, 22, 20); provider_layout.setSpacing(14)
        provider_layout.addWidget(label('Shodan checks candidates by exact IP and can discover more through hostname search. Censys adds historical DNS context when configured. These sources do not alone prove ownership.', 'muted'))
        credentials = QFormLayout()
        credentials.setVerticalSpacing(12)
        self.credential_inputs = {}
        for name in ('SHODAN_API_KEY','CENSYS_API_TOKEN','CENSYS_ORG_ID'):
            entry = QLineEdit(); entry.setEchoMode(QLineEdit.Password)
            entry.setPlaceholderText('Configured' if credential_presence()[name] else 'Not configured')
            self.credential_inputs[name] = entry
            credentials.addRow(name, entry)
        provider_layout.addLayout(credentials)
        provider_layout.addWidget(button('Save provider credentials', self.save_provider_credentials, True))
        outer.addWidget(provider_panel)
        outer.addWidget(label(f'Local database  ·  {self.store.path}', 'muted'))
        outer.addWidget(label('Credentials are saved in a local .env beside the database. Existing values stay masked; blank fields keep their values.', 'muted'))
        outer.addStretch()
        return page

    def save_provider_credentials(self):
        try:
            save_credentials({name: field.text() for name, field in self.credential_inputs.items()})
            for name, field in self.credential_inputs.items():
                field.clear()
                field.setPlaceholderText('Configured' if credential_presence()[name] else 'Not configured')
            self.statusBar().showMessage('Provider settings saved locally')
        except Exception as exc:
            QMessageBox.warning(self, 'Settings error', str(exc))

    def apply_theme(self, name):
        self.settings.setValue('theme', name)
        dark = name == 'Dark' or (name == 'System' and self.system_dark)
        QApplication.instance().setStyleSheet(DARK if dark else LIGHT)
        if hasattr(self, 'theme_box') and self.theme_box.currentText() != name:
            self.theme_box.setCurrentText(name)

    def eventFilter(self, source, event):
        if (source is QApplication.instance() and
                event.type() == QEvent.ApplicationPaletteChange and
                self.settings.value('theme', 'System') == 'System'):
            dark = QApplication.palette().color(QPalette.Window).lightness() < 128
            if dark != self.system_dark:
                self.system_dark = dark
                QApplication.instance().setStyleSheet(DARK if dark else LIGHT)
        return super().eventFilter(source, event)

    def refresh(self):
        runs = [run for run in self.store.runs() if run['status'] != 'RUNNING']
        fill(self.recent, [[r['id'],r['started'][:19],r['status'],r['count']] for r in runs[:10]])
        fill(self.history_table, [[r['id'],r['started'][:19],(r['completed'] or '')[:19],r['status'],r['count']] for r in runs])
        all_rows = [row for run in runs for row in self.store.results(run['id'])]
        included = sum(bool(r['included']) for r in all_rows)
        self.dashboard_summary.setText(f'{len(runs)} analyses · {len(all_rows)} candidates · {included} defensible assets')
        orgs = {}
        for row in all_rows:
            record = orgs.setdefault(row['organization'], {'runs':set(),'candidates':0,'assets':0})
            record['runs'].add(row['run_id']); record['candidates']+=1; record['assets']+=bool(row['included'])
        fill(self.organizations_table, [[name,len(v['runs']),v['candidates'],v['assets']] for name,v in sorted(orgs.items())])
        for value, count in zip(self.dashboard_numbers, (len(runs), len(all_rows), included, len(orgs))):
            value.setText(str(count))

    def closeEvent(self, event):
        if (self.worker and self.worker.isRunning()) or any(
                job['worker'] and not job['finished'] for job in self.jobs.values()):
            QMessageBox.information(self, 'Analysis running', 'Cancel the analysis and wait for it to stop before closing.')
            event.ignore(); return
        QApplication.instance().removeEventFilter(self)
        super().closeEvent(event)
