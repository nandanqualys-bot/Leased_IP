"""Qt desktop shell, target workflow, history, results, and evidence inspection."""
from __future__ import annotations
import json
from pathlib import Path

from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import (QMainWindow, QWidget, QFrame, QHBoxLayout, QVBoxLayout,
    QLabel, QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QLineEdit, QFileDialog, QMessageBox, QTabWidget, QFormLayout, QSpinBox,
    QComboBox, QDialog, QDialogButtonBox, QProgressBar, QPlainTextEdit, QCheckBox,
    QAbstractItemView, QApplication)

from .engine import input_engine, normalize_targets, targets_from_excel, slug
from .storage import Store
from .workers import AnalysisWorker
from .export import export_results, filename
from .theme import LIGHT, DARK


def label(text, kind=None):
    widget = QLabel(text)
    if kind: widget.setObjectName(kind)
    widget.setWordWrap(True)
    return widget


def button(text, callback, primary=False):
    widget = QPushButton(text)
    if primary: widget.setObjectName('primary')
    widget.clicked.connect(callback)
    return widget


def table(columns):
    widget = QTableWidget(0, len(columns))
    widget.setHorizontalHeaderLabels(columns)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.horizontalHeader().setStretchLastSection(True)
    widget.verticalHeader().setVisible(False)
    widget.setAlternatingRowColors(True)
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
    widget.resizeColumnsToContents()


class DetailDialog(QDialog):
    def __init__(self, row, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{row['ip']} · Evidence")
        self.resize(780, 620)
        layout = QVBoxLayout(self)
        finding = row['finding']; candidate = row['candidate']
        layout.addWidget(label(f"{row['ip']}  ·  {row['status']}", 'heading'))
        layout.addWidget(label(f"{row['organization']}  ·  {'; '.join(row['domains'])}", 'muted'))
        for title, value in (
            ('Why discovered', '; '.join(candidate.get('discovery_sources', [])) + ' · ' + str(row.get('hostname') or '')),
            ('Infrastructure', f"Origin {candidate.get('origin_asn', 'Unknown')} · {finding.get('origin_org', 'Unknown')} · RDAP {finding.get('registered_org', 'Unknown')}"),
            ('Attribution', f"{finding.get('relationship', 'Unverified')} · {finding.get('confidence', 'Unknown')} · score {finding.get('score', '—')} · {'Included' if row['included'] else 'Excluded'}"),
            ('Proof summary', finding.get('proof', 'No proof summary available')),
        ):
            layout.addWidget(label(f'{title}: {value}'))
        layout.addWidget(label('Evidence', 'heading'))
        evidence = table(['Source', 'Observation', 'Points'])
        fill(evidence, finding.get('evidence', []))
        layout.addWidget(evidence, 1)
        layout.addWidget(button('Copy IP', lambda: QApplication.clipboard().setText(row['ip'])))
        layout.addWidget(button('Close', self.accept))


class MainWindow(QMainWindow):
    def __init__(self, store=None):
        super().__init__()
        self.store = store or Store()
        self.settings = QSettings('AtlasEASM', 'Desktop')
        self.current_targets = []
        self.current_run = None
        self.current_rows = []
        self.worker = None
        self.setWindowTitle('Atlas EASM · Off-ASN intelligence')
        self.setMinimumSize(1050, 680)
        self.resize(1320, 830)
        self._build()
        self.apply_theme(self.settings.value('theme', 'Light'))
        self.refresh()

    def _build(self):
        host = QWidget(); self.setCentralWidget(host)
        horizontal = QHBoxLayout(host); horizontal.setContentsMargins(0,0,0,0)
        sidebar = QFrame(); sidebar.setObjectName('sidebar'); sidebar.setFixedWidth(215)
        nav = QVBoxLayout(sidebar); nav.setContentsMargins(18,25,18,18); nav.setSpacing(10)
        nav.addWidget(label('ATLAS EASM', 'heading'))
        nav.addWidget(label('Infrastructure intelligence', 'muted'))
        self.stack = QStackedWidget()
        for name, method in [('Dashboard', self._dashboard), ('New Analysis', self._new_analysis),
                             ('Results', self._results), ('Organizations', self._organizations),
                             ('History', self._history), ('Settings', self._settings)]:
            index = self.stack.addWidget(method())
            nav.addWidget(button(name, lambda _=False, i=index: self.navigate(i)))
        nav.addStretch()
        horizontal.addWidget(sidebar); horizontal.addWidget(self.stack,1)
        self.statusBar().showMessage('Ready')

    def navigate(self, index):
        self.stack.setCurrentIndex(index)
        if index in (0, 3, 4): self.refresh()

    def _page(self, title):
        page = QWidget(); outer = QVBoxLayout(page)
        outer.setContentsMargins(28,24,28,24); outer.setSpacing(14)
        outer.addWidget(label(title, 'heading'))
        return page, outer

    def _dashboard(self):
        page, outer = self._page('Dashboard')
        self.dashboard_summary = label('No analyses yet. Start with a target.'); outer.addWidget(self.dashboard_summary)
        outer.addWidget(button('New analysis', lambda: self.navigate(1), True))
        outer.addWidget(label('Recent analyses', 'heading'))
        self.recent = table(['Run', 'Started', 'Status', 'Candidates']); outer.addWidget(self.recent)
        self.recent.cellDoubleClicked.connect(lambda r,_: self._open_selected_run(self.recent, r))
        return page

    def _new_analysis(self):
        page, outer = self._page('New analysis')
        outer.addWidget(label('Enter targets manually or import an Excel workbook. Both use the same validation.'))
        form = QFormLayout()
        self.parent_name = QLineEdit(); self.entity = QLineEdit(); self.domain = QLineEdit()
        self.asns = QLineEdit(); self.registrants = QLineEdit()
        for title, widget in [('Parent organization', self.parent_name), ('Target entity', self.entity),
                              ('Target domain(s), ; separated', self.domain), ('Known ASN(s), ; separated', self.asns),
                              ('Registrant names, ; separated', self.registrants)]: form.addRow(title, widget)
        outer.addLayout(form)
        actions = QHBoxLayout()
        actions.addWidget(button('Add target', self.add_manual, True))
        actions.addWidget(button('Import Excel', self.import_excel))
        actions.addWidget(button('Download template', self.template))
        actions.addStretch(); outer.addLayout(actions)
        outer.addWidget(label('Review targets', 'heading'))
        self.preview = table(['Parent organization', 'Target entity', 'Domain', 'Known ASNs', 'Registrant names'])
        self.preview.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        outer.addWidget(self.preview,1)
        outer.addWidget(button('Remove selected', self.remove_target))
        self.start_button = button('Run analysis', self.start_analysis, True); outer.addWidget(self.start_button)
        self.progress = QProgressBar(); outer.addWidget(self.progress)
        self.progress_text = label(''); outer.addWidget(self.progress_text)
        outer.addWidget(button('Cancel running analysis', self.cancel_analysis))
        return page

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
            self.current_targets.extend(targets)
            self.show_preview()
        except Exception as exc: QMessageBox.warning(self, 'Import failed', str(exc))

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
        if self.worker and self.worker.isRunning(): return
        # Revalidate the whole preview so duplicates across separate imports are caught.
        rows = [dict(zip(input_engine.COLUMNS, [t['parent_organization'], t['target_entity'],
                 ';'.join(t['target_domains']), ';'.join(t['known_asns']),
                 ';'.join(t['known_registrant_names'])])) for t in self.current_targets]
        try:
            self.current_targets = normalize_targets(rows)
        except ValueError as exc:
            QMessageBox.warning(self, 'Invalid target list', str(exc)); return
        cfg = self._runtime_config()
        self.worker = AnalysisWorker(self.store.path, list(self.current_targets), cfg)
        self.worker.progress.connect(self.on_progress)
        self.worker.completed.connect(self.on_completed)
        self.start_button.setEnabled(False)
        self.progress.setRange(0, len(self.current_targets))
        self.progress.setValue(0)
        self.progress_text.setText('Starting analysis…')
        self.worker.start()

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
        page, outer = self._page('Results')
        self.run_heading = label('Open an analysis from Dashboard or History.', 'muted'); outer.addWidget(self.run_heading)
        controls = QHBoxLayout()
        self.search = QLineEdit(); self.search.setPlaceholderText('Search IP, organization, ASN, hostname…')
        self.search.textChanged.connect(self.filter_results); controls.addWidget(self.search,1)
        self.org_filter = QComboBox(); self.org_filter.currentIndexChanged.connect(self.filter_results)
        controls.addWidget(self.org_filter)
        controls.addWidget(button('Export', self.export_current)); outer.addLayout(controls)
        self.tabs = QTabWidget(); self.result_tables = {}
        for title in ('EASM Assets', 'Candidates', 'Shared Infrastructure', 'Rejected', 'Evidence'):
            tab = table(['IP', 'Organization', 'Domain', 'Origin ASN', 'Relationship', 'Confidence', 'Status'])
            tab.cellDoubleClicked.connect(lambda row, col, widget=tab: self.open_detail(widget, row))
            self.result_tables[title] = tab; self.tabs.addTab(tab, title)
        outer.addWidget(self.tabs, 1)
        self.result_count = label(''); outer.addWidget(self.result_count)
        return page

    def open_run(self, run_id):
        self.current_run = run_id; self.current_rows = self.store.results(run_id)
        self.run_heading.setText(f'Analysis #{run_id} · {len(self.current_rows)} candidate IPs · double-click an IP for evidence')
        self.org_filter.blockSignals(True); self.org_filter.clear(); self.org_filter.addItem('All organizations')
        self.org_filter.addItems(sorted({r['organization'] for r in self.current_rows}))
        self.org_filter.blockSignals(False)
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
            fill(tab, [[r['ip'], r['organization'], ';'.join(r['domains']),
                        r['candidate'].get('origin_asn'), r['finding'].get('relationship'),
                        r['finding'].get('confidence'), r['status']] for r in group])
            self.tabs.setTabText(list(self.result_tables).index(title), f'{title} ({len(group)})')
        self.result_count.setText(f'{len(rows)} matching candidates · {len(groups["EASM Assets"])} defensible assets')

    def open_detail(self, widget, visual_row):
        item = widget.item(visual_row, 0)
        if not item: return
        for name, tab in self.result_tables.items():
            if widget is tab:
                DetailDialog(self.visible_rows[name][item.data(Qt.UserRole)], self).exec(); return

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

    def _organizations(self):
        page, outer = self._page('Organizations')
        outer.addWidget(label('Select an organization to inspect its latest analysis.'))
        self.organizations_table = table(['Organization', 'Runs', 'Candidates', 'EASM Assets'])
        outer.addWidget(self.organizations_table)
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
        self.history_table = table(['Run', 'Started', 'Completed', 'Status', 'Candidates'])
        self.history_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        outer.addWidget(self.history_table)
        self.history_table.cellDoubleClicked.connect(lambda r,_: self._open_selected_run(self.history_table, r))
        outer.addWidget(button('Retry selected', self.retry_selected))
        outer.addWidget(button('Compare two selected runs', self.compare_runs))
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
        form = QFormLayout()
        self.theme_box = QComboBox(); self.theme_box.addItems(['Light','Dark'])
        self.theme_box.currentTextChanged.connect(self.apply_theme)
        self.workers_spin = QSpinBox(); self.workers_spin.setRange(1,32); self.workers_spin.setValue(4)
        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(3,120); self.timeout_spin.setValue(15)
        form.addRow('Appearance', self.theme_box)
        form.addRow('Workers', self.workers_spin); form.addRow('HTTP timeout (seconds)', self.timeout_spin)
        outer.addLayout(form)
        outer.addWidget(label(f'Local database: {self.store.path}'))
        outer.addWidget(label('Optional provider credentials: set SHODAN_API_KEY, CENSYS_API_TOKEN and CENSYS_ORG_ID in your local environment or .env file. Values are never shown or saved in analysis results.'))
        outer.addStretch()
        return page

    def apply_theme(self, name):
        self.settings.setValue('theme', name)
        QApplication.instance().setStyleSheet(DARK if name == 'Dark' else LIGHT)
        if hasattr(self, 'theme_box') and self.theme_box.currentText() != name:
            self.theme_box.setCurrentText(name)

    def refresh(self):
        runs = self.store.runs()
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

    def closeEvent(self, event):
        if self.worker and self.worker.isRunning():
            QMessageBox.information(self, 'Analysis running', 'Cancel the analysis and wait for it to stop before closing.')
            event.ignore(); return
        super().closeEvent(event)
