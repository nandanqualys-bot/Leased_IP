import os

import pandas as pd
import pytest
from PySide6.QtCore import Qt, QSettings, QPoint, QPointF
from PySide6.QtGui import QWheelEvent
from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox, QLineEdit
from PySide6.QtTest import QTest

from app import credentials, engine
from app.export import OPTIONS, export_results
from app.storage import Store
from app.window import MainWindow


@pytest.fixture
def desktop(tmp_path, monkeypatch):
    application = QApplication.instance() or QApplication([])
    monkeypatch.setenv('EASM_DATA_DIR', str(tmp_path))
    for name in credentials.NAMES: monkeypatch.delenv(name, raising=False)
    settings = QSettings(str(tmp_path/'settings.ini'), QSettings.IniFormat)
    monkeypatch.setattr('app.window.QSettings', lambda *args: settings)
    window = MainWindow(Store(tmp_path/'atlas.db'))
    yield application, window
    window.close(); application.processEvents()


def target(name):
    return engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        [name, name, name.lower()+'.example.com', 'AS64500', '']))])[0]


def result(name, ip='1.1.1.1', included=True, status='CONFIRMED_LEASED'):
    return {'organization':name, 'entity':name, 'domains':[name.lower()+'.example.com'],
            'ip':ip, 'hostname':name.lower()+'.example.com', 'candidate':{},
            'finding':{'proof':name+' proof', 'evidence':[('DNS', name+' observed',25)]},
            'included':included, 'status':status}


def test_delete_isolated_and_shared_runs_preserve_other_targets(tmp_path):
    store = Store(tmp_path/'atlas.db')
    shared = store.start([target('Alpha'),target('Bravo')])
    store.finish(shared,[result('Alpha'),result('Bravo')])
    solo = store.start([target('Alpha')]); store.finish(solo,[])
    protected = ['credentials.enc','encryption.key','easm_cache.db','settings.ini']
    for name in protected: (tmp_path/name).write_bytes(b'unchanged')
    store.delete_organization('aLpHa')
    assert [run['id'] for run in store.runs()] == [shared]
    assert [row['organization'] for row in store.results(shared)] == ['Bravo']
    assert store.targets(shared) == [target('Bravo')]
    assert [row['name'] for row in store.organization_summaries()] == ['Bravo']
    with store.connect() as con:
        assert con.execute('PRAGMA foreign_key_check').fetchall() == []
        assert con.execute('SELECT count(*) FROM organizations').fetchone()[0] == 1
    for name in protected: assert (tmp_path/name).read_bytes() == b'unchanged'


def test_delete_running_organization_rolls_back(tmp_path):
    store = Store(tmp_path/'atlas.db')
    completed = store.start([target('Alpha')]); store.finish(completed,[result('Alpha')])
    running = store.start([target('Alpha')])
    with pytest.raises(ValueError, match='running'):
        store.delete_organization('Alpha')
    assert len(store.runs()) == 2 and len(store.results(completed)) == 1
    assert store.targets(running) == [target('Alpha')]


def test_delete_confirmation_and_immediate_refresh(desktop, monkeypatch):
    application, window = desktop
    run = window.store.start([target('Alpha')]); window.store.finish(run,[result('Alpha')])
    window.refresh(); window.open_run(run)
    def cancel(dialog):
        assert dialog.defaultButton().text() == 'Cancel'
        assert {b.text() for b in dialog.buttons()} == {'Cancel','Delete'}
        return 0
    monkeypatch.setattr(QMessageBox,'exec',cancel)
    window.delete_organization('Alpha')
    assert len(window.store.runs()) == 1
    monkeypatch.setattr(window,'confirm_organization_deletion',lambda name: True)
    window.delete_organization('Alpha')
    assert window.store.runs() == []
    assert window.history_table.rowCount() == 0
    assert window.exports_table.rowCount() == 0 and window.current_rows == []


@pytest.mark.parametrize('mode', OPTIONS)
def test_export_scopes_and_empty_workbooks(tmp_path, mode):
    rows = [result('Alpha'),result('Alpha','8.8.8.8',False,'UNVERIFIED'),
            result('Alpha','9.9.9.9',False,'PENDING'),result('Bravo')]
    path = tmp_path/'alpha.xlsx'
    export_results(rows,path,mode=mode,organization='Alpha')
    sheets = pd.read_excel(path,sheet_name=None)
    for frame in sheets.values():
        assert 'Bravo' not in frame.to_string()
    if mode == 'Export Full Workbook':
        assert list(sheets) == ['Summary','EASM Assets','Candidates','Rejected','Evidence','Score Breakdown','Score Guide']
        assert len(sheets['EASM Assets']) == 1
        assert len(sheets['Rejected']) == 1
        assert len(sheets['Candidates']) == 3
    if mode in ('Export EASM Assets','Export Verified Results','Export Rejected'):
        assert len(next(iter(sheets.values()))) == 1
    with pytest.raises(FileExistsError): export_results(rows,path,mode=mode,organization='Alpha')
    export_results([],tmp_path/'empty.xlsx',mode=mode,organization='Empty')
    assert pd.ExcelFile(tmp_path/'empty.xlsx').sheet_names


def test_export_from_page_without_opening_and_save_as(desktop, tmp_path, monkeypatch):
    _, window = desktop
    run = window.store.start([target('Alpha'),target('Bravo')])
    window.store.finish(run,[result('Alpha'),result('Bravo')])
    empty = window.store.start([target('Empty')]); window.store.finish(empty,[])
    window.navigate(8)
    assert window.exports_table.rowCount() == 3
    assert window.current_run is None
    original = tmp_path/'exists.xlsx'; original.write_bytes(b'keep original')
    destination = tmp_path/'new.xlsx'
    paths = iter([str(original),str(destination)])
    monkeypatch.setattr(QDialog,'exec',lambda dialog: QDialog.Accepted)
    monkeypatch.setattr(QFileDialog,'getSaveFileName',lambda *a,**kw: (next(paths),'Excel'))
    def choose_save_as(dialog):
        save_as=next((b for b in dialog.buttons() if b.text()=='Save As'),None)
        if save_as is not None: save_as.click()
        else: return QMessageBox.Close
    monkeypatch.setattr(QMessageBox,'exec',choose_save_as)
    row = next(r for r in range(window.exports_table.rowCount()) if window.exports_table.item(r,0).text()=='Alpha')
    window.exports_table.cellWidget(row,5).click()
    assert original.read_bytes() == b'keep original'
    worker=window.export_workers[-1]
    assert worker.wait(10000)
    desktop[0].processEvents()
    assert destination.exists()
    assert pd.read_excel(destination, sheet_name='Candidates')['Organization'].tolist() == ['Alpha']
    assert window.current_run is None


def test_provider_save_show_hide_reopen_and_stale_test(desktop, tmp_path, monkeypatch):
    _, window = desktop
    entry = window.credential_inputs['SHODAN_API_KEY']
    entry.setText('persistent-test-key'); window.save_provider_credentials('Shodan')
    assert window.provider_labels['Shodan'].text() == 'Configured'
    assert entry.text() == '' and entry.echoMode() == QLineEdit.Password
    assert entry.placeholderText() == '**********************'
    window.toggle_credential('SHODAN_API_KEY')
    assert entry.text() == 'persistent-test-key' and entry.echoMode() == QLineEdit.Normal
    window.toggle_credential('SHODAN_API_KEY')
    assert entry.text() == '' and entry.echoMode() == QLineEdit.Password
    window.provider_test_finished('Shodan',1,'Connection verified')
    assert 'Never' not in window.provider_last_tested['Shodan'].text()
    window.replace_provider_key('Shodan'); entry.setText('replacement-key')
    window.save_provider_credentials('Shodan')
    window.provider_test_finished('Shodan',1,'Connection verified')
    assert window.provider_connection['Shodan'].text() == 'Not tested for current credentials'
    monkeypatch.delenv('SHODAN_API_KEY')
    reopened = MainWindow(window.store)
    assert reopened.provider_labels['Shodan'].text() == 'Configured'
    assert reopened.credential_inputs['SHODAN_API_KEY'].text() == ''
    reopened.toggle_credential('SHODAN_API_KEY')
    assert reopened.credential_inputs['SHODAN_API_KEY'].text() == 'replacement-key'
    assert b'replacement-key' not in (tmp_path/'credentials.enc').read_bytes()
    reopened.close()


def test_settings_wheel_requires_focus(desktop):
    application, window = desktop
    window.show(); window.navigate(5); application.processEvents()
    spin = window.workers_spin
    window.nav_buttons[0].setFocus(); application.processEvents()
    def wheel():
        return QWheelEvent(QPointF(10,10),QPointF(spin.mapToGlobal(QPoint(10,10))),QPoint(),QPoint(0,120),
                           Qt.NoButton,Qt.NoModifier,Qt.NoScrollPhase,False)
    before = spin.value(); event = wheel(); QApplication.sendEvent(spin,event)
    assert spin.value() == before and not event.isAccepted()
    spin.setFocus(Qt.MouseFocusReason); application.processEvents()
    QApplication.sendEvent(spin,wheel())
    assert spin.value() == before+1


def test_preview_retains_structured_values(desktop):
    _, window = desktop
    data = target('Alpha'); data['known_asns'] = ['AS64500','AS64501']
    data['known_registrant_names'] = ['Alpha Inc.','Alpha, Inc.']
    window.current_targets = [data]; window.show_preview()
    assert window.preview.item(0,3).data(Qt.UserRole+1) == ['AS64500','AS64501']
    assert window.preview.item(0,4).data(Qt.UserRole+1) == ['Alpha Inc.','Alpha, Inc.']
    assert window.preview.item(0,4).toolTip() == 'Alpha Inc.\nAlpha, Inc.'


def test_delete_single_analysis_keeps_organization_and_other_runs(desktop, monkeypatch):
    app,window=desktop
    runs=[]
    for label in ('A','B','C'):
        run=window.store.start([target('Alpha')]); window.store.finish(run,[result('Alpha',f'1.1.1.{len(runs)+1}')]); runs.append(run)
    window.navigate(4); window.open_run(runs[1])
    def confirm(dialog):
        assert 'organization and its other analyses remain' in dialog.informativeText()
        next(b for b in dialog.buttons() if b.text()=='Delete Analysis').click()
    monkeypatch.setattr(QMessageBox,'exec',confirm)
    window.delete_analysis(runs[1])
    assert [r['id'] for r in window.store.runs()] == [runs[2],runs[0]]
    assert window.store.organization_overview() == [{'name':'Alpha','runs':2,'candidates':2,'assets':2}]
    assert window.current_run is None and window.current_rows == []
    assert window.history_table.rowCount() == 2
    assert len(window.store.recent_analyses(10)) == 2
    assert window.store.organization_summaries()[0]['run_id'] == runs[2]


def test_dashboard_recent_compact_expands_and_collapses(desktop):
    app,window=desktop
    for index in range(12):
        run=window.store.start([target('Alpha')]); window.store.finish(run,[result('Alpha',f'1.1.{index//254}.{index+1}')])
    window.resize(1000,650); window.show(); window.navigate(0); app.processEvents()
    assert window.recent.rowCount() == 3 and window.recent.verticalScrollBarPolicy() == Qt.ScrollBarAlwaysOff
    assert window.recent_panel.maximumHeight() <= 260
    window.toggle_recent_analyses(); app.processEvents(); QTest.qWait(250)
    assert window.recent_expanded and window.recent.rowCount() == 10
    assert window.recent_panel.height() > 260
    assert window.stack.currentWidget().verticalScrollBar().maximum() > 0
    window.toggle_recent_analyses(); app.processEvents(); QTest.qWait(250)
    assert not window.recent_expanded and window.recent.rowCount() == 3
    assert window.recent_panel.maximumHeight() == 260


def test_dashboard_recent_query_does_not_load_full_result_history(desktop, monkeypatch):
    _,window=desktop
    run=window.store.start([target('Alpha')]); window.store.finish(run,[result('Alpha')])
    monkeypatch.setattr(window.store,'results',lambda *_: pytest.fail('Dashboard must use aggregate queries'))
    window.refresh_dashboard()
    assert window.recent.rowCount() == 1


def test_new_analysis_accepts_natural_lists_and_reports_invalid_values(desktop):
    _,window=desktop
    raw=dict(zip(engine.input_engine.COLUMNS,['CIBC','CIBC','cibc.com, wrongdomain\ncibc.ca','AS12345, hello\n27385','CIBC Inc.; CIBC, Inc.']))
    normalized,warnings=window._validated_target_rows([raw])
    assert normalized[0]['target_domains'] == ['cibc.com','cibc.ca']
    assert normalized[0]['known_asns'] == ['AS12345','AS27385']
    assert normalized[0]['known_registrant_names'] == ['CIBC Inc.','CIBC, Inc.']
    assert len(warnings) == 2
    window.show_validation_summary(warnings)
    assert not window.validation_banner.isHidden()
    assert 'wrongdomain' in window.validation_banner.text() and 'hello' in window.validation_banner.text()
    invalid=dict(zip(engine.input_engine.COLUMNS,['CIBC','CIBC','bad-domain-value','ASHELLO','']))
    normalized,warnings=window._validated_target_rows([invalid])
    assert normalized == [] and any('valid target domain is required' in warning for warning in warnings)
