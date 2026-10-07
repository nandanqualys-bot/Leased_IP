import json
import os
from pathlib import Path

import pandas as pd
import pytest
from PySide6.QtWidgets import QApplication
from app import engine
from app.storage import Store
from app.export import export_results, filename
from app.window import MainWindow
from app.workers import AnalysisWorker


@pytest.fixture(scope='session')
def app():
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'
    return QApplication.instance() or QApplication([])


def test_inputs_and_asn(tmp_path):
    assert engine.canonical_asn('27385') == 'AS27385'
    assert engine.canonical_asn('as27385') == 'AS27385'
    with pytest.raises(ValueError): engine.canonical_asn('AS bad')
    row = dict(zip(engine.input_engine.COLUMNS, ['Qualys, Inc.', '', 'HTTPS://Qualys.com/', '27385', 'Qualys']))
    manual = engine.normalize_targets([row])
    assert manual[0]['known_asns'] == ['AS27385']
    pd.DataFrame([row]).to_excel(tmp_path/'targets.xlsx', index=False)
    assert engine.targets_from_excel(str(tmp_path/'targets.xlsx')) == manual


def test_known_asn_is_excluded_before_verification(monkeypatch):
    targets = engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example', 'Example', 'example.com', 'AS27385', 'Example']))])
    rows = []
    for ip, asn in [('1.1.1.1', 'AS27385'), ('8.8.8.8', 'AS13335')]:
        rows.append({'IP':ip,'Origin_ASN':asn,'Discovered_Hostname':'example.com',
                     'Origin_Organization':'Provider','Hosting_Provider':'Provider',
                     'Discovery_Source':'DNS','Discovery_Evidence':'{}','First_Seen':'', 'Last_Seen':''})
    monkeypatch.setattr(engine.discovery, 'process_target', lambda *a, **k: rows)
    calls=[]
    def verify(t,c,client,cfg):
        calls.append(c['ip'])
        return {'confidence':'LOW','relationship':'Unverified','score':30,'evidence':[], 'proof':'Weak evidence'}
    monkeypatch.setattr(engine.verification, 'score_candidate', verify)
    results = engine.analyze(targets)
    assert [r['status'] for r in results] == ['KNOWN_ASN_EXCLUDED','UNVERIFIED']
    assert calls == ['8.8.8.8']
    assert not any(r['included'] for r in results)


def test_storage_reopen_export_and_ui(app, tmp_path):
    db = tmp_path/'atlas.db'
    store = Store(db)
    targets = engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Qualys, Inc.', 'Qualys', 'qualys.com', 'AS27385', 'Qualys']))])
    run_id=store.start(targets)
    row={'organization':'Qualys, Inc.','entity':'Qualys','domains':['qualys.com'],
         'ip':'1.1.1.1','hostname':'qualys.com','candidate':{'origin_asn':'AS13335'},
         'finding':{'relationship':'Unverified','confidence':'LOW','score':30,
                    'proof':'Weak evidence','evidence':[('DNS','qualys.com',25)]},
         'status':'UNVERIFIED','included':False}
    store.finish(run_id,[row])
    reopened=Store(db)
    assert reopened.runs()[0]['count']==1
    assert reopened.results(run_id)[0]['finding']['evidence'][0][0]=='DNS'
    assert reopened.targets(run_id)==targets
    assert filename('Qualys, Inc.',run_id,'xlsx').startswith('qualys_inc_run_')
    export_results(reopened.results(run_id),tmp_path/'report.xlsx')
    assert 'Evidence' in pd.ExcelFile(tmp_path/'report.xlsx').sheet_names
    window=MainWindow(reopened)
    window.show(); app.processEvents(); window.open_run(run_id)
    assert window.isVisible() and window.current_rows[0]['ip']=='1.1.1.1'
    window.close()


def test_worker_runs_off_ui_thread(app, tmp_path, monkeypatch):
    targets=engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example','Example','example.com','AS64500','']))])
    monkeypatch.setattr('app.workers.analyze', lambda *a: [])
    worker=AnalysisWorker(tmp_path/'db.sqlite',targets)
    worker.start(); assert worker.wait(5000)
    assert Store(tmp_path/'db.sqlite').runs()[0]['status']=='COMPLETED'


def test_direct_sample_analysis_persists(app, tmp_path, monkeypatch):
    """Exercise real discovery/score functions with controlled provider observations."""
    d=engine.discovery; v=engine.verification
    monkeypatch.setattr(d,'crtsh',lambda *a: [])
    monkeypatch.setattr(d,'official_site_discovery',lambda *a: ([],[]))
    monkeypatch.setattr(d,'dns_cnames',lambda *a: [])
    monkeypatch.setattr(d,'dns_resolve',lambda *a: [('1.1.1.1','A','DNS'),('8.8.8.8','A','DNS')])
    monkeypatch.setattr(d,'ripestat_network_info',lambda client,ip: {'asns':[27385 if ip=='8.8.8.8' else 13335]})
    monkeypatch.setattr(d,'ripestat_as_overview',lambda *a: {'holder':'Provider'})
    monkeypatch.setattr(v,'rdap',lambda *a: {})
    monkeypatch.setattr(v,'ripe_network',lambda *a: {'asns':[13335]})
    monkeypatch.setattr(v,'ripe_as',lambda *a: {'holder':'Provider'})
    monkeypatch.setattr(v,'ptr',lambda *a: '')
    monkeypatch.setattr(v,'resolve',lambda *a: ['1.1.1.1'])
    monkeypatch.setattr(v,'tls',lambda *a: {})
    monkeypatch.setattr(v,'crt_assoc',lambda *a: [])
    monkeypatch.setattr(v,'shodan',lambda *a: {})
    targets=engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example','Example','example.com','27385','Example']))])
    records=engine.analyze(targets, cfg={'max_workers':1,'tls_ports':[443]})
    assert {r['status'] for r in records}=={'KNOWN_ASN_EXCLUDED','UNVERIFIED'}
    assert len([r for r in records if r['status']=='KNOWN_ASN_EXCLUDED'])==1
    store=Store(tmp_path/'run.db'); run=store.start(targets); store.finish(run, records)
    reopened=Store(tmp_path/'run.db')
    assert len(reopened.results(run))==2
    assert reopened.results(run)[0]['organization']=='Example'
