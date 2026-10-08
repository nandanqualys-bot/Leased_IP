import json
import os
from pathlib import Path

import pandas as pd
import pytest
from PySide6.QtWidgets import QApplication, QLineEdit
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


def test_provider_settings_are_private_and_masked(app, tmp_path, monkeypatch):
    monkeypatch.setenv('EASM_DATA_DIR',str(tmp_path))
    from app import credentials
    credentials.save({'SHODAN_API_KEY':'example-test-value'})
    assert credentials.path().read_text().find('example-test-value') >= 0
    if os.name != 'nt': assert credentials.path().stat().st_mode & 0o077 == 0
    assert credentials.presence()['SHODAN_API_KEY']
    window=MainWindow(Store(tmp_path/'database.sqlite'))
    assert window.credential_inputs['SHODAN_API_KEY'].text() == ''
    assert window.credential_inputs['SHODAN_API_KEY'].echoMode() == QLineEdit.Password
    window.close()
    monkeypatch.delenv('SHODAN_API_KEY',raising=False)


def test_reverify_creates_new_run(app, tmp_path, monkeypatch):
    from app.workers import ReverifyWorker
    target=engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example','Example','example.com','AS64500','']))])[0]
    store=Store(tmp_path/'db.sqlite')
    run=store.start([target]); old={'organization':'Example','entity':'Example','domains':['example.com'],
        'ip':'1.1.1.1','hostname':'example.com',
        'candidate':{'ip':'1.1.1.1','hostname':'example.com','origin_asn':'AS13335','discovery_sources':['DNS']},
        'finding':{'confidence':'LOW','relationship':'Unverified','evidence':[]},
        'status':'UNVERIFIED','included':False}
    store.finish(run,[old])
    monkeypatch.setattr(engine.verification,'score_candidate',lambda *a: {
        'confidence':'HIGH','relationship':'Leased/Hosted','score':85,'evidence':[('TLS','match',25)],'proof':'Updated'})
    monkeypatch.setattr(engine.verification,'ripe_network',lambda *a: {'asns':[13335]})
    worker=ReverifyWorker(store.path,target,old,{'max_retries':0})
    worker.start(); assert worker.wait(5000)
    newer=store.runs()[0]['id']
    assert newer != run
    assert store.results(newer)[0]['status']=='CONFIRMED_LEASED'
    assert store.results(run)[0]['status']=='UNVERIFIED'


def test_reverify_rechecks_known_asn(app, tmp_path, monkeypatch):
    from app.workers import ReverifyWorker
    target=engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example','Example','example.com','AS27385','']))])[0]
    store=Store(tmp_path/'db.sqlite')
    old={'organization':'Example','entity':'Example','domains':['example.com'],'ip':'1.1.1.1',
         'hostname':'example.com','candidate':{'ip':'1.1.1.1','origin_asn':'AS13335'},
         'finding':{'evidence':[]},'status':'UNVERIFIED','included':False}
    monkeypatch.setattr(engine.verification,'ripe_network',lambda *a: {'asns':[27385]})
    def forbidden(*args): raise AssertionError('Known ASN must not reach verification')
    monkeypatch.setattr(engine.verification,'score_candidate',forbidden)
    worker=ReverifyWorker(store.path,target,old,{'max_retries':0})
    worker.start(); assert worker.wait(5000)
    assert store.results(store.runs()[0]['id'])[0]['status']=='KNOWN_ASN_EXCLUDED'


def test_public_cache_reuses_get_without_storing_provider_keys(tmp_path):
    import requests
    from app.cache import CachedGet
    class Provider:
        calls = 0
        def get(self, url, **kwargs):
            self.calls += 1
            response = requests.Response(); response.status_code=200
            response.url=url; response._content=b'{"data":{"asns":[13335]}}'
            response.headers['Content-Type']='application/json'
            return response
    class Client(CachedGet, Provider): pass
    client=Client(); client.set_cache(tmp_path/'cache.db')
    url='https://stat.ripe.net/data/network-info/data.json?resource=1.1.1.1'
    assert client.get(url).json()['data']['asns']==[13335]
    assert client.get(url).json()['data']['asns']==[13335]
    assert client.calls==1
    client.get('https://api.shodan.io/shodan/host/1.1.1.1',params={'key':'secret'})
    assert client.calls==2
    assert b'secret' not in (tmp_path/'cache.db').read_bytes()


def test_shodan_hostname_search_adds_only_in_scope_public_ipv4(monkeypatch):
    d=engine.discovery
    class Response:
        ok=True
        def json(self):
            return {'matches':[
                {'ip_str':'1.1.1.1','hostnames':['app.example.com']},
                {'ip_str':'8.8.8.8','hostnames':['unrelated.org']},
                {'ip_str':'10.0.0.1','hostnames':['app.example.com']},
                {'ip_str':'2606:4700::1111','hostnames':['app.example.com']},
            ]}
    class Client:
        def get(self,url,**kwargs):
            assert url=='https://api.shodan.io/shodan/host/search'
            assert kwargs['params']['query']=='hostname:"example.com"'
            return Response()
    assert d.shodan_domain_candidates(Client(),'test-key','example.com') == [('1.1.1.1',['app.example.com'])]
    assert d.shodan_domain_candidates(Client(),'','example.com') == []


def test_new_candidate_sources_keep_known_asn_filter(monkeypatch):
    d=engine.discovery
    monkeypatch.setattr(d,'crtsh',lambda *a: [])
    monkeypatch.setattr(d,'official_site_discovery',lambda *a: ([],[]))
    monkeypatch.setattr(d,'dns_cnames',lambda *a: [])
    monkeypatch.setattr(d,'dns_resolve',lambda *a: [])
    monkeypatch.setattr(d,'shodan_domain_candidates',lambda *a: [('1.1.1.1',['app.example.com'])])
    monkeypatch.setattr(d,'ripestat_network_info',lambda client,ip: {'asns':[27385 if ip=='1.1.1.1' else 13335]})
    monkeypatch.setattr(d,'ripestat_as_overview',lambda *a: {'holder':'Provider'})
    target={'parent_organization':'Example','target_entity':'Example','target_domains':['example.com'],
            'known_asns':['AS27385'],'known_registrant_names':[]}
    rows=d.process_target(target,object(),None,{'shodan_api_key':'test-key'},
                          history_lookup=lambda domain:['8.8.8.8'])
    assert {r['IP'] for r in rows}=={'8.8.8.8'}
    assert rows[0]['Discovery_Source']=='Historical DNS (context)'
    assert d.process_target(target,object(),None,{},include_known=True,
                            history_lookup=lambda domain:['8.8.8.8'])[0]['In_Known_ASN']


def test_shodan_host_lookup_uses_exact_ip():
    v=engine.verification
    class Response:
        ok=True
        def json(self): return {'hostnames':['app.example.com']}
    class Client:
        def get(self,url,**kwargs):
            assert url=='https://api.shodan.io/shodan/host/1.1.1.1'
            assert kwargs['params']['key']=='test-key'
            return Response()
    assert v.shodan(Client(),'test-key','1.1.1.1')['hostnames']==['app.example.com']


def test_cloud_rdap_does_not_cancel_live_dns_and_tls(monkeypatch):
    v=engine.verification
    monkeypatch.setattr(v,'rdap',lambda *a: {'name':'Unrelated Cloud Provider'})
    monkeypatch.setattr(v,'rdap_org',lambda data: data['name'])
    monkeypatch.setattr(v,'ripe_network',lambda *a: {'asns':[13335]})
    monkeypatch.setattr(v,'ripe_as',lambda *a: {'holder':'Provider'})
    monkeypatch.setattr(v,'ptr',lambda *a: '')
    monkeypatch.setattr(v,'resolve',lambda *a: ['1.1.1.1'])
    monkeypatch.setattr(v,'tls',lambda *a: {'cn':'app.example.com','sans':['app.example.com']})
    monkeypatch.setattr(v,'crt_assoc',lambda *a: [])
    monkeypatch.setattr(v,'shodan',lambda *a: {})
    target={'parent_organization':'Example','target_entity':'Example','target_domains':['example.com'],
            'known_asns':['AS64500'],'known_registrant_names':[]}
    candidate={'ip':'1.1.1.1','hostname':'app.example.com','origin_asn':'AS13335'}
    result=v.score_candidate(target,candidate,object(),{})
    assert result['score']==50
    assert not any(x[1].startswith('Negative:') for x in result['evidence'])


def test_censys_history_is_wired_into_desktop_discovery(monkeypatch):
    target={'parent_organization':'Example','target_entity':'Example','target_domains':['example.com'],
            'known_asns':['AS64500'],'known_registrant_names':[]}
    monkeypatch.setattr(engine.verification,'censys_enabled',lambda cfg: True)
    monkeypatch.setattr(engine.verification,'censys_domain_history',lambda client,cfg,domain,days: ['1.1.1.1'])
    observed=[]
    def discover(t,client,cache,cfg,**kwargs):
        observed.extend(kwargs['history_lookup']('example.com'))
        return []
    monkeypatch.setattr(engine.discovery,'process_target',discover)
    assert engine.analyze([target],cfg={'censys_history_days':31})==[]
    assert observed==['1.1.1.1']


def test_origin_changing_to_known_asn_during_verification_still_excludes(monkeypatch):
    targets=engine.normalize_targets([dict(zip(engine.input_engine.COLUMNS,
        ['Example','Example','example.com','AS27385','']))])
    row={'IP':'1.1.1.1','Origin_ASN':'AS13335','Discovered_Hostname':'app.example.com',
         'Origin_Organization':'Provider','Hosting_Provider':'Provider',
         'Discovery_Source':'DNS','Discovery_Evidence':'{}','First_Seen':'','Last_Seen':''}
    monkeypatch.setattr(engine.discovery,'process_target',lambda *a,**k:[row])
    monkeypatch.setattr(engine.verification,'score_candidate',lambda *a:{
        'origin_asn':'AS27385','confidence':'HIGH','relationship':'Owned','score':90,
        'evidence':[('DNS','Observed',25)],'proof':'Old proof'})
    result=engine.analyze(targets)[0]
    assert result['status']=='KNOWN_ASN_EXCLUDED'
    assert not result['included']


def test_local_config_key_is_used_when_environment_key_missing(monkeypatch):
    monkeypatch.delenv('SHODAN_API_KEY', raising=False)
    monkeypatch.setattr(engine.discovery, 'cfg_load', lambda path: {'shodan_api_key':'local-test-key'})
    assert engine.config()['shodan_api_key']=='local-test-key'
