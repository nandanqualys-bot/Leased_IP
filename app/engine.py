"""Direct, cancellable adapter around the existing passive EASM engine."""
from __future__ import annotations
import importlib.util
import ipaddress
import json
import re
import sys
import unicodedata
from pathlib import Path

import pandas as pd

ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

input_engine = _load('easm_input', '01_generate_input.py')
discovery = _load('easm_discovery', '02_off_asn_discovery.py')
verification = _load('easm_verification', '04_ip_verification.py')


def canonical_asn(value: str) -> str:
    result = input_engine.normalize_asn(value)
    if result and not input_engine.ASN_RE.fullmatch(result):
        raise ValueError(f'Invalid ASN: {value}')
    return result


def normalize_targets(rows: list[dict]) -> list[dict]:
    frame = pd.DataFrame(rows, columns=input_engine.COLUMNS).fillna('')
    frame = input_engine.validate_rows(frame)
    return input_engine.to_json(frame)['targets']


def targets_from_excel(path: str) -> list[dict]:
    return normalize_targets(input_engine.load_input(Path(path)).to_dict('records'))


def slug(value: str) -> str:
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore').decode().lower()
    return re.sub(r'_+', '_', re.sub(r'[^a-z0-9]+', '_', value)).strip('_') or 'organization'


def config():
    cfg = discovery.cfg_load(ROOT / 'config.json')
    # Credentials are supplied by the existing optional environment providers.
    cfg.pop('shodan_api_key', None)
    cfg.pop('censys_api_token', None)
    cfg.pop('censys_org_id', None)
    return cfg


def analyze(targets: list[dict], emit=lambda *a: None, cancelled=lambda: False, cfg=None) -> list[dict]:
    """Return verified and excluded records; never write Excel during analysis."""
    cfg = cfg or config()
    client_d = discovery.HttpClient(cfg.get('timeouts', {}).get('http', 15), cfg.get('max_retries', 2), cfg.get('request_delay', .2))
    client_v = verification.Client(cfg)
    all_records = []
    for index, target in enumerate(targets, 1):
        if cancelled():
            break
        emit('discovery', index, len(targets), target['parent_organization'])
        rows = discovery.process_target(target, client_d, None, cfg, include_known=True)
        # The legacy engine filters by canonical ASNs. Defend the boundary again.
        known = {canonical_asn(x) for x in target.get('known_asns', []) if x}
        for row in rows:
            if cancelled():
                break
            ip = row['IP']
            if ipaddress.ip_address(ip).version != 4:
                continue
            origin = canonical_asn(row['Origin_ASN']) if row['Origin_ASN'] != 'Not Available' else ''
            if origin in known:
                all_records.append({
                    'organization': target['parent_organization'], 'entity': target['target_entity'],
                    'domains': target['target_domains'], 'ip': ip,
                    'hostname': row['Discovered_Hostname'],
                    'candidate': {'ip': ip, 'origin_asn': origin, 'origin_organization': row['Origin_Organization'],
                                  'discovery_sources': row['Discovery_Source'].split(';')},
                    'finding': {'relationship': 'Known target ASN', 'confidence': 'EXCLUDED',
                                'proof': f'{ip} is originated by {origin}, a known target ASN. Excluded before verification.',
                                'evidence': [('Known ASN', f'Origin {origin} matches target ASN', 0)]},
                    'status': 'KNOWN_ASN_EXCLUDED', 'included': False,
                })
                continue
            candidate = {
                'ip': ip, 'hostname': row['Discovered_Hostname'],
                'origin_asn': origin or 'Not Available',
                'origin_organization': row['Origin_Organization'],
                'hosting_provider': row['Hosting_Provider'],
                'discovery_sources': row['Discovery_Source'].split(';'),
                'discovery_evidence': row['Discovery_Evidence'],
                'first_seen': row['First_Seen'], 'last_seen': row['Last_Seen'],
            }
            emit('verification', index, len(targets), ip)
            try:
                finding = verification.score_candidate(target, candidate, client_v, cfg)
                status = classify(finding)
                result = {
                    'organization': target['parent_organization'],
                    'entity': target['target_entity'], 'domains': target['target_domains'],
                    'ip': ip, 'hostname': candidate['hostname'], 'candidate': candidate,
                    'finding': finding, 'status': status,
                    'included': status in ('CONFIRMED_OWNED', 'CONFIRMED_LEASED', 'CONFIRMED_OPERATED'),
                }
                all_records.append(result)
            except Exception as exc:
                all_records.append({
                    'organization': target['parent_organization'], 'entity': target['target_entity'],
                    'domains': target['target_domains'], 'ip': ip, 'hostname': candidate['hostname'],
                    'candidate': candidate, 'finding': {'proof': f'Verification failed: {exc}', 'evidence': []},
                    'status': 'ERROR', 'included': False,
                })
    return all_records


def classify(finding: dict) -> str:
    confidence = finding.get('confidence', '')
    relationship = finding.get('relationship', '')
    if confidence == 'CONFIRMED' and relationship == 'Owned':
        return 'CONFIRMED_OWNED'
    if confidence in ('CONFIRMED', 'HIGH') and relationship == 'Leased/Hosted':
        return 'CONFIRMED_LEASED'
    if confidence in ('CONFIRMED', 'HIGH') and relationship == 'Operated':
        return 'CONFIRMED_OPERATED'
    if any(x[0] == 'Shared Infrastructure' for x in finding.get('evidence', [])):
        return 'SHARED_INFRASTRUCTURE'
    if confidence == 'MEDIUM':
        return 'LIKELY_ASSOCIATED'
    return 'UNVERIFIED'
