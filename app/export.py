"""Explicit exports from stored analysis results."""
import json
from datetime import datetime
from pathlib import Path
import pandas as pd
from .engine import slug


def filename(organization, run_id, suffix):
    return f'{slug(organization)}_run_{run_id}_{datetime.now():%Y%m%d_%H%M%S}.{suffix}'


def export_results(rows, destination):
    path = Path(destination)
    payload = []
    evidence = []
    for row in rows:
        finding = row['finding']
        payload.append({
            'Organization': row['organization'], 'Target Entity': row['entity'],
            'Target Domain': ';'.join(row['domains']), 'IP': row['ip'],
            'Hostname': row['hostname'], 'Origin ASN': row['candidate'].get('origin_asn'),
            'Origin Organization': finding.get('origin_org'),
            'Registered Organization': finding.get('registered_org'),
            'Relationship': finding.get('relationship'), 'Confidence': finding.get('confidence'),
            'Confidence Score': finding.get('score'), 'Attribution Status': row['status'],
            'Included in EASM': bool(row['included']), 'Proof Summary': finding.get('proof'),
        })
        for source, detail, points in finding.get('evidence', []):
            evidence.append({'IP': row['ip'], 'Source': source, 'Evidence': detail, 'Score Contribution': points})
    if path.suffix.lower() == '.json':
        path.write_text(json.dumps({'results': payload, 'evidence': evidence}, indent=2, default=str), encoding='utf-8')
    else:
        frame = pd.DataFrame(payload)
        with pd.ExcelWriter(path, engine='openpyxl') as writer:
            frame.to_excel(writer, sheet_name='Candidates', index=False)
            frame[frame['Included in EASM']].to_excel(writer, sheet_name='EASM Assets', index=False)
            pd.DataFrame(evidence).to_excel(writer, sheet_name='Evidence', index=False)
    return path
