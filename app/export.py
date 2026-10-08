"""Explicit exports from stored analysis results."""
import json
from datetime import datetime
from pathlib import Path
import pandas as pd
from .engine import slug


def filename(organization, run_id, suffix):
    return f'{slug(organization)}_run_{run_id}_{datetime.now():%Y%m%d_%H%M%S}.{suffix}'


OPTIONS = ('Export EASM Assets', 'Export Verified Results', 'Export Candidates',
           'Export Rejected', 'Export Evidence', 'Export Full Workbook')


def export_results(rows, destination, mode=None, organization=None, overwrite=False):
    from .credentials import sanitize
    rows = sanitize(rows)
    if organization is not None:
        rows = [row for row in rows if row['organization'].casefold() == organization.casefold()]
    path = Path(destination)
    if path.exists() and not overwrite:
        raise FileExistsError('Choose Replace or another filename before exporting.')
    if mode not in (None, *OPTIONS):
        raise ValueError('Unknown export option')
    if mode in ('Export EASM Assets', 'Export Verified Results'):
        rows = [row for row in rows if row['included']]
    elif mode == 'Export Rejected':
        rows = [row for row in rows if not row['included'] and row['status'] != 'PENDING']
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
        columns = ['Organization', 'Target Entity', 'Target Domain', 'IP', 'Hostname', 'Origin ASN',
                   'Origin Organization', 'Registered Organization', 'Relationship', 'Confidence',
                   'Confidence Score', 'Attribution Status', 'Included in EASM', 'Proof Summary']
        frame = pd.DataFrame(payload, columns=columns)
        verified = frame[frame['Included in EASM'].astype(bool)]
        rejected = frame[(~frame['Included in EASM'].astype(bool)) & (frame['Attribution Status'] != 'PENDING')]
        observations = pd.DataFrame(evidence, columns=['IP', 'Source', 'Evidence', 'Score Contribution'])
        with pd.ExcelWriter(path, engine='openpyxl') as writer:
            if mode == 'Export Full Workbook':
                pd.DataFrame([{'Organization': organization or '', 'Verified Assets': len(verified),
                               'Candidates': len(frame), 'Rejected': len(rejected), 'Evidence':len(observations)}]).to_excel(
                                   writer, sheet_name='Summary', index=False)
                verified.to_excel(writer, sheet_name='Verified Assets', index=False)
                frame.to_excel(writer, sheet_name='Candidates', index=False)
                rejected.to_excel(writer, sheet_name='Rejected', index=False)
                observations.to_excel(writer, sheet_name='Evidence', index=False)
            elif mode == 'Export Evidence':
                observations.to_excel(writer, sheet_name='Evidence', index=False)
            elif mode is not None:
                sheet = {'Export EASM Assets':'EASM Assets', 'Export Verified Results':'Verified Assets',
                         'Export Candidates':'Candidates', 'Export Rejected':'Rejected'}[mode]
                frame.to_excel(writer, sheet_name=sheet, index=False)
            else:
                frame.to_excel(writer, sheet_name='Candidates', index=False)
                verified.to_excel(writer, sheet_name='EASM Assets', index=False)
                observations.to_excel(writer, sheet_name='Evidence', index=False)
    return path
